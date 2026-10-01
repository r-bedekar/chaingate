// U-05 R2-2 legacy part, owner decision 7 requirement 3 (and Addendum 2 §3.2, IL1-IL5): the pending-install marker is
// durable before the database transaction; interruption at every point leaves the old committed state before COMMIT and
// may leave the new one after it; the signature pair is never mixed; doctor reports "unverifiable", the integrity gate
// refuses everything but the completing command, and completion must use the recorded seed. The legacy `update-seed`
// runs as the real command function in a child (u05-r22-mutator.mjs) killed at named points; verification there uses a
// TEST key (U05_TEST_SPKI), never a replaced product key.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { freshHome, runCli, startMutator, v3Host, age, deadPid, exists } from '../helpers/u05-r22.mjs';
import { testKey, buildLegacySeed, legacyWitness, snapshot, DEFAULT_PKGS, NEW_PKGS } from '../helpers/u05-r22-legacy.mjs';

const key = testKey();
const MARKER = (base) => path.join(base, 'witness.db.install-pending.json');
const LOCAL = { decisions: [{ id: 5, pkg: 'alpha', ver: '1.0.0', disposition: 'BLOCK', at: '2026-02-01 00:00:00' }],
  overrides: [{ id: 3, pkg: 'alpha', ver: '1.1.0', reason: 'local override' }] };
const doctorChecks = (r) => { try { return JSON.parse(r.stdout); } catch { assert.fail(`doctor --json printed no JSON:\n${r.out}`); } };

function host({ newPkgs = NEW_PKGS, newVersion = '2026.test.new' } = {}) {
  const { home, base } = freshHome('il');
  const old = buildLegacySeed(path.join(home, 'old'), { key, seedVersion: '2026.test.old', pkgs: DEFAULT_PKGS });
  const neu = buildLegacySeed(path.join(home, 'new'), { key, seedVersion: newVersion, pkgs: newPkgs,
    decisions: [{ pkg: 'gamma', ver: '3.0.0', disposition: 'BLOCK', at: '2026-03-01 00:00:00' }] });
  const w = legacyWitness(base, { from: 'seed', seed: old, local: LOCAL });           // the old signed pair installed
  return { home, base, w, old, neu, cleanup: () => fs.rmSync(home, { recursive: true, force: true }) };
}
const env = (bundle) => ({ U05_LEGACY_BUNDLE: bundle.dir, U05_TEST_SPKI: key.spki });
const pair = (base) => ({
  sha: exists(path.join(base, 'witness.db.sha256')) ? fs.readFileSync(path.join(base, 'witness.db.sha256'), 'utf8').trim() : null,
  sig: exists(path.join(base, 'witness.db.sig')) ? fs.readFileSync(path.join(base, 'witness.db.sig')).toString('hex') : null,
});
const sigHex = (s) => fs.readFileSync(s.sig).toString('hex');
/** The pair on disk is the old pair, a partial pair, or the new pair -- never one of each. */
function assertNeverMixed(h) {
  const p = pair(h.base);
  if (p.sha && p.sig) {
    const oldPair = p.sha === h.old.digest && p.sig === sigHex(h.old);
    const newPair = p.sha === h.neu.digest && p.sig === sigHex(h.neu);
    assert.ok(oldPair || newPair, `a mixed signature pair is on disk: ${JSON.stringify(p)}`);
  }
}
const seedVersionOf = (w) => snapshot(w).rows.seed_metadata.find((r) => r.key === 'seed_version')?.value;

const POINTS = [
  ['beforeBegin', 1, 'old'], ['duringRefresh', 1, 'old'], ['afterCommit', 1, 'new'],
  ['betweenSidecarOps', 1, 'new'], ['betweenSidecarOps', 2, 'new'], ['betweenSidecarOps', 3, 'new'],
  ['beforeMarkerRemoval', 1, 'new'],
];
for (const [point, nth, expected] of POINTS) {
  test(`interrupted at ${point}${nth > 1 ? ` #${nth}` : ''}: ${expected} database state, marker kept, never a mixed pair; completion converges`, async () => {
    const h = host();
    try {
      const before = snapshot(h.w);
      const m = startMutator(h.base, 'update-seed', [], { killAt: point, nth, env: env(h.neu) });
      const reached = await m.at(point); const r = await m.done;
      assert.equal(reached, true, `SEAM-ABSENT: no ${point} point\n${r.all}`);
      assert.equal(r.signal, 'SIGKILL');
      assert.equal(exists(MARKER(h.base)), true, 'the marker was made durable before the database changed');
      assert.equal(seedVersionOf(h.w), expected === 'old' ? '2026.test.old' : '2026.test.new');
      if (expected === 'old') assert.deepEqual(snapshot(h.w).rows, before.rows, 'before COMMIT: the old committed state');
      assert.equal(snapshot(h.w).integrity, 'ok');
      assertNeverMixed(h);
      // doctor: unverifiable with the pending detail, never tamper (the marker is read before the pair)
      const d = doctorChecks(await runCli(h.base, ['doctor', '--json'], { timeoutMs: 20000 }));
      const sig = d.find((c) => c.name === 'seed-signature');
      assert.equal(sig.severity, 'unverifiable', JSON.stringify(sig));
      assert.match(sig.detail, /interrupted legacy seed installation .* was not completed/);
      // a non-completing mutating command is refused by the gate
      const a = await runCli(h.base, ['allow', 'alpha@1.0.0', '--reason', 'test'], { timeoutMs: 20000 });
      assert.equal(a.code, 6, a.out); assert.match(a.out, /interrupted legacy seed installation/);
      // completion: the same seed again
      const c = startMutator(h.base, 'update-seed', [], { env: env(h.neu) }); const cr = await c.done;
      assert.equal(cr.code, 0, cr.all);
      assert.equal(exists(MARKER(h.base)), false);
      assert.equal(seedVersionOf(h.w), '2026.test.new');
      assert.deepEqual(pair(h.base), { sha: h.neu.digest, sig: sigHex(h.neu) });
      const after = snapshot(h.w);
      assert.deepEqual(after.rows.gate_decisions.filter((x) => x.id === 5), before.rows.gate_decisions.filter((x) => x.id === 5));
      assert.equal(after.rows.gate_decisions.filter((x) => x.package_name === 'gamma').length, 1, 'imported once, not per attempt');
    } finally { h.cleanup(); }
  });
}

test('interrupted DURING COMMIT (timed SIGKILL trials): old or new, never mixed, integrity ok; the marker stays; completion converges', async (t) => {
  const many = Array.from({ length: 40 }, (_, i) => ({ id: 1000 + i, name: `pkg${i}`,
    versions: Array.from({ length: 50 }, (_, j) => ({ id: 100000 + i * 100 + j, version: `1.${j}.0`,
      files: [{ id: 500000 + i * 100 + j, filename: `pkg${i}-1.${j}.0.tgz` }] })) }));
  const tally = { old: 0, new: 0 };
  for (const delay of [0, 1, 2, 4, 8, 16]) {
    const h = host({ newPkgs: many });
    try {
      const m = startMutator(h.base, 'update-seed', [], { pauseAt: 'beforeCommit', env: env(h.neu) });
      assert.equal(await m.at('beforeCommit'), true, 'SEAM-ABSENT: no beforeCommit point');
      m.go(); setTimeout(() => m.child.kill('SIGKILL'), delay);
      await m.done;
      const v = seedVersionOf(h.w);
      assert.ok(v === '2026.test.old' || v === '2026.test.new', `state ${v}`);
      tally[v === '2026.test.old' ? 'old' : 'new'] += 1;
      assert.equal(snapshot(h.w).integrity, 'ok');
      assertNeverMixed(h);
      if (exists(MARKER(h.base))) {
        const c = startMutator(h.base, 'update-seed', [], { env: env(h.neu) });
        assert.equal((await c.done).code, 0);
      }
      assert.equal(seedVersionOf(h.w), '2026.test.new'); assert.equal(exists(MARKER(h.base)), false);
    } finally { h.cleanup(); }
  }
  t.diagnostic(`timed kills around COMMIT: ${tally.old} left the old state, ${tally.new} the new state`);
});

test('completion must use the recorded seed: a different seed is refused, naming both digests', async () => {
  const h = host();
  try {
    const m = startMutator(h.base, 'update-seed', [], { killAt: 'afterCommit', env: env(h.neu) });
    assert.equal(await m.at('afterCommit'), true, 'SEAM-ABSENT'); await m.done;
    const other = buildLegacySeed(path.join(h.home, 'other'), { key, seedVersion: '2026.test.other', pkgs: NEW_PKGS });
    const c = startMutator(h.base, 'update-seed', [], { env: env(other) }); const r = await c.done;
    assert.equal(r.code, 1, r.all);
    assert.match(r.all, new RegExp(`${h.neu.digest.slice(0, 16)}.*is pending; this command would install ${other.digest.slice(0, 16)}`));
    assert.equal(exists(MARKER(h.base)), true, 'the pending installation is kept');
  } finally { h.cleanup(); }
});

test('a failure AFTER commit is reported as refreshed, never as "nothing committed"', async () => {
  const h = host();
  try {
    const m = startMutator(h.base, 'update-seed', [], { pauseAt: 'afterDatabase', env: env(h.neu) });
    assert.equal(await m.at('afterDatabase'), true, 'SEAM-ABSENT: no afterDatabase point');
    // make the sidecar installation fail: a directory where the new .sha256 must be renamed
    fs.rmSync(path.join(h.base, 'witness.db.sha256'), { force: true }); fs.mkdirSync(path.join(h.base, 'witness.db.sha256'));
    fs.writeFileSync(path.join(h.base, 'witness.db.sha256', 'keep'), 'x');
    m.go(); const r = await m.done;
    assert.equal(r.code, 1, r.all);
    assert.match(r.all, /witness database was refreshed, but the signature files were not installed/);
    assert.doesNotMatch(r.all, /nothing was committed/);
    assert.equal(exists(MARKER(h.base)), true);
  } finally { h.cleanup(); }
});

// ---- IL1-IL5 (Addendum 2 §3.2) -------------------------------------------------------------------------------------------
const writeMarker = (base, rec = {}) => fs.writeFileSync(MARKER(base), `${JSON.stringify({ schema: 'chaingate-legacy-install/1',
  kind: 'legacy-seed', new_sha256: 'a'.repeat(64), source: 'test', started_at: '2026-10-01T00:00:00Z', pid: 1, ...rec })}\n`);

test('IL1 marker present: doctor unverifiable; allow and plain init refused by the gate; no proxy started', async () => {
  const h = host();
  try {
    writeMarker(h.base);
    const sig = doctorChecks(await runCli(h.base, ['doctor', '--json'], { timeoutMs: 20000 })).find((c) => c.name === 'seed-signature');
    assert.equal(sig.severity, 'unverifiable'); assert.match(sig.detail, /interrupted legacy seed installation/);
    const a = await runCli(h.base, ['allow', 'alpha@1.0.0', '--reason', 'x'], { timeoutMs: 20000 });
    assert.equal(a.code, 6, a.out);
    const i = await runCli(h.base, ['init'], { timeoutMs: 30000 });
    assert.equal(i.code, 6, i.out); assert.equal(i.spawnedProxy, undefined);
  } finally { h.cleanup(); }
});

test('IL2 guard: no marker -> the seed-signature check behaves as before', async () => {
  const h = await v3Host();
  try {
    const sig = doctorChecks(await runCli(h.base, ['doctor', '--json'], { timeoutMs: 20000 })).find((c) => c.name === 'seed-signature');
    assert.equal(sig.severity, 'skipped');
  } finally { h.cleanup(); }
});

test('IL3 marker on a v3-only host: unverifiable (the marker is not hidden by "no legacy seed"); plain init refused', async () => {
  const h = await v3Host();
  try {
    writeMarker(h.base);
    const sig = doctorChecks(await runCli(h.base, ['doctor', '--json'], { timeoutMs: 20000 })).find((c) => c.name === 'seed-signature');
    assert.equal(sig.severity, 'unverifiable');
    const i = await runCli(h.base, ['init'], { timeoutMs: 30000 });
    assert.equal(i.code, 6, i.out); assert.equal(i.spawnedProxy, undefined);
  } finally { h.cleanup(); }
});

test('IL5 a stale marker of a dead process is never cleaned up; it stays pending until completed', async () => {
  const h = host();
  try {
    writeMarker(h.base, { pid: deadPid() }); age(MARKER(h.base), 120);
    await runCli(h.base, ['update-seed', '--rollback'], { timeoutMs: 20000 });     // a mutator: lock, recovery, cleanup
    assert.equal(exists(MARKER(h.base)), true);
    const sig = doctorChecks(await runCli(h.base, ['doctor', '--json'], { timeoutMs: 20000 })).find((c) => c.name === 'seed-signature');
    assert.equal(sig.severity, 'unverifiable');
  } finally { h.cleanup(); }
});
