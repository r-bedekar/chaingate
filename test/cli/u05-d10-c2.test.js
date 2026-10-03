// U-05 owner decision 10, C2: ONE applicable-BLOCK rule on every path (observation and writes, historical reads,
// tarball enforcement, BLOCKs held only in memory). Expected results are the decision table in
// U-05-OWNER-DECISION-10-C1-C2-SCOPE-20261002.md §3, written before this file; run failing-first on 8f90e6a.
// A SKIP, a missing gate, an input-rule (error or unusable input) result or unrecognised text never clears a BLOCK.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { openWitnessDB } from '../../witness/db.js';
import { seed, registry, proxy, tarball, packument, rows, dispositions, failingWitness, insertRows, historical,
  PUBLISHED, tmp, stopAll, safely } from '../helpers/u05-d10.mjs';

const silence = () => { const e = console.error; const w = console.warn; console.error = () => {}; console.warn = () => {}; return () => { console.error = e; console.warn = w; }; };

async function world(t, { policy = 'BLOCK' } = {}) {
  const dir = tmp('c2'); const reg = await registry(); const s = seed();
  const restore = silence();
  t.after(async () => { await stopAll(); restore(); await safely(() => reg.close()); await safely(() => s.cleanup());
    await safely(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })); });
  return { dir, reg, s, witness: path.join(dir, 'witness.db'), policy };
}

// ---------------------------------------------------------------- erroneous supersession, end to end
for (const policy of ['BLOCK', 'WARN']) {
  test(`C2-1 (${policy}) an evidence gap after a content-hash BLOCK neither clears it nor churns; a definitive match does`, async (t) => {
    const w = await world(t, { policy });
    const px = await proxy({ upstream: w.reg.url, witness: w.witness, policy, seedDb: w.s.dbPath });
    t.after(() => px.stop());
    await packument(px, 'p');                                             // baseline
    w.reg.set('p', { mode: { '1.4.0': 'alt' } });
    assert.ok(!(await packument(px, 'p')).versions.includes('1.4.0'), 'content-hash BLOCK withholds 1.4.0');
    w.reg.set('p', { mode: { '1.4.0': 'none' } });
    for (let i = 0; i < 3; i += 1) {
      assert.ok(!(await packument(px, 'p')).versions.includes('1.4.0'), `gap observation ${i}: still withheld`);
    }
    assert.equal((await tarball(px, 'p', '1.4.0')).status, 403, 'the tarball stays refused after the gap');
    assert.deepEqual(dispositions(w.witness, 'p', '1.4.0'), ['ALLOW', 'BLOCK', 'ALLOW'], 'the gap row is recorded once, never repeated');
    w.reg.set('p', { mode: { '1.4.0': 'real' } });
    assert.ok((await packument(px, 'p')).versions.includes('1.4.0'), 'a definitive match clears it');
    assert.deepEqual(dispositions(w.witness, 'p', '1.4.0'), ['ALLOW', 'BLOCK', 'ALLOW', 'ALLOW'],
      'the definitive clearance is recorded although the disposition did not change');
    assert.equal((await tarball(px, 'p', '1.4.0')).status, 200);
  });
}

test('C2-2 (WARN) the seed cannot be read after a pin BLOCK: the pinned version is withheld and refused, during and after', async (t) => {
  const w = await world(t, { policy: 'WARN' }); const sw = { on: false };
  const px = await proxy({ upstream: w.reg.url, witness: w.witness, policy: 'WARN', seedDb: w.s.dbPath, seedFault: sw });
  t.after(() => px.stop());
  assert.ok(!(await packument(px, 'p')).versions.includes('1.3.0'));
  sw.on = true;
  assert.ok(!(await packument(px, 'p')).versions.includes('1.3.0'), 'an unreadable seed does not release the pinned version');
  assert.equal((await tarball(px, 'p', '1.3.0')).status, 403, 'during the failure');
  sw.on = false;
  assert.equal((await tarball(px, 'p', '1.3.0')).status, 403, 'after the seed recovers, before any metadata request');
  assert.equal(rows(w.witness, 'p', '1.3.0')[0].disposition, 'BLOCK', 'the original row is unchanged');
});

test('C2-3 (WARN) a BLOCK held only in memory is kept when a later evaluation does not clear it', async (t) => {
  // WARN: under BLOCK a storage failure already makes every decision BLOCK, which would hide this path.
  const w = await world(t, { policy: 'WARN' }); const witness = failingWitness(w.dir);
  const px = await proxy({ upstream: w.reg.url, witness, policy: 'WARN', seedDb: w.s.dbPath });
  t.after(() => px.stop());
  await packument(px, 'p');                                               // baselines; every p decision is held
  w.reg.set('p', { mode: { '1.4.0': 'alt' } }); await packument(px, 'p');   // content-hash BLOCK, held
  w.reg.set('p', { mode: { '1.4.0': 'none' } }); await packument(px, 'p');  // evidence gap
  const t1 = await tarball(px, 'p', '1.4.0');
  assert.equal(t1.status, 403, 'the held BLOCK still refuses');
  assert.equal(t1.json?.persisted, false);
});

test('C2-3b (WARN) a held BLOCK is forgotten once a later evaluation definitively clears it (added with the C2 commit)', async (t) => {
  const w = await world(t, { policy: 'WARN' }); const witness = failingWitness(w.dir);
  const px = await proxy({ upstream: w.reg.url, witness, policy: 'WARN', seedDb: w.s.dbPath });
  t.after(() => px.stop());
  await packument(px, 'p');
  w.reg.set('p', { mode: { '1.4.0': 'alt' } }); await packument(px, 'p');
  assert.equal((await tarball(px, 'p', '1.4.0')).status, 403, 'held');
  w.reg.set('p', { mode: { '1.4.0': 'real' } }); await packument(px, 'p');  // the hash matches the baseline again
  assert.equal((await tarball(px, 'p', '1.4.0')).status, 200, 'cleared definitively: forgotten and served');
});

test('C2-4 a missing gate is not clearance: the v3 seed removed, the pin BLOCK stays', async (t) => {
  const w = await world(t);
  let px = await proxy({ upstream: w.reg.url, witness: w.witness, seedDb: w.s.dbPath });
  await packument(px, 'p'); await px.stop();
  px = await proxy({ upstream: w.reg.url, witness: w.witness, v3: false });
  t.after(() => px.stop());
  assert.ok(!(await packument(px, 'p')).versions.includes('1.3.0'), 'without the seed-v3 gate the pin is not cleared');
  assert.equal((await tarball(px, 'p', '1.3.0')).status, 403);
});

// ---------------------------------------------------------------- overrides
test('C2-5 (guard) an override applies only while it exists; revoking it restores the underlying BLOCK', async (t) => {
  const w = await world(t);
  let px = await proxy({ upstream: w.reg.url, witness: w.witness, seedDb: w.s.dbPath });
  await packument(px, 'p'); await px.stop();
  let d = openWitnessDB(w.witness); d.insertOverride('p', '1.3.0', 'test override'); d.close();
  px = await proxy({ upstream: w.reg.url, witness: w.witness, seedDb: w.s.dbPath });
  await packument(px, 'p');
  assert.equal((await tarball(px, 'p', '1.3.0')).status, 200, 'override present');
  w.reg.set('p', { mode: { '1.3.0': 'none' } }); await packument(px, 'p'); // a non-definitive observation meanwhile
  await px.stop();
  d = openWitnessDB(w.witness); d.deleteOverride('p', '1.3.0'); d.close();
  px = await proxy({ upstream: w.reg.url, witness: w.witness, seedDb: w.s.dbPath });
  t.after(() => px.stop());
  assert.equal((await tarball(px, 'p', '1.3.0')).status, 403, 'revoked: the pin BLOCK applies again');
});

// ---------------------------------------------------------------- the rule itself, on stated rows
const R = (id, version, disposition, gates, at = '2026-10-01 00:00:00') => ({ id, package_name: 'p', version, disposition, gates_fired: gates, decided_at: at });
const PIN11 = { gate: 'seed-v3', result: 'BLOCK', detail: 'cft-policy-1.1: seed-v3:known-malicious-pin: recorded advisory ADV-P-130 pins p@1.3.0 (source synthetic-fixture)' };
const NOPIN11 = { gate: 'seed-v3', result: 'ALLOW', detail: 'cft-policy-1.1: seed-v3:known-malicious-pin: no recorded advisory pins this version | seed-v3:channel-a:critical: below threshold' };
const WARN11 = { gate: 'seed-v3', result: 'WARN', detail: 'cft-policy-1.1: seed-v3:coverage: nothing in this finding was evaluated' };
const NOPIN10 = { gate: 'seed-v3', result: 'ALLOW', detail: 'cft-policy-1.0: seed-v3:known-malicious-pin: no recorded advisory pins this version' };
const INPUT11 = { gate: 'seed-v3', result: 'WARN', detail: 'cft-policy-1.1: seed-v3:input: Error: the seed cannot be read' };
const RUNERR = { gate: 'seed-v3', result: 'WARN', detail: 'cft-policy-1.1: the seed-v3 path could not run (boom)' };
const CHB = { gate: 'content-hash', result: 'BLOCK', detail: 'integrity hash differs from baseline: sha512-a… → sha512-b…' };
const CHOK = { gate: 'content-hash', result: 'ALLOW', detail: 'integrity hash matches baseline' };
const CHSKIP = { gate: 'content-hash', result: 'SKIP', detail: 'incoming packument missing hash fields' };
const CHERR = { gate: 'content-hash', result: 'SKIP', detail: 'gate_error: boom' };
const OVR = { gate: 'override', result: 'ALLOW', detail: 'override: test' };

function applicable(t, list, overrides = []) {
  const dir = tmp('rule'); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const w = path.join(dir, 'witness.db'); insertRows(w, list, overrides);
  const d = openWitnessDB(w);
  try { return d.getApplicableDecision('p', list[0].version); } finally { d.close(); }
}
const verdict = (a) => (a.block ? 'BLOCK' : a.disposition);

test('C2-6 two blocking gates: both must be accounted for', (t) => {
  const rowsA = [R(1, '1.3.0', 'BLOCK', [CHB, PIN11]), R(2, '1.3.0', 'WARN', [CHOK, INPUT11])];
  assert.equal(verdict(applicable(t, rowsA)), 'BLOCK', 'content-hash cleared, the pin not');
  // Each reason is cleared by its own definitive result at any later point: content-hash in row 2, the pin in row 3.
  // (Expectation corrected with the C2 commit: the failing-first version expected BLOCK here, which the rule does not say.)
  const rowsB = [...rowsA, R(3, '1.3.0', 'ALLOW', [CHSKIP, NOPIN11])];
  assert.equal(verdict(applicable(t, rowsB)), 'ALLOW', 'content-hash cleared in row 2, the pin in row 3');
  const rowsB2 = [...rowsA, R(3, '1.3.0', 'BLOCK', [CHB, NOPIN11]), R(4, '1.3.0', 'ALLOW', [CHSKIP, NOPIN11])];
  assert.equal(verdict(applicable(t, rowsB2)), 'BLOCK', 'content-hash BLOCKed again in row 3 and only SKIPped since');
  const rowsC = [R(1, '1.3.0', 'BLOCK', [CHB, PIN11]), R(2, '1.3.0', 'ALLOW', [CHOK, NOPIN11])];
  const c = applicable(t, rowsC);
  assert.equal(verdict(c), 'ALLOW', 'both definitively cleared in one row');
  assert.deepEqual(c.pending, []);
});

test('C2-7 repeated error rows and a long history do not clear a BLOCK; reading it stays fast', (t) => {
  const list = [R(1, '1.3.0', 'BLOCK', [PIN11])];
  for (let i = 2; i <= 1000; i += 1) list.push(R(i, '1.3.0', i % 2 ? 'WARN' : 'ALLOW', i % 2 ? [CHERR, INPUT11] : [CHSKIP, RUNERR]));
  const t0 = process.hrtime.bigint();
  const a = applicable(t, list);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  assert.equal(verdict(a), 'BLOCK'); assert.deepEqual(a.pending, ['seed-v3:pin']);
  assert.ok(ms < 1000, `read in ${ms.toFixed(1)} ms`);
  list.push(R(1001, '1.3.0', 'ALLOW', [CHOK, NOPIN11]));
  assert.equal(verdict(applicable(t, list)), 'ALLOW', 'a definitive clearance at the end of a long history');
});

test('C2-8 unrecognised text is never clearance; policy-1.0 rows never clear a pin (D4)', (t) => {
  const odd = [
    { gate: 'content-hash', result: 'ALLOW', detail: 'hashes look fine' },
    { gate: 'seed-v3', result: 'ALLOW', detail: 'cft-policy-2.0: seed-v3:known-malicious-pin: no recorded advisory pins this version' },
  ];
  assert.equal(verdict(applicable(t, [R(1, '1.4.0', 'BLOCK', [CHB]), R(2, '1.4.0', 'ALLOW', [odd[0]])])), 'BLOCK');
  assert.equal(verdict(applicable(t, [R(1, '1.3.0', 'BLOCK', [PIN11]), R(2, '1.3.0', 'ALLOW', [odd[1]])])), 'BLOCK');
  assert.equal(verdict(applicable(t, [R(1, '1.3.0', 'BLOCK', [PIN11]), R(2, '1.3.0', 'ALLOW', [NOPIN10])])), 'BLOCK', 'a 1.0 "no advisory" does not clear a pin');
  assert.equal(verdict(applicable(t, [R(1, '1.3.0', 'BLOCK', [PIN11]), R(2, '1.3.0', 'WARN', [WARN11])])), 'WARN',
    'a 1.1 evaluation that did not decide by the input rule is an actual pin lookup with no pin');
  assert.equal(verdict(applicable(t, [R(1, '1.3.0', 'BLOCK', [{ gate: 'legacy-seed', result: 'BLOCK', detail: 'x' }]), R(2, '1.3.0', 'ALLOW', [CHOK, NOPIN11])])), 'BLOCK',
    'an unknown gate\'s BLOCK is cleared only by an override');
  assert.equal(verdict(applicable(t, [R(1, '1.3.0', 'BLOCK', 'not json'), R(2, '1.3.0', 'ALLOW', [CHOK, NOPIN11])])), 'BLOCK',
    'a BLOCK row whose results cannot be read is unclassified');
});

test('C2-9 the rule on overrides: live -> ALLOW; revoked -> the underlying decision', (t) => {
  const list = [R(1, '1.3.0', 'BLOCK', [PIN11]), R(2, '1.3.0', 'ALLOW', [OVR]), R(3, '1.3.0', 'ALLOW', [CHSKIP, INPUT11])];
  assert.equal(verdict(applicable(t, list, [{ package_name: 'p', version: '1.3.0', reason: 'test' }])), 'ALLOW', 'live override');
  assert.equal(verdict(applicable(t, list)), 'BLOCK', 'revoked override');
});

// ---------------------------------------------------------------- histories written by the PUBLISHED runtimes
const EXPECTED = {           // scenario -> [version, applicable verdict after the captured history]
  'pin-input-warn': ['1.3.0', 'BLOCK'], 'pin-input-block': ['1.3.0', 'BLOCK'], 'ch-gap': ['1.4.0', 'BLOCK'],
  'ch-clear': ['1.4.0', 'ALLOW'], 'override-revoke': ['1.3.0', 'BLOCK'], multi: ['1.3.0', 'BLOCK'], long: ['1.3.0', 'BLOCK'],
};
for (const runtime of PUBLISHED) {
  test(`C2-10 (${runtime}) histories written by the published runtime: the applicable decision`, (t) => {
    for (const [scenario, [version, want]] of Object.entries(EXPECTED)) {
      const h = historical(runtime, scenario);
      const dir = tmp('hist'); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
      const w = path.join(dir, 'witness.db'); insertRows(w, h.rows, h.overrides);
      const d = openWitnessDB(w);
      let a; try { a = d.getApplicableDecision('p', version); } finally { d.close(); }
      assert.equal(verdict(a), want, `${runtime} ${scenario} p@${version}`);
    }
  });

  test(`C2-11 (${runtime}) end to end: historical rows, metadata unavailable, WARN policy -> refused where a BLOCK applies`, async (t) => {
    for (const [scenario, [version, want]] of Object.entries(EXPECTED)) {
      const w = await world(t, { policy: 'WARN' });
      const h = historical(runtime, scenario); insertRows(w.witness, h.rows, h.overrides);
      const before = rows(w.witness, 'p', version).map((r) => `${r.id}|${r.disposition}|${r.gates_fired}`);
      w.reg.set('p', { status: 503 });                                    // nothing can be re-evaluated
      const px = await proxy({ upstream: w.reg.url, witness: w.witness, policy: 'WARN', seedDb: w.s.dbPath });
      const r = await tarball(px, 'p', version);
      await px.stop();
      assert.equal(r.status, want === 'BLOCK' ? 403 : 200, `${runtime} ${scenario} p@${version}: ${r.status} ${r.json?.error ?? ''}`);
      assert.deepEqual(rows(w.witness, 'p', version).map((x) => `${x.id}|${x.disposition}|${x.gates_fired}`), before,
        'historical rows preserved byte for byte');
    }
  });
}

test('C2-12 `why --cached` shows the decision that applies beside the latest row (added with the C2 commit)', async (t) => {
  const { spawnSync } = await import('node:child_process');
  const dir = tmp('why'); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const w = path.join(dir, 'witness.db'); const h = historical('0.1.2', 'ch-gap'); insertRows(w, h.rows, h.overrides);
  const cli = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'cli', 'index.js');
  const r = spawnSync(process.execPath, [cli, 'why', 'p@1.4.0', '--cached', '--json'],
    { env: { ...process.env, CHAINGATE_WITNESS_DB: w, NO_COLOR: '1' }, encoding: 'utf8' });
  const j = JSON.parse(r.stdout);
  assert.equal(j.cached.disposition, 'ALLOW', 'the latest row (an evidence-gap ALLOW)');
  assert.equal(j.applicable.disposition, 'BLOCK');
  assert.deepEqual(j.applicable.pending, ['content-hash']);
});
