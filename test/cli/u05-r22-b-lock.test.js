// U-05 R2-2 (b): every seed mutator is coordinated by one kernel-released lock per base; an interrupted symlink activation
// is recovered from an intent journal; leftovers of dead mutators are removed conservatively (R2-2 §2, Addendum 1 §2-3,
// Addendum 2 §3.1 and §3.4). Failing-first: the first mutator runs as the REAL command function in a child
// (u05-r22-mutator.mjs) paused or killed at a named hook; the second is the real CLI. Where the only way to reach a case
// is a hook that the unfixed code does not have, the result there is SEAM-ABSENT, not a demonstrated defect.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { activeBundleId, previousBundleId, seedsDir, activeLink, previousLink, bundleFiles } from '../../cli/seed-bundle.js';
import { ROOT, v3Host, v3Variant, runCli, runProxyEntry, startMutator, sha256, exists, age, deadPid, canFifo, mkfifo }
  from '../helpers/u05-r22.mjs';

const POSIX = process.platform !== 'win32';
const posixOnly = { skip: POSIX ? false : 'POSIX symlink activation (Windows uses one atomic record)' };
const SEEDARGS = (s) => ['--seed', s.db, '--unsigned-development'];
const state = (base) => ({ active: activeBundleId(base), previous: previousBundleId(base) });
const CONTENTION = /another seed command .*is running/;
const manifestSha = (base, id) => JSON.parse(fs.readFileSync(path.join(seedsDir(base), id, 'bundle.json'), 'utf8')).sha256;
const doctorChecks = (r) => { try { return JSON.parse(r.stdout); } catch { assert.fail(`doctor --json printed no JSON:\n${r.out}`); } };
const INTENT = (base) => path.join(seedsDir(base), '.activation-intent.json');
/** Killed at the hook: SIGKILL on POSIX; on Windows the child ends with a non-zero code and no signal (TerminateProcess). */
const assertKilled = (r) => assert.ok(r.signal === 'SIGKILL' || (process.platform === 'win32' && r.code !== 0 && r.code !== null), `not killed: ${JSON.stringify({ code: r.code, signal: r.signal })}`);

/** Install `s` as a new active bundle through the real CLI; returns its bundle id. */
async function install(h, s) {
  const r = await runCli(h.base, ['update-seed', ...SEEDARGS(s)], { timeoutMs: 30000 });
  assert.equal(r.code, 0, r.out);
  return activeBundleId(h.base);
}

// ---- B1 / B1' / B11: a second mutator while the first is in progress -------------------------------------------------
test('B1 update-seed while another update-seed is mid-staging: the second is REFUSED and changes nothing', async () => {
  const h = await v3Host(); const y1 = await v3Variant('1', { padTo: 3 << 20 }); const y2 = await v3Variant('2');
  try {
    const m1 = startMutator(h.base, 'update-seed', SEEDARGS(y1), { pauseAt: 'midStagingCopy' });
    assert.equal(await m1.at('midStagingCopy'), true, 'the first mutator reached the staging copy');
    const r2 = await runCli(h.base, ['update-seed', ...SEEDARGS(y2)], { timeoutMs: 20000 });
    m1.go(); const r1 = await m1.done;
    assert.equal(r2.code, 1, `the second mutator must be refused\n${r2.out}`);
    assert.match(r2.out, CONTENTION);
    assert.equal(r1.code, 0, r1.all);
    const s = state(h.base);
    assert.equal(manifestSha(h.base, s.active), sha256(y1.db), 'the first mutator\'s bundle is active');
    assert.equal(s.previous, h.id, 'the chain is (Y1, A0): nothing from the refused mutator');
  } finally { y1.cleanup(); y2.cleanup(); h.cleanup(); }
});

test("B1b the activation-read interleaving: M2(Y1) paused after reading active; M2(Y2) refused; result (Y1, A0)", async () => {
  const h = await v3Host(); const y1 = await v3Variant('1'); const y2 = await v3Variant('2');
  try {
    const m1 = startMutator(h.base, 'update-seed', SEEDARGS(y1), { pauseAt: 'afterActiveRead' });
    assert.equal(await m1.at('afterActiveRead'), true, 'SEAM-ABSENT: no afterActiveRead point');
    const r2 = await runCli(h.base, ['update-seed', ...SEEDARGS(y2)], { timeoutMs: 20000 });
    m1.go(); const r1 = await m1.done;
    assert.equal(r2.code, 1, r2.out); assert.match(r2.out, CONTENTION); assert.equal(r1.code, 0, r1.all);
    assert.equal(state(h.base).previous, h.id);
  } finally { y1.cleanup(); y2.cleanup(); h.cleanup(); }
});

test("B1' init --seed while update-seed is in progress: init is refused, starts no proxy, changes nothing", async () => {
  const h = await v3Host(); const y1 = await v3Variant('1', { padTo: 3 << 20 }); const y2 = await v3Variant('2');
  try {
    const m1 = startMutator(h.base, 'update-seed', SEEDARGS(y1), { pauseAt: 'midStagingCopy' });
    assert.equal(await m1.at('midStagingCopy'), true);
    const r2 = await runCli(h.base, ['init', ...SEEDARGS(y2)], { timeoutMs: 30000 });
    m1.go(); await m1.done;
    assert.equal(r2.spawnedProxy, undefined, 'init started a proxy');
    assert.equal(r2.code, 1, r2.out); assert.match(r2.out, CONTENTION);
  } finally { y1.cleanup(); y2.cleanup(); h.cleanup(); }
});

test('B11 legacy-route commands while update-seed is in progress are refused by the lock', async () => {
  const h = await v3Host(); const y1 = await v3Variant('1', { padTo: 3 << 20 });
  try {
    const m1 = startMutator(h.base, 'update-seed', SEEDARGS(y1), { pauseAt: 'midStagingCopy' });
    assert.equal(await m1.at('midStagingCopy'), true);
    const legacy = path.join(ROOT, 'test', 'fixtures', 'test-seed-bundle', 'chaingate-seed.db');
    const results = {
      'init --seed <legacy> --force': await runCli(h.base, ['init', '--seed', legacy, '--force'], { timeoutMs: 30000 }),
      'plain update-seed': await runCli(h.base, ['update-seed'], { timeoutMs: 30000 }),
    };
    m1.go(); await m1.done;
    for (const [k, r] of Object.entries(results)) {
      assert.equal(r.spawnedProxy, undefined, `${k} started a proxy`);
      assert.match(r.out, CONTENTION, `${k}: not refused by the lock\n${r.out}`);
    }
  } finally { y1.cleanup(); h.cleanup(); }
});

test('B3 update-seed while a rollback is paused after its previous read: refused; the result is the rollback alone', async () => {
  const h = await v3Host(); const y1 = await v3Variant('1'); const y2 = await v3Variant('2');
  try {
    const a1 = await install(h, y1);                               // (A1, A0)
    const m = startMutator(h.base, 'update-seed', ['--rollback'], { pauseAt: 'afterPreviousRead' });
    assert.equal(await m.at('afterPreviousRead'), true, 'SEAM-ABSENT: no afterPreviousRead point');
    const r2 = await runCli(h.base, ['update-seed', ...SEEDARGS(y2)], { timeoutMs: 20000 });
    m.go(); const r = await m.done;
    assert.equal(r2.code, 1, r2.out); assert.match(r2.out, CONTENTION); assert.equal(r.code, 0, r.all);
    assert.deepEqual(state(h.base), { active: h.id, previous: a1 });
  } finally { y1.cleanup(); y2.cleanup(); h.cleanup(); }
});

// ---- B7: readers never take or wait on the lock -----------------------------------------------------------------------
test('B7 guard: proxy start, doctor and status complete while a mutator holds the lock', async () => {
  const h = await v3Host(); const y1 = await v3Variant('1', { padTo: 3 << 20 });
  try {
    const m1 = startMutator(h.base, 'update-seed', SEEDARGS(y1), { pauseAt: 'midStagingCopy' });
    assert.equal(await m1.at('midStagingCopy'), true);
    const p = await runProxyEntry(h.base, { timeoutMs: 15000, until: /listening on/ });
    const d = await runCli(h.base, ['doctor', '--json'], { timeoutMs: 15000 });
    const st = await runCli(h.base, ['status', '--json'], { timeoutMs: 15000 });
    m1.go(); await m1.done;
    assert.equal(p.matched, true, `the proxy did not start while the lock was held\n${p.out}`);
    assert.equal(d.timedOut, false); assert.ok(Array.isArray(doctorChecks(d)));
    assert.equal(st.timedOut, false); assert.equal(st.code, 0, st.out);
  } finally { y1.cleanup(); h.cleanup(); }
});

// ---- B4 / D3k: a mutator killed mid-copy; the next one cleans up under the lock ---------------------------------------
test('D3k a mutator killed mid-copy leaves partial staging; the next mutator removes it (dead pid, old enough)', async () => {
  const h = await v3Host(); const y1 = await v3Variant('1', { padTo: 3 << 20 }); const y2 = await v3Variant('2');
  try {
    const m1 = startMutator(h.base, 'update-seed', SEEDARGS(y1), { killAt: 'midStagingCopy' });
    assert.equal(await m1.at('midStagingCopy'), true); const r1 = await m1.done;
    assertKilled(r1);
    const left = fs.readdirSync(seedsDir(h.base)).filter((n) => n.startsWith('.staging-'));
    assert.equal(left.length, 1, 'the killed copy left its staging directory');
    age(path.join(seedsDir(h.base), left[0]), 20);
    const r2 = await runCli(h.base, ['update-seed', ...SEEDARGS(y2)], { timeoutMs: 20000 });
    assert.equal(r2.code, 0, r2.out);
    assert.equal(exists(path.join(seedsDir(h.base), left[0])), false, 'the dead mutator\'s staging was removed');
    assert.equal(state(h.base).previous, h.id);
  } finally { y1.cleanup(); y2.cleanup(); h.cleanup(); }
});

// ---- RC: the intent journal, every row of Addendum 1 §2.3, through the real commands ----------------------------------
// K0 = after the intent is published, K1 = after the previous swap, K2 = after the active swap (before the intent is
// removed). The next mutator is one that changes nothing itself after recovery: plain update-seed on a v3 host refuses,
// update-seed --rollback with no previous refuses.
const K = { K0: 'afterIntentPublish', K1: 'betweenRenames', K2: 'afterActiveSwap' };
async function killAndRecover(h, args, k) {
  const m = startMutator(h.base, 'update-seed', args, { killAt: K[k] });
  const reached = await m.at(K[k]); await m.done;
  assert.equal(reached, true, `SEAM-ABSENT: no ${K[k]} point`);
  const mid = state(h.base);
  const next = await runCli(h.base, ['update-seed'], { timeoutMs: 20000 });
  assert.equal(next.timedOut, false);
  return { mid, after: state(h.base), next };
}

for (const k of ['K0', 'K1', 'K2']) {
  test(`RC normal update (A,P) -> (T,A), killed at ${k}: recovered to ${k === 'K2' ? 'after' : 'before'}`, posixOnly, async () => {
    const h = await v3Host(); const p = await v3Variant('1'); const t = await v3Variant('2');
    try {
      const a = await install(h, p);                                  // (A=p, P=h.id)
      const r = await killAndRecover(h, SEEDARGS(t), k);
      if (k === 'K1') assert.deepEqual(r.mid, { active: a, previous: a }, 'the interrupted state is (A, A)');
      const want = k === 'K2' ? { active: activeBundleId(h.base), previous: a } : { active: a, previous: h.id };
      assert.deepEqual(r.after, want);
      if (k === 'K2') assert.equal(manifestSha(h.base, r.after.active), sha256(t.db));
      assert.equal(exists(INTENT(h.base)), false, 'the intent is removed once recovered');
    } finally { p.cleanup(); t.cleanup(); h.cleanup(); }
  });

  test(`RC rollback (A,P) -> (P,A), killed at ${k}`, posixOnly, async () => {
    const h = await v3Host(); const p = await v3Variant('1');
    try {
      const a = await install(h, p);                                  // (A=p, P=h.id)
      const r = await killAndRecover(h, ['--rollback'], k);
      assert.deepEqual(r.after, k === 'K2' ? { active: h.id, previous: a } : { active: a, previous: h.id });
    } finally { p.cleanup(); h.cleanup(); }
  });
}

for (const k of ['K0', 'K2']) {
  test(`RC reactivating the active bundle (A,P) -> (A,P), killed at ${k}: previous stays P (F-L1)`, posixOnly, async () => {
    const h = await v3Host(); const p = await v3Variant('1');
    try {
      const a = await install(h, p);                                  // (A=p, P=h.id)
      const r = await killAndRecover(h, SEEDARGS(p), k);              // the same bundle again
      assert.deepEqual(r.after, { active: a, previous: h.id });
    } finally { p.cleanup(); h.cleanup(); }
  });
}

test('RC8 killed during recovery three times, then retried: converges; the chain is never progressively altered', posixOnly, async () => {
  const h = await v3Host(); const p = await v3Variant('1'); const t = await v3Variant('2');
  try {
    const a = await install(h, p);
    const m = startMutator(h.base, 'update-seed', SEEDARGS(t), { killAt: K.K1 });
    assert.equal(await m.at(K.K1), true, `SEAM-ABSENT: no ${K.K1} point`); await m.done;
    for (let i = 0; i < 3; i += 1) {
      const r = startMutator(h.base, 'update-seed', [], { killAt: 'duringRecovery' });
      assert.equal(await r.at('duringRecovery'), true, 'SEAM-ABSENT: no duringRecovery point'); await r.done;
      assert.equal(exists(INTENT(h.base)), true, 'an interrupted recovery keeps the intent');
      assert.equal(activeBundleId(h.base), a, 'recovery never changes active');
    }
    const fin = await runCli(h.base, ['update-seed'], { timeoutMs: 20000 });
    assert.equal(fin.timedOut, false);
    assert.deepEqual(state(h.base), { active: a, previous: h.id });
    assert.equal(exists(INTENT(h.base)), false);
  } finally { p.cleanup(); t.cleanup(); h.cleanup(); }
});

// ---- RC9: what recovery refuses -------------------------------------------------------------------------------------
function writeIntent(base, rec) { fs.writeFileSync(INTENT(base), typeof rec === 'string' ? rec : `${JSON.stringify(rec)}\n`); }
const intentRec = (before, after) => ({ schema: 'chaingate-activation-intent/1', op: 'activate', before, after, pid: 1,
  at: new Date().toISOString() });

test('RC9a an invalid intent refuses every mutator and is preserved as evidence', posixOnly, async () => {
  const h = await v3Host(); const t = await v3Variant('2');
  try {
    writeIntent(h.base, '{ this is not json');
    const before = state(h.base);
    const r = await runCli(h.base, ['update-seed', ...SEEDARGS(t)], { timeoutMs: 20000 });
    assert.equal(r.code, 1, r.out);
    assert.match(r.out, /activation intent .* is not valid/);
    assert.match(r.out, /\.activation-intent\.json\.held-/, 'the documented archive path is given');
    assert.equal(fs.readFileSync(INTENT(h.base), 'utf8'), '{ this is not json', 'preserved unchanged');
    assert.deepEqual(state(h.base), before);
  } finally { t.cleanup(); h.cleanup(); }
});

test('RC9b an intent whose recovery needs a bundle that no longer exists: refused, intent and links kept', posixOnly, async () => {
  const h = await v3Host(); const p = await v3Variant('1'); const t = await v3Variant('2');
  try {
    const a = await install(h, p);                                     // (a, h.id)
    // an update a -> T was interrupted at K1: (a, a) on disk; recovery would restore previous = h.id, which is gone
    fs.rmSync(previousLink(h.base)); fs.symlinkSync(a, previousLink(h.base));
    writeIntent(h.base, intentRec({ active: a, previous: h.id }, { active: 'ffffffffffffffff', previous: a }));
    fs.chmodSync(path.join(seedsDir(h.base), h.id), 0o755);
    for (const f of Object.values(bundleFiles(path.join(seedsDir(h.base), h.id)))) { try { fs.chmodSync(f, 0o644); } catch { /* absent */ } }
    fs.rmSync(path.join(seedsDir(h.base), h.id), { recursive: true, force: true });
    const r = await runCli(h.base, ['update-seed', ...SEEDARGS(t)], { timeoutMs: 20000 });
    assert.equal(r.code, 1, r.out);
    assert.match(r.out, new RegExp(`${h.id}.*no longer exists`));
    assert.equal(exists(INTENT(h.base)), true, 'the intent is kept');
    assert.deepEqual(state(h.base), { active: a, previous: a }, 'the links are kept as they were');
  } finally { p.cleanup(); t.cleanup(); h.cleanup(); }
});

test('RC9c active moved outside the protocol (neither before nor after): refused, intent kept', posixOnly, async () => {
  const h = await v3Host(); const p = await v3Variant('1'); const t = await v3Variant('2');
  try {
    const a = await install(h, p);                                     // (a, h.id)
    writeIntent(h.base, intentRec({ active: h.id, previous: null }, { active: 'eeeeeeeeeeeeeeee', previous: h.id }));
    const r = await runCli(h.base, ['update-seed', ...SEEDARGS(t)], { timeoutMs: 20000 });
    assert.equal(r.code, 1, r.out);
    assert.match(r.out, /changed outside/);
    assert.equal(exists(INTENT(h.base)), true);
    assert.deepEqual(state(h.base), { active: a, previous: h.id });
  } finally { p.cleanup(); t.cleanup(); h.cleanup(); }
});

test('doctor and status report a pending intent read-only, and repair nothing', posixOnly, async () => {
  const h = await v3Host();
  try {
    writeIntent(h.base, intentRec({ active: h.id, previous: null }, { active: h.id, previous: null }));
    const d = await runCli(h.base, ['doctor', '--json'], { timeoutMs: 15000 });
    const c = doctorChecks(d).find((x) => x.name === 'seed-activation-intent');
    assert.ok(c, 'doctor has a seed-activation-intent check');
    assert.equal(c.pass, false); assert.match(c.detail, /an interrupted activation is pending/);
    const s = await runCli(h.base, ['status', '--json'], { timeoutMs: 15000 });
    assert.equal(JSON.parse(s.stdout).seed_v3.pending_intent, true);
    assert.equal(exists(INTENT(h.base)), true, 'readers do not recover');
  } finally { h.cleanup(); }
});

// ---- LK: the reporting classes, through the real command ---------------------------------------------------------------
test('LK2 permission: a base where the lock file cannot be created refuses with the permission class', {
  skip: POSIX && process.getuid?.() !== 0 ? false : 'needs a non-root POSIX user',
}, async () => {
  const h = await v3Host(); const t = await v3Variant('2');
  try {
    fs.rmSync(path.join(h.base, '.seed-mutation.lock'), { force: true });   // the setup may have created it
    fs.chmodSync(h.base, 0o555);
    const r = await runCli(h.base, ['update-seed', ...SEEDARGS(t)], { timeoutMs: 20000 });
    fs.chmodSync(h.base, 0o755);
    assert.equal(r.code, 1, r.out);
    assert.match(r.out, /cannot create or open the lock file/);
    assert.equal(activeBundleId(h.base), h.id);
  } finally { try { fs.chmodSync(h.base, 0o755); } catch { /* restored */ } t.cleanup(); h.cleanup(); }
});

test('LK3 corruption: a lock file that is not a SQLite database refuses with the damaged class', async () => {
  const h = await v3Host(); const t = await v3Variant('2');
  try {
    fs.writeFileSync(path.join(h.base, '.seed-mutation.lock'), 'this is not a database, it is a note\n'.repeat(200));
    const r = await runCli(h.base, ['update-seed', ...SEEDARGS(t)], { timeoutMs: 20000 });
    assert.equal(r.code, 1, r.out);
    assert.match(r.out, /lock file .* is damaged/);
    assert.equal(activeBundleId(h.base), h.id);
  } finally { t.cleanup(); h.cleanup(); }
});

test('LK3b corruption: a FIFO at the lock path is refused promptly, never opened by SQLite', {
  skip: canFifo ? false : 'needs mkfifo (POSIX)',
}, async () => {
  const h = await v3Host(); const t = await v3Variant('2');
  try {
    fs.rmSync(path.join(h.base, '.seed-mutation.lock'), { force: true });   // the setup may have created it
    mkfifo(path.join(h.base, '.seed-mutation.lock'));
    const r = await runCli(h.base, ['update-seed', ...SEEDARGS(t)], { timeoutMs: 15000 });
    assert.equal(r.timedOut, false, 'blocked on the lock path');
    assert.equal(r.code, 1, r.out); assert.match(r.out, /lock file .* is damaged/);
  } finally { t.cleanup(); h.cleanup(); }
});

// ---- CL: conservative cleanup of leftovers -------------------------------------------------------------------------------
function leftovers(h, pid) {
  const s = seedsDir(h.base);
  const made = {
    staging: path.join(s, `.staging-${pid}-1700000000000`),
    activeSw: path.join(s, `active.switching-${pid}`),
    prevSw: path.join(s, `previous.switching-${pid}`),
    ptrTmp: path.join(s, `activation.json.tmp-${pid}`),
    intentTmp: path.join(s, `.activation-intent.json.tmp-${pid}`),
    witnessStaging: path.join(h.base, `witness.db.staging-${pid}`),
  };
  fs.mkdirSync(made.staging); fs.writeFileSync(path.join(made.staging, 'chaingate-seed-v3.db'), 'partial');
  if (POSIX) { fs.symlinkSync(h.id, made.activeSw); fs.symlinkSync(h.id, made.prevSw); }
  for (const f of [made.ptrTmp, made.intentTmp, made.witnessStaging]) fs.writeFileSync(f, 'x');
  return made;
}

test('CL1 leftovers of a DEAD pid older than 15 minutes are removed by the next mutator; the lock file never', async () => {
  const h = await v3Host();
  try {
    const pid = deadPid();
    const made = leftovers(h, pid);
    for (const p of Object.values(made)) if (exists(p)) age(p, 20);
    const r = await runCli(h.base, ['update-seed'], { timeoutMs: 20000 });       // refuses after cleanup on a v3 host
    assert.equal(r.timedOut, false);
    const remaining = Object.entries(made).filter(([, p]) => exists(p)).map(([k]) => k);
    assert.deepEqual(remaining, [], `not removed: ${remaining.join(', ')}`);
    assert.equal(exists(path.join(h.base, '.seed-mutation.lock')), true, 'the lock file is permanent');
  } finally { h.cleanup(); }
});

test('CL2 leftovers of a LIVE pid, or young ones of a dead pid, are kept (and doctor reports them)', async () => {
  const h = await v3Host();
  try {
    const alive = leftovers(h, process.pid);                          // this test runner: alive
    for (const p of Object.values(alive)) if (exists(p)) age(p, 20);
    const young = leftovers(h, deadPid());                            // dead, but just made
    const r = await runCli(h.base, ['update-seed'], { timeoutMs: 20000 });
    assert.equal(r.timedOut, false);
    for (const [k, p] of [...Object.entries(alive), ...Object.entries(young)]) if (POSIX || !/Sw$/.test(k)) assert.equal(exists(p), true, `${k} was removed`);
    const d = await runCli(h.base, ['doctor', '--json'], { timeoutMs: 15000 });
    const c = doctorChecks(d).find((x) => x.name === 'seed-leftovers');
    assert.ok(c, 'doctor has a seed-leftovers check');
    assert.match(c.detail, new RegExp(`\\.staging-${process.pid}-`));
  } finally { h.cleanup(); }
});

test('CL3/CL4 unknown names, repair copies and damaged bundles are kept; unknown ones are reported by doctor', async () => {
  const h = await v3Host();
  try {
    const s = seedsDir(h.base);
    const keep = [path.join(s, '.staging-notapid'), path.join(s, 'random-note.txt'), path.join(s, `${h.id}.r2`),
      path.join(s, `${h.id}.damaged-1700000000000`)];
    fs.mkdirSync(keep[0]); fs.writeFileSync(keep[1], 'mine'); fs.mkdirSync(keep[2]); fs.mkdirSync(keep[3]);
    for (const p of keep) age(p, 60);
    const r = await runCli(h.base, ['update-seed'], { timeoutMs: 20000 });
    assert.equal(r.timedOut, false);
    for (const p of keep) assert.equal(exists(p), true, `${path.basename(p)} was removed`);
    const c = doctorChecks(await runCli(h.base, ['doctor', '--json'], { timeoutMs: 15000 })).find((x) => x.name === 'seed-leftovers');
    assert.ok(c); assert.match(c.detail, /random-note\.txt/); assert.match(c.detail, /\.staging-notapid/);
  } finally { h.cleanup(); }
});

// ---- B10: the lock file is touched by the lock module only ---------------------------------------------------------------
test('B10 the lock path is named in exactly one runtime module', () => {
  const hits = [];
  const walk = (d) => { for (const n of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, n.name);
    if (n.isDirectory()) walk(p); else if (/\.(m?js)$/.test(n.name) && fs.readFileSync(p, 'utf8').includes('.seed-mutation.lock')) hits.push(path.relative(ROOT, p).split(path.sep).join('/'));
  } };
  for (const d of ['cli', 'proxy', 'witness', 'seed', 'gates']) walk(path.join(ROOT, d));
  if (fs.readFileSync(path.join(ROOT, 'config-store.js'), 'utf8').includes('.seed-mutation.lock')) hits.push('config-store.js');
  assert.deepEqual(hits, ['cli/seed-mutation-lock.js']);
});
