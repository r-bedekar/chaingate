// U-05 gap-closure r2 (owner decision 6): health states (Addendum 1 §B) and FULL enforcement ordering (§C, revision 2
// §3.6 under F2), through a real in-process proxy. Expected values come from the addendum and revision 2, written before
// this file. FULL is a resource-safety refusal, not a finding about any package.
import test from 'node:test';
import assert from 'node:assert/strict';
import { withProxy, scriptedGate, TRIGGER, DROP, unreadableDoc, DOCS, tgz, versionsOf } from './u05-r2-proxy.mjs';
import { LIVE, WARNCFG } from './u05-fixtures.mjs';
import { witnessStorageCheck } from '../../cli/storage-check.js';
import { enforceTarballGate } from '../../proxy/server.js';
import { createUnstoredBlocks } from '../../proxy/unstored-blocks.js';

const CAP1 = { unstoredBlockCapEntries: 1 };
const alive = { pid: 4242, state: 'alive' };
const check = (self) => witnessStorageCheck({ pid: alive, self });
const failsDoctor = (c) => c.pass === false && !c.severity;

// ------------------------------------------------------------------------------------------------ §B health states
test('B1 a remembered BLOCK before any write attempt: HELD with no write-health evidence; never a pass', async () => {
  await withProxy({ cfg: LIVE, docs: { ...DOCS(), u: unreadableDoc('u') } }, async (h) => {
    assert.equal((await h.get('/u')).status, 200);
    const s = await h.self();
    assert.ok(s.unstored_blocks.count > 0, 'LIVE: the unreadable versions are remembered BLOCKs (no write attempted)');
    assert.equal(s.storage.state, 'held');
    assert.equal(s.storage.last_outcome, null, 'no write outcome at all');
    const c = check(s);
    assert.ok(failsDoctor(c), 'doctor fails (exit 1)');
    assert.match(c.detail, /no write-health evidence/);
    assert.doesNotMatch(c.detail, /writes? fail/i, 'an input refusal is not reported as a write failure');
  });
});

test('B2 failure before a decision is computed (a read): FAILING_HELD with stage read', async () => {
  await withProxy({ cfg: WARNCFG }, async (h) => {
    const real = h.proxy.witnessDb.getBaseline.bind(h.proxy.witnessDb);
    h.proxy.witnessDb.getBaseline = (n, v) => { if (n === 'p') throw new Error('injected read failure'); return real(n, v); };
    await h.get('/p');
    const s = await h.self();
    assert.equal(s.storage.state, 'failing_held');
    assert.equal(s.storage.last_failure.stage, 'read');
    assert.ok(failsDoctor(check(s)));
    assert.match(check(s).detail, /read/);
  });
});

test('B3 one observation with committed rows AND a failed row counts as a failure (failure dominates)', async () => {
  await withProxy({ cfg: WARNCFG }, async (h) => {
    h.exec(TRIGGER('p', '1.3.0'));
    await h.get('/p');
    const s = await h.self();
    assert.ok(h.proxy.witnessDb.getLatestDecision('p', '1.4.0'), 'p@1.4.0 committed in the same observation');
    assert.equal(s.storage.state, 'failing_held');
  });
  const gate = scriptedGate({ 'x@2.0.0': 'WARN' });
  await withProxy({ gateModules: [gate] }, async (h) => {
    h.exec(TRIGGER('x', '2.0.0'));
    await h.get('/x');
    const s = await h.self();
    assert.equal(s.unstored_blocks.count, 0, 'a WARN is not remembered');
    assert.equal(s.storage.state, 'failing', 'count 0 with a failed write: FAILING, not RECOVERED');
    assert.ok(failsDoctor(check(s)));
  });
});

test('B4 a later evaluated decision supersedes a memory-only BLOCK: RECOVERED, with the corrected wording', async () => {
  const gate = scriptedGate({ 'x@2.0.0': 'BLOCK' });
  await withProxy({ gateModules: [gate] }, async (h) => {
    h.exec(TRIGGER('x', '2.0.0'));
    await h.get('/x');
    assert.equal((await h.self()).storage.state, 'failing_held');
    h.exec(DROP('x', '2.0.0'));
    gate.verdicts['x@2.0.0'] = 'ALLOW';
    await h.get('/x');
    const s = await h.self();
    assert.equal(s.unstored_blocks.count, 0);
    assert.equal(s.storage.state, 'recovered');
    const c = check(s);
    assert.equal(c.pass, true);
    assert.match(c.detail, /stored, or superseded by a later evaluated decision/);
    assert.match(c.detail, /does not mean that every earlier BLOCK is stored/);
  });
});

test('B5 FULL with zero entries stays degraded; tarballs follow §C', async () => {
  const gate = scriptedGate({ 'x@2.0.0': 'BLOCK', 'y@2.0.0': 'BLOCK' });
  await withProxy({ gateModules: [gate], conf: CAP1 }, async (h) => {
    h.exec(TRIGGER('x', '2.0.0')); h.exec(TRIGGER('y', '2.0.0'));
    await h.get('/x'); await h.get('/y');
    let s = await h.self();
    assert.equal(s.unstored_blocks.full, true); assert.equal(s.storage.state, 'full_held');
    h.exec(DROP('x', '2.0.0')); h.exec(DROP('y', '2.0.0'));
    await h.get('/x');                                                  // x's BLOCK is now stored and forgotten
    s = await h.self();
    assert.equal(s.unstored_blocks.count, 0);
    assert.equal(s.storage.state, 'full_empty');
    assert.ok(failsDoctor(check(s)), 'FULL_EMPTY fails doctor');
    assert.equal((await h.tarball('x', '2.0.0')).status, 403, 'stored BLOCK');
    const y = await h.tarball('y', '2.0.0');
    assert.equal(y.status, 503, 'never remembered, never stored: refused while FULL');
    assert.equal(y.json?.error, 'chaingate_storage_degraded');
    assert.match(y.json?.detail ?? '', /resource-safety refusal; not a finding about this package/);
  });
});

test('B6 the remaining states: NO_EVIDENCE, HEALTHY, NOT_RUNNING, UNREACHABLE, and an old proxy without the field', async () => {
  await withProxy({ cfg: WARNCFG }, async (h) => {
    let s = await h.self();
    assert.equal(s.storage.state, 'no_evidence');
    let c = check(s); assert.equal(c.pass, true); assert.equal(c.severity, 'skipped');
    await h.get('/q');
    s = await h.self();
    assert.equal(s.storage.state, 'healthy');
    c = check(s); assert.equal(c.pass, true); assert.equal(c.severity, undefined);
  });
  const notRunning = witnessStorageCheck({ pid: null, self: null });
  assert.equal(notRunning.severity, 'skipped'); assert.equal(notRunning.state, 'not_running');
  const unreachable = witnessStorageCheck({ pid: alive, self: null });
  assert.equal(unreachable.severity, 'unverifiable'); assert.equal(unreachable.state, 'unreachable');
  const indeterminate = witnessStorageCheck({ pid: { pid: 4242, state: 'indeterminate', code: 'EPERM' }, self: null });
  assert.equal(indeterminate.severity, 'unverifiable');
  const old = witnessStorageCheck({ pid: alive, self: { service: 'chaingate-proxy', version: '0.1.3', unstored_blocks: { count: 0 } } });
  assert.equal(old.severity, 'unverifiable', 'a proxy that does not report storage health is not a pass');
});

// ------------------------------------------------------------------------------------------------ §C FULL ordering
/** Stored ALLOW (q), stored WARN (w), stored BLOCK (z), then x remembered and y overflowed: FULL. */
async function fullBench(cfg, fn) {
  const gate = scriptedGate({ 'w@2.0.0': 'WARN', 'z@2.0.0': 'BLOCK', 'x@2.0.0': 'BLOCK', 'y@2.0.0': 'BLOCK' });
  await withProxy({ cfg, gateModules: [gate], conf: CAP1 }, async (h) => {
    for (const p of ['/q', '/w', '/z']) assert.equal((await h.get(p)).status, 200);
    h.exec(TRIGGER('x', '2.0.0')); h.exec(TRIGGER('y', '2.0.0'));
    await h.get('/x'); await h.get('/y');
    assert.equal((await h.self()).unstored_blocks.full, true, 'FULL');
    await fn(h);
  });
}

for (const [label, cfg] of [['LIVE', LIVE], ['WARN', WARNCFG], ['pilot', null]]) {
  test(`R-8 / §C ${label}: every tarball return is ordered after FULL; only an established override is excepted`, async () => {
    await fullBench(cfg, async (h) => {
      const st = async (p) => (await h.get(p)).status;
      assert.equal(await st('/x/-/zzz-2.0.0.tgz'), 503, 'version not derivable: refused (today served)');
      assert.equal(await st(tgz('n', '9.9.9')), 503, 'no decision: refused');
      assert.equal(await st(tgz('q', '1.3.0')), 503, 'stored ALLOW is not permission while FULL');
      assert.equal(await st(tgz('w', '2.0.0')), 503, 'stored WARN is not permission while FULL');
      assert.equal(await st(tgz('z', '2.0.0')), 403, 'stored BLOCK');
      assert.equal(await st(tgz('x', '2.0.0')), 403, 'remembered BLOCK');
      assert.equal(await st(tgz('y', '2.0.0')), 503, 'the overflowed BLOCK: refused by FULL');
      h.proxy.witnessDb.insertOverride('y', '2.0.0', 'operator exception for the test');
      assert.equal(await st(tgz('y', '2.0.0')), 200, 'an established exact override is the only exception');
      const real = h.proxy.witnessDb.getOverride.bind(h.proxy.witnessDb);
      h.proxy.witnessDb.getOverride = () => { throw new Error('injected override lookup failure'); };
      assert.equal(await st(tgz('y', '2.0.0')), 503, 'an override that cannot be established does not permit');
      assert.equal(await st(tgz('z', '2.0.0')), 403);
      h.proxy.witnessDb.getOverride = real;
      const realLatest = h.proxy.witnessDb.getLatestDecision.bind(h.proxy.witnessDb);
      const realApplicable = h.proxy.witnessDb.getApplicableDecision.bind(h.proxy.witnessDb);
      // Vehicle (owner decision 10, C2): the FULL branch reads getApplicableDecision; the injection moves with it.
      h.proxy.witnessDb.getLatestDecision = () => { throw new Error('injected lookup failure'); };
      h.proxy.witnessDb.getApplicableDecision = () => { throw new Error('injected lookup failure'); };
      assert.equal(await st(tgz('q', '1.3.0')), 503, 'P6a while FULL');
      assert.equal(await st(tgz('x', '2.0.0')), 403, 'remembered still 403');
      h.proxy.witnessDb.getLatestDecision = () => ({ get disposition() { throw new Error('injected: record unreadable'); } });
      h.proxy.witnessDb.getApplicableDecision = () => ({ get block() { throw new Error('injected: record unreadable'); } });
      // Addendum §C step 5: a read that throws while FULL is refused by the FULL branch itself (503) under every
      // configuration; the outer-catch FULL rule is defence in depth. Today: LIVE 502, otherwise passthrough.
      assert.equal(await st(tgz('q', '1.3.0')), 503, 'an unreadable decision record while FULL: refused');
      h.proxy.witnessDb.getLatestDecision = realLatest;
      h.proxy.witnessDb.getApplicableDecision = realApplicable;
      const q = await h.get('/q');
      assert.equal(q.status, 200, 'the normal packument path is unchanged while FULL');
      h.proxy.witness.observePackument = () => { throw new Error('injected observation failure'); };
      h.proxy.witness.failureDecisionsFor = () => { throw new Error('injected failure-decision failure'); };
      const n = await h.get('/n');
      assert.equal(n.status, 502, 'P3 with no decision: refused under every configuration while FULL');
      assert.match(n.json?.detail ?? '', /full/i);
      assert.equal(await st('/'), 404, 'router-unsupported requests keep their refusal');
      assert.equal(await st('/-/ping'), 404);
    });
  });
}

test('§C missing database context does not bypass the FULL refusal (gate unit)', () => {
  const unstored = createUnstoredBlocks({ caps: { entries: 1, bytes: 1024 * 1024 } });
  unstored.note('a', '1', { disposition: 'BLOCK', persisted: false, results: [] });
  unstored.note('b', '1', { disposition: 'BLOCK', persisted: false, results: [] });
  assert.equal(unstored.full, true);
  const r = enforceTarballGate(null, 'b', 'b-1.tgz', null, { unstored, overriddenLive: () => false }, {});
  assert.equal(r?.refuse?.status, 503); assert.equal(r?.refuse?.error, 'chaingate_storage_degraded');
  const n = enforceTarballGate(null, 'b', 'not-a-tarball-name', null, { unstored, overriddenLive: () => false }, {});
  assert.equal(n?.refuse?.status, 503, 'and an unparseable identity');
});

test('outside FULL nothing changes for an unparseable tarball name or a never-observed version (normal scope not broadened)', async () => {
  await withProxy({ cfg: WARNCFG }, async (h) => {
    assert.equal((await h.get('/x/-/zzz-2.0.0.tgz')).status, 200);
    assert.equal((await h.get(tgz('n', '9.9.9'))).status, 200);
  });
});

// ------------------------------------------------------------------------------------------------ R cases via the proxy
test('R-6 counterexample: an older stored ALLOW never permits a newer unstored BLOCK, with or without FULL', async () => {
  const gate = scriptedGate({});
  await withProxy({ gateModules: [gate], conf: { unstoredBlockCapEntries: 1 } }, async (h) => {
    await h.get('/x'); await h.get('/y');                               // stored ALLOW for x@2.0.0 and y@2.0.0
    gate.verdicts['x@2.0.0'] = 'BLOCK'; gate.verdicts['y@2.0.0'] = 'BLOCK';
    h.exec(TRIGGER('x', '2.0.0')); h.exec(TRIGGER('y', '2.0.0'));
    await h.get('/x');
    assert.equal((await h.tarball('x', '2.0.0')).status, 403, 'memory first: 403');
    await h.get('/y');                                                 // y's BLOCK overflows
    assert.equal((await h.self()).unstored_blocks.full, true);
    assert.equal((await h.tarball('y', '2.0.0')).status, 503, 'the stored ALLOW is not permission while FULL');
  });
});

test('R-2 via the proxy: an over-long package name BLOCK sends the record to FULL (identity never truncated)', async () => {
  const long = 'a'.repeat(215);
  const docs = { ...DOCS(), [long]: { ...DOCS().x, name: long } };
  const gate = scriptedGate({ [`${long}@2.0.0`]: 'BLOCK' });
  await withProxy({ gateModules: [gate], docs }, async (h) => {
    h.exec(TRIGGER(long, '2.0.0'));
    const r = await h.get(`/${long}`);
    assert.equal(r.status, 200); assert.ok(!versionsOf(r).includes('2.0.0'), 'the packument still omits it');
    const s = await h.self();
    assert.equal(s.unstored_blocks.full, true); assert.equal(s.unstored_blocks.identity_rejected, 1);
    assert.equal((await h.get(tgz(long, '2.0.0'))).status, 503);
    assert.equal((await h.tarball('q', '1.3.0')).status, 503, 'every tarball without a stored BLOCK or override');
  });
});

test('invalid caps refuse start-up by name', async () => {
  await assert.rejects(withProxy({ conf: { unstoredBlockCapEntries: 0 } }, async () => {}), /unstored_block_cap_entries/);
  await assert.rejects(withProxy({ conf: { unstoredBlockCapBytes: 1024 } }, async () => {}), /unstored_block_cap_bytes/);
});
