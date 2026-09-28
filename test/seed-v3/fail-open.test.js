// CFT-05 — the paths that turned "the check could not run" into "the package is fine".
//
// D1's fail-open is right for a pattern gate that could not run: one broken module among several
// that still produced evidence should not block an install. It was NOT right once a gate can BLOCK
// on a recorded advisory naming this exact version, because every one of these paths discarded that
// BLOCK without saying so:
//
//   1. gates/index.js   a module that THREW became SKIP, and SKIP does not count toward the
//                       disposition -> ALLOW
//   2. gates/index.js   a module returning MALFORMED output became SKIP -> ALLOW
//   3. witness/store.js runGates throwing was answered with a hand-written `disposition: 'ALLOW'`
//   4. witness/store.js a per-version failure was answered with `{disposition:'ALLOW', results:[]}`
//   5. witness/store.js a version whose manifest could not be parsed got NO decision at all, and
//                       gates/rewriter.js keeps a version with no decision
//   6. witness/store.js a transaction failure THREW, and
//   7. proxy/server.js  answered that throw by serving the packument RAW -- every decision in the
//                       document lost, silently
//
// The fix is not to make D1 fail closed: a module now DECLARES what its own failure means, and the
// runner still invents nothing. A module declaring neither `onError` nor `onErrorResult` behaves
// exactly as before, which is what every pilot gate does.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createGateRunner } from '../../gates/index.js';
import { rewritePackument } from '../../gates/rewriter.js';
import { openWitnessDB } from '../../witness/db.js';
import { createWitness } from '../../witness/store.js';

const PKG = 'p';
const HISTORY = Array.from({ length: 10 }, (_, i) => ({ version: `0.${i}.0` }));

const throwingGate = (over = {}) => ({
  name: 'seed-v3',
  evaluate() { throw new Error('seed is unreadable'); },
  ...over,
});
const malformedGate = (over = {}) => ({
  name: 'seed-v3',
  evaluate() { return { nonsense: true }; },
  ...over,
});
/** A pilot-shaped gate: declares nothing, so its failure must still be a SKIP. */
const pilotGate = { name: 'content-hash', evaluate() { throw new Error('boom'); } };

const input = (version = '1.0.0') => ({
  ecosystem: 'npm', packageName: PKG, version, incoming: {}, baseline: null, history: HISTORY,
});

// --- 1 & 2: the runner ----------------------------------------------------------------------------
test('a gate that throws no longer silently becomes ALLOW when it declares otherwise', () => {
  const open = createGateRunner({ modules: [throwingGate()] })(input());
  assert.equal(open.disposition, 'ALLOW', 'undeclared: D1 behaviour is unchanged');
  assert.equal(open.results[0].result, 'SKIP');

  const closed = createGateRunner({ modules: [throwingGate({ onErrorResult: 'BLOCK' })] })(input());
  assert.equal(closed.disposition, 'BLOCK');
  assert.match(closed.results[0].detail, /gate_error: seed is unreadable/);
});

test('a gate states what its failure means through onError, and the runner does not invent it', () => {
  const mod = throwingGate({
    onErrorResult: 'BLOCK',
    onError: (err) => ({ gate: 'seed-v3', result: 'WARN', detail: `policy says warn: ${err.message}` }),
  });
  const r = createGateRunner({ modules: [mod] })(input());
  assert.equal(r.disposition, 'WARN', 'onError wins over the declared fallback');
  assert.match(r.results[0].detail, /policy says warn/);
});

test('a gate whose own onError throws falls back to what it DECLARED, never to a silent skip', () => {
  const mod = throwingGate({
    onErrorResult: 'BLOCK',
    onError() { throw new Error('handler broke too'); },
  });
  const r = createGateRunner({ modules: [mod] })(input());
  assert.equal(r.disposition, 'BLOCK');
  assert.match(r.results[0].detail, /onError also threw/);
});

test('MALFORMED gate output is held to the same declaration as a throw', () => {
  assert.equal(createGateRunner({ modules: [malformedGate()] })(input()).disposition, 'ALLOW');
  const closed = createGateRunner({ modules: [malformedGate({ onErrorResult: 'BLOCK' })] })(input());
  assert.equal(closed.disposition, 'BLOCK');
  assert.equal(closed.results[0].detail, 'malformed gate output');
});

test('every pilot gate declares nothing, so D1 fail-open is untouched for them', async () => {
  const { DEFAULT_GATE_MODULES } = await import('../../gates/index.js');
  for (const mod of DEFAULT_GATE_MODULES) {
    assert.equal(mod.onError, undefined, `${mod.name} must not have gained an onError`);
    assert.equal(mod.onErrorResult, undefined, `${mod.name} must not have gained an onErrorResult`);
  }
  assert.equal(createGateRunner({ modules: [pilotGate] })(input()).disposition, 'ALLOW');
});

test('failureDecision asks every module, and is ALLOW when none of them declares anything', () => {
  const none = createGateRunner({ modules: [pilotGate] });
  assert.equal(none.failureDecision(new Error('x')).disposition, 'ALLOW');
  const closed = createGateRunner({ modules: [throwingGate({ onErrorResult: 'BLOCK' })] });
  assert.equal(closed.failureDecision(new Error('x')).disposition, 'BLOCK');
});

// --- 3 to 6: the witness store ----------------------------------------------------------------------
function witnessWith(modules, dir) {
  const db = openWitnessDB(join(dir, 'witness.db'));
  db.applySchema();
  const runGates = createGateRunner({ modules });
  return { witness: createWitness({ db, runGates, config: {} }), db };
}

const packumentWith = (versions) => ({
  name: PKG,
  'dist-tags': { latest: Object.keys(versions).at(-1) },
  time: Object.fromEntries(Object.keys(versions).map((v) => [v, '2026-01-01T00:00:00.000Z'])),
  versions,
});
const manifest = (v) => ({ name: PKG, version: v, dist: { shasum: 'a', tarball: `https://x/${v}.tgz` } });

test('a version whose manifest cannot be parsed gets a DECISION, not silence', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cft05-failopen-'));
  try {
    const { witness, db } = witnessWith([throwingGate({ onErrorResult: 'BLOCK' })], dir);
    // `parseVersionsFromPackument` drops a non-object manifest, so this version never reached the
    // gate loop -- and the rewriter keeps a version with no decision entry.
    const doc = packumentWith({ '1.0.0': manifest('1.0.0'), '2.0.0': null });
    const observed = witness.observePackument(PKG, doc);
    assert.ok(observed.decisions.has('2.0.0'), 'the unparseable version must still be decided');
    assert.equal(observed.decisions.get('2.0.0').disposition, 'BLOCK');
    // and the rewriter then actually removes it
    const { packument: out } = rewritePackument(doc, observed.decisions);
    assert.equal(Object.prototype.hasOwnProperty.call(out.versions, '2.0.0'), false);
    db.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a packument with NO readable manifests is decided, not served unexamined', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cft05-failopen-'));
  try {
    const { witness, db } = witnessWith([throwingGate({ onErrorResult: 'BLOCK' })], dir);
    const doc = packumentWith({ '1.0.0': null, '2.0.0': 'not an object' });
    const observed = witness.observePackument(PKG, doc);
    assert.equal(observed.decisions.size, 2);
    for (const v of ['1.0.0', '2.0.0']) {
      assert.equal(observed.decisions.get(v).disposition, 'BLOCK', v);
    }
    db.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('an observation that fails outright yields decisions for every version in the document', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cft05-failopen-'));
  try {
    const { witness, db } = witnessWith([throwingGate({ onErrorResult: 'BLOCK' })], dir);
    const doc = packumentWith({ '1.0.0': manifest('1.0.0'), '2.0.0': manifest('2.0.0') });
    const observed = witness.failureDecisionsFor(doc, new Error('database is locked'));
    assert.equal(observed.failed, true);
    assert.equal(observed.decisions.size, 2);
    for (const v of ['1.0.0', '2.0.0']) {
      const d = observed.decisions.get(v);
      assert.equal(d.disposition, 'BLOCK', v);
      assert.match(JSON.stringify(d.results), /database is locked/);
    }
    // with no declaring module it is ALLOW -- the previous behaviour, now stated rather than assumed
    const plain = witnessWith([pilotGate], dir);
    assert.equal(plain.witness.failureDecisionsFor(doc, new Error('x')).decisions.get('1.0.0')
      .disposition, 'ALLOW');
    plain.db.close();
    db.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a version whose gate run throws is decided by declaration, not by a hand-written ALLOW', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cft05-failopen-'));
  try {
    // A runner that throws outright, which is what `runGates threw` answered with ALLOW before.
    const db = openWitnessDB(join(dir, 'witness.db'));
    db.applySchema();
    const base = createGateRunner({ modules: [throwingGate({ onErrorResult: 'BLOCK' })] });
    const exploding = Object.assign(() => { throw new Error('runner exploded'); },
      { failureDecision: base.failureDecision });
    const witness = createWitness({ db, runGates: exploding, config: {} });
    const doc = packumentWith({ '1.0.0': manifest('1.0.0') });
    const observed = witness.observePackument(PKG, doc);
    assert.equal(observed.decisions.get('1.0.0').disposition, 'BLOCK');
    assert.match(JSON.stringify(observed.decisions.get('1.0.0').results), /runner exploded/);
    db.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// --- 7: the rewriter's own fail-open ------------------------------------------------------------------
test('the rewriter still keeps an undecided version, which is why the store must decide them all', () => {
  // This is deliberately NOT changed: the rewriter is pure and knows nothing about gates. The hole it
  // leaves is closed at the source -- every version in the document now carries a decision.
  const doc = packumentWith({ '1.0.0': manifest('1.0.0') });
  const { packument: out } = rewritePackument(doc, new Map());
  assert.ok(out.versions['1.0.0'], 'documented: no decision means kept');
});
