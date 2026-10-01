// U-05 S2 / Amendment 1 — every fallback site where a decision is replaced, defaulted or never made: table T-F of
// U-05-S2-DECISION-TABLES-20260930.md, sites from Amendment 1 §3. Fault-injection, written and run failing-first on
// a6cb8e4. Expected values come from the table, not from runtime output.
//
// Fixture: the real seed-v3 gate beside the six pilot modules (as proxy/server.js wires them), a real witness DB, and
// `p@1.3.0` pinned (ADV-P-130), `p@1.4.0` unpinned, `p@1.5.0` pinned AND overridden, `q@1.3.0` unpinned.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import G from '../../seed/v3/gate.js';
import { createGateRunner, DEFAULT_GATE_MODULES } from '../../gates/index.js';
import { openWitnessDB } from '../../witness/db.js';
import { createWitness } from '../../witness/store.js';
import {
  buildSeed, openFixtureSeed, docFor, gateInput, failPinLookup, namingRow, after, CONFIGS,
} from './u05-fixtures.mjs';

const quiet = { info() {}, warn() {}, error() {} };
const DOC_P = () => docFor('p', [['1.3.0', after(1)], ['1.4.0', after(2)], ['1.5.0', after(3)]]);
const unreadable = (doc, versions) => ({ ...doc,
  versions: Object.fromEntries(Object.entries(doc.versions).map(([v, m]) => [v, versions.includes(v) ? 'not-a-manifest' : m])) });

function harness(cfg, { modules = null, onDecision = null } = {}) {
  const s = buildSeed({ layout: '1.0' });
  const seed = openFixtureSeed(s.dbPath);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'u05-witness-'));
  const db = openWitnessDB(path.join(dir, 'witness.db'));
  db.applySchema();                                   // as proxy/server.js does after opening
  db.insertOverride('p', '1.5.0', 'operator exception for the test');
  const gate = G.createSeedV3Gate({ seed, config: cfg, domainVersionCount: 'from-packument', onDecision });
  const runGates = createGateRunner({ modules: modules ? modules(gate) : [...DEFAULT_GATE_MODULES, gate],
    getOverride: (n, v) => db.getOverride(n, v), logger: quiet });
  const witness = createWitness({ db, runGates, config: {}, logger: quiet });
  return { seed, db, gate, runGates, witness,
    close() { try { db.close(); } catch { /* closed */ } seed.close(); s.cleanup(); fs.rmSync(dir, { recursive: true, force: true }); } };
}

const noAdvisory = (d) => !d.results.some((x) => typeof x.detail === 'string' && /ADV-/.test(x.detail));
function expectPinned(d, label) {
  assert.equal(d.disposition, 'BLOCK', `${label}: BLOCK`);
  assert.ok(namingRow(d.results, 'ADV-P-130'), `${label}: a BLOCK row names ADV-P-130`);
}
function expectInputRule(d, cfg, label) {
  assert.equal(d.disposition, cfg.on_unusable_input, `${label}: the input rule decides`);
  assert.ok(noAdvisory(d), `${label}: no advisory is claimed`);
}
const seedRow = (d) => d.results.find((x) => x.gate === 'seed-v3');

/** The three controls of one pre-evaluation fallback, under both settings. */
function preEvaluation(label, run) {
  for (const [name, cfg] of Object.entries(CONFIGS)) {
    const h = harness(cfg);
    try {
      const decisions = run(h);
      expectPinned(decisions.get('1.3.0'), `${label} ${name} pinned`);
      expectInputRule(decisions.get('1.4.0'), cfg, `${label} ${name} unpinned`);
      const ov = decisions.get('1.5.0');
      expectInputRule(ov, cfg, `${label} ${name} pinned+overridden (as today)`);
      assert.match(seedRow(ov).detail, /override/, `${label} ${name}: says why the advisory was not consulted`);
    } finally { h.close(); }
  }
}

test('S1 all manifests unreadable: identity forwarded per version key', () => {
  preEvaluation('S1', (h) => h.witness.observePackument('p', unreadable(DOC_P(), Object.keys(DOC_P().versions))).decisions);
});

test('S4 one version unparseable among readable ones', () => {
  preEvaluation('S4', (h) => h.witness.observePackument('p', unreadable(DOC_P(), ['1.3.0', '1.4.0', '1.5.0'])).decisions);
});

test('S2 the runner itself throws', () => {
  preEvaluation('S2', (h) => {
    const wrapped = () => { throw new Error('injected runner failure'); };
    wrapped.failureDecision = h.runGates.failureDecision;
    return createWitness({ db: h.db, runGates: wrapped, config: {}, logger: quiet }).observePackument('p', DOC_P()).decisions;
  });
});

test('S3a a witness read fails before evaluation', () => {
  preEvaluation('S3a', (h) => { h.db.getBaseline = () => { throw new Error('injected read failure'); };
    return h.witness.observePackument('p', DOC_P()).decisions; });
});

test('S5 the observation transaction fails before evaluating', () => {
  preEvaluation('S5-before', (h) => { h.db.getHistory = () => { throw new Error('injected history failure'); };
    return h.witness.observePackument('p', DOC_P()).decisions; });
});

test('S6 / P2 failureDecisionsFor takes the request-bound package name', () => {
  preEvaluation('S6', (h) => h.witness.failureDecisionsFor(DOC_P(), new Error('observation could not run'), 'p').decisions);
});

test('S6 identity-less (no package name given): the input rule for every version, nothing named', () => {
  for (const [name, cfg] of Object.entries(CONFIGS)) {
    const h = harness(cfg);
    try {
      const out = h.witness.failureDecisionsFor(DOC_P(), new Error('observation could not run')).decisions;
      for (const v of ['1.3.0', '1.4.0', '1.5.0']) expectInputRule(out.get(v), cfg, `S6-no-identity ${name} ${v}`);
    } finally { h.close(); }
  }
});

/** A computed decision survives a LATER failure; nothing claims it was stored. */
function postEvaluation(label, inject) {
  for (const [name, cfg] of Object.entries(CONFIGS)) {
    const h = harness(cfg);
    try {
      inject(h);
      const out = h.witness.observePackument('p', DOC_P()).decisions;
      const pinned = out.get('1.3.0');
      expectPinned(pinned, `${label} ${name} pinned`);
      assert.equal(pinned.persisted, false, `${label} ${name}: persisted:false`);
      assert.match(pinned.results[0].detail, /NOT stored/, `${label} ${name}: the record says it was not stored`);
      const unp = out.get('1.4.0');
      assert.equal(unp.disposition, cfg.on_unusable_input, `${label} ${name} unpinned keeps today's outcome`);
      assert.equal(unp.persisted, false);
      assert.equal(out.get('1.5.0').disposition, cfg.on_unusable_input, `${label} ${name} overridden keeps today's outcome`);
      delete h.db.insertGateDecision;
      assert.equal(h.db.getLatestDecision('p', '1.3.0'), null, `${label} ${name}: nothing was stored for p@1.3.0`);
    } finally { h.close(); }
  }
}

test('S3b a witness WRITE fails after evaluation (method fault)', () => {
  postEvaluation('S3b', (h) => { h.db.insertGateDecision = () => { throw new Error('injected write failure'); }; });
});

test('S3b a witness WRITE fails after evaluation (SQLite trigger inside the witness database)', () => {
  for (const [name, cfg] of Object.entries(CONFIGS)) {
    const h = harness(cfg);
    try {
      h.db.db.exec(`CREATE TRIGGER u05_inject BEFORE INSERT ON gate_decisions WHEN NEW.package_name = 'p'
        AND NEW.version = '1.3.0' BEGIN SELECT RAISE(ABORT, 'injected trigger failure'); END;`);
      const out = h.witness.observePackument('p', DOC_P()).decisions;
      expectPinned(out.get('1.3.0'), `trigger ${name}`);
      assert.equal(out.get('1.3.0').persisted, false);
      assert.equal(h.db.getLatestDecision('p', '1.3.0'), null);
      assert.equal(out.get('1.4.0').disposition, 'ALLOW', `trigger ${name}: other versions are unaffected`);
      assert.notEqual(h.db.getLatestDecision('p', '1.4.0'), null, 'and they are stored');
    } finally { h.close(); }
  }
});

// Owner decision 2026-10-01, item 2 (A1-OV): an exact-version override under a witness write failure gives the SAME
// disposition as the released 0.1.2, under both input policies. The overridden version's computed ALLOW is the minimum,
// so the failure decides, as in 0.1.2 (where the failure replaced the computed decision). The expected values were
// checked against the published 0.1.2 by the U-05 evidence harness qual/a1-ov.mjs; they are pinned here.
test('A1-OV override x write failure: the same disposition as 0.1.2, under both input policies', () => {
  const faults = {
    method: (h) => { h.db.insertGateDecision = () => { throw new Error('injected write failure'); }; },
    trigger: (h) => h.db.db.exec(`CREATE TRIGGER u05_inject BEFORE INSERT ON gate_decisions WHEN NEW.package_name = 'p'
      AND NEW.version IN ('1.5.0', '1.4.0') BEGIN SELECT RAISE(ABORT, 'injected trigger failure'); END;`),
  };
  for (const [name, cfg] of Object.entries(CONFIGS)) {
    for (const [fault, inject] of Object.entries(faults)) {
      const h = harness(cfg);
      try {
        inject(h);
        const out = h.witness.observePackument('p', DOC_P()).decisions;
        const ov = out.get('1.5.0');
        assert.equal(ov.disposition, cfg.on_unusable_input, `A1-OV ${name}/${fault}: 0.1.2's outcome (the input rule)`);
        assert.equal(ov.persisted, false, `A1-OV ${name}/${fault}: not claimed as stored`);
        assert.ok(noAdvisory(ov), `A1-OV ${name}/${fault}: the overridden pin is not consulted on the failure path`);
        assert.equal(out.get('1.4.0').disposition, cfg.on_unusable_input, `A1-OV ${name}/${fault}: unpinned control as 0.1.2`);
        if (fault === 'method') delete h.db.insertGateDecision;
        assert.equal(h.db.getLatestDecision('p', '1.5.0'), null, `A1-OV ${name}/${fault}: nothing stored`);
        assert.ok(h.db.getOverride('p', '1.5.0'), `A1-OV ${name}/${fault}: the override itself is untouched`);
      } finally { h.close(); }
    }
  }
});

test('S5 the observation transaction fails AFTER evaluating (rolled back): computed decisions kept, persisted:false', () => {
  for (const [name, cfg] of Object.entries(CONFIGS)) {
    const h = harness(cfg);
    try {
      const realTx = h.db.db.transaction.bind(h.db.db);
      h.db.db.transaction = (fn) => realTx((...a) => { fn(...a); throw new Error('injected failure after evaluation'); });
      const out = h.witness.observePackument('p', DOC_P()).decisions;
      expectPinned(out.get('1.3.0'), `S5-after ${name}`);
      assert.equal(out.get('1.3.0').persisted, false);
      assert.equal(out.get('1.4.0').disposition, cfg.on_unusable_input, `S5-after ${name} unpinned: today's outcome`);
      delete h.db.db.transaction;
      assert.equal(h.db.getLatestDecision('p', '1.3.0'), null, 'rolled back: nothing stored');
    } finally { h.close(); }
  }
});

// --- the runner and the gate ------------------------------------------------------------------------
test('R2 the seed-v3 module throws inside runGates: identity forwarded to onError', () => {
  for (const [name, cfg] of Object.entries(CONFIGS)) {
    const h = harness(cfg, { modules: (g) => [...DEFAULT_GATE_MODULES, { ...g, evaluate() { throw new Error('module fault'); } }] });
    try {
      expectPinned(h.runGates(gateInput(DOC_P(), '1.3.0')), `R2 ${name}`);
      expectInputRule(h.runGates(gateInput(DOC_P(), '1.4.0')), cfg, `R2 ${name} unpinned`);
      expectInputRule(h.runGates(gateInput(docFor('q', [['1.3.0', after()]]), '1.3.0')), cfg, `R2 ${name} q@1.3.0`);
    } finally { h.close(); }
  }
});

test('R3 the seed-v3 module returns malformed output: its onError is asked, with identity', () => {
  for (const [name, cfg] of Object.entries(CONFIGS)) {
    const h = harness(cfg, { modules: (g) => [...DEFAULT_GATE_MODULES, { ...g, evaluate() { return { nonsense: true }; } }] });
    try {
      expectPinned(h.runGates(gateInput(DOC_P(), '1.3.0')), `R3 ${name}`);
      expectInputRule(h.runGates(gateInput(DOC_P(), '1.4.0')), cfg, `R3 ${name} unpinned`);
    } finally { h.close(); }
  }
});

test('G4 an onDecision callback that throws does not replace the decision it was given', () => {
  for (const [name, cfg] of Object.entries(CONFIGS)) {
    const h = harness(cfg, { onDecision: () => { throw new Error('sink failed'); } });
    try {
      const pinned = h.runGates(gateInput(DOC_P(), '1.3.0'));
      expectPinned(pinned, `G4 ${name}`);
      const unp = h.runGates(gateInput(DOC_P(), '1.4.0'));
      assert.equal(unp.disposition, 'ALLOW', `G4 ${name}: the computed ALLOW, not the input rule`);
      assert.match(seedRow(unp).detail, /sink failed/, `G4 ${name}: the callback failure is stated`);
    } finally { h.close(); }
  }
});

test('G6 onError: identity-less, lookup failure, overridden', () => {
  for (const [name, cfg] of Object.entries(CONFIGS)) {
    const h = harness(cfg);
    try {
      const none = h.gate.onError(new Error('no identity here'));
      assert.equal(none.result, cfg.on_unusable_input, `${name} identity-less`);
      assert.match(none.detail, /not consulted/);
      assert.doesNotMatch(none.detail, /ADV-/);
      const ov = h.gate.onError(new Error('x'), { packageName: 'p', version: '1.5.0', overridden: true });
      assert.equal(ov.result, cfg.on_unusable_input, `${name} overridden`);
      assert.match(ov.detail, /override/);
      const pinned = h.gate.onError(new Error('x'), { packageName: 'p', version: '1.3.0' });
      assert.equal(pinned.result, 'BLOCK', `${name} pinned`);
      assert.match(pinned.detail, /ADV-P-130/);
      failPinLookup(h.seed);
      const failed = h.gate.onError(new Error('x'), { packageName: 'p', version: '1.3.0' });
      assert.equal(failed.result, cfg.on_unusable_input, `${name} lookup failed`);
      assert.match(failed.detail, /lookup FAILED/);
    } finally { h.close(); }
  }
});

// --- pilot-only configuration --------------------------------------------------------------------------
test('pilot-only runner: module exceptions and malformed output stay SKIP, S1 declarations stay ALLOW (unchanged)', () => {
  const h = harness({ on_unusable_input: 'BLOCK', on_no_evidence: 'WARN' }, {
    modules: () => [{ name: 'content-hash', evaluate() { throw new Error('boom'); } },
      { name: 'dep-structure', evaluate() { return { nonsense: 1 }; } }] });
  try {
    const r = h.runGates({ ...gateInput(DOC_P(), '1.3.0'), history: [] });
    assert.equal(r.disposition, 'ALLOW');
    assert.deepEqual(r.results.map((x) => x.result), ['SKIP', 'SKIP']);
    const s1 = h.witness.observePackument('p', unreadable(DOC_P(), Object.keys(DOC_P().versions))).decisions;
    assert.equal(s1.get('1.3.0').disposition, 'ALLOW');
  } finally { h.close(); }
});

test('pilot-only runner, A3: a computed content-hash BLOCK is kept when its write fails (stricter only)', () => {
  const h = harness({ on_unusable_input: 'BLOCK', on_no_evidence: 'WARN' }, {
    modules: () => [{ name: 'content-hash', evaluate: (i) => ({ gate: 'content-hash',
      result: i.version === '1.3.0' ? 'BLOCK' : 'ALLOW', detail: 'stub' }) }] });
  try {
    h.db.insertGateDecision = () => { throw new Error('injected write failure'); };
    const out = h.witness.observePackument('p', DOC_P()).decisions;
    assert.equal(out.get('1.3.0').disposition, 'BLOCK');
    assert.equal(out.get('1.3.0').persisted, false);
    assert.equal(out.get('1.4.0').disposition, 'ALLOW', 'pilot-only declaration is ALLOW, as today');
  } finally { h.close(); }
});
