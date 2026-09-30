// U-01 A2/A3/A4 — the refactored gate AND `check` each reproduce the goldens captured from the frozen
// 306bccde gate (test/fixtures/u01-goldens, commit "U-01 A1"). Agreement with each other is not
// enough; each is compared with the recorded answer.
//
// U-05 (T2, revision 2 §6): the goldens are FROZEN and unchanged. They record cft-policy-1.0; this runtime is
// cft-policy-1.1. The exact reproduction by the released 0.1.2 is T1 (qualification evidence, outside the suite).
// Here each golden is compared after the ENUMERATED expected differences of U-05-S2-DECISION-TABLES-20260930.md
// T-2, and only those: D1 the decision's policy_version, D2 the policy prefix of the gate detail. The tables
// predict no other difference on these inputs (no pinned refusal, no absent-package stub, no failure path), so
// anything else fails here.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import R from '../../seed/v3/reader.js';
import G from '../../seed/v3/gate.js';
import { buildCheckRecord, inputFromPackument as checkInput } from '../../cli/check-record.js';
import {
  syntheticCases, rc3Cases, buildSyntheticSeed, inputFromPackument, canonical, sha256, RC3_DIR,
} from './u01-cases.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GOLD = path.join(HERE, '..', 'fixtures', 'u01-goldens');
const load = (f) => JSON.parse(fs.readFileSync(path.join(GOLD, f), 'utf8'));
const TOOL = { name: 'chaingate', version: 'test' };

const isRefusal = (d) => d.results.length === 1 && d.results[0].gate === 'seed-v3:input';

// T-2 D1/D2, written from the decision tables (not from runtime output). Applied to a COPY of the golden.
const POLICY_1_0 = 'cft-policy-1.0';
const POLICY_1_1 = 'cft-policy-1.1';
function expectedUnder11(g) {
  const out = structuredClone(g);
  assert.equal(out.decision.policy_version, POLICY_1_0, `${g.id}: the golden records policy 1.0`);
  out.decision.policy_version = POLICY_1_1;                                          // D1
  assert.ok(out.gate_result.detail.startsWith(`${POLICY_1_0}: `), `${g.id}: golden detail prefix`);
  out.gate_result.detail = `${POLICY_1_1}: ${out.gate_result.detail.slice(POLICY_1_0.length + 2)}`;   // D2
  return out;
}

function viaGate(seed, c) {
  const decisions = [];
  const gate = G.createSeedV3Gate({ seed, config: c.policy, domainVersionCount: 'from-packument',
    onDecision: (d) => decisions.push(d) });
  const gateResult = gate.evaluate(inputFromPackument(c.doc, c.version));
  assert.equal(decisions.length, 1);
  return { gateResult, decision: decisions[0] };
}

function viaCheck(seed, c) {
  return buildCheckRecord({ seed, bundleId: null, policy: c.policy, domainVersionCount: 'from-packument',
    input: checkInput(c.doc, c.doc.name, c.version),
    request: { package: c.doc.name, version: c.version }, override: null, tool: TOOL });
}

function compareAll(seed, cases, golden, label) {
  const byId = new Map(golden.records.map((r) => [r.id, r]));
  assert.deepEqual(cases.map((c) => c.id), golden.records.map((r) => r.id), `${label}: case set drifted from the goldens`);
  let n = 0;
  for (const c of cases) {
    const g = expectedUnder11(byId.get(c.id));
    assert.equal(sha256(canonical(c.doc)), g.request.document_sha256, `${c.id}: input document changed since capture`);
    assert.equal(g.threw, null);

    // the refactored GATE: GateResult and the full decision, exactly
    const { gateResult, decision } = viaGate(seed, c);
    assert.deepEqual(gateResult, g.gate_result, `${c.id}: gate result differs from the frozen gate`);
    assert.deepEqual(decision, g.decision, `${c.id}: gate decision differs from the frozen gate`);

    // CHECK: the same decision, carried in the chaingate.check/1 shape
    const rec = viaCheck(seed, c);
    assert.equal(rec.decision.disposition, g.decision.disposition, `${c.id}: check disposition`);
    assert.deepEqual(rec.decision.results, g.decision.results, `${c.id}: check results (incl. detail text)`);
    assert.deepEqual(rec.decision.not_evaluated, g.decision.not_evaluated, `${c.id}: check not_evaluated`);
    assert.equal(rec.decision.evidence_complete, g.decision.evidence_complete, `${c.id}: check evidence_complete`);
    assert.equal(rec.decision.policy_version, g.decision.policy_version);
    assert.deepEqual(rec.effective, { action: g.decision.disposition, basis: 'evaluation' });
    if (isRefusal(g.decision)) {
      assert.equal(rec.result, 'refused', `${c.id}: a policy refusal is result "refused"`);
      assert.ok(!('candidate' in rec) && !('finding' in rec), `${c.id}: a refusal carries no candidate or finding`);
      assert.equal(g.decision.placement, null);
    } else {
      assert.equal(rec.result, 'evaluated');
      assert.equal(rec.candidate.placement.kind, g.decision.placement, `${c.id}: check placement`);
      assert.deepEqual(rec.finding.seed, g.decision.seed, `${c.id}: finding bound to the same seed`);
    }
    n++;
  }
  return n;
}

// The goldens were captured on a synthetic seed built with better-sqlite3 11.10.0 (SQLite 3.49.2).
// SQLite stamps the library version that last wrote a database into its header (bytes 96-99), so the
// same generator under another SQLite produces a file that differs in exactly those bytes. The
// evaluation is therefore run on the CAPTURED seed itself (its digest must equal the goldens' recorded
// one), and a separate test proves today's generator still builds that seed apart from the stamp.
// The goldens are unchanged.
const CAPTURED_SEED = path.join(HERE, '..', 'fixtures', 'u04', 'synthetic-seed-captured.db');

test('A2 synthetic: refactored gate and check reproduce every frozen golden exactly', () => {
  const golden = load('synthetic.json');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'u01-captured-'));
  const dbPath = path.join(dir, 'chaingate-seed.db');
  fs.copyFileSync(CAPTURED_SEED, dbPath);
  fs.copyFileSync(`${CAPTURED_SEED}.sha256`, `${dbPath}.sha256`);
  assert.equal(sha256(fs.readFileSync(dbPath)), golden.seed_sha256,
    'the seed evaluated is byte-identical to the one the goldens were captured on');
  const seed = R.openSeed(dbPath, { trust: R.TRUST_UNSIGNED_DEV });
  try {
    assert.equal(compareAll(seed, syntheticCases(), golden, 'synthetic'), golden.n);
  } finally { seed.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('A2 synthetic: the seed generator still builds the captured seed, apart from SQLite\'s version stamp', () => {
  const captured = fs.readFileSync(CAPTURED_SEED);
  const { dir, dbPath } = buildSyntheticSeed();
  try {
    const built = fs.readFileSync(dbPath);
    assert.equal(built.length, captured.length, 'same size');
    const differing = [];
    for (let i = 0; i < built.length; i++) if (built[i] !== captured[i]) differing.push(i);
    assert.ok(differing.every((i) => i >= 96 && i <= 99),
      `only header bytes 96-99 (SQLITE_VERSION_NUMBER) may differ; differing offsets: ${differing.slice(0, 20)}`);
    for (const buf of [built, captured]) {
      const v = buf.readUInt32BE(96);                     // e.g. 3049002 = 3.49.2, 3053002 = 3.53.2
      assert.ok(v >= 3000000 && v < 4000000, `header bytes 96-99 hold a SQLite 3 version number (got ${v})`);
    }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('A2 rc3: refactored gate and check reproduce every frozen golden exactly on the real seed',
  { skip: RC3_DIR ? false : 'set CFT04_CANDIDATE to the rc3 candidate directory', timeout: 600000 }, () => {
    const golden = load('rc3.json');
    const seed = R.openSeed(path.join(RC3_DIR, 'chaingate-seed.db'), { trust: R.TRUST_UNSIGNED_DEV });
    try {
      assert.equal(seed.report.content_sha256, golden.seed_sha256, 'the goldens were captured on this seed');
      assert.equal(compareAll(seed, rc3Cases(seed.db), golden, 'rc3'), golden.n);
    } finally { seed.close(); }
  });

// --- A3: missing publication time, frozen precedence preserved --------------------------------------
test('A3 missing publication time is evaluated, precedence preserved, and a pin still BLOCKs', () => {
  const golden = load('synthetic.json');
  const { dir, dbPath } = buildSyntheticSeed();
  const seed = R.openSeed(dbPath, { trust: R.TRUST_UNSIGNED_DEV });
  const want = {
    'notime-pin-block-ineligible': ['ineligible-no-publication-time', 'BLOCK'],
    'notime-unpinned-ineligible': ['ineligible-no-publication-time', 'WARN'],
    'notime-nonstring-time': ['ineligible-no-publication-time', 'WARN'],
    'notime-recorded-pinned': ['recorded', 'BLOCK'],
    'notime-recorded-unpinned': ['recorded', 'ALLOW'],
    'notime-stub': ['ineligible-stub', 'WARN'],
    'notime-uncovered': ['uncovered-package', 'WARN'],
    'alt-pin-notime': ['ineligible-no-publication-time', 'BLOCK'],
  };
  try {
    const cases = new Map(syntheticCases().map((c) => [c.id, c]));
    for (const [id, [placement, disposition]] of Object.entries(want)) {
      const g = golden.records.find((r) => r.id === id);
      assert.equal(g.decision.placement, placement, `${id}: golden placement`);
      assert.equal(g.decision.disposition, disposition, `${id}: golden disposition`);
      const { decision } = viaGate(seed, cases.get(id));
      assert.equal(decision.placement, placement, `${id}: gate`);
      assert.equal(decision.disposition, disposition, `${id}: gate`);
      const rec = viaCheck(seed, cases.get(id));
      assert.equal(rec.result, 'evaluated', `${id}: missing time is NOT a refusal`);
      assert.equal(rec.candidate.placement.kind, placement, `${id}: check`);
      assert.equal(rec.decision.disposition, disposition, `${id}: check`);
      assert.equal(rec.finding.candidate.published_s, null, `${id}: publication time passed as null`);
    }
  } finally { seed.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('A3 rc3: missing time on real pins gives recorded or ineligible, and BLOCKs either way',
  { skip: RC3_DIR ? false : 'set CFT04_CANDIDATE to the rc3 candidate directory', timeout: 600000 }, () => {
    const golden = load('rc3.json');
    const notime = golden.records.filter((r) => r.id.startsWith('rc3-pin-notime:'));
    assert.ok(notime.length >= 4);
    assert.deepEqual([...new Set(notime.map((r) => r.decision.placement))].sort(),
      ['ineligible-no-publication-time', 'recorded']);
    assert.ok(notime.every((r) => r.decision.disposition === 'BLOCK'));
  });

// --- A4: refusals ------------------------------------------------------------------------------------
test('A4 missing manifest, version absent and malformed manifests are refusals with no candidate or finding', () => {
  const { dir, dbPath } = buildSyntheticSeed();
  const seed = R.openSeed(dbPath, { trust: R.TRUST_UNSIGNED_DEV });
  try {
    const ids = ['refuse-missing-manifest', 'refuse-version-absent', 'refuse-malformed-npmuser',
      'refuse-version-mismatch', 'refuse-bad-time'];
    const cases = new Map(syntheticCases().map((c) => [c.id, c]));
    for (const id of ids) {
      const rec = viaCheck(seed, cases.get(id));
      assert.equal(rec.result, 'refused', id);
      assert.equal(rec.decision.disposition, 'BLOCK', `${id}: on_unusable_input=BLOCK`);
      assert.deepEqual(Object.keys(rec),
        ['schema', 'result', 'tool', 'request', 'seed', 'decision', 'effective', 'explanation'], id);
    }
    const warn = viaCheck(seed, cases.get('alt-refuse-missing-manifest'));
    assert.equal(warn.result, 'refused');
    assert.equal(warn.decision.disposition, 'WARN', 'on_unusable_input=WARN');
  } finally { seed.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});
