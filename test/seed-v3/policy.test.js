// CFT-05 — the policy contract: findings become actions HERE and nowhere else.
//
// Two properties are load-bearing and are asserted directly rather than implied:
//   * the detection contract is untouched — a finding carries no disposition, policy does not write
//     one into it, and the two versions are separate strings;
//   * missing evidence never becomes a clean result — not through a SKIP that quietly aggregates to
//     ALLOW, and not through a default nobody chose.

import test from 'node:test';
import assert from 'node:assert';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import K from '../../seed/v3/contract.js';
import POL from '../../seed/v3/policy.js';
import R from '../../seed/v3/reader.js';

const DIRNAME = dirname(fileURLToPath(import.meta.url));

// --- a synthetic finding, so the table can be exercised without a seed -----------------------------
const triDict = (v, reason = null) => (v === null
  ? K.unknown(reason || K.COLD_START).asDict() : K.known(v).asDict());

function finding({ groups = {}, predicates = {}, constituents = {}, contractVersion = null } = {}) {
  const g = {}; const gt = {};
  for (const name of K.CHANNEL_A_GROUPS) {
    const v = name in groups ? groups[name] : false;
    g[name] = triDict(v); gt[name] = v === null ? K.unknown(K.COLD_START) : K.known(v);
  }
  const p = {}; const pt = {};
  for (const name of K.DAC_PREDICATES) {
    const v = name in predicates ? predicates[name] : false;
    p[name] = triDict(v); pt[name] = v === null ? K.unknown(K.COLD_START) : K.known(v);
  }
  const c = {};
  for (const name of K.PUBLISHER_CONSTITUENTS) {
    c[name] = triDict(name in constituents ? constituents[name] : false);
  }
  return {
    contract_version: contractVersion || K.CONTRACT_VERSION,
    candidate: { package: 'p', version: '1.0.0' },
    seed: { corpus_snapshot_digest: 'a'.repeat(64) },
    channel_a: { groups: g, publisher_constituents: c, install_body: null,
      ...K.aggregate(gt, [['critical', K.CHANNEL_A_T]], K.CHANNEL_A_GROUPS.length) },
    dac_trajectory: { predicates: p,
      ...K.aggregate(pt, [['surface', K.DAC_SURFACE_T], ['any', K.DAC_ANY_T]], K.DAC_PREDICATES.length) },
  };
}
const nothing = { publisher: null, provenance: null, install: null, size: null, git: null };
const noPredicates = Object.fromEntries(K.DAC_PREDICATES.map((k) => [k, null]));

// --- separation -------------------------------------------------------------------------------------
test('policy is versioned separately from the detection contract, and does not touch findings', () => {
  assert.notStrictEqual(POL.POLICY_CONTRACT_VERSION, K.CONTRACT_VERSION);
  assert.match(POL.POLICY_CONTRACT_VERSION, /^cft-policy-/);
  assert.strictEqual(POL.IMPLEMENTED_DETECTION_CONTRACT, K.CONTRACT_VERSION);

  const f = finding();
  const before = JSON.stringify(f);
  const d = POL.decide(f, { config: { on_no_evidence: 'WARN', on_unusable_input: 'WARN' } });
  assert.strictEqual(JSON.stringify(f), before, 'the finding must come back unmodified');
  assert.ok(!('disposition' in f) && !('results' in f), 'and must never gain a disposition');
  assert.strictEqual(d.detection_contract_version, K.CONTRACT_VERSION);
});

test('the detection modules do not import policy, in either direction', () => {
  // `join(DIRNAME, '..', '..', 'seed', 'v3', x)` deliberately: that is the idiom sync-to-runtime.py rewrites for the
  // runtime layout. Computing the directory inline instead resolved to the repo root there, where
  // contract.js does not exist — the test passed here and failed after the sync.
  for (const m of ['contract.js', 'checker.js', 'reader.js', 'adapter.js', 'normalize.js']) {
    assert.doesNotMatch(readFileSync(join(DIRNAME, '..', '..', 'seed', 'v3', m), 'utf8'), /from '\.\/policy\.js'/, m);
  }
  // ...and no disposition vocabulary leaks into the detection contract itself.
  const contract = readFileSync(join(DIRNAME, '..', '..', 'seed', 'v3', 'contract.js'), 'utf8');
  for (const word of ['ALLOW', 'WARN', 'BLOCK']) assert.doesNotMatch(contract, new RegExp(word), word);
});

// --- the decision table -------------------------------------------------------------------------------
test('a known-malware pin BLOCKs: a recorded advisory for this exact version', () => {
  const d = POL.decide(finding(), { pin: { advisory_id: 'MAL-2026-6358', source: 'osv' } });
  assert.strictEqual(d.disposition, 'BLOCK');
  const hit = d.results.find((x) => x.gate === 'seed-v3:known-malicious-pin');
  assert.strictEqual(hit.result, 'BLOCK');
  assert.match(hit.detail, /MAL-2026-6358/);
});

test('a trajectory or Channel-A threshold WARNs and never BLOCKs', () => {
  // all four DAC predicates true: over both thresholds
  const d1 = POL.decide(finding({ predicates: Object.fromEntries(K.DAC_PREDICATES.map((k) => [k, true])) }));
  assert.strictEqual(d1.disposition, 'WARN');
  assert.ok(d1.results.every((x) => x.result !== 'BLOCK'));

  // Channel-A at T=3 of M=5
  const d2 = POL.decide(finding({ groups: { publisher: true, provenance: true, install: true } }));
  assert.strictEqual(d2.disposition, 'WARN');
  const t = d2.results.find((x) => x.gate === 'seed-v3:channel-a:critical');
  assert.strictEqual(t.result, 'WARN');
  assert.match(t.detail, /never blocks/);
});

test('nothing broken and everything evaluated is the only way to reach ALLOW', () => {
  const d = POL.decide(finding());
  assert.strictEqual(d.disposition, 'ALLOW');
  assert.strictEqual(d.evidence_complete, true);
  assert.deepStrictEqual(d.not_evaluated, []);
});

test('an INDETERMINATE threshold is a SKIP that says so, not a clean result', () => {
  // two groups broke, two unevaluable: the retained interval [2, 4] spans the threshold of 3
  const d = POL.decide(finding({
    groups: { publisher: true, provenance: true, install: null, size: null },
    config: {},
  }), { config: { on_no_evidence: 'WARN' } });
  const t = d.results.find((x) => x.gate === 'seed-v3:channel-a:critical');
  assert.strictEqual(t.result, 'SKIP');
  assert.match(t.detail, /NOT a clean result/);
  assert.match(t.detail, /\[2, 4\]/);
  assert.strictEqual(d.evidence_complete, false);
  assert.ok(d.not_evaluated.length > 0, 'and it names what it could not see');
});

test('incomplete evidence is always recorded, even when the disposition is ALLOW', () => {
  const d = POL.decide(finding({ groups: { git: null } }),
    { config: { on_no_evidence: 'WARN', on_unusable_input: 'WARN' } });
  assert.strictEqual(d.evidence_complete, false);
  assert.deepStrictEqual(d.not_evaluated.map((m) => m.name), ['git']);
  assert.ok(d.results.some((x) => x.gate === 'seed-v3:coverage' && x.result === 'SKIP'));
});

// --- the two genuinely open choices ---------------------------------------------------------------------
test('with NOTHING evaluated, policy declines to decide rather than defaulting to ALLOW', () => {
  const d = POL.decide(finding({ groups: nothing, predicates: noPredicates }));
  assert.strictEqual(d.disposition, null, 'silence is not a pass');
  assert.deepStrictEqual(d.undecided, ['on_no_evidence']);
  assert.strictEqual(d.evidence_complete, false);
});

test('an operator may set either open choice, and then the answer is theirs and is recorded', () => {
  const f = finding({ groups: nothing, predicates: noPredicates });
  assert.strictEqual(POL.decide(f, { config: { on_no_evidence: 'WARN' } }).disposition, 'WARN');
  assert.strictEqual(POL.decide(f, { config: { on_no_evidence: 'ALLOW' } }).disposition, 'ALLOW');
  assert.deepStrictEqual(POL.decide(f, { config: { on_no_evidence: 'ALLOW' } }).undecided, []);
});

test('a recorded pin still BLOCKs when there is no history to evaluate', () => {
  const d = POL.decide(finding({ groups: nothing, predicates: noPredicates }),
    { pin: { advisory_id: 'MAL-2026-0001', source: 'osv' } });
  assert.strictEqual(d.disposition, 'BLOCK', 'a recorded fact does not need history');
});

test('a trust failure or unsupported input yields no finding, and never an ALLOW', () => {
  const refusal = new R.SeedRefused(['signature: present but no trusted key supplied']);
  const undecided = POL.decide(null, { refusal });
  assert.strictEqual(undecided.disposition, null);
  assert.deepStrictEqual(undecided.undecided, ['on_unusable_input']);
  assert.match(undecided.results[0].detail, /no trusted key/);

  assert.strictEqual(POL.decide(null, { refusal, config: { on_unusable_input: 'BLOCK' } }).disposition, 'BLOCK');
  assert.strictEqual(POL.decide(null, { refusal, config: { on_unusable_input: 'WARN' } }).disposition, 'WARN');
});

test('a finding from an unimplemented detection contract is an unsupported input', () => {
  const d = POL.decide(finding({ contractVersion: 'cft-detection-contract-9.9' }),
    { config: { on_unusable_input: 'BLOCK' } });
  assert.strictEqual(d.disposition, 'BLOCK');
  assert.match(d.results[0].detail, /cft-detection-contract-9\.9/);
  assert.strictEqual(d.evidence_complete, false);
});

test('only the genuinely open choices are open, and a typo is never read as a policy', () => {
  assert.deepStrictEqual(POL.OPEN_CHOICE_KEYS, ['on_unusable_input', 'on_no_evidence']);
  for (const k of POL.OPEN_CHOICE_KEYS) {
    assert.ok(POL.OPEN_CHOICES[k].question && POL.OPEN_CHOICES[k].why_open, k);
    assert.ok('REFUSE_TO_DECIDE' in POL.OPEN_CHOICES[k].values, `${k} must be declinable`);
  }
  assert.throws(() => POL.decide(finding(), { config: { on_unusable_inputs: 'BLOCK' } }),
    POL.PolicyConfigInvalid, 'a misspelt key must not silently do nothing');
  assert.throws(() => POL.decide(finding(), { config: { on_no_evidence: 'ALOW' } }),
    POL.PolicyConfigInvalid);
  assert.throws(() => POL.normaliseConfig('BLOCK everything'), POL.PolicyConfigInvalid);
});

// --- D1 behaviour that is locked and must stay ------------------------------------------------------------
test("D1's aggregation is unchanged: BLOCK wins, then WARN, and SKIP never escalates", () => {
  const A = { result: 'ALLOW' }; const W = { result: 'WARN' };
  const B = { result: 'BLOCK' }; const S = { result: 'SKIP' };
  assert.strictEqual(POL.aggregate([A, A]), 'ALLOW');
  assert.strictEqual(POL.aggregate([A, S, S, S, S]), 'ALLOW', 'skips do not count');
  assert.strictEqual(POL.aggregate([A, W, S]), 'WARN');
  assert.strictEqual(POL.aggregate([W, W, W, W]), 'WARN', 'N warnings do NOT escalate');
  assert.strictEqual(POL.aggregate([A, W, B]), 'BLOCK');
  assert.deepStrictEqual(POL.DISPOSITIONS, ['ALLOW', 'WARN', 'BLOCK']);
});

test("D1's override short-circuits to ALLOW, outranks a pin, and is recorded as incomplete", () => {
  const d = POL.decide(finding({ groups: { publisher: true, provenance: true, install: true } }), {
    pin: { advisory_id: 'MAL-2026-6358' },
    override: { reason: 'known false positive', created_at: '2026-09-20T00:00:00Z' },
  });
  assert.strictEqual(d.disposition, 'ALLOW');
  assert.deepStrictEqual(d.results, [{ gate: 'override', result: 'ALLOW', detail: 'override: known false positive' }]);
  assert.strictEqual(d.override.reason, 'known false positive');
  assert.strictEqual(d.evidence_complete, false, 'nothing ran, so nothing was established');
});

// --- against the real seed -----------------------------------------------------------------------------------
const CAND = process.env.CFT04_CANDIDATE || '';
const SEED = CAND ? join(CAND, 'chaingate-seed.db') : '';
const have = Boolean(CAND) && existsSync(SEED);

test('the pin lookup reads the real seed and a real finding decides',
  { skip: have ? false : 'set CFT04_CANDIDATE to a gated candidate directory', timeout: 120000 },
  () => {
    const seed = R.openSeed(SEED, { trust: R.TRUST_UNSIGNED_DEV });
    try {
      assert.strictEqual(POL.pinFor(seed, 'definitely-not-a-real-package-xyzzy', '1.0.0'), null);
      const pinned = seed.db.prepare(
        'SELECT p.package_name AS name, k.version AS version, k.advisory_id AS advisory_id '
        + 'FROM known_malicious_pins k JOIN packages p ON p.id = k.package_id LIMIT 1').get();
      if (pinned) {
        const row = POL.pinFor(seed, pinned.name, pinned.version);
        assert.strictEqual(row.advisory_id, pinned.advisory_id);
      }
      // an uncovered package: every observation NOT_EVALUATED, so policy declines rather than allows
      const f = seed.check(R.candidateFromMapping({
        package_name: 'definitely-not-a-real-package-xyzzy', version: '1.0.0', lineage_id: null,
        ord: null, published_s: 1700000000, identity_digest: null, tuple_digest: null,
        maint_digest: '', repo_digest: null, body_digest: '', has_scripts: false,
        head_present: false, provenance_present: false, publish_method: '', provider_class: 'unknown',
        size_bytes: null, tool_name: '', tool_key: 0,
      }));
      const d = POL.decide(f, { pin: POL.pinFor(seed, f.candidate.package, f.candidate.version) });
      assert.strictEqual(d.disposition, null, 'an uncovered package is not an ALLOW');
      assert.deepStrictEqual(d.undecided, ['on_no_evidence']);
      assert.ok(d.not_evaluated.every((m) => m.reason === K.UNCOVERED_PACKAGE));
    } finally { seed.close(); }
  });
