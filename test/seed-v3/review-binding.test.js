// Regressions for the three defects found in the 2026-09-20 review of the consumer layer.
//
//   1. COMPOSED BINDING was checked against corpus_snapshot_digest alone. Every build of the same
//      snapshot under the same rules shares that value, so vectors generated against a DIFFERENT
//      seed passed acceptance and were then compared as if they belonged to this one.
//   2. EXPECTATIONS were compared key-by-key over whichever keys the expected object happened to
//      supply. An empty expectation therefore agreed with every candidate, and a truncated one
//      agreed with too many.
//   3. CONTEXTUAL LOWERCASE: str.lower() decides U+03A3 from its neighbours, so a per-character
//      table hashed every script body containing a word ending in sigma differently. (The exhaustive
//      proof is in lower-proof.test.js; the end of this file pins the reported case.)

import test from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import CONF from '../../seed/v3/conformance.js';
import N from '../../seed/v3/normalize.js';
import X from '../../seed/v3/normalize-extra.js';
import R from '../../seed/v3/reader.js';

const DIRNAME = dirname(fileURLToPath(import.meta.url));
const DIR = mkdtempSync(join(tmpdir(), 'cft04-binding-'));
const write = (name, body) => {
  const p = join(DIR, name); writeFileSync(p, JSON.stringify(body)); return p;
};

const SNAPSHOT = 'a'.repeat(64);
const SEED_LOGICAL = 'b'.repeat(64);
const FIXTURES = 'c'.repeat(64);
const fakeSeed = () => ({ meta: { corpus_snapshot_digest: SNAPSHOT }, db: null });
const established = {
  seed_logical_digest: SEED_LOGICAL,
  fixtures_digest: FIXTURES,
  established: { seed_logical_digest: 're-derived from the seed file',
    fixtures_digest: 'recomputed from fixtures.jsonl' },
};

/** A composed vector file whose cases are irrelevant: every assertion below fails in acceptance. */
function composedFile(name, boundTo, cases = null) {
  return write(name, {
    schema: 'composed-vectors-1',
    domain_version_count: 0,
    bound_to: boundTo,
    cases: cases || [{
      package_name: 'p', lineage_id: 1, ord: 0, row: { version: '1.0.0' },
      expected_candidate: Object.fromEntries(CONF.COMPOSED_EXPECTED_FIELDS.map((k) => [k, null])),
      expected_finding: { channel_a: {}, dac_trajectory: {} },
    }],
  });
}

const goodBinding = {
  candidate_id: 'seed-v3.0-test', corpus_snapshot_digest: SNAPSHOT,
  seed_logical_digest: SEED_LOGICAL, fixtures_digest: FIXTURES,
};

// --- 1. composed binding ---------------------------------------------------------------------------
test('composed vectors claiming the right snapshot but a DIFFERENT seed fail acceptance', async () => {
  const path = composedFile('wrong-seed.json', { ...goodBinding, seed_logical_digest: 'd'.repeat(64) });
  const r = await CONF.composedConformance(fakeSeed(), { vectorsPath: path, verified: established });
  assert.strictEqual(r.result, 'FAIL');
  assert.strictEqual(r.failure, 'acceptance');
  assert.strictEqual(r.acceptance.bound_to_this_seed, true, 'the snapshot alone still agrees');
  assert.notStrictEqual(r.acceptance.bound_to_seed_logical_digest, true,
    'which is exactly why the snapshot alone is not the binding');
  assert.match(String(r.acceptance.bound_to_seed_logical_digest), /re-derived from the seed file/);
});

test('composed vectors bound to DIFFERENT fixtures fail acceptance', async () => {
  const path = composedFile('wrong-fixtures.json', { ...goodBinding, fixtures_digest: 'e'.repeat(64) });
  const r = await CONF.composedConformance(fakeSeed(), { vectorsPath: path, verified: established });
  assert.strictEqual(r.failure, 'acceptance');
  assert.notStrictEqual(r.acceptance.bound_to_fixtures_digest, true);
  assert.match(String(r.acceptance.bound_to_fixtures_digest), /recomputed from fixtures.jsonl/);
});

test('an incomplete bound_to is refused rather than partially checked', async () => {
  for (const drop of ['candidate_id', 'corpus_snapshot_digest', 'seed_logical_digest', 'fixtures_digest']) {
    const bt = { ...goodBinding }; delete bt[drop];
    const r = await CONF.composedConformance(fakeSeed(), {
      vectorsPath: composedFile(`drop-${drop}.json`, bt), verified: established });
    assert.strictEqual(r.failure, 'acceptance', drop);
    assert.notStrictEqual(r.acceptance.bound_to_declared, true, drop);
    assert.match(String(r.acceptance.bound_to_declared), new RegExp(drop.replace(/_/g, '_')));
  }
});

test("a vector file's own claim is never evidence for itself", async () => {
  // No verified context and no fixtures directory: nothing can establish either identity, so the
  // binding is UNPROVEN and that is a failure — not a pass by default on the file's own say-so.
  const r = await CONF.composedConformance(fakeSeed(), { vectorsPath: composedFile('self.json', goodBinding) });
  assert.strictEqual(r.failure, 'acceptance');
  assert.match(String(r.acceptance.bound_to_seed_logical_digest), /no verified seed identity/);
  assert.match(String(r.acceptance.bound_to_fixtures_digest), /no verified fixtures identity/);
  assert.match(String(r.identities_established.fixtures_digest), /no fixtures directory supplied/);
});

test('matching established identities pass, and the result says how each was established', async () => {
  const r = await CONF.composedConformance(fakeSeed(), {
    vectorsPath: composedFile('good.json', goodBinding), verified: established });
  for (const k of ['bound_to_declared', 'bound_to_this_seed', 'bound_to_seed_logical_digest',
    'bound_to_fixtures_digest']) {
    assert.strictEqual(r.acceptance[k], true, `${k}: ${r.acceptance[k]}`);
  }
  assert.strictEqual(r.identities_established.seed_logical_digest, 're-derived from the seed file');
  assert.strictEqual(r.identities_established.fixtures_digest, 'recomputed from fixtures.jsonl');
});

test('verifiedIdentities establishes, never reads: an unreadable seed yields null and says why', () => {
  const ids = CONF.verifiedIdentities({ meta: {}, db: null }, null);
  assert.strictEqual(ids.seed_logical_digest, null);
  assert.strictEqual(ids.fixtures_digest, null);
  assert.match(ids.established.seed_logical_digest, /could not re-derive/);
});

// --- 2. expectation completeness --------------------------------------------------------------------
test('the contract field set is fixed, and both vector schemas are held to it', () => {
  assert.deepStrictEqual(CONF.ADAPTER_EXPECTED_FIELDS, [...R.CANDIDATE_REQUIRED].sort());
  assert.deepStrictEqual(CONF.COMPOSED_EXPECTED_FIELDS,
    CONF.ADAPTER_EXPECTED_FIELDS.filter((k) => k !== 'package_name'));
  assert.ok(CONF.COMPOSED_EXPECTED_FIELDS.length >= 16);
});

test('an EMPTY expectation is not a pass: it would agree with every candidate', () => {
  const full = Object.fromEntries(CONF.ADAPTER_EXPECTED_FIELDS.map((k) => [k, null]));
  const path = write('empty-expectation.json', {
    schema: 'adapter-vectors-1', domain_version_count: 0,
    cases: [{ package_name: 'p', row: { version: '1.0.0' }, expected: {} }],
  });
  const r = CONF.adapterConformance(path);
  assert.strictEqual(r.result, 'FAIL');
  assert.strictEqual(r.failure, 'acceptance');
  assert.match(String(r.acceptance.expectations_complete), /must carry exactly the/);
  // and a complete one gets past acceptance into comparison
  const ok = write('full-expectation.json', {
    schema: 'adapter-vectors-1', domain_version_count: 0,
    cases: [{ package_name: 'p', row: { version: '1.0.0' }, expected: full }],
  });
  assert.strictEqual(CONF.adapterConformance(ok).acceptance.expectations_complete, true);
});

test('a truncated or padded expectation names what is missing and what is unknown', () => {
  const full = Object.fromEntries(CONF.ADAPTER_EXPECTED_FIELDS.map((k) => [k, null]));
  const short = { ...full }; delete short.identity_digest; delete short.size_bytes;
  const r1 = CONF.adapterConformance(write('short.json', {
    schema: 'adapter-vectors-1', domain_version_count: 0,
    cases: [{ package_name: 'p', row: {}, expected: short }] }));
  assert.match(String(r1.acceptance.expectations_complete), /missing \[identity_digest, size_bytes\]/);

  const padded = { ...full, not_a_contract_field: 1 };
  const r2 = CONF.adapterConformance(write('padded.json', {
    schema: 'adapter-vectors-1', domain_version_count: 0,
    cases: [{ package_name: 'p', row: {}, expected: padded }] }));
  assert.match(String(r2.acceptance.expectations_complete), /unknown \[not_a_contract_field\]/);
});

test('composed expectations are held to the same rule, on both halves of the case', async () => {
  const bad = await CONF.composedConformance(fakeSeed(), {
    verified: established,
    vectorsPath: composedFile('empty-candidate.json', goodBinding, [{
      package_name: 'p', lineage_id: 1, ord: 0, row: {},
      expected_candidate: {}, expected_finding: { channel_a: {}, dac_trajectory: {} },
    }]),
  });
  assert.strictEqual(bad.failure, 'acceptance');
  assert.match(String(bad.acceptance.expected_candidates_complete), /must carry exactly the/);

  const noFinding = await CONF.composedConformance(fakeSeed(), {
    verified: established,
    vectorsPath: composedFile('no-finding.json', goodBinding, [{
      package_name: 'p', lineage_id: 1, ord: 0, row: {},
      expected_candidate: Object.fromEntries(CONF.COMPOSED_EXPECTED_FIELDS.map((k) => [k, null])),
      expected_finding: { channel_a: {} },
    }]),
  });
  assert.strictEqual(noFinding.failure, 'acceptance');
  assert.match(String(noFinding.acceptance.expected_findings_complete), /no channel_a or no dac_trajectory/);
});

test('diffExpected compares the whole contract set, treating an absent key as null on both sides', () => {
  const fields = ['a', 'b', 'c'];
  assert.deepStrictEqual(CONF.diffExpected({ a: 1 }, { a: 1 }, fields), [],
    'b and c absent on both sides agree');
  assert.deepStrictEqual(CONF.diffExpected({ a: 1, b: 2 }, { a: 1 }, fields),
    [{ field: 'b', got: 2, want: null }],
    'a value the expectation does not mention is still compared');
});

// --- 3. contextual lowercase -------------------------------------------------------------------------
test('the reported case: Greek OS lowercases with a FINAL sigma before the body is hashed', () => {
  assert.strictEqual(N.pyLower('ΟΣ'), 'ος');
  const [has, digest] = N.installBodyDigest('ΟΣ', null, null);
  assert.strictEqual(has, 1);
  assert.strictEqual(digest, N.installBodyDigest(null, 'ος', null)[1],
    'the digest is over the lowered form, so these must agree');
  assert.notStrictEqual(digest, N.installBodyDigest(null, 'οσ', null)[1],
    'and must NOT agree with the small-sigma form a per-character table produced');
});

test('the repository path takes the same lowercase, and Python strip, not JS trim', () => {
  assert.strictEqual(X.canonicalRepoUrl('https://github.com/ΟΣ/Repo'),
    'github.com/ος/repo');
  // NEL: str.strip() removes it, JS trim() does not — it used to become part of the host
  assert.strictEqual(X.canonicalRepoUrl('https://github.com/owner/repo'),
    'github.com/owner/repo');
  // BOM: JS trim() removes it, str.strip() does not — it used to vanish from the repo name
  assert.strictEqual(X.canonicalRepoUrl('https://github.com/owner/repo﻿'),
    'github.com/owner/repo﻿');
});

// --- the real artifacts, when they are present ---------------------------------------------------------
const CAND = process.env.CFT04_CANDIDATE || '';
const SEED_PATH = CAND ? join(CAND, 'chaingate-seed.db') : '';
const havePack = Boolean(CAND) && existsSync(SEED_PATH)
  && existsSync(join(DIRNAME, '..', '..', 'seed', 'v3', 'composed-vectors.json'));

test('against the real artifacts the binding is established, not asserted',
  { skip: havePack ? false : 'set CFT04_CANDIDATE to a gated candidate directory', timeout: 600000 },
  async () => {
    const seed = R.openSeed(SEED_PATH, { trust: R.TRUST_UNSIGNED_DEV });
    try {
      const r = await CONF.composedConformance(seed, { fixturesDir: join(CAND, 'fixtures') });
      assert.strictEqual(r.acceptance.bound_to_seed_logical_digest, true,
        String(r.acceptance.bound_to_seed_logical_digest));
      assert.strictEqual(r.acceptance.bound_to_fixtures_digest, true,
        String(r.acceptance.bound_to_fixtures_digest));
      assert.strictEqual(r.acceptance.expected_candidates_complete, true);
      assert.strictEqual(r.result, 'PASS', JSON.stringify(r.failures, null, 1));
    } finally { seed.close(); }
  });
