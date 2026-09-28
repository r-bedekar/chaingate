// Regression cases for the 2026-09-20 follow-up review: the six red probes, the adapter's invented
// observations, and the adapter-vector scope/acceptance defects.

import test from 'node:test';
import assert from 'node:assert';
import { readFileSync, existsSync, writeFileSync, mkdtempSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';

import N from '../../seed/v3/normalize.js';
import A from '../../seed/v3/adapter.js';
import R from '../../seed/v3/reader.js';
import CONF from '../../seed/v3/conformance.js';

const DIRNAME = dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(join(DIRNAME, '..', '..', 'seed', 'v3', 'vectors.json'), 'utf8'));

const NEL = '\u0085';        // NEXT LINE: Python whitespace, not JavaScript's        // NEXT LINE: Python whitespace, not JavaScript's
const BOM = '\ufeff';        // ZERO WIDTH NO-BREAK SPACE: JavaScript whitespace, not Python's        // ZERO WIDTH NO-BREAK SPACE: JavaScript whitespace, not Python's
const AR3 = '\u0663';        // ARABIC-INDIC DIGIT THREE: matched by Python's \d, not by JS's        // ARABIC-INDIC DIGIT THREE: matched by Python's \d, not by JS's

// --- 1. script-body hashing uses PYTHON's lower and PYTHON's whitespace -----------------------------
test('install-body digest splits on Python whitespace, not the JS class', () => {
  // JS \s contains U+FEFF and not U+0085; Python's split() is the other way round, so each body
  // normalised differently and hashed differently on the two sides.
  const byInput = new Map(V.install_body_digest.map((v) => [JSON.stringify([v.install, v.preinstall, v.postinstall]), v.out]));
  for (const v of V.install_body_digest) {
    assert.deepStrictEqual(N.installBodyDigest(v.install, v.preinstall, v.postinstall), v.out);
  }
  assert.ok(byInput.size > 0);
  // the two counterexamples, stated directly
  assert.deepStrictEqual(N.pySplitWhitespace(`echo${NEL}ok`), ['echo', 'ok']);
  assert.deepStrictEqual(`echo${NEL}ok`.split(/\s+/), [`echo${NEL}ok`], 'the naive split is the bug');
  assert.deepStrictEqual(N.pySplitWhitespace(`echo${BOM}ok`), [`echo${BOM}ok`]);
  assert.deepStrictEqual(`echo${BOM}ok`.split(/\s+/), ['echo', 'ok'], 'and it is wrong the other way too');
});

test('install-body digest lowercases the way str.lower does', () => {
  assert.strictEqual(N.pyLower('ABC'), 'abc');
  // the table is generated from CPython, so this asserts agreement rather than assuming it
  const lower = JSON.parse(readFileSync(join(DIRNAME, '..', '..', 'seed', 'v3', 'unicode-tables.json'), 'utf8')).lower;
  let checked = 0;
  for (const [hex, want] of Object.entries(lower)) {
    const ch = String.fromCodePoint(Number.parseInt(hex, 16));
    assert.strictEqual(N.pyLower(ch), want, `U+${hex.toUpperCase()}`);
    checked += 1;
  }
  assert.ok(checked > 1000, `expected a full table, checked ${checked}`);
});

// --- 2. node_major follows Python's Unicode \d -------------------------------------------------------
test('node_major matches Python on Unicode digits', () => {
  for (const v of V.node_major) assert.strictEqual(N.nodeMajor(v.in), v.out, JSON.stringify(v.in));
  assert.strictEqual(N.nodeMajor(`v${AR3}.0.0`), AR3);
  assert.strictEqual(/^v?(\d+)/.exec(`v${AR3}.0.0`), null, 'the ASCII-only regex is the bug');
});

// --- 3. repr escaping, and what JavaScript genuinely cannot represent ---------------------------------
test('repr escapes non-printable characters the way Python does', () => {
  assert.strictEqual(N.pyRepr(NEL), `'\\x85'`);
  assert.strictEqual(N.pyRepr('\u2028'), `'\\u2028'`);
  assert.strictEqual(N.pyRepr(String.fromCodePoint(0x10ffff)), `'\\U0010ffff'`);
  assert.strictEqual(N.pyRepr('ok'), `'ok'`);
  assert.strictEqual(N.pyIsPrintable(0x20), true, 'space is printable');
  assert.strictEqual(N.pyIsPrintable(0x85), false);
  assert.strictEqual(N.pyIsPrintable(0xfeff), false);
});

test('a maintainer set whose repr JavaScript cannot reproduce is REFUSED, not guessed', () => {
  // Both of these survive JSON.parse in a form Python would have distinguished.
  assert.throws(() => N.maintainersDigest([{ name: 1.0 }]), /ambiguous/);
  assert.throws(() => N.maintainersDigest([{ 2: 'b', 1: 'a' }]), /integer-like keys/);
  // and the vectors say which inputs those are, so conformance can require the refusal
  const unrepresentable = V.maintainers_digest.filter((v) => v.representable_in_js === false);
  assert.ok(unrepresentable.length >= 3, 'the counterexamples must be marked in the vectors');
  for (const v of unrepresentable) assert.throws(() => N.maintainersDigest(v.in));
});

test('everything else on the repr path reproduces exactly', () => {
  for (const v of V.maintainers_digest.filter((x) => x.representable_in_js !== false)) {
    assert.deepStrictEqual(N.maintainersDigest(v.in), v.out, JSON.stringify(v.in));
  }
  assert.deepStrictEqual(N.maintainersDigest([{ email: `${NEL}alice@example.com` }])[0].length, 32);
});

// --- 4. the adapter no longer invents or moves observations --------------------------------------------
const RAW = {
  version: '1.0.0', published_at: '2026-01-02T03:04:05Z', publisher_name: null, publisher_email: null,
  publisher_tool: null, published_with_node_version: null, maintainers: null, provenance_present: false,
  publish_method: null, has_install_scripts: false, install_script: null, preinstall_script: null,
  postinstall_script: null, git_head: null, source_repo_url: null, package_size_bytes: null,
};
const OPTS = { packageName: 'review-synthetic', domainVersionCount: 0 };

test('an OMITTED observation is refused; explicit null is how absence is stated', () => {
  assert.doesNotThrow(() => A.candidateFromRawRow(RAW, OPTS));
  for (const k of Object.keys(RAW)) {
    const row = { ...RAW }; delete row[k];
    assert.throws(() => A.candidateFromRawRow(row, OPTS), /is required/, `omitting ${k} must be refused`);
  }
  // the specific case from the review: an omitted git_head became head_present:false, which is the
  // gitHead-disappearance witness firing on an observation nobody made.
  const noHead = { ...RAW }; delete noHead.git_head;
  assert.throws(() => A.candidateFromRawRow(noHead, OPTS), /git_head is required/);
});

test('gitHead presence uses Python strip, so it agrees about U+0085 and U+FEFF', () => {
  // Python: `bool(gh) and str(gh).strip() != ""`
  assert.strictEqual(A.candidateFromRawRow({ ...RAW, git_head: NEL }, OPTS).head_present, false);
  assert.strictEqual(A.candidateFromRawRow({ ...RAW, git_head: BOM }, OPTS).head_present, true);
  assert.strictEqual(NEL.trim(), NEL, 'JS trim leaves NEL — the bug in one direction');
  assert.strictEqual(BOM.trim(), '', 'JS trim removes BOM — the bug in the other');
});

test('an impossible calendar date is refused, never silently re-dated', () => {
  // Date.parse rolls 2026-02-30 to 2026-03-02, which MOVES the candidate within package history.
  assert.throws(() => A.candidateFromRawRow({ ...RAW, published_at: '2026-02-30T00:00:00Z' }, OPTS),
    /not a real calendar date/);
  assert.throws(() => A.candidateFromRawRow({ ...RAW, published_at: '2026-04-31T00:00:00Z' }, OPTS),
    /not a real calendar date/);
  assert.throws(() => A.candidateFromRawRow({ ...RAW, published_at: '2026-13-01T00:00:00Z' }, OPTS),
    /out-of-range|not an ISO-8601/);
  assert.throws(() => A.candidateFromRawRow({ ...RAW, published_at: 'yesterday' }, OPTS), /not an ISO-8601/);
  // real dates still work, leap day included
  assert.strictEqual(A.candidateFromRawRow({ ...RAW, published_at: '2028-02-29T00:00:00Z' }, OPTS).published_s,
    Math.floor(Date.UTC(2028, 1, 29) / 1000));
  assert.strictEqual(A.candidateFromRawRow({ ...RAW, published_at: '2026-01-02T03:04:05+02:00' }, OPTS).published_s,
    Math.floor(Date.UTC(2026, 0, 2, 3, 4, 5) / 1000) - 7200);
});

// --- 5. adapter-vector acceptance -----------------------------------------------------------------------
test('an empty or malformed adapter-vector file is NOT a pass', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cft04-acc-'));
  const write = (name, body) => { const p = join(dir, name); writeFileSync(p, JSON.stringify(body)); return p; };

  const empty = write('empty.json', { schema: 'adapter-vectors-1', domain_version_count: 0, cases: [] });
  const r1 = CONF.adapterConformance(empty);
  assert.strictEqual(r1.result, 'FAIL', 'an empty pack returned PASS 0/0 before this');
  assert.match(String(r1.acceptance.cases_non_empty), /not a PASS/);

  const noSchema = write('noschema.json', { domain_version_count: 0, cases: [{ package_name: 'x', row: {}, expected: {} }] });
  assert.strictEqual(CONF.adapterConformance(noSchema).acceptance.schema !== true, true);

  const noCount = write('nocount.json', { schema: 'adapter-vectors-1', cases: [{ package_name: 'x', row: {}, expected: {} }] });
  assert.notStrictEqual(CONF.adapterConformance(noCount).acceptance.domain_version_count_declared, true);

  const malformed = write('malformed.json', { schema: 'adapter-vectors-1', domain_version_count: 0, cases: [{ nope: 1 }] });
  assert.notStrictEqual(CONF.adapterConformance(malformed).acceptance.cases_well_formed, true);
});

test('the adapter result states its scope, and does not claim to be a finding', () => {
  const r = CONF.adapterConformance();
  if (r.result === 'UNAVAILABLE') return;
  assert.match(r.what, /EXTRACT row -> candidate/);
  assert.match(r.what, /NOT a finding/);
});

// --- 6. the composed path: row -> candidate -> finding, with real history ----------------------------------
const CAND = process.env.CFT04_CANDIDATE || '';
const SEED = CAND ? join(CAND, 'chaingate-seed.db') : '';
const havePack = Boolean(CAND) && existsSync(SEED)
  && existsSync(join(DIRNAME, '..', '..', 'seed', 'v3', 'composed-vectors.json'));

test('composed conformance: raw row -> candidate -> finding against real package history',
  { skip: havePack ? false : 'set CFT04_CANDIDATE to a gated candidate directory to run this', timeout: 600000 },
  async () => {
    const seed = R.openSeed(SEED, { trust: R.TRUST_UNSIGNED_DEV });
    try {
      // the fixtures directory is what lets the binding be ESTABLISHED rather than read; see
      // review-binding.test.js for why corpus_snapshot_digest alone is not the binding.
      const r = await CONF.composedConformance(seed, { fixturesDir: join(CAND, 'fixtures') });
      assert.strictEqual(r.acceptance.has_real_history, true, 'null lineage everywhere exercises no history');
      assert.strictEqual(r.acceptance.bound_to_this_seed, true);
      assert.strictEqual(r.acceptance.bound_to_seed_logical_digest, true);
      assert.strictEqual(r.acceptance.bound_to_fixtures_digest, true);
      assert.strictEqual(r.result, 'PASS', JSON.stringify(r.failures, null, 1));
      assert.ok(r.cases > 0 && r.agreeing === r.cases);
      assert.ok(r.packages > 1, 'the cases must span more than one package history');
    } finally { seed.close(); }
  });

test('composed vectors bound to a DIFFERENT seed fail acceptance, not comparison',
  { skip: havePack ? false : 'candidate not present', timeout: 600000 }, async () => {
    const seed = R.openSeed(SEED, { trust: R.TRUST_UNSIGNED_DEV });
    try {
      const fake = { ...seed, meta: { ...seed.meta, corpus_snapshot_digest: '0'.repeat(64) } };
      const r = await CONF.composedConformance(fake, { fixturesDir: join(CAND, 'fixtures') });
      assert.strictEqual(r.result, 'FAIL');
      assert.strictEqual(r.failure, 'acceptance');
      assert.notStrictEqual(r.acceptance.bound_to_this_seed, true);
    } finally { seed.close(); }
  });

// --- 7. export drift ---------------------------------------------------------------------------------
test('every named export is also in the module default export', async () => {
  // The new helpers reached the named list and not the default object, so tests importing the default
  // saw `undefined` rather than a function. A structural check costs nothing and catches it.
  const mods = ['contract.js', 'checker.js', 'normalize.js', 'normalize-extra.js', 'adapter.js',
    'logical.js', 'reader.js', 'parity.js', 'conformance.js'];
  for (const m of mods) {
    const x = await import(`../../seed/v3/${m}`);
    const named = Object.keys(x).filter((k) => k !== 'default');
    const dflt = new Set(Object.keys(x.default || {}));
    const missing = named.filter((k) => !dflt.has(k));
    assert.deepStrictEqual(missing, [], `${m} default export is missing: ${missing.join(', ')}`);
  }
});
