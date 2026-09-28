// Regression cases for every counterexample from the 2026-09-20 JS review.
// Each one passed before the review and must fail loudly if the fix is ever lost.
import { readFileSync as __rfs } from 'node:fs';
const readJson = (rel) => JSON.parse(__rfs(new URL(rel, import.meta.url), 'utf8'));

import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import N from '../../seed/v3/normalize.js';
import R from '../../seed/v3/reader.js';
import L from '../../seed/v3/logical.js';
import P from '../../seed/v3/parity.js';

const DEV = { trust: R.TRUST_UNSIGNED_DEV };
const FINAL_SIGMA = '\u03c2';   // GREEK SMALL LETTER FINAL SIGMA
const SIGMA = '\u03c3';   // GREEK SMALL LETTER SIGMA
const CHEROKEE_A = '\u13a0';   // CHEROKEE LETTER A
const NEL = '\u0085';   // NEXT LINE
const BOM = '\ufeff';   // ZERO WIDTH NO-BREAK SPACE
const ZWSP = '\u200b';   // ZERO WIDTH SPACE
const PUA = '\ue000';   // PRIVATE USE AREA
const ASTRAL = String.fromCodePoint(0x10000);

function tmpdir() { return fs.mkdtempSync(path.join(os.tmpdir(), 'cft04-cx-')); }

// --- 1. casefold is not toLowerCase, in BOTH directions -------------------------------------------
test('final sigma folds to sigma; toLowerCase leaves it alone', () => {
  assert.strictEqual(N.casefold(FINAL_SIGMA), SIGMA);
  assert.strictEqual(FINAL_SIGMA.toLowerCase(), FINAL_SIGMA, 'the naive path is the bug');
  assert.strictEqual(N.normName(FINAL_SIGMA), SIGMA);
});

test('Cherokee capitals fold to themselves; toLowerCase moves them', () => {
  assert.strictEqual(N.casefold(CHEROKEE_A), CHEROKEE_A);
  assert.notStrictEqual(CHEROKEE_A.toLowerCase(), CHEROKEE_A, 'the naive path is the bug');
  assert.strictEqual(N.normName(CHEROKEE_A), CHEROKEE_A);
});

test('an identity digest follows the fold, so the fold has to be the right one', () => {
  // Folding is for caseless matching, so both Cherokee cases legitimately fold EQUAL — case folding
  // maps the lowercase U+AB70 block back onto U+13A0. The divergence is in the VALUE a naive
  // implementation produces: toLowerCase yields U+AB70 where Python yields U+13A0, and the digest is
  // taken over that value.
  assert.strictEqual(N.identityDigest(`x@${FINAL_SIGMA}.com`), N.identityDigest(`x@${SIGMA}.com`));
  assert.strictEqual(N.casefold(CHEROKEE_A.toLowerCase()), CHEROKEE_A, 'both cases fold to U+13A0');
  assert.strictEqual(N.normEmail(`x@${CHEROKEE_A}.com`), `x@${CHEROKEE_A}.com`);
  assert.notStrictEqual(`x@${CHEROKEE_A}.com`.toLowerCase(), `x@${CHEROKEE_A}.com`,
    'a toLowerCase-based reader would have digested a different string');
});

// --- 2. str.strip() is not trim() ------------------------------------------------------------------
test('Python strips U+0085 NEL and JavaScript does not', () => {
  assert.strictEqual(N.pyStrip(`${NEL}x${NEL}`), 'x');
  assert.notStrictEqual(`${NEL}x${NEL}`.trim(), 'x', 'the naive path is the bug');
  assert.strictEqual(N.normEmail(`${NEL}Alice@example.com${NEL}`), 'alice@example.com');
});

test('JavaScript strips U+FEFF BOM and Python does not', () => {
  assert.strictEqual(N.pyStrip(`${BOM}x${BOM}`), `${BOM}x${BOM}`);
  assert.strictEqual(`${BOM}x${BOM}`.trim(), 'x', 'the naive path is the bug');
  assert.strictEqual(N.normEmail(`${BOM}Alice@example.com${BOM}`), `${BOM}alice@example.com${BOM}`);
});

test('neither strips a zero-width space', () => {
  assert.strictEqual(N.pyStrip(`${ZWSP}x`), `${ZWSP}x`);
});

// --- 3. code-point ordering, not UTF-16 code-unit ordering -----------------------------------------
test('an astral character sorts AFTER U+E000 by code point and before it in naive JS', () => {
  assert.ok(N.cmpCodePoints(PUA, ASTRAL) < 0, 'U+E000 precedes U+10000 by code point');
  assert.ok(ASTRAL < PUA, 'the naive comparison disagrees — which is the bug');
});

test('maintainer-set ordering follows code point, so the digest is stable', () => {
  const a = N.maintainersDigest([{ name: PUA }, { name: ASTRAL }]);
  const b = N.maintainersDigest([{ name: ASTRAL }, { name: PUA }]);
  assert.deepStrictEqual(a, b, 'input order must not matter');
  // The value is pinned by vectors.json, generated from canonical_maintainers_hash.
  const V = readJson('../../seed/v3/vectors.json');
  const want = V.maintainers_digest.find((v) => Array.isArray(v.in) && v.in.length === 2
    && v.in[0] && v.in[0].name === PUA && v.in[1] && v.in[1].name === ASTRAL);
  assert.ok(want, 'the counterexample must be in the generated vectors');
  assert.deepStrictEqual(a, want.out);
});

// --- 4. schema_version must be exactly an integer ---------------------------------------------------
const RULES = { channel_a: 'infra5d-1.2+fu2final+norm1+sizeshrink', dac_trajectory: 'dac-trajectory-1.0' };

function tinySeed(dir, overrides = {}) {
  const db = path.join(dir, 'seed.db');
  const con = new Database(db);
  con.exec('CREATE TABLE seed_metadata (key TEXT PRIMARY KEY, value TEXT)');
  for (const t of R.REQUIRED_TABLES) if (t !== 'seed_metadata') con.exec(`CREATE TABLE ${t} (placeholder INTEGER)`);
  const meta = {
    schema_version: '3', contract_version: 'cft-seed-v3-contract-1.0', rule_versions: JSON.stringify(RULES),
    corpus_snapshot_digest: 'a'.repeat(64), history_cutoff: '2026-09-19T20:50:26Z', ...overrides,
  };
  const ins = con.prepare('INSERT INTO seed_metadata VALUES (?, ?)');
  for (const [k, v] of Object.entries(meta)) ins.run(k, v);
  con.close();
  fs.writeFileSync(`${db}.sha256`, `${R.sha256File(db)}\n`);
  return db;
}

test('a schema_version that is not exactly an integer is refused', () => {
  // Number.parseInt('3garbage') is 3, so the lenient parse ACCEPTED a seed declaring nonsense.
  for (const bad of ['3garbage', '3.0', '3 x', '', 'three', '0x3', '3e0', 'Infinity']) {
    const rep = R.verify(tinySeed(tmpdir(), { schema_version: bad }), DEV);
    assert.strictEqual(rep.ok, false, `schema_version=${JSON.stringify(bad)} must be refused`);
    assert.match(String(rep.checks.schema_version), /this reader implements/);
  }
});

test('surrounding whitespace is still a legitimate integer, as in Python int()', () => {
  assert.strictEqual(R.verify(tinySeed(tmpdir(), { schema_version: ' 3 ' }), DEV).ok, true);
});

// --- 5. integers beyond the exactly-representable range ---------------------------------------------
const GOOD = {
  package_name: 'x', version: '1.0.0', published_s: 1700000000, lineage_id: 1, ord: 0,
  identity_digest: 'a'.repeat(64), tuple_digest: 'b'.repeat(64), maint_digest: 'c'.repeat(32),
  tool_name: 'npm', tool_key: 1001000, provenance_present: false, publish_method: 'unknown',
  has_scripts: false, body_digest: '', head_present: false, repo_digest: null,
  size_bytes: 1234, provider_class: 'unknown',
};

test('an unsafe integer is refused rather than silently rounded', () => {
  const raw = JSON.stringify(GOOD).replace('"size_bytes":1234', '"size_bytes":9007199254740993');
  const parsed = JSON.parse(raw);
  assert.strictEqual(parsed.size_bytes, 9007199254740992, 'JSON.parse alters it — that is the hazard');
  assert.throws(() => R.candidateFromMapping(parsed), /outside the exactly-representable/);
  for (const f of ['size_bytes', 'lineage_id', 'ord']) {
    assert.throws(() => R.candidateFromMapping({ ...GOOD, [f]: 2 ** 53 }), /outside the exactly-representable/);
  }
  assert.doesNotThrow(() => R.candidateFromMapping({ ...GOOD, size_bytes: Number.MAX_SAFE_INTEGER }));
});

// --- 6. EXACT fixture-to-seed binding ----------------------------------------------------------------
// The gated candidate is an internal artifact; no absolute path is baked in. Set CFT04_CANDIDATE to
// a candidate directory (containing chaingate-seed.db and fixtures/) to run these; otherwise they skip.
const CAND = process.env.CFT04_CANDIDATE || '';
const SEED = path.join(CAND, 'chaingate-seed.db');
const FIXTURES = path.join(CAND, 'fixtures');
const present = Boolean(CAND) && fs.existsSync(SEED) && fs.existsSync(path.join(FIXTURES, 'manifest.json'));

test('the JS re-derives the same seed logical digest as the producer',
  { skip: present ? false : 'set CFT04_CANDIDATE to a gated candidate directory to run this', timeout: 600000 }, () => {
    const man = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'manifest.json'), 'utf8'));
    assert.strictEqual(L.logicalDigestOfDb(SEED), man.seed_logical_digest);
  });

test('a pack whose manifest names a DIFFERENT seed fails on exact binding',
  { skip: present ? false : 'set CFT04_CANDIDATE to a gated candidate directory to run this', timeout: 600000 }, () => {
    // corpus_snapshot_digest and rule_versions are shared by every build of the same snapshot under
    // the same rules, so before this check such a pack passed parity outright.
    const dir = tmpdir();
    const pack = path.join(dir, 'pack');
    fs.mkdirSync(pack);
    fs.copyFileSync(path.join(FIXTURES, 'manifest.json'), path.join(pack, 'manifest.json'));
    fs.copyFileSync(path.join(FIXTURES, 'fixtures.jsonl'), path.join(pack, 'fixtures.jsonl'));
    const man = JSON.parse(fs.readFileSync(path.join(pack, 'manifest.json'), 'utf8'));
    man.seed_logical_digest = '0'.repeat(64);
    fs.writeFileSync(path.join(pack, 'manifest.json'), JSON.stringify(man));
    const seed = R.openSeed(SEED, DEV);
    try {
      const { checks } = P.acceptance(pack, seed);
      assert.notStrictEqual(checks.seed_logical_digest_rederived, true);
      assert.match(String(checks.seed_logical_digest_rederived), /re-derived .* != manifest/);
      // the weaker bindings still pass, which is exactly why they were not enough
      assert.strictEqual(checks['seed_binding.corpus_snapshot_digest'], true);
      assert.strictEqual(checks['seed_binding.rule_versions'], true);
    } finally { seed.close(); }
  });

test('the logical digest formats floats the way Python does', () => {
  // This previously REFUSED anything at or beyond 1e16 because the formatting was unfinished. The
  // portability pass completed it, so the exponent window is now handled rather than declined; what
  // remains refused is only what json.dumps could not write as JSON at all.
  assert.strictEqual(L.pyFloat(1001000), '1001000.0', 'an integral REAL keeps its .0, as Python writes it');
  assert.notStrictEqual(String(1001000), L.pyFloat(1001000));
  assert.strictEqual(L.pyFloat(1e16), '1e+16', 'Python switches to exponent here; JavaScript does not');
  assert.strictEqual(String(1e16), '10000000000000000');
  assert.throws(() => L.pyFloat(Infinity), L.NonPortableValue);
  assert.throws(() => L.pyFloat(NaN), L.NonPortableValue);
});
