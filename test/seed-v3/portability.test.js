// The portability pass: the remaining normalisation paths, logical-number formatting, the end-to-end
// raw-row adapter, and the qualification gate. Every expectation here comes from producer-generated
// vectors, and every place exact reproduction is unsupported refuses by name instead of guessing.

import test from 'node:test';
import assert from 'node:assert';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import N from '../../seed/v3/normalize.js';
import X from '../../seed/v3/normalize-extra.js';
import A from '../../seed/v3/adapter.js';
import L from '../../seed/v3/logical.js';
import CONF from '../../seed/v3/conformance.js';

const DIRNAME = dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(join(DIRNAME, '..', '..', 'seed', 'v3', 'vectors.json'), 'utf8'));

// --- repository URL ---------------------------------------------------------------------------------
test('canonical_repo_url matches the producer on every vector', () => {
  for (const v of V.canonical_repo_url) {
    assert.deepStrictEqual(X.canonicalRepoUrl(v.in), v.out, JSON.stringify(v.in));
  }
});

test('repo_digest matches the producer, and an unparseable URL is null rather than a guessed key', () => {
  for (const v of V.repo_digest) assert.deepStrictEqual(X.repoDigest(v.in), v.out, JSON.stringify(v.in));
  assert.strictEqual(X.repoDigest('not a url'), null);
  assert.strictEqual(X.repoDigest('https://localhost/o/r'), null, 'a host without a dot is not a host');
  // scheme, git+ prefix, SCP form and .git suffix all collapse to the same key
  const want = X.canonicalRepoUrl('https://github.com/owner/repo');
  for (const u of ['git+https://github.com/owner/repo.git', 'git@github.com:owner/repo.git',
    'HTTPS://GitHub.COM/Owner/Repo', 'git://github.com/owner/repo']) {
    assert.strictEqual(X.canonicalRepoUrl(u), want, u);
  }
});

// --- publisher tool ---------------------------------------------------------------------------------
test('parse_publisher_tool matches the producer, including the incomparable cases', () => {
  for (const v of V.parse_publisher_tool) {
    assert.deepStrictEqual(X.parsePublisherTool(v.in), v.out, JSON.stringify(v.in));
  }
  assert.deepStrictEqual(X.parsePublisherTool('npm@10.2.3'), ['npm', 10002003]);
  assert.deepStrictEqual(X.parsePublisherTool('npm@10.2.3 linux-x64'), ['npm', 10002003],
    'the platform token is discarded by the anchor');
  assert.deepStrictEqual(X.parsePublisherTool(null), ['', 0], 'empty name = incomparable, not a downgrade');
});

// --- staged-publish approver unfold -------------------------------------------------------------------
test('resolve_publisher_email matches the producer, including the approver shapes', () => {
  for (const v of V.resolve_publisher_email) {
    assert.strictEqual(X.resolvePublisherEmail(v.email, v.raw_metadata), v.out,
      JSON.stringify([v.email, v.raw_metadata]));
  }
});

test('identity follows the approver unfold, not the raw publisher field', () => {
  for (const v of V.identity_digest_with_metadata) {
    assert.strictEqual(X.identityDigestOf(v.email, v.raw_metadata), v.out,
      JSON.stringify([v.email, v.raw_metadata]));
  }
  const meta = { approver: { publisher_email: 'orig@example.com' } };
  assert.strictEqual(X.identityDigestOf('approver@example.com', meta), N.identityDigest('orig@example.com'));
});

// --- logical-number formatting -------------------------------------------------------------------------
test('Python float repr matches the producer on every vector, including the switch points', () => {
  for (const v of V.python_float_repr) {
    const num = v.in === '-0.0' ? -0 : Number(v.in);
    assert.strictEqual(L.pyFloat(num), v.out, `repr(${v.in})`);
  }
});

test('Python and JavaScript disagree about float formatting, which is why this exists', () => {
  assert.strictEqual(L.pyFloat(1001000), '1001000.0');
  assert.strictEqual(String(1001000), '1001000', 'the naive path drops the fractional part');
  assert.strictEqual(L.pyFloat(1e16), '1e+16');
  assert.strictEqual(String(1e16), '10000000000000000', 'and uses a different exponent window');
  assert.strictEqual(L.pyFloat(1e-5), '1e-05', 'Python pads the exponent to two digits');
  assert.strictEqual(L.pyFloat(-0), '-0.0');
});

test('values json.dumps could not write as JSON are refused by name', () => {
  assert.throws(() => L.pyFloat(NaN), L.NonPortableValue);
  assert.throws(() => L.pyFloat(Infinity), L.NonPortableValue);
  assert.throws(() => L.pyFloat(-Infinity), L.NonPortableValue);
});

test('a SQLite integer too large for a double is carried exactly, not rounded', () => {
  // better-sqlite3 rounds silently by default; the digest enables safe integers, so a BigInt arrives
  // and is serialised exactly the way Python's unbounded int would be.
  assert.strictEqual(L.jsonValue(9007199254740993n, false), '9007199254740993');
  assert.strictEqual(L.jsonValue(-9007199254740993n, false), '-9007199254740993');
  assert.throws(() => L.jsonValue(9007199254740993, false), L.NonPortableValue,
    'a rounded double must never be digested as if it were exact');
});

// --- end-to-end raw row -> candidate ---------------------------------------------------------------------
const E2E_PATH = join(DIRNAME, '..', '..', 'seed', 'v3', 'e2e-vectors.json');
const e2ePresent = existsSync(E2E_PATH);

test('the adapter reproduces the producer on real extract rows (candidate only, no finding)',
  { skip: e2ePresent ? false : 'no e2e-vectors.json; generate with make_e2e_vectors.py' }, () => {
    const r = CONF.adapterConformance(E2E_PATH);
    assert.strictEqual(r.result, 'PASS', JSON.stringify(r.failures, null, 1));
    assert.ok(r.cases > 0 && r.agreeing === r.cases);
  });

const RAW = {
  version: '1.2.3', published_at: '2026-01-02T03:04:05Z', publisher_name: 'Alice',
  publisher_email: 'Alice@Example.COM', publisher_tool: 'npm@10.2.3',
  published_with_node_version: 'v20.11.0', maintainers: [{ name: 'alice', email: 'alice@example.com' }],
  provenance_present: true, publish_method: 'oidc', has_install_scripts: false,
  install_script: null, preinstall_script: null, postinstall_script: null,
  git_head: 'abc123', source_repo_url: 'git+https://github.com/owner/repo.git',
  package_size_bytes: 12345,
};

test('the adapter refuses what it cannot derive faithfully, rather than defaulting it', () => {
  const opts = { packageName: 'p', domainVersionCount: 0 };
  assert.doesNotThrow(() => A.candidateFromRawRow(RAW, opts));
  // a missing observation is not `false`: every field, not a chosen few
  for (const k of Object.keys(RAW)) {
    const row = { ...RAW }; delete row[k];
    assert.throws(() => A.candidateFromRawRow(row, opts), /is required/, `${k} must be required`);
  }
  // a field this adapter does not understand may be the one carrying the evidence
  assert.throws(() => A.candidateFromRawRow({ ...RAW, some_new_field: 1 }, opts), /unknown raw fields/);
  // provider_class depends on it, and 0 means "no other versions", not "unknown"
  assert.throws(() => A.candidateFromRawRow(RAW, { packageName: 'p' }), /domainVersionCount/);
  assert.throws(() => A.candidateFromRawRow(RAW, { packageName: 'p', domainVersionCount: -1 }), /domainVersionCount/);
  // booleans must be booleans
  assert.throws(() => A.candidateFromRawRow({ ...RAW, has_install_scripts: 1 }, opts), /must be a boolean/);
  // an unparseable timestamp is refused, never coerced to null (which would mean "no publication time")
  assert.throws(() => A.candidateFromRawRow({ ...RAW, published_at: 'not a date' }, opts), /not an ISO-8601 timestamp/);
});

test('the adapter passes through the same candidate boundary as every other entry point', () => {
  const opts = { packageName: 'p', domainVersionCount: 0 };
  assert.throws(() => A.candidateFromRawRow({ ...RAW, package_size_bytes: -1 }, opts), /must be >= 0/);
  assert.throws(() => A.candidateFromRawRow({ ...RAW, package_size_bytes: 2 ** 53 }, opts),
    /outside the exactly-representable/);
});

test('the adapter normalises exactly as the unit vectors say', () => {
  const c = A.candidateFromRawRow(RAW, { packageName: 'p', domainVersionCount: 0 });
  assert.strictEqual(c.identity_digest, N.identityDigest('alice@example.com'));
  assert.strictEqual(c.tuple_digest, N.tupleDigest('Alice', 'Alice@Example.COM'));
  assert.strictEqual(c.repo_digest, X.repoDigest('https://github.com/owner/repo'));
  assert.deepStrictEqual([c.tool_name, c.tool_key], X.parsePublisherTool('npm@10.2.3'));
  assert.strictEqual(c.provider_class, 'unverified', 'domainVersionCount 0 on a corporate domain');
  assert.strictEqual(c.published_s, Math.floor(Date.parse('2026-01-02T03:04:05Z') / 1000));
  assert.strictEqual(c.head_present, true);
  assert.strictEqual(c.body_digest, '', 'no install body');
});

// --- qualification gate ---------------------------------------------------------------------------------
test('a CFT acceptance run requires the artifact; a developer run may skip it', () => {
  const saved = process.env.CFT04_CANDIDATE;
  const savedQ = process.env.CFT_QUALIFY;
  try {
    delete process.env.CFT04_CANDIDATE;
    const missing = CONF.resolveCandidate();
    assert.strictEqual(missing.ok, false);
    assert.match(missing.reason, /must be handed the gated candidate directory/);

    delete process.env.CFT_QUALIFY;
    assert.strictEqual(CONF.isQualification(), false, 'ordinary development by default');
    process.env.CFT_QUALIFY = '1';
    assert.strictEqual(CONF.isQualification(), true, 'CFT_QUALIFY=1 makes it qualification');

    process.env.CFT04_CANDIDATE = '/definitely/not/a/candidate';
    const bad = CONF.resolveCandidate();
    assert.strictEqual(bad.ok, false);
    assert.match(bad.reason, /does not contain chaingate-seed\.db/);
  } finally {
    if (saved === undefined) delete process.env.CFT04_CANDIDATE; else process.env.CFT04_CANDIDATE = saved;
    if (savedQ === undefined) delete process.env.CFT_QUALIFY; else process.env.CFT_QUALIFY = savedQ;
  }
});
