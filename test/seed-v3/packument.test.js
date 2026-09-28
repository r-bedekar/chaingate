// CFT-05 — the npm packument adapter and the assembled installation path.
//
// The 400-case extract-row set does not cover any of this. Its input is a producer EXTRACT row whose
// columns were already chosen, named and normalised by the collector; a packument is the registry's
// own document — versions{} keyed by version string, a separate time{} map, nested dist{}, _npmUser,
// scripts{}, and a `repository` that is a string in some packages and an object in others.

import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import { createHash } from 'node:crypto';

import PK from '../../seed/v3/packument.js';
import A from '../../seed/v3/adapter.js';
import POL from '../../seed/v3/policy.js';
import G from '../../seed/v3/gate.js';
import R from '../../seed/v3/reader.js';
import CONF from '../../seed/v3/conformance.js';

// --- against real packuments ---------------------------------------------------------------------
test('the adapter reproduces the producer over REAL npm packuments', () => {
  const r = CONF.packumentConformance();
  if (r.result === 'UNAVAILABLE') {
    assert.fail('packument-vectors.json is missing; generate with make_packument_vectors.py');
  }
  assert.strictEqual(r.result, 'PASS', JSON.stringify(r.failures, null, 1));
  assert.ok(r.cases > 100, `only ${r.cases} real versions`);
  assert.ok(r.adversarial_cases >= 20, `only ${r.adversarial_cases} adversarial manifests`);
  // `agreeing` counts BOTH halves: the real packuments and the adversarial manifests.
  assert.strictEqual(r.agreeing, r.cases + r.adversarial_cases,
    `${r.agreeing} of ${r.cases + r.adversarial_cases}`);
  assert.strictEqual(r.adversarial_agreeing, r.adversarial_cases);
  assert.ok(r.packages >= 10, 'the fixtures must span more than a couple of packages');
  assert.deepStrictEqual(r.refused_versions, [], 'no real version should be unreadable');
  // The producer's oracle does not enforce the candidate contract, so it can emit candidates the
  // consumer must refuse. Reported explicitly rather than absorbed.
  for (const v of r.producer_contract_violations) {
    assert.ok(v.violations.length > 0, `${v.label} was carved out without a spec violation`);
  }
});

test('the packument result is reported separately and states what it does NOT cover', () => {
  const r = CONF.packumentConformance();
  assert.match(r.what, /packument -> observation row -> candidate/);
  assert.match(r.what, /NOT a finding/);
  assert.match(r.ground_truth, /_parse_single_version/);
});

// --- the mapping, case by case -----------------------------------------------------------------------
const MANIFEST = {
  name: 'p',
  version: '1.2.3',
  _npmUser: { name: 'Alice', email: 'Alice@Example.COM' },
  _npmVersion: '10.2.3',
  _nodeVersion: 'v20.11.0',
  maintainers: [{ name: 'alice', email: 'alice@example.com' }],
  gitHead: 'abc123',
  repository: { type: 'git', url: 'git+https://github.com/owner/repo.git' },
  dist: { shasum: 'aa', integrity: 'sha512-x', tarball: 'https://x/p.tgz', unpackedSize: 12345 },
};
const obs = (over = {}) => PK.observationFromManifest('1.2.3', { ...MANIFEST, ...over },
  '2026-01-02T03:04:05.000Z');

test('every observation is stated: no field is omitted and none is defaulted away', () => {
  const row = obs();
  const RAW = ['version', 'published_at', 'publisher_name', 'publisher_email', 'publisher_tool',
    'published_with_node_version', 'maintainers', 'provenance_present', 'publish_method',
    'has_install_scripts', 'install_script', 'preinstall_script', 'postinstall_script',
    'git_head', 'source_repo_url', 'package_size_bytes', 'raw_metadata'];
  assert.deepStrictEqual(Object.keys(row).sort(), [...RAW].sort());
  // a manifest carrying almost nothing still states every field, as explicit null
  const bare = PK.observationFromManifest('0.0.1', { name: 'p', version: '0.0.1' }, null);
  assert.deepStrictEqual(Object.keys(bare).sort(), [...RAW].sort());
  assert.strictEqual(bare.publisher_email, null);
  assert.strictEqual(bare.git_head, null);
  assert.strictEqual(bare.published_at, null);
  assert.strictEqual(bare.package_size_bytes, null);
  assert.strictEqual(bare.provenance_present, false, 'no attestations is an observation');
  assert.strictEqual(bare.publish_method, 'unknown');
});

test('publisher, tool and node version follow the producer exactly', () => {
  assert.strictEqual(obs().publisher_name, 'Alice');
  assert.strictEqual(obs().publisher_email, 'Alice@Example.COM', 'raw here; normalisation is later');
  assert.strictEqual(obs().publisher_tool, 'npm@10.2.3');
  assert.strictEqual(obs({ _npmVersion: '  10.2.3  ' }).publisher_tool, 'npm@10.2.3');
  assert.strictEqual(obs({ _npmVersion: '   ' }).publisher_tool, null, 'blank is not a tool');
  assert.strictEqual(obs({ _npmVersion: 10 }).publisher_tool, null, 'a non-string is not a tool');
  // published_with_node_version is the backfill rule: the value only if it is a JSON string,
  // with no strip and no truncation.
  assert.strictEqual(obs().published_with_node_version, 'v20.11.0');
  assert.strictEqual(obs({ _nodeVersion: ' v20 ' }).published_with_node_version, ' v20 ');
  assert.strictEqual(obs({ _nodeVersion: 20 }).published_with_node_version, null);
});

test('install scripts follow the Q4 lock, including where its two halves disagree', () => {
  const s = (scripts) => obs({ scripts });
  assert.strictEqual(s({ preinstall: 'node x.js' }).has_install_scripts, true);
  assert.strictEqual(s({ preinstall: 'node x.js' }).preinstall_script, 'node x.js');
  assert.strictEqual(s({ test: 'jest' }).has_install_scripts, false, 'test is not an install hook');
  assert.strictEqual(s({ preinstall: '' }).has_install_scripts, false, 'an empty string is falsy');
  // the documented disagreement: a truthy NON-STRING hook sets the boolean and leaves the columns null
  const odd = s({ install: ['node', 'x.js'] });
  assert.strictEqual(odd.has_install_scripts, true);
  assert.strictEqual(odd.install_script, null);
  // ...and PYTHON truthiness decides, which differs from JavaScript's on values a registry stores
  assert.strictEqual(s({ install: [] }).has_install_scripts, false, 'Python: [] is falsy');
  assert.strictEqual(s({ install: {} }).has_install_scripts, false, 'Python: {} is falsy');
  assert.strictEqual(s({ install: 0 }).has_install_scripts, false, 'Python: 0 is falsy');
  assert.strictEqual(s({ install: '0' }).has_install_scripts, true, "but '0' is truthy in both");
  assert.strictEqual(obs({ scripts: 'not an object' }).has_install_scripts, false);
});

test('gitHead takes Python strip and a 64-character cap; repository takes both shapes', () => {
  assert.strictEqual(obs({ gitHead: '  abc123  ' }).git_head, 'abc123');
  assert.strictEqual(obs({ gitHead: '   ' }).git_head, null, 'blank is absent, not empty');
  assert.strictEqual(obs({ gitHead: 'x'.repeat(80) }).git_head, 'x'.repeat(64));
  assert.strictEqual(obs({ gitHead: 42 }).git_head, null);
  assert.strictEqual(obs({ repository: 'https://github.com/owner/repo' }).source_repo_url,
    'https://github.com/owner/repo', 'old packages store a bare string');
  assert.strictEqual(obs({ repository: { type: 'git' } }).source_repo_url, null, 'no url');
  assert.strictEqual(obs({ repository: ['x'] }).source_repo_url, null);
});

test('provenance is the presence of dist.attestations, and drives publish_method', () => {
  const withProv = obs({ dist: { ...MANIFEST.dist, attestations: { url: 'https://x', provenance: {} } } });
  assert.strictEqual(withProv.provenance_present, true);
  assert.strictEqual(withProv.publish_method, 'oidc');
  assert.strictEqual(obs().provenance_present, false);
  assert.strictEqual(obs().publish_method, 'unknown');
});

test('a size is carried RAW, and refused at the candidate boundary rather than nulled', () => {
  // The producer stores `dist.get("unpackedSize")` with no type guard. Nulling a float here replaced
  // "a size that cannot be used" with "no size was observed" -- a different claim about the release.
  assert.strictEqual(obs({ dist: { unpackedSize: 1234 } }).package_size_bytes, 1234);
  assert.strictEqual(obs({ dist: { unpackedSize: '1234' } }).package_size_bytes, '1234');
  assert.strictEqual(obs({ dist: { unpackedSize: 12.5 } }).package_size_bytes, 12.5);
  assert.strictEqual(obs({ dist: {} }).package_size_bytes, null, 'absent really is absent');
  // ...and the boundary is where it is refused, by name
  const opts = { packageName: 'p', domainVersionCount: 0 };
  assert.throws(() => A.candidateFromRawRow(obs({ dist: { unpackedSize: 12.5 } }), opts),
    /size_bytes: must be an integer/);
  assert.throws(() => A.candidateFromRawRow(obs({ dist: { unpackedSize: -1 } }), opts),
    /size_bytes: must be >= 0/);
});

test('provenance takes PYTHON truthiness, because a witness depends on it', () => {
  // `Boolean({})` is true in JavaScript and `bool({})` is false in Python. An empty attestations
  // object made this adapter report provenance PRESENT where the producer reports absent.
  for (const attestations of [{}, [], '', 0, false, null, undefined]) {
    const row = obs({ dist: { ...MANIFEST.dist, attestations } });
    assert.strictEqual(row.provenance_present, false, JSON.stringify(attestations) || 'undefined');
    assert.strictEqual(row.publish_method, 'unknown');
  }
  for (const attestations of [{ url: 'x' }, ['x'], 'yes', 1, true]) {
    const row = obs({ dist: { ...MANIFEST.dist, attestations } });
    assert.strictEqual(row.provenance_present, true, JSON.stringify(attestations));
    assert.strictEqual(row.publish_method, 'oidc');
  }
});

test('the publisher fields are refused exactly where the producer refuses them', () => {
  const opts = { packageName: 'p', domainVersionCount: 0 };
  // the PARSER fails on a non-object _npmUser: no row exists at all
  assert.throws(() => obs({ _npmUser: 'alice' }), /_npmUser is string/);
  assert.throws(() => obs({ _npmUser: ['alice'] }), /_npmUser is an array/);
  // a TRUTHY non-string reaches the row, and the candidate step refuses it
  const truthy = obs({ _npmUser: { name: 1, email: 2 } });
  assert.strictEqual(truthy.publisher_name, 1, 'the row records what was observed');
  assert.throws(() => A.candidateFromRawRow(truthy, opts),
    /publisher_name must be a string or null/);
  // a FALSY non-string is coerced by the producer's `x or ""`, so it is NOT refused
  const falsy = obs({ _npmUser: { name: 0, email: false } });
  assert.doesNotThrow(() => A.candidateFromRawRow(falsy, opts));
});

// --- refusals -------------------------------------------------------------------------------------------
test('what the packument does not permit an observation of is refused, never guessed', () => {
  assert.throws(() => PK.observationFromManifest('1.0.0', null, null), PK.PackumentRejected);
  assert.throws(() => PK.observationFromManifest('', MANIFEST, null), PK.PackumentRejected);
  // the key and the manifest naming different releases: nothing here can say which is right
  assert.throws(() => PK.observationFromManifest('9.9.9', MANIFEST, null),
    /key and the manifest name different releases/);
  assert.throws(() => PK.observationFromManifest('1.2.3', MANIFEST, 12345), /time\[.*\] is not a string/);
  assert.throws(() => PK.observationsFromPackument({ versions: {} }), /no name/);
  assert.throws(() => PK.observationsFromPackument({ name: 'p' }), /no versions object/);
  assert.throws(() => PK.observationsFromPackument('not a packument'), PK.PackumentRejected);
});

test('a version the document cannot be read for is REPORTED, never silently dropped', () => {
  const doc = {
    name: 'p',
    versions: { '1.0.0': { name: 'p', version: '1.0.0' }, '2.0.0': null,
      '3.0.0': { name: 'p', version: '3.0.1' } },
    time: { '1.0.0': '2026-01-01T00:00:00.000Z' },
  };
  const r = PK.observationsFromPackument(doc);
  assert.strictEqual(r.versions_seen, 3, 'the count is of what the document offered');
  assert.strictEqual(r.rows.length, 1);
  assert.deepStrictEqual(r.refused.map((x) => x.version), ['2.0.0', '3.0.0']);
  assert.strictEqual(r.rows[0].published_at, '2026-01-01T00:00:00.000Z');
});

test('a version with no time entry is null, not the packument modification time', () => {
  const r = PK.observationsFromPackument({
    name: 'p',
    versions: { '1.0.0': { name: 'p', version: '1.0.0' } },
    time: { created: '2020-01-01T00:00:00.000Z', modified: '2026-01-01T00:00:00.000Z' },
  });
  assert.strictEqual(r.rows[0].published_at, null);
});

// --- the assembled path ---------------------------------------------------------------------------------
const SCHEMA = `
CREATE TABLE packages (id INTEGER PRIMARY KEY, package_name TEXT NOT NULL UNIQUE, latest_version TEXT,
  lineage_count INTEGER NOT NULL, major_order TEXT NOT NULL);
CREATE TABLE lineages (id INTEGER PRIMARY KEY, package_id INTEGER NOT NULL, ord INTEGER NOT NULL,
  lineage_key TEXT NOT NULL, first_version TEXT NOT NULL, last_version TEXT NOT NULL,
  n_versions INTEGER NOT NULL, first_published_s INTEGER NOT NULL, last_published_s INTEGER NOT NULL);
CREATE TABLE lineage_state (lineage_id INTEGER NOT NULL, grp TEXT NOT NULL, initial_state TEXT NOT NULL,
  PRIMARY KEY (lineage_id, grp)) WITHOUT ROWID;
CREATE TABLE spine (lineage_id INTEGER NOT NULL, ord INTEGER NOT NULL, version TEXT NOT NULL,
  published_s INTEGER NOT NULL, prerelease INTEGER NOT NULL, size_bytes INTEGER, tool_key REAL,
  shasum BLOB, capture_class TEXT NOT NULL, row_digest BLOB NOT NULL,
  PRIMARY KEY (lineage_id, ord)) WITHOUT ROWID;
CREATE TABLE events (lineage_id INTEGER NOT NULL, grp TEXT NOT NULL, ord INTEGER NOT NULL,
  version TEXT NOT NULL, published_s INTEGER NOT NULL, after_state TEXT NOT NULL,
  witness_row_digest BLOB NOT NULL, PRIMARY KEY (lineage_id, grp, ord)) WITHOUT ROWID;
CREATE TABLE known_malicious_pins (package_id INTEGER NOT NULL, version TEXT NOT NULL,
  advisory_id TEXT NOT NULL, source TEXT NOT NULL,
  PRIMARY KEY (package_id, version, advisory_id)) WITHOUT ROWID;
CREATE TABLE seed_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
`;

function fixtureSeed({ pinned = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft05-gate-'));
  const p = path.join(dir, 'chaingate-seed.db');
  const db = new Database(p);
  db.exec(SCHEMA);
  db.prepare('INSERT INTO packages VALUES (?,?,?,?,?)').run(1, 'p', '1.2.3', 1, '1');
  db.prepare('INSERT INTO lineages VALUES (?,?,?,?,?,?,?,?,?)')
    .run(1, 1, 0, '1', '1.0.0', '1.2.3', 2, 1700000000, 1767322000);
  for (const g of ['publisher', 'provenance', 'install', 'git', 'deps']) {
    db.prepare('INSERT INTO lineage_state VALUES (?,?,?)').run(1, g, '{}');
  }
  db.prepare('INSERT INTO spine VALUES (?,?,?,?,?,?,?,?,?,?)')
    .run(1, 0, '1.0.0', 1700000000, 0, 1000, 100, null, 'LIVE', Buffer.alloc(32));
  if (pinned) {
    db.prepare('INSERT INTO known_malicious_pins VALUES (?,?,?,?)').run(1, '1.2.3', 'MAL-TEST-1', 'osv');
  }
  for (const [k, v] of Object.entries({
    schema_version: '3', contract_version: 'cft-seed-v3-contract-1.0',
    corpus_snapshot_digest: 'f'.repeat(64), history_cutoff: '2026-09-01T00:00:00Z',
    // the reader's OWN declared support, not a literal that drifts away from it
    rule_versions: JSON.stringify(Object.fromEntries(
      Object.entries(R.SUPPORTED_RULE_VERSIONS).map(([family, vs]) => [family, vs[0]]))),
  })) db.prepare('INSERT INTO seed_metadata VALUES (?,?)').run(k, v);
  db.close();
  fs.writeFileSync(`${p}.sha256`,
    `${createHash('sha256').update(fs.readFileSync(p)).digest('hex')}  chaingate-seed.db\n`);
  return R.openSeed(p, { trust: R.TRUST_UNSIGNED_DEV });
}

const GATE_INPUT = { packageName: 'p', version: '1.2.3', rawManifest: MANIFEST,
  publishedAt: '2026-01-02T03:04:05.000Z' };

// Placement is grounded in FU-2 and exercised in lineage-coverage.test.js; this file keeps the
// composition of packument -> row -> candidate -> finding -> policy.
const POLICY = { on_unusable_input: 'BLOCK', on_no_evidence: 'WARN' };

test('the gate composes packument -> row -> candidate -> finding -> policy, and decides nothing itself', () => {
  const seed = fixtureSeed();
  try {
    const seen = [];
    const gate = G.createSeedV3Gate({ seed, config: POLICY, domainVersionCount: 0,
      onDecision: (d) => seen.push(d) });
    assert.strictEqual(gate.name, 'seed-v3');
    const res = gate.evaluate(GATE_INPUT);
    assert.ok(['ALLOW', 'WARN', 'BLOCK', 'SKIP'].includes(res.result));
    assert.strictEqual(seen.length, 1, 'the full decision is available for reporting');
    assert.strictEqual(seen[0].policy_version, POL.POLICY_CONTRACT_VERSION);
    assert.match(res.detail, /cft-policy-/);
  } finally { seed.close(); }
});

test('a recorded advisory pin BLOCKs through the whole path', () => {
  const seed = fixtureSeed({ pinned: true });
  try {
    const gate = G.createSeedV3Gate({ seed, config: { ...POLICY, on_no_evidence: 'ALLOW' }, domainVersionCount: 0 });
    const res = gate.evaluate(GATE_INPUT);
    assert.strictEqual(res.result, 'BLOCK');
    assert.match(res.detail, /MAL-TEST-1/);
  } finally { seed.close(); }
});

test('without a raw manifest the decision comes from POLICY, not from a bare SKIP', () => {
  // A SKIP here bypassed policy entirely and, because SKIP does not count toward the aggregate,
  // permitted the install.
  const seed = fixtureSeed();
  try {
    const gate = G.createSeedV3Gate({ seed, config: POLICY, domainVersionCount: 0 });
    const res = gate.evaluate({ ...GATE_INPUT, rawManifest: null });
    assert.strictEqual(res.result, 'BLOCK', 'on_unusable_input: BLOCK was the stated choice');
    assert.match(res.detail, /cft-policy-/);
  } finally { seed.close(); }
});

test('a manifest the adapter refuses becomes an UNUSABLE INPUT for policy, never an ALLOW', () => {
  const seed = fixtureSeed();
  try {
    const gate = G.createSeedV3Gate({ seed, config: POLICY, domainVersionCount: 0 });
    const res = gate.evaluate({ ...GATE_INPUT, version: '9.9.9' });   // key vs manifest disagree
    assert.strictEqual(res.result, 'BLOCK');
    // An unresolved policy cannot be wired at all now: silence would be indistinguishable from
    // permission once the aggregate runs. See lineage-coverage.test.js.
    assert.throws(() => G.createSeedV3Gate({ seed, config: {}, domainVersionCount: 0 }),
      /must not leave policy unresolved/);
  } finally { seed.close(); }
});

test('a misconfigured policy fails when the gate is WIRED, not on the packument that hits it', () => {
  const seed = fixtureSeed();
  try {
    assert.throws(() => G.createSeedV3Gate({ seed, config: { ...POLICY, on_no_evidence: 'ALOW' }, domainVersionCount: 0 }),
      POL.PolicyConfigInvalid);
    assert.throws(() => G.createSeedV3Gate({ seed, config: { ...POLICY, nonsense: 'BLOCK' }, domainVersionCount: 0 }),
      POL.PolicyConfigInvalid);
  } finally { seed.close(); }
});

test('findingsFromPackument walks a whole document and reports what it refused', () => {
  const seed = fixtureSeed();
  try {
    const doc = { name: 'p', versions: { '1.2.3': MANIFEST, '2.0.0': null },
      time: { '1.2.3': '2026-01-02T03:04:05.000Z' } };
    const r = PK.findingsFromPackument(doc, seed, {
      lineageOf: (pkg, v) => G.resolvePlacement(seed, pkg, v, 1767225600),
    });
    assert.strictEqual(r.package_name, 'p');
    assert.strictEqual(r.results.length, 1);
    assert.strictEqual(r.results[0].finding.contract_version, 'cft-detection-contract-1.0');
    assert.ok(!('disposition' in r.results[0].finding), 'a finding never carries an action');
    assert.deepStrictEqual(r.refused.map((x) => x.version), ['2.0.0']);
  } finally { seed.close(); }
});
