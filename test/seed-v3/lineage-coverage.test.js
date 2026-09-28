// CFT-05 — where a LIVE release sits in a package's recorded history.
//
// This is the case a proxy sees first and the one the 152,804-candidate parity does NOT cover: every
// record in that pack carries a recorded ordinal, and not one carries `ord: null`. So the path the
// contract provides for a live candidate — `checker.channelA` reads `ord === null` as "extends the
// tip" and compares against the last recorded version — is exercised here and nowhere else.
//
// The defect this file was written for: passing `lineage_id: null` for a new release reported every
// Channel-A group as NOT_EVALUATED(uncovered_package). That is a FALSE statement about a package the
// seed covers, and it threw away an evaluation the contract supports.

import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';
import { dirname, join } from 'node:path';

const DIRNAME = dirname(fileURLToPath(import.meta.url));
import Database from 'better-sqlite3';
import { createHash } from 'node:crypto';

import K from '../../seed/v3/contract.js';
import R from '../../seed/v3/reader.js';
import G from '../../seed/v3/gate.js';
import POL from '../../seed/v3/policy.js';
import A from '../../seed/v3/adapter.js';
import PK from '../../seed/v3/packument.js';

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

const BASE_S = 1767225600;                                  // 2026-01-01T00:00:00Z
const PUBLISHED_ISO = '2026-02-01T00:00:00.000Z';
const PUBLISHED_S = Math.floor(Date.parse(PUBLISHED_ISO) / 1000);

/** A manifest that matches the seeded initial state, so nothing breaks unless the test makes it. */
const manifestFor = (version, over = {}) => ({
  name: 'p', version,
  _npmUser: { name: 'alice', email: 'alice@example.com' },
  _npmVersion: '10.2.3',
  maintainers: [{ name: 'alice', email: 'alice@example.com' }],
  gitHead: 'abc123',
  dist: { unpackedSize: 1000, attestations: { url: 'https://x' } },
  ...over,
});

// The seeded state is DERIVED from that manifest through the real adapter, not written by hand.
// Hand-written placeholder digests made the publisher witness break on a release the test called
// "unchanged", so the fixture — not the evaluator — was producing the warning.
const BASELINE = A.candidateFromRawRow(
  PK.observationFromManifest('1.0.0', manifestFor('1.0.0'), PUBLISHED_ISO),
  { packageName: 'p', lineageId: 1, ord: 0, domainVersionCount: 0 },
);
const INITIAL = {
  publisher: {
    identity_digest: BASELINE.identity_digest,
    tuple_digest: BASELINE.tuple_digest,
    maint_digest: BASELINE.maint_digest,
    tool_name: BASELINE.tool_name,
  },
  provenance: { present: true },
  install: { has_scripts: false, body_digest: '' },
  git: { head_present: true, repo_digest: null },
  deps: {},
};

/** A seed with `lineages` chains, each `[versions...]`, all sharing one initial state. */
function buildSeed(lineages, { pinnedVersion = null } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft05-lineage-'));
  const dbPath = path.join(dir, 'chaingate-seed.db');
  const db = new Database(dbPath);
  db.exec(SCHEMA);
  db.prepare('INSERT INTO packages VALUES (?,?,?,?,?)')
    .run(1, 'p', lineages.at(-1).at(-1), lineages.length, lineages.map((_, i) => String(i + 1)).join(','));
  lineages.forEach((versions, i) => {
    const lid = i + 1;
    const firstS = BASE_S + i * 1_000_000;
    db.prepare('INSERT INTO lineages VALUES (?,?,?,?,?,?,?,?,?)').run(
      lid, 1, i, String(i + 1), versions[0], versions.at(-1), versions.length,
      firstS, firstS + (versions.length - 1) * 100_000);
    for (const g of Object.keys(INITIAL)) {
      db.prepare('INSERT INTO lineage_state VALUES (?,?,?)').run(lid, g, JSON.stringify(INITIAL[g]));
    }
    versions.forEach((v, ord) => {
      db.prepare('INSERT INTO spine VALUES (?,?,?,?,?,?,?,?,?,?)')
        .run(lid, ord, v, firstS + ord * 100_000, 0, BASELINE.size_bytes, BASELINE.tool_key,
          null, 'LIVE', Buffer.alloc(32));
    });
  });
  if (pinnedVersion) {
    db.prepare('INSERT INTO known_malicious_pins VALUES (?,?,?,?)')
      .run(1, pinnedVersion, 'MAL-2026-LINEAGE', 'osv');
  }
  for (const [k, v] of Object.entries({
    schema_version: '3', contract_version: 'cft-seed-v3-contract-1.0',
    corpus_snapshot_digest: 'f'.repeat(64), history_cutoff: '2026-12-31T00:00:00Z',
    rule_versions: JSON.stringify(Object.fromEntries(
      Object.entries(R.SUPPORTED_RULE_VERSIONS).map(([family, vs]) => [family, vs[0]]))),
  })) db.prepare('INSERT INTO seed_metadata VALUES (?,?)').run(k, v);
  db.close();
  fs.writeFileSync(`${dbPath}.sha256`,
    `${createHash('sha256').update(fs.readFileSync(dbPath)).digest('hex')}  chaingate-seed.db\n`);
  return R.openSeed(dbPath, { trust: R.TRUST_UNSIGNED_DEV });
}

const POLICY = { on_unusable_input: 'BLOCK', on_no_evidence: 'WARN' };

function decideFor(seed, packageName, version,
  { config = POLICY, manifest = null, publishedAt = PUBLISHED_ISO } = {}) {
  const decisions = [];
  const gate = G.createSeedV3Gate({
    seed, config, domainVersionCount: 0, onDecision: (d) => decisions.push(d) });
  const result = gate.evaluate({
    packageName, version, rawManifest: manifest || manifestFor(version), publishedAt });
  return { result, decision: decisions[0] };
}

/** The placement of a release, resolved the way the gate resolves it. */
const placeOf = (seed, version, publishedS = PUBLISHED_S, pkg = 'p') =>
  G.resolvePlacement(seed, pkg, version, publishedS);

const reasonsOf = (d) => [...new Set((d.not_evaluated || []).map((m) => m.reason))].sort();

// --- placement is grounded in FU-2, and the shortcut is gone -------------------------------------
test('the "single lineage implies append" shortcut no longer exists', () => {
  assert.strictEqual(G.placeInSeed, undefined, 'the old entry point must be gone, not aliased');
  assert.ok(typeof G.resolvePlacement === 'function');
  assert.ok(!Object.values(G.PLACEMENTS).includes('extends-single-lineage'));
});

test('FU-2 E2: the lineage key is the leading-integer major, and a non-digit prefix is 0', () => {
  assert.strictEqual(G.majorOf('1.2.3'), '1');
  assert.strictEqual(G.majorOf('0.4.0'), '0');
  assert.strictEqual(G.majorOf('12.0.0'), '12');
  assert.strictEqual(G.majorOf('v2.0.0'), '0', 'a non-digit prefix falls back to 0');
  assert.strictEqual(G.majorOf(''), '0');
  assert.strictEqual(G.majorOf(null), '0');
});

test('FU-2 E4/E5: a stub or a release with no publication time holds no predecessor', () => {
  const seed = buildSeed([['1.0.0', '1.1.0']]);
  try {
    assert.ok(G.isStub('0.0.1-security'));
    assert.ok(!G.isStub('1.0.0-security-fix'));

    const stub = placeOf(seed, '0.0.1-security');
    assert.strictEqual(stub.kind, G.PLACEMENTS.INELIGIBLE_STUB);
    assert.strictEqual(stub.channel_a_usable, false);
    assert.match(stub.reason, /E4/);

    const noTime = placeOf(seed, '1.2.0', null);
    assert.strictEqual(noTime.kind, G.PLACEMENTS.INELIGIBLE_NO_PUBLICATION_TIME);
    assert.strictEqual(noTime.channel_a_usable, false);
    assert.match(noTime.reason, /E5/);
  } finally { seed.close(); }
});

test('a RECORDED release is placed at the ordinal the seed gives it', () => {
  const seed = buildSeed([['1.0.0', '1.1.0', '1.2.0']]);
  try {
    const p = placeOf(seed, '1.1.0');
    assert.strictEqual(p.kind, G.PLACEMENTS.RECORDED);
    assert.deepStrictEqual([p.lineage_id, p.ord, p.channel_a_usable], [1, 1, true]);
  } finally { seed.close(); }
});

test('an APPEND requires publication ORDERING, not merely a matching lineage', () => {
  // the fixture publishes at BASE_S + ord*100_000; the tip of lineage 1 is BASE_S + 200_000
  const seed = buildSeed([['1.0.0', '1.1.0', '1.2.0']]);
  try {
    const tipS = BASE_S + 200_000;
    const after = placeOf(seed, '1.3.0', tipS + 1);
    assert.strictEqual(after.kind, G.PLACEMENTS.APPEND);
    assert.deepStrictEqual([after.lineage_id, after.ord, after.channel_a_usable], [1, null, true]);

    // THE COUNTEREXAMPLE the shortcut got wrong: same single lineage, same major, but published
    // BEFORE the recorded tip. That is not a successor.
    const before = placeOf(seed, '1.1.5', tipS - 1);
    assert.strictEqual(before.kind, G.PLACEMENTS.HISTORICAL_OMITTED);
    assert.strictEqual(before.channel_a_usable, false);
    assert.match(before.reason, /is published before the recorded tip/);

  } finally { seed.close(); }
});

// --- SUB-SECOND ORDERING: equal stored seconds are NOT equal timestamps ----------------------------
test('equal stored seconds are AMBIGUOUS, not a tie to break on the version string', () => {
  // The seed stores publication time in SECONDS (contract.TIMESTAMP_PRECISION), while FU-2 sorts on
  // the full `published_at`. Two releases inside one second are indistinguishable in the seed, and
  // the real order may go either way -- so breaking the tie on the version string INVENTED an
  // ordering. The detection contract already takes this position: hasPriorVersion and priorStates
  // both classify an equal `published_s` as AMBIGUOUS rather than prior.
  assert.strictEqual(K.TIMESTAMP_PRECISION, 'unix_seconds_utc');

  const seed = buildSeed([['1.0.0', '1.1.0', '1.2.0']]);
  const tipS = BASE_S + 200_000;                       // the recorded tip, 1.2.0
  try {
    // strictly after and strictly before still decide
    assert.strictEqual(placeOf(seed, '1.3.0', tipS + 1).kind, G.PLACEMENTS.APPEND);
    assert.strictEqual(placeOf(seed, '1.3.0', tipS - 1).kind, G.PLACEMENTS.HISTORICAL_OMITTED);

    // THE COUNTEREXAMPLE, both directions of the version string. Neither may resolve, and in
    // particular the sorts-later name must NOT be promoted to an append.
    for (const version of ['1.3.0', '1.0.5']) {
      const p = placeOf(seed, version, tipS);
      assert.strictEqual(p.kind, G.PLACEMENTS.UNRESOLVED,
        `${version} at the tip's exact second must not resolve`);
      assert.strictEqual(p.channel_a_usable, false);
      assert.match(p.reason, /stores publication time in SECONDS/);
      assert.match(p.reason, /sub-second/);
    }

    // and the three-way comparison itself, directly
    assert.strictEqual(G.compareToRecorded(10, 9), 'after');
    assert.strictEqual(G.compareToRecorded(9, 10), 'before');
    assert.strictEqual(G.compareToRecorded(10, 10), 'ambiguous');
  } finally { seed.close(); }
});

test('an ambiguous second keeps the DAC trajectory and an exact-version pin', () => {
  const tipS = BASE_S + 200_000;
  const AT_TIP = new Date(tipS * 1000).toISOString();
  const seed = buildSeed([['1.0.0', '1.1.0', '1.2.0']]);
  try {
    const { decision } = decideFor(seed, 'p', '1.3.0', { publishedAt: AT_TIP });
    assert.strictEqual(decision.placement, G.PLACEMENTS.UNRESOLVED);
    assert.strictEqual(decision.channel_a_usable, false);
    assert.ok(decision.results.some((x) => x.gate === 'seed-v3:dac-trajectory:any'),
      'the DAC trajectory does not depend on placement');
  } finally { seed.close(); }

  const pinned = buildSeed([['1.0.0', '1.1.0', '1.2.0']], { pinnedVersion: '1.3.0' });
  try {
    const { result } = decideFor(pinned, 'p', '1.3.0', { publishedAt: AT_TIP });
    assert.strictEqual(result.result, 'BLOCK', 'an exact-version pin needs no ordering at all');
  } finally { pinned.close(); }
});

test('a NEW-MAJOR release is a cold start, not an append to some other lineage', () => {
  const seed = buildSeed([['1.0.0', '1.1.0']]);
  try {
    const p = placeOf(seed, '2.0.0', BASE_S + 999_999);
    assert.strictEqual(p.kind, G.PLACEMENTS.NEW_MAJOR_COLD_START);
    assert.strictEqual(p.channel_a_usable, false);
    assert.match(p.reason, /first of its own lineage/);
  } finally { seed.close(); }
});

test('several lineages sharing a major, or a CalVer collapse, are UNRESOLVED and say why', () => {
  const two = buildSeed([['1.0.0', '1.1.0'], ['2.0.0', '2.1.0']]);
  try {
    const p = placeOf(two, '2.2.0', BASE_S + 9_000_000);
    assert.strictEqual(p.kind, G.PLACEMENTS.APPEND, 'distinct majors still resolve');
    assert.strictEqual(placeOf(two, '9.0.0', BASE_S + 9_000_000).kind,
      G.PLACEMENTS.NEW_MAJOR_COLD_START);
  } finally { two.close(); }

  // FU-2 E1 depends on the package's full distinct-major publish sequence, which the seed does not
  // store, so any release that could participate in a CalVer collapse is unresolved.
  assert.ok(G.isCalverYear('2024'));
  assert.ok(!G.isCalverYear('2099'), 'outside the 2000..2027 window');
  assert.ok(!G.isCalverYear('1'));
  const calver = buildSeed([['2024.1.0', '2024.2.0']]);
  try {
    const p = placeOf(calver, '2025.1.0', BASE_S + 9_000_000);
    assert.strictEqual(p.kind, G.PLACEMENTS.UNRESOLVED);
    assert.match(p.reason, /E1 CalVer collapse/);
  } finally { calver.close(); }
});

test('a package the seed does not cover is UNCOVERED, and says exactly that', () => {
  const seed = buildSeed([['1.0.0', '1.1.0']]);
  try {
    const p = placeOf(seed, '1.0.0', PUBLISHED_S, 'not-in-seed');
    assert.strictEqual(p.kind, G.PLACEMENTS.UNCOVERED_PACKAGE);
    assert.strictEqual(p.channel_a_usable, false);
  } finally { seed.close(); }
});

// --- what survives an unresolved placement ----------------------------------------------------------
test('an APPEND is fully evaluated against the tip, and a break there is SEEN', () => {
  const seed = buildSeed([['1.0.0', '1.1.0', '1.2.0']]);
  const AFTER = new Date((BASE_S + 300_000) * 1000).toISOString();
  try {
    const same = decideFor(seed, 'p', '1.3.0', { publishedAt: AFTER });
    assert.strictEqual(same.decision.placement, G.PLACEMENTS.APPEND);
    assert.strictEqual(same.decision.channel_a_usable, true);
    assert.deepStrictEqual(reasonsOf(same.decision), [], 'an append is fully evaluated');
    assert.strictEqual(same.decision.disposition, 'ALLOW');

    const dropped = decideFor(seed, 'p', '1.3.0', {
      publishedAt: AFTER, manifest: manifestFor('1.3.0', { dist: { unpackedSize: 1000 } }) });
    assert.strictEqual(dropped.decision.disposition, 'WARN', 'a provenance drop at the tip surfaces');
  } finally { seed.close(); }
});

test('an UNRESOLVED placement keeps the DAC trajectory, which never needed a lineage', () => {
  const seed = buildSeed([['1.0.0', '1.1.0'], ['2.0.0', '2.1.0']]);
  try {
    // published before both tips and matching no single lineage cleanly -> historical
    const r = decideFor(seed, 'p', '1.0.5', {
      publishedAt: new Date((BASE_S + 50_000) * 1000).toISOString() });
    const d = r.decision;
    assert.strictEqual(d.channel_a_usable, false);

    // Channel-A is NOT used, and says so rather than reporting thresholds over an empty comparison
    const ca = d.results.find((x) => x.gate === 'seed-v3:channel-a');
    assert.strictEqual(ca.result, 'SKIP');
    assert.match(ca.detail, /are NOT used/);
    assert.ok(!d.results.some((x) => x.gate === 'seed-v3:channel-a:critical'),
      'no Channel-A threshold result may appear for an unplaced release');

    // ...while the DAC thresholds DO appear: they read prior versions across the whole package
    assert.ok(d.results.some((x) => x.gate === 'seed-v3:dac-trajectory:surface'));
    assert.ok(d.results.some((x) => x.gate === 'seed-v3:dac-trajectory:any'));
    const dacEvaluated = d.not_evaluated.filter((m) => m.where === 'dac_trajectory.predicate');
    assert.strictEqual(dacEvaluated.length, 0, 'the DAC predicates remain independently evaluable');

    // and the Channel-A observations carry the PLACEMENT's reason, not `uncovered_package`
    const caMissing = d.not_evaluated.filter((m) => m.where.startsWith('channel_a'));
    assert.strictEqual(caMissing.length, 8, '5 groups + 3 publisher constituents');
    for (const m of caMissing) {
      assert.strictEqual(m.stated_by, 'placement');
      assert.notStrictEqual(m.reason, K.UNCOVERED_PACKAGE,
        'a covered package must never be reported as uncovered');
      assert.match(m.reason, /is published before the recorded tip/);
    }
  } finally { seed.close(); }
});

test('an EXACT-VERSION pin still BLOCKs through every unresolved placement', () => {
  for (const [label, version, publishedAt] of [
    ['historical', '1.0.5', new Date((BASE_S + 50_000) * 1000).toISOString()],
    ['new major', '9.9.9', PUBLISHED_ISO],
    ['stub', '0.0.1-security', PUBLISHED_ISO],
    ['no publication time', '1.5.0', null],
  ]) {
    const seed = buildSeed([['1.0.0', '1.1.0', '1.2.0']], { pinnedVersion: version });
    try {
      const { result, decision } = decideFor(seed, 'p', version, { publishedAt });
      assert.strictEqual(result.result, 'BLOCK', `${label}: a recorded advisory needs no placement`);
      assert.match(result.detail, /MAL-2026-LINEAGE/);
      assert.strictEqual(decision.channel_a_usable, false, label);
    } finally { seed.close(); }
  }
});

test('an uncovered package is still uncovered, and policy still declines to call it clean', () => {
  const seed = buildSeed([['1.0.0', '1.1.0']]);
  try {
    const { decision } = decideFor(seed, 'not-in-seed', '1.0.0',
      { config: { on_unusable_input: 'BLOCK', on_no_evidence: 'WARN' } });
    assert.strictEqual(decision.placement, G.PLACEMENTS.UNCOVERED_PACKAGE);
    assert.strictEqual(decision.evidence_complete, false);
    assert.strictEqual(decision.disposition, 'WARN', 'nothing evaluated -> the operator\'s choice');
  } finally { seed.close(); }
});

// --- nothing invented at the wiring --------------------------------------------------------------------
test('a gate that enforces cannot be wired with an unresolved policy', () => {
  const seed = buildSeed([['1.0.0']]);
  try {
    assert.throws(() => G.createSeedV3Gate({ seed, config: {}, domainVersionCount: 0 }),
      /must not leave policy unresolved/);
    assert.throws(() => G.createSeedV3Gate({
      seed, config: { on_unusable_input: 'BLOCK' }, domainVersionCount: 0 }),
      /on_no_evidence/);
    assert.doesNotThrow(() => G.createSeedV3Gate({ seed, config: POLICY, domainVersionCount: 0 }));
  } finally { seed.close(); }
});

test('the domain version count must be STATED or COMPUTED, never defaulted', () => {
  const seed = buildSeed([['1.0.0']]);
  try {
    for (const bad of [undefined, -1, 1.5, '3', null]) {
      assert.throws(() => G.createSeedV3Gate({ seed, config: POLICY, domainVersionCount: bad }),
        /non-negative integer or 'from-packument'/, JSON.stringify(bad));
    }
    assert.doesNotThrow(() => G.createSeedV3Gate({ seed, config: POLICY, domainVersionCount: 0 }));
    assert.doesNotThrow(() => G.createSeedV3Gate({
      seed, config: POLICY, domainVersionCount: 'from-packument' }));
  } finally { seed.close(); }
});

// --- the domain version count is PACKAGE-SCOPED, and the writer computes it ------------------------
test('the count is the WRITER\'s: versions of THIS package from that e-mail domain', () => {
  // writer.py: `for r in rows: d = W.email_domain(r.get("publisher_email")); if d: dcount[d] += 1`
  // over EVERY version of the package, including ones lineage grouping later excludes.
  const versions = {
    '1.0.0': { _npmUser: { email: 'a@corp.example' } },
    '1.1.0': { _npmUser: { email: 'b@corp.example' } },
    '1.2.0': { _npmUser: { email: 'c@other.example' } },
    '0.0.1-security': { _npmUser: { email: 'd@corp.example' } },   // a stub still counts
    '1.3.0': { _npmUser: {} },                                     // no e-mail, no domain
    '1.4.0': { _npmUser: 'not-an-object' },
    '1.5.0': null,
  };
  const counts = PK.domainVersionCounts(versions);
  assert.strictEqual(counts.get('corp.example'), 3, 'the stub is counted, as the writer counts it');
  assert.strictEqual(counts.get('other.example'), 1);
  assert.strictEqual(counts.size, 2, 'no domain is invented for a missing or malformed publisher');
  assert.deepStrictEqual(PK.domainVersionCounts(null), new Map());
});

test("'from-packument' computes that count; nothing global is observed", () => {
  const versions = {
    '1.0.0': { _npmUser: { email: 'a@corp.example' } },
    '1.1.0': { _npmUser: { email: 'b@corp.example' } },
  };
  assert.deepStrictEqual(
    G.resolveDomainVersionCount('from-packument', { rawVersions: versions, candidateEmail: 'c@corp.example' }),
    { count: 2, source: 'from-packument', domain: 'corp.example' });
  // a domain with no other versions of this package is 0 — which is what 0 MEANS
  assert.strictEqual(G.resolveDomainVersionCount('from-packument',
    { rawVersions: versions, candidateEmail: 'x@elsewhere.example' }).count, 0);
  // no e-mail at all: no domain, and provider_class will be 'unknown' from the domain, not the count
  assert.strictEqual(G.resolveDomainVersionCount('from-packument',
    { rawVersions: versions, candidateEmail: null }).domain, null);
  // a stated integer is passed through, and says so
  assert.deepStrictEqual(G.resolveDomainVersionCount(0, {}), { count: 0, source: 'stated' });
  // and it REFUSES rather than guessing when it was told to compute but given nothing to compute from
  assert.throws(() => G.resolveDomainVersionCount('from-packument', { candidateEmail: 'a@b.co' }),
    /must not be guessed/);
});

test('the computed count reaches provider_class, and 0 is not the same claim as unknown', () => {
  const seed = buildSeed([['1.0.0', '1.1.0', '1.2.0']]);
  const AFTER = new Date((BASE_S + 300_000) * 1000).toISOString();
  try {
    // two versions of this package from the candidate's corporate domain -> verified-corporate
    const rawVersions = {
      '1.0.0': { _npmUser: { email: 'alice@corp.example' } },
      '1.1.0': { _npmUser: { email: 'bob@corp.example' } },
    };
    const manifest = manifestFor('1.3.0', { _npmUser: { name: 'alice', email: 'alice@corp.example' } });
    const seen = [];
    const gate = G.createSeedV3Gate({ seed, config: POLICY, domainVersionCount: 'from-packument',
      onDecision: (d) => seen.push(d) });
    gate.evaluate({ packageName: 'p', version: '1.3.0', rawManifest: manifest,
      rawVersions, publishedAt: AFTER });
    assert.ok(seen.length === 1);

    // the same candidate with a STATED 0 is classified differently, which is the whole point of
    // refusing to default it
    const stated = G.createSeedV3Gate({ seed, config: POLICY, domainVersionCount: 0 });
    const a = PK.observationFromManifest('1.3.0', manifest, AFTER);
    const withCount = A.candidateFromRawRow(a, { packageName: 'p', domainVersionCount: 2 });
    const withZero = A.candidateFromRawRow(a, { packageName: 'p', domainVersionCount: 0 });
    assert.strictEqual(withCount.provider_class, 'verified-corporate');
    assert.strictEqual(withZero.provider_class, 'unverified');
    assert.notStrictEqual(withZero.provider_class, 'unknown',
      '0 asserts the domain has no other versions; it is not "we could not tell"');
    assert.ok(stated);
  } finally { seed.close(); }
});

test('a MISSING manifest is routed through policy, never answered with a bare SKIP', () => {
  const seed = buildSeed([['1.0.0']]);
  try {
    const gate = G.createSeedV3Gate({
      seed, config: { on_unusable_input: 'BLOCK', on_no_evidence: 'WARN' }, domainVersionCount: 0 });
    const r = gate.evaluate({ packageName: 'p', version: '1.0.0', rawManifest: null });
    assert.strictEqual(r.result, 'BLOCK', 'policy decides, and it was told to fail closed');
    assert.match(r.detail, /cft-policy-/);

    const warn = G.createSeedV3Gate({
      seed, config: { on_unusable_input: 'WARN', on_no_evidence: 'WARN' }, domainVersionCount: 0 })
      .evaluate({ packageName: 'p', version: '1.0.0', rawManifest: undefined });
    assert.strictEqual(warn.result, 'WARN');
  } finally { seed.close(); }
});

test('the vectors DECLARE that their count-0 convention is the fixture adapter, not the seed', () => {
  // The correction this test exists for: the writer DOES compute package-scoped domain counts, and
  // the seed's own publisher state is mostly `verified-corporate` because of it. It is
  // `oracle.candidate_from_row` -- the fixture candidate adapter -- that passes None and so
  // classifies every fixture candidate with count 0. Both are the producer, and they disagree.
  const V = JSON.parse(readFileSync(join(DIRNAME, '..', '..', 'seed', 'v3', 'packument-vectors.json'), 'utf8'));
  assert.strictEqual(V.domain_version_count, 0);
  assert.ok(V._domain_note, 'the convention must be declared, not implied by a bare 0');
  assert.match(V._domain_note, /FIXTURE ADAPTER/);
  assert.match(V._domain_note, /writer\.py computes a PACKAGE-SCOPED count/);
  assert.match(V._domain_note, /from-packument/);
});

// --- the domain map is built ONCE PER DOCUMENT ---------------------------------------------------
test('N candidates do not cost N-squared manifest visits', () => {
  // Rebuilding the map per candidate made the work quadratic: 4 candidates over a 4-version
  // packument visited 16 manifests. The map belongs to the DOCUMENT, so it is computed once.
  const N = 4;
  let visits = 0;
  const versions = {};
  for (let i = 0; i < N; i += 1) {
    const v = `1.${i}.0`;
    const m = { name: 'p', version: v, _npmVersion: '10.2.3', dist: { unpackedSize: 1000 } };
    // count every read of the field the scan looks at
    Object.defineProperty(m, '_npmUser', {
      enumerable: true,
      get() { visits += 1; return { name: 'alice', email: 'alice@corp.example' }; },
    });
    versions[v] = m;
  }

  const seed = buildSeed([['0.1.0']]);
  try {
    const gate = G.createSeedV3Gate({ seed, config: POLICY, domainVersionCount: 'from-packument' });
    for (const [v, manifest] of Object.entries(versions)) {
      gate.evaluate({ packageName: 'p', version: v, rawManifest: manifest, rawVersions: versions,
        publishedAt: PUBLISHED_ISO });
    }
    // ONE scan of N manifests, plus one read per candidate for its own observation row.
    // The quadratic form cost N*N + N = 20 here.
    assert.strictEqual(visits, N + N,
      `expected one scan (${N}) plus one row read per candidate (${N}); got ${visits}`);
  } finally { seed.close(); }
});

test('the memo is scoped to the DOCUMENT, not to the package name', () => {
  const mk = (email) => ({ '1.0.0': { _npmUser: { email } } });
  const first = mk('a@corp.example');
  const second = mk('a@other.example');                 // a later fetch of the same package

  assert.strictEqual(G.domainCountsFor(first), G.domainCountsFor(first),
    'the same document must be scanned once');
  assert.notStrictEqual(G.domainCountsFor(first), G.domainCountsFor(second),
    'a different document must be scanned again, not answered from the earlier one');
  assert.strictEqual(G.domainCountsFor(second).get('corp.example'), undefined,
    'a package-name cache would have answered this with the first fetch');
  assert.strictEqual(G.domainCountsFor(second).get('other.example'), 1);
});

// --- the computed count reaches the FINDING ---------------------------------------------------------
test('the computed count propagates into the finding, not merely into the candidate', () => {
  // The 152,804-candidate parity does not establish this path: those candidates arrive with
  // provider_class already set. Here the count is COMPUTED from the packument, and the assertion is
  // on `finding.candidate.provider_class` -- what a consumer of the finding actually reads.
  const seed = buildSeed([['1.0.0', '1.1.0', '1.2.0']]);
  const AFTER = new Date((BASE_S + 300_000) * 1000).toISOString();
  const email = 'alice@corp.example';
  const manifest = manifestFor('1.3.0', { _npmUser: { name: 'alice', email } });

  /** run the whole path and return the finding the gate produced */
  const findingFor = (rawVersions) => {
    const seen = [];
    const gate = G.createSeedV3Gate({ seed, config: POLICY, domainVersionCount: 'from-packument',
      onDecision: (d) => seen.push(d) });
    gate.evaluate({ packageName: 'p', version: '1.3.0', rawManifest: manifest, rawVersions,
      publishedAt: AFTER });
    return seen[0];
  };

  try {
    // two other versions of THIS package from the same domain -> verified-corporate
    const many = findingFor({
      '1.0.0': { _npmUser: { email: 'x@corp.example' } },
      '1.1.0': { _npmUser: { email: 'y@corp.example' } },
    });
    assert.strictEqual(many.provider_class, 'verified-corporate',
      'the computed count must reach the finding the decision was taken from');

    // the same candidate in a document where the domain has no other versions -> unverified
    const none = findingFor({ '9.0.0': { _npmUser: { email: 'z@elsewhere.example' } } });
    assert.strictEqual(none.provider_class, 'unverified');

    // and the difference is the DOCUMENT, not the candidate: identical manifest both times
    assert.notStrictEqual(many.provider_class, none.provider_class);
  } finally { seed.close(); }
});

test('the contract itself supplies the live-candidate rule; this is not a consumer invention', () => {
  assert.strictEqual(R.CANDIDATE_SPEC.ord.nullable, true);
  assert.strictEqual(R.CANDIDATE_SPEC.lineage_id.nullable, true);
  assert.ok(!Object.keys(POL.OPEN_CHOICES).some((k) => /lineage|place/.test(k)));
});
