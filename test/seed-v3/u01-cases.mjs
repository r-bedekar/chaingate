// U-01 A1 — the fixed golden case set.
//
// This module defines INPUTS only. `u01-goldens.capture.mjs` runs them through the FROZEN gate at
// 306bccde and records what it returned; `u01-goldens.test.js` runs the same inputs through the
// refactored gate and through `check`, and requires the recorded answer exactly. Keeping the inputs
// in one module is what makes "the same case" mean the same bytes on both sides.
//
// It imports only modules that exist, unchanged, at 306bccde, so the capture can run there.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import R from '../../seed/v3/reader.js';
import A from '../../seed/v3/adapter.js';
import PK from '../../seed/v3/packument.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const PACKUMENT_FIXTURE_DIR = path.join(HERE, '..', '..', 'seed', 'v3', 'packument-fixtures');

// The two policies. PROXY_POLICY is what `chaingate init` records for the demo host; ALT_POLICY
// exercises the other value of each open choice on a subset, so a golden cannot pass by accident of
// one configuration.
export const PROXY_POLICY = Object.freeze({ on_unusable_input: 'BLOCK', on_no_evidence: 'WARN' });
export const ALT_POLICY = Object.freeze({ on_unusable_input: 'WARN', on_no_evidence: 'ALLOW' });

// ------------------------------------------------------------------------------------------------
// Synthetic seed — same schema and same derivation as test/seed-v3/lineage-coverage.test.js
// ------------------------------------------------------------------------------------------------
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

export const BASE_S = 1767225600;                         // 2026-01-01T00:00:00Z
export const STEP_S = 100_000;
const iso = (s) => new Date(s * 1000).toISOString();

/** A manifest that matches the seeded initial state, so nothing breaks unless a case makes it. */
export const manifestFor = (name, version, over = {}) => ({
  name, version,
  _npmUser: { name: 'alice', email: 'alice@example.com' },
  _npmVersion: '10.2.3',
  maintainers: [{ name: 'alice', email: 'alice@example.com' }],
  gitHead: 'abc123',
  dist: { unpackedSize: 1000, attestations: { url: 'https://x' } },
  ...over,
});

function initialFor(name) {
  const b = A.candidateFromRawRow(
    PK.observationFromManifest('1.0.0', manifestFor(name, '1.0.0'), iso(BASE_S)),
    { packageName: name, lineageId: 1, ord: 0, domainVersionCount: 0 });
  return {
    baseline: b,
    state: {
      publisher: { identity_digest: b.identity_digest, tuple_digest: b.tuple_digest,
        maint_digest: b.maint_digest, tool_name: b.tool_name },
      provenance: { present: true },
      install: { has_scripts: false, body_digest: '' },
      git: { head_present: true, repo_digest: null },
      deps: {},
    },
  };
}

/**
 * The synthetic seed. Package `p`: lineage 1 (major 1) with spine 1.0.0, 1.1.0, 1.2.0 published at
 * BASE_S + ord*STEP_S. Package `deep`: one lineage of 30 versions whose spine keeps only ords 20..29
 * and whose events table records 1.5.0 at ord 5, so a recorded release has a predecessor BEYOND the
 * spine. Pins on p@1.3.0 (append), p@1.4.0 (no publication time), p@1.1.0 (recorded).
 */
export function buildSyntheticSeed() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'u01-golden-'));
  const dbPath = path.join(dir, 'chaingate-seed.db');
  const db = new Database(dbPath);
  db.exec(SCHEMA);

  const P = initialFor('p');
  db.prepare('INSERT INTO packages VALUES (?,?,?,?,?)').run(1, 'p', '1.2.0', 1, '1');
  db.prepare('INSERT INTO lineages VALUES (?,?,?,?,?,?,?,?,?)')
    .run(1, 1, 0, '1', '1.0.0', '1.2.0', 3, BASE_S, BASE_S + 2 * STEP_S);
  for (const g of Object.keys(P.state)) {
    db.prepare('INSERT INTO lineage_state VALUES (?,?,?)').run(1, g, JSON.stringify(P.state[g]));
  }
  ['1.0.0', '1.1.0', '1.2.0'].forEach((v, ord) => {
    db.prepare('INSERT INTO spine VALUES (?,?,?,?,?,?,?,?,?,?)').run(1, ord, v, BASE_S + ord * STEP_S,
      0, P.baseline.size_bytes, P.baseline.tool_key, null, 'LIVE', Buffer.alloc(32));
  });
  for (const v of ['1.3.0', '1.4.0', '1.1.0']) {
    db.prepare('INSERT INTO known_malicious_pins VALUES (?,?,?,?)').run(1, v, `MAL-2026-U01-${v}`, 'osv');
  }

  const D = initialFor('deep');
  const deepVersions = Array.from({ length: 30 }, (_, i) => `1.${i}.0`);
  db.prepare('INSERT INTO packages VALUES (?,?,?,?,?)').run(2, 'deep', '1.29.0', 1, '1');
  db.prepare('INSERT INTO lineages VALUES (?,?,?,?,?,?,?,?,?)')
    .run(2, 2, 0, '1', '1.0.0', '1.29.0', 30, BASE_S, BASE_S + 29 * STEP_S);
  for (const g of Object.keys(D.state)) {
    db.prepare('INSERT INTO lineage_state VALUES (?,?,?)').run(2, g, JSON.stringify(D.state[g]));
  }
  for (let ord = 20; ord < 30; ord++) {
    db.prepare('INSERT INTO spine VALUES (?,?,?,?,?,?,?,?,?,?)').run(2, ord, deepVersions[ord],
      BASE_S + ord * STEP_S, 0, D.baseline.size_bytes, D.baseline.tool_key, null, 'LIVE', Buffer.alloc(32));
  }
  db.prepare('INSERT INTO events VALUES (?,?,?,?,?,?,?)').run(2, 'publisher', 5, '1.5.0',
    BASE_S + 5 * STEP_S, JSON.stringify(D.state.publisher), Buffer.alloc(32));

  // Package `pub`: the recorded publisher state has an EMPTY maint_digest, so the maintainers
  // constituent is NOT_EVALUATED (unsupported_field) whenever it is compared -- beside an identity
  // constituent that a changed publisher breaks. R6's publisher-constituent case.
  const U = initialFor('pub');
  const pubState = { ...U.state, publisher: { ...U.state.publisher, maint_digest: '' } };
  db.prepare('INSERT INTO packages VALUES (?,?,?,?,?)').run(3, 'pub', '1.2.0', 1, '1');
  db.prepare('INSERT INTO lineages VALUES (?,?,?,?,?,?,?,?,?)')
    .run(3, 3, 0, '1', '1.0.0', '1.2.0', 3, BASE_S, BASE_S + 2 * STEP_S);
  for (const g of Object.keys(pubState)) {
    db.prepare('INSERT INTO lineage_state VALUES (?,?,?)').run(3, g, JSON.stringify(pubState[g]));
  }
  ['1.0.0', '1.1.0', '1.2.0'].forEach((v, ord) => {
    db.prepare('INSERT INTO spine VALUES (?,?,?,?,?,?,?,?,?,?)').run(3, ord, v, BASE_S + ord * STEP_S,
      0, U.baseline.size_bytes, U.baseline.tool_key, null, 'LIVE', Buffer.alloc(32));
  });

  for (const [k, v] of Object.entries({
    schema_version: '3', contract_version: 'cft-seed-v3-contract-1.0',
    corpus_snapshot_digest: 'f'.repeat(64), history_cutoff: '2026-12-31T00:00:00Z',
    rule_versions: JSON.stringify(Object.fromEntries(
      Object.entries(R.SUPPORTED_RULE_VERSIONS).map(([family, vs]) => [family, vs[0]]))),
  })) db.prepare('INSERT INTO seed_metadata VALUES (?,?)').run(k, v);
  db.close();
  fs.writeFileSync(`${dbPath}.sha256`,
    `${createHash('sha256').update(fs.readFileSync(dbPath)).digest('hex')}  chaingate-seed.db\n`);
  return { dir, dbPath };
}

// ------------------------------------------------------------------------------------------------
// Case construction. Every case is a packument DOCUMENT plus a version, because that is what the
// proxy has and what `check --packument` will read: the gate input is derived from it the same way.
// ------------------------------------------------------------------------------------------------

/** The gate input the proxy derives from a packument document, per plan §3.3. */
export function inputFromPackument(doc, version) {
  const versions = doc && typeof doc.versions === 'object' && doc.versions !== null ? doc.versions : {};
  const time = doc && typeof doc.time === 'object' && doc.time !== null ? doc.time : {};
  return {
    packageName: doc.name,
    version,
    rawManifest: Object.prototype.hasOwnProperty.call(versions, version) ? versions[version] : undefined,
    publishedAt: time[version],
    rawVersions: versions,
  };
}

/** A synthetic packument for `name`: the seeded releases plus the candidate, with times. */
function synthDoc(name, seeded, candidate, { manifest, publishedAt, omitCandidate = false } = {}) {
  const versions = {};
  const time = {};
  seeded.forEach(([v, s]) => { versions[v] = manifestFor(name, v); time[v] = iso(s); });
  if (!omitCandidate) {
    versions[candidate] = manifest === undefined ? manifestFor(name, candidate) : manifest;
    if (publishedAt !== undefined) time[candidate] = publishedAt;
  }
  return { name, versions, time };
}

const P_SEEDED = [['1.0.0', BASE_S], ['1.1.0', BASE_S + STEP_S], ['1.2.0', BASE_S + 2 * STEP_S]];
const TIP_S = BASE_S + 2 * STEP_S;
const AFTER = iso(TIP_S + STEP_S);
const DEEP_SEEDED = Array.from({ length: 30 }, (_, i) => [`1.${i}.0`, BASE_S + i * STEP_S]);

/**
 * Synthetic cases. `doc` is the packument; `version` the candidate. When a case needs the time entry
 * of a SEEDED version removed (recorded release with no publication time) it says so explicitly.
 */
export function syntheticCases() {
  const cases = [];
  const add = (id, doc, version, policy = PROXY_POLICY, note = '') =>
    cases.push({ id, seed: 'synthetic', policy, doc, version, note });

  add('allow-append', synthDoc('p', P_SEEDED, '1.5.0', { publishedAt: AFTER }), '1.5.0', PROXY_POLICY,
    'successful ALLOW: an unchanged release appended after the recorded tip');
  add('warn-trajectory', synthDoc('p', P_SEEDED, '1.6.0', {
    publishedAt: AFTER,
    manifest: manifestFor('p', '1.6.0', {
      scripts: { postinstall: 'node x.js' }, dist: { unpackedSize: 9000, attestations: { url: 'https://x' } } }),
  }), '1.6.0', PROXY_POLICY, 'trajectory WARN: install script introduced and 9x size');
  add('pin-block-append', synthDoc('p', P_SEEDED, '1.3.0', { publishedAt: AFTER }), '1.3.0', PROXY_POLICY,
    'pin BLOCK on an appended release');

  // --- missing publication time: the frozen precedence of resolvePlacement -----------------------
  add('notime-pin-block-ineligible', synthDoc('p', P_SEEDED, '1.4.0', {}), '1.4.0', PROXY_POLICY,
    'no time[] entry; covered, not recorded, not a stub -> ineligible-no-publication-time; pinned -> BLOCK');
  add('notime-unpinned-ineligible', synthDoc('p', P_SEEDED, '1.7.0', {}), '1.7.0', PROXY_POLICY,
    'no time[] entry, not pinned -> ineligible-no-publication-time');
  {
    const doc = synthDoc('p', P_SEEDED, '1.1.0', { omitCandidate: true });
    delete doc.time['1.1.0'];
    add('notime-recorded-pinned', doc, '1.1.0', PROXY_POLICY,
      'no time[] entry but the version is RECORDED -> recorded outranks E5; pinned -> BLOCK');
  }
  {
    const doc = synthDoc('p', P_SEEDED, '1.2.0', { omitCandidate: true });
    delete doc.time['1.2.0'];
    add('notime-recorded-unpinned', doc, '1.2.0', PROXY_POLICY,
      'no time[] entry, recorded, not pinned -> recorded');
  }
  add('notime-stub', synthDoc('p', P_SEEDED, '0.0.1-security', {}), '0.0.1-security', PROXY_POLICY,
    'no time[] entry, takedown stub -> E4 outranks E5: ineligible-stub');
  add('notime-uncovered', synthDoc('q', [], '1.0.0', {}), '1.0.0', PROXY_POLICY,
    'no time[] entry, package not in the seed -> uncovered-package outranks everything');
  add('notime-nonstring-time', synthDoc('p', P_SEEDED, '1.8.0', { publishedAt: 1767900000 }), '1.8.0',
    PROXY_POLICY, 'time[] entry is a NUMBER: the gate passes null (not a refusal)');

  // --- refusals ----------------------------------------------------------------------------------
  add('refuse-missing-manifest', synthDoc('p', P_SEEDED, '1.5.0', { publishedAt: AFTER, manifest: null }),
    '1.5.0', PROXY_POLICY, 'versions[v] is null -> policy refusal');
  add('refuse-version-absent', synthDoc('p', P_SEEDED, '9.9.9', { omitCandidate: true }), '9.9.9',
    PROXY_POLICY, 'version absent from the document -> same refusal as a missing manifest');
  add('refuse-malformed-npmuser', synthDoc('p', P_SEEDED, '1.5.0', {
    publishedAt: AFTER, manifest: manifestFor('p', '1.5.0', { _npmUser: 'alice' }) }), '1.5.0',
  PROXY_POLICY, 'adapter rejection: _npmUser is a string');
  add('refuse-version-mismatch', synthDoc('p', P_SEEDED, '1.5.0', {
    publishedAt: AFTER, manifest: manifestFor('p', '1.5.1') }), '1.5.0', PROXY_POLICY,
  'adapter rejection: manifest.version disagrees with its key');
  add('refuse-bad-time', synthDoc('p', P_SEEDED, '1.5.0', { publishedAt: 'not-a-date' }), '1.5.0',
    PROXY_POLICY, 'adapter rejection: time[] is not ISO-8601');

  // --- placements --------------------------------------------------------------------------------
  add('uncovered', synthDoc('q', [], '1.0.0', { publishedAt: AFTER }), '1.0.0', PROXY_POLICY,
    'uncovered package');
  add('cold-start-new-major', synthDoc('p', P_SEEDED, '2.0.0', { publishedAt: AFTER }), '2.0.0',
    PROXY_POLICY, 'new-major cold start');
  add('unresolved-calver', synthDoc('p', P_SEEDED, '2024.1.0', { publishedAt: AFTER }), '2024.1.0',
    PROXY_POLICY, 'unresolved: CalVer-year major');
  add('unresolved-equal-second', synthDoc('p', P_SEEDED, '1.3.1', { publishedAt: iso(TIP_S) }), '1.3.1',
    PROXY_POLICY, 'unresolved: same stored second as the recorded tip');
  add('historical-omitted', synthDoc('p', P_SEEDED, '1.1.5', { publishedAt: iso(TIP_S - 1) }), '1.1.5',
    PROXY_POLICY, 'historical-omitted: published before the recorded tip');
  add('stub-with-time', synthDoc('p', P_SEEDED, '0.0.2-security', { publishedAt: AFTER }),
    '0.0.2-security', PROXY_POLICY, 'ineligible-stub with a publication time');
  add('recorded-deep-beyond-spine', synthDoc('deep', DEEP_SEEDED, '1.5.0', { omitCandidate: true }),
    '1.5.0', PROXY_POLICY, 'incomplete evidence: recorded at ord 5, predecessor beyond the K spine');
  add('append-deep', synthDoc('deep', DEEP_SEEDED, '1.30.0', { publishedAt: iso(BASE_S + 31 * STEP_S) }),
    '1.30.0', PROXY_POLICY, 'append to a lineage whose spine is truncated');

  add('publisher-broke-beside-unevaluated', synthDoc('pub', P_SEEDED, '1.3.0', {
    publishedAt: AFTER,
    manifest: manifestFor('pub', '1.3.0', { _npmUser: { name: 'mallory', email: 'mallory@evil.example' } }),
  }), '1.3.0', PROXY_POLICY, 'publisher identity BROKE while the maintainers constituent is NOT_EVALUATED');

  // --- the other policy values -------------------------------------------------------------------
  add('alt-refuse-missing-manifest', synthDoc('p', P_SEEDED, '1.5.0', { publishedAt: AFTER, manifest: null }),
    '1.5.0', ALT_POLICY, 'on_unusable_input=WARN');
  add('alt-uncovered', synthDoc('q', [], '1.0.0', { publishedAt: AFTER }), '1.0.0', ALT_POLICY,
    'on_no_evidence=ALLOW');
  add('alt-cold-start', synthDoc('p', P_SEEDED, '2.0.0', { publishedAt: AFTER }), '2.0.0', ALT_POLICY,
    'on_no_evidence=ALLOW on a cold start');
  add('alt-pin-notime', synthDoc('p', P_SEEDED, '1.4.0', {}), '1.4.0', ALT_POLICY,
    'a pin still BLOCKs under on_no_evidence=ALLOW');
  return cases;
}

/** rc3 cases: every version of every real packument fixture, plus pins and edge cases on the real seed. */
export function rc3Cases(seedDb) {
  const cases = [];
  const add = (id, doc, version, policy = PROXY_POLICY, note = '') =>
    cases.push({ id, seed: 'rc3', policy, doc, version, note });
  const files = fs.readdirSync(PACKUMENT_FIXTURE_DIR).filter((f) => f.endsWith('.json')).sort();
  for (const f of files) {
    const doc = JSON.parse(fs.readFileSync(path.join(PACKUMENT_FIXTURE_DIR, f), 'utf8'));
    for (const v of Object.keys(doc.versions)) add(`rc3:${f}:${v}`, doc, v, PROXY_POLICY, 'real packument');
    // the newest version with its time[] entry removed: missing time on a real covered package
    const last = Object.keys(doc.versions).at(-1);
    const noTime = { ...doc, time: { ...doc.time } };
    delete noTime.time[last];
    add(`rc3-notime:${f}:${last}`, noTime, last, PROXY_POLICY, 'real packument, time[] entry removed');
  }
  // Real pins. Chosen deterministically from the seed, so the case set does not depend on a list
  // typed here: the first pins by (package_name, version) that are MAL- advisories.
  // Two whose version the seed RECORDS and two it does not, so the no-publication-time precedence
  // (recorded outranks E5; otherwise ineligible-no-publication-time) is exercised on the real seed.
  const recorded = "EXISTS (SELECT 1 FROM lineages l LEFT JOIN spine s ON s.lineage_id = l.id AND s.version = k.version "
    + 'LEFT JOIN events e ON e.lineage_id = l.id AND e.version = k.version WHERE l.package_id = k.package_id '
    + 'AND (s.version IS NOT NULL OR e.version IS NOT NULL))';
  const pickPins = (cond) => seedDb.prepare(
    'SELECT p.package_name AS name, k.version AS version FROM known_malicious_pins k '
    + `JOIN packages p ON p.id = k.package_id WHERE k.advisory_id LIKE 'MAL-%' AND ${cond} `
    + "AND k.version NOT GLOB '*-security' "
    + 'GROUP BY p.package_name, k.version ORDER BY p.package_name, k.version LIMIT 2').all();
  const pins = [...pickPins(recorded), ...pickPins(`NOT ${recorded}`)];
  for (const pin of pins) {
    const minimal = { name: pin.name, version: pin.version,
      _npmUser: { name: 'x', email: 'x@example.invalid' }, dist: { unpackedSize: 1000 } };
    add(`rc3-pin-notime:${pin.name}@${pin.version}`,
      { name: pin.name, versions: { [pin.version]: minimal }, time: {} }, pin.version, PROXY_POLICY,
      'real pin, no publication time');
    add(`rc3-pin-time:${pin.name}@${pin.version}`,
      { name: pin.name, versions: { [pin.version]: minimal }, time: { [pin.version]: '2026-06-01T00:00:00.000Z' } },
      pin.version, PROXY_POLICY, 'real pin, with a publication time');
  }
  add('rc3-uncovered', { name: 'definitely-not-a-real-package-xyzzy',
    versions: { '1.0.0': { name: 'definitely-not-a-real-package-xyzzy', version: '1.0.0' } },
    time: { '1.0.0': '2026-06-01T00:00:00.000Z' } }, '1.0.0', PROXY_POLICY, 'uncovered on the real seed');
  return cases;
}

/** Canonical JSON (sorted keys) — used ONLY to digest documents; recorded results keep their order. */
export function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v === undefined ? null : v);
}
export const sha256 = (s) => createHash('sha256').update(s).digest('hex');

export const RC3_DIR = process.env.CFT04_CANDIDATE || '';
