// U-05 S2 — shared fixtures for the D4 / Amendment 1 tests (decision tables:
// ~/docs/plans/CFT/U-05-S2-DECISION-TABLES-20260930.md).
//
// Synthetic seeds in BOTH pin layouts, built here from the same derivation as u01-cases.mjs:
//   1.0  known_malicious_pins(package_id, version, advisory_id, source): the rc3 layout; the lookup joins `packages`
//   1.1  known_malicious_pins(package_id, package_name, version, advisory_id, source) + index (package_name, version),
//        seed_metadata.contract_version = cft-seed-v3-contract-1.1 (revision 2 §3.5)
// Packages `p` and `q`: one lineage (major 1) recording 1.0.0, 1.1.0, 1.2.0. Package `u` is NOT represented.
// Pins: p@1.3.0 ADV-P-130, p@1.5.0 ADV-P-150, p@2.0.0 ADV-P-200, and u@1.0.0 ADV-U-100 (package_id 9001, no
// `packages` row: visible only by name, i.e. only in the 1.1 layout — in 1.0 it is the orphan-row control, case f).
// Nothing here is a real package, advisory or seed.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import Database from 'better-sqlite3';
import R from '../../seed/v3/reader.js';
import A from '../../seed/v3/adapter.js';
import PK from '../../seed/v3/packument.js';

export const SEED_CONTRACT_1_0 = 'cft-seed-v3-contract-1.0';
export const SEED_CONTRACT_1_1 = 'cft-seed-v3-contract-1.1';
export const LIVE = Object.freeze({ on_unusable_input: 'BLOCK', on_no_evidence: 'WARN' });
export const WARNCFG = Object.freeze({ on_unusable_input: 'WARN', on_no_evidence: 'WARN' });
export const CONFIGS = Object.freeze({ live: LIVE, warn: WARNCFG });

export const BASE_S = 1767225600;                         // 2026-01-01T00:00:00Z
export const STEP_S = 100_000;
export const iso = (s) => new Date(s * 1000).toISOString();
export const SEEDED = [['1.0.0', BASE_S], ['1.1.0', BASE_S + STEP_S], ['1.2.0', BASE_S + 2 * STEP_S]];
export const TIP_S = BASE_S + 2 * STEP_S;
export const after = (n = 1) => iso(TIP_S + n * STEP_S);

export const PINS = Object.freeze([
  { pkgId: 1, name: 'p', version: '1.3.0', advisory: 'ADV-P-130' },
  { pkgId: 1, name: 'p', version: '1.5.0', advisory: 'ADV-P-150' },
  { pkgId: 1, name: 'p', version: '2.0.0', advisory: 'ADV-P-200' },
  { pkgId: 9001, name: 'u', version: '1.0.0', advisory: 'ADV-U-100' },
]);
export const advisoryFor = (name, version) => PINS.find((x) => x.name === name && x.version === version)?.advisory;

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

const CORE = `
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
CREATE TABLE seed_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
`;
export const PINS_1_0 = `CREATE TABLE known_malicious_pins (package_id INTEGER NOT NULL, version TEXT NOT NULL,
  advisory_id TEXT NOT NULL, source TEXT NOT NULL, PRIMARY KEY (package_id, version, advisory_id)) WITHOUT ROWID;`;
export const PINS_1_1 = `CREATE TABLE known_malicious_pins (package_id INTEGER NOT NULL, package_name TEXT NOT NULL,
  version TEXT NOT NULL, advisory_id TEXT NOT NULL, source TEXT NOT NULL,
  PRIMARY KEY (package_id, version, advisory_id)) WITHOUT ROWID;
CREATE INDEX idx_pins_name ON known_malicious_pins(package_name, version);`;

/**
 * Build a synthetic seed. `layout` '1.0' | '1.1'. `pinsSql` / `contract` override the layout's own (for the
 * malformed-seed probes). Returns { dir, dbPath, cleanup }.
 */
export function buildSeed({ layout = '1.0', pins = PINS, pinsSql = null, contract = null } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `u05-seed-${layout}-`));
  const dbPath = path.join(dir, 'chaingate-seed.db');
  const db = new Database(dbPath);
  db.exec(CORE);
  db.exec(pinsSql ?? (layout === '1.1' ? PINS_1_1 : PINS_1_0));
  let lid = 0;
  for (const [pid, name] of [[1, 'p'], [2, 'q']]) {
    const P = initialFor(name);
    lid += 1;
    db.prepare('INSERT INTO packages VALUES (?,?,?,?,?)').run(pid, name, '1.2.0', 1, '1');
    db.prepare('INSERT INTO lineages VALUES (?,?,?,?,?,?,?,?,?)')
      .run(lid, pid, 0, '1', '1.0.0', '1.2.0', 3, BASE_S, TIP_S);
    for (const g of Object.keys(P.state)) {
      db.prepare('INSERT INTO lineage_state VALUES (?,?,?)').run(lid, g, JSON.stringify(P.state[g]));
    }
    SEEDED.forEach(([v, s], ord) => {
      db.prepare('INSERT INTO spine VALUES (?,?,?,?,?,?,?,?,?,?)').run(lid, ord, v, s,
        0, P.baseline.size_bytes, P.baseline.tool_key, null, 'LIVE', Buffer.alloc(32));
    });
  }
  const cols = db.prepare("SELECT name FROM pragma_table_info('known_malicious_pins')").all().map((r) => r.name);
  for (const k of pins) {
    const row = cols.includes('package_name')
      ? [k.pkgId, k.name, k.version, k.advisory, 'synthetic-fixture']
      : [k.pkgId, k.version, k.advisory, 'synthetic-fixture'];
    db.prepare(`INSERT INTO known_malicious_pins VALUES (${row.map(() => '?').join(',')})`).run(...row);
  }
  for (const [k, v] of Object.entries({
    schema_version: '3', contract_version: contract ?? (layout === '1.1' ? SEED_CONTRACT_1_1 : SEED_CONTRACT_1_0),
    corpus_snapshot_digest: 'f'.repeat(64), history_cutoff: '2026-12-31T00:00:00Z',
    rule_versions: JSON.stringify(Object.fromEntries(
      Object.entries(R.SUPPORTED_RULE_VERSIONS).map(([family, vs]) => [family, vs[0]]))),
  })) db.prepare('INSERT INTO seed_metadata VALUES (?,?)').run(k, v);
  db.close();
  fs.writeFileSync(`${dbPath}.sha256`,
    `${createHash('sha256').update(fs.readFileSync(dbPath)).digest('hex')}  chaingate-seed.db\n`);
  return { dir, dbPath, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

export const openFixtureSeed = (dbPath) => R.openSeed(dbPath, { trust: R.TRUST_UNSIGNED_DEV });

/** A packument for `name`: the seeded releases plus `extra` [[version, publishedAt | undefined, manifest?]]. */
export function docFor(name, extra = [], { seeded = SEEDED } = {}) {
  const versions = {};
  const time = {};
  for (const [v, s] of seeded) { versions[v] = manifestFor(name, v); time[v] = iso(s); }
  for (const [v, t, m] of extra) {
    versions[v] = m === undefined ? manifestFor(name, v) : m;
    if (t !== undefined) time[v] = t;
  }
  return { name, 'dist-tags': { latest: Object.keys(versions).at(-1) }, versions, time };
}

/** Gate input from a document, exactly as the store builds it (witness/store.js 117-133, rawManifest null when absent). */
export function gateInput(doc, version) {
  const has = Object.prototype.hasOwnProperty.call(doc.versions, version);
  return { packageName: doc.name, version, rawManifest: has ? doc.versions[version] : null,
    publishedAt: typeof doc.time[version] === 'string' ? doc.time[version] : null, rawVersions: doc.versions };
}

/** Make every seed query that touches the pins table throw; returns a restore function. */
export function failPinLookup(seed, message = 'injected pin lookup failure') {
  const real = seed.db.prepare.bind(seed.db);
  seed.db.prepare = (sql) => {
    if (/known_malicious_pins/.test(sql)) throw new Error(message);
    return real(sql);
  };
  return () => { delete seed.db.prepare; };
}

/** The row in `results` that names advisory `adv` with result `want`, or undefined. */
export const namingRow = (results, adv, want = 'BLOCK') =>
  (results || []).find((x) => x.result === want && typeof x.detail === 'string' && x.detail.includes(adv));
