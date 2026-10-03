// U-05 R2-2 legacy part: synthetic LEGACY seeds and witness databases on the REAL legacy schema
// (test/fixtures/bundle-schema.sql, vendored from the collector's dump) and on the runtime schema (witness/db.js), signed
// with a throwaway test key. Logical snapshots compare content, relationships and EFFECTIVE decisions, not counts.
// Synthetic inputs only.
import fs from 'node:fs';
import path from 'node:path';
import { createHash, generateKeyPairSync, sign as edSign } from 'node:crypto';
import Database from 'better-sqlite3';

import { ROOT } from './u05-r22.mjs';
import { openWitnessDB } from '../../witness/db.js';
import { verifyStagedSeed, verifyPersistedSignature } from '../../witness/seed_verify.js';
import { enforceTarballGate } from '../../proxy/server.js';

export const LEGACY_SCHEMA = fs.readFileSync(path.join(ROOT, 'test', 'fixtures', 'bundle-schema.sql'), 'utf8');

export function testKey() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { publicKey, privateKey, spki: publicKey.export({ type: 'spki', format: 'der' }).toString('base64') };
}

/** Injected verifiers that use the TEST key (the product's pinned key is never replaced). */
export const verifierFor = (key) => (staged) => verifyStagedSeed(staged, { pubkey: key.publicKey });
export const persistedVerifierFor = (key) => (sha, sig) => verifyPersistedSignature(sha, sig, { pubkey: key.publicKey });

const sha256File = (f) => createHash('sha256').update(fs.readFileSync(f)).digest('hex');

/** Drop the CREATE TABLE statements of `drop` from the vendored schema (an older or partial seed). */
function schemaWithout(drop) {
  if (!drop.length) return LEGACY_SCHEMA;
  return LEGACY_SCHEMA.split(/;\s*\n/).filter((stmt) => !drop.some((t) => new RegExp(`\\b(TABLE|ON)\\s+${t}\\b`).test(stmt)))
    .join(';\n');
}

/**
 * A signed synthetic legacy seed: chaingate-seed.db (+ .sha256 + .sig) in `dir`.
 * pkgs: [{ id, name, versions: [{ id, version, content_hash, files: [{ id, filename }] }] }]
 */
export function buildLegacySeed(dir, { key, seedVersion = '2026.test.2', pkgs = DEFAULT_PKGS, decisions = [],
  overrides = [], labels = true, depFirstPublish = [], drop = [], sql = null } = {}) {
  fs.mkdirSync(dir, { recursive: true });
  const dbPath = path.join(dir, 'chaingate-seed.db');
  fs.rmSync(dbPath, { force: true });
  const db = new Database(dbPath);
  db.exec(schemaWithout(drop));
  // One transaction for the fixture rows: row-by-row autocommit cost one fsync per row (about 4,000 for the timed-kill
  // trials' seed), which took the Windows CI unit job past its time limit. The rows written are the same.
  db.exec('BEGIN');
  for (const p of pkgs) {
    db.prepare("INSERT INTO packages (id, ecosystem, package_name) VALUES (?, 'npm', ?)").run(p.id, p.name);
    for (const v of p.versions) {
      db.prepare(`INSERT INTO versions (id, package_id, version, published_at, content_hash, content_hash_algo,
        integrity_hash, publisher_name, maintainers, provenance_source) VALUES (?,?,?,?,?,?,?,?,?,?)`)
        .run(v.id, p.id, v.version, v.published_at ?? '2026-01-01T00:00:00Z', v.content_hash ?? `h-${p.name}-${v.version}`,
          'sha512', `sha512-${p.name}-${v.version}`, 'pub', JSON.stringify([{ name: 'm' }]), v.provenance_source ?? 'collected');
      for (const f of drop.includes('version_files') ? [] : (v.files ?? [])) {
        db.prepare('INSERT INTO version_files (id, version_id, filename, content_hash) VALUES (?,?,?,?)')
          .run(f.id, v.id, f.filename, `fh-${f.filename}`);
      }
    }
    if (labels && !drop.includes('attack_labels')) {
      db.prepare(`INSERT INTO attack_labels (package_id, version_id, is_malicious, attack_name, source, advisory_id)
        VALUES (?, ?, 1, 'malware', 'osv', ?)`).run(p.id, p.versions[0]?.id ?? null, `MAL-TEST-${p.name}`);
    }
  }
  const meta = { schema_version: '2', seed_version: seedVersion, exported_at: '2026-04-26T00:00:00Z' };
  for (const [k, v] of Object.entries(meta)) db.prepare('INSERT INTO seed_metadata (key, value) VALUES (?, ?)').run(k, v);
  for (const d of decisions) {
    db.prepare(`INSERT INTO gate_decisions (${d.id ? 'id, ' : ''}package_name, version, disposition, gates_fired, decided_at)
      VALUES (${d.id ? '?, ' : ''}?,?,?,?,?)`).run(...(d.id ? [d.id] : []), d.pkg, d.ver, d.disposition,
      JSON.stringify(d.gates ?? [{ gate: 'seed', result: d.disposition }]), d.at);
  }
  for (const o of overrides) {
    db.prepare(`INSERT INTO overrides (${o.id ? 'id, ' : ''}package_name, version, reason, created_at) VALUES (${o.id ? '?, ' : ''}?,?,?,?)`)
      .run(...(o.id ? [o.id] : []), o.pkg, o.ver, o.reason, o.at ?? '2026-01-02 00:00:00');
  }
  if (!drop.includes('dep_first_publish')) {
    for (const r of depFirstPublish) db.prepare("INSERT INTO dep_first_publish (package_name, first_publish, status) VALUES (?, ?, 'ok')").run(r.name, r.at);
  }
  db.exec('COMMIT');
  if (sql) db.exec(sql);
  db.close();
  const digest = sha256File(dbPath);
  fs.writeFileSync(`${dbPath}.sha256`, `${digest}\n`);
  fs.writeFileSync(`${dbPath}.sig`, edSign(null, Buffer.from(digest, 'ascii'), key.privateKey));
  return { dir, db: dbPath, sha: `${dbPath}.sha256`, sig: `${dbPath}.sig`, digest, size: fs.statSync(dbPath).size };
}

export const DEFAULT_PKGS = [
  { id: 1, name: 'alpha', versions: [{ id: 10, version: '1.0.0', files: [{ id: 100, filename: 'alpha-1.0.0.tgz' }] },
    { id: 11, version: '1.1.0', files: [{ id: 101, filename: 'alpha-1.1.0.tgz' }] }] },
  { id: 2, name: 'beta', versions: [{ id: 20, version: '2.0.0', files: [{ id: 200, filename: 'beta-2.0.0.tgz' }] }] },
];
/** The NEW seed: alpha changes, beta goes, gamma arrives (ids reused and moved on purpose). */
export const NEW_PKGS = [
  { id: 1, name: 'alpha', versions: [{ id: 10, version: '1.0.0', content_hash: 'h-alpha-1.0.0-v2', files: [{ id: 100, filename: 'alpha-1.0.0.tgz' }] },
    { id: 12, version: '1.2.0', files: [{ id: 102, filename: 'alpha-1.2.0.tgz' }] }] },
  { id: 3, name: 'gamma', versions: [{ id: 20, version: '3.0.0', files: [{ id: 200, filename: 'gamma-3.0.0.tgz' }] }] },
];

/**
 * A witness database as a legacy host has it: `from: 'seed'` = installed from a legacy seed (its schema), `from:
 * 'runtime'` = created by the runtime (--no-seed). Then local state: decisions, overrides, a locally observed baseline,
 * the dep cache. Rows use explicit ids where a test needs a collision.
 */
export function legacyWitness(base, { from = 'seed', seed = null, local = {}, sidecars = true } = {}) {
  fs.mkdirSync(base, { recursive: true });
  const w = path.join(base, 'witness.db');
  if (from === 'seed') fs.copyFileSync(seed.db, w);
  const h = openWitnessDB(w); h.applySchema();
  for (const d of local.decisions ?? []) {
    h.db.prepare(`INSERT INTO gate_decisions (${d.id ? 'id, ' : ''}package_name, version, disposition, gates_fired, decided_at)
      VALUES (${d.id ? '?, ' : ''}?,?,?,?,?)`).run(...(d.id ? [d.id] : []), d.pkg, d.ver, d.disposition,
      JSON.stringify(d.gates ?? [{ gate: 'local', result: d.disposition }]), d.at);
  }
  for (const o of local.overrides ?? []) {
    h.db.prepare(`INSERT INTO overrides (${o.id ? 'id, ' : ''}package_name, version, reason, created_at) VALUES (${o.id ? '?, ' : ''}?,?,?,?)`)
      .run(...(o.id ? [o.id] : []), o.pkg, o.ver, o.reason, o.at ?? '2026-01-03 00:00:00');
  }
  for (const b of local.baselines ?? []) h.recordBaseline(b.pkg, b.ver, { content_hash: `local-${b.pkg}-${b.ver}`, files: [{ filename: `${b.pkg}-${b.ver}.tgz` }] });
  for (const r of local.depCache ?? []) h.db.prepare("INSERT OR REPLACE INTO dep_first_publish (package_name, first_publish, status) VALUES (?, ?, 'ok')").run(r.name, r.at);
  h.close();
  if (from === 'seed' && seed && sidecars) { fs.copyFileSync(seed.sha, path.join(base, 'witness.db.sha256')); fs.copyFileSync(seed.sig, path.join(base, 'witness.db.sig')); }
  return w;
}

const TABLES = ['packages', 'versions', 'version_files', 'attack_labels', 'seed_metadata', 'gate_decisions', 'overrides', 'dep_first_publish'];
const KEY = { seed_metadata: 'key', dep_first_publish: 'package_name' };

/** Every row of every known table (ordered by its key), the table list, foreign_key_check, integrity_check. */
export function snapshot(dbPath) {
  const db = new Database(dbPath, { readonly: true, fileMustExist: true });
  try {
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map((r) => r.name);
    const rows = {};
    for (const t of TABLES) if (tables.includes(t)) rows[t] = db.prepare(`SELECT * FROM "${t}" ORDER BY "${KEY[t] ?? 'id'}"`).all();
    return { tables, rows, fk: db.pragma('foreign_key_check'), integrity: db.pragma('integrity_check', { simple: true }) };
  } finally { db.close(); }
}

/** Project rows onto `cols` (to compare a witness table with the seed table on the copied columns). */
export const project = (rows, cols) => rows.map((r) => Object.fromEntries(cols.map((c) => [c, r[c]])));

/**
 * The EFFECTIVE decision for every (package, version) that has a decision or an override: what getLatestDecision and the
 * N3 getLatestNonOverrideDecision return, whether an override exists, and the tarball gate's verdict.
 */
export function effective(dbPath) {
  const w = openWitnessDB(dbPath, { readonly: true });
  try {
    const keys = w.db.prepare(`SELECT package_name AS p, version AS v FROM gate_decisions UNION
      SELECT package_name, version FROM overrides ORDER BY 1, 2`).all();
    const out = {};
    for (const { p, v } of keys) {
      const latest = w.getLatestDecision(p, v); const nonOv = w.getLatestNonOverrideDecision(p, v);
      const gate = enforceTarballGate(w, p, `${p}-${v}.tgz`, null, { overriddenLive: (n, ver) => Boolean(w.getOverride(n, ver)) }, {});
      out[`${p}@${v}`] = { latest: latest && { id: latest.id, disposition: latest.disposition }, nonOverride: nonOv && nonOv.disposition,
        override: Boolean(w.getOverride(p, v)), tarball: gate ? (gate.refuse?.status ?? gate.status ?? 'refused') : 'allowed' };
    }
    return out;
  } finally { w.close(); }
}
