// U-05 R2-2, legacy part: installing or refreshing the LEGACY witness seed (the seed IS the witness database) without
// ever renaming a file over an existing database (owner decision 7; Addendum 2 §2.4 and §3.2; decision 7 §2).
//
//   * An existing witness.db is refreshed IN PLACE, in ONE SQLite transaction: the seed tables are replaced from the
//     verified staged seed (ATTACHed), the seed's own decisions and overrides are imported only where no local row has
//     the same natural key, and local tables are never touched. Every connection sees the old or the new committed
//     state; a writer holding its lock past the busy timeout makes the refresh refuse with nothing committed.
//   * A missing witness.db is created from a complete, verified, closed staging file in the SAME directory, published
//     with link(2), which atomically refuses an existing destination. There is no copy fallback.
//   * A pending-install marker is made durable BEFORE the database changes, and removed only once the database is
//     committed and both signature files are in place. Until then doctor reports the seed signature as unverifiable
//     and the integrity gate refuses every mutating command except the one that completes this installation.
//
// The persisted .sha256/.sig say that the installed seed came from a signed bundle. They do NOT authenticate the
// current, mutable witness database, and nothing here claims they do.
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

import { CAPS, FileRefused, openRegular, readBounded, hashRange, sha256Regular } from '../seed/v3/bounded-file.js';
import { fmt } from './format.js';
import { copyFdExact } from './seed-bundle.js';
import { assertHeld } from './seed-mutation-lock.js';
import { readPidRecord } from './proxy-control.js';
import { admit, LEGACY_SIDECARS } from './space-admission.js';

export const MARKER_FILE = 'witness.db.install-pending.json';
const MARKER_SCHEMA = 'chaingate-legacy-install/1';
export const BUSY_MS = 2000;
export const markerPath = (paths) => path.join(path.dirname(paths.witnessDb), MARKER_FILE);

/** Refused: nothing changed, unless `committed` says the database was already refreshed. */
export class LegacyInstallRefused extends Error {
  constructor(message, { committed = false, kind = 'refused' } = {}) {
    super(message); this.name = 'LegacyInstallRefused'; this.committed = committed; this.kind = kind;
  }
}

function fsyncDir(dir) {
  if (process.platform === 'win32') return;
  const fd = fs.openSync(dir, 'r');
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

// ---- the pending-install marker ---------------------------------------------------------------------------------------
/**
 * Read-only: { state: 'none' } | { state: 'pending', marker } | { state: 'invalid', why } | { state: 'unreadable', why }.
 * Doctor and the gate use it. Only a marker that is genuinely ABSENT (ENOENT) is "none": a location that cannot be
 * checked (EACCES, EIO, ...) is 'unreadable', never "no marker" (owner decision 8, Q1/Q2).
 */
export function readInstallMarker(paths) {
  const file = markerPath(paths);
  let st;
  try { st = fs.lstatSync(file); } catch (e) {
    if (e.code === 'ENOENT') return { state: 'none' };
    return { state: 'unreadable', why: `it could not be checked (${e.code || e.message})` };
  }
  if (!st.isFile()) return { state: 'invalid', why: 'it is not a regular file' };
  let rec;
  try { rec = JSON.parse(readBounded(file, CAPS.marker, { noFollow: true }).toString('utf8')); }
  catch (e) { return { state: 'invalid', why: e instanceof FileRefused ? e.why : `unreadable or not JSON: ${e.message}` }; }
  if (!rec || typeof rec !== 'object' || rec.schema !== MARKER_SCHEMA || rec.kind !== 'legacy-seed'
    || typeof rec.new_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(rec.new_sha256)) {
    return { state: 'invalid', why: 'not a legacy-install marker this version recognises' };
  }
  return { state: 'pending', marker: rec };
}

function writeMarker(paths, rec) {
  const file = markerPath(paths);
  const tmp = `${file}.tmp-${process.pid}`;
  fs.rmSync(tmp, { force: true });
  const fd = fs.openSync(tmp, 'wx', 0o600);
  try { fs.writeSync(fd, `${JSON.stringify(rec)}\n`); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(tmp, file);
  fsyncDir(path.dirname(file));
}

function removeMarker(paths) {
  try { fs.unlinkSync(markerPath(paths)); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  fsyncDir(path.dirname(markerPath(paths)));
}

// ---- the real schema, by owner (decision 7 §2.1) ---------------------------------------------------------------------
/** Columns of the RUNTIME schema (witness/db.js) of each replaced table: what the runtime reads and writes. */
export const RUNTIME_COLUMNS = Object.freeze({
  packages: ['id', 'ecosystem', 'package_name'],
  versions: ['id', 'package_id', 'version', 'published_at', 'content_hash', 'content_hash_algo', 'integrity_hash',
    'git_head', 'package_size_bytes', 'dependency_count', 'dependencies', 'dev_dependencies', 'peer_dependencies',
    'optional_dependencies', 'bundled_dependencies', 'dev_dependency_count', 'peer_dependency_count',
    'optional_dependency_count', 'bundled_dependency_count', 'publisher_name', 'publisher_email', 'publisher_tool',
    'maintainers', 'publish_method', 'provenance_present', 'provenance_details', 'has_install_scripts',
    'source_repo_url', 'license', 'first_observed_at', 'last_seen_at'],
  version_files: ['id', 'version_id', 'filename', 'packagetype', 'content_hash', 'content_hash_algo', 'size_bytes',
    'uploaded_at', 'url', 'first_observed_at', 'last_seen_at'],
  seed_metadata: ['key', 'value'],
});
/** Seed-owned tables: replaced. attack_labels is optional (the runtime does not read it). */
export const REQUIRED_SEED_TABLES = ['packages', 'versions', 'version_files', 'seed_metadata'];
export const OPTIONAL_SEED_TABLES = ['attack_labels'];
/** Children before parents (foreign keys are ON); insertion is the reverse. */
const DELETE_ORDER = ['version_files', 'attack_labels', 'versions', 'packages', 'seed_metadata'];
const INSERT_ORDER = ['packages', 'versions', 'version_files', 'attack_labels', 'seed_metadata'];
const ORDER_KEY = { seed_metadata: 'key' };
/** Local tables: never replaced. gate_decisions and overrides receive the seed's rows by natural key (§2.3). */
export const LOCAL_TABLES = ['gate_decisions', 'overrides', 'dep_first_publish'];
const DECISION_COLUMNS = ['package_name', 'version', 'disposition', 'gates_fired', 'decided_at'];
const OVERRIDE_COLUMNS = ['package_name', 'version', 'reason', 'created_at'];

const q = (id) => `"${String(id).replace(/"/g, '""')}"`;
const tablesOf = (db, schema) => new Set(db.prepare(`SELECT name FROM ${schema}.sqlite_master WHERE type = 'table'`)
  .all().map((r) => r.name));
const columnsOf = (db, schema, table) => db.prepare(`PRAGMA ${schema}.table_info(${q(table)})`).all();

/**
 * What a refresh of the attached `seed` into `main` would do, decided before any write. `refusal` set means: refuse,
 * nothing changes. Columns copied = present in BOTH tables; required = the runtime schema's, in both.
 */
export function planRefresh(db) {
  const seedTables = tablesOf(db, 'seed'); const mainTables = tablesOf(db, 'main');
  const plan = { tables: [], notCarried: [], refusal: null, imports: [] };
  const refuse = (why) => { plan.refusal = why; return plan; };
  for (const t of REQUIRED_SEED_TABLES) {
    if (!seedTables.has(t)) return refuse(`the seed has no ${t} table`);
    if (!mainTables.has(t)) return refuse(`the witness database has no ${t} table`);
  }
  for (const t of [...REQUIRED_SEED_TABLES, ...OPTIONAL_SEED_TABLES]) {
    if (!mainTables.has(t)) {
      if (seedTables.has(t)) plan.notCarried.push(`${t} (the witness database has no such table; the runtime does not read it)`);
      continue;
    }
    const mainCols = columnsOf(db, 'main', t); const seedCols = seedTables.has(t) ? columnsOf(db, 'seed', t) : [];
    const mainNames = new Set(mainCols.map((c) => c.name)); const seedNames = new Set(seedCols.map((c) => c.name));
    for (const need of RUNTIME_COLUMNS[t] ?? []) {
      if (!seedNames.has(need)) return refuse(`the seed's ${t} table has no ${need} column`);
      if (!mainNames.has(need)) return refuse(`the witness database's ${t} table has no ${need} column (an older schema; refreshing it in place is refused)`);
    }
    if (seedTables.has(t)) {
      for (const c of mainCols) {
        if (c.notnull && c.dflt_value === null && !c.pk && !seedNames.has(c.name)) {
          return refuse(`the witness database's ${t}.${c.name} is required, and the seed has no such column`);
        }
      }
    }
    const cols = mainCols.map((c) => c.name).filter((n) => seedNames.has(n));
    for (const c of seedCols) if (!mainNames.has(c.name)) plan.notCarried.push(`${t}.${c.name}`);
    plan.tables.push({ name: t, columns: cols, fromSeed: seedTables.has(t) });
  }
  const known = new Set([...REQUIRED_SEED_TABLES, ...OPTIONAL_SEED_TABLES, 'gate_decisions', 'overrides']);
  for (const t of [...seedTables].sort()) {
    if (!known.has(t) && !t.startsWith('sqlite_')) plan.notCarried.push(`${t} (${LOCAL_TABLES.includes(t) ? 'a local table' : 'not a seed table this version refreshes'}; not imported)`);
  }
  for (const [t, cols] of [['gate_decisions', DECISION_COLUMNS], ['overrides', OVERRIDE_COLUMNS]]) {
    if (!seedTables.has(t)) continue;
    const have = new Set(columnsOf(db, 'seed', t).map((c) => c.name));
    const missing = cols.filter((c) => !have.has(c));
    if (missing.length) return refuse(`the seed's ${t} table has no ${missing.join(', ')} column(s)`);
    if (!mainTables.has(t)) return refuse(`the witness database has no ${t} table`);
    plan.imports.push(t);
  }
  return plan;
}

/**
 * The in-place refresh: ONE transaction on the witness connection (busy timeout `busyMs`), with the staged seed
 * ATTACHed (never written). Returns `{ committed: true, ... }`; throws LegacyInstallRefused with `committed` set to
 * whether COMMIT had returned. Hooks (tests only): duringRefresh, beforeCommit, afterCommit.
 */
export function refreshLegacyWitness(witnessPath, stagedPath, { hooks = {}, busyMs = BUSY_MS } = {}) {
  let db; let committed = false; let inTx = false; let attached = false;
  const result = { committed: false, imported: { gate_decisions: 0, overrides: 0 }, notCarried: [], replaced: [], warnings: [] };
  try {
    db = new Database(witnessPath, { timeout: busyMs, fileMustExist: true });
    db.pragma('foreign_keys = ON');
    db.prepare('ATTACH DATABASE ? AS seed').run(stagedPath); attached = true;
    const plan = planRefresh(db);
    if (plan.refusal) throw new LegacyInstallRefused(`${plan.refusal}; nothing was changed`, { kind: 'schema' });
    result.notCarried = plan.notCarried;
    try { db.exec('BEGIN IMMEDIATE'); } catch (e) {
      if (String(e.code).startsWith('SQLITE_BUSY')) {
        throw new LegacyInstallRefused('another process is writing to the witness database and did not finish within '
          + `${busyMs / 1000} s; the refresh was refused and nothing was committed`, { kind: 'busy' });
      }
      throw e;
    }
    inTx = true;
    const byName = new Map(plan.tables.map((t) => [t.name, t]));
    for (const t of DELETE_ORDER) if (byName.has(t)) db.exec(`DELETE FROM main.${q(t)}`);
    hooks.duringRefresh?.();
    for (const t of INSERT_ORDER) {
      const e = byName.get(t);
      if (!e || !e.fromSeed) continue;
      const cols = e.columns.map(q).join(', ');
      db.exec(`INSERT INTO main.${q(t)} (${cols}) SELECT ${cols} FROM seed.${q(t)} ORDER BY ${q(ORDER_KEY[t] ?? 'id')}`);
      result.replaced.push(t);
    }
    // The seed's own decisions and overrides, by NATURAL KEY (decision 7 §2.3): only where no local row exists for that
    // (package, version); never by id; in the seed's order. Constraint violations abort the transaction, never skip.
    if (plan.imports.includes('gate_decisions')) {
      const c = DECISION_COLUMNS.map(q).join(', ');
      result.imported.gate_decisions = db.prepare(`INSERT INTO main.gate_decisions (${c})
        SELECT ${DECISION_COLUMNS.map((x) => `s.${q(x)}`).join(', ')} FROM seed.gate_decisions s
        WHERE NOT EXISTS (SELECT 1 FROM main.gate_decisions m WHERE m.package_name = s.package_name AND m.version = s.version)
        ORDER BY s.id`).run().changes;
    }
    if (plan.imports.includes('overrides')) {
      const c = OVERRIDE_COLUMNS.map(q).join(', ');
      result.imported.overrides = db.prepare(`INSERT INTO main.overrides (${c})
        SELECT ${OVERRIDE_COLUMNS.map((x) => `s.${q(x)}`).join(', ')} FROM seed.overrides s
        WHERE NOT EXISTS (SELECT 1 FROM main.overrides m WHERE m.package_name = s.package_name AND m.version = s.version)
        ORDER BY s.id`).run().changes;
    }
    const fk = db.prepare('PRAGMA main.foreign_key_check').all();
    if (fk.length) {
      throw new LegacyInstallRefused(`the refreshed tables would break ${fk.length} relationship(s) `
        + `(first: ${fk[0].table} -> ${fk[0].parent}); nothing was committed`, { kind: 'schema' });
    }
    hooks.beforeCommit?.();
    db.exec('COMMIT');
    committed = true; inTx = false; result.committed = true;
    hooks.afterCommit?.();
  } catch (e) {
    if (inTx) { try { db.exec('ROLLBACK'); } catch { /* the transaction is already gone */ } }
    if (!committed && String(e.code).startsWith('SQLITE_CONSTRAINT_FOREIGNKEY')) {
      e = new LegacyInstallRefused(`the seed's tables break a relationship (${e.message}); nothing was committed`,
        { kind: 'schema' });
    }
    const err = e instanceof LegacyInstallRefused ? e : new LegacyInstallRefused(
      `the refresh failed (${e.code || e.name}: ${e.message}); ${committed ? 'the database WAS refreshed' : 'nothing was committed'}`,
      { committed });
    err.committed = committed;
    if (!committed) { closeQuietly(db, attached); throw err; }
    result.warnings.push(err.message);
  }
  // after the commit: a DETACH or close error is reported as such, never as "nothing committed"
  try { if (attached) db.exec('DETACH DATABASE seed'); } catch (e) { result.warnings.push(`detach after commit: ${e.message}`); }
  try { db.close(); } catch (e) { result.warnings.push(`close after commit: ${e.message}`); }
  return result;
}

function closeQuietly(db, attached) {
  if (!db) return;
  try { if (attached) db.exec('DETACH DATABASE seed'); } catch { /* best effort */ }
  try { db.close(); } catch { /* best effort */ }
}

const LINK_UNSUPPORTED = new Set(['EPERM', 'ENOTSUP', 'EOPNOTSUPP', 'EXDEV', 'ENOSYS', 'EMLINK']);

/**
 * First creation (decision 7 §2.6): a complete, verified, closed copy in the DESTINATION directory, published with
 * link(2) -- which fails if the destination exists. Returns 'created' or 'exists' (someone created it first: the caller
 * takes the existing-database path). An unsupported link refuses; there is no copy fallback.
 */
export function createWitnessFromStaged(paths, staged, { hooks = {}, fsImpl = {} } = {}) {
  const dir = path.dirname(paths.witnessDb);
  const tmp = path.join(dir, `witness.db.staging-${process.pid}`);
  fs.rmSync(tmp, { force: true });
  const src = openRegular(staged.path);
  try {
    if (src.size !== staged.size) throw new LegacyInstallRefused(`the verified seed changed size (${src.size}, not ${staged.size}); nothing was installed`);
    copyFdExact(src.fd, staged.size, tmp, staged.path, hooks);
  } catch (e) { fs.rmSync(tmp, { force: true }); throw e; } finally { fs.closeSync(src.fd); }
  // Once link() has PUBLISHED witness.db, any later failure is reported as such (committed), so the caller keeps the
  // pending marker and the same command completes the installation (owner decision 8, Q3/Q4).
  const afterPublication = (what, e) => new LegacyInstallRefused(`the witness database was created (published), but `
    + `${what} failed (${e.code || e.message}); the installation stays pending: re-run the same command with the same `
    + 'seed to complete it', { committed: true, kind: 'published' });
  let outcome;
  try {
    const out = openRegular(tmp);
    try { if (hashRange(out.fd, 0, staged.size, tmp) !== staged.digest) throw new LegacyInstallRefused('the staging copy does not match the verified digest; nothing was installed'); }
    finally { fs.closeSync(out.fd); }
    hooks.beforeWitnessLink?.();
    try { (fsImpl.linkSync ?? fs.linkSync)(tmp, paths.witnessDb); outcome = 'created'; } catch (e) {
      if (e.code === 'EEXIST') outcome = 'exists';
      else if (LINK_UNSUPPORTED.has(e.code)) {
        throw new LegacyInstallRefused(`this filesystem cannot create the witness database without risking an overwrite `
          + `(link: ${e.code}); nothing was installed`, { kind: 'unsupported' });
      } else throw e;
    }
    if (outcome === 'created') {
      try { fsyncDir(dir); } catch (e) { throw afterPublication('synchronising its directory', e); }
    }
  } catch (e) {
    try { fs.rmSync(tmp, { force: true }); } catch { /* an owned name: a later seed command removes it */ }
    throw e;
  }
  try { fs.rmSync(tmp, { force: true }); } catch (e) {
    if (outcome === 'created') throw afterPublication('removing the staging copy', e);
    // 'exists': this step published nothing; the leftover has an owned name and a later seed command removes it
  }
  return outcome;
}

/**
 * The persisted pair, NEVER mixed (decision 7 §2.4 step 6): the new files are written and fsynced under staging names,
 * then the old .sig, the old .sha256 are removed, the new .sha256 and the new .sig renamed in. At every instant the
 * pair on disk is the old pair, a partial pair (read as absent) or the new pair. Hook: betweenSidecarOps.
 */
export function installSidecars(paths, { sha256Bytes, sigBytes }, { hooks = {} } = {}) {
  const dir = path.dirname(paths.witnessDb);
  const st = { sha: `${paths.witnessDbSha256}.staging-${process.pid}`, sig: `${paths.witnessDbSig}.staging-${process.pid}` };
  for (const [p, bytes] of [[st.sha, sha256Bytes], [st.sig, sigBytes]]) {
    fs.rmSync(p, { force: true });
    const fd = fs.openSync(p, 'wx', 0o600);
    try { fs.writeSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  }
  const step = (fn) => { fn(); hooks.betweenSidecarOps?.(); };
  step(() => fs.rmSync(paths.witnessDbSig, { force: true }));
  step(() => fs.rmSync(paths.witnessDbSha256, { force: true }));
  step(() => fs.renameSync(st.sha, paths.witnessDbSha256));
  fs.renameSync(st.sig, paths.witnessDbSig);
  fsyncDir(dir);
}

/**
 * Install or refresh the legacy witness seed from a VERIFIED staged seed (`staged`: { path, size, digest, sha256Bytes,
 * sigBytes, source }), under the seed-mutation lock. `mode`: 'create-only' (fresh legacy host), 'refresh' (explicit
 * replacement: `init --seed <legacy> --force`, `update-seed`). Returns what it did; throws LegacyInstallRefused.
 */
export function installLegacySeed(paths, staged, { lock, mode, hooks = {}, seam, fsImpl } = {}) {
  assertHeld(lock, path.dirname(paths.witnessDb));
  // policy precondition: the proxy recorded for this base is not running. Safety does not rest on it (the refresh is
  // transactional); it keeps a proxy from evaluating against a seed while it is being replaced.
  const pid = readPidRecord(paths.pidFile);
  if (pid && (pid.state === 'alive' || pid.state === 'indeterminate')) {
    throw new LegacyInstallRefused(`the proxy (pid ${pid.pid}) ${pid.state === 'alive' ? 'is running' : 'may be running'}; `
      + 'stop it first: chaingate stop. Nothing was changed.', { kind: 'proxy-running' });
  }
  const m = readInstallMarker(paths);
  if (m.state === 'invalid' || m.state === 'unreadable') {
    throw new LegacyInstallRefused(`the pending-install marker ${markerPath(paths)} ${m.state === 'invalid' ? 'is not valid'
      : 'cannot be checked'} (${m.why}); nothing was changed. Inspect it; a marker this version cannot read is never `
      + 'guessed around.', { kind: 'marker' });
  }
  const completing = m.state === 'pending';
  if (completing && m.marker.new_sha256 !== staged.digest) {
    throw new LegacyInstallRefused(`an interrupted installation of the legacy seed ${m.marker.new_sha256.slice(0, 16)}... `
      + `(${m.marker.source ?? 'source not recorded'}) is pending; this command would install `
      + `${staged.digest.slice(0, 16)}... instead. Complete it with the same seed. Nothing was changed.`, { kind: 'marker' });
  }
  const exists = fs.existsSync(paths.witnessDb);
  if (exists && mode === 'create-only' && !completing) {
    throw new LegacyInstallRefused('the witness database already exists; nothing was changed', { kind: 'routing' });
  }
  // space: a first creation copies the seed beside witness.db; a refresh writes about the seed's size to the journal
  const adm = admit([{ dir: path.dirname(paths.witnessDb), bytes: BigInt(staged.size) + LEGACY_SIDECARS,
    what: exists ? 'refreshing the witness database (journal, an estimate)' : 'creating the witness database' }], seam);
  if (!adm.ok) throw new LegacyInstallRefused(adm.refusal, { kind: 'space' });

  if (!completing) {
    writeMarker(paths, { schema: MARKER_SCHEMA, kind: 'legacy-seed', new_sha256: staged.digest,
      source: staged.source ?? null, started_at: new Date().toISOString(), pid: process.pid });
  }
  hooks.afterMarker?.();
  const did = { warnings: adm.warnings, completing, created: false, refreshed: null };
  try {
    const route = exists ? 'refresh' : createWitnessFromStaged(paths, staged, { hooks, fsImpl });
    if (route === 'created') did.created = true;
    else {
      hooks.beforeBegin?.();
      did.refreshed = refreshLegacyWitness(paths.witnessDb, staged.path, { hooks });
    }
  } catch (e) {
    const committed = Boolean(e.committed);
    // nothing was committed: a marker THIS run wrote is removed (the host is as it was); a pre-existing one stays
    if (!committed && !completing) { try { removeMarker(paths); } catch { /* left: doctor reports it */ } }
    throw e;
  }
  hooks.afterDatabase?.();
  try { installSidecars(paths, staged, { hooks }); } catch (e) {
    throw new LegacyInstallRefused(`the witness database was ${did.created ? 'created' : 'refreshed'}, but the signature `
      + `files were not installed (${e.code || e.message}); doctor reports the seed signature as unverifiable until this `
      + 'command is re-run', { committed: true, kind: 'sidecars' });
  }
  hooks.beforeMarkerRemoval?.();
  removeMarker(paths);
  return did;
}

/**
 * A downloaded legacy bundle as a staged seed: its digest computed here from the file in the owned directory, and checked
 * against the digest the verified sidecar claims; the sidecars read once, bounded.
 */
export function downloadedSeed(bundle) {
  const { fd, size } = openRegular(bundle.dbPath); fs.closeSync(fd);
  const sha256Bytes = readBounded(bundle.sha256Path, CAPS.sidecar);
  const sigBytes = readBounded(bundle.sigPath, CAPS.sidecar);
  const digest = sha256Regular(bundle.dbPath);
  if (digest !== sha256Bytes.toString('utf8').trim()) {
    throw new LegacyInstallRefused('the downloaded seed no longer matches its verified digest; nothing was changed', { kind: 'verify' });
  }
  return { path: bundle.dbPath, size, digest, sha256Bytes, sigBytes,
    source: bundle.tagName ? `release ${bundle.tagName}` : 'the latest release' };
}

/** seed_metadata.seed_version, read with a plain query (null when the table or row is absent or unreadable). */
export function seedVersionAt(dbPath) {
  let d;
  try { d = new Database(dbPath, { readonly: true, fileMustExist: true }); return d.prepare("SELECT value FROM seed_metadata WHERE key = 'seed_version'").get()?.value ?? null; }
  catch { return null; } finally { try { d?.close(); } catch { /* closed */ } }
}

/** Package and version counts, read with plain queries (zero for a table that is absent). */
export function storeCountsAt(dbPath) {
  let d;
  const count = (t) => { try { return d.prepare(`SELECT COUNT(*) AS n FROM ${q(t)}`).get().n; } catch { return 0; } };
  try { d = new Database(dbPath, { readonly: true, fileMustExist: true }); return { packages: count('packages'), versions: count('versions') }; }
  catch { return { packages: 0, versions: 0 }; } finally { try { d?.close(); } catch { /* closed */ } }
}

/** What an installation did, said once (init and update-seed). */
export function reportLegacyInstall(did, log = console.log) {
  for (const w of did.warnings ?? []) log(fmt.warn(w));
  if (did.completing) log(fmt.ok('Completed the interrupted legacy seed installation'));
  if (did.created) log(fmt.ok('Witness database created from the verified legacy seed'));
  else if (did.refreshed) {
    log(fmt.ok('Witness database refreshed in place; local decisions and overrides were kept'));
    const im = did.refreshed.imported;
    if (im.gate_decisions || im.overrides) {
      log(fmt.dim(`  imported from the seed, for versions with no local row: ${im.gate_decisions} decision(s), `
        + `${im.overrides} override(s)`));
    }
    if (did.refreshed.notCarried.length) log(fmt.dim(`  not carried from the seed: ${did.refreshed.notCarried.join(', ')}`));
    for (const w of did.refreshed.warnings) log(fmt.warn(`  ${w}`));
  }
}
