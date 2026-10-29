import Database from 'better-sqlite3';
import { applicableFromRows } from './decision-rule.js';

/**
 * A stored decision row that recorded an exact-version override ALLOW: the runner's synthetic `override` result
 * (gates/index.js). Structural, never inferred from text. Such a row applies only while the override it recorded still
 * exists.
 */
export function isOverrideRow(gatesFired) {
  return Array.isArray(gatesFired) && gatesFired.some((r) => r && r.gate === 'override');
}

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS packages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem    TEXT NOT NULL CHECK (ecosystem = 'npm'),
    package_name TEXT NOT NULL,
    UNIQUE (ecosystem, package_name)
);

CREATE TABLE IF NOT EXISTS versions (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id                  INTEGER NOT NULL REFERENCES packages(id),
    version                     TEXT NOT NULL,
    published_at                TEXT,
    content_hash                TEXT,
    content_hash_algo           TEXT,
    integrity_hash              TEXT,
    git_head                    TEXT,
    package_size_bytes          INTEGER,
    dependency_count            INTEGER,
    dependencies                TEXT,
    dev_dependencies            TEXT,
    peer_dependencies           TEXT,
    optional_dependencies       TEXT,
    bundled_dependencies        TEXT,
    dev_dependency_count        INTEGER,
    peer_dependency_count       INTEGER,
    optional_dependency_count   INTEGER,
    bundled_dependency_count    INTEGER,
    publisher_name              TEXT,
    publisher_email             TEXT,
    publisher_tool              TEXT,
    maintainers                 TEXT,
    publish_method              TEXT,
    provenance_present          INTEGER,
    provenance_details          TEXT,
    has_install_scripts         INTEGER,
    source_repo_url             TEXT,
    license                     TEXT,
    first_observed_at           TEXT DEFAULT (datetime('now')),
    last_seen_at                TEXT,
    UNIQUE (package_id, version)
);

CREATE TABLE IF NOT EXISTS version_files (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id        INTEGER NOT NULL REFERENCES versions(id),
    filename          TEXT NOT NULL,
    packagetype       TEXT,
    content_hash      TEXT,
    content_hash_algo TEXT,
    size_bytes        INTEGER,
    uploaded_at       TEXT,
    url               TEXT,
    first_observed_at TEXT DEFAULT (datetime('now')),
    last_seen_at      TEXT,
    UNIQUE (version_id, filename)
);

CREATE TABLE IF NOT EXISTS gate_decisions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name TEXT NOT NULL,
    version      TEXT NOT NULL,
    disposition  TEXT NOT NULL CHECK (disposition IN ('ALLOW','WARN','BLOCK')),
    gates_fired  TEXT NOT NULL,
    decided_at   TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS overrides (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name TEXT NOT NULL,
    version      TEXT NOT NULL,
    reason       TEXT NOT NULL,
    created_at   TEXT DEFAULT (datetime('now')),
    UNIQUE (package_name, version)
);

CREATE TABLE IF NOT EXISTS seed_metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Out-of-band dep first-publish cache used by the scope-boundary gate.
-- status:      'ok' = first_publish populated; 'vanished' = upstream 404;
--              'error' = transient failure (short TTL so we retry).
-- first_publish is immutable on npm (it's the package's creation
-- timestamp), so 'ok' rows never need refreshing. 'vanished' rows also
-- never need refreshing (deleted packages don't un-delete). Only 'error'
-- rows get a 5-minute negative-cache TTL. See witness/dep-cache.js.
CREATE TABLE IF NOT EXISTS dep_first_publish (
    package_name  TEXT PRIMARY KEY,
    first_publish TEXT,
    status        TEXT NOT NULL CHECK (status IN ('ok','vanished','error')),
    cached_at     TEXT NOT NULL DEFAULT (datetime('now')),
    attempts      INTEGER NOT NULL DEFAULT 1
);

-- Since 0.1.4: the only per-install facts kept on disk -- named warnings served, refusals resting on a
-- fact, and dist-tags moved off a fact-withheld version. Written by the proxy once per install and event; pruned at its
-- start (365 days, at most 100,000 rows). Its statements are prepared LAZILY (namedFactStmts), never in _prepare(): a
-- read-only handle on a database the 0.1.3 code created has no such table, and must still open (it reads as empty).
CREATE TABLE IF NOT EXISTS named_fact_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    at             TEXT NOT NULL,
    kind           TEXT NOT NULL CHECK (kind IN ('named-served','fact-refused','fact-tag-moved')),
    package_name   TEXT NOT NULL,
    version        TEXT NOT NULL,
    classes        TEXT NOT NULL,
    reason         TEXT,
    policy_version TEXT,
    seed_sha256    TEXT,
    install_key    TEXT,
    k_version      TEXT
);
CREATE INDEX IF NOT EXISTS idx_named_fact_events_at ON named_fact_events(at);

-- Since 0.1.4: the user's actions. Live state in acceptances and pins; every action appended to
-- adjudications, which triggers keep append-only. Lazily prepared statements, as for named_fact_events.
CREATE TABLE IF NOT EXISTS acceptances (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name   TEXT NOT NULL,
    version        TEXT NOT NULL,
    named          TEXT NOT NULL,
    decision_id    INTEGER,
    policy_version TEXT,
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (package_name, version)
);
CREATE TABLE IF NOT EXISTS pins (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name TEXT NOT NULL,
    class_key    TEXT NOT NULL,
    k_version    TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (package_name, class_key)
);
CREATE TABLE IF NOT EXISTS adjudications (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    action         TEXT NOT NULL CHECK (action IN ('accept','unaccept','pin','unpin','allow','allow-revoke','why')),
    package_name   TEXT NOT NULL,
    version        TEXT,
    k_version      TEXT,
    classes        TEXT NOT NULL,
    decision_id    INTEGER,
    policy_version TEXT,
    interactive    INTEGER NOT NULL,
    ci             INTEGER NOT NULL
);
CREATE TRIGGER IF NOT EXISTS adjudications_append_only_u BEFORE UPDATE ON adjudications
  BEGIN SELECT RAISE(ABORT, 'adjudications are append-only'); END;
CREATE TRIGGER IF NOT EXISTS adjudications_append_only_d BEFORE DELETE ON adjudications
  BEGIN SELECT RAISE(ABORT, 'adjudications are append-only'); END;

-- Since 0.1.5: the entry facts of each version this proxy served, written once per version on its
-- first download (tarballs are immutable per version): the main and bin targets the registry manifest names, each read (size,
-- sha256, the closed-vocabulary fileFacts summary) or not read (its reason). walk = 'refused' when the archive itself was refused
-- (no files). S7 compares a version with the last one served before it. Retention: the newest 3 served versions per package and at
-- most 200,000 in all (recordEntryFacts).
-- Since 0.1.5: shape = the version's file sizes by class (proxy/shadow-facts.js), written with the entry facts; shadow = its
-- recorded facts (dist-tags, sign transitions, known owner, size change), written once after its first download's rows are final.
-- Record only: no verdict reads them. static_facts = the static-checks-1.6 facts of an armed walk (proxy/static-checks.js
-- staticFactsOf), written once when its rows are recorded. Record only likewise. static_facts_ms = the time that walk's 1.6 work spent (the member windows
-- and tally, the streamed share and staticFactsOf), in milliseconds, written with static_facts. repo_claim = an armed version's
-- repository claim (proxy/shadow-facts.js repoClaimFact: its attestation bundle's repository against its package metadata's), written
-- once after its first download; record only likewise. repo_claim_ms = the time it took, the bundle fetch included, in milliseconds.
-- Since 0.1.6: walk_wait_ms = how long the download that stored the facts waited for a tarball-check walk slot, in milliseconds.
CREATE TABLE IF NOT EXISTS entry_fact_versions (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name          TEXT NOT NULL,
    version               TEXT NOT NULL,
    served_at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    walk                  TEXT NOT NULL CHECK (walk IN ('read','refused')),
    reason                TEXT,
    static_checks_version TEXT NOT NULL,
    facts_ms              REAL,
    shape                 TEXT,
    shadow                TEXT,
    static_facts          TEXT,
    static_facts_ms       REAL,
    repo_claim            TEXT,
    repo_claim_ms         REAL,
    walk_wait_ms          REAL,
    UNIQUE (package_name, version)
);
CREATE TABLE IF NOT EXISTS entry_facts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER NOT NULL REFERENCES entry_fact_versions(id) ON DELETE CASCADE,
    role       TEXT NOT NULL CHECK (role IN ('main','bin')),
    path       TEXT NOT NULL,
    state      TEXT NOT NULL CHECK (state IN ('read','not-read','absent')),
    size_bytes INTEGER,
    sha256     TEXT,
    facts      TEXT,
    reason     TEXT,
    UNIQUE (version_id, role, path)
);
CREATE INDEX IF NOT EXISTS idx_efv_pkg_order ON entry_fact_versions(package_name, id DESC);
CREATE INDEX IF NOT EXISTS idx_ef_version    ON entry_facts(version_id);
-- Since 0.1.6: the advisory pins of the last accepted pins feed cut, read after the seed's own pins. A cut replaces them
-- whole, in one transaction; advisory_id is null for a record with no public advisory (a ChainGate analyst record).
CREATE TABLE IF NOT EXISTS advisory_pins (
    package_name  TEXT NOT NULL,
    version       TEXT NOT NULL,
    record_id     TEXT NOT NULL,
    advisory_id   TEXT,
    source        TEXT NOT NULL,
    evidence_json TEXT,
    added_at      TEXT,
    feed_cut_at   TEXT NOT NULL,
    feed_digest   TEXT NOT NULL,
    PRIMARY KEY (package_name, version, record_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS advisory_pins_feed (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    cut_at      TEXT NOT NULL,
    digest      TEXT NOT NULL,
    rows        INTEGER NOT NULL,
    accepted_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
-- The last fetch of the pins feed: when, what came of it ('accepted', 'same', 'held', 'refused', 'failed') and why; a held cut's
-- digest is what update-advisories --accept-cut names. The kept cut above keeps serving whatever this says.
CREATE TABLE IF NOT EXISTS advisory_pins_fetch (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    attempted_at TEXT NOT NULL,
    outcome      TEXT NOT NULL CHECK (outcome IN ('accepted','same','held','refused','failed')),
    why          TEXT,
    held_digest  TEXT,
    held_cut_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_versions_pkg      ON versions(package_id);
CREATE INDEX IF NOT EXISTS idx_versions_pub_at   ON versions(package_id, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_vfiles_ver        ON version_files(version_id);
CREATE INDEX IF NOT EXISTS idx_decisions_pkg_ver ON gate_decisions(package_name, version);
CREATE INDEX IF NOT EXISTS idx_decisions_at      ON gate_decisions(decided_at DESC);
`;

const VERSION_COLUMNS = [
  'version', 'published_at',
  'content_hash', 'content_hash_algo', 'integrity_hash', 'git_head',
  'package_size_bytes',
  'dependency_count', 'dependencies', 'dev_dependencies', 'peer_dependencies',
  'optional_dependencies', 'bundled_dependencies',
  'dev_dependency_count', 'peer_dependency_count',
  'optional_dependency_count', 'bundled_dependency_count',
  'publisher_name', 'publisher_email', 'publisher_tool', 'maintainers',
  'publish_method', 'provenance_present', 'provenance_details',
  'has_install_scripts', 'source_repo_url', 'license',
];

const JSON_COLUMNS = new Set([
  'dependencies', 'dev_dependencies', 'peer_dependencies',
  'optional_dependencies', 'bundled_dependencies',
  'maintainers', 'provenance_details',
]);

function encodeJson(v) {
  if (v == null) return null;
  if (typeof v === 'string') return v;
  return JSON.stringify(v);
}

/** A copy of `row` with one JSON text field parsed (`fallback` when it does not parse). */
function decodeJsonField(row, field, fallback) {
  let v;
  try { v = JSON.parse(row[field]); } catch { v = fallback; }
  return { ...row, [field]: v };
}

function decodeRow(row) {
  if (!row) return null;
  const out = { ...row };
  for (const col of JSON_COLUMNS) {
    if (out[col] != null) {
      try { out[col] = JSON.parse(out[col]); } catch { /* keep as string */ }
    }
  }
  return out;
}

export class WitnessDB {
  constructor(dbPath, { readonly = false, timeoutMs = 5000 } = {}) {
    this.db = new Database(dbPath, { readonly, timeout: timeoutMs });
    // Pragma writes fail when the underlying file isn't already in the
    // requested mode and the connection is readonly. Skip pragmas in
    // readonly mode — the file's existing settings are what we read.
    if (!readonly) {
      this.db.pragma('journal_mode = WAL');
      this.db.pragma('foreign_keys = ON');
      this.db.pragma('synchronous = NORMAL');
    }
    this.readonly = readonly;
    this._stmts = null;
  }

  applySchema() {
    if (this.readonly) {
      throw new Error(
        'applySchema called on a readonly handle. Open the ' +
        'witness DB in read-write mode (and only at known ' +
        'migration sites) before applying schema.',
      );
    }
    this.db.exec(SCHEMA_SQL);
    // 0.1.5: facts_ms joined entry_fact_versions after the table; a table created before it gains the column
    const efv = this.db.prepare("SELECT name FROM pragma_table_info('entry_fact_versions')").all().map((c) => c.name);
    if (efv.length && !efv.includes('facts_ms')) this.db.exec('ALTER TABLE entry_fact_versions ADD COLUMN facts_ms REAL');
    // 0.1.5: shape, shadow and static_facts likewise
    for (const c of ['shape', 'shadow', 'static_facts']) if (efv.length && !efv.includes(c)) this.db.exec(`ALTER TABLE entry_fact_versions ADD COLUMN ${c} TEXT`);
    if (efv.length && !efv.includes('static_facts_ms')) this.db.exec('ALTER TABLE entry_fact_versions ADD COLUMN static_facts_ms REAL');
    if (efv.length && !efv.includes('repo_claim')) this.db.exec('ALTER TABLE entry_fact_versions ADD COLUMN repo_claim TEXT');
    if (efv.length && !efv.includes('repo_claim_ms')) this.db.exec('ALTER TABLE entry_fact_versions ADD COLUMN repo_claim_ms REAL');
    if (efv.length && !efv.includes('walk_wait_ms')) this.db.exec('ALTER TABLE entry_fact_versions ADD COLUMN walk_wait_ms REAL');   // 0.1.6
    this._prepare();
    return this;
  }

  _prepare() {
    if (this._stmts) return;
    const cols = VERSION_COLUMNS.join(', ');
    const placeholders = VERSION_COLUMNS.map((c) => `@${c}`).join(', ');
    this._stmts = {
      upsertPackage: this.db.prepare(
        `INSERT INTO packages (ecosystem, package_name) VALUES ('npm', @name)
         ON CONFLICT(ecosystem, package_name) DO UPDATE SET package_name = excluded.package_name
         RETURNING id`,
      ),
      getPackageId: this.db.prepare(
        `SELECT id FROM packages WHERE ecosystem = 'npm' AND package_name = ?`,
      ),
      insertVersion: this.db.prepare(
        `INSERT OR IGNORE INTO versions (package_id, ${cols})
         VALUES (@package_id, ${placeholders})
         RETURNING id`,
      ),
      getVersionId: this.db.prepare(
        `SELECT id FROM versions WHERE package_id = ? AND version = ?`,
      ),
      getBaselineByName: this.db.prepare(
        `SELECT v.* FROM versions v
         JOIN packages p ON p.id = v.package_id
         WHERE p.ecosystem = 'npm' AND p.package_name = ? AND v.version = ?`,
      ),
      getFilesByVersionId: this.db.prepare(
        `SELECT filename, packagetype, content_hash, content_hash_algo,
                size_bytes, uploaded_at, url, first_observed_at, last_seen_at
         FROM version_files WHERE version_id = ? ORDER BY filename`,
      ),
      insertFile: this.db.prepare(
        `INSERT OR IGNORE INTO version_files
           (version_id, filename, packagetype, content_hash, content_hash_algo,
            size_bytes, uploaded_at, url)
         VALUES (@version_id, @filename, @packagetype, @content_hash, @content_hash_algo,
                 @size_bytes, @uploaded_at, @url)`,
      ),
      bumpLastSeen: this.db.prepare(
        `UPDATE versions SET last_seen_at = datetime('now')
         WHERE id = ? AND (last_seen_at IS NULL OR last_seen_at < datetime('now'))`,
      ),
      bumpFileLastSeen: this.db.prepare(
        `UPDATE version_files SET last_seen_at = datetime('now')
         WHERE version_id = ? AND (last_seen_at IS NULL OR last_seen_at < datetime('now'))`,
      ),
      insertDecision: this.db.prepare(
        `INSERT INTO gate_decisions (package_name, version, disposition, gates_fired)
         VALUES (?, ?, ?, ?)`,
      ),
      getOverride: this.db.prepare(
        `SELECT package_name, version, reason, created_at
         FROM overrides WHERE package_name = ? AND version = ?`,
      ),
      insertOverride: this.db.prepare(
        `INSERT INTO overrides (package_name, version, reason) VALUES (?, ?, ?)
         ON CONFLICT(package_name, version) DO UPDATE SET
           reason = excluded.reason, created_at = datetime('now')`,
      ),
      listOverrides: this.db.prepare(
        `SELECT package_name, version, reason, created_at FROM overrides ORDER BY created_at DESC`,
      ),
      deleteOverride: this.db.prepare(
        `DELETE FROM overrides WHERE package_name = ? AND version = ?`,
      ),
      decisionStats: this.db.prepare(
        `SELECT disposition, COUNT(*) as count FROM gate_decisions GROUP BY disposition`,
      ),
      decisionTotal: this.db.prepare(`SELECT COUNT(*) as count FROM gate_decisions`),
      recentDecisions: this.db.prepare(
        `SELECT package_name, version, disposition, gates_fired, decided_at
         FROM gate_decisions ORDER BY decided_at DESC, id DESC LIMIT ?`,
      ),
      packageCount: this.db.prepare(`SELECT COUNT(*) as count FROM packages`),
      versionCount: this.db.prepare(`SELECT COUNT(*) as count FROM versions`),
      fileCount: this.db.prepare(`SELECT COUNT(*) as count FROM version_files`),
      getSeedMeta: this.db.prepare(`SELECT value FROM seed_metadata WHERE key = ?`),
      setSeedMeta: this.db.prepare(
        `INSERT INTO seed_metadata (key, value) VALUES (?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
      ),
      historyForPackage: this.db.prepare(
        `SELECT v.* FROM versions v
         JOIN packages p ON p.id = v.package_id
         WHERE p.ecosystem = 'npm' AND p.package_name = ?
         ORDER BY v.published_at DESC NULLS LAST, v.id DESC`,
      ),
      getLatestDecision: this.db.prepare(
        `SELECT id, disposition, gates_fired, decided_at
         FROM gate_decisions
         WHERE package_name = ? AND version = ?
         ORDER BY decided_at DESC, id DESC
         LIMIT 1`,
      ),
      // Same order as getLatestDecision, every row: read lazily (iterate) and stopped at the first match.
      decisionsNewestFirst: this.db.prepare(
        `SELECT id, disposition, gates_fired, decided_at
         FROM gate_decisions
         WHERE package_name = ? AND version = ?
         ORDER BY decided_at DESC, id DESC`,
      ),
      // The same order, oldest first, for the applicable-BLOCK walk.
      decisionsOldestFirst: this.db.prepare(
        `SELECT id, disposition, gates_fired, decided_at
         FROM gate_decisions
         WHERE package_name = ? AND version = ?
         ORDER BY decided_at ASC, id ASC`,
      ),
    };
  }

  _upsertPackageId(packageName) {
    const existing = this._stmts.getPackageId.get(packageName);
    if (existing) return existing.id;
    const row = this._stmts.upsertPackage.get({ name: packageName });
    return row.id;
  }

  getBaseline(packageName, version) {
    this._prepare();
    const row = this._stmts.getBaselineByName.get(packageName, version);
    if (!row) return null;
    const decoded = decodeRow(row);
    decoded.files = this._stmts.getFilesByVersionId.all(row.id);
    return decoded;
  }

  getHistory(packageName) {
    this._prepare();
    return this._stmts.historyForPackage.all(packageName).map(decodeRow);
  }

  recordBaseline(packageName, version, data) {
    this._prepare();
    const write = this.db.transaction((pkg, ver, incoming) => {
      const packageId = this._upsertPackageId(pkg);
      const params = { package_id: packageId, version: ver };
      for (const col of VERSION_COLUMNS) {
        if (col === 'version') continue;
        let v = incoming[col];
        if (JSON_COLUMNS.has(col)) v = encodeJson(v);
        if (typeof v === 'boolean') v = v ? 1 : 0;
        params[col] = v ?? null;
      }
      const inserted = this._stmts.insertVersion.get(params);
      let versionId;
      if (inserted && inserted.id != null) {
        versionId = inserted.id;
      } else {
        versionId = this._stmts.getVersionId.get(packageId, ver).id;
      }
      for (const file of incoming.files ?? []) {
        this._stmts.insertFile.run({
          version_id: versionId,
          filename: file.filename,
          packagetype: file.packagetype ?? 'tarball',
          content_hash: file.content_hash ?? null,
          content_hash_algo: file.content_hash_algo ?? null,
          size_bytes: file.size_bytes ?? null,
          uploaded_at: file.uploaded_at ?? null,
          url: file.url ?? null,
        });
        this._stmts.bumpFileLastSeen.run(versionId);
      }
      this._stmts.bumpLastSeen.run(versionId);
      return versionId;
    });
    return write(packageName, version, data);
  }

  /**
   * Since 0.1.4: the named_fact_events statements, prepared on first use. Null when the table does not exist
   * (a database the 0.1.3 code created, opened read-only): readers treat that as empty.
   */
  _namedFactStmts() {
    if (this._nfStmts !== undefined) return this._nfStmts;
    const exists = this.db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'named_fact_events'").get();
    if (!exists) return null;                 // not cached: applySchema on a read-write handle may create it later
    this._nfStmts = {
      insert: this.db.prepare(
        `INSERT INTO named_fact_events (at, kind, package_name, version, classes, reason, policy_version, seed_sha256,
           install_key, k_version)
         VALUES (@at, @kind, @package_name, @version, @classes, @reason, @policy_version, @seed_sha256, @install_key, @k_version)`,
      ),
      // the NEWEST rows of the window; the caller gets them oldest first
      since: this.db.prepare(
        `SELECT id, at, kind, package_name, version, classes, reason, policy_version, seed_sha256, install_key, k_version
         FROM named_fact_events WHERE at >= ? ORDER BY at DESC, id DESC LIMIT ?`,
      ),
      pruneOlder: this.db.prepare('DELETE FROM named_fact_events WHERE at < ?'),
      pruneBeyond: this.db.prepare(
        `DELETE FROM named_fact_events WHERE id NOT IN
           (SELECT id FROM named_fact_events ORDER BY at DESC, id DESC LIMIT ?)`,
      ),
    };
    return this._nfStmts;
  }

  /**
   * Since 0.1.4: the statements of one lazily used table, prepared on first use; null while the table does not
   * exist (a database the 0.1.3 code created, opened read-only), which readers treat as empty.
   */
  _tableStmts(table, build) {
    this._lazyStmts ??= new Map();
    if (this._lazyStmts.has(table)) return this._lazyStmts.get(table);
    if (!this.db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(table)) return null;
    const st = build();
    this._lazyStmts.set(table, st);
    return st;
  }

  _acceptStmts() {
    return this._tableStmts('acceptances', () => ({
      get: this.db.prepare('SELECT * FROM acceptances WHERE package_name = ? AND version = ?'),
      upsert: this.db.prepare(
        `INSERT INTO acceptances (package_name, version, named, decision_id, policy_version)
         VALUES (@package_name, @version, @named, @decision_id, @policy_version)
         ON CONFLICT(package_name, version) DO UPDATE SET named = excluded.named, decision_id = excluded.decision_id,
           policy_version = excluded.policy_version, created_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`,
      ),
      del: this.db.prepare('DELETE FROM acceptances WHERE package_name = ? AND version = ?'),
      list: this.db.prepare('SELECT * FROM acceptances ORDER BY package_name, version'),
    }));
  }

  _pinStmts() {
    return this._tableStmts('pins', () => ({
      list: this.db.prepare('SELECT package_name, class_key, k_version, created_at FROM pins ORDER BY package_name, class_key'),
      upsert: this.db.prepare(
        `INSERT INTO pins (package_name, class_key, k_version) VALUES (@package_name, @class_key, @k_version)
         ON CONFLICT(package_name, class_key) DO UPDATE SET k_version = excluded.k_version,
           created_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`,
      ),
      delAll: this.db.prepare('DELETE FROM pins WHERE package_name = ?'),
      delOne: this.db.prepare('DELETE FROM pins WHERE package_name = ? AND class_key = ?'),
    }));
  }

  _adjStmts() {
    return this._tableStmts('adjudications', () => ({
      append: this.db.prepare(
        `INSERT INTO adjudications (action, package_name, version, k_version, classes, decision_id, policy_version, interactive, ci)
         VALUES (@action, @package_name, @version, @k_version, @classes, @decision_id, @policy_version, @interactive, @ci)`,
      ),
      list: this.db.prepare('SELECT * FROM adjudications ORDER BY id'),
    }));
  }

  getAcceptance(packageName, version) {
    const st = this._acceptStmts();
    const row = st ? st.get.get(packageName, version) : null;
    return row ? decodeJsonField(row, 'named', []) : null;
  }

  upsertAcceptance(a) {
    const st = this._acceptStmts();
    if (!st) throw new Error('the acceptances table does not exist (applySchema was not run on this handle)');
    return st.upsert.run({ package_name: a.package_name, version: a.version, named: JSON.stringify(a.named ?? []),
      decision_id: a.decision_id ?? null, policy_version: a.policy_version ?? null }).changes;
  }

  _entryFactStmts() {
    if (!this._tableStmts('entry_facts', () => ({}))) return null;
    return this._tableStmts('entry_fact_versions', () => ({
      has: this.db.prepare('SELECT 1 FROM entry_fact_versions WHERE package_name = ? AND version = ?'),
      insV: this.db.prepare(`INSERT OR IGNORE INTO entry_fact_versions (package_name, version, walk, reason, static_checks_version, facts_ms, shape,
        walk_wait_ms) VALUES (@package_name, @version, @walk, @reason, @static_checks_version, @facts_ms, @shape, @walk_wait_ms)`),
      shadowSet: this.db.prepare('UPDATE entry_fact_versions SET shadow = @shadow WHERE package_name = @p AND version = @v AND shadow IS NULL'),
      staticSet: this.db.prepare('UPDATE entry_fact_versions SET static_facts = @x, static_facts_ms = @ms WHERE package_name = @p AND version = @v AND static_facts IS NULL'),
      claimSet: this.db.prepare('UPDATE entry_fact_versions SET repo_claim = @x, repo_claim_ms = @ms WHERE package_name = @p AND version = @v AND repo_claim IS NULL'),
      insF: this.db.prepare(`INSERT OR IGNORE INTO entry_facts (version_id, role, path, state, size_bytes, sha256, facts, reason)
        VALUES (@version_id, @role, @path, @state, @size_bytes, @sha256, @facts, @reason)`),
      prev: this.db.prepare(`SELECT * FROM entry_fact_versions WHERE package_name = @p AND version <> @v AND id <
        COALESCE((SELECT id FROM entry_fact_versions WHERE package_name = @p AND version = @v), 9223372036854775807) ORDER BY id DESC LIMIT 1`),
      files: this.db.prepare('SELECT role, path, state, size_bytes, sha256, facts, reason FROM entry_facts WHERE version_id = ? ORDER BY id'),
      prunePkg: this.db.prepare(`DELETE FROM entry_fact_versions WHERE package_name = @package_name AND id NOT IN
        (SELECT id FROM entry_fact_versions WHERE package_name = @package_name ORDER BY id DESC LIMIT @keep)`),
      count: this.db.prepare('SELECT COUNT(*) AS c FROM entry_fact_versions'),
      pruneAll: this.db.prepare(`DELETE FROM entry_fact_versions WHERE id IN (SELECT id FROM entry_fact_versions ORDER BY id LIMIT ?)`),
    }));
  }

  /** 0.1.5: whether the entry facts of this version are stored (false on a database without the tables). */
  hasEntryFacts(packageName, version) {
    const st = this._entryFactStmts();
    return Boolean(st && st.has.get(packageName, version));
  }

  /**
   * 0.1.5: store one served version's entry facts, once: 'wrote', or 'exists' (nothing changed). Serving order is the row id
   * (first download). Prunes to the newest `keepPerPackage` versions of the package and `maxVersions` in all, oldest served first.
   */
  recordEntryFacts(r, { keepPerPackage = 3, maxVersions = 200_000 } = {}) {
    const st = this._entryFactStmts();
    if (!st) throw new Error('the entry facts tables do not exist (applySchema was not run on this handle)');
    return this.db.transaction(() => {
      const ins = st.insV.run({ package_name: r.package_name, version: r.version, walk: r.walk, reason: r.reason ?? null,
        static_checks_version: r.static_checks_version, facts_ms: Number.isFinite(r.facts_ms) ? r.facts_ms : null,
        shape: r.shape == null ? null : JSON.stringify(r.shape), walk_wait_ms: Number.isFinite(r.walk_wait_ms) ? r.walk_wait_ms : null });
      if (!ins.changes) return 'exists';
      const versionId = Number(ins.lastInsertRowid);
      for (const f of Array.isArray(r.files) ? r.files : []) {
        st.insF.run({ version_id: versionId, role: f.role, path: f.path, state: f.state, size_bytes: f.size_bytes ?? null,
          sha256: f.sha256 ?? null, facts: f.facts == null ? null : JSON.stringify(f.facts), reason: f.reason ?? null });
      }
      st.prunePkg.run({ package_name: r.package_name, keep: keepPerPackage });
      const over = st.count.get().c - maxVersions;
      if (over > 0) st.pruneAll.run(over);
      return 'wrote';
    })();
  }

  /**
   * 0.1.5: the last version of the package this proxy served BEFORE `version` (before its first download when it is stored,
   * else the last one served), with its files; null on a cold start.
   */
  predecessorEntryFacts(packageName, version) {
    const st = this._entryFactStmts();
    const v = st ? st.prev.get({ p: packageName, v: version }) : null;
    if (!v) return null;
    const files = st.files.all(v.id).map((f) => decodeJsonField(f, 'facts', null));
    return { version: v.version, served_at: v.served_at, walk: v.walk, reason: v.reason, static_checks_version: v.static_checks_version, facts_ms: v.facts_ms ?? null,
      shape: decodeJsonField(v, 'shape', null).shape ?? null, files };
  }

  /** 0.1.5: store a served version's shadow facts, once; 1 when written, 0 when already stored or no entry facts row exists. */
  recordShadowFacts(packageName, version, facts) {
    const st = this._entryFactStmts();
    if (!st) throw new Error('the entry facts tables do not exist (applySchema was not run on this handle)');
    return st.shadowSet.run({ p: packageName, v: version, shadow: JSON.stringify(facts) }).changes;
  }

  /** 0.1.5: a version's stored shadow facts, or null (none, a database without the column, or not readable). Never throws. */
  shadowFactsFor(packageName, version) {
    try {
      const r = this.db.prepare('SELECT shadow FROM entry_fact_versions WHERE package_name = ? AND version = ?').get(packageName, version);
      return r && typeof r.shadow === 'string' ? JSON.parse(r.shadow) : null;
    } catch { return null; }
  }

  /** 0.1.5: store a version's static-checks-1.6 facts ({ facts, s5 }) and the time they took (ms, or NULL), once; 1 when written,
   *  0 when already stored or no entry facts row exists. */
  recordStaticFacts(packageName, version, x, ms = null) {
    const st = this._entryFactStmts();
    if (!st) throw new Error('the entry facts tables do not exist (applySchema was not run on this handle)');
    return st.staticSet.run({ p: packageName, v: version, x: JSON.stringify(x), ms: Number.isFinite(ms) ? ms : null }).changes;
  }

  /** 0.1.5: a version's stored static-checks-1.6 facts, or null (none, a database without the column, or not readable). Never throws. */
  staticFactsFor(packageName, version) {
    try {
      const r = this.db.prepare('SELECT static_facts FROM entry_fact_versions WHERE package_name = ? AND version = ?').get(packageName, version);
      return r && typeof r.static_facts === 'string' ? JSON.parse(r.static_facts) : null;
    } catch { return null; }
  }

  /** 0.1.5: store an armed version's repository claim and the time it took (ms, or NULL), once; 1 when written, 0 when already
   *  stored or no entry facts row exists. */
  recordRepoClaim(packageName, version, x, ms = null) {
    const st = this._entryFactStmts();
    if (!st) throw new Error('the entry facts tables do not exist (applySchema was not run on this handle)');
    return st.claimSet.run({ p: packageName, v: version, x: JSON.stringify(x), ms: Number.isFinite(ms) ? ms : null }).changes;
  }

  /** 0.1.5: a version's stored repository claim, or null (none, a database without the column, or not readable). Never throws. */
  repoClaimFor(packageName, version) {
    try {
      const r = this.db.prepare('SELECT repo_claim FROM entry_fact_versions WHERE package_name = ? AND version = ?').get(packageName, version);
      return r && typeof r.repo_claim === 'string' ? JSON.parse(r.repo_claim) : null;
    } catch { return null; }
  }

  deleteAcceptance(packageName, version) {
    const st = this._acceptStmts();
    return st ? st.del.run(packageName, version).changes : 0;
  }

  listAcceptances() {
    const st = this._acceptStmts();
    return st ? st.list.all().map((r) => decodeJsonField(r, 'named', [])) : [];
  }

  _advisoryPinStmts() {
    return this._tableStmts('advisory_pins', () => ({
      get: this.db.prepare('SELECT package_name, version, record_id, advisory_id, source, evidence_json, added_at, feed_cut_at '
        + 'FROM advisory_pins WHERE package_name = ? AND version = ? ORDER BY advisory_id IS NULL, advisory_id, record_id LIMIT 1'),
      clear: this.db.prepare('DELETE FROM advisory_pins'),
      pairs: this.db.prepare('SELECT DISTINCT package_name, version FROM advisory_pins'),
      insert: this.db.prepare('INSERT INTO advisory_pins (package_name, version, record_id, advisory_id, source, evidence_json, added_at, '
        + 'feed_cut_at, feed_digest) VALUES (@package_name, @version, @record_id, @advisory_id, @source, @evidence_json, @added_at, '
        + '@feed_cut_at, @feed_digest)'),
      feed: this.db.prepare('SELECT cut_at, digest, rows, accepted_at FROM advisory_pins_feed WHERE id = 1'),
      setFeed: this.db.prepare(`INSERT INTO advisory_pins_feed (id, cut_at, digest, rows) VALUES (1, @cut_at, @digest, @rows)
        ON CONFLICT(id) DO UPDATE SET cut_at = excluded.cut_at, digest = excluded.digest, rows = excluded.rows,
          accepted_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`),
    }));
  }

  _advisoryPinFetchStmts() {
    return this._tableStmts('advisory_pins_fetch', () => ({
      get: this.db.prepare('SELECT attempted_at, outcome, why, held_digest, held_cut_at FROM advisory_pins_fetch WHERE id = 1'),
      set: this.db.prepare(`INSERT INTO advisory_pins_fetch (id, attempted_at, outcome, why, held_digest, held_cut_at)
        VALUES (1, @attempted_at, @outcome, @why, @held_digest, @held_cut_at)
        ON CONFLICT(id) DO UPDATE SET attempted_at = excluded.attempted_at, outcome = excluded.outcome, why = excluded.why,
          held_digest = excluded.held_digest, held_cut_at = excluded.held_cut_at`),
    }));
  }

  /** Since 0.1.6: the last pins feed fetch ({ attempted_at, outcome, why, held_digest, held_cut_at }), or null before the first. */
  advisoryPinsFetch() {
    const st = this._advisoryPinFetchStmts();
    return st ? (st.get.get() ?? null) : null;
  }

  /** Since 0.1.6: record the outcome of one pins feed fetch. */
  recordAdvisoryPinsFetch({ attemptedAt, outcome, why = null, heldDigest = null, heldCutAt = null }) {
    const st = this._advisoryPinFetchStmts();
    if (!st) throw new Error('advisory_pins_fetch is not in this witness database (open it read-write once to apply the schema)');
    st.set.run({ attempted_at: attemptedAt, outcome, why: why === null ? null : String(why).slice(0, 2000), held_digest: heldDigest,
      held_cut_at: heldCutAt });
  }

  /** Since 0.1.6: the versions this store recorded a BLOCK for since an ISO time, as a Set of "name@version". */
  blockedVersionsSince(sinceIso) {
    return new Set(this.db.prepare("SELECT DISTINCT package_name, version FROM gate_decisions WHERE disposition = 'BLOCK' "
      + 'AND datetime(decided_at) >= datetime(?)').all(sinceIso).map((r) => `${r.package_name}@${r.version}`));
  }

  /** Since 0.1.6: the (name, version) pairs of the kept cut, as "name@version". */
  advisoryPinPairs() {
    const st = this._advisoryPinStmts();
    return new Set(st ? st.pairs.all().map((r) => `${r.package_name}@${r.version}`) : []);
  }

  /** Since 0.1.6: the overlay pin for an exact version (an advisory id first), or null; null when the table does not exist. */
  advisoryPinFor(packageName, version) {
    const st = this._advisoryPinStmts();
    return st ? (st.get.get(packageName, version) ?? null) : null;
  }

  /** Since 0.1.6: the accepted pins feed cut ({ cut_at, digest, rows, accepted_at }), or null before the first. */
  advisoryPinsFeed() {
    const st = this._advisoryPinStmts();
    return st ? (st.feed.get() ?? null) : null;
  }

  /**
   * Since 0.1.6: replace the overlay with one accepted cut, whole, in ONE transaction: a failure part way leaves the previous cut
   * as it was. rows: [{ package_name, version, record_id, advisory_id, source, evidence_json, added_at }]. With `expectDigest`
   * (a digest, or null for "no cut yet") the replace happens only while the kept cut is still that one; returns whether it did.
   */
  replaceAdvisoryPins({ cutAt, digest, rows, expectDigest }) {
    const st = this._advisoryPinStmts();
    if (!st) throw new Error('advisory_pins is not in this witness database (open it read-write once to apply the schema)');
    return this.db.transaction(() => {
      if (expectDigest !== undefined && (st.feed.get()?.digest ?? null) !== expectDigest) return false;
      st.clear.run();
      for (const r of rows) {
        st.insert.run({ package_name: r.package_name, version: r.version, record_id: r.record_id, advisory_id: r.advisory_id ?? null,
          source: r.source, evidence_json: r.evidence_json ?? null, added_at: r.added_at ?? null, feed_cut_at: cutAt, feed_digest: digest });
      }
      st.setFeed.run({ cut_at: cutAt, digest, rows: rows.length });
      return true;
    })();
  }

  listPins() {
    const st = this._pinStmts();
    return st ? st.list.all() : [];
  }

  upsertPin(p) {
    const st = this._pinStmts();
    if (!st) throw new Error('the pins table does not exist (applySchema was not run on this handle)');
    return st.upsert.run({ package_name: p.package_name, class_key: p.class_key, k_version: p.k_version }).changes;
  }

  /** Delete a package's pins: every class, or the one named. Returns the number deleted. */
  deletePins(packageName, classKey = null) {
    const st = this._pinStmts();
    if (!st) return 0;
    return (classKey == null ? st.delAll.run(packageName) : st.delOne.run(packageName, classKey)).changes;
  }

  appendAdjudication(a) {
    const st = this._adjStmts();
    if (!st) throw new Error('the adjudications table does not exist (applySchema was not run on this handle)');
    return st.append.run({ action: a.action, package_name: a.package_name, version: a.version ?? null, k_version: a.k_version ?? null,
      classes: JSON.stringify(a.classes ?? {}), decision_id: a.decision_id ?? null, policy_version: a.policy_version ?? null,
      interactive: a.interactive ? 1 : 0, ci: a.ci ? 1 : 0 }).lastInsertRowid;
  }

  listAdjudications() {
    const st = this._adjStmts();
    return st ? st.list.all().map((r) => decodeJsonField(r, 'classes', {})) : [];
  }

  /** PRAGMA data_version: changes when ANOTHER connection commits (the pin set's change check). */
  dataVersion() {
    return this.db.pragma('data_version', { simple: true });
  }

  insertNamedFactEvent(e) {
    const st = this._namedFactStmts();
    if (!st) throw new Error('the named_fact_events table does not exist (applySchema was not run on this handle)');
    return st.insert.run({ at: e.at, kind: e.kind, package_name: e.package_name, version: e.version,
      classes: JSON.stringify(e.classes ?? {}), reason: e.reason ?? null, policy_version: e.policy_version ?? null,
      seed_sha256: e.seed_sha256 ?? null, install_key: e.install_key ?? null, k_version: e.k_version ?? null }).lastInsertRowid;
  }

  /**
   * The newest `limit` rows at or after `sinceIso` (ISO 8601; default: all), returned oldest first. A missing table reads
   * as empty.
   */
  listNamedFactEvents({ sinceIso = '', limit = 10_000 } = {}) {
    const st = this._namedFactStmts();
    if (!st) return [];
    return st.since.all(sinceIso, limit).reverse().map((r) => {
      let classes;
      try { classes = JSON.parse(r.classes); } catch { classes = {}; }
      return { ...r, classes };
    });
  }

  pruneNamedFactEvents({ maxAgeDays = 365, maxRows = 100_000, now = Date.now() } = {}) {
    const st = this._namedFactStmts();
    if (!st) return 0;
    const cutoff = new Date(now - maxAgeDays * 86_400_000).toISOString();
    return st.pruneOlder.run(cutoff).changes + st.pruneBeyond.run(maxRows).changes;
  }

  insertGateDecision(packageName, version, disposition, gatesFired) {
    this._prepare();
    const payload = JSON.stringify(gatesFired ?? []);
    const res = this._stmts.insertDecision.run(packageName, version, disposition, payload);
    return res.lastInsertRowid;
  }

  getLatestDecision(packageName, version) {
    this._prepare();
    const row = this._stmts.getLatestDecision.get(packageName, version);
    if (!row) return null;
    let parsed;
    try { parsed = JSON.parse(row.gates_fired); } catch { parsed = []; }
    return {
      id: row.id,
      disposition: row.disposition,
      gates_fired: parsed,
      decided_at: row.decided_at,
    };
  }

  /**
   * The newest decision for (pkg, version) that is NOT a stored override ALLOW: the decision
   * that applies once the override it recorded no longer exists. A row whose gates_fired does not parse is not an
   * override row; it is returned and read by its disposition, as getLatestDecision's callers read it. Read-only.
   */
  getLatestNonOverrideDecision(packageName, version) {
    this._prepare();
    for (const row of this._stmts.decisionsNewestFirst.iterate(packageName, version)) {
      let parsed;
      try { parsed = JSON.parse(row.gates_fired); } catch { parsed = []; }
      if (isOverrideRow(parsed)) continue;
      return { id: row.id, disposition: row.disposition, gates_fired: parsed, decided_at: row.decided_at };
    }
    return null;
  }

  /**
   * Every stored decision for (pkg, version), oldest first, with gates_fired parsed (a row whose gates_fired does not
   * parse keeps the raw text, which the applicable-BLOCK rule reads as unclassified). Read-only.
   */
  getDecisionHistory(packageName, version) {
    this._prepare();
    return this._stmts.decisionsOldestFirst.all(packageName, version).map((row) => {
      let parsed;
      try { parsed = JSON.parse(row.gates_fired); } catch { parsed = row.gates_fired; }
      return { id: row.id, disposition: row.disposition, gates_fired: parsed, decided_at: row.decided_at };
    });
  }

  /**
   * The decision that APPLIES to (pkg, version) under the one applicable-BLOCK rule
   * (witness/decision-rule.js). `overrideLive` defaults to whether an exact override exists now. Read errors propagate:
   * a caller that cannot read the history has no decision. Read-only.
   */
  getApplicableDecision(packageName, version, { overrideLive } = {}) {
    const live = overrideLive === undefined ? Boolean(this.getOverride(packageName, version)) : Boolean(overrideLive);
    return applicableFromRows(this.getDecisionHistory(packageName, version), { overrideLive: live });
  }

  getOverride(packageName, version) {
    this._prepare();
    return this._stmts.getOverride.get(packageName, version) ?? null;
  }

  insertOverride(packageName, version, reason) {
    this._prepare();
    const res = this._stmts.insertOverride.run(packageName, version, reason);
    return res.lastInsertRowid;
  }

  listOverrides() {
    this._prepare();
    return this._stmts.listOverrides.all();
  }

  deleteOverride(packageName, version) {
    this._prepare();
    const res = this._stmts.deleteOverride.run(packageName, version);
    return res.changes > 0;
  }

  getDecisionStats() {
    this._prepare();
    const rows = this._stmts.decisionStats.all();
    const stats = { ALLOW: 0, WARN: 0, BLOCK: 0 };
    for (const r of rows) stats[r.disposition] = r.count;
    stats.total = this._stmts.decisionTotal.get().count;
    return stats;
  }

  getRecentDecisions(limit = 5) {
    this._prepare();
    return this._stmts.recentDecisions.all(limit).map((row) => {
      let parsed;
      try { parsed = JSON.parse(row.gates_fired); } catch { parsed = []; }
      return { ...row, gates_fired: parsed };
    });
  }

  getStoreCounts() {
    this._prepare();
    return {
      packages: this._stmts.packageCount.get().count,
      versions: this._stmts.versionCount.get().count,
      files: this._stmts.fileCount.get().count,
    };
  }

  getSeedMetadata(key) {
    this._prepare();
    const row = this._stmts.getSeedMeta.get(key);
    return row ? row.value : null;
  }

  setSeedMetadata(key, value) {
    this._prepare();
    this._stmts.setSeedMeta.run(key, String(value));
  }

  close() {
    this.db.close();
  }
}

export function openWitnessDB(dbPath, opts) {
  return new WitnessDB(dbPath, opts);
}
