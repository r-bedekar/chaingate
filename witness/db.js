import Database from 'better-sqlite3';

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
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.db.pragma('synchronous = NORMAL');
    this._stmts = null;
  }

  createSchema() {
    this.db.exec(SCHEMA_SQL);
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

  getOverride(packageName, version) {
    this._prepare();
    return this._stmts.getOverride.get(packageName, version) ?? null;
  }

  insertOverride(packageName, version, reason) {
    this._prepare();
    const res = this._stmts.insertOverride.run(packageName, version, reason);
    return res.lastInsertRowid;
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
  const db = new WitnessDB(dbPath, opts);
  db.createSchema();
  return db;
}
