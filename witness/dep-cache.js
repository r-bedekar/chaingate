// Dependency first-publish cache.
//
// Backs the scope-boundary gate. Stores, for every dep name we've ever
// looked up, the timestamp when that package was first published on npm.
//
// Why this cache exists:
//   scope-boundary needs to know "is this dep itself freshly published?"
//   Answering that means an extra upstream packument fetch per novel dep.
//   We can't do that inside the better-sqlite3 transaction that runs the
//   gates (sync only, can't await). So the gate reads this cache
//   synchronously, and a background worker (proxy/dep-fetcher.js) fills
//   it out-of-band.
//
// Freshness model — deliberately non-standard:
//
//   status='ok'       → first_publish is IMMUTABLE on npm. Cache forever.
//                       No TTL. No re-fetch. Zero stale-data risk.
//   status='vanished' → upstream returned 404. Deleted packages don't
//                       come back. Cache forever.
//   status='error'    → transient (5xx, network). 5-minute negative TTL
//                       so we don't hammer upstream on outages. Short
//                       enough that an hour-long outage doesn't poison
//                       the cache; long enough that we don't retry
//                       every request.
//
// This asymmetry is why the cache is simpler (and safer) than a
// standard web cache: the "ok" path needs no invalidation at all.

const ERROR_TTL_MS = 5 * 60 * 1000; // 5 minutes

function sqlNowFrom(nowMs) {
  // better-sqlite3 stores 'YYYY-MM-DD HH:MM:SS' via datetime('now'). We
  // produce the same format for writes-through-JS so comparisons line up.
  return new Date(nowMs).toISOString().slice(0, 19).replace('T', ' ');
}

function parseSqlTime(s) {
  if (typeof s !== 'string') return null;
  // SQLite datetime('now') returns 'YYYY-MM-DD HH:MM:SS' (UTC).
  const iso = s.length === 19 && s[10] === ' ' ? `${s.slice(0, 10)}T${s.slice(11)}Z` : s;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : null;
}

export class DepCache {
  constructor(db, { now = () => Date.now(), errorTtlMs = ERROR_TTL_MS } = {}) {
    if (!db || !db.db) throw new Error('DepCache: witness db required');
    this.db = db;
    this._now = now;
    this._errorTtlMs = errorTtlMs;
    this._stmts = null;
  }

  _prepare() {
    if (this._stmts) return;
    this._stmts = {
      get: this.db.db.prepare(
        `SELECT package_name, first_publish, status, cached_at, attempts
         FROM dep_first_publish WHERE package_name = ?`,
      ),
      upsert: this.db.db.prepare(
        `INSERT INTO dep_first_publish (package_name, first_publish, status, cached_at, attempts)
         VALUES (@package_name, @first_publish, @status, @cached_at, 1)
         ON CONFLICT(package_name) DO UPDATE SET
           first_publish = excluded.first_publish,
           status        = excluded.status,
           cached_at     = excluded.cached_at,
           attempts      = dep_first_publish.attempts + 1`,
      ),
      delete: this.db.db.prepare(
        `DELETE FROM dep_first_publish WHERE package_name = ?`,
      ),
    };
  }

  /**
   * Synchronous read. Returns one of:
   *   { hit: true,  status: 'ok',       first_publish: <ISO string> }
   *   { hit: true,  status: 'vanished', first_publish: null }
   *   { hit: false }   // cold, or 'error' past its TTL
   */
  lookup(packageName) {
    if (typeof packageName !== 'string' || !packageName) return { hit: false };
    this._prepare();
    const row = this._stmts.get.get(packageName);
    if (!row) return { hit: false };

    if (row.status === 'ok') {
      return { hit: true, status: 'ok', first_publish: row.first_publish };
    }
    if (row.status === 'vanished') {
      return { hit: true, status: 'vanished', first_publish: null };
    }
    // error: honor the negative-cache TTL, otherwise treat as cold.
    const cachedAt = parseSqlTime(row.cached_at);
    if (cachedAt != null && this._now() - cachedAt < this._errorTtlMs) {
      return { hit: true, status: 'error', first_publish: null };
    }
    return { hit: false };
  }

  recordOk(packageName, firstPublishIso) {
    this._prepare();
    this._stmts.upsert.run({
      package_name: packageName,
      first_publish: firstPublishIso,
      status: 'ok',
      cached_at: sqlNowFrom(this._now()),
    });
  }

  recordVanished(packageName) {
    this._prepare();
    this._stmts.upsert.run({
      package_name: packageName,
      first_publish: null,
      status: 'vanished',
      cached_at: sqlNowFrom(this._now()),
    });
  }

  recordError(packageName) {
    this._prepare();
    this._stmts.upsert.run({
      package_name: packageName,
      first_publish: null,
      status: 'error',
      cached_at: sqlNowFrom(this._now()),
    });
  }

  /** Test helper: wipe a single row. Not exposed via witness/db.js API. */
  _purge(packageName) {
    this._prepare();
    this._stmts.delete.run(packageName);
  }
}
