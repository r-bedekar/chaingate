// Since 0.1.6: fetching seed shards (a contract 1.3 seed as buckets of packages under a signed root) into a seed cache.
//
// The host serves root.json.gz, root.json.sig, keys.json and keys.json.sig (the key list the seed key signs, the advisory
// feed's own, copied unchanged) at fixed paths, and each bucket at buckets/<5-digit bucket>/<its gz sha256>.gz, the name the root
// gives it (a bucket the host does not have, a 404, means the root moved on: the root is fetched again and the bucket asked for
// once more under it; still missing, its packages are uncovered). Each request is a plain GET with no identifiers and no
// registry token, over https, with no redirect, 10 seconds at most. root.json.gz is asked for with the ETag of the last one, so a
// refresh with no new cut costs one 304. A root is accepted at the reader's clock, never at its own cut time; a bucket download
// stops at the size the root names. Verifying and importing are seed/v3/shards.js; this module only fetches and records.
import { createPublicKey } from 'node:crypto';
import fs from 'node:fs';
import { dirname, join } from 'node:path';
import Database from 'better-sqlite3';
import { CHAINGATE_SEED_PUBKEY_B64 } from '../witness/seed_verify.js';
import { PINS_LIMITS } from '../witness/pins-feed.js';
import * as SH from '../seed/v3/shards.js';
import { readConfigStrict, writeConfig } from '../config-store.js';

export const SHARDS_FETCH_TIMEOUT_MS = 10_000;
const BUCKET_FETCHES_AT_ONCE = 8;
const SEED_KEY = createPublicKey({ key: Buffer.from(CHAINGATE_SEED_PUBKEY_B64, 'base64'), format: 'der', type: 'spki' });

class TooLarge extends Error {}
/** A host answer other than 200 (or an expected 304); `status` is the HTTP status. */
class HttpStatus extends Error { constructor(message, status) { super(message); this.status = status; } }
const capOf = (path) => (path.startsWith('keys.json') ? PINS_LIMITS.manifestBytes : path === 'root.json.sig' ? 64 : SH.SHARD_LIMITS.rootBytes);
/** Where bucket `i` is served: by the gz sha256 its root names, so a bucket's address changes whenever its bytes do. */
export const bucketPath = (i, gzSha256) => `buckets/${String(i).padStart(5, '0')}/${gzSha256}.gz`;

/**
 * An https base URL as a source: get(path, { cap, etag }) resolves to { status: 200, bytes, etag } or, when `etag` is given and
 * the host answers 304, { status: 304 }. `fetchImpl` is for tests; a local http host is accepted for them.
 */
export function shardSource(base, { fetchImpl = fetch, timeoutMs = SHARDS_FETCH_TIMEOUT_MS } = {}) {
  const u = new URL(base.endsWith('/') ? base : `${base}/`);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(u.hostname))) {
    throw new SH.ShardRefused('the seed shards URL must be https');
  }
  return async (path, { cap = capOf(path), etag = null } = {}) => {
    const res = await fetchImpl(new URL(path, u), { redirect: 'error', headers: etag ? { 'if-none-match': etag } : {},
      signal: AbortSignal.timeout(timeoutMs) });
    if (res.status === 304 && etag) { await res.body?.cancel?.(); return { status: 304 }; }
    if (res.status !== 200) { await res.body?.cancel?.(); throw new HttpStatus(`${path}: HTTP ${res.status}`, res.status); }
    const parts = []; let n = 0;
    for await (const c of res.body) {
      n += c.length;
      if (n > cap) throw new TooLarge(`${path}: longer than ${cap} bytes`);   // leaving the loop cancels the body
      parts.push(Buffer.from(c));
    }
    return { status: 200, bytes: Buffer.concat(parts), etag: res.headers.get('etag') };
  };
}

function readCache(cachePath, fn) {
  if (!fs.existsSync(cachePath)) return fn(null);
  const db = new Database(cachePath, { readonly: true, fileMustExist: true });
  try { return fn(db); } finally { db.close(); }
}
const tableOf = (db, name) => Boolean(db?.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name));
const heldOf = (db) => new Set(tableOf(db, 'shard_buckets') ? db.prepare('SELECT i FROM shard_buckets').pluck().all() : []);

/**
 * Fetch the root and make it the cache's current one. Resolves to { outcome: 'accepted' | 'same', cut_at, held, dropped }, where
 * `dropped` lists the buckets the cache held whose rows the new root no longer lists (their packages are uncovered until fetched
 * again). Rejects on anything else, recording the outcome in a cache that exists; the cache's current root keeps serving.
 * `feedKeys` is the advisory feed's keys.json when known: the copy beside the root must equal it.
 */
export async function refreshRoot({ get, cachePath, seedKey = SEED_KEY, now = Date.now(), bits = SH.BUCKET_BITS, feedKeys = null }) {
  const { etag, held } = readCache(cachePath, (db) => ({
    etag: tableOf(db, 'shard_root') && db.prepare('SELECT 1 FROM shard_root WHERE id = 1').get() ? (SH.readFetch(db)?.root_etag ?? null) : null,
    held: heldOf(db),
  }));
  const record = (o) => { if (fs.existsSync(cachePath)) SH.recordFetch(cachePath, o); };
  try {
    const g = await get('root.json.gz', { etag });
    if (g.status === 304) {
      record({ outcome: 'same' });
      return { outcome: 'same', cut_at: readCache(cachePath, (db) => db.prepare('SELECT cut_at FROM shard_root WHERE id = 1').pluck().get()),
        held: held.size, dropped: [] };
    }
    const rootBytes = SH.gunzipRoot(g.bytes);
    const sig = (await get('root.json.sig')).bytes;
    const keysBytes = (await get('keys.json')).bytes;
    const keysSig = (await get('keys.json.sig')).bytes;
    if (feedKeys && !Buffer.from(feedKeys).equals(keysBytes)) throw new SH.ShardRefused('the key list beside the root differs from the advisory feed\'s');
    const root = SH.verifyRoot({ rootBytes, sig, keysBytes, keysSig, seedKey, now, bits });
    const same = readCache(cachePath, (db) => tableOf(db, 'shard_root') && db.prepare('SELECT digest FROM shard_root WHERE id = 1').pluck().get() === root.digest);
    SH.setRoot(cachePath, root);
    const after = readCache(cachePath, heldOf);
    SH.recordFetch(cachePath, { outcome: same ? 'same' : 'accepted', etag: g.etag, accepted: !same });
    return { outcome: same ? 'same' : 'accepted', cut_at: root.cut_at, held: after.size, dropped: [...held].filter((i) => !after.has(i)) };
  } catch (e) {
    record({ outcome: e instanceof SH.ShardRefused ? 'refused' : 'failed', why: String(e?.why ?? e?.message ?? e).slice(0, 300) });
    throw e;
  }
}

/** The buckets of these package names that the cache does not hold, sorted. */
export function bucketsFor(cachePath, names, { bits = SH.BUCKET_BITS } = {}) {
  const held = readCache(cachePath, heldOf);
  return [...new Set(names.map((n) => SH.bucketOf(n, bits)))].filter((i) => !held.has(i)).sort((a, b) => a - b);
}

/**
 * Fetch, verify and import these buckets under the cache's current root, a few at a time: `root` when the caller holds it
 * verified (the proxy's open seed cache), else checked again from the cache. Resolves to { imported, failed: [{ i, why }] }: a
 * bucket that fails is left out whole and the others are imported; importing refuses a root that is not the cache's. With
 * `refresh`, a bucket the host answers 404 for is asked for once more after one root refresh for the whole call.
 */
export async function fetchBuckets({ get, cachePath, buckets, seedKey = SEED_KEY, bits = SH.BUCKET_BITS, root: held = null, refresh = null }) {
  const cacheRoot = () => readCache(cachePath, (db) => {
    if (!db) throw new SH.ShardRefused('the seed cache has no root yet');
    return SH.checkCache(db, { seedKey, bits }).root;
  });
  let root = held ?? cacheRoot();
  const imported = []; const failed = [];
  const pass = async (list, { last }) => {
    const missing = []; const queue = [...list];
    const one = async () => {
      for (let i = queue.shift(); i !== undefined; i = queue.shift()) {
        const e = root.buckets[i];
        try {
          if (!e) throw new SH.ShardRefused(`bucket ${i} is not listed in the root`);
          let got;
          try { got = await get(bucketPath(i, e.gz_sha256), { cap: e.gz_bytes }); } catch (err) {
            if (err instanceof TooLarge) throw new SH.ShardRefused(`bucket ${i}: longer than its gz_bytes (${e.gz_bytes})`);
            if (err instanceof HttpStatus && err.status === 404 && !last) { missing.push(i); continue; }
            throw err;
          }
          SH.importBucket(cachePath, root, i, SH.verifyBucketBytes(root, i, got.bytes));
          imported.push(i);
        } catch (err) { failed.push({ i, why: String(err?.why ?? err?.message ?? err).slice(0, 300) }); }
      }
    };
    await Promise.all(Array.from({ length: Math.min(BUCKET_FETCHES_AT_ONCE, list.length) }, one));
    return missing;
  };
  // a 404 means the root moved on: refresh it once for the whole call (`refresh` resolves to the new root, or null to read it
  // from the cache), then ask for each missing bucket once more under it
  const missing = await pass(buckets, { last: !refresh });
  if (missing.length) {
    try { root = (await refresh()) ?? cacheRoot(); } catch { /* the root held stays */ }
    await pass(missing, { last: true });
  }
  const byI = (a, b) => (a.i ?? a) - (b.i ?? b);
  return { imported: imported.sort(byI), failed: failed.sort(byI) };
}

const LOCKFILE_MAX_BYTES = 64 * 1024 * 1024;

/**
 * The package names a project's lockfile lists (npm-shrinkwrap.json, else package-lock.json; lockfile versions 1 to 3), sorted
 * and unique; [] when there is none or it cannot be read. Only names are taken, to know which buckets to fetch.
 */
export function lockfileNames(dir) {
  for (const f of ['npm-shrinkwrap.json', 'package-lock.json']) {
    const p = join(dir, f);
    let doc;
    try {
      if (!fs.statSync(p).isFile() || fs.statSync(p).size > LOCKFILE_MAX_BYTES) continue;
      doc = JSON.parse(fs.readFileSync(p, 'utf8'));
    } catch { continue; }
    const names = new Set();
    if (doc && typeof doc.packages === 'object' && doc.packages) {
      for (const k of Object.keys(doc.packages)) {
        const at = k.lastIndexOf('node_modules/');
        if (at >= 0) names.add(k.slice(at + 'node_modules/'.length));
      }
    } else {
      const walk = (deps) => {
        for (const [n, d] of Object.entries(deps ?? {})) { names.add(n); if (d && typeof d === 'object') walk(d.dependencies); }
      };
      if (doc && typeof doc.dependencies === 'object') walk(doc.dependencies);
    }
    return [...names].filter((n) => n.length > 0 && n.length <= 214).sort();
  }
  return [];
}

/**
 * `init`: make the cache ready to read: the root, the buckets of `names`, and at least one bucket in all (a bucket brings the
 * seed's tables). Resolves to { ok: true, root_digest, cut_at, held, failed } or { ok: false, why }; never rejects.
 */
export async function setUpSeedCache({ get, cachePath, names = [], seedKey = SEED_KEY, now = Date.now(), bits = SH.BUCKET_BITS,
  feedKeys = null }) {
  try {
    fs.mkdirSync(dirname(cachePath), { recursive: true });
    const r = await refreshRoot({ get, cachePath, seedKey, now, bits, feedKeys });
    const need = bucketsFor(cachePath, names, { bits });
    const refresh = async () => { await refreshRoot({ get, cachePath, seedKey, now, bits, feedKeys }); return null; };
    const f = await fetchBuckets({ get, cachePath, buckets: need, seedKey, bits, refresh });
    let held = readCache(cachePath, (db) => [...heldOf(db)].sort((a, b) => a - b));
    if (!held.length) {
      const one = await fetchBuckets({ get, cachePath, buckets: [0], seedKey, bits, refresh });
      if (!one.imported.length) return { ok: false, why: one.failed[0]?.why ?? 'no bucket could be fetched' };
      held = [0];
    }
    const digest = readCache(cachePath, (db) => db.prepare('SELECT digest FROM shard_root WHERE id = 1').pluck().get());
    return { ok: true, root_digest: digest, cut_at: r.cut_at, held, failed: f.failed };
  } catch (e) { return { ok: false, why: String(e?.why ?? e?.message ?? e).slice(0, 300) }; }
}

/**
 * What a cache file holds, for `status` and `doctor`, read without verifying (the proxy verifies when it opens the cache):
 * { root_cut_at, root_digest, buckets_held, buckets_total, seed_version, notices_path, notices_sha256, last_fetch }, or null
 * when there is no cache or no root yet.
 */
export function readSeedCache(cachePath) {
  try {
    return readCache(cachePath, (db) => {
      if (!db || !tableOf(db, 'shard_root')) return null;
      const r = db.prepare('SELECT digest, cut_at, root_json FROM shard_root WHERE id = 1').get();
      if (!r) return null;
      let total = null; let version = null; let notices = { path: null, sha256: null };
      try {
        const root = JSON.parse(r.root_json);
        total = Array.isArray(root.buckets) ? root.buckets.length : null;
        version = typeof root.seed_version === 'string' ? root.seed_version : null;
        notices = noticesOf(root);
      } catch { /* unread */ }
      const f = SH.readFetch(db);
      return { root_cut_at: r.cut_at, root_digest: r.digest, buckets_held: heldOf(db).size, buckets_total: total, seed_version: version,
        notices_path: notices.path, notices_sha256: notices.sha256, last_fetch: f ? { outcome: f.outcome, attempted_at: f.attempted_at, why: f.why } : null };
    });
  } catch { return null; }
}

const SEED_TAG = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;
// The third-party notices the root names: a plain file name on the host and the sha256 of its bytes. Shown only, never fetched
// or read by a decision; a root naming anything else shows no notices.
const NOTICES_FILE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const noticesOf = (root) => (typeof root.notices_path === 'string' && NOTICES_FILE.test(root.notices_path)
  && typeof root.notices_sha256 === 'string' && /^[0-9a-f]{64}$/.test(root.notices_sha256)
  ? { path: root.notices_path, sha256: root.notices_sha256 } : { path: null, sha256: null });

/** The URL of the notices the cache's root names, on the configured host, or null. */
export function seedCacheNoticesUrl(url, cache) {
  if (!url || !cache?.notices_path) return null;
  try { return new URL(cache.notices_path, url.endsWith('/') ? url : `${url}/`).href; } catch { return null; }
}
const age = (ms) => (ms < 48 * 3600e3 ? `${Math.max(0, Math.floor(ms / 3600e3))} h` : `${Math.floor(ms / 86400e3)} days`);

/**
 * What `status` and `doctor` say about the seed cache. `url` is the configured host or null (off); `cache` is readSeedCache's
 * result. Returns { state, text, notice }: state is 'off', 'none', 'fresh', 'old' (past 48 hours) or 'stale' (past 7 days);
 * notice is true when the user should look (no root yet, old, stale, a failed or refused fetch).
 */
export function describeSeedCache({ url, cache, now = Date.now() }) {
  if (!url && !cache) return { state: 'off', text: 'off (seed_cache is false)', notice: false };
  const parts = [];
  let state = 'none';
  if (!cache) parts.push('no root fetched yet; the installed full seed, if any, serves until one is');
  else {
    const ms = now - Date.parse(cache.root_cut_at);
    state = ms > 7 * 864e5 ? 'stale' : ms > 48 * 3600e3 ? 'old' : 'fresh';
    // the root's seed_version (the published seed's tag) is shown beside its cut, only as a plain short tag; nothing decides on it
    const tag = typeof cache.seed_version === 'string' && SEED_TAG.test(cache.seed_version) ? `, seed ${cache.seed_version}` : '';
    parts.push(`root of ${cache.root_cut_at}${tag} (${age(ms)} old), ${cache.buckets_held} of ${cache.buckets_total ?? '?'} buckets held `
      + '(the others are fetched when a package needs them)');
    if (state === 'old') parts.push('older than 48 hours');
    if (state === 'stale') parts.push('older than 7 days, stated on every decision');
    const notices = seedCacheNoticesUrl(url, cache);
    if (notices) parts.push(`third-party notices: ${notices}`);
  }
  const last = cache?.last_fetch;
  if (last && ['failed', 'refused'].includes(last.outcome)) parts.push(`last fetch ${last.outcome} at ${last.attempted_at}: ${last.why}`);
  if (!url) parts.push('fetching is off');
  const notice = state !== 'fresh' || ['failed', 'refused'].includes(last?.outcome);
  return { state, text: parts.join('; '), notice };
}

/**
 * Since 0.1.6: a command that installs or activates a full seed (`init --seed`, `update-seed --seed`, `update-seed --rollback`)
 * turns the seed cache off, so the seed it activates is the one ChainGate reads; the user's other settings are kept. Returns the
 * line to print, or null when the cache was already off.
 */
export function seedCacheOffForFullSeed(configFile) {
  const existing = readConfigStrict(configFile) || {};
  if (existing.seed_cache === false) return null;
  writeConfig(configFile, { ...existing, seed_cache: false });
  return seedCacheOffLine(configFile);
}
export const seedCacheOffLine = (configFile) => `Seed cache off ("seed_cache": false in ${configFile}): the full seed you installed is the `
  + 'one ChainGate reads. Remove that setting to use the seed cache again.';

export default { SHARDS_FETCH_TIMEOUT_MS, shardSource, refreshRoot, bucketsFor, fetchBuckets, bucketPath, lockfileNames, setUpSeedCache,
  readSeedCache, describeSeedCache, seedCacheNoticesUrl, seedCacheOffForFullSeed };
