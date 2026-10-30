// Since 0.1.6: the seed cache in the running proxy. The proxy reads the cache in place of a full seed; this keeps it current.
//
// - Before a package is decided, its bucket is fetched when the cache does not hold it. The decision waits at most `waitMs`
//   (5 seconds by default); past that the package is uncovered for this decision and the bucket keeps downloading, one fetch per
//   bucket however many requests need it.
// - A bucket the host does not have (404) means the root moved on: the root is refreshed and the bucket asked for once more;
//   still missing, the package is uncovered.
// - The root is refreshed at start and hourly (a 304 when nothing changed). A new root is opened and verified as at start, then
//   taken over by the seed the gate holds; the buckets it changed are fetched again.
// - With no cache in use yet (an installed full seed serves, or none), the refresh fetches the root and one bucket, so the next
//   start reads the cache.
// A problem is one log line; whatever the cache holds keeps serving.
import fs from 'node:fs';
import { createPublicKey } from 'node:crypto';
import Database from 'better-sqlite3';
import { openSeed, TRUST_AUTHENTICATED } from '../seed/v3/reader.js';
import * as SH from '../seed/v3/shards.js';
import { refreshRoot, fetchBuckets } from '../cli/seed-shards.js';
import { CHAINGATE_SEED_PUBKEY_B64 } from '../witness/seed_verify.js';

export const DEFAULT_SEED_CACHE_WAIT_MS = 5_000;
export const SEED_CACHE_REFRESH_MS = 3600e3;

/**
 * @param {object} o
 *   o.get        a shard source (cli/seed-shards.js shardSource)
 *   o.cachePath  the cache file
 *   o.seedKey    the seed public key as a KeyObject (the embedded one when null); o.bits the bucket bits (14 in production)
 *   o.feedKeys   async () => the advisory feed's keys.json, or null when it is off
 *   o.now        clock (ms) for the root's age and key validity
 */
export function createSeedCache({ get, cachePath, seedKey = null, bits = SH.BUCKET_BITS, waitMs = DEFAULT_SEED_CACHE_WAIT_MS,
  feedKeys = async () => null, now = Date.now, log = null }) {
  const key = seedKey ?? createPublicKey({ key: Buffer.from(CHAINGATE_SEED_PUBKEY_B64, 'base64'), format: 'der', type: 'spki' });
  let seed = null;                     // the Seed the gate holds, when it is this cache
  const inflight = new Map();          // bucket -> Promise of its fetch
  let refreshing = null;
  let lastFetch = null;

  const fetchOne = (i) => {
    if (inflight.has(i)) return inflight.get(i);
    // a 404 means the root moved on: refresh it (shared with any refresh in progress), then ask once more under the root now held
    const p = fetchBuckets({ get, cachePath, buckets: [i], seedKey: key, bits, root: seed?.shards?.root ?? null,
      refresh: async () => { await refresh(); return seed?.shards?.root ?? null; } })
      .then((r) => {
        if (r.failed.length) log?.warn?.(`[seed-cache] bucket ${i}: ${r.failed[0].why}`);
        else seed?.reloadHeld();
        return r;
      })
      .catch((e) => { log?.warn?.(`[seed-cache] bucket ${i}: ${e.message}`); return { imported: [], failed: [{ i, why: e.message }] }; })
      .finally(() => inflight.delete(i));
    inflight.set(i, p);
    return p;
  };

  /** Resolves once `name`'s bucket is held or `waitMs` has passed; never rejects. */
  async function need(name) {
    const b = seed?.bucketOf(name);
    if (!b || b.held) return;
    let timer;
    await Promise.race([fetchOne(b.i), new Promise((r) => { timer = setTimeout(r, waitMs); timer.unref?.(); })]);
    clearTimeout(timer);
  }

  const holdsBuckets = () => {
    if (!fs.existsSync(cachePath)) return false;
    const db = new Database(cachePath, { readonly: true, fileMustExist: true });
    try { return SH.cacheBuckets(db).length > 0; } catch { return false; } finally { db.close(); }
  };

  /** Fetch the root; take over a new one; fetch the buckets it changed. Resolves to refreshRoot's result, or { outcome: 'failed' }. */
  function refresh() {
    refreshing ??= (async () => {
      try {
        const r = await refreshRoot({ get, cachePath, seedKey: key, now: now(), bits, feedKeys: await feedKeys().catch(() => null) });
        lastFetch = { outcome: r.outcome, at: new Date(now()).toISOString(), why: null };
        if (seed && r.outcome === 'accepted') {
          seed.adopt(openSeed(cachePath, { trust: TRUST_AUTHENTICATED, pubkey: key, shardBits: bits, now }));
          log?.info?.(`[seed-cache] root of ${r.cut_at} (${r.held} buckets kept)`);
        }
        const again = seed ? r.dropped : (holdsBuckets() ? [] : [0]);   // with no cache in use: one bucket brings the tables
        await Promise.all(again.map(fetchOne));
        return r;
      } catch (e) {
        lastFetch = { outcome: e instanceof SH.ShardRefused ? 'refused' : 'failed', at: new Date(now()).toISOString(), why: e.message };
        log?.warn?.(`[seed-cache] root: ${e.message}`);
        return { outcome: lastFetch.outcome, why: e.message };
      } finally { refreshing = null; }
    })();
    return refreshing;
  }

  function state() {
    const s = seed?.shards;
    const recorded = (() => {
      if (!fs.existsSync(cachePath)) return null;
      const db = new Database(cachePath, { readonly: true, fileMustExist: true });
      try { return SH.readFetch(db); } catch { return null; } finally { db.close(); }
    })();
    return {
      in_use: Boolean(s),
      root_cut_at: s?.root.cut_at ?? null,
      root_age_days: s ? Math.max(0, Math.floor((now() - Date.parse(s.root.cut_at)) / 864e5)) : null,
      buckets_held: s ? s.held.size : null,
      buckets_total: s ? s.root.buckets.length : null,
      fetching: inflight.size,
      last_fetch: lastFetch ?? (recorded ? { outcome: recorded.outcome, at: recorded.attempted_at, why: recorded.why } : null),
    };
  }

  /** Every fetch in progress settled (tests, shutdown). */
  async function idle() {
    while (refreshing || inflight.size) await Promise.allSettled([refreshing, ...inflight.values()]);
  }

  return { attach: (s) => { seed = s?.shards ? s : null; }, need, refresh, state, idle };
}

