// Out-of-band dep first-publish fetcher.
//
// The scope-boundary gate needs to know, for a dep name it's never
// seen, when that package was first published. We can't fetch that
// synchronously inside the gate runner (which runs inside a
// better-sqlite3 transaction). Instead this module runs a small
// background worker pool: gates enqueue lookups, the pool fetches
// at ≤ 5 rps, and results land in the witness dep_first_publish
// cache table.
//
// Design choices:
//
//   1. Single undici Pool instance dedicated to this background work.
//      Uses a separate connection pool from the main proxy's upstream
//      requests so a burst of scope-boundary lookups can't starve
//      packument/tarball traffic, and vice versa.
//
//   2. Serial worker with a sleep-based throttle. We dispatch one fetch,
//      wait intervalMs, dispatch the next. At 200ms interval → 5 rps.
//      No token bucket library needed; the queue IS the bucket.
//
//   3. Dedup by package name. If a lookup for 'foo' is already in
//      flight or already enqueued, a second request for 'foo' is
//      a no-op. Prevents queue bloat when many versions reference
//      the same dep.
//
//   4. Bounded queue. If > maxQueueSize pending, drop new enqueues.
//      Install storms shouldn't turn us into an upstream DDoS source.
//
//   5. Derives `first_publish` from the packument's `time.created`
//      field. That's npm's immutable creation timestamp. Fallback:
//      the minimum of `time[version]` over all versions. If neither
//      is present, record as 'error'.
//
//   6. Graceful stop(): drains inflight, aborts pending, resolves.

const DEFAULT_INTERVAL_MS = 200; // 5 rps
const DEFAULT_MAX_QUEUE = 100;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function deriveFirstPublish(packument) {
  if (!packument || typeof packument !== 'object') return null;
  const time = packument.time;
  if (!time || typeof time !== 'object') return null;
  if (typeof time.created === 'string' && time.created) return time.created;
  // Fallback: minimum of version keys. Ignore 'created' / 'modified' meta keys.
  let minIso = null;
  for (const [k, v] of Object.entries(time)) {
    if (k === 'created' || k === 'modified') continue;
    if (typeof v !== 'string') continue;
    if (minIso == null || v < minIso) minIso = v;
  }
  return minIso;
}

export function createDepFetcher({
  depCache,
  fetchPackument,
  logger = null,
  intervalMs = DEFAULT_INTERVAL_MS,
  maxQueueSize = DEFAULT_MAX_QUEUE,
} = {}) {
  if (!depCache) throw new Error('createDepFetcher: depCache required');
  if (typeof fetchPackument !== 'function') {
    throw new Error('createDepFetcher: fetchPackument function required');
  }
  const log = logger ?? { info() {}, warn() {}, error() {} };

  const queue = []; // ordered names
  const inflight = new Set(); // names currently being fetched
  const pending = new Set(); // names in the queue
  let running = false;
  let stopping = false;
  let stats = { enqueued: 0, dropped: 0, ok: 0, vanished: 0, error: 0 };
  let loopDone = null;

  function enqueue(packageName) {
    if (stopping) return false;
    if (typeof packageName !== 'string' || !packageName) return false;
    if (inflight.has(packageName) || pending.has(packageName)) return false;
    if (queue.length >= maxQueueSize) {
      stats.dropped += 1;
      log.warn(`[dep-fetcher] queue full (${queue.length}), dropped ${packageName}`);
      return false;
    }
    queue.push(packageName);
    pending.add(packageName);
    stats.enqueued += 1;
    if (!running) startLoop();
    return true;
  }

  async function fetchOne(name) {
    inflight.add(name);
    try {
      const resp = await fetchPackument(name);
      if (resp.statusCode === 404) {
        depCache.recordVanished(name);
        stats.vanished += 1;
        return;
      }
      if (resp.statusCode !== 200) {
        depCache.recordError(name);
        stats.error += 1;
        log.warn(`[dep-fetcher] ${name}: upstream ${resp.statusCode}`);
        return;
      }
      let body;
      try {
        body = await resp.body.json();
      } catch (err) {
        depCache.recordError(name);
        stats.error += 1;
        log.warn(`[dep-fetcher] ${name}: json parse failed: ${err.message}`);
        return;
      }
      const firstPublish = deriveFirstPublish(body);
      if (!firstPublish) {
        depCache.recordError(name);
        stats.error += 1;
        log.warn(`[dep-fetcher] ${name}: no time.created in packument`);
        return;
      }
      depCache.recordOk(name, firstPublish);
      stats.ok += 1;
    } catch (err) {
      depCache.recordError(name);
      stats.error += 1;
      log.warn(`[dep-fetcher] ${name}: ${err.message}`);
    } finally {
      inflight.delete(name);
    }
  }

  function startLoop() {
    if (running) return;
    running = true;
    loopDone = (async () => {
      while (!stopping && queue.length > 0) {
        const name = queue.shift();
        pending.delete(name);
        await fetchOne(name);
        if (!stopping && queue.length > 0) {
          await sleep(intervalMs);
        }
      }
      running = false;
    })();
  }

  async function stop() {
    stopping = true;
    queue.length = 0;
    pending.clear();
    if (loopDone) await loopDone;
  }

  function getStats() {
    return { ...stats, queued: queue.length, inflight: inflight.size };
  }

  return { enqueue, stop, getStats, _deriveFirstPublish: deriveFirstPublish };
}
