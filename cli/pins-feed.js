// Since 0.1.6: fetching the ChainGate pins feed (shown to users as the advisory feed) and applying an accepted cut to the witness store.
//
// One source is a base URL (https only) or a local directory with the same layout: keys.json and keys.json.sig (the key
// manifest the seed key signs), latest.jsonl (the newest cut), cuts/<stamp>.jsonl and .sig (the dated copies: the newest
// cut's signature and the walk back are read from them), latest.jsonl.sig (used only when the dated signature is missing). Each request is a plain GET with no identifiers and no registry token, 10 seconds and 16 MiB at
// most. Whatever happens, the kept cut keeps serving; the outcome is recorded for `status` and `doctor`.
import { createPublicKey } from 'node:crypto';
import { join } from 'node:path';
import { CHAINGATE_SEED_PUBKEY_B64 } from '../witness/seed_verify.js';
import { readBounded } from '../seed/v3/bounded-file.js';
import { PINS_LIMITS, PinsFeedRefused, verifyKeyManifest, decideCut, storeRows, feedAge, stampOf } from '../witness/pins-feed.js';

export const PINS_FETCH_TIMEOUT_MS = 10_000;
export const PINS_REFRESH_MS = 3600e3;
const RECENT_BLOCK_MS = 30 * 24 * 3600e3;

const SEED_KEY = createPublicKey({ key: Buffer.from(CHAINGATE_SEED_PUBKEY_B64, 'base64'), format: 'der', type: 'spki' });

/** An https base URL as a source. `fetchImpl` is for tests. */
export function urlSource(base, { fetchImpl = fetch, timeoutMs = PINS_FETCH_TIMEOUT_MS } = {}) {
  const u = new URL(base.endsWith('/') ? base : `${base}/`);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(u.hostname))) {
    throw new PinsFeedRefused('the pins feed URL must be https');
  }
  return async (path) => {
    const cap = path.startsWith('keys.json') ? PINS_LIMITS.manifestBytes : PINS_LIMITS.feedBytes;
    const res = await fetchImpl(new URL(path, u), { redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
    if (res.status !== 200) { await res.body?.cancel?.(); throw new Error(`${path}: HTTP ${res.status}`); }
    const parts = []; let n = 0;
    for await (const c of res.body) {
      n += c.length;
      if (n > cap) throw new Error(`${path}: larger than ${cap} bytes`);
      parts.push(Buffer.from(c));
    }
    return Buffer.concat(parts);
  };
}

/** A local directory as a source (`update-advisories --file`). */
export function dirSource(dir) {
  return async (path) => readBounded(join(dir, ...path.split('/')),
    path.startsWith('keys.json') ? PINS_LIMITS.manifestBytes : PINS_LIMITS.feedBytes);
}

/**
 * The signature of latest.jsonl. A cache in front of the feed (the raw host keeps files up to 5 minutes) can pair a new
 * latest.jsonl with the old latest.jsonl.sig, so the signature is read from the cut's own dated copy, which never changes
 * once written; latest.jsonl.sig only when that copy cannot be read. Either way the signature is verified.
 */
async function latestSigFor(get, bytes) {
  let stamp = null;
  try {
    const nl = bytes.indexOf(0x0a);
    const cutAt = JSON.parse(bytes.subarray(0, nl < 0 ? bytes.length : nl).toString('ascii')).cut_at;
    if (typeof cutAt === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(cutAt)) stamp = stampOf(cutAt);
  } catch { /* parseCut refuses it below */ }
  if (stamp) { try { return await get(`cuts/${stamp}.jsonl.sig`); } catch { /* fall back */ } }
  return get('latest.jsonl.sig');
}

/**
 * Fetch, decide, apply. Returns { outcome, why, cut_at, digest, rows, walked }; outcome is one of 'accepted', 'same', 'held',
 * 'refused' (the feed said something this version will not take) or 'failed' (it could not be read). Never throws for a feed
 * problem; a store that cannot record throws.
 */
export async function refreshPins({ get, db, seedKey = SEED_KEY, now = Date.now(), accept = null }) {
  const attemptedAt = new Date(now).toISOString();
  const kept0 = db.advisoryPinsFeed();
  let d;
  try {
    const keys = verifyKeyManifest(await get('keys.json'), await get('keys.json.sig'), { seedKey });
    const bytes = await get('latest.jsonl');
    const latest = { bytes, sig: await latestSigFor(get, bytes) };
    const kept = kept0 ? { cut_at: kept0.cut_at, digest: kept0.digest, pairs: db.advisoryPinPairs() } : null;
    const loadCut = async (stamp) => ({ bytes: await get(`cuts/${stamp}.jsonl`), sig: await get(`cuts/${stamp}.jsonl.sig`) });
    d = await decideCut({ latest, kept, loadCut, keys, now, accept });
  } catch (err) {
    const outcome = err instanceof PinsFeedRefused ? 'refused' : 'failed';
    const why = err instanceof PinsFeedRefused ? err.why : String(err?.message ?? err);
    db.recordAdvisoryPinsFetch({ attemptedAt, outcome, why });
    return { outcome, why, cut_at: kept0?.cut_at ?? null, digest: kept0?.digest ?? null, rows: kept0?.rows ?? 0, walked: 0 };
  }
  const { cut } = d;
  if (d.action === 'held') {
    // the person deciding --accept-cut sees what protection the cut would lift: up to 20 removed versions blocked here lately
    let why = d.why;
    if (d.removed?.length) {
      let recent = [];
      try {
        const blocked = db.blockedVersionsSince(new Date(now - RECENT_BLOCK_MS).toISOString());
        recent = d.removed.filter((x) => blocked.has(x));
      } catch { /* the hold stands without the list */ }
      if (recent.length) {
        why += `; it would lift ${recent.length} version(s) this proxy BLOCKed in the last 30 days: ${recent.slice(0, 20).join(', ')}`
          + `${recent.length > 20 ? ` and ${recent.length - 20} more` : ''}`;
      }
    }
    db.recordAdvisoryPinsFetch({ attemptedAt, outcome: 'held', why, heldDigest: cut.digest, heldCutAt: cut.head.cut_at });
    return { outcome: 'held', why, cut_at: cut.head.cut_at, digest: cut.digest, rows: cut.rows.length, walked: d.walked };
  }
  if (d.action === 'accept') {
    const applied = db.replaceAdvisoryPins({ cutAt: cut.head.cut_at, digest: cut.digest, rows: storeRows(cut),
      expectDigest: kept0?.digest ?? null });
    if (!applied) {
      const why = 'another process changed the kept cut while this one was read; the next fetch decides again';
      db.recordAdvisoryPinsFetch({ attemptedAt, outcome: 'failed', why });
      return { outcome: 'failed', why, cut_at: null, digest: null, rows: 0, walked: d.walked };
    }
  }
  const outcome = d.action === 'accept' ? 'accepted' : 'same';
  db.recordAdvisoryPinsFetch({ attemptedAt, outcome, why: d.why });
  return { outcome, why: d.why, cut_at: cut.head.cut_at, digest: cut.digest, rows: cut.rows.length, walked: d.walked };
}

const hours = (ms) => (ms < 48 * 3600e3 ? `${Math.max(0, Math.floor(ms / 3600e3))} h` : `${Math.floor(ms / 86400e3)} days`);

/**
 * What `status` and `doctor` say about the advisory feed. `url` is the configured base URL or null; `feed` and `fetch` are the
 * store's advisoryPinsFeed() and advisoryPinsFetch(). Returns { state, text, notice }: state is 'off', 'none', 'fresh', 'old'
 * (past 48 hours) or 'stale' (past 7 days); notice is true when the user should look (old, stale, held, refused, failing).
 */
export function describePinsFeed({ url, feed, fetch: last, now = Date.now() }) {
  const age = feedAge(feed, now);
  const parts = [];
  if (feed) parts.push(`cut ${feed.cut_at} (${hours(age.ageMs)} old), ${feed.rows} versions`);
  else parts.push('no cut accepted yet');
  if (age.state === 'old') parts.push('older than 48 hours');
  if (age.state === 'stale') parts.push('STALE: older than 7 days, the last accepted cut keeps serving');
  if (last?.outcome === 'held') parts.push(`cut ${last.held_cut_at} HELD (${last.why}); take it with: chaingate update-advisories --accept-cut ${last.held_digest}`);
  else if (last && ['refused', 'failed'].includes(last.outcome)) parts.push(`last fetch ${last.outcome} at ${last.attempted_at}: ${last.why}`);
  if (!url) {
    if (!feed && !last) return { state: 'off', text: 'not configured (no advisory_feed_url, or advisory_feed is false)', notice: false };
    parts.push('fetching is off');
  }
  const notice = ['old', 'stale'].includes(age.state) || ['held', 'refused', 'failed'].includes(last?.outcome) || (Boolean(url) && !feed);
  return { state: feed ? age.state : 'none', text: parts.join('; '), notice };
}
