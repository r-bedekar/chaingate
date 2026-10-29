// Since 0.1.6: reading the ChainGate pins feed. Pure: no network and no store here. The caller fetches the files, this module
// says whether a cut may replace the kept one, and the witness store applies it (witness/db.js replaceAdvisoryPins).
//
// Trust: the seed key (the one key the CLI embeds) signs a key manifest; the manifest names the pins keys, each with a
// validity window of at most 90 days; a cut is signed by the pins key its header names, valid at the cut's own time. The
// signature is raw Ed25519 over the ASCII sha256 hex of the cut file, as for the seed.
//
// No gaps: every cut names the previous published cut (its digest and its time). A newer cut is accepted only when its chain
// reaches the kept cut, every link checked; a link that is missing or does not verify refuses the cut, it is never skipped.
// The walk goes back at most 7 days; past that, or when a cut adds more than 2,000 new versions, or removes more than 100
// versions or a quarter of the kept ones (whichever is fewer; an empty cut over a non-empty one always), the cut is HELD until
// `chaingate update-advisories --accept-cut <digest>` takes it. Versions are counted as (name, version), so an entry moved to
// another advisory is neither added nor removed. A refused or held cut leaves the kept cut serving.
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';

export const PINS_FEED_VERSION = 'pins-feed-1.3';
export const KEY_MANIFEST_VERSION = 'pins-keys-1.0';
export const PINS_LIMITS = Object.freeze({
  feedBytes: 16 * 1024 * 1024,
  manifestBytes: 64 * 1024,
  keyValidityMs: 90 * 24 * 3600e3,
  walkBackMs: 7 * 24 * 3600e3,
  walkLinks: 400,
  floodNewRows: 2000,
  removedRows: 100,
  removedFraction: 0.25,
  ageWarnMs: 48 * 3600e3,
  ageStaleMs: 7 * 24 * 3600e3,
  futureSkewMs: 10 * 60e3,
});
export const SOURCES = Object.freeze(['osv', 'ghsa', 'chaingate-analyst']);

export class PinsFeedRefused extends Error {
  constructor(why) { super(why); this.name = 'PinsFeedRefused'; this.why = why; }
}
const refuse = (why) => { throw new PinsFeedRefused(why); };

const HEX64 = /^[0-9a-f]{64}$/;
const TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const KEY_ID = /^ed25519:[0-9a-f]{16}$/;
const SRI512 = /^sha512-[A-Za-z0-9+/]{86}==$/;                    // a capture's npm dist.integrity, as the publisher admits it
const TEXT = /^[\x21-\x7e]{1,214}$/;
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const tsMs = (s) => (typeof s === 'string' && TS.test(s) ? Date.parse(s) : NaN);
const exactKeys = (o, keys) => Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));

export const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');

/** The file name of a dated copy: cut_at 2026-10-29T10:00:00Z -> 20261029T100000Z. */
export const stampOf = (cutAt) => cutAt.replace(/[-:]/g, '');

/** A key id in the seed's form: "ed25519:" + the first 16 hex of sha256 over the raw 32-byte public key. */
export function keyIdOf(spkiDer) {
  const der = Buffer.from(spkiDer);
  if (der.length !== 44 || !der.subarray(0, 12).equals(ED25519_SPKI_PREFIX)) refuse('a manifest key is not an Ed25519 public key');
  return `ed25519:${sha256Hex(der.subarray(12)).slice(0, 16)}`;
}

/**
 * The pins keys a key manifest delegates. `seedKey` is the embedded seed public key (a KeyObject); the manifest bytes are
 * signed as they are. Every listed key must be Ed25519, carry its own id, and have a window of more than 0 and at most 90
 * days. Returns all pins keys; a cut is checked against the one valid at its own time.
 */
export function verifyKeyManifest(bytes, sig, { seedKey, role = 'pins' }) {
  if (!Buffer.isBuffer(bytes) || bytes.length > PINS_LIMITS.manifestBytes) refuse('the key manifest is missing or too large');
  if (!Buffer.isBuffer(sig) || sig.length !== 64) refuse('the key manifest signature is not 64 bytes');
  if (!cryptoVerify(null, bytes, seedKey, sig)) refuse('the key manifest signature does not verify against the seed key');
  let m;
  try { m = JSON.parse(bytes.toString('ascii')); } catch { refuse('the key manifest is not JSON'); }
  if (!isObj(m) || m.key_manifest_version !== KEY_MANIFEST_VERSION) refuse(`the key manifest is not ${KEY_MANIFEST_VERSION}`);
  if (!Array.isArray(m.keys)) refuse('the key manifest lists no keys');
  const keys = [];
  for (const k of m.keys) {
    if (!isObj(k) || typeof k.spki_b64 !== 'string' || !KEY_ID.test(k.key_id ?? '')) refuse('a manifest key is malformed');
    const der = Buffer.from(k.spki_b64, 'base64');
    if (keyIdOf(der) !== k.key_id) refuse(`manifest key ${k.key_id} does not match its public key`);
    const from = tsMs(k.valid_from); const to = tsMs(k.valid_to);
    if (!(to - from > 0 && to - from <= PINS_LIMITS.keyValidityMs)) refuse(`manifest key ${k.key_id} has a window over 90 days`);
    if (k.role !== role) continue;           // a list may carry keys of other roles (pins, shards)
    keys.push({ key_id: k.key_id, from, to, key: createPublicKey({ key: der, format: 'der', type: 'spki' }) });
  }
  if (!keys.length) refuse(`the key manifest names no ${role} key`);
  return keys;
}

const HEAD_KEYS = ['feed_version', 'cut_at', 'count', 'prev_cut_digest', 'prev_cut_at', 'pins_key_id', 'label_input_digest',
  'label_input_metadata_cutoff'];
const ROW_KEYS = ['name', 'version', 'advisory_id', 'also_advisories', 'record_id', 'source', 'evidence', 'added_at'];

function checkRow(r, i) {
  const at = `row ${i + 1}`;
  if (!isObj(r) || !exactKeys(r, ROW_KEYS)) refuse(`${at} does not have the row fields`);
  if (typeof r.name !== 'string' || !TEXT.test(r.name) || typeof r.version !== 'string' || !TEXT.test(r.version)) refuse(`${at}: bad name or version`);
  if (r.advisory_id !== null && !(typeof r.advisory_id === 'string' && TEXT.test(r.advisory_id))) refuse(`${at}: bad advisory_id`);
  if (!Array.isArray(r.also_advisories) || !r.also_advisories.every((a) => typeof a === 'string' && TEXT.test(a))) refuse(`${at}: bad also_advisories`);
  if (typeof r.record_id !== 'string' || !TEXT.test(r.record_id)) refuse(`${at}: bad record_id`);
  if (!SOURCES.includes(r.source)) refuse(`${at}: unknown source`);
  const e = r.evidence;
  const okEvidence = isObj(e) && ((e.kind === 'advisory' && exactKeys(e, ['kind', 'advisory_id']) && typeof e.advisory_id === 'string' && TEXT.test(e.advisory_id))
    || (e.kind === 'capture' && exactKeys(e, ['kind', 'sha256', 'dist_integrity']) && HEX64.test(e.sha256 ?? '')
      && SRI512.test(e.dist_integrity ?? '')));
  if (!okEvidence) refuse(`${at}: bad evidence`);
  if (r.source === 'chaingate-analyst' ? e.kind !== 'capture' : e.kind !== 'advisory') refuse(`${at}: evidence does not fit its source`);
  if (!TS.test(r.added_at ?? '')) refuse(`${at}: bad added_at`);
}

/**
 * Parse one cut: ASCII, one JSON object per line, every line ending in a newline; the header, then `count` rows sorted by
 * (name, version), each pair once. Anything else refuses the cut.
 */
export function parseCut(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > PINS_LIMITS.feedBytes) refuse('the cut is empty or too large');
  if (bytes.some((b) => b > 0x7e || (b < 0x20 && b !== 0x0a))) refuse('the cut is not plain ASCII');
  const text = bytes.toString('ascii');
  if (!text.endsWith('\n')) refuse('the cut does not end with a newline');
  const lines = text.slice(0, -1).split('\n');
  let head; const rows = [];
  try { head = JSON.parse(lines[0]); for (const l of lines.slice(1)) rows.push(JSON.parse(l)); } catch { refuse('a cut line is not JSON'); }
  if (!isObj(head) || !exactKeys(head, HEAD_KEYS)) refuse('the cut header does not have the header fields');
  if (head.feed_version !== PINS_FEED_VERSION) refuse(`the cut is ${String(head.feed_version).slice(0, 40)}, this version reads ${PINS_FEED_VERSION}`);
  if (!TS.test(head.cut_at ?? '')) refuse('bad cut_at');
  if (!KEY_ID.test(head.pins_key_id ?? '')) refuse('bad pins_key_id');
  const first = head.prev_cut_digest === null && head.prev_cut_at === null;
  if (!first && !(HEX64.test(head.prev_cut_digest ?? '') && tsMs(head.prev_cut_at) < tsMs(head.cut_at))) {
    refuse('prev_cut_digest and prev_cut_at must both name an earlier cut, or both be null');
  }
  if (!Number.isInteger(head.count) || head.count !== rows.length) refuse(`the header counts ${head.count} rows, the cut has ${rows.length}`);
  rows.forEach(checkRow);
  for (let i = 1; i < rows.length; i++) {
    const a = rows[i - 1]; const b = rows[i];
    if (!(a.name < b.name || (a.name === b.name && a.version < b.version))) refuse(`rows ${i} and ${i + 1} are not sorted or repeat a version`);
  }
  return { head, rows, digest: sha256Hex(bytes) };
}

/** Check a parsed cut's signature: the key its header names, valid at the cut's own time, over the ASCII digest. */
export function verifyCut(cut, sig, keys) {
  if (!Buffer.isBuffer(sig) || sig.length !== 64) refuse(`the signature of cut ${cut.head.cut_at} is not 64 bytes`);
  const at = tsMs(cut.head.cut_at);
  const k = keys.find((x) => x.key_id === cut.head.pins_key_id && x.from <= at && at < x.to);
  if (!k) refuse(`no pins key ${cut.head.pins_key_id} is valid at ${cut.head.cut_at}`);
  if (!cryptoVerify(null, Buffer.from(cut.digest, 'ascii'), k.key, sig)) refuse(`the signature of cut ${cut.head.cut_at} does not verify`);
  return cut;
}

/**
 * Decide whether the latest cut replaces the kept one.
 *   latest   { bytes, sig } of latest.jsonl
 *   kept     { cut_at, digest, pairs: Set<"name@version"> } or null before the first accepted cut
 *   loadCut  async (stamp) => { bytes, sig } of cuts/<stamp>.jsonl; throws when the copy cannot be read
 *   keys     from verifyKeyManifest
 *   accept   a digest the user named with --accept-cut, or null
 * Returns { action: 'same' | 'accept' | 'held', cut, walked, why, removed }; removed lists the kept "name@version" pairs the cut
 * leaves out. A cut that cannot be accepted throws PinsFeedRefused.
 */
export async function decideCut({ latest, kept, loadCut, keys, now = Date.now(), accept = null }) {
  const cut = verifyCut(parseCut(latest.bytes), latest.sig, keys);
  const at = tsMs(cut.head.cut_at);
  if (at > now + PINS_LIMITS.futureSkewMs) refuse(`cut ${cut.head.cut_at} is dated in the future`);
  if (kept && cut.digest === kept.digest) return { action: 'same', cut, walked: 0, why: null };
  const named = accept !== null && accept === cut.digest;
  const held = (why) => (named ? { action: 'accept', cut, walked: 0, why: `taken by --accept-cut: ${why}` } : { action: 'held', cut, walked: 0, why });
  if (!kept) return { action: 'accept', cut, walked: 0, why: 'first cut' };

  const keptAt = tsMs(kept.cut_at);
  if (!(at > keptAt)) refuse(`cut ${cut.head.cut_at} is not later than the kept cut ${kept.cut_at}`);
  if (at - keptAt > PINS_LIMITS.walkBackMs) return held(`the kept cut ${kept.cut_at} is more than 7 days older than ${cut.head.cut_at}`);

  // walk back to the kept cut, every link checked
  let cur = cut; let walked = 0;
  while (cur.head.prev_cut_digest !== kept.digest) {
    const { prev_cut_digest: pd, prev_cut_at: pa } = cur.head;
    if (pd === null || !(tsMs(pa) > keptAt)) refuse(`cut ${cur.head.cut_at} does not lead back to the kept cut ${kept.cut_at}`);
    if (++walked > PINS_LIMITS.walkLinks) refuse('the chain back to the kept cut is too long');
    let raw;
    try { raw = await loadCut(stampOf(pa)); } catch (e) { refuse(`the cut of ${pa} cannot be read (${String(e?.message ?? e).slice(0, 120)})`); }
    const prev = verifyCut(parseCut(raw.bytes), raw.sig, keys);
    if (prev.digest !== pd || prev.head.cut_at !== pa) refuse(`the cut of ${pa} is not the one ${cur.head.cut_at} names`);
    cur = prev;
  }
  if (cur.head.prev_cut_at !== kept.cut_at) refuse(`cut ${cur.head.cut_at} names the kept digest with another time`);

  const pairs = new Set(cut.rows.map((r) => `${r.name}@${r.version}`));
  const added = [...pairs].filter((x) => !kept.pairs.has(x)).length;
  const removed = [...kept.pairs].filter((x) => !pairs.has(x)).sort();
  const removeLimit = Math.min(PINS_LIMITS.removedRows, Math.floor(kept.pairs.size * PINS_LIMITS.removedFraction));
  const reasons = [];
  if (added > PINS_LIMITS.floodNewRows) reasons.push(`the cut adds ${added} new versions (more than ${PINS_LIMITS.floodNewRows})`);
  if (kept.pairs.size > 0 && pairs.size === 0) reasons.push(`the cut is empty and would remove all ${kept.pairs.size} versions`);
  else if (removed.length > removeLimit) {
    reasons.push(`the cut removes ${removed.length} versions (more than ${removeLimit}: 100, or a quarter of the ${kept.pairs.size} held, whichever is fewer)`);
  }
  if (reasons.length) return { ...held(reasons.join('; ')), walked, removed };
  return { action: 'accept', cut, walked, why: null, removed };
}

/** The store rows of an accepted cut (witness/db.js replaceAdvisoryPins). */
export function storeRows(cut) {
  return cut.rows.map((r) => ({ package_name: r.name, version: r.version, record_id: r.record_id, advisory_id: r.advisory_id,
    source: r.source, evidence_json: JSON.stringify({ ...r.evidence, also_advisories: r.also_advisories }), added_at: r.added_at }));
}

/** How old the kept cut is: 'fresh', 'old' (past 48 hours) or 'stale' (past 7 days), or 'none'. */
export function feedAge(kept, now = Date.now()) {
  if (!kept) return { state: 'none', ageMs: null };
  const ageMs = now - tsMs(kept.cut_at);
  return { state: ageMs > PINS_LIMITS.ageStaleMs ? 'stale' : ageMs > PINS_LIMITS.ageWarnMs ? 'old' : 'fresh', ageMs };
}
