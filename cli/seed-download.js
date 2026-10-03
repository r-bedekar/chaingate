import { createWriteStream, mkdirSync, rmSync, readdirSync, lstatSync, realpathSync, openSync, writeSync, fsyncSync,
  closeSync, renameSync, unlinkSync } from 'node:fs';
import { join, basename, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import { Readable, Transform } from 'node:stream';
import { SEED_FILES } from './constants.js';
import { resolveLatestSeedAssets } from './seed-resolver.js';
import { CAPS, FileRefused, readBounded } from '../seed/v3/bounded-file.js';
import { admit } from './space-admission.js';

// U-05 R2-2, legacy part (Addendum 1 §5; O3 approved for LEGACY downloads only): every byte received is counted against
// an independent limit, with backpressure, deadlines and an owned temporary directory that is always removed.
/** H: the legacy seed DATABASE download. 2.53x the only published legacy release (seed-v2.1, 106,172,416 bytes). It does
 *  not apply to rc3 or any local v3 database, nor to a local legacy `--seed` file (those are bounded by measured size). */
export const LEGACY_DB_MAX_BYTES = 256 * 1024 * 1024;
export const SIDECAR_MAX_BYTES = CAPS.sidecar;
export const TIMEOUTS = Object.freeze({ connectMs: 30_000, idleMs: 60_000, totalMs: 30 * 60_000 });
const DIR_NAME = /^chaingate-seed-[0-9a-f]{12}$/;
const RECORD_SCHEMA = 'chaingate-download/1';

export class DownloadRefused extends Error {
  constructor(message, kind) { super(message); this.name = 'DownloadRefused'; this.kind = kind; }
}

function formatMB(bytes) {
  return (bytes / (1024 * 1024)).toFixed(1);
}

function renderProgress(filename, received, total) {
  if (!process.stdout.isTTY) return;
  if (total > 0) {
    const pct = ((received / total) * 100).toFixed(1);
    process.stdout.write(
      `\r  ${filename}: ${formatMB(received)} MB / ${formatMB(total)} MB (${pct}%)`
    );
  } else {
    process.stdout.write(`\r  ${filename}: ${formatMB(received)} MB`);
  }
}

/** A declared Content-Length, or null when absent, malformed or negative (then the independent limit still applies). */
const declaredLength = (v) => (typeof v === 'string' && /^\d{1,15}$/.test(v.trim()) ? Number(v.trim()) : null);

/**
 * Download `url` into the NEW file `dest` (created exclusively, 0600): at most `max` bytes, whatever the headers say; a
 * valid Content-Length above `max` refuses before the body is read, and received bytes must equal it. Deadlines: connect
 * and headers, an idle gap with no bytes, and a total. Every stage's errors are handled by the pipeline from creation.
 * `onHeaders(declared)` may throw to refuse (space admission). Returns { bytes }.
 */
export async function downloadTo(url, dest, { max, filename = basename(dest), fetchImpl = fetch, timeouts = TIMEOUTS,
  onHeaders } = {}) {
  const ctrl = new AbortController();
  const fail = (msg, kind) => ctrl.abort(new DownloadRefused(`${filename}: ${msg}`, kind));
  const total = setTimeout(() => fail(`not complete within ${timeouts.totalMs / 1000} s`, 'timeout'), timeouts.totalMs);
  let idle = null;
  const unwrap = (e) => (e instanceof DownloadRefused ? e : (e?.cause instanceof DownloadRefused ? e.cause
    : (ctrl.signal.reason instanceof DownloadRefused && ctrl.signal.aborted ? ctrl.signal.reason : e)));
  try {
    let resp;
    const connect = setTimeout(() => fail(`no response within ${timeouts.connectMs / 1000} s`, 'timeout'), timeouts.connectMs);
    try { resp = await fetchImpl(url, { redirect: 'follow', signal: ctrl.signal }); }
    catch (e) { throw unwrap(e); } finally { clearTimeout(connect); }
    if (!resp.ok) { try { await resp.body?.cancel(); } catch { /* discarded */ } throw new DownloadRefused(`${filename}: HTTP ${resp.status}`, 'http'); }
    const declared = declaredLength(resp.headers.get('content-length'));
    if (declared !== null && declared > max) {
      try { await resp.body?.cancel(); } catch { /* discarded */ }
      throw new DownloadRefused(`${filename}: the server declares ${declared} bytes, more than the ${max}-byte limit`, 'too-large');
    }
    try { onHeaders?.(declared); } catch (e) { try { await resp.body?.cancel(); } catch { /* discarded */ } throw e; }
    const showProgress = (declared ?? 0) > 1024 * 1024 && process.stdout.isTTY;
    let received = 0; let lastRender = 0;
    const armIdle = () => { clearTimeout(idle); idle = setTimeout(() => fail(`no data for ${timeouts.idleMs / 1000} s`, 'stalled'), timeouts.idleMs); };
    armIdle();
    const limit = new Transform({
      transform(chunk, _enc, cb) {
        received += chunk.length;
        armIdle();
        if (received > max) return cb(new DownloadRefused(`${filename}: more than the ${max}-byte limit arrived`, 'too-large'));
        if (declared !== null && received > declared) {
          return cb(new DownloadRefused(`${filename}: more bytes arrived than the declared ${declared}`, 'length-mismatch'));
        }
        if (showProgress && Date.now() - lastRender > 100) { renderProgress(filename, received, declared); lastRender = Date.now(); }
        return cb(null, chunk);
      },
    });
    try {
      await pipeline(Readable.fromWeb(resp.body), limit, createWriteStream(dest, { flags: 'wx', mode: 0o600 }),
        { signal: ctrl.signal });
    } catch (e) { throw unwrap(e); }
    if (showProgress) { renderProgress(filename, received, declared); process.stdout.write('\n'); }
    if (declared !== null && received !== declared) {
      throw new DownloadRefused(`${filename}: received ${received} of the declared ${declared} bytes`, 'length-mismatch');
    }
    return { bytes: received };
  } finally { clearTimeout(idle); clearTimeout(total); }
}

// ---- the owned temporary directory and its record ----------------------------------------------------------------------
export const recordPath = (base, pid = process.pid) => join(base, `.download-${pid}.json`);

function writeRecord(base, rec) {
  const file = recordPath(base); const tmp = `${file}.tmp`;
  rmSync(tmp, { force: true });
  const fd = openSync(tmp, 'wx', 0o600);
  try { writeSync(fd, `${JSON.stringify(rec)}\n`); fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(tmp, file);
}

/** Remove the owned directory FIRST, and the record only once that succeeded. Returns null, or what remains. */
export function removeDownload(base, dir, pid = process.pid) {
  try { rmSync(dir, { recursive: true, force: true }); } catch (e) { return `${dir} (${e.code || e.message})`; }
  try { unlinkSync(recordPath(base, pid)); } catch (e) { if (e.code !== 'ENOENT') return `${recordPath(base, pid)} (${e.code})`; }
  return null;
}

/**
 * A `.download-<pid>.json` left by a terminated process, VALIDATED before anything is removed (Addendum 2 §3.4): bounded,
 * the schema, a directory directly inside the REAL tmpdir named chaingate-seed-<12 hex>, a real directory (not a link),
 * holding only the expected file names. Returns { dir } when it is safe to remove, or { keep: why }.
 */
export function validateDownloadRecord(file) {
  let rec;
  try { rec = JSON.parse(readBounded(file, CAPS.record, { noFollow: true }).toString('utf8')); }
  catch (e) { return { keep: e instanceof FileRefused ? e.why : `unreadable: ${e.message}` }; }
  if (!rec || rec.schema !== RECORD_SCHEMA || typeof rec.dir !== 'string') return { keep: 'not a download record this version recognises' };
  let realTmp; try { realTmp = realpathSync(tmpdir()); } catch { return { keep: 'the temporary directory cannot be resolved' }; }
  if (!DIR_NAME.test(basename(rec.dir))) return { keep: `its directory ${rec.dir} is not a chaingate-seed-<id> name` };
  let st; try { st = lstatSync(rec.dir); } catch (e) { return e.code === 'ENOENT' ? { dir: rec.dir, gone: true } : { keep: e.code }; }
  if (!st.isDirectory()) return { keep: `${rec.dir} is not a real directory` };
  if (realpathSync(dirname(rec.dir)) !== realTmp) return { keep: `${rec.dir} is not directly inside ${realTmp}` };
  const extra = readdirSync(rec.dir).filter((n) => !SEED_FILES.includes(n));
  if (extra.length) return { keep: `${rec.dir} holds unexpected entries (${extra.join(', ')})` };
  return { dir: rec.dir };
}

/**
 * Download the LEGACY seed bundle (db + .sha256 + .sig) into an owned temporary directory recorded in
 * `<base>/.download-<pid>.json`. The caller removes it with `cleanup()` on every exit path (network failure, verification
 * failure, destination failure, success); after a termination the next seed command removes it (cleanLeftovers).
 *
 * @returns {Promise<{dir, dbPath, sha256Path, sigPath, tagName, size, warnings, cleanup}>}
 */
export async function fetchSeedBundle({ base = null, fetchImpl = fetch, resolve = resolveLatestSeedAssets,
  timeouts = TIMEOUTS, maxDb = LEGACY_DB_MAX_BYTES, seam } = {}) {
  const { tagName, urls } = await resolve({ fetchImpl, timeouts });

  const dir = join(tmpdir(), `chaingate-seed-${randomBytes(6).toString('hex')}`);
  mkdirSync(dir, { mode: 0o700 });
  if (base) writeRecord(base, { schema: RECORD_SCHEMA, pid: process.pid, dir, started_at: new Date().toISOString() });
  const cleanup = () => (base ? removeDownload(base, dir) : (rmSync(dir, { recursive: true, force: true }), null));
  const warnings = [];
  try {
    const out = { dir, tagName, warnings, cleanup };
    for (const filename of SEED_FILES) {
      const isDb = !filename.endsWith('.sha256') && !filename.endsWith('.sig');
      const dest = join(dir, filename);
      const r = await downloadTo(urls[filename], dest, { filename, fetchImpl, timeouts,
        max: isDb ? maxDb : SIDECAR_MAX_BYTES,
        // space on the temporary filesystem: min(declared, H) + 8 KiB (sidecars), P2 when unknown -- H still bounds it
        onHeaders: isDb ? (declared) => {
          const adm = admit([{ dir, bytes: BigInt(Math.min(declared ?? maxDb, maxDb)) + 8192n,
            what: 'downloading the legacy seed' }], seam);
          warnings.push(...adm.warnings);
          if (!adm.ok) throw new DownloadRefused(adm.refusal, 'space');
        } : undefined });
      if (filename.endsWith('.sha256')) out.sha256Path = dest;
      else if (filename.endsWith('.sig')) out.sigPath = dest;
      else { out.dbPath = dest; out.size = r.bytes; }
    }
    return out;
  } catch (e) {
    const left = cleanup();
    if (left) e.message += `; the download directory could not be removed: ${left}`;
    throw e;
  }
}
