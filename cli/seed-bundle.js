// Versioned seed bundles, ONE authoritative activation record, and one resolution per startup.
//
// A seed is not a file. It is a BUNDLE: a database, the digest sidecar the reader verifies it
// against, the signature, and the identity those imply. Replacing part of one leaves a host running
// a combination that never existed — which is how in-place replacement produced a rollback whose
// restored database sat beside a newer sidecar the reader then refused.
//
// Three properties this file exists to hold:
//
// 1. RESOLVE ONCE. `seeds/active` is a symlink. Opening `seeds/active/db`, then
//    `seeds/active/db.sha256`, then `seeds/active/db.sig` is three separate traversals, and an
//    activation landing between them means those three opens follow DIFFERENT targets — a database
//    from one bundle checked against another's digest. Atomic replacement of the link does not help,
//    because the race is across opens, not within one. So the link is resolved ONCE, to a concrete
//    directory, and every file is then read through that pinned directory.
//
// 2. A RETAINED BUNDLE IS VERIFIED BEFORE IT IS REUSED. Content addressing makes re-installing the
//    same bytes cheap, but "a directory with that name exists" is not "a usable bundle is there":
//    the retained copy may have been damaged since. And the database bytes alone do not identify a
//    bundle — the same database signed and unsigned are different things to trust. So the id covers
//    the signature too, and a retained bundle is validated and reports ITS identity, not the
//    incoming one's.
//
// 3. ONE AUTHORITATIVE ACTIVATION RECORD. Which bundle is active is the symlink, and nothing else.
//    Identity and trust live inside the bundle it points at. Writing them into config.json as well
//    would mean two records of the same fact, and an interrupted update leaving them disagreeing —
//    the split state this design exists to avoid. config.json holds the operator's POLICY, which is
//    not a property of any bundle.
//
//    ON WINDOWS the record is a FILE, `seeds/activation.json`, holding both the active and the
//    previous bundle: a symlink cannot be renamed over an existing one there (EPERM, even as an
//    administrator), and creating one may need Developer Mode. A file IS replaced by one rename,
//    so the switch stays a single atomic step. See docs: U-04 Windows activation pointer design.
//    Linux and macOS keep the symlinks.

import { existsSync, mkdirSync, copyFileSync, writeFileSync, renameSync, rmSync,
  chmodSync, symlinkSync, readlinkSync, realpathSync, readdirSync, statSync,
  lstatSync, openSync, readSync, writeSync, fsyncSync, closeSync, rmdirSync, unlinkSync } from 'node:fs';
import { join, basename, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import Database from 'better-sqlite3';

import { sha256File, openSeed, TRUST_AUTHENTICATED,
  TRUST_UNSIGNED_DEV } from '../seed/v3/reader.js';
import { CHAINGATE_SEED_PUBKEY_B64 } from '../witness/seed_verify.js';
import { CAPS, FileRefused, openRegular, readBounded, readBoundedIfPresent, sha256Bytes, hashRange }
  from '../seed/v3/bounded-file.js';
import { admit, V3_SIDECARS } from './space-admission.js';
import { acquireSeedMutationLock, releaseSeedMutationLock, assertHeld } from './seed-mutation-lock.js';
import { probePid } from './proxy-control.js';
import { validateDownloadRecord, removeDownload } from './seed-download.js';
import { SEED_V3_FILENAME } from './constants.js';

export const SEEDS_DIRNAME = 'seeds';
export const ACTIVE_LINK = 'active';
export const PREVIOUS_LINK = 'previous';
export const BUNDLE_MANIFEST = 'bundle.json';
export const ACTIVATION_FILE = 'activation.json';
const ACTIVATION_SCHEMA = 'chaingate-activation/1';
const ACTIVATION_MAX_BYTES = 4096;
/** A bundle directory name: its 16-hex id, or a repair copy `<id>.r<n>`. Nothing else can be referenced. */
const BUNDLE_NAME = /^[0-9a-f]{16}(\.r[1-9][0-9]*)?$/;

export const seedsDir = (base) => join(base, SEEDS_DIRNAME);
export const activeLink = (base) => join(seedsDir(base), ACTIVE_LINK);
export const previousLink = (base) => join(seedsDir(base), PREVIOUS_LINK);
export const activationFile = (base) => join(seedsDir(base), ACTIVATION_FILE);

/** 'pointer' (Windows) or 'symlink' (POSIX). Tests select a mode explicitly with `{ mode }`. */
export const activationMode = (opts = {}) => opts.mode ?? (process.platform === 'win32' ? 'pointer' : 'symlink');
const isPointer = (opts) => activationMode(opts) === 'pointer';

export const bundleFiles = (dir) => ({
  db: join(dir, SEED_V3_FILENAME),
  sha256: join(dir, `${SEED_V3_FILENAME}.sha256`),
  sig: join(dir, `${SEED_V3_FILENAME}.sig`),
  manifest: join(dir, BUNDLE_MANIFEST),
});

const trustOf = (name) => (name === 'unsigned-development' ? TRUST_UNSIGNED_DEV : TRUST_AUTHENTICATED);
/** What a bounded-read refusal says (the caller names the file). */
const whyOf = (e) => (e instanceof FileRefused ? e.why : e.message);

/** What the seed itself declares, read without trusting a filename. */
export function inspectSeed(dbPath) {
  // A FIFO or device would block SQLite's open by path: it is judged on a non-blocking descriptor first (R2-2 §3.1).
  try { closeSync(openRegular(dbPath).fd); } catch (e) {
    if (!(e instanceof FileRefused)) throw e;
    return { schemaVersion: null, corpusSnapshotDigest: null, contractVersion: null, refused: e.why };
  }
  const db = new Database(dbPath, { readonly: true, fileMustExist: true });
  try {
    const has = db.prepare(
      "SELECT 1 FROM sqlite_master WHERE type='table' AND name='seed_metadata'").get();
    if (!has) return { schemaVersion: null, corpusSnapshotDigest: null, contractVersion: null };
    const get = (k) => (db.prepare('SELECT value FROM seed_metadata WHERE key = ?').get(k)
      || {}).value ?? null;
    const raw = get('schema_version');
    const n = raw === null ? null : Number.parseInt(String(raw).trim(), 10);
    return {
      schemaVersion: Number.isInteger(n) ? n : null,
      corpusSnapshotDigest: get('corpus_snapshot_digest'),
      contractVersion: get('contract_version'),
    };
  } catch { return { schemaVersion: null, corpusSnapshotDigest: null, contractVersion: null }; }
  finally { db.close(); }
}

export const isV3Seed = (dbPath) => inspectSeed(dbPath).schemaVersion === 3;

/**
 * A bundle's identity covers the SIGNATURE as well as the database.
 *
 * Keying on the database digest alone made the same bytes signed and unsigned collide on one id —
 * two bundles a host must treat differently, sharing a directory and a manifest.
 */
export function bundleIdOf(dbDigest, sigDigest) {
  return createHash('sha256')
    .update(`${dbDigest}\n${sigDigest || 'unsigned'}`).digest('hex').slice(0, 16);
}

/**
 * Open a bundle directory the way the proxy will and report what it ACTUALLY is.
 * @returns {{ok: boolean, why: string|null, identity: object|null}}
 */
export function verifyBundleDir(dir, { trust } = {}) {
  const f = bundleFiles(dir);
  for (const [k, p] of Object.entries(f)) {
    if (k === 'sig') continue;                       // optional
    if (!existsSync(p)) return { ok: false, why: `missing ${basename(p)}`, identity: null };
  }
  let manifest = null;
  try { manifest = JSON.parse(readBounded(f.manifest, CAPS.manifest).toString('utf8')); }
  catch (e) { return { ok: false, why: `unreadable ${BUNDLE_MANIFEST}: ${whyOf(e)}`, identity: null }; }

  let dbDigest;
  try { dbDigest = sha256File(f.db); } catch (e) {
    if (!(e instanceof FileRefused)) throw e;
    return { ok: false, why: `${basename(f.db)}: ${e.why}`, identity: null };
  }
  if (manifest.sha256 !== dbDigest) {
    return { ok: false, identity: null,
      why: `database digest ${dbDigest.slice(0, 16)}... does not match the manifest's `
        + `${String(manifest.sha256).slice(0, 16)}...` };
  }
  // The signature is hashed from at most CAPS.sidecar bytes: this is its first access, before the reader's cap.
  let sigDigest = null;
  try { const b = readBoundedIfPresent(f.sig, CAPS.sidecar); sigDigest = b ? sha256Bytes(b) : null; }
  catch (e) { return { ok: false, why: `${basename(f.sig)}: ${whyOf(e)}`, identity: null }; }
  const id = bundleIdOf(dbDigest, sigDigest);
  if (basename(dir) !== id && manifest.bundle_id !== id) {
    return { ok: false, identity: null,
      why: `bundle contents hash to ${id}, which is neither the directory name nor the manifest id` };
  }

  // The check that matters: does the READER accept it, under the trust this bundle claims?
  const claimedTrust = trust || manifest.trust;
  let authenticated = false;
  try {
    const seed = openSeed(f.db, { trust: trustOf(claimedTrust), pubkey: CHAINGATE_SEED_PUBKEY_B64 });
    try { authenticated = Boolean(seed.report?.authenticated); } finally { seed.close(); }
  } catch (e) {
    return { ok: false, why: `the reader refuses it: ${e.message}`, identity: null };
  }
  const info = inspectSeed(f.db);
  return {
    ok: true,
    why: null,
    identity: {
      ...manifest,
      bundle_id: id,
      sha256: dbDigest,
      signature_sha256: sigDigest,
      signed: sigDigest !== null,
      authenticated,
      trust: claimedTrust,
      schema_version: info.schemaVersion,
      contract_version: info.contractVersion,
      corpus_snapshot_digest: info.corpusSnapshotDigest,
    },
  };
}

/** Refused before or while staging: the input itself, the space for it, or the copy. Nothing in use was touched. */
export class StagingRefused extends Error {
  constructor(message, kind) { super(message); this.name = 'StagingRefused'; this.kind = kind; }
}

/**
 * Copy EXACTLY `size` bytes of the open source `fd`, from offset 0 with explicit positions, into the NEW file `dest`
 * (created exclusively, 0600). Ending before `size` is refused, and so is data at offset `size` (the source grew): the
 * staged copy is the source as it was when opened, or nothing. fsynced before it returns.
 * `hooks` (tests only, inert otherwise): beforeStagingWrite(pos), midStagingCopy(pos).
 */
export function copyFdExact(fd, size, dest, source, hooks = {}) {
  const out = openSync(dest, 'wx', 0o600);
  try {
    const buf = Buffer.alloc(1 << 20);
    let pos = 0;
    while (pos < size) {
      const n = readSync(fd, buf, 0, Math.min(buf.length, size - pos), pos);
      if (n === 0) {
        throw new FileRefused(source, 'ECG_TRUNCATED', `it ended at byte ${pos}, before the ${size} bytes it had when opened`);
      }
      hooks.beforeStagingWrite?.(pos);
      let w = 0;
      while (w < n) w += writeSync(out, buf, w, n - w, pos + w);
      pos += n;
      hooks.midStagingCopy?.(pos);
    }
    if (readSync(fd, Buffer.alloc(1), 0, 1, size) > 0) {
      throw new FileRefused(source, 'ECG_GREW', `it grew past the ${size} bytes it had when opened`);
    }
    fsyncSync(out);
  } finally { closeSync(out); }
}

const removeStaging = (dir) => {
  try { rmSync(dir, { recursive: true, force: true }); return null; } catch (e) { return `${dir} (${e.code || e.message})`; }
};

/**
 * PRIVATE STAGING (U-05 R2-2 (d); Addendum 1 §4). The caller-supplied seed is opened ONCE, as a regular file, without
 * blocking; its sidecars are read once, bounded; space is admitted; exactly its opened size is copied into a new
 * `seeds/.staging-<pid>-<ms>/`; and the source is never read again. Everything after this -- the digest, the
 * classification (SQLite opens only the STAGED copy), the signature -- describes the staged bytes.
 *
 * A catchable failure removes the staging directory (or names what remains). The caller calls `discard()` when done;
 * after `finishStagedBundle` has moved the directory into place there is nothing left to discard.
 *
 * @param {{sidecars?: {sha256Path: string|null, sigPath: string|null}, seam?: object, hooks?: object, lock: object}} opts
 *   `lock`: the live seed-mutation token for `base` (required).
 */
export function stageIncoming(seedPath, base, { sidecars, seam, hooks = {}, lock } = {}) {
  assertHeld(lock, base);                                  // R2-2 (b): staging happens under the seed-mutation lock
  let src;
  try { src = openRegular(seedPath); } catch (e) {
    throw new StagingRefused(e instanceof FileRefused ? `${seedPath}: ${e.why}` : `cannot open ${seedPath}: ${e.code || e.message}`, 'input');
  }
  let dir = null;
  try {
    const size = src.size;
    const side = sidecars ?? { sha256Path: `${seedPath}.sha256`, sigPath: `${seedPath}.sig` };
    let sha256Bytes; let sigBytes;
    try {
      sha256Bytes = side.sha256Path ? readBoundedIfPresent(side.sha256Path, CAPS.sidecar) : null;
      sigBytes = side.sigPath ? readBoundedIfPresent(side.sigPath, CAPS.sidecar) : null;
    } catch (e) { throw new StagingRefused(e instanceof FileRefused ? `${e.path}: ${e.why}` : e.message, 'input'); }

    mkdirSync(seedsDir(base), { recursive: true });
    const adm = admit([{ dir: seedsDir(base), bytes: BigInt(size) + V3_SIDECARS, what: 'staging the seed' }], seam);
    if (!adm.ok) throw new StagingRefused(adm.refusal, 'space');

    dir = join(seedsDir(base), `.staging-${process.pid}-${Date.now()}`);
    mkdirSync(dir, { mode: 0o700 });
    const files = bundleFiles(dir);
    try { copyFdExact(src.fd, size, files.db, seedPath, hooks); } catch (e) {
      throw new StagingRefused(e instanceof FileRefused ? `${seedPath}: ${e.why}`
        : `copying ${seedPath} failed (${e.code || e.name}): ${e.message}`, e instanceof FileRefused ? 'input' : 'copy');
    }
    closeSync(src.fd); src = null;                      // the source is not read again
    hooks.afterStagingCopy?.();

    const staged = openRegular(files.db);
    let digest;
    try {
      if (staged.size !== size) throw new StagingRefused(`the staged copy is ${staged.size} bytes, not ${size}`, 'copy');
      digest = hashRange(staged.fd, 0, size, files.db);
    } finally { closeSync(staged.fd); }
    const info = inspectSeed(files.db);
    const owned = dir;
    return { dir, files, size, digest, sha256Bytes, sigBytes, info, warnings: adm.warnings, source: seedPath,
      discard: () => removeStaging(owned) };
  } catch (e) {
    if (dir) {
      const left = removeStaging(dir);
      if (left) e.message += `; the staging copy could not be removed: ${left}`;
    }
    throw e;
  } finally { if (src) closeSync(src.fd); }
}

/**
 * Finish a privately staged v3 seed into a bundle: the runtime writes the digest sidecar and the manifest, the .sig is
 * written from the bounded bytes, the READER validates it, and it is moved into place -- installed but NOT active.
 * Nothing in use is touched. Returns the identity of the bundle now on disk, which, when an equivalent bundle was
 * already retained, is THAT bundle's verified identity rather than the incoming copy's assumed one.
 */
export function finishStagedBundle(staged, base, { trust, lock } = {}) {
  assertHeld(lock, base);
  const { dir: staging, files: out, digest: dbDigest, sha256Bytes: claimedBytes, sigBytes, info } = staged;
  if (info.schemaVersion !== 3) {
    throw new Error(`not a v3 seed: schema_version=${JSON.stringify(info.schemaVersion)}`);
  }
  try {
    if (claimedBytes !== null) {
      const claimed = claimedBytes.toString('utf8').trim().split(/\s+/)[0];
      if (claimed !== dbDigest) {
        throw new Error(`bundle digest ${claimed.slice(0, 16)}... does not describe the bytes supplied `
          + `(${dbDigest.slice(0, 16)}...)`);
      }
    }
    writeFileSync(out.sha256, `${dbDigest}  ${SEED_V3_FILENAME}\n`);
    if (sigBytes !== null) writeFileSync(out.sig, sigBytes);
    const sigDigest = sigBytes !== null ? sha256Bytes(sigBytes) : null;
    const id = bundleIdOf(dbDigest, sigDigest);

    writeFileSync(out.manifest, `${JSON.stringify({
      bundle_id: id, sha256: dbDigest, signature_sha256: sigDigest, signed: sigDigest !== null,
      trust, schema_version: info.schemaVersion, contract_version: info.contractVersion,
      corpus_snapshot_digest: info.corpusSnapshotDigest, size_bytes: staged.size,
      staged_at: new Date().toISOString(),
    }, null, 2)}\n`);

    const verdict = verifyBundleDir(staging, { trust });
    if (!verdict.ok) throw new Error(`staged bundle is not usable: ${verdict.why}`);

    // BUNDLE DIRECTORIES ARE IMMUTABLE ONCE PLACED. A running process may have pinned this exact
    // directory (resolve-once), so repairing a damaged bundle by replacing its directory in place
    // would pull the ground out from under that process — the very thing pinning exists to prevent.
    // A repair therefore goes into a FRESH physical directory and is activated normally; the damaged
    // one is left alone for whoever is still reading it, and `chaingate doctor` reports it.
    let dest = join(seedsDir(base), id);
    let replacedDamaged = null;
    if (existsSync(dest)) {
      // A bundle with this id is retained. VERIFY IT rather than assume it: the copy on disk may
      // have been damaged since it was installed, and reusing a damaged bundle because its name
      // matched would activate something no one checked.
      const retained = verifyBundleDir(dest, { trust });
      if (retained.ok) {
        return { ...retained.identity, dir: dest, dir_name: basename(dest),
          path: bundleFiles(dest).db, reused: true };
      }
      replacedDamaged = retained.why;
      let n = 2;
      while (existsSync(join(seedsDir(base), `${id}.r${n}`))) n += 1;
      dest = join(seedsDir(base), `${id}.r${n}`);
    }

    renameSync(staging, dest);
    for (const f of Object.values(bundleFiles(dest))) if (existsSync(f)) chmodSync(f, 0o444);
    const placed = verifyBundleDir(dest, { trust });
    if (!placed.ok) throw new Error(`installed bundle is not usable: ${placed.why}`);
    return { ...placed.identity, dir: dest, dir_name: basename(dest), path: bundleFiles(dest).db,
      reused: false, ...(replacedDamaged ? { replaced_damaged: replacedDamaged } : {}) };
  } finally {
    removeStaging(staging);
  }
}

/**
 * Stage a complete bundle from paths, validate it WITH THE READER, and leave it installed but NOT active: private
 * staging (stageIncoming) followed by finishStagedBundle. Kept for callers that hold paths (tests, the seed tooling).
 */
export function stageBundle({ dbPath, sha256Path = null, sigPath = null }, base, { trust, seam, hooks, lock } = {}) {
  return underLock(base, { hooks, lock }, (token) => {
    const staged = stageIncoming(dbPath, base, { sidecars: { sha256Path, sigPath }, seam, hooks, lock: token });
    try { return finishStagedBundle(staged, base, { trust, lock: token }); } finally { staged.discard(); }
  });
}

/**
 * THE activation record. One swap, and nothing else records which bundle is active — so there is
 * no second copy of the fact to fall out of step with it. POSIX: a symlink swap. Windows: one file
 * replace (see activatePointer).
 */
export function activateBundle(base, dirName, opts = {}) {
  return underLock(base, opts, (lock) => {
    const dir = join(seedsDir(base), dirName);
    const verdict = verifyBundleDir(dir);
    if (!verdict.ok) throw new Error(`refusing to activate ${dirName}: ${verdict.why}`);
    if (isPointer(opts)) return { ...verdict.identity, dir_name: dirName, ...activatePointer(base, dirName, opts) };

    refuseForeignPointer(base);
    const current = activeBundleId(base, opts);
    opts.hooks?.afterActiveRead?.();
    const previousNow = previousBundleId(base, opts);
    // POSIX: two renames, so the intent is published FIRST (R2-2 §2.2 option B; Addendum 1 §2.1). After any kill the
    // next mutator recovers (active, previous) to exactly this before or after state.
    const after = { active: dirName, previous: current && current !== dirName ? current : previousNow };
    writeIntent(base, { schema: INTENT_SCHEMA, op: opts.op ?? 'activate',
      before: { active: current, previous: previousNow }, after, pid: process.pid, at: new Date().toISOString() });
    opts.hooks?.afterIntentPublish?.();                                           // K0
    if (current && current !== dirName) {
      // remember what to roll back TO, before the swap rather than after it
      const tmpPrev = `${previousLink(base)}.switching-${process.pid}`;
      rmSync(tmpPrev, { force: true });
      symlinkSync(current, tmpPrev);
      renameSync(tmpPrev, previousLink(base));
    }
    opts.hooks?.betweenRenames?.();                                               // K1
    const link = activeLink(base);
    const tmp = `${link}.switching-${process.pid}`;
    rmSync(tmp, { force: true });
    symlinkSync(dirName, tmp);             // relative: the tree can be moved or mounted elsewhere
    renameSync(tmp, link);                 // ATOMIC replace
    opts.hooks?.afterActiveSwap?.();                                              // K2
    fsyncDir(seedsDir(base));
    removeIntent(base);
    return { ...verdict.identity, dir_name: dirName };
  });
}

/**
 * Windows: write the COMPLETE next state to a temporary file, flush it, then rename it over
 * activation.json. The working record is never removed first: if the write or the rename fails, the
 * previous record (or the legacy links) is untouched and still usable. Legacy symlinks from an older
 * client are removed only AFTER the new record is in place.
 */
function activatePointer(base, dirName, opts) {
  const fsx = { renameSync, ...(opts.fsImpl || {}) };
  const state = currentPointerState(base);            // activation.json, or the legacy links (migration)
  opts.hooks?.afterActiveRead?.();
  const next = {
    schema: ACTIVATION_SCHEMA,
    active: dirName,
    previous: state.active && state.active !== dirName ? state.active : (state.previous ?? null),
    updated_at: new Date().toISOString(),
  };
  const file = activationFile(base);
  const tmp = `${file}.tmp-${process.pid}`;
  try {
    const fd = openSync(tmp, 'w');
    try { writeSync(fd, `${JSON.stringify(next, null, 2)}\n`); fsyncSync(fd); } finally { closeSync(fd); }
    opts.hooks?.afterPointerTempWrite?.();
    fsx.renameSync(tmp, file);                         // ONE step: the old record until it succeeds
  } catch (err) {
    rmSync(tmp, { force: true });
    throw err;
  }
  const warnings = [];
  for (const link of [activeLink(base), previousLink(base)]) {
    if (!lstatOrNull(link)) continue;
    try { removeLink(link); } catch (e) {
      warnings.push(`could not remove the legacy activation link ${link} (${e.code || e.message}); `
        + `${ACTIVATION_FILE} is authoritative, but older ChainGate versions would still read the link`);
    }
  }
  // Leftover temporaries of OTHER processes are not removed here: under the lock, at the start of the next mutator,
  // only those of dead processes older than 15 minutes are (cleanLeftovers).
  return { previous: next.previous, record: ACTIVATION_FILE, ...(warnings.length ? { warnings } : {}) };
}

/** Roll the one activation record back to the bundle it pointed at before. */
export function rollbackActivation(base, opts = {}) {
  return underLock(base, opts, (lock) => {
    const prev = previousBundleId(base, opts);
    opts.hooks?.afterPreviousRead?.();
    if (!prev) return null;
    const verdict = verifyBundleDir(join(seedsDir(base), prev));
    if (!verdict.ok) throw new Error(`refusing to roll back to ${prev}: ${verdict.why}`);
    return activateBundle(base, prev, { ...opts, lock, op: 'rollback' });
  });
}

const lstatOrNull = (p) => { try { return lstatSync(p); } catch { return null; } };
const linkTarget = (p) => { try { return basename(readlinkSync(p)); } catch { return null; } };
function removeLink(p) {
  try { rmSync(p, { force: true }); } catch (e) {
    if (e.code === 'EPERM' || e.code === 'EISDIR' || e.code === 'ERR_FS_EISDIR') rmdirSync(p); else throw e;
  }
  if (lstatOrNull(p)) rmdirSync(p);                    // a Windows directory link some APIs leave behind
}
// ---- U-05 R2-2 (b): the intent journal, its recovery, and conservative cleanup, all under the seed-mutation lock ----

export const INTENT_FILE = '.activation-intent.json';
const INTENT_SCHEMA = 'chaingate-activation-intent/1';
export const intentFile = (base) => join(seedsDir(base), INTENT_FILE);

/** fsync a directory so a rename or unlink in it is durable (best effort; Windows cannot fsync a directory). */
function fsyncDir(dir) {
  if (process.platform === 'win32') return;
  const fd = openSync(dir, 'r');
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function writeIntent(base, rec) {
  const tmp = `${intentFile(base)}.tmp-${process.pid}`;
  rmSync(tmp, { force: true });
  const fd = openSync(tmp, 'wx', 0o600);
  try { writeSync(fd, `${JSON.stringify(rec)}\n`); fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(tmp, intentFile(base));
  fsyncDir(seedsDir(base));
}

function removeIntent(base) {
  try { unlinkSync(intentFile(base)); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  fsyncDir(seedsDir(base));
}

/**
 * The activation intent, read-only and bounded (doctor and status may call this without the lock; it repairs nothing).
 * @returns {{state: 'none'} | {state: 'pending', intent: object} | {state: 'invalid', why: string}}
 */
export function readActivationIntent(base) {
  const file = intentFile(base);
  const st = lstatOrNull(file);
  if (!st) return { state: 'none' };
  const invalid = (why) => ({ state: 'invalid', why });
  if (!st.isFile()) return invalid('it is not a regular file');
  let rec;
  try { rec = JSON.parse(readBounded(file, CAPS.intent, { noFollow: true }).toString('utf8')); }
  catch (e) { return invalid(e instanceof FileRefused ? e.why : `unreadable or not JSON: ${e.message}`); }
  if (!rec || typeof rec !== 'object' || Array.isArray(rec)) return invalid('not a JSON object');
  if (rec.schema !== INTENT_SCHEMA) return invalid(`unknown schema ${JSON.stringify(rec.schema)}`);
  const name = (v, nullable) => (v === null && nullable) || (typeof v === 'string' && BUNDLE_NAME.test(v));
  for (const side of ['before', 'after']) {
    const r = rec[side];
    if (!r || typeof r !== 'object') return invalid(`${side} is missing`);
    if (!name(r.active, side === 'before')) return invalid(`${side}.active ${JSON.stringify(r.active)} is not a bundle name`);
    if (!name(r.previous, true)) return invalid(`${side}.previous ${JSON.stringify(r.previous)} is not a bundle name`);
  }
  return { state: 'pending', intent: rec };
}

/** Recovery refused: nothing was changed, and the intent is kept (Addendum 1 §2.2, Addendum 2 §3.1). */
export class ActivationRecoveryRefused extends Error {
  constructor(message) { super(message); this.name = 'ActivationRecoveryRefused'; }
}

/**
 * Recover an interrupted symlink activation, FIRST in every mutator and under the lock (Addendum 1 §2.2 as corrected by
 * Addendum 2 §3.1). It writes only the `previous` link, never `active`, so repeated interruption and retry converge:
 *   active = after.active  -> previous = after.previous  (the operation took effect: roll forward)
 *   active = before.active -> previous = before.previous (it did not: roll back)
 *   anything else          -> refuse; active was moved outside this protocol (e.g. by an older client)
 * A target bundle that no longer exists, or an intent that is not valid, refuses with the intent and the links kept.
 */
export function recoverActivation(base, opts = {}) {
  const r = readActivationIntent(base);
  if (r.state === 'none') return { state: 'none' };
  const file = intentFile(base);
  if (r.state === 'invalid') {
    throw new ActivationRecoveryRefused(`the activation intent ${file} is not valid (${r.why}). Nothing was changed, `
      + 'and it is kept as evidence. Inspect `chaingate status` and `chaingate doctor --json`; then, as a deliberate '
      + `step, archive it by renaming it to ${INTENT_FILE}.held-<UTC timestamp> (nothing deletes it for you).`);
  }
  if (isPointer(opts)) {
    throw new ActivationRecoveryRefused(`an activation intent ${file} exists, but this platform records activation in `
      + `${ACTIVATION_FILE}, not in links. Nothing was changed. Archive it by renaming it to ${INTENT_FILE}.held-<UTC timestamp>.`);
  }
  const { before, after } = r.intent;
  const current = linkTarget(activeLink(base));
  let target;
  if (current === after.active) target = after.previous;
  else if (current === before.active) target = before.previous;
  else {
    throw new ActivationRecoveryRefused(`the active bundle is ${current ?? '(none)'}, which is neither the interrupted `
      + `activation's starting point (${before.active ?? '(none)'}) nor its target (${after.active}): it was changed `
      + `outside this protocol, for example by an older ChainGate. The intent ${file} is kept; nothing was changed.`);
  }
  opts.hooks?.duringRecovery?.();
  if (linkTarget(previousLink(base)) !== target) {
    if (target === null) removeLink(previousLink(base));
    else {
      const ds = lstatOrNull(join(seedsDir(base), target));
      if (!ds || !ds.isDirectory()) {
        throw new ActivationRecoveryRefused(`recovering the interrupted activation needs bundle ${target} as the rollback `
          + `target, and it no longer exists. The intent ${file} and the activation links are kept; nothing was changed.`);
      }
      const tmp = `${previousLink(base)}.switching-${process.pid}`;
      rmSync(tmp, { force: true });
      symlinkSync(target, tmp);
      renameSync(tmp, previousLink(base));
    }
  }
  fsyncDir(seedsDir(base));
  removeIntent(base);
  return { state: 'recovered', active: current, previous: target };
}

// Leftovers this runtime can create, by exact name, each carrying the creating pid (Addendum 1 §3.3).
const OWNED = {
  seeds: [
    { re: /^\.staging-(\d+)-\d+$/, kind: 'dir' },
    { re: /^(?:active|previous)\.switching-(\d+)$/, kind: 'link' },
    { re: /^activation\.json\.tmp-(\d+)$/, kind: 'file' },
    { re: /^\.activation-intent\.json\.tmp-(\d+)$/, kind: 'file' },
  ],
  base: [
    { re: /^witness\.db\.staging-(\d+)$/, kind: 'file' },
    { re: /^witness\.db\.(?:sha256|sig)\.staging-(\d+)$/, kind: 'file' },
    { re: /^witness\.db\.install-pending\.json\.tmp-(\d+)$/, kind: 'file' },
    { re: /^\.download-(\d+)\.json$/, kind: 'download' },
  ],
};
/** A conservative DELAY, not proof against PID reuse: young leftovers may survive and are reported (Addendum 2 §3.4). */
export const LEFTOVER_MIN_AGE_MS = 15 * 60 * 1000;
// What else legitimately lives in seeds/: bundles, repair copies, damaged bundles, the records, held evidence.
const KNOWN_IN_SEEDS = (n) => BUNDLE_NAME.test(n) || /^[0-9a-f]{16}(\.r[1-9][0-9]*)?\.damaged-/.test(n)
  || [ACTIVE_LINK, PREVIOUS_LINK, ACTIVATION_FILE, INTENT_FILE].includes(n) || n.startsWith(`${INTENT_FILE}.held-`);

function classifyLeftovers(base, { now = Date.now(), probe = probePid } = {}) {
  const owned = []; const unrecognised = [];
  for (const [where, dir] of [['seeds', seedsDir(base)], ['base', base]]) {
    let names = [];
    try { names = readdirSync(dir); } catch { continue; }
    for (const n of names) {
      const full = join(dir, n);
      const hit = OWNED[where].map((p) => [p, n.match(p.re)]).find(([, m]) => m);
      if (!hit) { if (where === 'seeds' && !KNOWN_IN_SEEDS(n)) unrecognised.push(full); continue; }
      const [p, m] = hit; const pid = Number(m[1]);
      const st = lstatOrNull(full);
      if (!st) continue;
      const typeOk = p.kind === 'dir' ? st.isDirectory() : p.kind === 'link' ? st.isSymbolicLink() : st.isFile();
      let record = null;
      let keep = null;
      if (!typeOk) keep = 'not the kind of entry that name belongs to';
      else if (pid === process.pid) keep = 'this process';
      else {
        const live = probe(pid);
        if (live.state === 'alive') keep = `process ${pid} is alive`;
        else if (live.state !== 'dead') keep = `process ${pid} could not be checked (${live.code})`;
        else if (now - st.mtimeMs < LEFTOVER_MIN_AGE_MS) keep = 'younger than 15 minutes';
        else if (p.kind === 'download') {
          // a download record names a directory outside the base: it is validated before anything is removed
          record = validateDownloadRecord(full);
          if (record.keep) keep = `its record is not usable (${record.keep})`;
        }
      }
      owned.push({ path: full, kind: p.kind, keep, pid, record });
    }
  }
  return { owned, unrecognised };
}

/**
 * Remove leftovers of DEAD mutators, under the lock, at the start of every mutator: an exact owned name carrying a pid
 * that probes dead, older than 15 minutes, of the expected kind, and not this process's. Everything else is kept.
 * This is not pruning: no bundle is ever removed. A failed removal is reported with its path, never as removed.
 */
export function cleanLeftovers(base, opts = {}) {
  assertHeld(opts.lock, base);
  const { owned } = classifyLeftovers(base, opts);
  const out = { removed: [], kept: [], failed: [] };
  for (const e of owned) {
    if (e.keep) { out.kept.push({ path: e.path, why: e.keep }); continue; }
    try {
      if (e.kind === 'download') {
        // the recorded directory FIRST; the record only once that removal succeeded (Addendum 2 §3.4)
        const left = removeDownload(base, e.record.dir, e.pid);
        if (left) { out.failed.push({ path: e.path, why: `could not remove ${left}` }); continue; }
        out.removed.push(e.record.dir, e.path);
        continue;
      }
      if (e.kind === 'dir') rmSync(e.path, { recursive: true });
      else if (e.kind === 'link') removeLink(e.path);
      else unlinkSync(e.path);
      out.removed.push(e.path);
    } catch (err) { out.failed.push({ path: e.path, why: err.code || err.message }); }
  }
  return out;
}

/** Read-only, for doctor: owned leftovers still present (and why each is kept) and unrecognised entries in seeds/. */
export function surveyLeftovers(base) {
  const { owned, unrecognised } = classifyLeftovers(base);
  return { owned: owned.map((e) => ({ path: e.path, why: e.keep ?? 'removable by the next seed command' })), unrecognised };
}

/**
 * Hold the lock for the duration of `fn(token)`, after RECOVERY and CLEANUP (in that order) - the prologue every mutator
 * runs. `report(lines)` receives what recovery and cleanup did.
 */
export function withSeedMutationSync(base, fn, opts = {}) {
  const token = acquireSeedMutationLock(base);
  try {
    const rec = recoverActivation(base, opts);
    const cl = cleanLeftovers(base, { lock: token });
    opts.report?.({ recovery: rec, cleanup: cl });
    return fn(token);
  } finally { releaseSeedMutationLock(token); }
}

/** As withSeedMutationSync, for an async body (the commands). */
export async function withSeedMutation(base, fn, opts = {}) {
  const token = acquireSeedMutationLock(base);
  try {
    const rec = recoverActivation(base, opts);
    const cl = cleanLeftovers(base, { lock: token });
    opts.report?.({ recovery: rec, cleanup: cl });
    return await fn(token);
  } finally { releaseSeedMutationLock(token); }
}

/** A given token must be live for `base`; without one, the call takes the lock (and runs the prologue) itself. */
function underLock(base, opts, fn) {
  if (opts.lock) { assertHeld(opts.lock, base); return fn(opts.lock); }
  return withSeedMutationSync(base, fn, opts);
}

/**
 * Read and STRICTLY validate activation.json. null when it does not exist. Anything else that is
 * wrong with it throws ActivationBroken: a broken pointer never falls back to an older record.
 */
export function readActivationPointer(base, opts = {}) {
  const file = activationFile(base);
  const st = lstatOrNull(file);
  if (!st) return null;
  const broken = (why) => new ActivationBroken(file, why);
  if (!st.isFile()) throw broken('it is not a regular file');
  if (st.size > ACTIVATION_MAX_BYTES) throw broken(`it is ${st.size} bytes, more than ${ACTIVATION_MAX_BYTES}`);
  opts.hooks?.afterLstat?.();                          // test seam (R2-2 C6c); inert otherwise
  // What lstat saw is not what an open receives: the decision is taken again on the DESCRIPTOR, which must be a regular
  // file (O_NOFOLLOW on POSIX) of at most ACTIVATION_MAX_BYTES, read through that descriptor only.
  let bytes;
  try { bytes = readBounded(file, ACTIVATION_MAX_BYTES, { noFollow: true }); }
  catch (e) { throw broken(e instanceof FileRefused ? e.why : `unreadable: ${e.message}`); }
  let rec;
  try { rec = JSON.parse(bytes.toString('utf8')); } catch (e) { throw broken(`unreadable or not JSON: ${e.message}`); }
  if (!rec || typeof rec !== 'object' || Array.isArray(rec)) throw broken('not a JSON object');
  if (rec.schema !== ACTIVATION_SCHEMA) throw broken(`unknown schema ${JSON.stringify(rec.schema)}`);
  const ref = (role, name, nullable) => {
    if (name === null && nullable) return null;
    if (typeof name !== 'string' || !BUNDLE_NAME.test(name)) throw broken(`${role} ${JSON.stringify(name)} is not a bundle name`);
    const dir = join(seedsDir(base), name);
    const ds = lstatOrNull(dir);
    if (!ds || !ds.isDirectory()) throw broken(`${role} bundle ${name} is not a directory in ${seedsDir(base)}`);
    let real;
    try { real = realpathSync(dir); } catch (e) { throw broken(`${role} bundle ${name}: ${e.code || e.message}`); }
    if (dirname(real) !== realpathSync(seedsDir(base))) throw broken(`${role} bundle ${name} resolves outside ${seedsDir(base)}`);
    return name;
  };
  return { active: ref('active', rec.active, false), previous: ref('previous', rec.previous ?? null, true) };
}

/** The current state for the NEXT pointer write: the pointer if present, else the legacy links. */
function currentPointerState(base) {
  const p = readActivationPointer(base);
  if (p) return p;
  return { active: linkTarget(activeLink(base)), previous: linkTarget(previousLink(base)) };
}

/** POSIX: a Windows pointer record here is not something this platform writes; fail closed on it. */
function refuseForeignPointer(base) {
  if (lstatOrNull(activationFile(base))) {
    throw new ActivationBroken(activationFile(base),
      'a Windows activation record (activation.json) exists on this platform, which records activation as symlinks');
  }
}

export const activeBundleId = (base, opts = {}) => {
  if (isPointer(opts)) { const p = readActivationPointer(base); return p ? p.active : linkTarget(activeLink(base)); }
  refuseForeignPointer(base);
  return linkTarget(activeLink(base));
};
export const previousBundleId = (base, opts = {}) => {
  if (isPointer(opts)) { const p = readActivationPointer(base); return p ? p.previous : linkTarget(previousLink(base)); }
  refuseForeignPointer(base);
  return linkTarget(previousLink(base));
};

/** Windows: activation.json and an older client's symlink both present (the link is stale). */
export function staleLegacyLink(base, opts = {}) {
  if (!isPointer(opts) || !lstatOrNull(activationFile(base))) return null;
  const links = [activeLink(base), previousLink(base)].filter((l) => lstatOrNull(l));
  return links.length ? links : null;
}

export class ActivationBroken extends Error {
  constructor(link, why) {
    super(`chaingate: the activation link ${link} exists but does not resolve: ${why}\n`
      + '  A host that HAS activated a bundle must not read as "no seed configured": that turns a\n'
      + '  broken link into silently disabled detection.\n'
      + (String(link).endsWith(ACTIVATION_FILE)
        ? `  Fix: remove ${link} (it is not usable and is never guessed around), then run\n`
          + '  `chaingate init --seed <bundle>` to record a bundle explicitly.'
        : '  Fix: re-run `chaingate init --seed <bundle>`, or `chaingate update-seed --rollback`.'));
    this.name = 'ActivationBroken';
    this.link = link;
  }
}

/**
 * RESOLVE ONCE. The caller pins this directory for the life of the process and reads every file
 * through it, so a concurrent activation cannot make two opens follow different bundles.
 *
 * `null` means NO link — a host that has never activated a bundle, which is a legitimate state.
 * A link that exists but does not resolve is a different thing entirely and throws: `existsSync`
 * follows symlinks, so a dangling one answered "false" and the caller read that as "no seed",
 * silently turning detection off on a host that had activated one. `lstat` asks about the link
 * itself, which is the question being asked here.
 */
export function resolveActiveBundle(base, opts = {}) {
  if (isPointer(opts)) {
    const p = readActivationPointer(base);            // throws ActivationBroken on a bad record
    if (p) {
      const dir = realpathSync(join(seedsDir(base), p.active));
      if (!existsSync(bundleFiles(dir).db)) {
        throw new ActivationBroken(activationFile(base), `it names ${p.active}, which holds no ${SEED_V3_FILENAME}`);
      }
      return { id: basename(dir), dir, files: bundleFiles(dir) };
    }
    // no pointer yet: an install made before 0.1.2 is read through its legacy links, as below
  } else {
    refuseForeignPointer(base);
  }
  const link = activeLink(base);
  let linkStat = null;
  try { linkStat = lstatSync(link); } catch { return null; }      // genuinely absent
  if (!linkStat.isSymbolicLink() && !linkStat.isDirectory()) {
    throw new ActivationBroken(link, 'it is neither a symlink nor a directory');
  }
  let dir;
  try { dir = realpathSync(link); } catch (err) {
    throw new ActivationBroken(link, `${err.code || err.name}: ${err.message}`);
  }
  if (!existsSync(bundleFiles(dir).db)) {
    throw new ActivationBroken(link, `it resolves to ${dir}, which holds no ${SEED_V3_FILENAME}`);
  }
  return { id: basename(dir), dir, files: bundleFiles(dir) };
}

/** Every installed bundle, newest first. Previous bundles are KEPT: rollback needs them. */
export function listBundles(base) {
  const dir = seedsDir(base);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((n) => ![ACTIVE_LINK, PREVIOUS_LINK, ACTIVATION_FILE].includes(n) && !n.startsWith('.')
      && !n.includes('.damaged-') && !n.includes('.switching-') && !n.startsWith(`${ACTIVATION_FILE}.tmp-`))
    .map((id) => {
      const v = verifyBundleDir(join(dir, id));
      return { id, usable: v.ok, why: v.why, ...(v.identity || {}) };
    })
    .sort((a, b) => String(b.staged_at).localeCompare(String(a.staged_at)));
}
