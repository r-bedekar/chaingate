// U-05 R2-2 (c): every small metadata file is read through ONE descriptor, judged by what that descriptor is, and never
// read past its cap. Opening by path and then trusting the path again is what let a FIFO stall a command forever, and a
// padded sidecar be read whole: `existsSync` and `lstat` describe whatever the path named at that moment, not what a
// later open receives.
//
// On POSIX the open is non-blocking, so a FIFO with no writer, or a device, returns at once and is then refused by
// `fstat`. Windows has neither O_NONBLOCK nor O_NOFOLLOW; there the open is plain and the same `fstat` decides. What a
// Windows device or pipe open does is qualified natively (R2-2 §3.3), not inferred from this file.
//
// It lives beside the reader because the reader is a self-contained consumer of seed/v3; the CLI and the witness use it
// from here.
import fs from 'node:fs';
import crypto from 'node:crypto';

/** The caps, confirmed against every shipped artefact before use (r22/caps-check.txt: the largest is 440 bytes). */
export const CAPS = Object.freeze({
  sidecar: 4096,            // a seed's .sha256 or .sig, a bundle's, or the persisted legacy pair
  manifest: 65536,          // a bundle's bundle.json
  key: 16384,               // a PEM public key named by path
  activation: 4096,         // seeds/activation.json
  intent: 4096,             // seeds/.activation-intent.json
  config: 65536,            // config.json
  marker: 4096,             // witness.db.install-pending.json
  record: 4096,             // .download-<pid>.json
});

const POSIX = process.platform !== 'win32';

/** A file refused for what it IS (not a regular file, a link where none is allowed) or for its size. */
export class FileRefused extends Error {
  constructor(path, code, why) {
    super(`${path}: ${why}`);
    this.name = 'FileRefused';
    this.code = code;           // ECG_NOT_REGULAR | ECG_IS_LINK | ECG_TOO_LARGE | ECG_TRUNCATED | ECG_GREW
    this.path = String(path);
    this.why = why;
  }
}

function kindOf(st) {
  if (st.isFIFO()) return 'a FIFO';
  if (st.isCharacterDevice()) return 'a character device';
  if (st.isBlockDevice()) return 'a block device';
  if (st.isSocket()) return 'a socket';
  if (st.isDirectory()) return 'a directory';
  if (st.isSymbolicLink()) return 'a symbolic link';
  return 'not a regular file';
}

/**
 * Open `path` read-only WITHOUT blocking, and keep the descriptor only if it is a regular file.
 * `noFollow`: refuse a symbolic link at the last component (POSIX O_NOFOLLOW; on Windows the caller's lstat decides).
 * @returns {{fd: number, size: number}}
 */
export function openRegular(path, { noFollow = false } = {}) {
  const c = fs.constants;
  const flags = POSIX ? (c.O_RDONLY | c.O_NONBLOCK | (noFollow ? c.O_NOFOLLOW : 0)) : c.O_RDONLY;
  let fd;
  try { fd = fs.openSync(path, flags); } catch (e) {
    if (noFollow && e.code === 'ELOOP') throw new FileRefused(path, 'ECG_IS_LINK', 'it is a symbolic link');
    throw e;
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw new FileRefused(path, 'ECG_NOT_REGULAR', `it is ${kindOf(st)}, not a regular file`);
    return { fd, size: st.size };
  } catch (e) { fs.closeSync(fd); throw e; }
}

/** Read at most `cap` bytes of a regular file, from offset 0 through one descriptor. More than `cap` is refused. */
export function readBoundedFd(fd, size, cap, path) {
  if (size > cap) throw new FileRefused(path, 'ECG_TOO_LARGE', `it is ${size} bytes, more than the ${cap}-byte limit`);
  const buf = Buffer.alloc(cap + 1);
  let off = 0;
  for (;;) {
    const n = fs.readSync(fd, buf, off, buf.length - off, off);
    if (n === 0) break;
    off += n;
    if (off > cap) throw new FileRefused(path, 'ECG_TOO_LARGE', `it grew past the ${cap}-byte limit while being read`);
  }
  return buf.subarray(0, off);
}

/** `readBoundedFd` for a path: opened once, non-blocking, judged by `fstat`, closed before returning. */
export function readBounded(path, cap, opts = {}) {
  const { fd, size } = openRegular(path, opts);
  try { return readBoundedFd(fd, size, cap, path); } finally { fs.closeSync(fd); }
}

/** As readBounded, but a missing file is `null` rather than an error. Anything else that is wrong still throws. */
export function readBoundedIfPresent(path, cap, opts = {}) {
  try { return readBounded(path, cap, opts); } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw e;
  }
}

/**
 * SHA-256 of exactly `length` bytes from `start`, read with EXPLICIT positions (never the descriptor's own position,
 * which an earlier pass may have exhausted). Ending early is refused: the bytes hashed are the bytes claimed.
 */
export function hashRange(fd, start, length, path = '(descriptor)') {
  const h = crypto.createHash('sha256');
  const buf = Buffer.alloc(1 << 20);
  let pos = start; let left = length;
  while (left > 0) {
    const n = fs.readSync(fd, buf, 0, Math.min(buf.length, left), pos);
    if (n === 0) throw new FileRefused(path, 'ECG_TRUNCATED', `it ended ${left} bytes before the ${length} expected`);
    h.update(buf.subarray(0, n)); pos += n; left -= n;
  }
  return h.digest('hex');
}

/** SHA-256 of a whole regular file from offset 0 to its end, through one non-blocking, type-checked descriptor. */
export function sha256Regular(path) {
  const { fd } = openRegular(path);
  try {
    const h = crypto.createHash('sha256');
    const buf = Buffer.alloc(1 << 22);
    let pos = 0;
    for (;;) {
      const n = fs.readSync(fd, buf, 0, buf.length, pos);
      if (n === 0) break;
      h.update(buf.subarray(0, n)); pos += n;
    }
    return h.digest('hex');
  } finally { fs.closeSync(fd); }
}

/** SHA-256 of bytes already read (a bounded sidecar). */
export const sha256Bytes = (b) => crypto.createHash('sha256').update(b).digest('hex');
