// U-05 R2-2 (b): ONE lock per installation base, taken by every seed mutator (install, update, rollback, the legacy
// routes) before its first decision-bearing read, and held until it is done (R2-2 §2.1, Addendum 1 §3.1).
//
// The lock is a SQLite database file, `<base>/.seed-mutation.lock`, held by `BEGIN EXCLUSIVE` on a dedicated connection.
// The OPERATING SYSTEM releases it when the process dies (fcntl on POSIX, LockFileEx on Windows), so there is no
// takeover logic, no stale-owner guess and no PID-reuse question. better-sqlite3 is already a dependency.
//
// Rules this module keeps:
//   * the file is created once (0600) and never removed or replaced; nothing writes to it;
//   * it is opened ONLY here. On POSIX, closing any descriptor on a file drops every fcntl lock the process holds on it,
//     so the one non-SQLite open (the regular-file check below) happens before the lock is taken, and never while held;
//   * the 2 s bound covers only the wait for the lock, not any filesystem operation;
//   * it gives exclusivity among cooperating 0.1.3 clients only. 0.1.2 and older ignore it.
//
// Readers (proxy start-up, doctor, status) never take or wait on it.
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

import { FileRefused, openRegular } from '../seed/v3/bounded-file.js';

export const LOCK_FILENAME = '.seed-mutation.lock';
export const LOCK_WAIT_MS = 2000;

/** The lock could not be taken. `kind`: contention | permission | corruption | other. Nothing was changed. */
export class LockUnavailable extends Error {
  constructor(kind, message, cause) { super(message); this.name = 'LockUnavailable'; this.kind = kind; if (cause) this.cause = cause; }
}
/** A programming error: this process already holds the lock for that base (inner code takes the token instead). */
export class LockAlreadyHeldInProcess extends Error {
  constructor(base) { super(`this process already holds the seed-mutation lock for ${base}`); this.name = 'LockAlreadyHeldInProcess'; }
}
/** A token that is not live proof of holding the lock for that base. */
export class LockNotHeld extends Error {
  constructor(base) { super(`the seed-mutation lock for ${base} is not held by this caller`); this.name = 'LockNotHeld'; }
}

const held = new Map();              // real base -> { serial, db }
let serials = 0;

const PERMISSION = new Set(['EACCES', 'EPERM', 'EROFS', 'SQLITE_CANTOPEN', 'SQLITE_READONLY', 'SQLITE_PERM',
  'SQLITE_AUTH', 'SQLITE_READONLY_DIRECTORY', 'SQLITE_CANTOPEN_ISDIR']);
const CORRUPTION = new Set(['SQLITE_NOTADB', 'SQLITE_CORRUPT', 'EISDIR', 'ELOOP']);

function classify(file, err) {
  const code = err?.code ?? '';
  if (err instanceof LockUnavailable) return err;
  if (code === 'SQLITE_BUSY' || String(code).startsWith('SQLITE_BUSY') || code === 'SQLITE_LOCKED') {
    return new LockUnavailable('contention', 'another seed command (install, update or rollback) is running for '
      + `${path.dirname(file)}; nothing was changed. Run this again once it has finished.`, err);
  }
  if (PERMISSION.has(code) || String(code).startsWith('SQLITE_CANTOPEN') || String(code).startsWith('SQLITE_READONLY')) {
    return new LockUnavailable('permission', `cannot create or open the lock file ${file} (${code || err.message}); `
      + 'nothing was changed. Seed commands need write access to the ChainGate directory.', err);
  }
  if (CORRUPTION.has(code) || err instanceof FileRefused) {
    return new LockUnavailable('corruption', `the lock file ${file} is damaged (${err.why || code || err.message}); `
      + 'nothing was changed. Remove it once no seed command is running.', err);
  }
  return err;
}

/**
 * Take the lock for `base`, waiting at most `waitMs` for another holder. Returns a token: `{ base, serial }`, where
 * `base` is the REAL path. Throws LockUnavailable (contention, permission, corruption) or LockAlreadyHeldInProcess.
 */
export function acquireSeedMutationLock(base, { waitMs = LOCK_WAIT_MS } = {}) {
  let realBase;
  try { fs.mkdirSync(base, { recursive: true }); realBase = fs.realpathSync(base); }
  catch (e) { throw classify(path.join(base, LOCK_FILENAME), e); }
  if (held.has(realBase)) throw new LockAlreadyHeldInProcess(realBase);
  const file = path.join(realBase, LOCK_FILENAME);

  // created once, never replaced (an existing one is used as it is)
  try { fs.closeSync(fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600)); }
  catch (e) { if (e.code !== 'EEXIST') throw classify(file, e); }
  // a regular file, not a link, FIFO or device: judged on a descriptor BEFORE the lock is taken (see the header)
  try {
    const st = fs.lstatSync(file);
    if (!st.isFile()) throw new FileRefused(file, 'ECG_NOT_REGULAR', 'it is not a regular file');
    fs.closeSync(openRegular(file, { noFollow: true }).fd);
  } catch (e) { throw classify(file, e); }

  let db;
  try { db = new Database(file, { timeout: waitMs, fileMustExist: true }); } catch (e) { throw classify(file, e); }
  try {
    const mode = String(db.pragma('journal_mode', { simple: true })).toLowerCase();
    if (mode !== 'delete') {
      throw new LockUnavailable('corruption', `the lock file ${file} is damaged (journal mode ${mode}, not delete); `
        + 'nothing was changed. Remove it once no seed command is running.');
    }
    db.exec('BEGIN EXCLUSIVE');
  } catch (e) {
    try { db.close(); } catch { /* closing a failed connection */ }
    throw classify(file, e);
  }
  serials += 1;
  held.set(realBase, { serial: serials, db });
  return Object.freeze({ base: realBase, serial: serials });
}

/** Release a token's lock (ROLLBACK, then close). A token that is not live is ignored. */
export function releaseSeedMutationLock(token) {
  const e = token && held.get(token.base);
  if (!e || e.serial !== token.serial) return false;
  held.delete(token.base);
  try { e.db.exec('ROLLBACK'); } catch { /* nothing to roll back */ }
  try { e.db.close(); } catch { /* already closed */ }
  return true;
}

/** Throw LockNotHeld unless `token` is the live lock for `base`. */
export function assertHeld(token, base) {
  let real;
  try { real = fs.realpathSync(base); } catch { throw new LockNotHeld(base); }
  const e = held.get(real);
  if (!token || token.base !== real || !e || e.serial !== token.serial) throw new LockNotHeld(base);
}

/** Run `fn(token)` holding the lock; it is released on return or throw (and by the OS if the process dies). */
export async function withSeedMutationLock(base, fn, opts = {}) {
  const token = acquireSeedMutationLock(base, opts);
  try { return await fn(token); } finally { releaseSeedMutationLock(token); }
}
