// U-05 R2-2 (b): the seed-mutation lock module itself (Addendum 1 §3.1). New API: on the code before (b) this file fails at
// import, which is reported as API-absent, not as a behavioural failure.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import Database from 'better-sqlite3';

import { acquireSeedMutationLock, releaseSeedMutationLock, assertHeld, withSeedMutationLock, LockUnavailable,
  LockAlreadyHeldInProcess, LockNotHeld, LOCK_FILENAME, LOCK_WAIT_MS } from '../../cli/seed-mutation-lock.js';
import { activateBundle } from '../../cli/seed-bundle.js';
import { ROOT, v3Host } from '../helpers/u05-r22.mjs';

const HOLDER = path.join(ROOT, 'test', 'helpers', 'u05-r22-lockholder.mjs');
const tmpBase = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-lock-')); const b = path.join(d, '.chaingate'); fs.mkdirSync(b); return { d, b }; };

function holder(base, mode) {
  const c = spawn(process.execPath, [HOLDER, base, ...(mode ? [mode] : [])], { stdio: ['pipe', 'pipe', 'pipe'] });
  let out = '';
  const held = new Promise((resolve) => { c.stdout.on('data', (x) => { out += x; if (out.includes('HELD')) resolve(true); }); c.on('close', () => resolve(out.includes('HELD'))); });
  const done = new Promise((resolve) => c.on('close', (code, signal) => resolve({ code, signal, out })));
  return { c, held, done, release: () => c.stdin.write('\n') };
}

test('acquire creates the permanent lock file (0600 on POSIX, rollback-journal mode); release frees it in-process', () => {
  const { d, b } = tmpBase();
  try {
    assert.equal(LOCK_FILENAME, '.seed-mutation.lock'); assert.equal(LOCK_WAIT_MS, 2000);
    const t = acquireSeedMutationLock(b);
    const f = path.join(b, LOCK_FILENAME);
    assert.equal(fs.statSync(f).isFile(), true);
    if (process.platform !== 'win32') assert.equal(fs.statSync(f).mode & 0o777, 0o600);
    assertHeld(t, b);
    releaseSeedMutationLock(t);
    assert.equal(fs.existsSync(f), true, 'the lock file is never removed');
    const t2 = acquireSeedMutationLock(b); releaseSeedMutationLock(t2);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('LK4 nested acquisition of a base this process holds throws at once (no 2 s wait)', () => {
  const { d, b } = tmpBase();
  try {
    const t = acquireSeedMutationLock(b);
    const t0 = Date.now();
    assert.throws(() => acquireSeedMutationLock(b), LockAlreadyHeldInProcess);
    assert.ok(Date.now() - t0 < 500);
    releaseSeedMutationLock(t);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('LK5/LK6 a released token, or a token for another base, is not proof of holding', () => {
  const x = tmpBase(); const y = tmpBase();
  try {
    const tx = acquireSeedMutationLock(x.b);
    const ty = acquireSeedMutationLock(y.b);
    assert.throws(() => assertHeld(tx, y.b), LockNotHeld);
    releaseSeedMutationLock(tx);
    assert.throws(() => assertHeld(tx, x.b), LockNotHeld);
    assertHeld(ty, y.b); releaseSeedMutationLock(ty);
  } finally { fs.rmSync(x.d, { recursive: true, force: true }); fs.rmSync(y.d, { recursive: true, force: true }); }
});

test('LK1 contention: another process holds it past the wait -> LockUnavailable (contention) after about 2 s', async () => {
  const { d, b } = tmpBase();
  const h = holder(b);
  try {
    assert.equal(await h.held, true);
    const t0 = Date.now();
    assert.throws(() => acquireSeedMutationLock(b), (e) => e instanceof LockUnavailable && e.kind === 'contention');
    const waited = Date.now() - t0;
    assert.ok(waited >= 1500 && waited < 6000, `waited ${waited} ms`);
  } finally { h.release(); await h.done; fs.rmSync(d, { recursive: true, force: true }); }
});

test('B6 the holder is killed while a second waits: the second acquires within the wait', async () => {
  const { d, b } = tmpBase();
  const h = holder(b);
  try {
    assert.equal(await h.held, true);
    setTimeout(() => h.c.kill('SIGKILL'), 500);
    const t0 = Date.now();
    const t = await new Promise((resolve, reject) => setImmediate(() => { try { resolve(acquireSeedMutationLock(b)); } catch (e) { reject(e); } }));
    const waited = Date.now() - t0;
    assert.ok(waited < LOCK_WAIT_MS + 1000, `waited ${waited} ms`);
    releaseSeedMutationLock(t);
  } finally { await h.done; fs.rmSync(d, { recursive: true, force: true }); }
});

test('the operating system releases the lock when the holder dies (no takeover logic)', async () => {
  const { d, b } = tmpBase();
  try {
    const h = holder(b, 'kill-self'); await h.done;
    const t0 = Date.now(); const t = acquireSeedMutationLock(b);
    assert.ok(Date.now() - t0 < 1000); releaseSeedMutationLock(t);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('a lock file switched to WAL is the damaged class (only rollback-journal mode is accepted)', () => {
  const { d, b } = tmpBase();
  try {
    const db = new Database(path.join(b, LOCK_FILENAME)); db.pragma('journal_mode = WAL'); db.close();
    assert.throws(() => acquireSeedMutationLock(b), (e) => e instanceof LockUnavailable && e.kind === 'corruption');
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('withSeedMutationLock releases on throw; the low-level activateBundle takes the lock itself, or checks a given token', async () => {
  const h = await v3Host();
  const other = tmpBase();
  try {
    await assert.rejects(withSeedMutationLock(h.base, async () => { throw new Error('inside'); }), /inside/);
    const t = acquireSeedMutationLock(h.base); releaseSeedMutationLock(t);           // free again
    const ot = acquireSeedMutationLock(other.b);
    assert.throws(() => activateBundle(h.base, h.id, { lock: ot }), LockNotHeld);
    releaseSeedMutationLock(ot);
    const hh = holder(h.base); assert.equal(await hh.held, true);
    assert.throws(() => activateBundle(h.base, h.id), (e) => e instanceof LockUnavailable && e.kind === 'contention');
    hh.release(); await hh.done;
    activateBundle(h.base, h.id);                                                   // self-locking when free
  } finally { fs.rmSync(other.d, { recursive: true, force: true }); h.cleanup(); }
});
