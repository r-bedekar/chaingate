// U-05 R2-2 (c): the bounded-read helper itself, and readActivationPointer deciding on the DESCRIPTOR (C6c). New API:
// on r2 head d757aa7 this file fails at import, which is reported as API-absent, not as a behavioural failure.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';

import { CAPS, FileRefused, openRegular, readBounded, readBoundedFd, readBoundedIfPresent, hashRange, sha256Regular }
  from '../../seed/v3/bounded-file.js';
import { readActivationPointer, activationFile, seedsDir, ActivationBroken } from '../../cli/seed-bundle.js';
import { canFifo, mkfifo } from '../helpers/u05-r22.mjs';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'cg-r22c-'));
const fifoOnly = { skip: canFifo ? false : 'needs mkfifo (POSIX)' };
const posixOnly = { skip: process.platform === 'win32' ? 'POSIX only' : false };

test('caps are the recorded values', () => {
  assert.deepEqual({ ...CAPS }, { sidecar: 4096, manifest: 65536, key: 16384, activation: 4096, intent: 4096,
    config: 65536, marker: 4096, record: 4096 });
});

test('readBounded: exactly the cap is read; one byte more is refused by size', () => {
  const d = tmp();
  try {
    fs.writeFileSync(path.join(d, 'ok'), Buffer.alloc(4096, 1));
    fs.writeFileSync(path.join(d, 'big'), Buffer.alloc(4097, 1));
    assert.equal(readBounded(path.join(d, 'ok'), 4096).length, 4096);
    assert.throws(() => readBounded(path.join(d, 'big'), 4096), (e) => e instanceof FileRefused && e.code === 'ECG_TOO_LARGE');
    assert.equal(readBoundedIfPresent(path.join(d, 'absent'), 4096), null);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('readBoundedFd: a file that grew after fstat is caught by reading at most cap + 1 bytes', () => {
  const d = tmp();
  try {
    const p = path.join(d, 'grew'); fs.writeFileSync(p, Buffer.alloc(10000, 2));
    const fd = fs.openSync(p, 'r');
    try {
      // `size` as fstat reported it before the growth: under the cap
      assert.throws(() => readBoundedFd(fd, 100, 4096, p), (e) => e.code === 'ECG_TOO_LARGE' && /grew/.test(e.why));
    } finally { fs.closeSync(fd); }
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('openRegular refuses a FIFO without blocking, and a directory', fifoOnly, () => {
  const d = tmp();
  try {
    const f = mkfifo(path.join(d, 'fifo'));
    const t0 = Date.now();
    assert.throws(() => openRegular(f), (e) => e.code === 'ECG_NOT_REGULAR' && /FIFO/.test(e.why));
    assert.ok(Date.now() - t0 < 2000, 'the open returned at once');
    assert.throws(() => openRegular(d), (e) => e.code === 'ECG_NOT_REGULAR' || e.code === 'EISDIR');
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('C6b openRegular refuses /dev/zero as a character device', posixOnly, () => {
  assert.throws(() => openRegular('/dev/zero'), (e) => e.code === 'ECG_NOT_REGULAR' && /character device/.test(e.why));
});

test('openRegular with noFollow refuses a symbolic link (POSIX O_NOFOLLOW)', posixOnly, () => {
  const d = tmp();
  try {
    fs.writeFileSync(path.join(d, 'real'), 'x'); fs.symlinkSync('real', path.join(d, 'link'));
    assert.throws(() => openRegular(path.join(d, 'link'), { noFollow: true }), (e) => e.code === 'ECG_IS_LINK');
    const { fd } = openRegular(path.join(d, 'link')); fs.closeSync(fd);    // followed when allowed
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('hashRange reads explicit positions: an exhausted descriptor still hashes from 0; truncation is refused', () => {
  const d = tmp();
  try {
    const p = path.join(d, 'f'); const bytes = Buffer.from('0123456789'.repeat(1000)); fs.writeFileSync(p, bytes);
    const fd = fs.openSync(p, 'r');
    try {
      fs.readSync(fd, Buffer.alloc(bytes.length), 0, bytes.length, null);           // position now at the end
      assert.equal(hashRange(fd, 0, bytes.length), createHash('sha256').update(bytes).digest('hex'));
      assert.throws(() => hashRange(fd, 0, bytes.length + 1, p), (e) => e.code === 'ECG_TRUNCATED');
    } finally { fs.closeSync(fd); }
    assert.equal(sha256Regular(p), createHash('sha256').update(bytes).digest('hex'));
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

// ---- C6c: readActivationPointer decides on what it OPENED, not on what lstat saw ------------------------------------
function pointerBase() {
  const d = tmp(); const base = path.join(d, '.chaingate'); fs.mkdirSync(seedsDir(base), { recursive: true });
  fs.mkdirSync(path.join(seedsDir(base), 'aaaaaaaaaaaaaaaa'));
  fs.writeFileSync(activationFile(base), `${JSON.stringify({ schema: 'chaingate-activation/1', active: 'aaaaaaaaaaaaaaaa', previous: null })}\n`);
  return { d, base };
}

test('C6c activation.json swapped for a FIFO between lstat and open is refused, without blocking', fifoOnly, () => {
  const { d, base } = pointerBase();
  try {
    assert.equal(readActivationPointer(base).active, 'aaaaaaaaaaaaaaaa', 'the unswapped record reads');
    const swap = () => { fs.rmSync(activationFile(base)); mkfifo(activationFile(base)); };
    const t0 = Date.now();
    assert.throws(() => readActivationPointer(base, { hooks: { afterLstat: swap } }),
      (e) => e instanceof ActivationBroken && /not a regular file|FIFO/.test(e.message));
    assert.ok(Date.now() - t0 < 2000);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('C6c activation.json swapped for a symbolic link between lstat and open is refused (O_NOFOLLOW)', posixOnly, () => {
  const { d, base } = pointerBase();
  try {
    const other = path.join(d, 'elsewhere.json'); fs.copyFileSync(activationFile(base), other);
    const swap = () => { fs.rmSync(activationFile(base)); fs.symlinkSync(other, activationFile(base)); };
    assert.throws(() => readActivationPointer(base, { hooks: { afterLstat: swap } }),
      (e) => e instanceof ActivationBroken && /symbolic link/.test(e.message));
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('C6c activation.json grown past 4 KiB between lstat and open is refused by size on the descriptor', () => {
  const { d, base } = pointerBase();
  try {
    const grow = () => { fs.appendFileSync(activationFile(base), ' '.repeat(5000)); };
    assert.throws(() => readActivationPointer(base, { hooks: { afterLstat: grow } }),
      (e) => e instanceof ActivationBroken && /4096-byte limit/.test(e.message));
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});
