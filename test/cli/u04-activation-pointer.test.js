// U-04 — the Windows activation record (seeds/activation.json). Forced with `{ mode: 'pointer' }`
// here so it runs on every platform; on Windows it is also the default path the lifecycle and
// acceptance tests exercise. Design: docs U-04 windows activation pointer design (2026-09-29).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import Database from 'better-sqlite3';

import {
  stageBundle, activateBundle, rollbackActivation, resolveActiveBundle, activeBundleId, previousBundleId,
  readActivationPointer, staleLegacyLink, activationFile, activeLink, previousLink, seedsDir, listBundles,
  ActivationBroken, ACTIVATION_FILE,
} from '../../cli/seed-bundle.js';
import { buildSyntheticSeed } from '../seed-v3/u01-cases.mjs';

const PTR = { mode: 'pointer' };
const SYM = { mode: 'symlink' };
const sha = (f) => createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const canSymlink = (() => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-symprobe-'));
  try { fs.mkdirSync(path.join(d, 't')); fs.symlinkSync('t', path.join(d, 'l')); return true; } catch { return false; }
  finally { fs.rmSync(d, { recursive: true, force: true }); }
})();

/** A host with three distinct staged (not activated) bundles A, B, C. */
function host() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'chaingate-u04-ptr-'));
  const base = path.join(home, '.chaingate'); fs.mkdirSync(base, { recursive: true });
  const seed = buildSyntheticSeed();
  const ids = {};
  for (const [name, digest] of [['A', null], ['B', 'b'.repeat(64)], ['C', 'c'.repeat(64)]]) {
    let db = seed.dbPath;
    if (digest) {
      const d = path.join(home, `src-${name}`); fs.mkdirSync(d); db = path.join(d, 'chaingate-seed.db');
      fs.copyFileSync(seed.dbPath, db);
      const h = new Database(db); h.prepare("UPDATE seed_metadata SET value = ? WHERE key = 'corpus_snapshot_digest'").run(digest); h.close();
    }
    fs.writeFileSync(`${db}.sha256`, `${sha(db)}\n`);
    ids[name] = stageBundle({ dbPath: db, sha256Path: `${db}.sha256` }, base, { trust: 'unsigned-development' }).dir_name;
  }
  return { base, ids, cleanup: () => { fs.rmSync(home, { recursive: true, force: true }); fs.rmSync(seed.dir, { recursive: true, force: true }); } };
}
const record = (base) => JSON.parse(fs.readFileSync(activationFile(base), 'utf8'));
const exists = (p) => { try { fs.lstatSync(p); return true; } catch { return false; } };

test('initial activation writes ONE record holding active and previous; no symlink is created', () => {
  const h = host();
  try {
    assert.equal(resolveActiveBundle(h.base, PTR), null, 'nothing active yet: a legitimate state');
    const r = activateBundle(h.base, h.ids.A, PTR);
    assert.equal(r.record, ACTIVATION_FILE);
    assert.deepEqual({ ...record(h.base), updated_at: 'x' }, { schema: 'chaingate-activation/1', active: h.ids.A, previous: null, updated_at: 'x' });
    assert.equal(resolveActiveBundle(h.base, PTR).id, h.ids.A);
    assert.equal(exists(activeLink(h.base)), false, 'no symlink on the pointer path');
    assert.equal(exists(previousLink(h.base)), false);
  } finally { h.cleanup(); }
});

test('update, rollback and roll forward are swaps of the one record', () => {
  const h = host();
  try {
    activateBundle(h.base, h.ids.A, PTR);
    activateBundle(h.base, h.ids.B, PTR);
    assert.equal(activeBundleId(h.base, PTR), h.ids.B); assert.equal(previousBundleId(h.base, PTR), h.ids.A);
    rollbackActivation(h.base, PTR);
    assert.equal(resolveActiveBundle(h.base, PTR).id, h.ids.A); assert.equal(previousBundleId(h.base, PTR), h.ids.B);
    rollbackActivation(h.base, PTR);
    assert.equal(activeBundleId(h.base, PTR), h.ids.B); assert.equal(previousBundleId(h.base, PTR), h.ids.A);
    activateBundle(h.base, h.ids.B, PTR);   // re-activating the active bundle keeps previous
    assert.equal(previousBundleId(h.base, PTR), h.ids.A);
    assert.equal(listBundles(h.base).length, 3, 'the record is not listed as a bundle');
  } finally { h.cleanup(); }
});

test('a failed replacement leaves the prior record intact and usable, and no temporary file behind', () => {
  const h = host();
  try {
    activateBundle(h.base, h.ids.A, PTR);
    const before = fs.readFileSync(activationFile(h.base), 'utf8');
    const failing = { ...PTR, fsImpl: { renameSync: () => { throw Object.assign(new Error('simulated EPERM'), { code: 'EPERM' }); } } };
    assert.throws(() => activateBundle(h.base, h.ids.B, failing), /simulated EPERM/);
    assert.equal(fs.readFileSync(activationFile(h.base), 'utf8'), before, 'record byte-identical');
    assert.equal(resolveActiveBundle(h.base, PTR).id, h.ids.A, 'the previous bundle is still active');
    assert.deepEqual(fs.readdirSync(seedsDir(h.base)).filter((n) => n.includes('.tmp-')), []);
  } finally { h.cleanup(); }
});

test('an interrupted write (leftover temporary file) is ignored by readers and cleaned by the next activation', () => {
  const h = host();
  try {
    activateBundle(h.base, h.ids.A, PTR);
    // U-05 R2-2 (b), Addendum 1 §3.3 / Addendum 2 §3.4: the next mutator removes a leftover only when its pid is DEAD and it
    // is older than 15 minutes (a young one, or a live writer's, is kept and reported). Was: any pid, at any age.
    const deadPid = Number(String(spawnSync(process.execPath, ['-e', 'process.stdout.write(String(process.pid))']).stdout));
    const leftover = `${activationFile(h.base)}.tmp-${deadPid}`;
    fs.writeFileSync(leftover, '{"schema":"chaingate-activation/1","active":"half-writ');
    const old = new Date(Date.now() - 20 * 60000); fs.utimesSync(leftover, old, old);
    assert.equal(resolveActiveBundle(h.base, PTR).id, h.ids.A);
    activateBundle(h.base, h.ids.B, PTR);
    assert.equal(exists(leftover), false, 'stale temporary removed after the successful switch');
    assert.equal(resolveActiveBundle(h.base, PTR).id, h.ids.B);
  } finally { h.cleanup(); }
});

test('malformed, unreadable or out-of-tree records FAIL CLOSED, with no fallback to a legacy link', { skip: !canSymlink && 'symlinks unavailable here' }, () => {
  const h = host();
  try {
    activateBundle(h.base, h.ids.A, SYM);   // a valid legacy link exists: it must NOT be used as a fallback
    const f = activationFile(h.base);
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-outside-'));
    const bad = {
      'not JSON': '{nope',
      'unknown schema': JSON.stringify({ schema: 'chaingate-activation/2', active: h.ids.A, previous: null }),
      'array': '[]',
      'traversal': JSON.stringify({ schema: 'chaingate-activation/1', active: '../outside', previous: null }),
      'absolute path': JSON.stringify({ schema: 'chaingate-activation/1', active: 'C:\\x', previous: null }),
      'missing bundle': JSON.stringify({ schema: 'chaingate-activation/1', active: 'f'.repeat(16), previous: null }),
      'bad previous': JSON.stringify({ schema: 'chaingate-activation/1', active: h.ids.A, previous: 'x/../y' }),
      'names itself': JSON.stringify({ schema: 'chaingate-activation/1', active: ACTIVATION_FILE, previous: null }),
      'oversize': JSON.stringify({ schema: 'chaingate-activation/1', active: h.ids.A, previous: null, pad: 'x'.repeat(5000) }),
    };
    for (const [label, content] of Object.entries(bad)) {
      fs.writeFileSync(f, content);
      assert.throws(() => resolveActiveBundle(h.base, PTR), (e) => e instanceof ActivationBroken, `${label}: resolve`);
      assert.throws(() => activeBundleId(h.base, PTR), (e) => e instanceof ActivationBroken, `${label}: activeBundleId`);
      assert.throws(() => activateBundle(h.base, h.ids.B, PTR), (e) => e instanceof ActivationBroken, `${label}: no activation over a broken record`);
    }
    // a bundle-named entry that is a symlink to a directory OUTSIDE seeds/
    const fake = path.join(seedsDir(h.base), 'e'.repeat(16));
    fs.symlinkSync(outside, fake, 'dir');
    fs.writeFileSync(f, JSON.stringify({ schema: 'chaingate-activation/1', active: 'e'.repeat(16), previous: null }));
    assert.throws(() => resolveActiveBundle(h.base, PTR), (e) => e instanceof ActivationBroken, 'out-of-tree bundle');
    // the record itself replaced by a directory
    fs.rmSync(f, { force: true }); fs.mkdirSync(f);
    assert.throws(() => resolveActiveBundle(h.base, PTR), (e) => e instanceof ActivationBroken, 'a directory is not a record');
    fs.rmSync(outside, { recursive: true, force: true });
  } finally { h.cleanup(); }
});

test('migration from an existing symlink install: read through the links, then replaced by the record', { skip: !canSymlink && 'symlinks unavailable here' }, () => {
  const h = host();
  try {
    // a pre-0.1.2 host: B active, A previous. Built directly: renaming a link over an existing link is
    // exactly the operation Windows refuses, so the legacy writer cannot be used here.
    fs.symlinkSync(h.ids.B, activeLink(h.base), 'dir'); fs.symlinkSync(h.ids.A, previousLink(h.base), 'dir');
    assert.equal(resolveActiveBundle(h.base, PTR).id, h.ids.B, 'no record yet: the legacy link is read');
    assert.equal(previousBundleId(h.base, PTR), h.ids.A);
    activateBundle(h.base, h.ids.C, PTR);
    assert.deepEqual([record(h.base).active, record(h.base).previous], [h.ids.C, h.ids.B]);
    assert.equal(exists(activeLink(h.base)), false, 'legacy links removed AFTER the record was written');
    assert.equal(exists(previousLink(h.base)), false);
    rollbackActivation(h.base, PTR);
    assert.equal(resolveActiveBundle(h.base, PTR).id, h.ids.B);
  } finally { h.cleanup(); }
});

test('record and a stale legacy link both present: the record is authoritative and the link is reported', { skip: !canSymlink && 'symlinks unavailable here' }, () => {
  const h = host();
  try {
    activateBundle(h.base, h.ids.A, PTR);
    fs.symlinkSync(h.ids.B, activeLink(h.base));   // an older client recreated its link
    assert.equal(resolveActiveBundle(h.base, PTR).id, h.ids.A, 'the record wins');
    assert.deepEqual(staleLegacyLink(h.base, PTR), [activeLink(h.base)]);
    assert.equal(staleLegacyLink(h.base, SYM), null, 'not a concern on the symlink platforms');
  } finally { h.cleanup(); }
});

test('symlink platforms fail closed on a Windows record instead of reading "no seed"', () => {
  const h = host();
  try {
    activateBundle(h.base, h.ids.A, PTR);   // e.g. a home directory copied from Windows
    assert.throws(() => resolveActiveBundle(h.base, SYM), (e) => e instanceof ActivationBroken);
    assert.throws(() => activeBundleId(h.base, SYM), (e) => e instanceof ActivationBroken);
    assert.equal(readActivationPointer(h.base).active, h.ids.A);
  } finally { h.cleanup(); }
});
