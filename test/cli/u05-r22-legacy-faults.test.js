// U-05 R2-2 legacy part, owner decision 8 §2: qualification-entry fault injection, written before any correction.
//   Q1/Q2 the pending-install marker cannot be checked (lstat EACCES for real, EIO injected): that is NOT "no marker";
//   Q3/Q4 first creation has PUBLISHED witness.db with link(), then the directory sync or the staging cleanup fails: the
//         pending marker must stay, the error must say publication occurred, and completion must still converge.
// Faults are injected by patching node:fs in this process only, at the exact point (after publication), so the code
// under test runs unchanged; every patch is restored in `finally`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

import { freshHome, exists } from '../helpers/u05-r22.mjs';
import { testKey, buildLegacySeed, snapshot, project } from '../helpers/u05-r22-legacy.mjs';
import { installLegacySeed, readInstallMarker, MARKER_FILE } from '../../cli/legacy-seed.js';
import { assertIntegrity } from '../../cli/integrity-gate.js';
import { acquireSeedMutationLock, releaseSeedMutationLock } from '../../cli/seed-mutation-lock.js';
import { resolvePaths } from '../../cli/paths.js';

const key = testKey();
const pathsFor = (base) => resolvePaths('user', process.cwd(), { CHAINGATE_HOME: base });
const stagedOf = (seed) => ({ path: seed.db, size: seed.size, digest: seed.digest, sha256Bytes: fs.readFileSync(seed.sha),
  sigBytes: fs.readFileSync(seed.sig), source: 'test' });
const fileSha = (f) => createHash('sha256').update(fs.readFileSync(f)).digest('hex');
function withLock(base, fn) { const t = acquireSeedMutationLock(base); try { return fn(t); } finally { releaseSeedMutationLock(t); } }
const quiet = async (fn) => { const e = console.error; console.error = () => {}; try { return await fn(); } finally { console.error = e; } };

/** Patch fs[name] for the duration of fn; `when(args)` decides whether this call fails with `code`. */
function patched(name, when, code, fn) {
  const real = fs[name];
  fs[name] = function (...args) { if (when(...args)) throw Object.assign(new Error(`injected ${code}`), { code }); return real.apply(fs, args); };
  try { return fn(); } finally { fs[name] = real; }
}

// ---- Q1 / Q2: a marker that cannot be checked -------------------------------------------------------------------------
test('Q1 marker lstat EACCES (the directory cannot be searched): not "no marker"; the gate refuses', {
  skip: process.platform === 'win32' || process.getuid?.() === 0 ? 'needs a non-root POSIX user' : false,
}, async () => {
  const { home, base } = freshHome('faults');
  try {
    const p = pathsFor(base);
    fs.chmodSync(base, 0o600);                                   // no search permission: lstat(base/<marker>) -> EACCES
    let m; let gate;
    try { m = readInstallMarker(p); gate = await quiet(() => assertIntegrity(p, { command: 'allow' })); }
    finally { fs.chmodSync(base, 0o755); }
    assert.notEqual(m.state, 'none', `an unreadable marker location was reported as no marker: ${JSON.stringify(m)}`);
    assert.match(String(m.why), /EACCES/);
    assert.equal(gate.ok, false, 'a mutating command must not proceed when the marker cannot be checked');
  } finally { fs.rmSync(home, { recursive: true, force: true }); }
});

test('Q2 marker lstat EIO (injected): not "no marker"; the gate refuses; an installation refuses', async () => {
  const { home, base } = freshHome('faults');
  try {
    const p = pathsFor(base);
    const seed = buildLegacySeed(path.join(home, 'seed'), { key });
    const isMarker = (f) => String(f).endsWith(MARKER_FILE);
    // everything that reads the marker runs SYNCHRONOUSLY inside the patch (assertIntegrity reads it before its first
    // await), so the patch is never restored early
    const errLog = console.error; console.error = () => {};
    const r = patched('lstatSync', isMarker, 'EIO', () => {
      const out = { m: readInstallMarker(p) };
      try { withLock(base, (lock) => installLegacySeed(p, stagedOf(seed), { lock, mode: 'create-only' })); out.install = 'installed'; }
      catch (e) { out.install = e.message; }
      out.gateP = assertIntegrity(p, { command: 'allow' });
      return out;
    });
    const gate = await r.gateP.finally(() => { console.error = errLog; });
    const { m, install } = r;
    assert.notEqual(m.state, 'none', JSON.stringify(m)); assert.match(String(m.why), /EIO/);
    assert.equal(gate.ok, false);
    assert.notEqual(install, 'installed', 'an installation must not proceed past a marker it cannot check');
    assert.equal(exists(p.witnessDb), false);
  } finally { fs.rmSync(home, { recursive: true, force: true }); }
});

// ---- Q3 / Q4: failures AFTER link() has published witness.db ---------------------------------------------------------
function afterPublication(label, inject, opts = {}) {
  test(`${label}: the marker stays, publication is reported, and completion converges`, opts, () => {
    const { home, base } = freshHome('faults');
    try {
      const p = pathsFor(base);
      const seed = buildLegacySeed(path.join(home, 'seed'), { key });
      let err = null;
      try { inject(p, () => withLock(base, (lock) => installLegacySeed(p, stagedOf(seed), { lock, mode: 'create-only' }))); }
      catch (e) { err = e; }
      assert.ok(err, 'the injected post-publication failure was not reached or was swallowed');
      assert.equal(exists(p.witnessDb), true, 'witness.db was published before the fault');
      assert.equal(fileSha(p.witnessDb), seed.digest);
      assert.equal(exists(path.join(base, MARKER_FILE)), true, 'the pending marker must be kept once witness.db is published');
      assert.match(err.message, /was created|published/, `the error must say publication occurred: ${err.message}`);
      assert.equal(err.committed, true);
      // completion with the same seed converges
      withLock(base, (lock) => installLegacySeed(p, stagedOf(seed), { lock, mode: 'create-only' }));
      assert.equal(exists(path.join(base, MARKER_FILE)), false);
      assert.equal(fs.readFileSync(p.witnessDbSha256, 'utf8').trim(), seed.digest);
      assert.deepEqual(project(snapshot(p.witnessDb).rows.packages, ['id', 'package_name']),
        project(snapshot(seed.db).rows.packages, ['id', 'package_name']));
    } finally { fs.rmSync(home, { recursive: true, force: true }); }
  });
}

afterPublication('Q3 link() succeeded, then the directory sync fails (EIO)', (p, run) => {
  // fsync of a DIRECTORY descriptor, only once witness.db exists (the marker's own directory sync happens before link)
  const dirFds = new Set(); const realOpen = fs.openSync;
  fs.openSync = function (f, ...a) { const fd = realOpen.call(fs, f, ...a); if (String(f) === path.dirname(p.witnessDb)) dirFds.add(fd); return fd; };
  try { patched('fsyncSync', (fd) => dirFds.has(fd) && fs.existsSync(p.witnessDb), 'EIO', run); }
  finally { fs.openSync = realOpen; }
}, { skip: process.platform === 'win32' ? 'Windows cannot fsync a directory, so ChainGate does not sync one there: no such failure point' : false });

afterPublication('Q4 link() succeeded, then removing the staging copy fails (EBUSY)', (p, run) => {
  patched('rmSync', (f) => /witness\.db\.staging-\d+$/.test(String(f)) && fs.existsSync(p.witnessDb), 'EBUSY', run);
});
