// U-05 R2-2 (d): private staging before SQLite, bounded copies and space admission (R2-2 §4, Addendum 1 §4 and §7).
// Failing-first on the head before (d). In-process cases use update-seed's existing `deps` argument; the seams added by
// (d) are `deps.seam` (statfs/stat) and `deps.hooks` (named copy points). Where only a seam can force a case, the result
// on the unfixed code is reported as SEAM-ABSENT, not as a demonstrated defect.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

import updateSeed from '../../cli/commands/update-seed.js';
import { resolvePaths } from '../../cli/paths.js';
import { activeBundleId, seedsDir } from '../../cli/seed-bundle.js';
import { ROOT, CLI, v3Host, v3Source, runCli, runNode, canFifo, mkfifo, sha256, exists } from '../helpers/u05-r22.mjs';

const ARGS = (s) => ['--seed', s.db, '--unsigned-development'];
const V3_SIDECARS = 4096 + 4096 + 65536 + 4096 + 4096;
const RESERVE = 64 * 1024 * 1024;

/** A second synthetic seed that installs as a NEW bundle. */
function otherSource(digest = 'd') {
  const s = v3Source();
  const h = new Database(s.db); h.prepare("UPDATE seed_metadata SET value = ? WHERE key = 'corpus_snapshot_digest'").run(digest.repeat(64)); h.close();
  fs.writeFileSync(s.sha, `${sha256(s.db)}\n`);
  return s;
}
const deps = (base, extra = {}) => ({
  fetchSeedBundle: async () => { throw new Error('test stub: no network'); },
  verifySeed: async () => { throw new Error('test stub'); },
  assertIntegrity: async () => ({ ok: true }),
  resolvePaths: (scope) => resolvePaths(scope, process.cwd(), { CHAINGATE_HOME: base }),
  ...extra,
});
async function run(fn) {
  const out = []; const err = []; const l = console.log; const e = console.error;
  console.log = (...a) => out.push(a.join(' ')); console.error = (...a) => err.push(a.join(' '));
  try { const code = await fn(); return { code, out: out.join('\n'), err: err.join('\n'), all: `${out.join('\n')}\n${err.join('\n')}` }; }
  finally { console.log = l; console.error = e; }
}
const entries = (base) => fs.readdirSync(seedsDir(base)).sort();
const staging = (base) => entries(base).filter((n) => n.startsWith('.staging-'));
/** statfs as a filesystem with block size 1 and `free` bytes available. */
const fakeFs = (free) => ({ statfs: () => ({ bsize: 1n, bavail: BigInt(free), blocks: 1n << 40n, bfree: BigInt(free) }) });
const required = (s) => fs.statSync(s.db).size + V3_SIDECARS + 4 * 1 + RESERVE;

// ---- admission ------------------------------------------------------------------------------------------------------
test('D1 available < required: refused before any staging, naming both figures; the active bundle unchanged', async () => {
  const h = await v3Host(); const s = otherSource();
  try {
    const before = entries(h.base);
    const r = await run(() => updateSeed(ARGS(s), deps(h.base, { seam: fakeFs(1024) })));
    assert.equal(r.code, 1, r.all);
    assert.match(r.all, /not enough free space/);
    assert.match(r.all, /needs about .* available/);
    assert.deepEqual(entries(h.base), before, 'nothing staged, installed or left behind');
    assert.equal(activeBundleId(h.base), h.id);
  } finally { s.cleanup(); h.cleanup(); }
});

test('D2 available = required is admitted; required - 1 is refused', async () => {
  const h = await v3Host(); const s = otherSource(); const s2 = otherSource('f');
  try {
    const at = await run(() => updateSeed(ARGS(s), deps(h.base, { seam: fakeFs(required(s)) })));
    assert.equal(at.code, 0, `exactly enough must be admitted\n${at.all}`);
    const below = await run(() => updateSeed(ARGS(s2), deps(h.base, { seam: fakeFs(required(s2) - 1) })));
    assert.equal(below.code, 1, `one byte short must be refused\n${below.all}`);
    assert.match(below.all, /not enough free space/);
  } finally { s.cleanup(); s2.cleanup(); h.cleanup(); }
});

test('D4 free space unavailable (statfs throws, or a zero block size): P2, proceed with the stated warning', async () => {
  const h = await v3Host();
  try {
    for (const [label, seam] of [
      ['statfs throws', { statfs: () => { throw Object.assign(new Error('not implemented'), { code: 'ENOSYS' }); } }],
      ['block size 0', { statfs: () => ({ bsize: 0n, bavail: 10n }) }]]) {
      const s = otherSource(label === 'statfs throws' ? 'a' : 'b');
      try {
        const r = await run(() => updateSeed(ARGS(s), deps(h.base, { seam })));
        assert.equal(r.code, 0, `${label}\n${r.all}`);
        assert.match(r.all, /free space could not be determined .* the copy proceeds, and a copy failure is cleaned up/, label);
      } finally { s.cleanup(); }
    }
  } finally { h.cleanup(); }
});

test('D5 guard: ample real space: success, no admission warning', async () => {
  const h = await v3Host(); const s = otherSource();
  try {
    const r = await run(() => updateSeed(ARGS(s), deps(h.base)));
    assert.equal(r.code, 0, r.all);
    assert.doesNotMatch(r.all, /free space/);
    assert.deepEqual(staging(h.base), []);
  } finally { s.cleanup(); h.cleanup(); }
});

// ---- the bounded copy -----------------------------------------------------------------------------------------------
test('D7/ST2 a source that grows during the copy is refused; at most its opened size was staged; nothing left', async () => {
  const h = await v3Host(); const s = otherSource();
  try {
    let grown = false;
    const hooks = { midStagingCopy: () => { if (!grown) { grown = true; fs.appendFileSync(s.db, Buffer.alloc(8192, 9)); } } };
    const r = await run(() => updateSeed(ARGS(s), deps(h.base, { hooks })));
    assert.equal(grown, true, 'SEAM-ABSENT: the copy exposes no midStagingCopy point');
    assert.equal(r.code, 1, r.all); assert.match(r.all, /grew/);
    assert.deepEqual(staging(h.base), []); assert.equal(activeBundleId(h.base), h.id);
  } finally { s.cleanup(); h.cleanup(); }
});

test('ST3 a source truncated during the copy is refused; nothing left', async () => {
  const h = await v3Host(); const s = otherSource();
  try {
    // larger than one 1 MiB copy chunk, so the cut lands DURING the copy (found by r22d-post: the synthetic seed fits in
    // one chunk, and the hook then fired after the last byte had been read)
    const p = new Database(s.db); p.exec('CREATE TABLE pad (b BLOB)'); p.prepare('INSERT INTO pad VALUES (?)').run(Buffer.alloc(3 << 20)); p.close();
    fs.writeFileSync(s.sha, `${sha256(s.db)}\n`);
    assert.ok(fs.statSync(s.db).size > (1 << 20));
    let cut = false;
    const hooks = { midStagingCopy: () => { if (!cut) { cut = true; fs.truncateSync(s.db, 4096); } } };
    const r = await run(() => updateSeed(ARGS(s), deps(h.base, { hooks })));
    assert.equal(cut, true, 'SEAM-ABSENT: the copy exposes no midStagingCopy point');
    assert.equal(r.code, 1, r.all); assert.match(r.all, /ended/);
    assert.deepEqual(staging(h.base), []);
  } finally { s.cleanup(); h.cleanup(); }
});

test('ST4 a same-size change to the source after the copy is irrelevant: the staged bytes are what is verified and installed', async () => {
  const h = await v3Host(); const s = otherSource(); const decoy = otherSource('9');
  try {
    const original = sha256(s.db);
    assert.equal(fs.statSync(decoy.db).size, fs.statSync(s.db).size);
    let swapped = false;
    const hooks = { afterStagingCopy: () => { swapped = true; fs.copyFileSync(decoy.db, s.db); } };
    const r = await run(() => updateSeed(ARGS(s), deps(h.base, { hooks })));
    assert.equal(swapped, true, 'SEAM-ABSENT: no afterStagingCopy point');
    assert.equal(r.code, 0, r.all);
    const id = activeBundleId(h.base);
    const manifest = JSON.parse(fs.readFileSync(path.join(seedsDir(h.base), id, 'bundle.json'), 'utf8'));
    assert.equal(manifest.sha256, original, 'the installed bundle is the bytes that were staged');
  } finally { decoy.cleanup(); s.cleanup(); h.cleanup(); }
});

test('D3 an injected write error mid-copy: exit 1, the staging copy removed, the active bundle unchanged', async () => {
  const h = await v3Host(); const s = otherSource();
  try {
    let fired = false;
    const hooks = { beforeStagingWrite: () => { fired = true; throw Object.assign(new Error('injected I/O error'), { code: 'EIO' }); } };
    const r = await run(() => updateSeed(ARGS(s), deps(h.base, { hooks })));
    assert.equal(fired, true, 'SEAM-ABSENT: no beforeStagingWrite point');
    assert.equal(r.code, 1, r.all); assert.match(r.all, /EIO/);
    assert.deepEqual(staging(h.base), []); assert.equal(activeBundleId(h.base), h.id);
  } finally { s.cleanup(); h.cleanup(); }
});

test('D3 EFBIG for real (RLIMIT_FSIZE, Linux): the catchable path cleans up; the errno is recorded', {
  skip: process.platform !== 'linux' ? 'RLIMIT_FSIZE through bash ulimit: Linux only here' : false,
}, async (t) => {
  const h = await v3Host(); const s = otherSource();
  try {
    const blocks = Math.max(1, Math.floor(fs.statSync(s.db).size / 2 / 1024));
    // SIGXFSZ would otherwise TERMINATE the process (no cleanup at all: that is D3k, a kill). The harness ignores it so
    // the write returns EFBIG and the product's catchable-error path is what is exercised.
    const ignore = path.join(ROOT, 'test', 'helpers', 'ignore-sigxfsz.mjs');
    const r = await runNode(['-c', `ulimit -f ${blocks}; exec "${process.execPath}" --import "${ignore}" "${CLI}" update-seed --seed "${s.db}" --unsigned-development`],
      { env: { CHAINGATE_HOME: h.base }, home: h.home, timeoutMs: 30000, cmd: 'bash' });
    assert.equal(r.timedOut, false);
    assert.equal(r.code, 1, r.out);
    assert.match(r.out, /EFBIG|File too large/);
    t.diagnostic(`observed: ${(r.out.match(/[^\n]*(EFBIG|File too large)[^\n]*/) || [''])[0].trim()}`);
    assert.deepEqual(staging(h.base), [], 'the partial staging copy was removed');
    assert.equal(activeBundleId(h.base), h.id);
  } finally { s.cleanup(); h.cleanup(); }
});

// ---- ST1: the source is judged before SQLite ever opens it ---------------------------------------------------------
test('ST1 a FIFO source is refused as not a regular file before SQLite or any download; nothing staged', {
  skip: canFifo ? false : 'needs mkfifo (POSIX)',
}, async () => {
  const h = await v3Host(); const s = v3Source();
  try {
    fs.rmSync(s.db); mkfifo(s.db);
    const before = entries(h.base);
    const r = await runCli(h.base, ['update-seed', ...ARGS(s)], { timeoutMs: 10000 });
    assert.equal(r.timedOut, false);
    assert.equal(r.code, 1, r.out);
    assert.match(r.out, /FIFO, not a regular file/);
    assert.doesNotMatch(r.out, /Downloading/, 'a refused input must not turn into a download');
    assert.deepEqual(entries(h.base), before);
  } finally { s.cleanup(); h.cleanup(); }
});

// ---- D6: a real filesystem smaller than the seed (CI only: needs a mounted small filesystem) ------------------------
const SMALL = process.env.CG_R22_SMALL_FS;
test('D6 a real filesystem smaller than the seed: admission refuses; forced past it, real ENOSPC is cleaned up', {
  skip: SMALL ? false : 'NOT TESTED here: set CG_R22_SMALL_FS to a mounted small filesystem (CI: tmpfs, hdiutil)',
}, async () => {
  const s = otherSource();
  const base = fs.mkdtempSync(path.join(SMALL, 'cg-d6-'));
  try {
    // pad the seed past the filesystem's free space
    const st = fs.statfsSync(SMALL); const free = Number(st.bavail) * Number(st.bsize);
    const big = path.join(path.dirname(s.db), 'big-seed.db'); fs.copyFileSync(s.db, big);
    fs.appendFileSync(big, Buffer.alloc(free + 1024 * 1024));
    fs.writeFileSync(`${big}.sha256`, `${sha256(big)}\n`);
    const refused = await run(() => updateSeed(['--seed', big, '--unsigned-development'], deps(base)));
    assert.equal(refused.code, 1); assert.match(refused.all, /not enough free space/);
    const forced = await run(() => updateSeed(['--seed', big, '--unsigned-development'], deps(base, { seam: fakeFs(Number.MAX_SAFE_INTEGER) })));
    assert.equal(forced.code, 1, forced.all); assert.match(forced.all, /ENOSPC/);
    assert.deepEqual(exists(seedsDir(base)) ? staging(base) : [], []);
  } finally { s.cleanup(); fs.rmSync(base, { recursive: true, force: true }); }
});
