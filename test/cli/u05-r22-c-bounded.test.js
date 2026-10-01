// U-05 R2-2 (c): the complete metadata and sidecar access path is bounded (R2-2 §3, Addendum 1 §4). Failing-first: every
// case here goes through an entry point that exists at r2 head d757aa7, so the same file shows the defect there and the
// fix after. Blocking cases run the REAL commands and the REAL proxy entry in child processes with hard timeouts, so the
// evidence shows whether the open itself returned.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { generateKeyPairSync, sign as edSign, createHash } from 'node:crypto';
import Database from 'better-sqlite3';

import { verifyBundleDir, seedsDir } from '../../cli/seed-bundle.js';
import { ROOT, v3Host, v3Source, freshHome, runCli, runProxyEntry, metered, canFifo, replaceWith, replaceWithFifo, padded,
  sparse, exists, sha256 } from '../helpers/u05-r22.mjs';

const VERIFY = path.join(ROOT, 'test', 'helpers', 'u05-r22-verify-bundle.mjs');
const BLOCK_MS = 10000;             // a refusal returns in well under a second; a blocked open never returns
const fifoOnly = { skip: canFifo ? false : 'needs mkfifo (POSIX); Windows device and pipe cases are W-C1/W-C2' };
const bundleNames = (base) => fs.readdirSync(seedsDir(base)).sort();
/** `doctor --json` prints the array of checks. */
const doctorChecks = (r) => { try { return JSON.parse(r.stdout); } catch { assert.fail(`doctor --json printed no JSON:\n${r.out}`); } };
/** Every command's outcome is collected before asserting, so the record shows each one, not only the first. */
function assertAllPrompt(results) {
  const blocked = Object.entries(results).filter(([, r]) => r.timedOut).map(([k]) => k);
  assert.deepEqual(blocked, [], `blocked (still running after ${BLOCK_MS} ms): ${blocked.join(', ')}`);
}

/** A second synthetic seed that would install as a NEW bundle (different snapshot digest). */
function otherSource() {
  const s = v3Source();
  const h = new Database(s.db); h.prepare("UPDATE seed_metadata SET value = ? WHERE key = 'corpus_snapshot_digest'").run('d'.repeat(64)); h.close();
  fs.writeFileSync(s.sha, `${sha256(s.db)}\n`);
  return s;
}

// ---- C1: bundle.json padded past its 64 KiB cap --------------------------------------------------------------------
test('C1a verifyBundleDir refuses a bundle.json larger than 64 KiB, naming the limit', async () => {
  const h = await v3Host();
  try {
    replaceWith(h.files.manifest, padded(fs.readFileSync(h.files.manifest, 'utf8'), 65537));
    const v = verifyBundleDir(h.dir);
    assert.equal(v.ok, false, 'a 65,537-byte manifest must not be read and accepted');
    assert.match(v.why, /65536-byte limit/);
  } finally { h.cleanup(); }
});

test('C1b doctor reports the active bundle unusable, naming the manifest limit', async () => {
  const h = await v3Host();
  try {
    replaceWith(h.files.manifest, padded(fs.readFileSync(h.files.manifest, 'utf8'), 65537));
    const r = await runCli(h.base, ['doctor', '--json'], { timeoutMs: BLOCK_MS });
    assert.equal(r.timedOut, false);
    const seed = doctorChecks(r).find((c) => c.name === 'seed-v3');
    assert.equal(seed.pass, false);
    assert.match(seed.detail, /65536-byte limit/);
  } finally { h.cleanup(); }
});

test('C1c the proxy refuses to start on a bundle whose manifest exceeds the limit', async () => {
  const h = await v3Host();
  try {
    replaceWith(h.files.manifest, padded(fs.readFileSync(h.files.manifest, 'utf8'), 65537));
    const r = await runProxyEntry(h.base, { timeoutMs: BLOCK_MS });
    assert.equal(r.timedOut, false, 'it must refuse at start-up, not start serving');
    assert.notEqual(r.code, 0);
    assert.match(r.out, /65536-byte limit/);
  } finally { h.cleanup(); }
});

test('C1d status returns, and reports the manifest as unreadable with the limit', async () => {
  const h = await v3Host();
  try {
    replaceWith(h.files.manifest, padded(fs.readFileSync(h.files.manifest, 'utf8'), 65537));
    const r = await runCli(h.base, ['status', '--json'], { timeoutMs: BLOCK_MS });
    assert.equal(r.timedOut, false);
    const rec = JSON.parse(r.stdout);
    assert.equal(rec.seed_v3.active, true);
    assert.match(String(rec.seed_v3.manifest_error), /65536-byte limit/);
  } finally { h.cleanup(); }
});

// ---- C2: the bundle's own .sha256 past its 4 KiB cap ---------------------------------------------------------------
test('C2 a bundle .sha256 larger than 4 KiB is refused by the reader, naming the limit', async () => {
  const h = await v3Host();
  try {
    replaceWith(h.files.sha256, padded(fs.readFileSync(h.files.sha256, 'utf8'), 4097));
    const v = verifyBundleDir(h.dir);
    assert.equal(v.ok, false);
    assert.match(v.why, /4096-byte limit/);
    const p = await runProxyEntry(h.base, { timeoutMs: BLOCK_MS });
    assert.equal(p.timedOut, false); assert.notEqual(p.code, 0); assert.match(p.out, /4096-byte limit/);
  } finally { h.cleanup(); }
});

// ---- C3: the INCOMING .sha256 past its cap (update-seed --seed, M2) -------------------------------------------------
test('C3 update-seed --seed refuses an incoming .sha256 larger than 4 KiB before staging anything', async () => {
  const h = await v3Host(); const s = otherSource();
  try {
    replaceWith(s.sha, padded(`${sha256(s.db)}\n`, 4097));
    const before = bundleNames(h.base);
    const r = await runCli(h.base, ['update-seed', '--seed', s.db, '--unsigned-development'], { timeoutMs: BLOCK_MS });
    assert.equal(r.timedOut, false);
    assert.equal(r.code, 1, r.out);
    assert.match(r.out, /4096-byte limit/);
    assert.deepEqual(bundleNames(h.base), before, 'nothing staged, installed or left behind');
  } finally { s.cleanup(); h.cleanup(); }
});

// ---- C4: the legacy persisted .sha256 past its cap --------------------------------------------------------------------
function testKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { spki: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'), privateKey };
}

test('C4a verifyPersistedSignature refuses a .sha256 larger than 4 KiB (SEED_FILE_REFUSED), signature or not', async () => {
  const k = testKeyPair();
  const h = await v3Host();
  try {
    const digest = createHash('sha256').update('synthetic legacy seed').digest('hex');
    const sha = path.join(h.base, 'witness.db.sha256'); const sig = path.join(h.base, 'witness.db.sig');
    fs.writeFileSync(sha, padded(`${digest}\n`, 4097));
    fs.writeFileSync(sig, edSign(null, Buffer.from(digest, 'ascii'), k.privateKey));
    const r = await metered(VERIFY, ['persisted', sha, sig, k.spki]);
    const v = JSON.parse(r.stdout.trim().split('\n').pop());
    assert.equal(v.ok, false, 'a padded digest file must not verify');
    assert.equal(v.code, 'SEED_FILE_REFUSED');
  } finally { h.cleanup(); }
});

test('C4b doctor reports an oversized persisted .sha256 as SEED_FILE_REFUSED', async () => {
  const h = await v3Host();
  try {
    fs.writeFileSync(path.join(h.base, 'witness.db.sha256'), padded(`${'a'.repeat(64)}\n`, 4097));
    fs.writeFileSync(path.join(h.base, 'witness.db.sig'), Buffer.alloc(64, 1));
    const r = await runCli(h.base, ['doctor', '--json'], { timeoutMs: BLOCK_MS });
    const c = doctorChecks(r).find((x) => x.name === 'seed-signature');
    assert.equal(c.pass, false);
    assert.match(c.detail, /SEED_FILE_REFUSED/);
  } finally { h.cleanup(); }
});

// ---- C5: the bundle .sig: at most cap + 1 bytes read, INCLUDING verifyBundleDir's own hash of it --------------------
test('C5 a sparse 256 MiB bundle .sig is refused after reading at most 4097 bytes per access', async () => {
  const h = await v3Host();
  try {
    sparse(h.files.sig, 256 * 1024 * 1024);
    const r = await metered(VERIFY, ['bundle', h.dir]);
    const v = JSON.parse(r.stdout.trim().split('\n').pop());
    assert.equal(v.ok, false);
    const sigReads = r.accesses.filter((a) => a.path === h.files.sig);
    assert.ok(sigReads.length > 0, 'the meter saw the .sig being read');
    const most = Math.max(...sigReads.map((a) => a.bytes));
    assert.ok(most <= 4097, `an access read ${most} bytes of the .sig (limit 4096 + 1)`);
  } finally { h.cleanup(); }
});

test('C5b a bundle .sig of 4097 bytes is refused, naming the limit', async () => {
  const h = await v3Host();
  try {
    replaceWith(h.files.sig, Buffer.alloc(4097, 7));
    const v = verifyBundleDir(h.dir);
    assert.equal(v.ok, false);
    assert.match(v.why, /4096-byte limit/);
  } finally { h.cleanup(); }
});

// ---- C6 / C8 (POSIX): a FIFO with no writer at each path, through the actual commands -------------------------------
// Expected after: a prompt refusal. On d757aa7 the open blocks, so the child is still running at the deadline.
const promptRefusal = (r, what) => {
  assert.equal(r.timedOut, false, `${what}: the command blocked (still running after ${BLOCK_MS} ms)`);
  assert.notEqual(r.code, 0, `${what}: a FIFO must be refused, not accepted\n${r.out}`);
};

test('C6 incoming seed database is a FIFO: update-seed --seed and init --seed return promptly', fifoOnly, async () => {
  const h = await v3Host(); const s = v3Source();
  try {
    replaceWithFifo(s.db);
    const before = bundleNames(h.base);
    // init on a fresh host (no witness database, nothing active): the FIFO is the first thing it would read
    const f = freshHome();
    try {
      const u = await runCli(h.base, ['update-seed', '--seed', s.db, '--unsigned-development'], { timeoutMs: BLOCK_MS });
      const i = await runCli(f.base, ['init', '--seed', s.db, '--unsigned-development'], { timeoutMs: BLOCK_MS });
      assertAllPrompt({ 'update-seed': u, init: i });
      promptRefusal(u, 'update-seed'); promptRefusal(i, 'init');
      assert.equal(i.spawnedProxy, undefined, 'no proxy was started');
      assert.deepEqual(bundleNames(h.base), before);
    } finally { fs.rmSync(f.home, { recursive: true, force: true }); }
  } finally { s.cleanup(); h.cleanup(); }
});

test('C6 incoming .sha256 and .sig are FIFOs: update-seed --seed returns promptly', fifoOnly, async () => {
  const h = await v3Host();
  try {
    for (const which of ['sha', 'sig']) {
      const s = otherSource();
      try {
        if (which === 'sig') fs.writeFileSync(s.sig, Buffer.alloc(64));    // a .sig makes the signed path read it
        replaceWithFifo(which === 'sha' ? s.sha : s.sig);
        const before = bundleNames(h.base);
        promptRefusal(await runCli(h.base, ['update-seed', '--seed', s.db, '--unsigned-development'], { timeoutMs: BLOCK_MS }),
          `incoming .${which}`);
        assert.deepEqual(bundleNames(h.base), before);
      } finally { s.cleanup(); }
    }
  } finally { h.cleanup(); }
});

for (const [label, pick] of [['bundle.json', (h) => h.files.manifest], ['bundle database', (h) => h.files.db],
  ['bundle .sha256', (h) => h.files.sha256], ['bundle .sig', (h) => h.files.sig]]) {
  test(`C6 ${label} is a FIFO: the proxy entry and doctor return promptly`, fifoOnly, async () => {
    const h = await v3Host();
    try {
      replaceWithFifo(pick(h));
      const p = await runProxyEntry(h.base, { timeoutMs: BLOCK_MS });
      const d = await runCli(h.base, ['doctor', '--json'], { timeoutMs: BLOCK_MS });
      assertAllPrompt({ [`proxy start (${label})`]: p, [`doctor (${label})`]: d });
      promptRefusal(p, `proxy start (${label})`);
      const seed = doctorChecks(d).find((c) => c.name === 'seed-v3');
      assert.equal(seed.pass, false, `doctor must report the bundle unusable (${label})`);
    } finally { h.cleanup(); }
  });
}

test('C8 status returns promptly when the active bundle.json is a FIFO', fifoOnly, async () => {
  const h = await v3Host();
  try {
    replaceWithFifo(h.files.manifest);
    const r = await runCli(h.base, ['status', '--json'], { timeoutMs: BLOCK_MS });
    assert.equal(r.timedOut, false, 'status blocked');
    assert.equal(r.code, 0);
    assert.match(String(JSON.parse(r.stdout).seed_v3.manifest_error), /FIFO/);
  } finally { h.cleanup(); }
});

test('C6 config.json is a FIFO: doctor and the proxy entry return promptly', fifoOnly, async () => {
  const h = await v3Host();
  try {
    replaceWithFifo(path.join(h.base, 'config.json'));
    const p = await runProxyEntry(h.base, { timeoutMs: BLOCK_MS });
    const d = await runCli(h.base, ['doctor', '--json'], { timeoutMs: BLOCK_MS });
    assertAllPrompt({ 'proxy start (config.json)': p, 'doctor (config.json)': d });
    promptRefusal(p, 'proxy start (config.json)');
    const c = doctorChecks(d).find((x) => x.name === 'config');
    assert.equal(c.pass, false);
  } finally { h.cleanup(); }
});

test('C6 the persisted legacy witness.db.sha256 is a FIFO: doctor returns promptly', fifoOnly, async () => {
  const h = await v3Host();
  try {
    fs.writeFileSync(path.join(h.base, 'witness.db.sig'), Buffer.alloc(64, 1));
    replaceWithFifo(path.join(h.base, 'witness.db.sha256'));
    const d = await runCli(h.base, ['doctor', '--json'], { timeoutMs: BLOCK_MS });
    assert.equal(d.timedOut, false, 'doctor blocked on the persisted .sha256');
    const c = doctorChecks(d).find((x) => x.name === 'seed-signature');
    assert.equal(c.pass, false); assert.match(c.detail, /SEED_FILE_REFUSED/);
  } finally { h.cleanup(); }
});

// ---- C6b (POSIX): a character device. Not run on d757aa7: there a read of /dev/zero grows without bound ------------
test('C6b a sidecar that resolves to /dev/zero is refused as not a regular file', {
  skip: process.platform === 'win32' ? 'POSIX device path'
    : (exists(path.join(ROOT, 'seed', 'v3', 'bounded-file.js')) ? false
      : 'not run on the unfixed code: reading /dev/zero there allocates without bound'),
}, async () => {
  const h = await v3Host();
  try {
    fs.chmodSync(h.files.sha256, 0o644); fs.rmSync(h.files.sha256); fs.symlinkSync('/dev/zero', h.files.sha256);
    const v = verifyBundleDir(h.dir);
    assert.equal(v.ok, false); assert.match(v.why, /character device/);
  } finally { h.cleanup(); }
});
