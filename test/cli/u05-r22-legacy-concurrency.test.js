// U-05 R2-2 legacy part, owner decision 7 requirements 4 (the kill case) and 5, through the real commands only.
//   4. A missing witness.db is created from a complete, verified, closed staging file in the destination directory and
//      published with link(2), which refuses an existing destination; a destination created first takes the
//      existing-database path; an unsupported link REFUSES (no copy fallback); a kill never exposes a partial witness.db.
//   5. The concurrency claims, exactly: a writer holding its lock past the busy timeout -> refusal, nothing committed; a
//      writer finishing within it -> the refresh proceeds after it; a running proxy -> refused by policy; and the real
//      CLI/proxy interaction while a refresh holds the write lock (the proxy starts on the old snapshot, I6; its decision
//      write waits and then fails through storage health; status reads old counts, then new ones).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';

import { freshHome, runCli, runNode, startMutator, freePort, exists, PROXY, ROOT } from '../helpers/u05-r22.mjs';
import { testKey, buildLegacySeed, legacyWitness, snapshot, project, DEFAULT_PKGS, NEW_PKGS } from '../helpers/u05-r22-legacy.mjs';
import { resolvePaths } from '../../cli/paths.js';
import { docFor } from '../seed-v3/u05-fixtures.mjs';

const key = testKey();
const MARKER_FILE = 'witness.db.install-pending.json';
const env = (bundle) => ({ U05_LEGACY_BUNDLE: bundle.dir, U05_TEST_SPKI: key.spki });
const fileSha = (f) => createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const pathsFor = (base) => resolvePaths('user', process.cwd(), { CHAINGATE_HOME: base });
const stagedOf = (seed) => ({ path: seed.db, size: seed.size, digest: seed.digest, sha256Bytes: fs.readFileSync(seed.sha),
  sigBytes: fs.readFileSync(seed.sig), source: 'test' });
const leftovers = (base) => fs.readdirSync(base).filter((n) => /staging|install-pending/.test(n));
const LOCAL = { decisions: [{ id: 5, pkg: 'alpha', ver: '1.0.0', disposition: 'BLOCK', at: '2026-02-01 00:00:00' }] };


test('C-4 killed while copying beside witness.db: no witness.db ever exists partially; completion creates it', async () => {
  const { home, base } = freshHome('create');
  try {
    const seed = buildLegacySeed(path.join(home, 'seed'), { key });
    // init --seed <legacy> on a fresh host: copy #1 is the private staging, copy #2 the one beside witness.db
    const m = startMutator(base, 'init', ['--seed', seed.db], { killAt: 'midStagingCopy', nth: 2, env: env(seed) });
    assert.equal(await m.at('midStagingCopy'), true, 'SEAM-ABSENT'); await m.done;
    assert.equal(exists(path.join(base, 'witness.db')), false, 'no partial witness.db');
    assert.equal(exists(path.join(base, MARKER_FILE)), true, 'the installation is pending');
    const c = startMutator(base, 'update-seed', [], { env: env(seed) }); const r = await c.done;
    assert.equal(r.code, 0, r.all);
    assert.equal(fileSha(path.join(base, 'witness.db')), seed.digest);
    assert.equal(exists(path.join(base, MARKER_FILE)), false);
  } finally { fs.rmSync(home, { recursive: true, force: true }); }
});

// ---- requirement 5 ---------------------------------------------------------------------------------------------------
/** A process holding a write transaction on `db` for `ms`, then committing nothing and exiting. */
function writer(db, ms) {
  const src = `const D=require(${JSON.stringify(path.join(ROOT, 'node_modules', 'better-sqlite3'))});const d=new D(${JSON.stringify(db)});`
    + `d.exec('BEGIN IMMEDIATE');process.stdout.write('HELD\\n');setTimeout(()=>{d.exec('ROLLBACK');d.close();process.exit(0)},${ms});`;
  const c = spawn(process.execPath, ['-e', src], { stdio: ['ignore', 'pipe', 'inherit'] });
  const held = new Promise((resolve) => { let o = ''; c.stdout.on('data', (x) => { o += x; if (o.includes('HELD')) resolve(true); }); c.on('close', () => resolve(false)); });
  return { held, done: new Promise((resolve) => c.on('close', resolve)) };
}
function legacyHost() {
  const { home, base } = freshHome('conc');
  const old = buildLegacySeed(path.join(home, 'old'), { key, seedVersion: '2026.test.old', pkgs: DEFAULT_PKGS });
  const neu = buildLegacySeed(path.join(home, 'new'), { key, seedVersion: '2026.test.new', pkgs: NEW_PKGS });
  // no persisted pair: the integrity gate verifies a pair with the PINNED key, which a test-key pair could never pass
  const w = legacyWitness(base, { from: 'seed', seed: old, local: LOCAL, sidecars: false });
  return { home, base, w, old, neu, cleanup: () => fs.rmSync(home, { recursive: true, force: true }) };
}
const seedVersionOf = (w) => snapshot(w).rows.seed_metadata.find((r) => r.key === 'seed_version')?.value;

test('K-1 a writer holding its lock past the 2 s busy timeout: refused, nothing committed, no marker left', async () => {
  const h = legacyHost();
  try {
    const before = snapshot(h.w);
    const wr = writer(h.w, 6000); assert.equal(await wr.held, true);
    const t0 = Date.now(); const m = startMutator(h.base, 'update-seed', [], { env: env(h.neu) }); const r = await m.done;
    const took = Date.now() - t0;
    await wr.done;
    assert.equal(r.code, 1, r.all);
    assert.match(r.all, /did not finish within 2 s; the refresh was refused and nothing was committed/);
    assert.deepEqual(snapshot(h.w).rows, before.rows);
    assert.equal(exists(path.join(h.base, MARKER_FILE)), false);
    assert.ok(took < 6000, `refused after the busy timeout, not after the writer (${took} ms)`);
  } finally { h.cleanup(); }
});

test('K-2 a writer finishing WITHIN the busy timeout: the refresh is serialized after it and succeeds', async () => {
  const h = legacyHost();
  try {
    const wr = writer(h.w, 500); assert.equal(await wr.held, true);
    const m = startMutator(h.base, 'update-seed', [], { env: env(h.neu) }); const r = await m.done; await wr.done;
    assert.equal(r.code, 0, r.all);
    assert.equal(seedVersionOf(h.w), '2026.test.new');
  } finally { h.cleanup(); }
});

test('K-3 policy precondition: a running proxy (or one whose liveness the OS refuses to report) refuses the replacement', {
  skip: process.platform === 'win32' || process.getuid?.() === 0 ? 'needs a non-root POSIX user (pid 1 -> EPERM)' : false,
}, async () => {
  const h = legacyHost();
  const sleeper = spawn(process.execPath, ['-e', 'setTimeout(()=>{},30000)'], { stdio: 'ignore' });
  try {
    const before = snapshot(h.w);
    for (const [pid, why] of [[sleeper.pid, /is running; stop it first: chaingate stop/], [1, /may be running; stop it first/]]) {
      fs.writeFileSync(path.join(h.base, 'proxy.pid'), String(pid));
      const r = await (startMutator(h.base, 'update-seed', [], { env: env(h.neu) })).done;
      assert.equal(r.code, 1, r.all); assert.match(r.all, why);
    }
    assert.deepEqual(snapshot(h.w).rows, before.rows);
  } finally { sleeper.kill('SIGKILL'); h.cleanup(); }
});

const getJson = (url) => new Promise((resolve) => {
  http.get(url, { agent: false }, (res) => { let b = ''; res.on('data', (x) => { b += x; }); res.on('end', () => {
    let json = null; try { json = JSON.parse(b); } catch { /* not JSON */ } resolve({ status: res.statusCode, json }); }); })
    .on('error', (e) => resolve({ status: 0, error: e.message }));
});

test('K-4 the CLI/proxy interaction while a refresh holds the write lock: the proxy starts on the old snapshot, its decision write fails through storage health, status reads old then new', async () => {
  const h = legacyHost();
  const upstream = http.createServer((req, res) => {
    const name = decodeURIComponent(req.url.slice(1));
    res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(docFor(name)));
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  let proxy = null;
  try {
    const m = startMutator(h.base, 'update-seed', [], { pauseAt: 'duringRefresh', env: env(h.neu) });
    assert.equal(await m.at('duringRefresh'), true, 'SEAM-ABSENT: no duringRefresh point');
    // status during the held refresh: the old committed state
    const s1 = JSON.parse((await runCli(h.base, ['status', '--json'], { timeoutMs: 20000 })).stdout);
    assert.equal(s1.seed.version, '2026.test.old');
    // the real proxy entry starts during it (I6)
    const port = await freePort();
    proxy = spawn(process.execPath, [PROXY], { env: { ...process.env, CHAINGATE_HOME: h.base, HOME: h.home,
      CHAINGATE_WITNESS_DB: h.w, CHAINGATE_PORT: String(port), CHAINGATE_HOST: '127.0.0.1',
      CHAINGATE_UPSTREAM: `http://127.0.0.1:${upstream.address().port}` }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = ''; proxy.stdout.on('data', (x) => { out += x; }); proxy.stderr.on('data', (x) => { out += x; });
    const t0 = Date.now(); while (!/listening on/.test(out) && Date.now() - t0 < 15000) await new Promise((r) => setTimeout(r, 50));
    assert.match(out, /listening on/, `the proxy did not start during the held refresh\n${out}`);
    // a packument fetch makes the proxy try to store a decision: it waits for the lock, then fails, and says so
    const pk = await getJson(`http://127.0.0.1:${port}/zeta`);
    assert.ok(pk.status === 200 || pk.status >= 400, `answered (${pk.status})`);
    const self = await getJson(`http://127.0.0.1:${port}/_chaingate/self`);
    assert.match(String(self.json?.storage?.state), /failing/, `storage: ${JSON.stringify(self.json?.storage)}`);
    // the refresh commits; status now reads the new state (separate statements: no single snapshot is claimed)
    m.go(); const r = await m.done;
    assert.equal(r.code, 0, r.all);
    const s2 = JSON.parse((await runCli(h.base, ['status', '--json'], { timeoutMs: 20000 })).stdout);
    assert.equal(s2.seed.version, '2026.test.new');
  } finally {
    if (proxy) proxy.kill('SIGKILL');
    await new Promise((r) => upstream.close(r));
    h.cleanup();
  }
});
