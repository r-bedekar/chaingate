// U-05 R2-2 legacy part, the downloader (Addendum 1 §5; O3: H = 256 MiB for the LEGACY database download only): an
// independent byte limit, backpressure, deadlines, handled errors at every stage, sidecars capped at 4 KiB, and an owned
// temporary directory that is removed on every exit path (and by the next seed command after a termination). Assets come
// from a loopback server; only the GitHub API listing is stubbed (u05-r22-download-child.mjs), so the same test runs
// against the code before and after. Options the old code does not take (deadlines, a smaller H) make those cases
// SEAM-ABSENT there; where the old code simply hangs, the child's hard timeout shows it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

import { ROOT, runNode, runCli, v3Host, age, deadPid, exists, freshHome } from '../helpers/u05-r22.mjs';

const CHILD = path.join(ROOT, 'test', 'helpers', 'u05-r22-download-child.mjs');
const SHA = Buffer.from(`${'a'.repeat(64)}\n`); const SIG = Buffer.alloc(64, 7);

/** A loopback asset server; `db(res)` decides how the database is served. */
async function server(db, { sig = SIG } = {}) {
  const s = http.createServer((req, res) => {
    if (req.url.endsWith('.sha256')) { res.setHeader('content-length', SHA.length); return res.end(SHA); }
    if (req.url.endsWith('.sig')) { res.setHeader('content-length', sig.length); return res.end(sig); }
    return db(res, req);
  });
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${s.address().port}`, close: () => new Promise((r) => { s.closeAllConnections?.(); s.close(r); }) };
}
/** Run the child with its own TMPDIR, so what it leaves behind is visible. */
async function child(srv, { base = '-', opts = {}, timeoutMs = 20000, cleanupAfter = false, bash = null } = {}) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-dl-tmp-'));
  const env = { TMPDIR: tmp, U05_DL_OPTS: JSON.stringify(opts), ...(cleanupAfter ? { U05_DL_CLEANUP: '1' } : {}) };
  const args = [CHILD, srv.url, base];
  const r = bash
    ? await runNode(['-c', `${bash}; exec "${process.execPath}" --import "${path.join(ROOT, 'test/helpers/ignore-sigxfsz.mjs')}" "${CHILD}" "${srv.url}" "${base}"`], { cmd: 'bash', env, timeoutMs })
    : await runNode(args, { env, timeoutMs });
  const results = r.stdout.split('\n').filter((l) => l.startsWith('RESULT ')).map((l) => JSON.parse(l.slice(7)));
  const left = fs.readdirSync(tmp);
  return { ...r, result: results[0] ?? null, results, left, tmp, done: () => fs.rmSync(tmp, { recursive: true, force: true }) };
}
const SMALL = { maxDb: 1024 * 1024, timeouts: { connectMs: 3000, idleMs: 1500, totalMs: 4000 } };

test('DL-C a write error mid-stream (RLIMIT_FSIZE) is HANDLED: a refusal, no crash, nothing left in the temporary directory', {
  skip: process.platform !== 'linux' ? 'bash ulimit: Linux only here' : false,
}, async () => {
  const body = Buffer.alloc(512 * 1024, 1);
  const srv = await server((res) => { res.setHeader('content-length', body.length); res.end(body); });
  try {
    const c = await child(srv, { bash: 'ulimit -f 64' });
    try {
      assert.equal(c.timedOut, false);
      assert.ok(c.result, `the child crashed instead of reporting (an unhandled 'error' event)\n${c.out}`);
      assert.equal(c.result.ok, false);
      assert.match(c.result.message, /EFBIG|too large/i);
      assert.deepEqual(c.left, [], `left behind: ${c.left.join(', ')}`);
    } finally { c.done(); }
  } finally { await srv.close(); }
});

test('DL-D an idle stall (no bytes) is refused at the idle deadline; nothing left', async () => {
  const srv = await server((res) => { res.setHeader('content-length', 10_000_000); res.write(Buffer.alloc(1024)); /* then nothing */ });
  try {
    const c = await child(srv, { opts: SMALL, timeoutMs: 12000 });
    try {
      assert.equal(c.timedOut, false, 'the download hung (no idle deadline)');
      assert.equal(c.result?.kind, 'stalled', JSON.stringify(c.result));
      assert.deepEqual(c.left, []);
    } finally { c.done(); }
  } finally { await srv.close(); }
});

test('DL-E a trickle that never ends is refused at the total deadline; nothing left', async () => {
  const srv = await server((res) => { res.setHeader('content-length', 10_000_000);
    const t = setInterval(() => { if (!res.write(Buffer.alloc(1))) { /* ignore */ } }, 100); res.on('close', () => clearInterval(t)); });
  try {
    const c = await child(srv, { opts: SMALL, timeoutMs: 12000 });
    try {
      assert.equal(c.timedOut, false, 'the download hung (no total deadline)');
      assert.equal(c.result?.kind, 'timeout', JSON.stringify(c.result));
      assert.deepEqual(c.left, []);
    } finally { c.done(); }
  } finally { await srv.close(); }
});

test('DL-F more than the limit with NO Content-Length is refused on the bytes received', async () => {
  const srv = await server((res) => { res.write(Buffer.alloc(800 * 1024)); res.write(Buffer.alloc(800 * 1024)); res.end(); });
  try {
    const c = await child(srv, { opts: SMALL });
    try {
      assert.equal(c.result?.ok, false, `downloaded past the limit: ${JSON.stringify(c.result)}`);
      assert.equal(c.result.kind, 'too-large'); assert.deepEqual(c.left, []);
    } finally { c.done(); }
  } finally { await srv.close(); }
});

test('DL-G a Content-Length above the limit is refused before the body is read', async () => {
  let wrote = 0;
  const srv = await server((res) => { res.setHeader('content-length', 3 * 1024 * 1024);
    const t = setInterval(() => { wrote += 65536; if (wrote > 3 * 1024 * 1024) { clearInterval(t); res.end(); } else res.write(Buffer.alloc(65536)); }, 20);
    res.on('close', () => clearInterval(t)); });
  try {
    const c = await child(srv, { opts: SMALL });
    try {
      assert.equal(c.result?.ok, false, JSON.stringify(c.result)); assert.equal(c.result.kind, 'too-large');
      assert.match(c.result.message, /declares/); assert.deepEqual(c.left, []);
    } finally { c.done(); }
  } finally { await srv.close(); }
});

test('DL-H fewer bytes than declared (the connection drops) fails, and the directory is removed', async () => {
  const srv = await server((res) => { res.setHeader('content-length', 100_000); res.write(Buffer.alloc(5000)); setTimeout(() => res.destroy(), 50); });
  try {
    const c = await child(srv, { opts: SMALL });
    try { assert.equal(c.result?.ok, false); assert.deepEqual(c.left, [], `left behind: ${c.left}`); } finally { c.done(); }
  } finally { await srv.close(); }
});

test('DL-J a server error on the database removes the temporary directory (network failure path)', async () => {
  const srv = await server((res) => { res.statusCode = 500; res.end('no'); });
  try {
    const c = await child(srv, {});
    try { assert.equal(c.result?.ok, false); assert.deepEqual(c.left, [], `left behind: ${c.left}`); } finally { c.done(); }
  } finally { await srv.close(); }
});

test('DL-N a sidecar larger than 4 KiB is refused', async () => {
  const body = Buffer.alloc(1000, 1);
  const srv = await server((res) => { res.setHeader('content-length', body.length); res.end(body); }, { sig: Buffer.alloc(5000, 1) });
  try {
    const c = await child(srv, {});
    try {
      assert.equal(c.result?.ok, false, `a 5000-byte signature was accepted: ${JSON.stringify(c.result)}`);
      assert.equal(c.result.kind, 'too-large'); assert.deepEqual(c.left, []);
    } finally { c.done(); }
  } finally { await srv.close(); }
});

test('DL-L success: the bundle is complete, and cleanup() removes the directory and its record (directory first)', async () => {
  const body = Buffer.alloc(200 * 1024, 3);
  const srv = await server((res) => { res.setHeader('content-length', body.length); res.end(body); });
  const { home, base } = freshHome('dl');
  try {
    const c = await child(srv, { base, cleanupAfter: true });
    try {
      assert.equal(c.result?.ok, true, JSON.stringify(c.result)); assert.equal(c.result.size, body.length);
      assert.deepEqual(c.results[1], { cleaned: true, dirLeft: false }, 'cleanup() removed the directory');
      assert.deepEqual(fs.readdirSync(base).filter((n) => n.startsWith('.download-')), [], 'and then its record');
    } finally { c.done(); }
  } finally { await srv.close(); fs.rmSync(home, { recursive: true, force: true }); }
});

test('DL-M a download killed mid-way: the next seed command removes ONLY the recorded directory (dead pid, old), then the record', async () => {
  const srv = await server((res) => { res.setHeader('content-length', 10_000_000); res.write(Buffer.alloc(4096)); });
  const h = await v3Host();
  try {
    const c = await child(srv, { base: h.base, timeoutMs: 3000 });          // killed by the hard timeout while stalled
    try {
      assert.equal(c.timedOut, true);
      const rec = fs.readdirSync(h.base).filter((n) => /^\.download-\d+\.json$/.test(n));
      assert.equal(rec.length, 1, 'the running download recorded its directory');
      const dir = JSON.parse(fs.readFileSync(path.join(h.base, rec[0]), 'utf8')).dir;
      assert.equal(exists(dir), true);
      // a decoy beside it that no record names is never touched
      const decoy = path.join(c.tmp, 'chaingate-seed-ffffffffffff'); fs.mkdirSync(decoy);
      age(path.join(h.base, rec[0]), 20); age(dir, 20);
      const r = await runCli(h.base, ['update-seed'], { timeoutMs: 20000, env: { TMPDIR: c.tmp } });
      assert.equal(r.timedOut, false);
      assert.equal(exists(dir), false, 'the recorded directory was removed');
      assert.equal(exists(path.join(h.base, rec[0])), false, 'then its record');
      assert.equal(exists(decoy), true, 'an unrecorded directory is kept');
    } finally { c.done(); }
  } finally { await srv.close(); h.cleanup(); }
});
