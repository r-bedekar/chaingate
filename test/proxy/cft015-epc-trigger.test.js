// 0.1.5 trigger addition (operator decision 2026-10-21, Phase A ruling 1 pending): the entry-path-change NOTE arms the keep-list
// walk, beside a named WARN row, the identity-break NOTE and the seed's coverage WARN (ruling 2026-10-13). entry-path-change reads
// scripts, bin and main of the version and of its lineage predecessor from the full packument the proxy always fetches
// (proxy/registry.js accept: application/json; the client's install-v1 accept is never relayed), so the trigger needs no new source.
// Failing first: written before the code. Tarballs are synthetic; nothing is run.
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
import { classify } from '../../witness/row-class.js';

const SC = () => import('../../proxy/static-checks.js');

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
// e: 1.8.0 moves main from index.js to lib/run.js after eight versions that kept index.js (the gates' first-seen history floor)
//    -> entry-path-change NOTE (contributing), nothing named -> armed
// f: a first version (no history, no lineage predecessor) -> entry-path-change is not a NOTE -> not armed, as before
// the per-version fields a real packument carries, so the proxy records each version as history
const REAL = (name, v) => ({ _npmUser: { name: 'maintainer', email: 'm@example.com' }, _npmVersion: '10.9.2',
  dist: { shasum: `shasum-${name}-${v}`, integrity: `sha512-${name}-${v}==`, tarball: `https://registry.npmjs.org/${name}/-/${name}-${v}.tgz`, unpackedSize: 1000 } });
const EV = Array.from({ length: 9 }, (_, i) => `1.${i}.0`);
const E = { name: 'e', 'dist-tags': { latest: '1.8.0' }, time: Object.fromEntries(EV.map((v, i) => [v, at(48 * i)])),
  versions: Object.fromEntries(EV.map((v) => [v, { name: 'e', version: v, main: v === '1.8.0' ? 'lib/run.js' : 'index.js', ...REAL('e', v) }])) };
const F = { name: 'f', 'dist-tags': { latest: '1.0.0' }, time: { '1.0.0': at(0) },
  versions: { '1.0.0': { name: 'f', version: '1.0.0', main: 'lib/run.js' } } };
const DOCS = { '/e': E, '/f': F };
const TARBALLS = {
  '/e/-/e-1.8.0.tgz': tgz({ 'package.json': JSON.stringify(E.versions['1.8.0']), 'lib/run.js': BENIGN }),
  '/f/-/f-1.0.0.tgz': tgz({ 'package.json': JSON.stringify(F.versions['1.0.0']), 'lib/run.js': BENIGN }),
};
async function withProxy(fn) {
  resetDependencyCache(); forgetManifestHooks();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-epc-'));
  const upstream = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]);
    if (TARBALLS[u]) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end(TARBALLS[u]); return; }
    if (DOCS[u]) { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(DOCS[u])); return; }
    res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}');
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${upstream.address().port}`,
    witnessDbPath: path.join(dir, 'witness.db'), headersTimeoutMs: 10_000, bodyTimeoutMs: 10_000 });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${proxy.address().port}`;
  try { return await fn({ base, proxy }); } finally {
    await new Promise((r) => proxy.close(r)); await new Promise((r) => upstream.close(r)); fs.rmSync(dir, { recursive: true, force: true });
    resetDependencyCache(); forgetManifestHooks();
  }
}
const get = (u, headers = {}) => new Promise((resolve, reject) => http.get(u, { agent: false, headers }, (res) => {
  const chunks = []; res.on('data', (x) => chunks.push(x)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
}).on('error', reject));
const settle = () => new Promise((r) => setTimeout(r, 200));
const rowsOf = (proxy, pkg, v) => proxy.witnessDb.getLatestDecision(pkg, v).gates_fired;
const srow = (proxy, pkg, v, id) => rowsOf(proxy, pkg, v).find((g) => g.gate.startsWith(`static:${id}-`));
const WARN = (gate) => ({ gate, result: 'WARN', detail: 'x' }); const NOTE = (gate) => ({ gate, result: 'NOTE', detail: 'x' });

test('EPC-U1 armedBy: the entry-path-change NOTE arms; its ALLOW or SKIP does not', async () => {
  const S = await SC();
  assert.equal(S.armedBy([NOTE('entry-path-change')]), 'entry-path-change');
  assert.equal(S.armedBy([NOTE('entry-path-change'), NOTE('size-jump')]), 'entry-path-change');
  assert.equal(S.armedBy([{ gate: 'entry-path-change', result: 'ALLOW', detail: 'x' }]), null);
  assert.equal(S.armedBy([{ gate: 'entry-path-change', result: 'SKIP', detail: 'not applicable: no lineage predecessor' }]), null, 'cold start does not arm');
  assert.equal(S.armedBy([WARN('entry-path-change')]), null, 'a raw WARN the role table has not turned into a NOTE is not the contributing row');
});

test('EPC-U2 the 2026-10-13 triggers keep their reasons: a named row and the identity-break NOTE are still named as before', async () => {
  const S = await SC();
  assert.equal(S.armedBy([WARN('install-introduced'), NOTE('entry-path-change')]), 'named row install-introduced');
  assert.equal(S.armedBy([NOTE('identity-break')]), 'identity-break');
});

test('EPC-E1 a main move against the lineage predecessor arms the walk: the static rows say "armed by entry-path-change"', async () => {
  await withProxy(async ({ base, proxy }) => {
    await get(`${base}/e`); await get(`${base}/e`);    // the second pass sees the first one's eight versions as history
    const t = await get(`${base}/e/-/e-1.8.0.tgz`);
    assert.equal(t.status, 200); assert.ok(t.body.equals(TARBALLS['/e/-/e-1.8.0.tgz']), 'the download is served as is');
    await settle();
    const all = rowsOf(proxy, 'e', '1.8.0');
    assert.ok(classify(all).contributing.includes('entry-path-change'), JSON.stringify(all));
    assert.equal(classify(all).named.length, 0, 'nothing named: only the new trigger can arm this walk');
    for (const id of ['S0', 'S1', 'S2', 'S3', 'S4', 'S5']) {
      const r = srow(proxy, 'e', '1.8.0', id);
      assert.ok(r, id); assert.doesNotMatch(r.detail, /^not checked: not armed/, `${id}: ${r.detail}`);
      assert.match(r.detail, /armed by entry-path-change$/, `${id}: ${r.detail}`);
    }
    assert.equal(srow(proxy, 'e', '1.8.0', 'S2').result, 'ALLOW', 'the kept main lib/run.js was read');
    assert.equal(proxy.witnessDb.getLatestDecision('e', '1.8.0').disposition, 'ALLOW', 'arming changes no decision');
  });
});

test('EPC-E2 a first version (below the eight-version history floor, no predecessor) gets no entry-path-change NOTE: the rows say every download armed the walk', async () => {
  await withProxy(async ({ base, proxy }) => {
    await get(`${base}/f`); await get(`${base}/f/-/f-1.0.0.tgz`); await settle();
    assert.ok(!classify(rowsOf(proxy, 'f', '1.0.0')).contributing.includes('entry-path-change'));
    // 0.1.6 every download is walked (deliberate change of expectation)
    for (const id of ['S0', 'S1', 'S2', 'S3', 'S4']) assert.match(srow(proxy, 'f', '1.0.0', id)?.detail ?? '', /armed by every download$/, id);
  });
});
