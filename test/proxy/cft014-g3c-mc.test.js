// 0.1.4 group 3, unit 3c — MC through the proxy (D-M2..D-M6): the first download is served unchanged and recorded; the next
// carries the notice; the record keeps it. Expected results: decision tables
// ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G3-TIER1-20261012.md §4, written before this file. Tarballs are synthetic,
// built with tar(1); nothing is installed or run.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createProxyServer } from '../../proxy/server.js';
import { resetDependencyCache } from '../../gates/dependency-cache.js';
import { forgetManifestHooks } from '../../proxy/manifest-check.js';
import { renderReport } from '../../cli/report-render.js';

const H = 3_600_000;
const T0 = Date.parse('2026-03-01T00:00:00Z');
const at = (h) => new Date(T0 + h * H).toISOString();
function tgz(pj) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g3cmc-'));
  try {
    fs.mkdirSync(path.join(dir, 'package'));
    fs.writeFileSync(path.join(dir, 'package', 'package.json'), JSON.stringify(pj));
    fs.writeFileSync(path.join(dir, 'package', 'index.js'), 'module.exports = 1;\n');
    // relative names inside the folder: GNU tar reads `C:\...` in -f as host:path (Windows CI run 38276078619)
    execFileSync('tar', ['-czf', 'o.tgz', 'package'], { cwd: dir });
    return fs.readFileSync(path.join(dir, 'o.tgz'));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
// m@1.1.0: the registry manifest declares no hook; its tarball's package.json declares a postinstall (manifest confusion)
const TARBALLS = {
  '/m/-/m-1.0.0.tgz': tgz({ name: 'm', version: '1.0.0' }),
  '/m/-/m-1.1.0.tgz': tgz({ name: 'm', version: '1.1.0', scripts: { postinstall: 'node s.js' } }),
};
const DOC = { name: 'm', 'dist-tags': { latest: '1.1.0' },
  versions: { '1.0.0': { name: 'm', version: '1.0.0' }, '1.1.0': { name: 'm', version: '1.1.0' } }, time: { '1.0.0': at(0), '1.1.0': at(48) } };

async function withProxy(fn) {
  resetDependencyCache(); forgetManifestHooks();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g3cp-'));
  const upstream = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]);
    if (TARBALLS[u]) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end(TARBALLS[u]); return; }
    if (u === '/m') { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(DOC)); return; }
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
const mcRow = (proxy, v) => proxy.witnessDb.getLatestDecision('m', v).gates_fired.find((g) => g.gate === 'install-manifest-mismatch');
const settle = () => new Promise((r) => setTimeout(r, 150));

test('G3c-3 (D-M2, D-M4) the first download: bytes unchanged, no notice; then the record, log, report and disk say it', async () => {
  await withProxy(async ({ base, proxy, logs }) => {
    await get(`${base}/m`, { 'npm-session': 'g3c3' });
    const t = await get(`${base}/m/-/m-1.1.0.tgz`, { 'npm-session': 'g3c3' });
    assert.equal(t.status, 200);
    assert.ok(t.body.equals(TARBALLS['/m/-/m-1.1.0.tgz']), 'the bytes npm gets are exactly the upstream bytes');
    assert.equal(t.headers['npm-notice'], undefined, 'headers were sent before the walk finished');
    await settle();
    const row = mcRow(proxy, '1.1.0');
    assert.equal(row?.result, 'WARN', JSON.stringify(proxy.witnessDb.getLatestDecision('m', '1.1.0')));
    assert.match(row.detail, /tarball package\.json declares postinstall/);
    assert.equal(proxy.witnessDb.getLatestDecision('m', '1.1.0').disposition, 'WARN');
    assert.ok(logs.some((l) => l.startsWith('[gate] m@1.1.0: WARN named install-manifest-mismatch')), JSON.stringify(logs));
    const rep = JSON.parse((await get(`${base}/_chaingate/report`)).body.toString());
    const text = renderReport(rep, { source: 'proxy' }).text;
    // since 0.1.6 the tarball package.json is what npm runs: its postinstall is the first install hook of m, so install-introduced
    // names it too, beside MC
    assert.ok(text.includes("m@1.1.0  NAMED WARNING: an install script appears that earlier releases did not have; its tarball's install scripts differ from its registry entry"), text);
    assert.ok(proxy.witnessDb.listNamedFactEvents().some((r) => r.kind === 'named-served' && r.version === '1.1.0'));
    // the matching version is ALLOW
    await get(`${base}/m/-/m-1.0.0.tgz`);
    await settle();
    assert.equal(mcRow(proxy, '1.0.0')?.result, 'ALLOW');
  });
});

test('G3c-4/G3c-5 (D-M4, D-M5) the next download carries the notice without a second walk; a re-observation keeps the WARN', async () => {
  await withProxy(async ({ base, proxy }) => {
    await get(`${base}/m`);
    await get(`${base}/m/-/m-1.1.0.tgz`);
    await settle();
    const rows = () => proxy.witnessDb.getDecisionHistory('m', '1.1.0').length;
    const n = rows();
    const t2 = await get(`${base}/m/-/m-1.1.0.tgz`);
    // since 0.1.6: install-introduced follows the tarball package.json npm runs (a first postinstall), beside MC
    assert.equal(t2.headers['npm-notice'], "chaingate: WARNING m@1.1.0: an install script appears that earlier releases did not have; its tarball's install scripts differ from its registry entry. Details: chaingate why m@1.1.0");
    await settle();
    // 0.1.6 every download is walked (deliberate change of expectation; 0.1.5 had one more walk here, armed by MC's WARN): the first
    // download's walk read the static checks too, so the outcome is settled and the next download walks nothing
    assert.equal(rows(), n, 'settled on the first walk: no second walk');
    await get(`${base}/m`);
    assert.equal(rows(), n, 'carry-forward: no new row');
    assert.equal(mcRow(proxy, '1.1.0').result, 'WARN');
  });
});

test('G3c-6 (D-M3; G4 dated note 4 R3) the hook map lost the package: the download refreshes it and MC is checked at once', async () => {
  // before R3 this download recorded "not checked" and was retried next time; the refresh-failure case is G4-8b
  await withProxy(async ({ base, proxy }) => {
    await get(`${base}/m`);
    forgetManifestHooks();
    await get(`${base}/m/-/m-1.1.0.tgz`);
    await settle();
    assert.equal(mcRow(proxy, '1.1.0')?.result, 'WARN');
  });
});
