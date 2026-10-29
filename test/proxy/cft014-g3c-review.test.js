// 0.1.4 group 3, unit 3c — review fixes in the proxy (G3 dated note 5 items 4-6; G3c-14..G3c-16). Expected results: decision
// tables ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G3-TIER1-20261012.md, dated note 5. Tarballs are synthetic (tar(1)).
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
import { walkerStats } from '../../proxy/tar-walk.js';
import { renderReport } from '../../cli/report-render.js';

const H = 3_600_000;
const T0 = Date.parse('2026-03-01T00:00:00Z');
const at = (h) => new Date(T0 + h * H).toISOString();
function tgz(pj, extra = null) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g3cr-'));
  try {
    fs.mkdirSync(path.join(dir, 'package'));
    fs.writeFileSync(path.join(dir, 'package', 'package.json'), JSON.stringify(pj));
    if (extra) fs.writeFileSync(path.join(dir, 'package', 'big.bin'), extra);
    // relative names inside the folder: GNU tar reads `C:\...` in -f as host:path (Windows CI run 38276078619)
    execFileSync('tar', ['-czf', 'o.tgz', 'package'], { cwd: dir });
    return fs.readFileSync(path.join(dir, 'o.tgz'));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
const man = (name, v, scripts) => ({ name, version: v, ...(scripts ? { scripts } : {}) });

async function withProxy(docs, tarballs, fn, { packumentStatus = () => 200, slow = new Set(), dir: given = null } = {}) {
  resetDependencyCache(); forgetManifestHooks();
  const dir = given ?? fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g3crp-'));
  const upstream = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]);
    if (tarballs[u]) {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      if (!slow.has(u)) { res.end(tarballs[u]); return; }
      const b = tarballs[u]; let i = 0;
      const tick = () => { if (i >= b.length) { res.end(); return; } res.write(b.subarray(i, i + 65536)); i += 65536; setTimeout(tick, 20); };
      tick(); return;
    }
    const d = docs[u.slice(1)];
    if (!d || packumentStatus() !== 200) { res.writeHead(d ? packumentStatus() : 404, { 'content-type': 'application/json' }); res.end('{}'); return; }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(d));
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${upstream.address().port}`,
    witnessDbPath: path.join(dir, 'witness.db'), headersTimeoutMs: 10_000, bodyTimeoutMs: 30_000 });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${proxy.address().port}`;
  const realErr = console.error; console.error = () => {};
  try { return await fn({ base, proxy }); } finally {
    console.error = realErr;
    await new Promise((r) => proxy.close(r)); upstream.closeAllConnections?.(); await new Promise((r) => upstream.close(r));
    if (!given) fs.rmSync(dir, { recursive: true, force: true });
    resetDependencyCache(); forgetManifestHooks();
  }
}
const get = (u, headers = {}) => new Promise((resolve, reject) => http.get(u, { agent: false, headers }, (res) => {
  const c = []; res.on('data', (x) => c.push(x)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(c) }));
}).on('error', reject));
const settle = () => new Promise((r) => setTimeout(r, 200));
const mc = (proxy, pkg, v) => proxy.witnessDb.getLatestDecision(pkg, v)?.gates_fired.find((g) => g.gate === 'install-manifest-mismatch');

test('G3c-14 (note 5.4) the late event: K computed; merged with an earlier named event of the version; never "not checked"', async () => {
  const docs = {
    k: { name: 'k', 'dist-tags': { latest: '1.1.0' }, versions: { '1.0.0': man('k', '1.0.0'), '1.0.1': man('k', '1.0.1'), '1.1.0': man('k', '1.1.0') },
      time: { '1.0.0': at(0), '1.0.1': at(10), '1.1.0': at(60) } },
    both: { name: 'both', 'dist-tags': { latest: '1.1.0' }, versions: { '1.0.0': man('both', '1.0.0'), '1.1.0': man('both', '1.1.0', { postinstall: 'node a.js' }) },
      time: { '1.0.0': at(0), '1.1.0': at(60) } },
    first: { name: 'first', 'dist-tags': { latest: '1.0.0' }, versions: { '1.0.0': man('first', '1.0.0') }, time: { '1.0.0': at(0) } },
  };
  const tarballs = {
    '/k/-/k-1.1.0.tgz': tgz({ name: 'k', version: '1.1.0', scripts: { postinstall: 'node x.js' } }),
    '/both/-/both-1.1.0.tgz': tgz({ name: 'both', version: '1.1.0', scripts: { postinstall: 'node b.js' } }),
    '/first/-/first-1.0.0.tgz': tgz({ name: 'first', version: '1.0.0', scripts: { install: 'x' } }),
  };
  await withProxy(docs, tarballs, async ({ base }) => {
    for (const n of ['k', 'both', 'first']) await get(`${base}/${n}`, { 'npm-session': 'g3c14' });
    for (const u of Object.keys(tarballs)) await get(`${base}${u}`, { 'npm-session': 'g3c14' });
    await settle();
    const rep = JSON.parse((await get(`${base}/_chaingate/report`)).body.toString());
    const late = rep.installs[0].events.find((e) => e.package === 'k' && e.late);
    assert.equal(late.k, '1.0.1', 'K computed for the late event');
    const text = renderReport(rep, { source: 'proxy' }).text;
    assert.ok(text.includes("both@1.1.0  NAMED WARNING: an install script appears that earlier releases did not have; its tarball's install scripts differ from its registry entry"), text);
    assert.equal(text.split('\n').filter((l) => l.startsWith('both@1.1.0  NAMED WARNING')).length, 1, 'one merged block');
    assert.ok(text.includes('first@1.0.0  NAMED WARNING'), text);
    assert.ok(!/package\(s\) were not checked by any named rule/.test(text), 'a named version is never "not checked"');
  });
});

test('G3c-15 (note 5.6) no second walk; an aborted download records nothing; a failed C1 records nothing', async () => {
  const docs = { m: { name: 'm', 'dist-tags': { latest: '1.1.0' }, versions: { '1.0.0': man('m', '1.0.0'), '1.1.0': man('m', '1.1.0') },
    time: { '1.0.0': at(0), '1.1.0': at(48) } } };
  const big = Buffer.alloc(8 * 1024 * 1024); for (let i = 0; i < big.length; i += 1) big[i] = (i * 2654435761) >>> 24;
  const tarballs = { '/m/-/m-1.1.0.tgz': tgz({ name: 'm', version: '1.1.0', scripts: { postinstall: 'x' } }), '/m/-/m-1.0.0.tgz': tgz({ name: 'm', version: '1.0.0' }, big) };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g3c15-'));
  try {
    await withProxy(docs, tarballs, async ({ base, proxy }) => {
      await get(`${base}/m`);
      await get(`${base}/m/-/m-1.1.0.tgz`); await settle();
      const walks = walkerStats().created;
      await get(`${base}/m/-/m-1.1.0.tgz`); await settle();
      // 0.1.6 every download is walked (deliberate change of expectation; 0.1.5 had one more walk here, armed by MC's WARN): the
      // first walk read the static checks too, so the outcome is settled
      assert.equal(walkerStats().created, walks, 'no second walk');
      await get(`${base}/m/-/m-1.1.0.tgz`); await settle();
      assert.equal(walkerStats().created, walks, 'a settled outcome is not walked again');
      // aborted: the client goes away mid-stream
      await new Promise((resolve) => {
        const req = http.get(`${base}/m/-/m-1.0.0.tgz`, { agent: false }, (res) => { res.once('data', () => { req.destroy(); setTimeout(resolve, 400); }); });
        req.on('error', () => {});
      });
      assert.equal(mc(proxy, 'm', '1.0.0'), undefined, 'an aborted download records nothing');
    }, { slow: new Set(['/m/-/m-1.0.0.tgz']), dir });
    // a second process on the same record, its metadata unavailable: the tarball is served unevaluated; nothing is walked
    await withProxy(docs, tarballs, async ({ base, proxy }) => {
      const before = proxy.witnessDb.getDecisionHistory('m', '1.0.0').length;
      await get(`${base}/m/-/m-1.0.0.tgz`); await settle();
      assert.equal(proxy.witnessDb.getDecisionHistory('m', '1.0.0').length, before, 'a failed C1 records nothing');
    }, { packumentStatus: () => 500, dir });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('G3c-16 (note 5.5) the MC carry-forward never enters an override row', async () => {
  const docs = { m: { name: 'm', 'dist-tags': { latest: '1.1.0' }, versions: { '1.0.0': man('m', '1.0.0'), '1.1.0': man('m', '1.1.0') },
    time: { '1.0.0': at(0), '1.1.0': at(48) } } };
  const tarballs = { '/m/-/m-1.1.0.tgz': tgz({ name: 'm', version: '1.1.0', scripts: { postinstall: 'x' } }) };
  await withProxy(docs, tarballs, async ({ base, proxy }) => {
    await get(`${base}/m`); await get(`${base}/m/-/m-1.1.0.tgz`); await settle();
    assert.equal(mc(proxy, 'm', '1.1.0').result, 'WARN');
    proxy.witnessDb.insertOverride('m', '1.1.0', 'g3c-16');
    await get(`${base}/m`);
    const latest = proxy.witnessDb.getLatestDecision('m', '1.1.0');
    assert.ok(latest.gates_fired.some((g) => g.gate === 'override'));
    assert.equal(latest.disposition, 'ALLOW');
    assert.ok(!latest.gates_fired.some((g) => g.gate === 'install-manifest-mismatch'));
  });
});
