// 0.1.5 naming of S6 and S7 (operator rulings R7 and R9 2026-10-22, on the static-checks-1.4 re-measure; S7 on the 1.5 condition):
// both are NAMED runner gates, out of the contributing list, with the CHECKS notice text as their label, as S0 and S5 were
// (2026-10-15). S1-S4 stay contributing. An S7 gain that the 1.5 condition does not name is an ALLOW row; `why` shows it as a fact,
// the Function constructor included. Policy identity stays cft-policy-1.2. Failing first: written before the code.
// Tarballs are synthetic; nothing is run.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { createProxyServer } from '../../proxy/server.js';
import { resetDependencyCache } from '../../gates/dependency-cache.js';
import { forgetManifestHooks } from '../../proxy/manifest-check.js';
import { classify } from '../../witness/row-class.js';

const SC = () => import('../../proxy/static-checks.js');
const RC = () => import('../../gates/row-class.js');
const POLM = () => import('../../seed/v3/policy.js');
const NOT = () => import('../../proxy/notice.js');
const CLI = fileURLToPath(new URL('../../cli/index.js', import.meta.url));
const S0G = 'static:S0-shell-fetch-in-hook'; const S5G = 'static:S5-oversized-hook-target';
const S6G = 'static:S6-network-beacon-in-hook-target'; const S7G = 'static:S7-entry-capability-gain';
const S6_TEXT = 'an install script sends details about this machine to the network';
const S7_TEXT = 'its entry file gained a capability its previous version did not have';

test('NS-1 roles: S0, S5, S6 and S7 are named runner gates, out of the contributing list; S1-S4 stay contributing; a named WARN stays WARN and withholds', async () => {
  const R = await RC(); const POL = (await POLM()).default; const S = await SC();
  assert.deepEqual(POL.NAMED_RUNNER_GATES, ['install-introduced', 'dependency-hooks', 'install-manifest-mismatch', 'size-jump-provenance', S0G, S5G, S6G, S7G,
    'static:S8-prebuilt-addon-dropper-in-hook', 'static:S9-hidden-script-in-gyp-build']);   // S8, S9 named by static-checks-1.8 (declared)
  for (const g of [S6G, S7G]) { assert.ok(!R.CONTRIBUTING_GATES.has(g), g); assert.equal(R.withRole({ gate: g, result: 'WARN', detail: 'd' }).result, 'WARN'); }
  for (const g of ['static:S1-loader-in-hook-target', 'static:S2-obfuscated-entry', 'static:S3-secret-harvest-with-sink', 'static:S4-wallet-swap-hook']) {
    assert.ok(R.CONTRIBUTING_GATES.has(g), g); assert.equal(R.withRole({ gate: g, result: 'WARN', detail: 'd' }).result, 'NOTE');
  }
  assert.deepEqual(classify([{ gate: S6G, result: 'WARN', detail: 'd' }, { gate: S7G, result: 'WARN', detail: 'd' }]).named, [S6G, S7G]);
  assert.deepEqual(S.withholdingChecks([{ gate: S6G, result: 'WARN', detail: 'd' }, { gate: S7G, result: 'WARN', detail: 'd' }]), [S6G, S7G]);
  assert.deepEqual(classify([{ gate: S7G, result: 'ALLOW', detail: 'no gain named vs 1.0.0' }]).named, [], 'an S7 gain not named is no named row');
  // the static checks did not move the policy in 0.1.5; 0.1.6 moved it to 1.3 for the strict-row re-tier, nothing else
  assert.equal(POL.POLICY_CONTRACT_VERSION, 'cft-policy-1.3', 'policy identity: 1.3 since 0.1.6');
});

test('NS-2 notice labels: S6 and S7 carry the CHECKS text byte for byte; S1-S4 have none', async () => {
  const N = await NOT(); const S = await SC();
  assert.equal(N.labelFor(S6G), S6_TEXT); assert.equal(N.labelFor(S7G), S7_TEXT);
  assert.equal(S.CHECKS.find((c) => c.id === 'S6').notice, S6_TEXT); assert.equal(S.CHECKS.find((c) => c.id === 'S7').notice, S7_TEXT);
  for (const c of S.CHECKS) if (['S1', 'S2', 'S3', 'S4'].includes(c.id)) assert.equal(N.labelFor(c.gate), null, c.gate);
  assert.equal(N.buildNotice({ kind: 'WARNING', pkg: 'e', version: '1.8.0', labels: [S7G] }), `chaingate: WARNING e@1.8.0: ${S7_TEXT}. Details: chaingate why e@1.8.0`);
});

// ------------------------------------------------------------------ end to end: a named S7 WARN, and an unnamed Function gain shown by `why`
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
const NETEXEC = 'const cp = require("child_process");\nfetch("https://x.example.invalid/").then(() => cp.execSync("id"));\n';
const NET_FUNCTION = 'fetch("https://x.example.invalid/").then((r) => new Function("r", "return r")(r));\n';
const REAL = (name, v) => ({ _npmUser: { name: 'maintainer', email: 'm@example.com' }, _npmVersion: '10.9.2',
  dist: { shasum: `shasum-${name}-${v}`, integrity: `sha512-${name}-${v}==`, tarball: `https://registry.npmjs.org/${name}/-/${name}-${v}.tgz`, unpackedSize: 1000 } });
const EV = Array.from({ length: 9 }, (_, i) => `1.${i}.0`);
// nine versions; 1.8.0 moves main to lib/run.js (entry-path-change arms the walk); 1.7.0 is the version served before
const pkgDoc = (name) => ({ name, 'dist-tags': { latest: '1.8.0' }, time: Object.fromEntries(EV.map((v, i) => [v, at(48 * i)])),
  versions: Object.fromEntries(EV.map((v) => [v, { name, version: v, main: v === '1.8.0' ? 'lib/run.js' : 'index.js', ...REAL(name, v) }])) });
const DOCS = { '/e': pkgDoc('e'), '/g': pkgDoc('g') };
const TARBALLS = {
  '/e/-/e-1.7.0.tgz': tgz({ 'package.json': JSON.stringify(DOCS['/e'].versions['1.7.0']), 'index.js': BENIGN }),
  '/e/-/e-1.8.0.tgz': tgz({ 'package.json': JSON.stringify(DOCS['/e'].versions['1.8.0']), 'lib/run.js': NETEXEC }),
  '/g/-/g-1.7.0.tgz': tgz({ 'package.json': JSON.stringify(DOCS['/g'].versions['1.7.0']), 'index.js': BENIGN }),
  '/g/-/g-1.8.0.tgz': tgz({ 'package.json': JSON.stringify(DOCS['/g'].versions['1.8.0']), 'lib/run.js': NET_FUNCTION }),
};
async function withProxy(fn) {
  resetDependencyCache(); forgetManifestHooks();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-ns67-'));
  const upstream = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]);
    if (TARBALLS[u]) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end(TARBALLS[u]); return; }
    if (DOCS[u]) { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(DOCS[u])); return; }
    res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}');
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const dbPath = path.join(dir, 'witness.db');
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${upstream.address().port}`,
    witnessDbPath: dbPath, headersTimeoutMs: 10_000, bodyTimeoutMs: 10_000 });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${proxy.address().port}`;
  try { return await fn({ base, proxy, dir, dbPath }); } finally {
    await new Promise((r) => proxy.close(r)); await new Promise((r) => upstream.close(r)); fs.rmSync(dir, { recursive: true, force: true });
    resetDependencyCache(); forgetManifestHooks();
  }
}
const get = (u) => new Promise((resolve, reject) => http.get(u, { agent: false }, (res) => {
  const chunks = []; res.on('data', (x) => chunks.push(x)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
}).on('error', reject));
const settle = () => new Promise((r) => setTimeout(r, 200));
const serve = async (base, name) => {
  await get(`${base}/${name}`); await get(`${base}/${name}`);
  await get(`${base}/${name}/-/${name}-1.7.0.tgz`); await settle();
  const t = await get(`${base}/${name}/-/${name}-1.8.0.tgz`); await settle(); return t;
};
const runCli = (args, env) => new Promise((resolve) => {
  const c = spawn(process.execPath, [CLI, ...args], { env: { ...process.env, NO_COLOR: '1', CI: '', ...env } });
  let out = ''; c.stdout.on('data', (d) => { out += d; }); c.stderr.on('data', (d) => { out += d; }); c.on('close', (code) => resolve({ code, out }));
});

test('NS-E1 a named S7 gain (net+exec) is recorded as a WARN named row; the download is served (switch off) and the next one carries S7\'s notice', async () => {
  await withProxy(async ({ base, proxy }) => {
    const t = await serve(base, 'e');
    assert.equal(t.status, 200); assert.ok(t.body.equals(TARBALLS['/e/-/e-1.8.0.tgz']), 'served unchanged');
    const rows = proxy.witnessDb.getLatestDecision('e', '1.8.0').gates_fired;
    const r = rows.find((g) => g.gate === S7G);
    assert.equal(r?.result, 'WARN', JSON.stringify(r));
    assert.match(r.detail, /^vs 1\.7\.0 \(the version this proxy served before\): main gained exec:child_process, net:fetch \(net\+exec: exec:child_process, net:fetch\)/);
    assert.ok(classify(rows).named.includes(S7G));
    const t2 = await get(`${base}/e/-/e-1.8.0.tgz`);
    assert.equal(t2.status, 200); assert.ok((t2.headers['npm-notice'] ?? '').includes(S7_TEXT), t2.headers['npm-notice']);
  });
});

test('NS-E2 the Function constructor names nothing: S7 is ALLOW, and `chaingate why` shows the excluded gain as a fact', async () => {
  await withProxy(async ({ base, proxy, dbPath, dir }) => {
    await serve(base, 'g');
    const rows = proxy.witnessDb.getLatestDecision('g', '1.8.0').gates_fired;
    const r = rows.find((x) => x.gate === S7G);
    assert.equal(r?.result, 'ALLOW', JSON.stringify(r));
    assert.ok(!classify(rows).named.includes(S7G));
    const w = await runCli(['why', 'g@1.8.0'], { CHAINGATE_WITNESS_DB: dbPath, HOME: dir });
    assert.match(w.out, /static:S7-entry-capability-gain: no gain named vs 1\.7\.0 \(the version this proxy served before\); main gained decode:Function, exec:Function, net:fetch \(not named: no decode\/obf gain other than decode:Function, no net\+exec pair other than exec:Function\)/, w.out);
  });
});
