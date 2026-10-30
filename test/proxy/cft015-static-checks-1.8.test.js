// 0.1.5 static-checks-1.8 (operator 2026-10-27: 0.1.5 held for it; S8 and S9, both named): recon v6.17 mirrored. Two new checks,
// appended after S7; S0-S7, every sink and every 1.6 fact are unchanged.
//   S8 prebuilt-addon-dropper-in-hook  an install hook loads a shipped native module (.node with an ELF / PE / Mach-O head), the
//                                      tarball has no native source, and a member is text under a one-byte XOR
//   S9 hidden-script-in-gyp-build      a binding.gyp or .gypi command expansion runs a package script with its standard output discarded
// Both read the member facts of every archive member (memberFacts over its first 2 MiB; the XOR read over the first 1 MiB), which the
// proxy already gathers on an armed walk (createMemberTally); without them a row is SKIP "not checked", stated.
// The hand-off: recon's sealed tools/recon/v6.17/static-checks.mjs (sha256 b82d7ae9...; manifest RECON-v6.17.SHA256SUMS 4d639394...,
// chaingate-ops g10-c2-recon-v6.17 @9c12718), lines 579-672 copied as written (sha256 8dc3e357... below). The vectors are recon's
// test/v617.test.mjs (sha256 6353f1a3...): the dropper shapes, the negatives, the gyp vectors and the adversarial bodies, as written.
// Failing first: written before the code. Tarballs and bodies are synthetic text; nothing is run.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { createProxyServer } from '../../proxy/server.js';
import { resetDependencyCache } from '../../gates/dependency-cache.js';
import { forgetManifestHooks } from '../../proxy/manifest-check.js';

const SC = () => import('../../proxy/static-checks.js');
const RC = () => import('../../gates/row-class.js');
const POLM = () => import('../../seed/v3/policy.js');
const NOT = () => import('../../proxy/notice.js');
const SRC = fileURLToPath(new URL('../../proxy/static-checks.js', import.meta.url));
const S8G = 'static:S8-prebuilt-addon-dropper-in-hook'; const S9G = 'static:S9-hidden-script-in-gyp-build';
const S8_NOTICE = 'an install script loads a prebuilt native module shipped without its source, next to an encoded file';
const S9_NOTICE = 'its native build file runs a package script during install and hides the output';
const BLOCK_SHA256 = '8dc3e3579daa8480dc0596d41fc5bcf4106035e101852f85eb972df26347b10f';   // recon v6.17 static-checks.mjs lines 579-672
const BLOCK_HEAD = '// ------------------------------------------------------------------ v6.17 static-checks-1.8: S8 (the native-addon dropper)';

// ------------------------------------------------------------------ recon's TEXT fixtures, as written (no captured sample, no payload)
const LOADER_TEXT = "var fs = require('fs'); var path = require('path');\nmodule.exports = function load(dir) { return fs.readdirSync(path.join(dir, 'lib')); };\n";
const xorBuf = (s, k) => Buffer.from(Buffer.from(s).map((b) => b ^ k));
const XOR_CACHE = xorBuf(LOADER_TEXT.repeat(40), 0x96);
const ELF = Buffer.concat([Buffer.from('7f454c46020101', 'hex'), Buffer.alloc(57), Buffer.from('fixture: an ELF head, not a module')]);
const PE = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(62), Buffer.from('fixture: a PE head, not a module')]);
const MACHO = Buffer.concat([Buffer.from('cffaedfe', 'hex'), Buffer.alloc(60), Buffer.from('fixture: a Mach-O head')]);
const CJK = Buffer.from(String.fromCodePoint(0x57fa, 0x7840, 0x89c4, 0x8303, 0x5bf9, 0x8bdd, 0x5904, 0x7406, 0xff0c, 0x8bf4, 0x660e, 0x6587, 0x6863, 0x3002).repeat(120));
const noNulRandom = (n, seed = 7) => { const b = Buffer.alloc(n); let x = seed; for (let i = 0; i < n; i++) { x = (x * 1103515245 + 12345) >>> 0; b[i] = 1 + ((x >>> 16) % 255); } return b; };
const NODE_E = "node -e \"try{require('./addon.node').init()}catch(e){}\"";
const NODE_E_WIN = "node -e \"try{require(process.platform==='win32'?'./addon_win.node':'./addon.node').init()}catch(e){}\"";
const SHAPES = {
  'node -e require(./addon.node)': { hooks: { postinstall: NODE_E }, files: { 'package.json': '{}', 'index.js': "try{require('./addon.node').init();}catch(e){}\n", 'addon.node': ELF, '.cache': XOR_CACHE } },
  'the win32 ternary': { hooks: { postinstall: NODE_E_WIN }, files: { 'package.json': '{}', 'addon.node': ELF, 'addon_win.node': PE, '.napi_cache': XOR_CACHE, 'README.md': '# Temporary Holding Version\n' } },
  'node-gyp-build with prebuilds/': { hooks: { postinstall: 'node-gyp-build' }, files: { 'package.json': '{}', 'index.js': "module.exports = require('node-gyp-build')(__dirname)\n",
    'prebuilds/linux-x64/node.napi.node': ELF, 'prebuilds/linux-x64/.napi_cache': XOR_CACHE, 'prebuilds/win32-x64/node.napi.node': PE, 'prebuilds/win32-x64/.napi_cache': XOR_CACHE } },
  'the decoy binding.gyp with empty sources': { hooks: { install: 'node-gyp rebuild', postinstall: 'node-gyp-build' }, files: { 'package.json': '{}', 'binding.gyp': '{\n  "targets": [\n    {\n      "target_name": "node",\n      "sources": []\n    }\n  ]\n}\n',
    'index.js': "module.exports = require('node-gyp-build')(__dirname)\n", 'prebuilds/darwin-arm64/node.napi.node': MACHO, 'prebuilds/darwin-arm64/.napi_cache': XOR_CACHE } },
  'a hook target that requires a .node file': { hooks: { postinstall: 'node setup.js' }, files: { 'package.json': '{}', 'setup.js': "try { require('./lib/x.node'); } catch (e) {}\n", 'lib/x.node': ELF, 'lib/data.bin': XOR_CACHE } },
};
const GYP_QUIET = '{\n  "targets": [{\n    "target_name": "nothing",\n    "type": "none",\n    "sources": ["<!(env node index.js >/dev/null 2>&1; echo stub.c)"]\n  }]\n}\n';
const GYP_NORMAL = '{"targets":[{"target_name":"a","sources":["src/a.cc"],"include_dirs":["<!(node -p \\"require(\'node-addon-api\').include\\")","<!@(node scripts/find-lib.cjs include)"],"libraries":["<!@(pkg-config --libs zlib 2>/dev/null)"]}]}\n';
const OBF = '(function(){var _0x1a2b=["x"];module.exports={};})();\n';

/**
 * The proxy's rows over a package given as recon's { hooks, files }: the registry manifest carries the hooks, the walk keeps the keep
 * list's files (as the walker does), and the member facts are memberFacts over every file (as createMemberTally gathers them).
 */
async function rowsOf(pkg, { tarballHooks = null, withMembers = true, membersOver = false } = {}) {
  const S = await SC(); const man = { name: 'fx', version: '1.0.0', scripts: pkg.hooks };
  const pj = tarballHooks ? { name: 'fx', version: '1.0.0', scripts: { ...pkg.hooks, ...tarballHooks } } : man;
  const kept = new Set([...S.keepListFor(man).paths, ...S.keepListFor(pj).paths]); const files = []; const members = [];
  for (const [p, c] of Object.entries(pkg.files)) {
    const data = Buffer.isBuffer(c) ? c : Buffer.from(c);
    members.push(S.memberFacts({ path: p, size: data.length, data }));
    if (kept.has(p)) files.push({ path: p, buf: data });
  }
  return S.staticRows({ manifest: man, packageJson: pj, walk: { ok: true, files, notKept: [] }, armed: 'install-introduced',
    ...(withMembers ? { members: membersOver ? [] : members, membersOver } : {}) });
}
const rowOf = (rows, gate) => rows.find((r) => r.gate === gate);
const gypOf = async (text, p = 'binding.gyp') => (await SC()).memberFacts({ path: p, size: Buffer.byteLength(text), data: Buffer.from(text) }).gyp_build;

// ------------------------------------------------------------------ identity, vocabulary, roles
test('C0 identity: static-checks-1.8; S8 and S9 appended after S7 with recon\'s gate, class and notice; S8_LIMITS, GYP_LIMITS and ADDON_LOADS as ruled', async () => {
  const S = await SC();
  assert.equal(S.STATIC_CHECKS_VERSION, 'static-checks-1.9');
  assert.deepEqual(S.CHECKS.map((c) => c.id), ['S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7', 'S8', 'S9']);
  assert.deepEqual(JSON.parse(JSON.stringify(S.CHECKS.find((c) => c.id === 'S8'))), { id: 'S8', gate: S8G, cls: 'prebuilt-addon-dropper-in-hook', roles: null, notice: S8_NOTICE });
  assert.deepEqual(JSON.parse(JSON.stringify(S.CHECKS.find((c) => c.id === 'S9'))), { id: 'S9', gate: S9G, cls: 'hidden-script-in-gyp-build', roles: null, notice: S9_NOTICE });
  assert.deepEqual(S.STATIC_GATES.slice(-2), [S8G, S9G]);
  assert.deepEqual({ ...S.S8_LIMITS }, { xorWindow: 1 << 20, xorMinBytes: 64, xorMaxPrintableBefore: 0.5, xorMinPrintableAfter: 0.95, listed: 20 }); assert.ok(Object.isFrozen(S.S8_LIMITS));
  assert.deepEqual({ ...S.GYP_LIMITS }, { maxExpansions: 200, expansionChars: 2000 }); assert.ok(Object.isFrozen(S.GYP_LIMITS));
  assert.deepEqual(S.ADDON_LOADS.map(([n, where]) => [n, where]), [['hook-names-node-file', 'command'], ['hook-runs-node-gyp-build', 'command'], ['target-requires-node-file', 'hook-target'], ['target-requires-node-gyp-build', 'hook-target']]);
});

test('C1 recon\'s block is copied as written: lines 579-672 of the sealed static-checks.mjs, byte for byte', async () => {
  const lines = fs.readFileSync(SRC, 'utf8').split('\n'); const i = lines.indexOf(BLOCK_HEAD);
  assert.ok(i >= 0, 'the block head is present');
  const block = `${lines.slice(i, i + 94).join('\n')}\n`;
  assert.equal(createHash('sha256').update(block).digest('hex'), BLOCK_SHA256);
});

test('C2 roles: S8 and S9 are named runner gates with the CHECKS notice text byte for byte; a WARN stays WARN and withholds', async () => {
  const R = await RC(); const POL = (await POLM()).default; const S = await SC(); const N = await NOT();
  assert.deepEqual(POL.NAMED_RUNNER_GATES.slice(-2), [S8G, S9G]);
  for (const g of [S8G, S9G]) { assert.ok(!R.CONTRIBUTING_GATES.has(g), g); assert.equal(R.withRole({ gate: g, result: 'WARN', detail: 'd' }).result, 'WARN', g); }
  assert.equal(N.labelFor(S8G), S8_NOTICE); assert.equal(N.labelFor(S9G), S9_NOTICE);
  assert.deepEqual(S.withholdingChecks([{ gate: S8G, result: 'WARN', detail: 'd' }, { gate: S9G, result: 'WARN', detail: 'd' }]), [S8G, S9G]);
  assert.equal(POL.POLICY_CONTRACT_VERSION, 'cft-policy-1.3', 'policy identity: 1.3 since 0.1.6 (the strict-row re-tier), not static checks 1.8');
});

// ------------------------------------------------------------------ member facts
test('C3 memberFacts: native, node_file, native_source, gyp_sources, xor_text, gyp_build; each read from the full path', async () => {
  const S = await SC(); const mf = (p, d) => S.memberFacts({ path: p, size: d.length, data: Buffer.isBuffer(d) ? d : Buffer.from(d) });
  assert.equal(mf('a.node', ELF).native, 'elf'); assert.equal(mf('a.node', PE).native, 'pe'); assert.equal(mf('a.node', MACHO).native, 'macho');
  assert.equal(mf('a.node', Buffer.from('module.exports = 1;\n')).native, null);
  const x = mf('.napi_cache', XOR_CACHE).xor_text; assert.ok(x && x.printable_before < 0.5 && x.printable_after >= 0.95, JSON.stringify(x));
  assert.deepEqual(Object.keys(x).sort(), ['printable_after', 'printable_before'], 'shares only: no key, no decoded byte');
  for (const [why, d] of [['UTF-8 text (CJK)', CJK], ['ASCII text', LOADER_TEXT.repeat(10)], ['high entropy, no NUL', noNulRandom(65536)], ['under 64 bytes', XOR_CACHE.subarray(0, 63)], ['binary (a NUL)', ELF],
    ['latin-1 text', Buffer.from(`caf\xe9 ${LOADER_TEXT}`.repeat(20), 'latin1')], ['XOR text behind a NUL (a stated limit)', Buffer.concat([Buffer.alloc(1), XOR_CACHE])]]) assert.equal(mf('m', d).xor_text, null, why);
  assert.equal(mf(`${'d/'.repeat(150)}a.node`, ELF).node_file, true, 'read from the full path (the record path is clipped)');
  assert.equal(mf('src/a.cc', 'int x;').native_source, true); assert.equal(mf('lib/a.js', 'x').native_source, false);
  assert.equal(mf('binding.gyp', "{'targets': [{'target_name': 'a', 'sources': [ 'a.c' ]}]}").gyp_sources, true);
  assert.equal(mf('binding.gyp', '{"targets":[{"target_name":"node","sources":[]}]}').gyp_sources, false, 'the decoy');
  assert.equal(mf('a.js', '"sources": ["x"]').gyp_sources, null, 'only a binding.gyp');
  assert.deepEqual(await gypOf(GYP_QUIET), { expansions: 1, quiet_script: 1 });
  assert.deepEqual(await gypOf(GYP_NORMAL), { expansions: 3, quiet_script: 0 });
  for (const [e, n, why] of [['sh build.sh >/dev/null; echo lib.a', 1, 'sh script, stdout discarded'], ['node x.js &>/dev/null', 1, '&>'], ['bun ./y.mjs 1>/dev/null', 1, '1>'],
    ['python3 tools/g.py > NUL & echo a.c', 1, 'NUL'], ['node x.js 2>/dev/null', 0, 'stderr only'], ['node -e "require(\'nan\')" >/dev/null', 0, 'inline code is not a package script'],
    ['node scripts/flags.mjs --libs', 0, 'output used'], ['cat a.txt >/dev/null', 0, 'not an interpreter']]) {
    assert.equal((await gypOf(`{"x":["<!(${e})"]}`)).quiet_script, n, why);
  }
  assert.equal((await gypOf(GYP_QUIET, 'common.gypi')).quiet_script, 1, 'a .gypi is read'); assert.equal(await gypOf(GYP_QUIET, 'index.js'), null);
});

test('C4 the 1.6 member facts are unchanged: the same record once the six new keys are set aside', async () => {
  const S = await SC(); const NEW = ['native', 'node_file', 'native_source', 'gyp_sources', 'xor_text', 'gyp_build'];
  for (const [p, d] of [['index.js', Buffer.from(LOADER_TEXT)], ['addon.node', ELF], ['.napi_cache', XOR_CACHE], ['README.md', CJK]]) {
    const a = S.memberFacts({ path: p, size: d.length, data: d });
    for (const k of NEW) assert.ok(k in a, `${p}: ${k} present`);
    const rest = Object.fromEntries(Object.entries(a).filter(([k]) => !NEW.includes(k)));
    assert.deepEqual(Object.keys(rest), ['path', 'size', 'truncated', 'excluded_path', 'binary', 'io', 'io_tokens', 'p2_lines', 'p9_lines', 'runs_total', 'run_counts', 'runs', 'agent'], p);
  }
});

// ------------------------------------------------------------------ S8 rows
test('C5 S8 WARN on recon\'s five dropper shapes, with the loads, the modules and the XOR-text member named (paths and counts only)', async () => {
  for (const [why, pkg] of Object.entries(SHAPES)) {
    const r = rowOf(await rowsOf(pkg), S8G);
    assert.equal(r?.result, 'WARN', `${why}: ${JSON.stringify(r)}`);
    assert.match(r.detail, /^an install hook loads a shipped native module \(.+\) and the tarball has no native source; .+ \(\d+ B\) is text under a one-byte XOR(?:; and \d+ more)?; armed by install-introduced$/, why);   // the more-clause added after the first run (declared)
    for (const bad of ['readdirSync', 'module.exports', 'fixture:', 'require(', 'init()']) assert.ok(!r.detail.includes(bad), `${why}: ${bad} leaked`);
  }
  assert.match(rowOf(await rowsOf(SHAPES['the win32 ternary']), S8G).detail, /\(addon\.node, addon_win\.node; hook-names-node-file\)/);
  assert.match(rowOf(await rowsOf(SHAPES['a hook target that requires a .node file']), S8G).detail, /; target-requires-node-file\)/);
});

test('C6 S8 ALLOW: native source, a binding.gyp source, no XOR member, no hook load, a non-native .node, UTF-8 text, high entropy, no hook, prepare', async () => {
  const base = SHAPES['node-gyp-build with prebuilds/'];
  const cases = [
    ['native source shipped', { ...base, files: { ...base.files, 'src/binding.cc': '#include <node_api.h>\n' } }],
    ['a binding.gyp with a source', { ...base, files: { ...base.files, 'binding.gyp': '{"targets":[{"target_name":"b","sources":["b.cc"]}]}' } }],
    ['no XOR-text member (A only)', { ...base, files: Object.fromEntries(Object.entries(base.files).filter(([p]) => !p.endsWith('.napi_cache'))) }],
    ['no hook load', { hooks: { postinstall: 'node setup.js' }, files: { 'setup.js': 'console.log("ok");\n', 'addon.node': ELF, '.cache': XOR_CACHE } }],
    ['a .node file that is not native', { hooks: { postinstall: NODE_E }, files: { 'addon.node': 'module.exports = 1;\n', '.cache': XOR_CACHE } }],
    ['UTF-8 text beside the module', { hooks: { postinstall: NODE_E }, files: { 'addon.node': ELF, 'LICENSE.zh-CN': CJK } }],
    ['high entropy beside the module', { hooks: { postinstall: NODE_E }, files: { 'addon.node': ELF, 'blob.bin': noNulRandom(70000) } }],
    ['prepare is not an install hook', { hooks: { prepare: NODE_E }, files: { 'addon.node': ELF, '.cache': XOR_CACHE } }],
  ];
  for (const [why, pkg] of cases) assert.equal(rowOf(await rowsOf(pkg), S8G)?.result, 'ALLOW', why);
  assert.match(rowOf(await rowsOf(cases[2][1]), S8G).detail, /^an install hook loads a shipped native module with no native source \(prebuilds\/linux-x64\/node\.napi\.node, prebuilds\/win32-x64\/node\.napi\.node\), and no member is text under a one-byte XOR/, 'A stays a fact on the row');
  assert.match(rowOf(await rowsOf({ hooks: {}, files: { 'addon.node': ELF, '.cache': XOR_CACHE } }), S8G).detail, /^no install hook; armed by/);
});

test('C7 a tarball package.json hook counts for S8; without member facts S8 and S9 are SKIP "not checked", stated, and over the member cap likewise', async () => {
  const t = rowOf(await rowsOf({ hooks: {}, files: { 'addon.node': ELF, '.cache': XOR_CACHE } }, { tarballHooks: { postinstall: NODE_E } }), S8G);
  assert.equal(t?.result, 'WARN', JSON.stringify(t));
  const none = await rowsOf(SHAPES['the win32 ternary'], { withMembers: false });
  for (const g of [S8G, S9G]) assert.equal(rowOf(none, g)?.detail, 'not checked: no member facts supplied; armed by install-introduced', g);
  const over = await rowsOf(SHAPES['the win32 ternary'], { membersOver: true }); const S = await SC();
  for (const g of [S8G, S9G]) assert.equal(rowOf(over, g)?.detail, `not checked: more than ${S.MAX_FACTS_MEMBERS} archive members: member facts not kept; armed by install-introduced`, g);
  assert.ok(S.staticSettled({ gates_fired: none }), 'a stated "not checked" for the tarball\'s own shape is final, not retried');
});

// ------------------------------------------------------------------ S9 rows
test('C8 S9 WARN on the test-brotli shape, with and without an install hook (npm builds a root binding.gyp itself); the command is never quoted', async () => {
  for (const hooks of [{ install: 'node-gyp rebuild' }, {}]) {
    const r = rowOf(await rowsOf({ hooks, files: { 'binding.gyp': GYP_QUIET, 'index.js': OBF } }), S9G);
    assert.equal(r?.result, 'WARN', JSON.stringify(r));
    assert.equal(r.detail, 'binding.gyp runs a package script in 1 command expansion with its output discarded; armed by install-introduced');
  }
});

test('C9 S9 ALLOW on normal gyp files and without one; S8 and S9 are independent', async () => {
  for (const [why, files, detail] of [['normal expansions', { 'binding.gyp': GYP_NORMAL, 'src/a.cc': 'int a;' }, '1 gyp file, 3 command expansions; none runs a package script with its output discarded'],
    ['no gyp file', { 'index.js': 'module.exports = 1;\n' }, 'no gyp file'],
    ['a quiet expansion with no package script', { 'binding.gyp': '{"x":["<!(make -C deps >/dev/null; echo lib.a)"]}' }, '1 gyp file, 1 command expansion; none runs a package script with its output discarded']]) {
    const r = rowOf(await rowsOf({ hooks: { install: 'node-gyp rebuild' }, files }), S9G);
    assert.equal(r?.result, 'ALLOW', why); assert.equal(r.detail, `${detail}; armed by install-introduced`, why);
  }
  const both = await rowsOf({ hooks: { postinstall: 'node-gyp-build' }, files: { ...SHAPES['node-gyp-build with prebuilds/'].files, 'binding.gyp': GYP_QUIET } });
  assert.equal(rowOf(both, S9G).result, 'WARN'); assert.equal(rowOf(both, S8G).result, 'ALLOW', 'a binding.gyp with a source list is native source for S8');
  for (const pkg of Object.values(SHAPES)) assert.equal(rowOf(await rowsOf(pkg), S9G).result, 'ALLOW');
});

test('C10 S0-S7 rows are unchanged by the member facts: the same rows with and without them', async () => {
  for (const pkg of [...Object.values(SHAPES), { hooks: { install: 'node-gyp rebuild' }, files: { 'binding.gyp': GYP_QUIET, 'index.js': OBF } }]) {
    const a = (await rowsOf(pkg)).filter((r) => ![S8G, S9G].includes(r.gate)); const b = (await rowsOf(pkg, { withMembers: false })).filter((r) => ![S8G, S9G].includes(r.gate));
    assert.deepEqual(a, b);
  }
});

// ------------------------------------------------------------------ bounded cost
test('C11 bounded cost: the XOR read over 1 MiB adversarial bodies, memberFacts over a 2 MiB window', async () => {
  const S = await SC(); const MiB = 1 << 20;
  const bodies = [['XOR text', Buffer.alloc(MiB, XOR_CACHE)], ['high entropy', noNulRandom(MiB)], ['all 0xff', Buffer.alloc(MiB, 0xff)], ['invalid UTF-8 at the end', Buffer.concat([Buffer.alloc(MiB - 1, 0x61), Buffer.from([0xc3])])]];
  for (const [why, d] of bodies) { const t0 = performance.now(); S.xorText(d); const ms = performance.now() - t0; assert.ok(ms < 300, `${why}: ${ms.toFixed(0)} ms`); }
  const big = Buffer.alloc(2 * MiB, XOR_CACHE); const t0 = performance.now(); const m = S.memberFacts({ path: 'big', size: 3 * MiB, data: big }); const ms = performance.now() - t0;
  assert.ok(m.xor_text, 'read over its first xorWindow bytes'); assert.ok(ms < 2500, `memberFacts 2 MiB: ${ms.toFixed(0)} ms`);
  assert.equal(S.xorText(Buffer.concat([Buffer.alloc(S.S8_LIMITS.xorWindow, 0x61), XOR_CACHE])), null, 'only the first xorWindow bytes are read');
  assert.ok(S.gypExpansions('<!('.repeat(1000)).length <= S.GYP_LIMITS.maxExpansions);
});

// ------------------------------------------------------------------ end to end: the proxy and `chaingate check --tarball`
const H = 3_600_000; const T0 = Date.parse('2026-03-01T00:00:00Z'); const at = (h) => new Date(T0 + h * H).toISOString();
function hdr(name, size) {
  const h = Buffer.alloc(512, 0); Buffer.from(name, 'utf8').copy(h, 0, 0, 100);
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116); h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
  h.write('00000000000\0', 136); h.write('        ', 148); h.write('0', 156, 'latin1'); h.write('ustar\0', 257, 'latin1'); h.write('00', 263, 'latin1');
  let sum = 0; for (let i = 0; i < 512; i += 1) sum += h[i]; h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1'); return h;
}
const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512, 0)]);
const tgz = (files) => zlib.gzipSync(Buffer.concat([...Object.entries(files).flatMap(([p, c]) => [hdr(`package/${p}`, Buffer.byteLength(c)), pad(Buffer.from(c))]), Buffer.alloc(1024, 0)]));
// d: 1.1.0 adds the dropper's postinstall 48 h after a hookless 1.0.0 -> install-introduced WARN (named) -> ARMED; its archive is the
// node -e shape. b: 1.1.0 adds an install hook and the test-brotli binding.gyp.
const doc = (name, extra) => ({ name, 'dist-tags': { latest: '1.1.0' }, time: { '1.0.0': at(0), '1.1.0': at(48) },
  versions: { '1.0.0': { name, version: '1.0.0', main: 'index.js' }, '1.1.0': { name, version: '1.1.0', main: 'index.js', ...extra } } });
const D = doc('d', { scripts: { postinstall: NODE_E } }); const B = doc('b', { scripts: { install: 'node-gyp rebuild' } });
const DOCS = { '/d': D, '/b': B };
const TARBALLS = {
  '/d/-/d-1.1.0.tgz': tgz({ 'package.json': JSON.stringify(D.versions['1.1.0']), 'index.js': "try{require('./addon.node').init();}catch(e){}\n", 'addon.node': ELF, '.cache': XOR_CACHE }),
  '/b/-/b-1.1.0.tgz': tgz({ 'package.json': JSON.stringify(B.versions['1.1.0']), 'index.js': OBF, 'binding.gyp': GYP_QUIET }),
};
async function withProxy(config, fn) {
  resetDependencyCache(); forgetManifestHooks();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-18-'));
  const up = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]);
    if (TARBALLS[u]) { res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': String(TARBALLS[u].length) }); res.end(TARBALLS[u]); return; }
    if (DOCS[u]) { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(DOCS[u])); return; }
    res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}');
  });
  await new Promise((r) => up.listen(0, '127.0.0.1', r));
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${up.address().port}`,
    witnessDbPath: path.join(dir, 'witness.db'), headersTimeoutMs: 10_000, bodyTimeoutMs: 20_000, ...config });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const realErr = console.error; console.error = () => {};
  try { return await fn({ base: `http://127.0.0.1:${proxy.address().port}`, proxy }); } finally {
    console.error = realErr;
    await new Promise((r) => proxy.close(r)); await new Promise((r) => up.close(r)); fs.rmSync(dir, { recursive: true, force: true });
    resetDependencyCache(); forgetManifestHooks();
  }
}
const get = (u) => new Promise((resolve, reject) => http.get(u, { agent: false }, (res) => {
  const chunks = []; res.on('data', (x) => chunks.push(x)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
}).on('error', reject));
const settle = () => new Promise((r) => setTimeout(r, 250));
async function rowsEventually(proxy, pkg, v, gate, ms = 5000) {
  const until = Date.now() + ms; const read = () => (proxy.witnessDb.getLatestDecision(pkg, v)?.gates_fired ?? []).find((g) => g.gate === gate);
  let r = read(); while (!r && Date.now() < until) { await new Promise((x) => setTimeout(x, 50)); r = read(); }
  return r;
}

test('C12 through the proxy: an armed download of the dropper records S8 WARN (named); the next download carries S8\'s notice', async () => {
  await withProxy({}, async ({ base, proxy }) => {
    await get(`${base}/d`); const t = await get(`${base}/d/-/d-1.1.0.tgz`); await settle();
    assert.equal(t.status, 200); assert.ok(t.body.equals(TARBALLS['/d/-/d-1.1.0.tgz']), 'served unchanged (switch off)');
    const r = await rowsEventually(proxy, 'd', '1.1.0', S8G);
    assert.equal(r?.result, 'WARN', JSON.stringify(r)); assert.match(r.detail, /^an install hook loads a shipped native module \(addon\.node; hook-names-node-file\) and the tarball has no native source; \.cache \(\d+ B\) is text under a one-byte XOR/);
    const t2 = await get(`${base}/d/-/d-1.1.0.tgz`);
    assert.equal(t2.status, 200); assert.ok((t2.headers['npm-notice'] ?? '').includes(S8_NOTICE), t2.headers['npm-notice']);
  });
});

test('C13 through the proxy with static_withhold on: the dropper is withheld (403 naming S8); the hidden gyp script likewise (S9)', async () => {
  await withProxy({ staticWithhold: true }, async ({ base, proxy }) => {
    await get(`${base}/d`); const t = await get(`${base}/d/-/d-1.1.0.tgz`); await settle();
    assert.equal(t.status, 403, String(t.body)); assert.equal(t.headers['npm-notice'], `chaingate: WITHHELD d@1.1.0: ${S8_NOTICE} (your static_withhold setting). Details: chaingate why d@1.1.0`);
    await get(`${base}/b`); const u = await get(`${base}/b/-/b-1.1.0.tgz`); await settle();
    assert.equal(u.status, 403, String(u.body)); assert.equal(u.headers['npm-notice'], `chaingate: WITHHELD b@1.1.0: ${S9_NOTICE} (your static_withhold setting). Details: chaingate why b@1.1.0`);
    assert.equal((await rowsEventually(proxy, 'b', '1.1.0', S9G))?.result, 'WARN');
  });
});

test('C14 chaingate check --tarball reads the member facts too: S8 and S9 rows in the tarball member', async () => {
  const { runCheck } = await import('../../cli/commands/check.js');
  const { buildSeed, docFor, after, manifestFor } = await import('../seed-v3/u05-fixtures.mjs');
  const s = buildSeed({ layout: '1.1' }); const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-18c-'));
  try {
    const man = { ...manifestFor('p', '1.3.0'), main: 'index.js', scripts: { postinstall: NODE_E } };
    const pk = path.join(dir, 'p.json'); fs.writeFileSync(pk, JSON.stringify(docFor('p', [['1.3.0', after(), man]])));
    const tb = path.join(dir, 'p-1.3.0.tgz'); fs.writeFileSync(tb, tgz({ 'package.json': JSON.stringify({ name: 'p', version: '1.3.0', main: 'index.js', scripts: { postinstall: NODE_E } }),
      'index.js': 'module.exports = 1;\n', 'addon.node': ELF, '.cache': XOR_CACHE, 'binding.gyp': GYP_QUIET }));
    const env = { ...process.env, CHAINGATE_HOME: dir, CHAINGATE_SEED_V3: s.dbPath, CHAINGATE_SEED_V3_TRUST: 'unsigned-development',
      CHAINGATE_POLICY_ON_UNUSABLE_INPUT: 'WARN', CHAINGATE_POLICY_ON_NO_EVIDENCE: 'WARN', CHAINGATE_WITNESS_DB: path.join(dir, 'w.db') };
    const { record } = await runCheck({ name: 'p', version: '1.3.0', packument: pk, tarball: tb, env, cwd: dir });
    assert.equal(record.tarball.static_checks_version, 'static-checks-1.9');
    const r8 = record.tarball.rows.find((x) => x.gate === S8G); const r9 = record.tarball.rows.find((x) => x.gate === S9G);
    assert.equal(r8?.result, 'ALLOW', `a binding.gyp is native source for S8 only when it names one: ${JSON.stringify(r8)}`);
    assert.equal(r9?.result, 'WARN', JSON.stringify(r9));
    fs.writeFileSync(tb, tgz({ 'package.json': JSON.stringify({ name: 'p', version: '1.3.0', main: 'index.js', scripts: { postinstall: NODE_E } }),
      'index.js': 'module.exports = 1;\n', 'addon.node': ELF, '.cache': XOR_CACHE }));
    const again = await runCheck({ name: 'p', version: '1.3.0', packument: pk, tarball: tb, env, cwd: dir });
    assert.equal(again.record.tarball.rows.find((x) => x.gate === S8G)?.result, 'WARN');
    assert.equal(again.record.tarball.disposition, 'WARN');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); s.cleanup?.(); }
});
