// U-03.1 — upstream HTTP hardening for @cgsec/chaingate 0.1.1.
//
// The proxy's upstream traffic (packuments, tarballs, background dependency lookups and the raw
// fallback) goes through proxy/registry.js, which uses an Agent from the pinned undici 6.28.1 with
// keep-alive disabled (`pipelining: 0`). These tests drive that path against a hostile loopback
// upstream and assert what the npm client receives, what the witness store and the dependency cache
// record, and how upstream sockets are actually used:
//
//   * response poisoning: an upstream that writes an unsolicited response after each reply (with
//     the next request's package name, or another one) must never have it delivered for, or
//     recorded as, a later request. On undici 6.25.0 and on 6.28.1 with keep-alive, we reproduced
//     this on reused sockets. The mitigation is not reusing upstream sockets, and the tests assert
//     that on the sockets themselves: one request per connection, closed by the client after it;
//   * truncated bodies must fail the request and never create witness records;
//   * header values carrying CR/LF must be rejected before anything reaches the upstream;
//   * ordinary traffic, sequential and concurrent, still works, one connection per request;
//   * the pinned client is the one in use even though `node:http` has installed Node's own bundled
//     undici as the process-wide dispatcher, and that global dispatcher is left alone.
//
// Everything is loopback. A raw `net` upstream is used where the attack needs byte-level control.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import semver from 'semver';
import { request as undiciRequest, Agent } from 'undici';

import { createProxyServer } from '../../proxy/server.js';
import { fetchPackument, UpstreamError } from '../../proxy/registry.js';
import { openWitnessDB } from '../../witness/db.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const GLOBAL_DISPATCHER = Symbol.for('undici.globalDispatcher.1');
const TRIALS = 30;
const GENUINE_CREATED = '2020-01-01T00:00:00.000Z';
const INJECTED_CREATED = '2099-09-09T00:00:00.000Z';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const close = (s) => new Promise((resolve) => s.close(() => resolve()));

async function waitFor(predicate, ms = 5_000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (predicate()) return true; await sleep(20); }
  return predicate();
}

function tmpDbPath() {
  const dir = mkdtempSync(join(tmpdir(), 'chaingate-u031-'));
  return { path: join(dir, 'witness.db'), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

async function startProxy(upstreamUrl, witnessDbPath) {
  const server = createProxyServer({
    port: 0, host: '127.0.0.1', upstream: upstreamUrl, witnessDbPath,
    headersTimeoutMs: 2_000, bodyTimeoutMs: 2_000,
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return { server, url: `http://127.0.0.1:${server.address().port}` };
}

/** A packument. `newDep` adds a dependency and a postinstall script to the last version. */
function packument(name, versions, { created = GENUINE_CREATED, newDep = null } = {}) {
  const vs = {}; const time = { created };
  versions.forEach((v, i) => {
    const last = i === versions.length - 1;
    vs[v] = {
      name, version: v,
      dependencies: newDep && last ? { [newDep]: '^1.0.0' } : {},
      ...(newDep && last ? { scripts: { postinstall: 'node setup.js' } } : {}),
      _npmUser: { name: 'maintainer', email: 'm@example.com' }, _npmVersion: '10.9.2',
      dist: { shasum: `shasum-${name}-${v}`, integrity: `sha512-${name}-${v}==`,
        tarball: `https://registry.npmjs.org/${name}/-/${name}-${v}.tgz`, unpackedSize: 1000 },
    };
    time[v] = created;
  });
  return JSON.stringify({ name, 'dist-tags': { latest: versions[versions.length - 1] }, versions: vs, time });
}

// What a hostile upstream wants a later request to receive: a version that exists in no genuine
// document, and a creation date no genuine document has.
const injected = (name) => packument(name, ['6.6.6'], { created: INJECTED_CREATED });

/** A response that invites keep-alive, so any reuse is the client's choice. */
function response(body, type = 'application/json') {
  return `HTTP/1.1 200 OK\r\ncontent-type: ${type}\r\ncontent-length: ${Buffer.byteLength(body)}\r\n`
    + `connection: keep-alive\r\nkeep-alive: timeout=30\r\n\r\n${body}`;
}

/**
 * Raw upstream: parses GET request heads per socket and hands each to `onRequest(path, socket)`.
 * Records every connection, the requests it carried, and whether the CLIENT closed it.
 */
function startRawUpstream(onRequest) {
  const stats = { connections: 0, requests: [], perConnection: new Map(), clientClosed: 0, closed: 0 };
  const sockets = new Set();
  const server = net.createServer((socket) => {
    const conn = ++stats.connections; sockets.add(socket); stats.perConnection.set(conn, 0);
    socket.on('end', () => { stats.clientClosed += 1; });
    socket.on('close', () => { stats.closed += 1; sockets.delete(socket); });
    socket.on('error', () => {});
    let buf = '';
    socket.on('data', (d) => {
      buf += d.toString('latin1');
      let i;
      while ((i = buf.indexOf('\r\n\r\n')) !== -1) {
        const head = buf.slice(0, i); buf = buf.slice(i + 4);
        const path = head.split('\r\n')[0].split(' ')[1];
        stats.requests.push({ conn, path, head });
        stats.perConnection.set(conn, stats.perConnection.get(conn) + 1);
        onRequest(path, socket);
      }
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    stats, url: `http://127.0.0.1:${server.address().port}`,
    close: () => { for (const s of sockets) s.destroy(); return close(server); },
  })));
}

/**
 * The sockets themselves: one request per connection, `connection: close` on every request, and
 * every connection closed after its single response. This upstream never closes a socket itself,
 * so each close is the client's; it may close cleanly (FIN) or by reset, which some platforms
 * (macOS) do. Either proves the connection was not kept for reuse.
 */
async function assertNoSocketReuse(up, label) {
  const { stats } = up;
  assert.ok(stats.requests.length > 0, `${label}: the upstream saw traffic`);
  const reused = [...stats.perConnection.entries()].filter(([, n]) => n > 1);
  assert.deepEqual(reused, [], `${label}: no upstream connection carried more than one request`);
  assert.equal(stats.connections, stats.requests.length, `${label}: one connection per request`);
  const keepAlive = stats.requests.filter((r) => !/\r\nconnection: close(\r\n|$)/i.test(r.head));
  assert.equal(keepAlive.length, 0, `${label}: every request asked for connection: close`);
  await waitFor(() => stats.closed === stats.connections, 2_000);
  assert.equal(stats.closed, stats.connections, `${label}: every connection was closed by the client after its response (FIN or reset)`);
}

/**
 * Hostile upstream: after answering `/a<i>` or `/host<i>` genuinely it immediately writes an
 * unsolicited response on the same socket. With `match`, the injected document carries the name
 * the NEXT request will ask for (`b<i>`, or the host's new dependency `dep<i>`); otherwise it is
 * named `pkg-evil`. Tarball requests are answered with GENUINE bytes followed by an injected EVIL
 * tarball response.
 */
function hostileUpstream({ match }) {
  return startRawUpstream((path, socket) => {
    const name = decodeURIComponent(path.slice(1));
    const inject = (next) => setImmediate(() => { if (!socket.destroyed) socket.write(response(injected(match ? next : 'pkg-evil'))); });
    if (/\/-\//.test(path)) {
      socket.write(response(`GENUINE ${path}`, 'application/octet-stream'));
      setImmediate(() => { if (!socket.destroyed) socket.write(response('EVIL-TARBALL', 'application/octet-stream')); });
    } else if (/^a\d+$/.test(name)) {
      socket.write(response(packument(name, ['2.0.0'])));
      inject(`b${name.slice(1)}`);
    } else if (/^host\d+$/.test(name)) {
      // Ten versions: history-dependent gates need MIN_HISTORY_DEPTH (8) prior versions on record.
      const versions = Array.from({ length: 10 }, (_, k) => `1.${k}.0`);
      socket.write(response(packument(name, versions, { newDep: `dep${name.slice(4)}` })));
      inject(`dep${name.slice(4)}`);
    } else {
      socket.write(response(packument(name, ['1.0.0', '1.1.0'])));
    }
  });
}

for (const match of [true, false]) {
  const kind = match ? "the next request's package name" : 'another package name';
  test(`poisoning, direct: injected responses carrying ${kind} never reach a later request on the same origin`, async (t) => {
    const up = await hostileUpstream({ match });
    const config = { upstream: up.url, headersTimeoutMs: 2_000, bodyTimeoutMs: 2_000 };
    let poisoned = 0;
    try {
      for (let i = 0; i < TRIALS; i++) {
        const a = await fetchPackument(`a${i}`, { config });
        assert.equal(JSON.parse(await a.body.text()).name, `a${i}`);
        const b = await fetchPackument(`b${i}`, { config });   // dispatched at once, same origin
        const text = await b.body.text();
        if (text.includes('6.6.6')) poisoned += 1;
        else assert.deepEqual(Object.keys(JSON.parse(text).versions), ['1.0.0', '1.1.0']);
      }
      t.diagnostic(`${TRIALS} pairs: poisoned ${poisoned}; ${up.stats.requests.length} requests on ${up.stats.connections} connections`);
      assert.equal(poisoned, 0, `the injected document was delivered in ${poisoned}/${TRIALS} pairs`);
      await assertNoSocketReuse(up, 'direct');
    } finally { await up.close(); }
  });

  test(`poisoning, through the proxy (${kind}): nothing injected reaches the client or the witness store`, async () => {
    const up = await hostileUpstream({ match });
    const { path, cleanup } = tmpDbPath();
    const proxy = await startProxy(up.url, path);
    try {
      for (let i = 0; i < TRIALS; i++) {
        const a = await undiciRequest(`${proxy.url}/a${i}`);
        assert.equal(a.statusCode, 200); await a.body.text();
        const b = await undiciRequest(`${proxy.url}/b${i}`);
        const text = await b.body.text();
        assert.equal(b.statusCode, 200, `trial ${i}`);
        assert.ok(!text.includes('6.6.6'), `trial ${i}: the npm client did not receive the injected version`);
        assert.equal(JSON.parse(text).name, `b${i}`);
      }
      const w = openWitnessDB(path, { readonly: true });
      try {
        assert.deepEqual(w.db.prepare("SELECT package_name FROM gate_decisions WHERE version = '6.6.6'").all(), []);
        assert.equal(w.db.prepare("SELECT COUNT(*) AS n FROM versions WHERE version = '6.6.6'").get().n, 0);
        assert.equal(w.db.prepare("SELECT COUNT(*) AS n FROM gate_decisions WHERE package_name = 'pkg-evil'").get().n, 0);
        for (let i = 0; i < TRIALS; i++) {
          const rows = w.db.prepare('SELECT version FROM gate_decisions WHERE package_name = ? ORDER BY version').all(`b${i}`);
          assert.deepEqual(rows.map((r) => r.version), ['1.0.0', '1.1.0'], `b${i} recorded exactly its own versions`);
        }
      } finally { w.close(); }
      await assertNoSocketReuse(up, 'proxy packuments');
    } finally { await close(proxy.server); await up.close(); cleanup(); }
  });

  test(`poisoning, background dependency lookups (${kind}): the dependency cache records only genuine answers`, async (t) => {
    const up = await hostileUpstream({ match });
    const { path, cleanup } = tmpDbPath();
    const proxy = await startProxy(up.url, path);
    const HOSTS = 8;
    try {
      // Twice each: the scope-boundary gate compares a version against the recorded history, so it
      // queues lookups for a new dependency only once the host's earlier versions are on record.
      for (const round of [1, 2]) {
        for (let i = 0; i < HOSTS; i++) {
          const r = await undiciRequest(`${proxy.url}/host${i}`);
          assert.equal(r.statusCode, 200, `round ${round}`); await r.body.text();
        }
      }
      const w = openWitnessDB(path, { readonly: true });
      try {
        const rows = () => w.db.prepare("SELECT package_name, first_publish, status FROM dep_first_publish ORDER BY package_name").all();
        const done = await waitFor(() => rows().length >= HOSTS, 10_000);
        t.diagnostic(`dependency cache: ${JSON.stringify(rows().map((r) => `${r.package_name}:${r.status}`))}`);
        assert.ok(done, 'every background lookup completed');
        const got = rows();
        assert.deepEqual(got.map((r) => r.package_name).sort(), Array.from({ length: HOSTS }, (_, i) => `dep${i}`).sort(),
          'lookups ran for exactly the new dependencies, and nothing for pkg-evil');
        for (const r of got) {
          assert.equal(r.status, 'ok', `${r.package_name} looked up`);
          assert.equal(r.first_publish, GENUINE_CREATED, `${r.package_name} cached the genuine creation date, not the injected one`);
        }
      } finally { w.close(); }
      const lookups = up.stats.requests.filter((r) => /^\/dep\d+$/.test(r.path)).length;
      assert.equal(lookups, HOSTS, 'the lookups really went upstream');
      await assertNoSocketReuse(up, 'background lookups');
    } finally { await close(proxy.server); await up.close(); cleanup(); }
  });
}

test('poisoning, tarballs: each tarball request receives its own bytes, never the injected response', async () => {
  const up = await hostileUpstream({ match: true });
  const { path, cleanup } = tmpDbPath();
  const proxy = await startProxy(up.url, path);
  try {
    for (let i = 0; i < TRIALS; i++) {
      const p = `/t${i}/-/t${i}-1.0.0.tgz`;
      const r = await undiciRequest(`${proxy.url}${p}`);
      assert.equal(r.statusCode, 200);
      assert.equal(await r.body.text(), `GENUINE ${p}`, `tarball ${i}`);
    }
    await assertNoSocketReuse(up, 'tarballs');
  } finally { await close(proxy.server); await up.close(); cleanup(); }
});

test('poisoning, raw fallback: the handler-level fallback fetch is covered by the same client', async (t) => {
  // The fallback runs only after an internal (non-upstream) error. Force one: the first writeHead
  // for each `/b<i>` response throws, so the handler falls back to a raw upstream fetch.
  const up = await hostileUpstream({ match: true });
  const { path, cleanup } = tmpDbPath();
  const proxy = await startProxy(up.url, path);
  const orig = http.ServerResponse.prototype.writeHead;
  const thrown = new Set();
  http.ServerResponse.prototype.writeHead = function (...args) {
    const url = this.req?.url ?? '';
    if (/^\/b\d+$/.test(url) && !thrown.has(url)) { thrown.add(url); throw new Error('test: forced internal error'); }
    return orig.apply(this, args);
  };
  try {
    for (let i = 0; i < TRIALS; i++) {
      const a = await undiciRequest(`${proxy.url}/a${i}`); await a.body.text();
      const b = await undiciRequest(`${proxy.url}/b${i}`);
      const text = await b.body.text();
      assert.equal(b.statusCode, 200);
      assert.ok(!text.includes('6.6.6'), `trial ${i}: the fallback served no injected version`);
      assert.equal(JSON.parse(text).name, `b${i}`);
    }
    assert.equal(thrown.size, TRIALS, 'the fallback path ran for every b request');
    const bFetches = up.stats.requests.filter((r) => /^\/b\d+$/.test(r.path)).length;
    t.diagnostic(`b requests upstream: ${bFetches} (normal fetch + fallback fetch)`);
    assert.equal(bFetches, TRIALS * 2, 'each b was fetched by the normal path and again by the fallback');
    await assertNoSocketReuse(up, 'fallback');
  } finally {
    http.ServerResponse.prototype.writeHead = orig;
    await close(proxy.server); await up.close(); cleanup();
  }
});

/** Proxy a single packument request against a raw upstream behaviour; return status and witness rows. */
async function proxyOnce(name, behaviour) {
  const up = await startRawUpstream((_path, socket) => behaviour(socket));
  const { path, cleanup } = tmpDbPath();
  const proxy = await startProxy(up.url, path);
  try {
    const r = await undiciRequest(`${proxy.url}/${name}`);
    const body = await r.body.text();
    const w = openWitnessDB(path, { readonly: true });
    try {
      const decisions = w.db.prepare('SELECT COUNT(*) AS n FROM gate_decisions WHERE package_name = ?').get(name).n;
      const baselines = w.db.prepare(
        'SELECT COUNT(*) AS n FROM versions v JOIN packages p ON p.id = v.package_id WHERE p.package_name = ?').get(name).n;
      return { status: r.statusCode, body, decisions, baselines };
    } finally { w.close(); }
  } finally { await close(proxy.server); await up.close(); cleanup(); }
}

test('truncated body (Content-Length longer than the bytes sent) fails the request and records nothing', async () => {
  const full = packument('pkg-t', ['1.0.0', '1.1.0']);
  const r = await proxyOnce('pkg-t', (s) => {
    s.write(`HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: ${full.length}\r\n\r\n`);
    s.end(full.slice(0, 60));
  });
  assert.equal(r.status, 502, 'served as an upstream failure, not as a document');
  assert.equal(r.decisions, 0); assert.equal(r.baselines, 0);
});

test('chunked stream closed before its terminating chunk is not treated as complete, even when the bytes parse', async () => {
  // The bytes received form a complete, parseable packument; only the 0-length terminator is
  // missing. Before undici 6.26 (and on Node 22's bundled 6.24.1) this was accepted as complete.
  const doc = packument('pkg-c', ['1.0.0']);
  const r = await proxyOnce('pkg-c', (s) => {
    s.write('HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n');
    s.end(`${Buffer.byteLength(doc).toString(16)}\r\n${doc}\r\n`);
  });
  assert.equal(r.status, 502, 'an unterminated chunked response is an upstream failure');
  assert.equal(r.decisions, 0, 'no gate decisions from an incomplete response');
  assert.equal(r.baselines, 0, 'no witness baselines from an incomplete response');
});

test('chunked stream cut mid-document fails the request and is never served to the client as complete', async () => {
  const doc = packument('pkg-m', ['1.0.0', '1.1.0']);
  const r = await proxyOnce('pkg-m', (s) => {
    s.write('HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n');
    s.end(`40\r\n${doc.slice(0, 64)}\r\n`);
  });
  assert.equal(r.status, 502);
  assert.equal(r.decisions, 0); assert.equal(r.baselines, 0);
});

test('relayed header values carrying CR/LF are rejected before anything reaches the upstream', async () => {
  const up = await startRawUpstream((p, s) => s.write(response(packument(p.slice(1), ['1.0.0']))));
  const config = { upstream: up.url, headersTimeoutMs: 2_000, bodyTimeoutMs: 2_000 };
  try {
    for (const value of ['Bearer x\r\nx-injected: 1', ['Bearer ok', 'Bearer x\r\nx-injected: 1'], 'x\ny', 'x\0y']) {
      await assert.rejects(fetchPackument('pkg-b', { config, requestHeaders: { authorization: value } }),
        (err) => err instanceof UpstreamError && /invalid authorization header/.test(err.message),
        `rejected: ${JSON.stringify(value)}`);
    }
    assert.equal(up.stats.requests.length, 0, 'the upstream received no request at all');
    const ok = await fetchPackument('pkg-b', { config, requestHeaders: { authorization: 'Bearer ok' } });
    assert.equal(JSON.parse(await ok.body.text()).name, 'pkg-b');
    assert.match(up.stats.requests[0].head, /\r\nauthorization: Bearer ok(\r\n|$)/);
    assert.ok(!up.stats.requests.some((r) => /x-injected/i.test(r.head)));
  } finally { await up.close(); }
});

test('coerced (non-string) header values are validated too (undici 6.28 request.js fix)', async () => {
  // ChainGate relays only strings from Node's parser, so it cannot produce this itself; the test
  // pins the pinned client's behaviour for any caller of the same `request()` path.
  const up = await startRawUpstream((_p, s) => s.write(response('{}')));
  const dispatcher = new Agent({ pipelining: 0 });   // the pinned client, not the global dispatcher
  try {
    const crafted = Object.assign(() => {}, { toString: () => 'x\r\nx-injected: 1' });
    await assert.rejects(undiciRequest(`${up.url}/pkg-b`, { dispatcher, headers: { 'x-test': crafted } }), /invalid x-test header/);
    await assert.rejects(undiciRequest(`${up.url}/pkg-b`, { dispatcher, headers: { 'x-test': ['ok', crafted] } }), /invalid x-test header/);
    assert.equal(up.stats.requests.length, 0);
  } finally { await dispatcher.close(); await up.close(); }
});

test('a client request with a control character in a header never reaches the upstream', async () => {
  const up = await startRawUpstream((_p, s) => s.write(response('{}')));
  const { path, cleanup } = tmpDbPath();
  const proxy = await startProxy(up.url, path);
  try {
    const port = new URL(proxy.url).port;
    const reply = await new Promise((resolve, reject) => {
      const c = net.connect(port, '127.0.0.1', () => c.write('GET /pkg-b HTTP/1.1\r\nhost: x\r\nauthorization: a\0b\r\n\r\n'));
      let out = ''; c.on('data', (d) => { out += d; }); c.on('end', () => resolve(out)); c.on('close', () => resolve(out)); c.on('error', reject);
      setTimeout(() => { c.destroy(); resolve(out); }, 1_000);
    });
    assert.match(reply, /^HTTP\/1\.1 400/, 'the proxy rejects the request');
    assert.equal(up.stats.requests.length, 0, 'nothing was sent upstream');
  } finally { await close(proxy.server); await up.close(); cleanup(); }
});

function honestUpstream() {
  const seen = { connections: 0, requests: 0, keepAliveRequests: 0 };
  const server = http.createServer({ keepAliveTimeout: 30_000 }, (req, res) => {
    seen.requests += 1;
    if (req.headers.connection !== 'close') seen.keepAliveRequests += 1;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(packument(decodeURIComponent(req.url.slice(1)), ['1.0.0', '1.2.3']));
  });
  server.on('connection', () => { seen.connections += 1; });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    url: `http://127.0.0.1:${server.address().port}`, seen,
    close: () => { server.closeAllConnections(); return close(server); },
  })));
}

test('compatibility: sequential packuments are answered correctly, one upstream connection each', async () => {
  const up = await honestUpstream();
  const { path, cleanup } = tmpDbPath();
  const proxy = await startProxy(up.url, path);
  const N = 20;
  try {
    for (let i = 0; i < N; i++) {
      const r = await undiciRequest(`${proxy.url}/seq-${i}`);
      assert.equal(r.statusCode, 200);
      assert.equal(JSON.parse(await r.body.text()).name, `seq-${i}`);
    }
    assert.equal(up.seen.requests, N);
    assert.equal(up.seen.connections, N, 'no upstream keep-alive reuse: one connection per request');
    assert.equal(up.seen.keepAliveRequests, 0, 'every upstream request asked for connection: close');
    const w = openWitnessDB(path, { readonly: true });
    try {
      for (let i = 0; i < N; i++) assert.ok(w.getBaseline(`seq-${i}`, '1.2.3'), `seq-${i} recorded under its own name`);
      assert.equal(w.db.prepare('SELECT COUNT(*) AS n FROM gate_decisions').get().n, N * 2);
    } finally { w.close(); }
  } finally { await close(proxy.server); await up.close(); cleanup(); }
});

test('compatibility: concurrent packuments are each answered with their own document', async () => {
  const up = await honestUpstream();
  const { path, cleanup } = tmpDbPath();
  const proxy = await startProxy(up.url, path);
  try {
    const names = Array.from({ length: 12 }, (_, i) => `par-${i}`);
    const bodies = await Promise.all(names.map(async (n) => {
      const r = await undiciRequest(`${proxy.url}/${n}`);
      assert.equal(r.statusCode, 200);
      return JSON.parse(await r.body.text()).name;
    }));
    assert.deepEqual(bodies, names);
    assert.equal(up.seen.connections, names.length, 'one upstream connection per request');
  } finally { await close(proxy.server); await up.close(); cleanup(); }
});

test("the pinned client is in use although node:http installed Node's bundled undici globally, which is left alone", async (t) => {
  const before = globalThis[GLOBAL_DISPATCHER];
  const nodeBundled = process.versions.undici;
  t.diagnostic(`Node bundled undici ${nodeBundled}; global dispatcher is ${before instanceof Agent ? 'the pinned undici' : "Node's bundled undici"}`);
  const truncated = (s) => {
    s.write('HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n');
    s.end('2\r\n{}\r\n');
  };
  const up = await startRawUpstream((_p, s) => truncated(s));
  try {
    const config = { upstream: up.url, headersTimeoutMs: 2_000, bodyTimeoutMs: 2_000 };
    const r = await fetchPackument('x', { config });
    await assert.rejects(r.body.text(), /Invalid EOF state|HPE_INVALID_EOF_STATE/, 'the proxy path rejects the unterminated chunked body');
    if (!(before instanceof Agent) && semver.lt(nodeBundled, '6.26.0')) {
      // Control: the global dispatcher (Node's bundled client) would have accepted the same bytes,
      // so the rejection above comes from the pinned client.
      const g = await undiciRequest(`${up.url}/x`);
      assert.equal(await g.body.text(), '{}', "Node's bundled client accepts the unterminated body");
    } else {
      t.diagnostic('control skipped: the global dispatcher already rejects unterminated chunked bodies');
    }
    assert.equal(globalThis[GLOBAL_DISPATCHER], before, 'the process-wide global dispatcher was not replaced');
    assert.doesNotMatch(readFileSync(join(ROOT, 'proxy', 'registry.js'), 'utf8'), /setGlobalDispatcher/);
  } finally { await up.close(); }
});

test('every upstream request in the proxy goes through the one pinned-client call site', () => {
  // Structural companion to the socket-level tests: server.js (normal and fallback paths) and the
  // background dependency fetcher reach the upstream only through registry.js.
  for (const f of ['server.js', 'dep-fetcher.js']) {
    const src = readFileSync(join(ROOT, 'proxy', f), 'utf8');
    assert.doesNotMatch(src, /from 'undici'|require\('undici'\)|\bfetch\(/, `${f} has no HTTP client of its own`);
  }
  const reg = readFileSync(join(ROOT, 'proxy', 'registry.js'), 'utf8');
  assert.equal((reg.match(/^\s*return await request\(/gm) ?? []).length, 1, 'registry.js has exactly one request() call');
  assert.equal((reg.match(/\brequest\(url/g) ?? []).length, 1);
  assert.match(reg, /new Agent\(\{ pipelining: 0 \}\)/);
  assert.match(reg, /dispatcher: upstreamAgent/);
});

test('the installed undici is the exact pinned version, at or above 6.28.1', () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  const pinned = pkg.dependencies.undici;
  assert.ok(semver.valid(pinned), `undici is pinned to an exact version (got ${pinned})`);
  assert.ok(semver.gte(pinned, '6.28.1') && semver.lt(pinned, '7.0.0'), `pin ${pinned} is a patched 6.x`);
  const req = createRequire(join(ROOT, 'proxy', 'registry.js'));
  const resolved = JSON.parse(readFileSync(req.resolve('undici/package.json'), 'utf8')).version;
  assert.equal(resolved, pinned, 'proxy/registry.js resolves exactly the pinned undici');
});
