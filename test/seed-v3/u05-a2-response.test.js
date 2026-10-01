// U-05 Amendment 2 (owner decision 2026-10-01, item 3), condition (a): a computed BLOCK must never be lost while the
// proxy builds its response. Expected results come from the Amendment 2 table (P4a, P4b, P5a, isolation), written
// before this file; the tests were run failing-first on 41886e5.
//
// Fault injection: `ServerResponse.prototype.writeHead` throws for the first call(s) of the targeted response, which
// reaches the real P4 (rewriter branch) and P5 (handler fallback) code without a test-only seam.
// Recorded vehicle change (gap-closure r2 Addendum 1 §E, owner decision 6): these tests first made console.error throw.
// The approved logging boundary (A1) absorbs logging failures, so that vehicle no longer reaches P4a/P5a; with logging
// failing, enforcement simply continues (200, BLOCKed version removed), which A2-1L/A2-2L/A2-3L now pin. The invariant
// is unchanged: the original document is never served.
// Fixture: the U-05 synthetic seed; p@1.3.0 pinned (ADV-P-130), p@1.4.0 and q@1.3.0 unpinned. Loopback only.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createProxyServer } from '../../proxy/server.js';
import { rewritePackument } from '../../gates/rewriter.js';
import { buildSeed, docFor, after, CONFIGS } from './u05-fixtures.mjs';

const DOCS = () => ({ p: docFor('p', [['1.3.0', after(1)], ['1.4.0', after(2)]]), q: docFor('q', [['1.3.0', after(1)]]) });
const listen = (srv) => new Promise((resolve) => { srv.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${srv.address().port}`)); });
const close = (srv) => new Promise((resolve) => { srv.close(() => resolve()); });
const get = (url) => new Promise((resolve, reject) => {
  http.get(url, { agent: false }, (res) => {
    let b = ''; res.setEncoding('utf8'); res.on('data', (x) => { b += x; });
    res.on('end', () => { let json = null; try { json = JSON.parse(b); } catch { /* not JSON */ } resolve({ status: res.statusCode, json }); });
  }).on('error', reject);
});

/** The first `times` writeHead calls of the PROXY (not the fixture registry) for `url` throw. Returns restore(). */
function failWriteHead(proxyUrl, url, times) {
  const real = http.ServerResponse.prototype.writeHead;
  const port = Number(new URL(proxyUrl).port);
  let n = 0;
  http.ServerResponse.prototype.writeHead = function patched(...args) {
    if (this.req?.url === url && this.socket?.localPort === port && n < times) { n += 1; throw new Error(`injected writeHead failure ${n}`); }
    return real.apply(this, args);
  };
  return () => { http.ServerResponse.prototype.writeHead = real; };
}

/** console.error throws on lines starting with any of `prefixes`; every other line is swallowed. Returns restore(). */
function failLogging(prefixes) {
  const real = console.error;
  console.error = (msg) => {
    const s = String(msg);
    if (prefixes.some((p) => s.startsWith(p))) throw new Error(`injected log failure (${s.slice(0, 30)})`);
  };
  return () => { console.error = real; };
}

async function withProxy(cfg, fn) {
  const seed = buildSeed({ layout: '1.1' });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'u05-a2-'));
  const docs = DOCS();
  const fetches = [];
  const upstream = http.createServer((req, res) => {
    const name = decodeURIComponent(req.url.slice(1));
    fetches.push(name);
    if (!docs[name]) { res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}'); return; }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(docs[name]));
  });
  const upstreamUrl = await listen(upstream);
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: upstreamUrl,
    witnessDbPath: path.join(dir, 'witness.db'), headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000,
    seedV3Path: seed.dbPath, seedV3Trust: 'unsigned-development',
    policyOnUnusableInput: cfg.on_unusable_input, policyOnNoEvidence: cfg.on_no_evidence }, {});
  const proxyUrl = await listen(proxy);
  try {
    return await fn({ proxyUrl, fetches });
  } finally {
    await close(proxy); await close(upstream); seed.cleanup(); fs.rmSync(dir, { recursive: true, force: true });
  }
}

const versionsOf = (r) => Object.keys(r.json?.versions ?? {});
function refusedNotServed(r, label) {
  assert.equal(r.status, 502, `${label}: refused with 502`);
  assert.equal(r.json?.error, 'chaingate_enforcement_failed', `${label}: says enforcement failed`);
  assert.ok(!versionsOf(r).includes('1.3.0'), `${label}: the BLOCKed version is not served`);
}

test('A2 control: without a fault the pinned version is removed and the rest is served', async () => {
  for (const [name, cfg] of Object.entries(CONFIGS)) {
    await withProxy(cfg, async ({ proxyUrl, fetches }) => {
      const r = await get(`${proxyUrl}/p`);
      assert.equal(r.status, 200, name);
      assert.ok(!versionsOf(r).includes('1.3.0'), `${name}: 1.3.0 removed`);
      assert.ok(versionsOf(r).includes('1.4.0'), `${name}: 1.4.0 served`);
      assert.deepEqual(fetches, ['p']);
    });
  }
});

test('A2-1 (P4a) the response cannot be written inside the rewriter branch: the original document is never served', async () => {
  for (const [name, cfg] of Object.entries(CONFIGS)) {
    await withProxy(cfg, async ({ proxyUrl, fetches }) => {
      const restore = failWriteHead(proxyUrl, '/p', 1);
      let r;
      try { r = await get(`${proxyUrl}/p`); } finally { restore(); }
      refusedNotServed(r, `A2-1 ${name}`);
      assert.match(r.json?.detail ?? '', /BLOCK/, `A2-1 ${name}: the detail says a BLOCK could not be enforced`);
      assert.deepEqual(fetches, ['p'], `A2-1 ${name}: one upstream fetch`);
    });
  }
});

test('A2-2 (P5a) the failure escapes the packument handler after a BLOCK: no raw passthrough', async () => {
  for (const [name, cfg] of Object.entries(CONFIGS)) {
    await withProxy(cfg, async ({ proxyUrl, fetches }) => {
      const restore = failWriteHead(proxyUrl, '/p', 2);
      let r;
      try { r = await get(`${proxyUrl}/p`); } finally { restore(); }
      refusedNotServed(r, `A2-2 ${name}`);
      assert.deepEqual(fetches, ['p'], `A2-2 ${name}: no second (passthrough) upstream fetch`);
    });
  }
});

test('A2-3 isolation: only the failing package is refused; others and later requests are served', async () => {
  for (const [name, cfg] of Object.entries(CONFIGS)) {
    await withProxy(cfg, async ({ proxyUrl }) => {
      const restore = failWriteHead(proxyUrl, '/p', 1);
      let before; let p; let afterQ;
      try {
        before = await get(`${proxyUrl}/q`);
        p = await get(`${proxyUrl}/p`);
        afterQ = await get(`${proxyUrl}/q`);
      } finally { restore(); }
      for (const [label, r] of [['before', before], ['after', afterQ]]) {
        assert.equal(r.status, 200, `A2-3 ${name} q ${label}`);
        assert.ok(versionsOf(r).includes('1.3.0'), `A2-3 ${name} q ${label}: q@1.3.0 (unpinned) served`);
      }
      refusedNotServed(p, `A2-3 ${name} p`);
      const ok = await get(`${proxyUrl}/p`);                 // the fault is gone: normal enforcement again
      assert.equal(ok.status, 200, `A2-3 ${name}: p served again once the response can be written`);
      assert.ok(!versionsOf(ok).includes('1.3.0') && versionsOf(ok).includes('1.4.0'), `A2-3 ${name}: and still enforced`);
    });
  }
});

// A1 (logging boundary): logging that fails on the same lines no longer reaches P4a/P5a. Enforcement continues and the
// original document is still never served. Failing-first on 3ee5aba (which answered 502).
for (const [label, prefixes] of [['A2-1L', ['[gate]']], ['A2-2L', ['[gate]', '[rewriter]']]]) {
  test(`${label} logging fails on ${prefixes.join(' and ')} lines: the BLOCK is still applied and the response is served`, async () => {
    for (const [name, cfg] of Object.entries(CONFIGS)) {
      await withProxy(cfg, async ({ proxyUrl, fetches }) => {
        const restore = failLogging(prefixes);
        let r;
        try { r = await get(`${proxyUrl}/p`); } finally { restore(); }
        assert.equal(r.status, 200, `${label} ${name}: served`);
        assert.ok(!versionsOf(r).includes('1.3.0'), `${label} ${name}: the BLOCKed version is removed`);
        assert.ok(versionsOf(r).includes('1.4.0'), `${label} ${name}: the rest is served`);
        assert.deepEqual(fetches, ['p'], `${label} ${name}: one upstream fetch`);
      });
    }
  });
}

test('A2-4 (P4b, pins existing behaviour) no change is reported only when no BLOCKed version is in the document', () => {
  const doc = DOCS().p;
  const absent = rewritePackument(doc, new Map([['9.9.9', { disposition: 'BLOCK', results: [] }]]));
  assert.equal(absent.changed, false);
  assert.strictEqual(absent.packument, doc, 'the document is returned unchanged');
  assert.ok(!Object.keys(absent.packument.versions).includes('9.9.9'));
  const present = rewritePackument(doc, new Map([['1.3.0', { disposition: 'BLOCK', results: [] }]]));
  assert.equal(present.changed, true);
  assert.ok(!Object.keys(present.packument.versions).includes('1.3.0'));
  assert.ok(!Object.values(present.packument['dist-tags']).includes('1.3.0'));
});
