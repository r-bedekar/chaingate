// P5.9 — Trivy attack validation
//
// Simulates the Trivy supply chain attack where an attacker force-pushed a
// Git tag, causing the registry to serve a different tarball under the same
// version string. ChainGate detects this via content-hash mismatch on the
// second observation.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request as undiciRequest } from 'undici';

import { createProxyServer } from '../../proxy/server.js';

// ---------------------------------------------------------------------------
// Helpers (duplicated per test file, following test/proxy/ convention)
// ---------------------------------------------------------------------------

function tmpDbPath() {
  const dir = mkdtempSync(join(tmpdir(), 'chaingate-trivy-'));
  return { path: join(dir, 'witness.db'), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function startFakeUpstream(handler) {
  const server = http.createServer(handler);
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, url: `http://127.0.0.1:${server.address().port}` });
    });
  });
}

async function startProxy(upstreamUrl, witnessDbPath, configOverrides = {}) {
  const server = createProxyServer({
    port: 0,
    host: '127.0.0.1',
    upstream: upstreamUrl,
    witnessDbPath,
    headersTimeoutMs: 5_000,
    bodyTimeoutMs: 5_000,
    ...configOverrides,
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return { server, url: `http://127.0.0.1:${server.address().port}` };
}

function close(s) {
  return new Promise((resolve) => s.close(resolve));
}

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

const FIXED_NOW = Date.parse('2026-04-15T12:00:00.000Z');
function hoursAgo(h) {
  return new Date(FIXED_NOW - h * 3_600_000).toISOString();
}

// ---------------------------------------------------------------------------
// Fixture: two packuments for trivy-plugin — same version, different hashes
// ---------------------------------------------------------------------------

function makePackument(hashFor050) {
  return JSON.stringify({
    name: 'trivy-plugin',
    'dist-tags': { latest: '0.50.0' },
    versions: {
      '0.49.0': {
        name: 'trivy-plugin',
        version: '0.49.0',
        dependencies: {},
        _npmUser: { name: 'aquasec', email: 'security@aquasec.com' },
        _npmVersion: '10.5.0',
        dist: {
          shasum: 'aaa111aaa111aaa111aaa111aaa111aaa111aaa1',
          integrity: 'sha512-STABLE049stable049stable049stable049==',
          tarball: 'https://registry.npmjs.org/trivy-plugin/-/trivy-plugin-0.49.0.tgz',
          unpackedSize: 95000,
        },
      },
      '0.50.0': {
        name: 'trivy-plugin',
        version: '0.50.0',
        dependencies: {},
        _npmUser: { name: 'aquasec', email: 'security@aquasec.com' },
        _npmVersion: '10.5.0',
        dist: {
          shasum: hashFor050.shasum,
          integrity: hashFor050.integrity,
          tarball: 'https://registry.npmjs.org/trivy-plugin/-/trivy-plugin-0.50.0.tgz',
          unpackedSize: 100000,
        },
      },
    },
    time: {
      created: '2025-06-01T00:00:00.000Z',
      modified: '2026-03-01T00:00:00.000Z',
      '0.49.0': hoursAgo(720), // 30 days ago
      '0.50.0': hoursAgo(240), // 10 days ago
    },
  });
}

const ORIGINAL_HASH = {
  shasum: 'bbb222bbb222bbb222bbb222bbb222bbb222bbb2',
  integrity: 'sha512-OriginalHashOriginalHashOriginalHash00==',
};

const COMPROMISED_HASH = {
  shasum: 'ccc333ccc333ccc333ccc333ccc333ccc333ccc3',
  integrity: 'sha512-CompromisedCompromisedCompromisedHash==',
};

const packumentA = makePackument(ORIGINAL_HASH);
const packumentB = makePackument(COMPROMISED_HASH);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('trivy: content-hash mismatch detects tarball replacement', async (t) => {
  const { path: dbPath, cleanup } = tmpDbPath();
  let currentBody = packumentA;

  const upstream = await startFakeUpstream((req, res) => {
    if (req.url === '/trivy-plugin') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(currentBody);
    } else if (req.url.endsWith('.tgz')) {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(Buffer.from([0x1f, 0x8b, 0x08]));
    } else {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end('{"error":"not found"}');
    }
  });

  const proxy = await startProxy(upstream.url, dbPath, { _nowMs: FIXED_NOW });

  try {
    // -- Observation 1: baseline recorded, both versions ALLOW --
    await t.test('first observation: baseline recorded, ALLOW', async () => {
      const resp = await undiciRequest(`${proxy.url}/trivy-plugin`);
      assert.equal(resp.statusCode, 200);
      const parsed = JSON.parse(await resp.body.text());

      // Both versions present (no blocks)
      assert.ok('0.49.0' in parsed.versions, '0.49.0 should be present');
      assert.ok('0.50.0' in parsed.versions, '0.50.0 should be present');
      assert.equal(parsed['dist-tags'].latest, '0.50.0');

      // DB: 0.50.0 is ALLOW
      const decision = proxy.server.witnessDb.getLatestDecision('trivy-plugin', '0.50.0');
      assert.ok(decision, 'decision should exist');
      assert.equal(decision.disposition, 'ALLOW');

      // content-hash should be SKIP on first observation
      const chGate = decision.gates_fired.find((g) => g.gate === 'content-hash');
      assert.ok(chGate, 'content-hash gate should be in gates_fired');
      assert.equal(chGate.result, 'SKIP');
    });

    // -- Observation 2: upstream now serves different hash → content-hash BLOCK --
    await t.test('re-observation with different hash: content-hash BLOCK', async () => {
      currentBody = packumentB;

      const resp = await undiciRequest(`${proxy.url}/trivy-plugin`);
      assert.equal(resp.statusCode, 200);
      const parsed = JSON.parse(await resp.body.text());

      // 0.50.0 blocked (stripped from packument)
      assert.ok(!('0.50.0' in parsed.versions), '0.50.0 should be stripped (BLOCK)');
      // 0.49.0 still present
      assert.ok('0.49.0' in parsed.versions, '0.49.0 should remain');
      // dist-tags.latest downgraded
      assert.equal(parsed['dist-tags'].latest, '0.49.0');

      // DB: disposition BLOCK
      const decision = proxy.server.witnessDb.getLatestDecision('trivy-plugin', '0.50.0');
      assert.equal(decision.disposition, 'BLOCK');

      // content-hash gate fired BLOCK with integrity mismatch detail
      const chGate = decision.gates_fired.find((g) => g.gate === 'content-hash');
      assert.ok(chGate, 'content-hash gate should be in gates_fired');
      assert.equal(chGate.result, 'BLOCK');
      assert.match(chGate.detail, /integrity hash differs/i);
    });

    // -- Tarball for blocked version → 403 --
    await t.test('tarball request for compromised 0.50.0 → 403', async () => {
      const resp = await undiciRequest(`${proxy.url}/trivy-plugin/-/trivy-plugin-0.50.0.tgz`);
      assert.equal(resp.statusCode, 403);
      const body = JSON.parse(await resp.body.text());
      assert.equal(body.error, 'blocked_by_chaingate');
      assert.equal(body.package, 'trivy-plugin');
      assert.equal(body.version, '0.50.0');
    });

    // -- Tarball for clean version → 200 --
    await t.test('tarball request for clean 0.49.0 → 200', async () => {
      const resp = await undiciRequest(`${proxy.url}/trivy-plugin/-/trivy-plugin-0.49.0.tgz`);
      assert.equal(resp.statusCode, 200);
      await resp.body.text(); // drain
    });
  } finally {
    await close(proxy.server);
    await close(upstream.server);
    cleanup();
  }
});
