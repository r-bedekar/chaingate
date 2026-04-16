// P5.9 — Axios attack validation (flagship test)
//
// Simulates the Axios 1.14.1 supply chain attack (2026-03-31): a phantom
// dependency (plain-crypto-js), publisher email change, OIDC provenance
// dropped, and install scripts added. ChainGate fires 4 gates simultaneously:
// dep-structure WARN, publisher-identity WARN, provenance-continuity WARN,
// scope-boundary BLOCK. Overall disposition: BLOCK.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request as undiciRequest } from 'undici';

import { createProxyServer } from '../../proxy/server.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function tmpDbPath() {
  const dir = mkdtempSync(join(tmpdir(), 'chaingate-axios-'));
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
// Fixture: axios packument with 8 clean versions + 1 attack version
// ---------------------------------------------------------------------------

const CLEAN_DEPS = {
  'follow-redirects': '^1.15.6',
  'form-data': '^4.0.0',
  'proxy-from-env': '1.1.0',
};

const LEGIT_USER = { name: 'jasonsaayman', email: 'jasonsaayman@gmail.com' };
const ATTACK_USER = { name: 'ifstap', email: 'ifstap@protonmail.me' };

const CLEAN_VERSIONS = [
  '1.7.0', '1.8.0', '1.9.0', '1.10.0',
  '1.11.0', '1.12.0', '1.13.0', '1.14.0',
];

function buildPackument() {
  const versions = {};
  const time = {
    created: '2019-10-01T00:00:00.000Z',
    modified: '2026-03-31T00:00:00.000Z',
  };

  // 8 clean versions: consistent publisher, deps, provenance, no install scripts
  for (let i = 0; i < CLEAN_VERSIONS.length; i++) {
    const v = CLEAN_VERSIONS[i];
    versions[v] = {
      name: 'axios',
      version: v,
      dependencies: { ...CLEAN_DEPS },
      _npmUser: { ...LEGIT_USER },
      _npmVersion: '10.5.0',
      dist: {
        shasum: `aaaa${i}000aaaa${i}000aaaa${i}000aaaa${i}000`.slice(0, 40),
        integrity: `sha512-CleanAxios${v.replace(/\./g, '')}CleanAxios==`,
        tarball: `https://registry.npmjs.org/axios/-/axios-${v}.tgz`,
        unpackedSize: 430000 + i * 1000,
        // OIDC provenance present on all clean versions
        attestations: {
          url: `https://registry.npmjs.org/-/npm/v1/attestations/axios@${v}`,
          provenance: { predicateType: 'https://slsa.dev/provenance/v1' },
        },
      },
    };
    // Stagger clean versions: 300 to 100 days ago (all well past 72h threshold)
    time[v] = hoursAgo(7200 - i * 600);
  }

  // Attack version: phantom dep, changed publisher, no provenance, install scripts
  versions['1.14.1'] = {
    name: 'axios',
    version: '1.14.1',
    dependencies: {
      ...CLEAN_DEPS,
      'plain-crypto-js': '^1.0.0', // phantom dependency
    },
    scripts: {
      install: 'node install.js', // triggers has_install_scripts
    },
    _npmUser: { ...ATTACK_USER }, // publisher change
    _npmVersion: '10.5.0',
    dist: {
      shasum: 'ffff9999ffff9999ffff9999ffff9999ffff9999',
      integrity: 'sha512-AttackAxios1141AttackAxios1141Attack==',
      tarball: 'https://registry.npmjs.org/axios/-/axios-1.14.1.tgz',
      unpackedSize: 445000,
      // NO attestations → provenance_present: false
    },
  };
  // Published 96h ago (> 72h threshold → release-age ALLOW)
  time['1.14.1'] = hoursAgo(96);

  return JSON.stringify({
    name: 'axios',
    'dist-tags': { latest: '1.14.1' },
    versions,
    time,
  });
}

const packumentBody = buildPackument();

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('axios attack: 3 WARN + 1 BLOCK from scope-boundary', async (t) => {
  const { path: dbPath, cleanup } = tmpDbPath();

  const upstream = await startFakeUpstream((req, res) => {
    if (req.url === '/axios') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(packumentBody);
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
    // Pre-populate dep cache: plain-crypto-js published 6h ago (< 24h → scope-boundary BLOCK)
    proxy.server.depCache.recordOk('plain-crypto-js', hoursAgo(6));

    // -- Observation 1: establish baselines (history empty → all ALLOW) --
    await t.test('first observation: baselines recorded, all ALLOW', async () => {
      const resp = await undiciRequest(`${proxy.url}/axios`);
      assert.equal(resp.statusCode, 200);
      await resp.body.text(); // drain

      // 1.14.1 is ALLOW on first observation (no history for comparison)
      const decision = proxy.server.witnessDb.getLatestDecision('axios', '1.14.1');
      assert.ok(decision, 'decision should exist for 1.14.1');
      assert.equal(decision.disposition, 'ALLOW', 'first-seen with empty history → ALLOW');
    });

    // Re-populate dep cache in case the background dep-fetcher overwrote it
    proxy.server.depCache.recordOk('plain-crypto-js', hoursAgo(6));

    // -- Observation 2: full history available → gates fire on 1.14.1 --
    await t.test('second observation: 1.14.1 BLOCKED, stripped from packument', async () => {
      const resp = await undiciRequest(`${proxy.url}/axios`);
      assert.equal(resp.statusCode, 200);
      const parsed = JSON.parse(await resp.body.text());

      // 1.14.1 blocked: stripped from response
      assert.ok(!('1.14.1' in parsed.versions), '1.14.1 should be stripped (BLOCK)');

      // Clean versions still present
      for (const v of CLEAN_VERSIONS) {
        assert.ok(v in parsed.versions, `${v} should remain in packument`);
      }

      // dist-tags.latest downgraded from 1.14.1 to 1.14.0
      assert.equal(parsed['dist-tags'].latest, '1.14.0');
    });

    await t.test('gate_decisions for 1.14.1: BLOCK with 4 gates firing', async () => {
      const decision = proxy.server.witnessDb.getLatestDecision('axios', '1.14.1');
      assert.equal(decision.disposition, 'BLOCK');

      // Build a map of gate name → result for easy assertions
      const gateMap = {};
      for (const g of decision.gates_fired) {
        gateMap[g.gate] = g;
      }

      // content-hash: SKIP (re-observation with same hash as baseline)
      assert.ok(gateMap['content-hash'], 'content-hash gate should be present');
      assert.equal(gateMap['content-hash'].result, 'ALLOW',
        'content-hash should ALLOW (same hash as recorded baseline)');

      // dep-structure: WARN (plain-crypto-js not in prior 8 versions)
      assert.ok(gateMap['dep-structure'], 'dep-structure gate should be present');
      assert.equal(gateMap['dep-structure'].result, 'WARN');
      assert.match(gateMap['dep-structure'].detail, /plain-crypto-js/);

      // publisher-identity: WARN (email changed)
      assert.ok(gateMap['publisher-identity'], 'publisher-identity gate should be present');
      assert.equal(gateMap['publisher-identity'].result, 'WARN');
      assert.match(gateMap['publisher-identity'].detail, /publisher changed/i);

      // provenance-continuity: WARN (prior had OIDC, this doesn't)
      assert.ok(gateMap['provenance-continuity'], 'provenance-continuity gate should be present');
      assert.equal(gateMap['provenance-continuity'].result, 'WARN');

      // release-age: ALLOW (96h > 72h threshold)
      assert.ok(gateMap['release-age'], 'release-age gate should be present');
      assert.equal(gateMap['release-age'].result, 'ALLOW');

      // scope-boundary: BLOCK (new dep + install scripts + dep < 24h old)
      assert.ok(gateMap['scope-boundary'], 'scope-boundary gate should be present');
      assert.equal(gateMap['scope-boundary'].result, 'BLOCK');
      assert.match(gateMap['scope-boundary'].detail, /plain-crypto-js/);
    });

    await t.test('clean version 1.14.0: not BLOCK (still in packument)', async () => {
      const decision = proxy.server.witnessDb.getLatestDecision('axios', '1.14.0');
      assert.ok(decision, 'decision should exist for 1.14.0');
      // On re-observation, 1.14.0's "latest prior" by publish_at is 1.14.1
      // (the attack version), so publisher-identity fires WARN — this is
      // correct: the gate is history-driven and the newest version in history
      // has a different publisher. Overall disposition stays WARN (not BLOCK).
      assert.notEqual(decision.disposition, 'BLOCK',
        '1.14.0 should not be BLOCK (it has no attack signals of its own)');
    });

    await t.test('tarball for 1.14.1 → 403 blocked_by_chaingate', async () => {
      const resp = await undiciRequest(`${proxy.url}/axios/-/axios-1.14.1.tgz`);
      assert.equal(resp.statusCode, 403);
      const body = JSON.parse(await resp.body.text());
      assert.equal(body.error, 'blocked_by_chaingate');
      assert.equal(body.package, 'axios');
      assert.equal(body.version, '1.14.1');
      assert.match(body.how_to_override, /chaingate allow axios@1\.14\.1/);
    });

    await t.test('tarball for clean 1.14.0 → 200', async () => {
      const resp = await undiciRequest(`${proxy.url}/axios/-/axios-1.14.0.tgz`);
      assert.equal(resp.statusCode, 200);
      await resp.body.text(); // drain
    });
  } finally {
    await close(proxy.server);
    await close(upstream.server);
    cleanup();
  }
});
