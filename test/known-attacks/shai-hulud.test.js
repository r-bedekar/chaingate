// P5.9 — Shai-Hulud attack validation
//
// Simulates the Shai-Hulud campaign where an attacker compromised npm tokens
// for hundreds of packages and published new versions under a different
// publisher identity. ChainGate detects the publisher-identity change on
// each package independently.

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
  const dir = mkdtempSync(join(tmpdir(), 'chaingate-shai-'));
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
// Fixture: 3 packages, each with publisher change on latest version
// ---------------------------------------------------------------------------

const LEGIT_EMAIL = 'legit-dev@example.com';
const COMPROMISED_EMAIL = 'compromised@example.com';

function makePackument(name, basename, versions) {
  const versionsObj = {};
  const time = { created: '2024-01-01T00:00:00.000Z', modified: '2026-03-10T00:00:00.000Z' };
  for (const v of versions) {
    versionsObj[v.ver] = {
      name,
      version: v.ver,
      dependencies: {},
      _npmUser: { name: v.email.split('@')[0], email: v.email },
      _npmVersion: '10.5.0',
      dist: {
        shasum: `sha1-${basename}-${v.ver.replace(/\./g, '')}`.padEnd(40, '0'),
        integrity: `sha512-${basename}-${v.ver}==`,
        tarball: `https://registry.npmjs.org/${name}/-/${basename}-${v.ver}.tgz`,
        unpackedSize: 50000,
      },
    };
    time[v.ver] = v.time;
  }
  const latest = versions[versions.length - 1].ver;
  return JSON.stringify({ name, 'dist-tags': { latest }, versions: versionsObj, time });
}

const PACKAGES = [
  {
    name: 'colors-test',
    basename: 'colors-test',
    versions: [
      { ver: '1.0.0', email: LEGIT_EMAIL, time: hoursAgo(2400) },
      { ver: '1.1.0', email: LEGIT_EMAIL, time: hoursAgo(1200) },
      { ver: '1.2.0', email: LEGIT_EMAIL, time: hoursAgo(600) },
      { ver: '1.3.0', email: COMPROMISED_EMAIL, time: hoursAgo(96) },
    ],
    attackVersion: '1.3.0',
  },
  {
    name: 'faker-test',
    basename: 'faker-test',
    versions: [
      { ver: '5.0.0', email: LEGIT_EMAIL, time: hoursAgo(2000) },
      { ver: '5.1.0', email: LEGIT_EMAIL, time: hoursAgo(1000) },
      { ver: '5.2.0', email: LEGIT_EMAIL, time: hoursAgo(500) },
      { ver: '5.3.0', email: COMPROMISED_EMAIL, time: hoursAgo(96) },
    ],
    attackVersion: '5.3.0',
  },
  {
    name: 'ua-parser-test',
    basename: 'ua-parser-test',
    versions: [
      { ver: '0.7.0', email: LEGIT_EMAIL, time: hoursAgo(1800) },
      { ver: '0.7.1', email: LEGIT_EMAIL, time: hoursAgo(900) },
      { ver: '0.7.2', email: LEGIT_EMAIL, time: hoursAgo(400) },
      { ver: '0.7.3', email: COMPROMISED_EMAIL, time: hoursAgo(96) },
    ],
    attackVersion: '0.7.3',
  },
];

const packumentBodies = {};
for (const pkg of PACKAGES) {
  packumentBodies[`/${pkg.name}`] = makePackument(pkg.name, pkg.basename, pkg.versions);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('shai-hulud: publisher takeover across 3 packages', async (t) => {
  const { path: dbPath, cleanup } = tmpDbPath();

  const upstream = await startFakeUpstream((req, res) => {
    const body = packumentBodies[req.url];
    if (body) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(body);
    } else {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end('{"error":"not found"}');
    }
  });

  const proxy = await startProxy(upstream.url, dbPath, { _nowMs: FIXED_NOW });

  try {
    // -- Observation 1: establish baselines (all ALLOW, history empty) --
    await t.test('first observation: all baselines recorded', async () => {
      for (const pkg of PACKAGES) {
        const resp = await undiciRequest(`${proxy.url}/${pkg.name}`);
        assert.equal(resp.statusCode, 200);
        await resp.body.text(); // drain

        // All versions ALLOW on first observation (no history to compare against)
        const decision = proxy.server.witnessDb.getLatestDecision(pkg.name, pkg.attackVersion);
        assert.ok(decision, `decision should exist for ${pkg.name}@${pkg.attackVersion}`);
        assert.equal(decision.disposition, 'ALLOW', 'first-seen should be ALLOW');
      }
    });

    // -- Observation 2: re-observe with full history → publisher-identity WARN --
    for (const pkg of PACKAGES) {
      await t.test(`${pkg.name}: publisher-identity WARN on ${pkg.attackVersion}`, async () => {
        const resp = await undiciRequest(`${proxy.url}/${pkg.name}`);
        assert.equal(resp.statusCode, 200);
        const parsed = JSON.parse(await resp.body.text());

        // WARN does not strip versions — all should be present
        for (const v of pkg.versions) {
          assert.ok(v.ver in parsed.versions, `${v.ver} should be present (WARN does not strip)`);
        }

        // Overall disposition: WARN (1 WARN, below 4-WARN escalation threshold)
        const decision = proxy.server.witnessDb.getLatestDecision(pkg.name, pkg.attackVersion);
        assert.ok(decision, `decision should exist for ${pkg.name}@${pkg.attackVersion}`);
        assert.equal(decision.disposition, 'WARN');

        // publisher-identity gate fired WARN
        const pubGate = decision.gates_fired.find((g) => g.gate === 'publisher-identity');
        assert.ok(pubGate, 'publisher-identity gate should be in gates_fired');
        assert.equal(pubGate.result, 'WARN');
        assert.match(pubGate.detail, /publisher changed/i);

        // Other gates should NOT be WARN or BLOCK (isolated signal)
        const otherFiring = decision.gates_fired.filter(
          (g) => g.gate !== 'first-seen' && g.gate !== 'publisher-identity' &&
                 (g.result === 'WARN' || g.result === 'BLOCK'),
        );
        assert.equal(otherFiring.length, 0, 'only publisher-identity should fire WARN/BLOCK');
      });
    }
  } finally {
    await close(proxy.server);
    await close(upstream.server);
    cleanup();
  }
});
