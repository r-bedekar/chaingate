import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request as undiciRequest } from 'undici';

import { createProxyServer, parseTarballVersion, normalizePackageName } from '../../proxy/server.js';

function tmpDbPath() {
  const dir = mkdtempSync(join(tmpdir(), 'chaingate-rewrite-'));
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

async function startProxy(upstreamUrl, witnessDbPath, { gateModules = [] } = {}) {
  const server = createProxyServer(
    {
      port: 0,
      host: '127.0.0.1',
      upstream: upstreamUrl,
      witnessDbPath,
      headersTimeoutMs: 2_000,
      bodyTimeoutMs: 2_000,
    },
    { gateModules },
  );
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return { server, url: `http://127.0.0.1:${server.address().port}` };
}

function close(s) {
  return new Promise((resolve) => s.close(resolve));
}

function axiosPackumentJson(versions = ['1.7.8', '1.7.9', '1.8.0'], latest = null) {
  const versionsObj = {};
  const time = { created: '2020-01-01T00:00:00Z', modified: '2024-12-23T00:00:00Z' };
  for (const v of versions) {
    versionsObj[v] = {
      name: 'axios',
      version: v,
      dependencies: { 'follow-redirects': '^1.15.6' },
      _npmUser: { name: 'jasonsaayman', email: 'j@example.com' },
      _npmVersion: '10.9.2',
      dist: {
        shasum: `shasum-${v}`,
        integrity: `sha512-${v}==`,
        tarball: `https://registry.npmjs.org/axios/-/axios-${v}.tgz`,
        unpackedSize: 432109,
      },
    };
    time[v] = '2024-12-23T00:00:00Z';
  }
  return JSON.stringify({
    name: 'axios',
    'dist-tags': { latest: latest ?? versions[versions.length - 1] },
    versions: versionsObj,
    time,
  });
}

// Uses the `content-hash` gate name so the first-seen poisoning-protection
// depth gate in gates/index.js does not suppress it — only content-hash is
// exempt, which matches reality: content-hash is the only V1 gate that can
// BLOCK, and it's baseline-based (not pattern-based) so depth is irrelevant.
const blockVersionModule = (version) => ({
  name: 'content-hash',
  evaluate: (input) => ({
    gate: 'content-hash',
    result: input.version === version ? 'BLOCK' : 'ALLOW',
    detail: `test block for ${version}`,
  }),
});

// ---- normalization helpers -----------------------------------------------

test('normalizePackageName: decodes %2F', () => {
  assert.equal(normalizePackageName('@babel/core'), '@babel/core');
  assert.equal(normalizePackageName('@babel%2Fcore'), '@babel/core');
  assert.equal(normalizePackageName('@babel%2fcore'), '@babel/core');
  assert.equal(normalizePackageName('axios'), 'axios');
});

test('parseTarballVersion: unscoped and scoped', () => {
  assert.equal(parseTarballVersion('axios', 'axios-1.7.9.tgz'), '1.7.9');
  assert.equal(parseTarballVersion('@babel/core', 'core-7.24.0.tgz'), '7.24.0');
  assert.equal(parseTarballVersion('axios', 'axios-2.0.0-rc.1.tgz'), '2.0.0-rc.1');
  assert.equal(parseTarballVersion('axios', 'not-matching.tgz'), null);
  assert.equal(parseTarballVersion('axios', 'axios-1.7.9.zip'), null);
});

// ---- packument rewrite ----------------------------------------------------

test('zero BLOCK decisions → body byte-identical to upstream', async () => {
  const body = axiosPackumentJson();
  const upstream = await startFakeUpstream((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(body);
  });
  const { path, cleanup } = tmpDbPath();
  const proxy = await startProxy(upstream.url, path);
  try {
    const resp = await undiciRequest(`${proxy.url}/axios`);
    assert.equal(resp.statusCode, 200);
    assert.equal(await resp.body.text(), body);
  } finally {
    await close(proxy.server);
    await close(upstream.server);
    cleanup();
  }
});

test('BLOCK via stub module → rewritten packument; blocked version absent', async () => {
  const body = axiosPackumentJson(['1.7.8', '1.7.9', '1.8.0'], '1.8.0');
  const upstream = await startFakeUpstream((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(body);
  });
  const { path, cleanup } = tmpDbPath();
  const proxy = await startProxy(upstream.url, path, {
    gateModules: [blockVersionModule('1.7.9')],
  });
  try {
    const resp = await undiciRequest(`${proxy.url}/axios`);
    assert.equal(resp.statusCode, 200);
    const parsed = JSON.parse(await resp.body.text());
    assert.ok(!('1.7.9' in parsed.versions));
    assert.ok('1.7.8' in parsed.versions);
    assert.ok('1.8.0' in parsed.versions);
    assert.equal(parsed['dist-tags'].latest, '1.8.0'); // latest unaffected
  } finally {
    await close(proxy.server);
    await close(upstream.server);
    cleanup();
  }
});

test('BLOCK the latest version → dist-tags.latest downgrades', async () => {
  const body = axiosPackumentJson(['1.7.8', '1.7.9', '1.8.0'], '1.8.0');
  const upstream = await startFakeUpstream((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(body);
  });
  const { path, cleanup } = tmpDbPath();
  const proxy = await startProxy(upstream.url, path, {
    gateModules: [blockVersionModule('1.8.0')],
  });
  try {
    const resp = await undiciRequest(`${proxy.url}/axios`);
    assert.equal(resp.statusCode, 200);
    const parsed = JSON.parse(await resp.body.text());
    assert.ok(!('1.8.0' in parsed.versions));
    assert.equal(parsed['dist-tags'].latest, '1.7.9');
  } finally {
    await close(proxy.server);
    await close(upstream.server);
    cleanup();
  }
});

test('rewritten response strips etag (stale against new body)', async () => {
  const body = axiosPackumentJson();
  const upstream = await startFakeUpstream((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', etag: 'W/"orig"' });
    res.end(body);
  });
  const { path, cleanup } = tmpDbPath();
  const proxy = await startProxy(upstream.url, path, {
    gateModules: [blockVersionModule('1.7.8')],
  });
  try {
    const resp = await undiciRequest(`${proxy.url}/axios`);
    assert.equal(resp.statusCode, 200);
    assert.equal(resp.headers.etag, undefined);
    await resp.body.text();
  } finally {
    await close(proxy.server);
    await close(upstream.server);
    cleanup();
  }
});

// ---- tarball BLOCK gate --------------------------------------------------

test('tarball request for BLOCK version → 403 with gate evidence', async () => {
  // First request: packument with stub BLOCKing 1.7.9 to populate gate_decisions.
  // Second request: tarball for 1.7.9 should 403 without touching upstream.
  let tarballHit = false;
  const upstream = await startFakeUpstream((req, res) => {
    if (req.url.includes('.tgz')) {
      tarballHit = true;
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(Buffer.from([0x1f, 0x8b]));
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(axiosPackumentJson());
  });
  const { path, cleanup } = tmpDbPath();
  const proxy = await startProxy(upstream.url, path, {
    gateModules: [blockVersionModule('1.7.9')],
  });
  try {
    await undiciRequest(`${proxy.url}/axios`).then((r) => r.body.text());
    const resp = await undiciRequest(`${proxy.url}/axios/-/axios-1.7.9.tgz`);
    assert.equal(resp.statusCode, 403);
    const json = JSON.parse(await resp.body.text());
    assert.equal(json.error, 'blocked_by_chaingate');
    assert.equal(json.package, 'axios');
    assert.equal(json.version, '1.7.9');
    assert.ok(Array.isArray(json.gates));
    assert.ok(json.gates.some((g) => g.gate === 'content-hash'));
    assert.match(json.how_to_override, /chaingate allow axios@1\.7\.9/);
    assert.equal(tarballHit, false, 'upstream tarball must not be hit for blocked version');
  } finally {
    await close(proxy.server);
    await close(upstream.server);
    cleanup();
  }
});

test('tarball for BLOCK version WITH override → 200 passthrough', async () => {
  const tarBytes = Buffer.from([0x1f, 0x8b, 0x08, 0x00]);
  const upstream = await startFakeUpstream((req, res) => {
    if (req.url.includes('.tgz')) {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(tarBytes);
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(axiosPackumentJson());
  });
  const { path, cleanup } = tmpDbPath();
  const proxy = await startProxy(upstream.url, path, {
    gateModules: [blockVersionModule('1.7.9')],
  });
  try {
    // Populate gate_decisions first.
    await undiciRequest(`${proxy.url}/axios`).then((r) => r.body.text());
    // Insert override directly — P5.8 CLI isn't built yet, but the DB path works.
    proxy.server.witnessDb.insertOverride('axios', '1.7.9', 'trusted mirror');
    const resp = await undiciRequest(`${proxy.url}/axios/-/axios-1.7.9.tgz`);
    assert.equal(resp.statusCode, 200);
    const buf = Buffer.from(await resp.body.arrayBuffer());
    assert.deepEqual(buf, tarBytes);
  } finally {
    await close(proxy.server);
    await close(upstream.server);
    cleanup();
  }
});

test('tarball for ALLOW version → 200 passthrough (no false block)', async () => {
  const tarBytes = Buffer.from([0x1f, 0x8b]);
  const upstream = await startFakeUpstream((req, res) => {
    if (req.url.includes('.tgz')) {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(tarBytes);
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(axiosPackumentJson());
  });
  const { path, cleanup } = tmpDbPath();
  const proxy = await startProxy(upstream.url, path, {
    gateModules: [blockVersionModule('1.7.9')],
  });
  try {
    await undiciRequest(`${proxy.url}/axios`).then((r) => r.body.text());
    const resp = await undiciRequest(`${proxy.url}/axios/-/axios-1.8.0.tgz`);
    assert.equal(resp.statusCode, 200);
    await resp.body.arrayBuffer();
  } finally {
    await close(proxy.server);
    await close(upstream.server);
    cleanup();
  }
});

test('tarball for never-observed version → 200 passthrough (no decision = no block)', async () => {
  const tarBytes = Buffer.from([0x1f, 0x8b]);
  const upstream = await startFakeUpstream((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/octet-stream' });
    res.end(tarBytes);
  });
  const { path, cleanup } = tmpDbPath();
  const proxy = await startProxy(upstream.url, path);
  try {
    const resp = await undiciRequest(`${proxy.url}/axios/-/axios-9.9.9.tgz`);
    assert.equal(resp.statusCode, 200);
    await resp.body.arrayBuffer();
  } finally {
    await close(proxy.server);
    await close(upstream.server);
    cleanup();
  }
});

test('scoped package name: /@babel/core and /@babel%2Fcore collide on one packages row', async () => {
  const scopedBody = JSON.stringify({
    name: '@babel/core',
    'dist-tags': { latest: '7.24.0' },
    versions: {
      '7.24.0': {
        name: '@babel/core',
        version: '7.24.0',
        dist: {
          shasum: 'abc',
          integrity: 'sha512-zzz==',
          tarball: 'https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz',
        },
      },
    },
    time: { '7.24.0': '2024-03-01T00:00:00Z' },
  });
  const upstream = await startFakeUpstream((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(scopedBody);
  });
  const { path, cleanup } = tmpDbPath();
  const proxy = await startProxy(upstream.url, path);
  try {
    await undiciRequest(`${proxy.url}/@babel/core`).then((r) => r.body.text());
    await undiciRequest(`${proxy.url}/@babel%2Fcore`).then((r) => r.body.text());
    const rows = proxy.server.witnessDb.db
      .prepare(`SELECT COUNT(*) AS n FROM packages WHERE package_name='@babel/core'`)
      .get().n;
    assert.equal(rows, 1, 'both URL forms must write to the same packages row');
  } finally {
    await close(proxy.server);
    await close(upstream.server);
    cleanup();
  }
});
