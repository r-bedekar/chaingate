import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request as undiciRequest } from 'undici';

import { createProxyServer } from '../../proxy/server.js';
import { openWitnessDB } from '../../witness/db.js';

function tmpDbPath() {
  const dir = mkdtempSync(join(tmpdir(), 'chaingate-observe-'));
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

async function startProxy(upstreamUrl, witnessDbPath) {
  const server = createProxyServer({
    port: 0,
    host: '127.0.0.1',
    upstream: upstreamUrl,
    witnessDbPath,
    headersTimeoutMs: 2_000,
    bodyTimeoutMs: 2_000,
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

function axiosPackument(versions = ['1.7.8', '1.7.9']) {
  const versionsObj = {};
  const time = {};
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
    time[v] = '2024-12-23T00:00:00.000Z';
  }
  return JSON.stringify({ name: 'axios', 'dist-tags': { latest: versions[versions.length - 1] }, versions: versionsObj, time });
}

test('packument request → witness records baselines + decisions; body byte-identical', async () => {
  const body = axiosPackument(['1.7.8', '1.7.9', '1.8.0']);
  const upstream = await startFakeUpstream((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(body);
  });
  const { path, cleanup } = tmpDbPath();
  const proxy = await startProxy(upstream.url, path);
  try {
    const resp = await undiciRequest(`${proxy.url}/axios`);
    assert.equal(resp.statusCode, 200);
    const text = await resp.body.text();
    assert.equal(text, body);

    // Inspect witness DB — open a separate handle (WAL allows concurrent readers).
    const inspector = openWitnessDB(path, { readonly: true });
    try {
      assert.ok(inspector.getBaseline('axios', '1.7.8'));
      assert.ok(inspector.getBaseline('axios', '1.7.9'));
      assert.ok(inspector.getBaseline('axios', '1.8.0'));
      const n = inspector.db
        .prepare(`SELECT COUNT(*) AS n FROM gate_decisions WHERE package_name='axios'`)
        .get().n;
      assert.equal(n, 3);
    } finally {
      inspector.close();
    }
  } finally {
    await close(proxy.server);
    await close(upstream.server);
    cleanup();
  }
});

test('double-observe → sparsity holds (no new decision rows on replay)', async () => {
  const body = axiosPackument();
  const upstream = await startFakeUpstream((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(body);
  });
  const { path, cleanup } = tmpDbPath();
  const proxy = await startProxy(upstream.url, path);
  try {
    await undiciRequest(`${proxy.url}/axios`).then((r) => r.body.text());
    await undiciRequest(`${proxy.url}/axios`).then((r) => r.body.text());
    const inspector = openWitnessDB(path, { readonly: true });
    try {
      const n = inspector.db
        .prepare(`SELECT COUNT(*) AS n FROM gate_decisions WHERE package_name='axios'`)
        .get().n;
      assert.equal(n, 2);
    } finally {
      inspector.close();
    }
  } finally {
    await close(proxy.server);
    await close(upstream.server);
    cleanup();
  }
});

test('upstream 404 → no DB writes; 404 relayed', async () => {
  const upstream = await startFakeUpstream((_req, res) => {
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end('{"error":"not found"}');
  });
  const { path, cleanup } = tmpDbPath();
  const proxy = await startProxy(upstream.url, path);
  try {
    const resp = await undiciRequest(`${proxy.url}/nope`);
    assert.equal(resp.statusCode, 404);
    await resp.body.text();
    const inspector = openWitnessDB(path, { readonly: true });
    try {
      const n = inspector.db.prepare(`SELECT COUNT(*) AS n FROM gate_decisions`).get().n;
      assert.equal(n, 0);
      const pkgs = inspector.db.prepare(`SELECT COUNT(*) AS n FROM packages`).get().n;
      assert.equal(pkgs, 0);
    } finally {
      inspector.close();
    }
  } finally {
    await close(proxy.server);
    await close(upstream.server);
    cleanup();
  }
});

test('non-JSON body on 200 → witness skipped, body relayed unchanged', async () => {
  const garbage = '<<<not-json>>>';
  const upstream = await startFakeUpstream((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(garbage);
  });
  const { path, cleanup } = tmpDbPath();
  const proxy = await startProxy(upstream.url, path);
  try {
    const resp = await undiciRequest(`${proxy.url}/axios`);
    assert.equal(resp.statusCode, 200);
    assert.equal(await resp.body.text(), garbage);
    const inspector = openWitnessDB(path, { readonly: true });
    try {
      const n = inspector.db.prepare(`SELECT COUNT(*) AS n FROM gate_decisions`).get().n;
      assert.equal(n, 0);
    } finally {
      inspector.close();
    }
  } finally {
    await close(proxy.server);
    await close(upstream.server);
    cleanup();
  }
});
