import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { request as undiciRequest } from 'undici';

import { createProxyServer } from '../../proxy/server.js';
import { classify } from '../../proxy/server.js';
import { encodePackageName } from '../../proxy/registry.js';

// ---- Test harness ----------------------------------------------------------

function startFakeUpstream(handler) {
  const server = http.createServer(handler);
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, url: `http://127.0.0.1:${port}` });
    });
  });
}

async function startProxyFor(upstreamUrl, extraConfig = {}) {
  const server = createProxyServer({
    port: 0,
    host: '127.0.0.1',
    upstream: upstreamUrl,
    headersTimeoutMs: 2_000,
    bodyTimeoutMs: 2_000,
    ...extraConfig,
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(server.config.port, server.config.host, resolve);
  });
  const { port } = server.address();
  return { server, url: `http://127.0.0.1:${port}` };
}

function closeServer(s) {
  return new Promise((resolve) => s.close(resolve));
}

// ---- encodePackageName -----------------------------------------------------

test('encodePackageName: unscoped pass-through', () => {
  assert.equal(encodePackageName('axios'), 'axios');
});

test('encodePackageName: scoped unencoded → encoded', () => {
  assert.equal(encodePackageName('@babel/core'), '%40babel%2Fcore');
});

test('encodePackageName: scoped already-encoded → still encoded', () => {
  assert.equal(encodePackageName('@babel%2Fcore'), '%40babel%2Fcore');
});

// ---- classify --------------------------------------------------------------

test('classify: unscoped packument', () => {
  assert.deepEqual(classify('/axios'), { kind: 'packument', name: 'axios' });
});

test('classify: scoped packument (unencoded)', () => {
  assert.deepEqual(classify('/@babel/core'), { kind: 'packument', name: '@babel/core' });
});

test('classify: scoped packument (percent-encoded)', () => {
  assert.deepEqual(classify('/@babel%2Fcore'), { kind: 'packument', name: '@babel%2Fcore' });
});

test('classify: unscoped tarball', () => {
  assert.deepEqual(classify('/axios/-/axios-1.7.9.tgz'), {
    kind: 'tarball',
    name: 'axios',
    filename: 'axios-1.7.9.tgz',
  });
});

test('classify: scoped tarball', () => {
  assert.deepEqual(classify('/@babel/core/-/core-7.24.0.tgz'), {
    kind: 'tarball',
    name: '@babel/core',
    filename: 'core-7.24.0.tgz',
  });
});

test('classify: unknown', () => {
  assert.equal(classify('/').kind, 'unknown');
  assert.equal(classify('/-/ping').kind, 'unknown');
  assert.equal(classify('/foo/bar/baz').kind, 'unknown');
});

// ---- End-to-end passthrough -----------------------------------------------

test('unscoped packument round-trip preserves body + headers', async () => {
  const body = JSON.stringify({ name: 'axios', 'dist-tags': { latest: '1.7.9' } });
  let received;
  const upstream = await startFakeUpstream((req, res) => {
    received = { method: req.method, url: req.url, headers: req.headers };
    res.writeHead(200, {
      'content-type': 'application/json',
      etag: 'W/"abc"',
      'cache-control': 'public, max-age=300',
    });
    res.end(body);
  });
  const proxy = await startProxyFor(upstream.url);
  try {
    const resp = await undiciRequest(`${proxy.url}/axios`);
    assert.equal(resp.statusCode, 200);
    assert.equal(resp.headers['content-type'], 'application/json');
    assert.equal(resp.headers.etag, 'W/"abc"');
    assert.equal(resp.headers['cache-control'], 'public, max-age=300');
    const text = await resp.body.text();
    assert.equal(text, body);
    assert.equal(received.method, 'GET');
    assert.equal(received.url, '/axios');
  } finally {
    await closeServer(proxy.server);
    await closeServer(upstream.server);
  }
});

test('scoped name "@babel/core" is URL-encoded to upstream', async () => {
  let received;
  const upstream = await startFakeUpstream((req, res) => {
    received = req.url;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
  });
  const proxy = await startProxyFor(upstream.url);
  try {
    const resp = await undiciRequest(`${proxy.url}/@babel/core`);
    assert.equal(resp.statusCode, 200);
    await resp.body.text();
    assert.equal(received, '/%40babel%2Fcore');
  } finally {
    await closeServer(proxy.server);
    await closeServer(upstream.server);
  }
});

test('tarball passthrough (binary-safe)', async () => {
  const tarballBytes = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef]);
  let received;
  const upstream = await startFakeUpstream((req, res) => {
    received = req.url;
    res.writeHead(200, {
      'content-type': 'application/octet-stream',
      'content-length': tarballBytes.length,
    });
    res.end(tarballBytes);
  });
  const proxy = await startProxyFor(upstream.url);
  try {
    const resp = await undiciRequest(`${proxy.url}/axios/-/axios-1.7.9.tgz`);
    assert.equal(resp.statusCode, 200);
    const buf = Buffer.from(await resp.body.arrayBuffer());
    assert.deepEqual(buf, tarballBytes);
    assert.equal(received, '/axios/-/axios-1.7.9.tgz');
  } finally {
    await closeServer(proxy.server);
    await closeServer(upstream.server);
  }
});

test('upstream 304 relays as 304 with no body', async () => {
  const upstream = await startFakeUpstream((req, res) => {
    if (req.headers['if-none-match'] === 'W/"cached"') {
      res.writeHead(304, { etag: 'W/"cached"' });
      res.end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json', etag: 'W/"cached"' });
    res.end('{}');
  });
  const proxy = await startProxyFor(upstream.url);
  try {
    const resp = await undiciRequest(`${proxy.url}/axios`, {
      headers: { 'if-none-match': 'W/"cached"' },
    });
    assert.equal(resp.statusCode, 304);
    assert.equal(resp.headers.etag, 'W/"cached"');
    const text = await resp.body.text();
    assert.equal(text, '');
  } finally {
    await closeServer(proxy.server);
    await closeServer(upstream.server);
  }
});

test('upstream 404 relays as 404', async () => {
  const upstream = await startFakeUpstream((req, res) => {
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end('{"error":"not found"}');
  });
  const proxy = await startProxyFor(upstream.url);
  try {
    const resp = await undiciRequest(`${proxy.url}/nonexistent-pkg`);
    assert.equal(resp.statusCode, 404);
    const text = await resp.body.text();
    assert.equal(text, '{"error":"not found"}');
  } finally {
    await closeServer(proxy.server);
    await closeServer(upstream.server);
  }
});

test('upstream timeout → proxy returns 504', async () => {
  const upstream = await startFakeUpstream((_req, _res) => {
    // never respond; let headersTimeout fire
  });
  const proxy = await startProxyFor(upstream.url, {
    headersTimeoutMs: 300,
    bodyTimeoutMs: 300,
  });
  try {
    const resp = await undiciRequest(`${proxy.url}/axios`);
    assert.equal(resp.statusCode, 504);
    const body = JSON.parse(await resp.body.text());
    assert.equal(body.error, 'upstream_timeout');
  } finally {
    await closeServer(proxy.server);
    await closeServer(upstream.server);
  }
});

test('Authorization header forwarded to upstream', async () => {
  let authHeader;
  const upstream = await startFakeUpstream((req, res) => {
    authHeader = req.headers.authorization;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
  });
  const proxy = await startProxyFor(upstream.url);
  try {
    await undiciRequest(`${proxy.url}/axios`, {
      headers: { authorization: 'Bearer token-xyz' },
    }).then((r) => r.body.text());
    assert.equal(authHeader, 'Bearer token-xyz');
  } finally {
    await closeServer(proxy.server);
    await closeServer(upstream.server);
  }
});

test('unknown route → 404', async () => {
  const upstream = await startFakeUpstream((_req, res) => {
    res.writeHead(500);
    res.end();
  });
  const proxy = await startProxyFor(upstream.url);
  try {
    const resp = await undiciRequest(`${proxy.url}/foo/bar/baz`);
    assert.equal(resp.statusCode, 404);
    const body = JSON.parse(await resp.body.text());
    assert.equal(body.error, 'not_found');
  } finally {
    await closeServer(proxy.server);
    await closeServer(upstream.server);
  }
});

test('non-GET method → 405', async () => {
  const upstream = await startFakeUpstream((_req, res) => {
    res.writeHead(200); res.end();
  });
  const proxy = await startProxyFor(upstream.url);
  try {
    const resp = await undiciRequest(`${proxy.url}/axios`, { method: 'POST' });
    assert.equal(resp.statusCode, 405);
    const body = JSON.parse(await resp.body.text());
    assert.equal(body.error, 'method_not_allowed');
  } finally {
    await closeServer(proxy.server);
    await closeServer(upstream.server);
  }
});
