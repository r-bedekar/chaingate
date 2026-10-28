// Redirects on the proxy's upstream requests (proxy/registry.js). Packuments and tarballs follow at most 2 redirects;
// past that the redirect response itself is returned. A redirect to another origin drops the user's `authorization`
// header; a redirect within the origin keeps it. The attestation fetch follows none. These hold on every undici the
// proxy has pinned (the request option in undici 6, the redirect interceptor in undici 7 and later).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { fetchPackument, fetchTarball, fetchAttestationBundle } from '../../proxy/registry.js';

const close = (s) => new Promise((resolve) => s.close(() => resolve()));

/** A loopback server; `route(req)` returns { status, headers, body }. Every request is logged. */
async function server(route) {
  const log = [];
  const s = http.createServer((req, res) => {
    log.push({ url: req.url, authorization: req.headers.authorization ?? null });
    const r = route(req);
    res.writeHead(r.status, { 'content-type': 'application/json', ...(r.headers ?? {}) });
    res.end(r.body ?? '');
  });
  await new Promise((resolve) => s.listen(0, '127.0.0.1', resolve));
  return { s, log, base: `http://127.0.0.1:${s.address().port}` };
}

const config = (upstream) => ({ upstream, headersTimeoutMs: 5_000, bodyTimeoutMs: 5_000 });
const DOC = JSON.stringify({ name: 'p', versions: {} });

test('a packument behind 1 or 2 same-origin redirects is followed and keeps the authorization header', async () => {
  const up = await server((req) => {
    if (req.url === '/p') return { status: 302, headers: { location: '/hop1' } };
    if (req.url === '/hop1') return { status: 301, headers: { location: '/final' } };
    if (req.url === '/final') return { status: 200, body: DOC };
    return { status: 404 };
  });
  try {
    const res = await fetchPackument('p', { config: config(up.base), requestHeaders: { authorization: 'Bearer t0k' } });
    assert.equal(res.statusCode, 200);
    assert.equal(await res.body.text(), DOC);
    assert.deepEqual(up.log.map((l) => l.url), ['/p', '/hop1', '/final']);
    assert.ok(up.log.every((l) => l.authorization === 'Bearer t0k'), 'same origin: the header is kept on every hop');
  } finally { await close(up.s); }
});

test('a third redirect is not followed: the redirect response itself is returned', async () => {
  const up = await server((req) => {
    const n = Number(req.url.match(/^\/hop(\d)$/)?.[1] ?? 0);
    return { status: 302, headers: { location: `/hop${n + 1}` } };
  });
  try {
    const res = await fetchTarball('p', 'p-1.0.0.tgz', { config: config(up.base) });
    await res.body.dump();
    assert.equal(res.statusCode, 302);
    assert.equal(res.headers.location, '/hop3');
    assert.deepEqual(up.log.map((l) => l.url), ['/p/-/p-1.0.0.tgz', '/hop1', '/hop2']);
  } finally { await close(up.s); }
});

test('a redirect to another origin is followed without the authorization header', async () => {
  const other = await server(() => ({ status: 200, body: DOC }));
  const up = await server(() => ({ status: 302, headers: { location: `${other.base}/moved` } }));
  try {
    const res = await fetchPackument('p', { config: config(up.base), requestHeaders: { authorization: 'Bearer t0k' } });
    assert.equal(res.statusCode, 200);
    assert.equal(await res.body.text(), DOC);
    assert.equal(up.log[0].authorization, 'Bearer t0k');
    assert.deepEqual(other.log, [{ url: '/moved', authorization: null }], 'the other origin never sees the header');
  } finally { await close(up.s); await close(other.s); }
});

test('the attestation fetch follows no redirect', async () => {
  const other = await server(() => ({ status: 200, body: '{}' }));
  const up = await server(() => ({ status: 302, headers: { location: `${other.base}/bundle` } }));
  try {
    const r = await fetchAttestationBundle('p', '1.0.0', { config: config(up.base), timeoutMs: 5_000, maxBytes: 1024 });
    assert.deepEqual(r, { ok: false, reason: 'HTTP 302' });
    assert.equal(up.log.length, 1);
    assert.equal(other.log.length, 0);
  } finally { await close(up.s); await close(other.s); }
});
