import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request as undiciRequest } from 'undici';

import { createProxyServer } from '../../proxy/server.js';

function tmpDbPath() {
  const dir = mkdtempSync(join(tmpdir(), 'chaingate-self-'));
  return { path: join(dir, 'witness.db'), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

async function startProxy(witnessDbPath) {
  const server = createProxyServer({
    port: 0,
    host: '127.0.0.1',
    upstream: 'http://127.0.0.1:1', // unused; self endpoint short-circuits before upstream
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

test('/_chaingate/self returns proxy identity', async () => {
  const db = tmpDbPath();
  const proxy = await startProxy(db.path);
  try {
    const resp = await undiciRequest(`${proxy.url}/_chaingate/self`);
    assert.equal(resp.statusCode, 200);
    const body = await resp.body.json();
    assert.equal(body.service, 'chaingate-proxy');
    assert.equal(typeof body.version, 'string');
    assert.equal(body.pid, process.pid);
  } finally {
    await close(proxy.server);
    db.cleanup();
  }
});
