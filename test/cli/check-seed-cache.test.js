// `chaingate check` on a seed cache: a package whose bucket the cache does not hold is fetched first, waiting at most the
// proxy's bound, so one seed answers in the proxy and in `check`; a host that is down leaves the package uncovered (WARN), as
// before; a held bucket is not asked for again.

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeConfig, DEFAULT_POLICY } from '../../config-store.js';
import { runCheck } from '../../cli/commands/check.js';
import { shardSource } from '../../cli/seed-shards.js';
import * as SH from '../../seed/v3/shards.js';
import { docFor } from '../seed-v3/u05-fixtures.mjs';
import { fixtureRel, caPathOf } from '../helpers/shards-host.mjs';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'shards-1.0');
const EXPECTED = JSON.parse(fs.readFileSync(path.join(FIX, 'good', 'expected.json'), 'utf8'));
const SEED_KEY = crypto.createPublicKey(fs.readFileSync(path.join(FIX, 'good', 'fixture-seed-pub.pem')));
const NOW = Date.parse(EXPECTED.now);
const good = (rel) => fs.readFileSync(path.join(FIX, 'good', rel));
const ROOT = SH.verifyRoot({ rootBytes: good('root.json'), sig: good('root.json.sig'), keysBytes: good('keys.json'),
  keysSig: good('keys.json.sig'), seedKey: SEED_KEY, now: NOW, bits: 3 });
const listen = (srv) => new Promise((r) => srv.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${srv.address().port}/`)));
const close = (srv) => new Promise((r) => srv.close(() => r()));

/** A scope home whose seed is a cache holding `held`, served by a local host (`down`: every request 503). */
async function withHome({ held = [0], down = false }, fn) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'cg016-chk-'));
  const base = path.join(home, '.chaingate');
  writeConfig(path.join(base, 'config.json'), { policy: DEFAULT_POLICY, advisory_feed: false, seed_cache_url: 'https://seed.example/shards/' });
  const cache = path.join(base, 'seed-cache', 'chaingate-seed.db');
  for (const i of held) SH.importBucket(cache, ROOT, i, SH.verifyBucketBytes(ROOT, i, good(`buckets/${String(i).padStart(5, '0')}.db.gz`)));
  const seen = [];
  const host = http.createServer((req, res) => {
    const rel = decodeURIComponent(new URL(req.url, 'http://x').pathname.slice(1));
    seen.push(rel);
    if (down) { res.writeHead(503); return res.end(); }
    let body; try { body = good(fixtureRel(rel)); } catch { res.writeHead(404); return res.end(); }
    res.writeHead(200); return res.end(body);
  });
  const hostUrl = await listen(host);
  const packument = path.join(home, 'pkg-b.json');
  fs.writeFileSync(packument, JSON.stringify(docFor('pkg-b')));
  const check = (extra = {}) => runCheck({ name: 'pkg-b', version: '1.1.0', packument, env: { HOME: home, CHAINGATE_HOME: base }, cwd: home,
    seams: { seedKey: SEED_KEY, shardBits: 3, now: () => NOW, get: shardSource(hostUrl), ...extra } });
  try { return await fn({ check, seen, cache }); } finally { await close(host); fs.rmSync(home, { recursive: true, force: true }); }
}

test('CK1 a package whose bucket the cache does not hold: check fetches the bucket first and the seed\'s pin BLOCKs', async () => {
  await withHome({ held: [0] }, async ({ check, seen }) => {
    const { record, exit } = await check();
    assert.deepEqual(seen, [caPathOf(ROOT, 2)], 'only the bucket of pkg-b is asked for');
    assert.equal(record.result, 'evaluated', JSON.stringify(record.error ?? null));
    assert.equal(record.effective.action, 'BLOCK');
    assert.notEqual(exit, 0);
    // held now: the next check asks for nothing
    seen.length = 0;
    const again = await check();
    assert.deepEqual(seen, []); assert.equal(again.record.effective.action, 'BLOCK');
  });
});

test('CK2 a host that is down: check waits at most the bound, and the package is not checked by the seed (WARN), as before', async () => {
  await withHome({ held: [0], down: true }, async ({ check, seen }) => {
    const t0 = Date.now();
    const { record } = await check({ waitMs: 300 });
    assert.ok(Date.now() - t0 < 4_000);
    assert.ok(seen.includes(caPathOf(ROOT, 2)));
    assert.equal(record.effective.action, 'WARN');
    assert.match(record.explanation.text.join('\n'), /does not hold this package's bucket/);
  });
});

test('CK3 a package whose bucket is held: check makes no request', async () => {
  await withHome({ held: [0, 2] }, async ({ check, seen }) => {
    const { record } = await check();
    assert.deepEqual(seen, []); assert.equal(record.effective.action, 'BLOCK');
  });
});
