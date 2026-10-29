// Since 0.1.6: fetching seed shards (a signed root and buckets of packages) into a seed cache. The root is fetched as
// root.json.gz with its ETag (a refresh with no new cut is a 304), decompressed as one gzip stream under the root bound, and
// accepted at the reader's clock with the key list beside it, which must equal the advisory feed's when that is known. A bucket
// download stops at the size the root names; each bucket is verified and imported whole, and one that fails leaves the others.
// The server here is a local one serving the seed lane's fixture unchanged. Written before the code.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import * as F from '../../cli/seed-shards.js';
import * as SH from '../../seed/v3/shards.js';
import R from '../../seed/v3/reader.js';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'shards-1.0');
const EXPECTED = JSON.parse(fs.readFileSync(path.join(FIX, 'good', 'expected.json'), 'utf8'));
const CASES = JSON.parse(fs.readFileSync(path.join(FIX, 'cases', 'cases.json'), 'utf8'));
const SEED_KEY = crypto.createPublicKey(fs.readFileSync(path.join(FIX, 'good', 'fixture-seed-pub.pem')));
const NOW = Date.parse(EXPECTED.now);
const fileOf = (c, rel) => fs.readFileSync(path.join(FIX, c && c.replaces.includes(rel) ? path.join('cases', c.name) : 'good', rel));

/** A local server for the fixture (or one of its cases); `over` replaces a path's answer; every request is recorded. */
async function serve(fn, { c = null, over = {} } = {}) {
  const seen = [];
  const srv = http.createServer((req, res) => {
    const rel = decodeURIComponent(new URL(req.url, 'http://x').pathname.slice(1));
    seen.push({ rel, inm: req.headers['if-none-match'] ?? null, ua: req.headers['user-agent'] ?? null, auth: req.headers.authorization ?? null });
    if (over[rel]) return over[rel](req, res);
    let body;
    try { body = fileOf(c, rel); } catch { res.writeHead(404); return res.end(); }
    // a case that replaces root.json alone is served as the gzip of its root.json, the bytes the client reads
    if (rel === 'root.json.gz' && c && c.replaces.includes('root.json') && !c.replaces.includes('root.json.gz')) body = zlib.gzipSync(fileOf(c, 'root.json'));
    const etag = `"${crypto.createHash('sha256').update(body).digest('hex').slice(0, 16)}"`;
    if (req.headers['if-none-match'] === etag) { res.writeHead(304, { etag }); return res.end(); }
    res.writeHead(200, { etag, 'content-length': body.length }); return res.end(body);
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg016-fetch-'));
  try {
    return await fn({ base: `http://127.0.0.1:${srv.address().port}/`, seen, cache: path.join(dir, 'chaingate-seed.db'), dir });
  } finally { srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
}
const opts = (extra = {}) => ({ seedKey: SEED_KEY, now: NOW, bits: 3, ...extra });
const open = (cache) => R.openSeed(cache, { trust: R.TRUST_AUTHENTICATED, pubkey: SEED_KEY, shardBits: 3, now: () => NOW });

test('SF1 a first refresh takes the root; the buckets of the named packages are fetched, verified and imported; nothing else is', async () => {
  await serve(async ({ base, seen, cache }) => {
    const get = F.shardSource(base);
    const r = await F.refreshRoot({ get, cachePath: cache, ...opts() });
    assert.deepEqual({ outcome: r.outcome, cut_at: r.cut_at, held: r.held }, { outcome: 'accepted', cut_at: EXPECTED.now, held: 0 });
    const need = F.bucketsFor(cache, ['pkg-b', 'pkg-e', 'pkg-b', 'not-in-the-seed-at-all'], { bits: 3 });
    assert.deepEqual(need, [...new Set([2, 4, SH.bucketOf('not-in-the-seed-at-all', 3)])].sort((a, b) => a - b));
    const f = await F.fetchBuckets({ get, cachePath: cache, buckets: need, ...opts() });
    assert.deepEqual(f.failed, []); assert.deepEqual(f.imported, need);
    const seed = open(cache);
    try {
      assert.equal(seed.report.shard_cache.buckets_held, need.length);
      assert.equal(seed.uncoveredReason('pkg-b'), null); assert.match(seed.uncoveredReason('pkg-a'), /bucket \(3\)/);
    } finally { seed.close(); }
    assert.deepEqual(F.bucketsFor(cache, ['pkg-b', 'pkg-e'], { bits: 3 }), [], 'held buckets are not fetched again');
    // plain requests: no identifiers, no registry token
    assert.ok(seen.every((s) => s.auth === null));
    assert.deepEqual(seen.map((s) => s.rel).sort(),
      [...need.map((i) => `buckets/${String(i).padStart(5, '0')}.db.gz`), 'keys.json', 'keys.json.sig', 'root.json.gz', 'root.json.sig'].sort(),
      'each file once');
  });
});

test('SF2 a refresh with no new cut is a 304 on root.json.gz and changes nothing', async () => {
  await serve(async ({ base, seen, cache }) => {
    const get = F.shardSource(base);
    await F.refreshRoot({ get, cachePath: cache, ...opts() });
    const before = seen.length;
    const r = await F.refreshRoot({ get, cachePath: cache, ...opts() });
    assert.equal(r.outcome, 'same');
    const after = seen.slice(before);
    assert.deepEqual(after.map((s) => s.rel), ['root.json.gz']);
    assert.match(after[0].inm ?? '', /^"[0-9a-f]{16}"$/);
  });
});

test('SF3 the root is accepted at the reader\'s clock: a shards key expired or not yet valid now is refused on download; nothing is stored', async () => {
  for (const c of CASES.filter((x) => x.name.startsWith('shards-key-'))) {
    await serve(async ({ base, cache }) => {
      await assert.rejects(F.refreshRoot({ get: F.shardSource(base), cachePath: cache, ...opts({ now: Date.parse(c.at) }) }),
        (e) => e instanceof SH.ShardRefused && /valid at/.test(e.message), c.name);
      if (fs.existsSync(cache)) {
        const db = new Database(cache, { readonly: true });
        try { assert.equal(db.prepare("SELECT count(*) FROM sqlite_master WHERE name = 'shard_root'").pluck().get(), 0, c.name); } finally { db.close(); }
      }
    }, { c });
  }
  // every root case of the fixture is refused through the fetch path too
  for (const c of CASES.filter((x) => !x.replaces.some((f) => f.startsWith('buckets/')) && !x.name.startsWith('shards-key-'))) {
    await serve(async ({ base, cache }) => {
      await assert.rejects(F.refreshRoot({ get: F.shardSource(base), cachePath: cache, ...opts() }), (e) => e instanceof SH.ShardRefused, c.name);
    }, { c });
  }
});

test('SF4 the key list beside the root must be the advisory feed\'s, byte for byte, when the feed\'s is known', async () => {
  await serve(async ({ base, cache }) => {
    const other = Buffer.concat([fileOf(null, 'keys.json'), Buffer.from(' ')]);
    await assert.rejects(F.refreshRoot({ get: F.shardSource(base), cachePath: cache, ...opts({ feedKeys: other }) }),
      (e) => e instanceof SH.ShardRefused && /key list beside the root differs from the advisory feed's/.test(e.message));
    const ok = await F.refreshRoot({ get: F.shardSource(base), cachePath: cache, ...opts({ feedKeys: fileOf(null, 'keys.json') }) });
    assert.equal(ok.outcome, 'accepted');
  });
});

test('SF5 a bucket download stops at the root\'s gz_bytes; a failed bucket is listed and the others are imported', async () => {
  const big = Buffer.alloc(4 * 1024 * 1024, 7); let sent = 0;
  const over = {
    'buckets/00002.db.gz': (req, res) => {
      res.writeHead(200);
      const tick = () => { if (sent >= big.length || res.destroyed) return res.end(); const n = Math.min(65536, big.length - sent); sent += n; res.write(big.subarray(sent - n, sent), tick); };
      tick();
    },
    'buckets/00004.db.gz': (req, res) => { res.writeHead(503); res.end(); },
  };
  await serve(async ({ base, cache }) => {
    const get = F.shardSource(base);
    await F.refreshRoot({ get, cachePath: cache, ...opts() });
    const f = await F.fetchBuckets({ get, cachePath: cache, buckets: [2, 3, 4], ...opts() });
    assert.deepEqual(f.imported, [3]);
    assert.deepEqual(f.failed.map((x) => x.i), [2, 4]);
    assert.match(f.failed[0].why, /longer than its gz_bytes/); assert.match(f.failed[1].why, /HTTP 503/);
    assert.ok(sent < big.length, `the download stopped early (${sent} of ${big.length} bytes sent)`);
    const seed = open(cache);
    try { assert.equal(seed.report.shard_cache.buckets_held, 1); } finally { seed.close(); }
  }, { over });
});

test('SF6 the host is https (a local test host aside), and a redirect is refused', async () => {
  assert.throws(() => F.shardSource('http://example.com/shards/'), /https/);
  await serve(async ({ base, cache }) => {
    await assert.rejects(F.refreshRoot({ get: F.shardSource(base), cachePath: cache, ...opts() }), /redirect|fetch failed/i);
  }, { over: { 'root.json.gz': (req, res) => { res.writeHead(302, { location: 'https://example.com/root.json.gz' }); res.end(); } } });
});
