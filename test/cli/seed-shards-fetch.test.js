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
import { fixtureRel, caPathOf, fixtureRoot } from '../helpers/shards-host.mjs';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'shards-1.0');
const EXPECTED = JSON.parse(fs.readFileSync(path.join(FIX, 'good', 'expected.json'), 'utf8'));
const CASES = JSON.parse(fs.readFileSync(path.join(FIX, 'cases', 'cases.json'), 'utf8'));
const SEED_KEY = crypto.createPublicKey(fs.readFileSync(path.join(FIX, 'good', 'fixture-seed-pub.pem')));
const NOW = Date.parse(EXPECTED.now);
const GOOD_ROOT = fixtureRoot(FIX);
const fileOf = (c, rel) => fs.readFileSync(path.join(FIX, c && c.replaces.includes(rel) ? path.join('cases', c.name) : 'good', rel));

/** A local server for the fixture (or one of its cases); `over` replaces a path's answer; every request is recorded. */
async function serve(fn, { c = null, over = {} } = {}) {
  const seen = [];
  const srv = http.createServer((req, res) => {
    const rel = decodeURIComponent(new URL(req.url, 'http://x').pathname.slice(1));
    seen.push({ rel, inm: req.headers['if-none-match'] ?? null, ua: req.headers['user-agent'] ?? null, auth: req.headers.authorization ?? null });
    if (over[rel]) return over[rel](req, res);
    let body;
    try { body = fileOf(c, fixtureRel(rel)); } catch { res.writeHead(404); return res.end(); }
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
      [...need.map((i) => caPathOf(GOOD_ROOT, i)), 'keys.json', 'keys.json.sig', 'root.json.gz', 'root.json.sig'].sort(),
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
    [caPathOf(GOOD_ROOT, 2)]: (req, res) => {
      res.writeHead(200);
      const tick = () => { if (sent >= big.length || res.destroyed) return res.end(); const n = Math.min(65536, big.length - sent); sent += n; res.write(big.subarray(sent - n, sent), tick); };
      tick();
    },
    [caPathOf(GOOD_ROOT, 4)]: (req, res) => { res.writeHead(503); res.end(); },
  };
  await serve(async ({ base, cache }) => {
    const get = F.shardSource(base);
    await F.refreshRoot({ get, cachePath: cache, ...opts() });
    const f = await F.fetchBuckets({ get, cachePath: cache, buckets: [2, 3, 4], ...opts() });
    assert.deepEqual(f.imported, [3]);
    assert.deepEqual(f.failed.map((x) => x.i), [2, 4]);
    assert.match(f.failed[0].why, /longer than its gz_bytes/); assert.match(f.failed[1].why, /HTTP 503/);
    assert.ok(sent > 0);
    const seed = open(cache);
    try { assert.equal(seed.report.shard_cache.buckets_held, 1); } finally { seed.close(); }
  }, { over });
});

test('SF5b the client stops reading a body past its cap: counted on the client, as the bytes it pulled', async () => {
  // a socket can take a whole small body before the client aborts, so the stop is measured on the client side
  // finite (4 MiB), so a client that ignored its cap would finish reading rather than read without end
  let pulled = 0; let cancelled = false;
  const body = new ReadableStream({
    pull(c) { if (pulled >= 4 * 1024 * 1024) { c.close(); return; } pulled += 65_536; c.enqueue(new Uint8Array(65_536)); },
    cancel() { cancelled = true; },
  }, { highWaterMark: 0 });
  const fetchImpl = async () => new Response(body, { status: 200 });
  const get = F.shardSource('http://127.0.0.1:9/', { fetchImpl });
  await assert.rejects(get('buckets/00002.db.gz', { cap: 200_000 }), /longer than 200000 bytes/);
  assert.ok(pulled <= 200_000 + 2 * 65_536, `pulled ${pulled} bytes for a cap of 200000`);
  assert.equal(cancelled, true, 'the body is cancelled');
});

test('SF6 the host is https (a local test host aside), and a redirect is refused', async () => {
  assert.throws(() => F.shardSource('http://example.com/shards/'), /https/);
  await serve(async ({ base, cache }) => {
    await assert.rejects(F.refreshRoot({ get: F.shardSource(base), cachePath: cache, ...opts() }), /redirect|fetch failed/i);
  }, { over: { 'root.json.gz': (req, res) => { res.writeHead(302, { location: 'https://example.com/root.json.gz' }); res.end(); } } });
});

test('SF7 setting up a cache: the root, the buckets the names need, and always at least one bucket (it brings the tables)', async () => {
  await serve(async ({ base, cache }) => {
    const r = await F.setUpSeedCache({ get: F.shardSource(base), cachePath: cache, names: ['pkg-b'], ...opts() });
    assert.equal(r.ok, true, JSON.stringify(r)); assert.equal(r.cut_at, EXPECTED.now); assert.deepEqual(r.held, [2]);
    assert.match(r.root_digest, /^[0-9a-f]{64}$/);
  });
  await serve(async ({ base, cache }) => {
    const r = await F.setUpSeedCache({ get: F.shardSource(base), cachePath: path.join(path.dirname(cache), 'sub', 'c.db'), names: [], ...opts() });
    assert.equal(r.ok, true); assert.deepEqual(r.held, [0], 'no names: one bucket all the same');
    const seed = R.openSeed(path.join(path.dirname(cache), 'sub', 'c.db'), { trust: R.TRUST_AUTHENTICATED, pubkey: SEED_KEY, shardBits: 3, now: () => NOW });
    seed.close();
  });
  await serve(async ({ base, cache }) => {
    const r = await F.setUpSeedCache({ get: F.shardSource(base), cachePath: cache, names: ['pkg-b'], ...opts() });
    assert.equal(r.ok, false); assert.match(r.why, /root\.json\.gz: HTTP 404/);
  }, { over: { 'root.json.gz': (req, res) => { res.writeHead(404); res.end(); } } });
});

test('SF8 the names a lockfile lists: package-lock or shrinkwrap, lockfile versions 1 to 3, nested and scoped; none is empty', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg016-lock-'));
  try {
    assert.deepEqual(F.lockfileNames(dir), []);
    fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: {
      '': { name: 'app' }, 'node_modules/a': {}, 'node_modules/@s/b': {}, 'node_modules/a/node_modules/c': {}, 'packages/local': {},
      'node_modules/linked': { link: true } } }));
    assert.deepEqual(F.lockfileNames(dir), ['@s/b', 'a', 'c', 'linked']);
    fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify({ lockfileVersion: 1, dependencies: {
      a: { version: '1.0.0', dependencies: { c: { version: '2.0.0' } } }, '@s/b': { version: '3.0.0' } } }));
    assert.deepEqual(F.lockfileNames(dir), ['@s/b', 'a', 'c']);
    fs.writeFileSync(path.join(dir, 'package-lock.json'), '{ not json');
    assert.deepEqual(F.lockfileNames(dir), []);
    fs.rmSync(path.join(dir, 'package-lock.json'));
    fs.writeFileSync(path.join(dir, 'npm-shrinkwrap.json'), JSON.stringify({ lockfileVersion: 2, packages: { 'node_modules/z': {} } }));
    assert.deepEqual(F.lockfileNames(dir), ['z']);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('SF9 what status and doctor say: off, none yet (a notice), held buckets and the root age, older than 48 hours or 7 days, a failed fetch', async () => {
  const H = 3600e3;
  assert.deepEqual(F.describeSeedCache({ url: null, cache: null }), { state: 'off', text: 'off (seed_cache is false)', notice: false });
  const none = F.describeSeedCache({ url: 'https://shards.example/', cache: null });
  assert.equal(none.state, 'none'); assert.equal(none.notice, true); assert.match(none.text, /no root fetched yet/);
  await serve(async ({ base, cache }) => {
    const r = await F.setUpSeedCache({ get: F.shardSource(base), cachePath: cache, names: ['pkg-b', 'pkg-e'], ...opts() });
    assert.equal(r.ok, true);
    const c = F.readSeedCache(cache);
    assert.deepEqual({ ...c, last_fetch: c.last_fetch.outcome }, { root_cut_at: EXPECTED.now, root_digest: r.root_digest, buckets_held: 2,
      buckets_total: 8, seed_version: EXPECTED.seed_version, notices_path: EXPECTED.notices_path, notices_sha256: EXPECTED.notices_sha256,
      last_fetch: 'accepted' });
    const notices = F.seedCacheNoticesUrl(base, c);
    const fresh = F.describeSeedCache({ url: base, cache: c, now: NOW + 2 * H });
    assert.equal(fresh.state, 'fresh'); assert.equal(fresh.notice, false);
    assert.equal(fresh.text, `root of ${EXPECTED.now}, seed ${EXPECTED.seed_version} (2 h old), 2 of 8 buckets held `
      + `(the others are fetched when a package needs them); third-party notices: ${notices}`);
    const untagged = F.describeSeedCache({ url: base, cache: { ...c, seed_version: null }, now: NOW + 2 * H });
    assert.equal(untagged.text, `root of ${EXPECTED.now} (2 h old), 2 of 8 buckets held `
      + `(the others are fetched when a package needs them); third-party notices: ${notices}`);
    // the root's seed_version (the published seed's tag) is shown beside cut_at; nothing decides on it
    const tagged = F.describeSeedCache({ url: base, cache: { ...c, seed_version: 'seed-v3.3-full' }, now: NOW + 2 * H });
    assert.equal(tagged.text, `root of ${EXPECTED.now}, seed seed-v3.3-full (2 h old), 2 of 8 buckets held (the others are fetched when a package needs them); `
      + `third-party notices: ${notices}`);
    assert.equal(tagged.state, 'fresh');
    const odd = F.describeSeedCache({ url: base, cache: { ...c, seed_version: 'x\u202ey\n' }, now: NOW + 2 * H });
    assert.equal(odd.text, untagged.text, 'a seed_version that is not a plain short tag is not shown');
    const old = F.describeSeedCache({ url: base, cache: c, now: NOW + 50 * H });
    assert.equal(old.state, 'old'); assert.equal(old.notice, true); assert.match(old.text, /older than 48 hours/);
    const stale = F.describeSeedCache({ url: base, cache: c, now: NOW + 8 * 24 * H });
    assert.equal(stale.state, 'stale'); assert.match(stale.text, /8 days old.*older than 7 days, stated on every decision/);
    const failed = F.describeSeedCache({ url: base, cache: { ...c, last_fetch: { outcome: 'failed', attempted_at: 'T', why: 'HTTP 503' } }, now: NOW + H });
    assert.equal(failed.notice, true); assert.match(failed.text, /last fetch failed at T: HTTP 503/);
  });
});

test('SF11 the third-party notices the root names: status and doctor show their address on the configured host; anything but a plain file name and a sha256 shows nothing', async () => {
  const H = 3600e3;
  await serve(async ({ base, cache }) => {
    const r = await F.setUpSeedCache({ get: F.shardSource(base), cachePath: cache, names: ['pkg-b'], ...opts() });
    assert.equal(r.ok, true);
    // the signed root, as the cutter wrote it, names the notices beside it by file name and sha256
    const c = F.readSeedCache(cache);
    assert.equal(c.notices_path, 'THIRD_PARTY_NOTICES.txt'); assert.equal(c.notices_sha256, EXPECTED.notices_sha256);
    assert.equal(crypto.createHash('sha256').update(fs.readFileSync(path.join(FIX, 'good', c.notices_path))).digest('hex'), c.notices_sha256);
    assert.equal(F.seedCacheNoticesUrl('https://shards.example', c), 'https://shards.example/THIRD_PARTY_NOTICES.txt');
    assert.equal(F.seedCacheNoticesUrl('https://h.example/seed/', c), 'https://h.example/seed/THIRD_PARTY_NOTICES.txt');
    assert.equal(F.seedCacheNoticesUrl(null, c), null, 'fetching off: no host to name');
    const d = F.describeSeedCache({ url: base, cache: c, now: NOW + 2 * H });
    assert.equal(d.state, 'fresh'); assert.equal(d.notice, false);
    assert.ok(d.text.endsWith(`; third-party notices: ${F.seedCacheNoticesUrl(base, c)}`), d.text);
    // status reads the cache file without verifying it; a root there naming anything else shows no notices
    const withRoot = (extra) => {
      const db = new Database(cache);
      try {
        const root = JSON.parse(db.prepare('SELECT root_json FROM shard_root WHERE id = 1').pluck().get());
        db.prepare('UPDATE shard_root SET root_json = ? WHERE id = 1').run(JSON.stringify({ ...root, ...extra }));
      } finally { db.close(); }
      return F.readSeedCache(cache);
    };
    const sha = EXPECTED.notices_sha256;
    for (const [extra, why] of [
      [{ notices_sha256: sha, notices_path: '../x.txt' }, 'a path'],
      [{ notices_sha256: sha, notices_path: 'https://elsewhere.example/n.txt' }, 'a URL'],
      [{ notices_sha256: sha, notices_path: 'N\u202e.txt' }, 'a control character'],
      [{ notices_sha256: sha.toUpperCase(), notices_path: 'THIRD_PARTY_NOTICES.txt' }, 'a sha256 that is not lower-case hex'],
      [{ notices_sha256: null, notices_path: 'THIRD_PARTY_NOTICES.txt' }, 'no sha256'],
      [{ notices_sha256: sha, notices_path: null }, 'no file name'],
    ]) {
      const o = withRoot(extra);
      assert.equal(o.notices_path, null, why); assert.equal(o.notices_sha256, null, why);
      assert.doesNotMatch(F.describeSeedCache({ url: base, cache: o, now: NOW + 2 * H }).text, /notices/, why);
    }
  });
});

test('SF12 a cache whose directory does not exist yet (a proxy after `init --seed`): the root refresh and a bucket fetch create it', async () => {
  await serve(async ({ base, dir }) => {
    const cachePath = path.join(dir, 'seed-cache', 'chaingate-seed.db');
    assert.equal(fs.existsSync(path.dirname(cachePath)), false);
    const get = F.shardSource(base);
    const r = await F.refreshRoot({ get, cachePath, ...opts() });
    assert.equal(r.outcome, 'accepted'); assert.equal(fs.existsSync(cachePath), true);
    const f = await F.fetchBuckets({ get, cachePath, buckets: [2], ...opts() });
    assert.deepEqual(f.imported, [2]); assert.deepEqual(f.failed, []);
    // a bucket imported before any root was held (the proxy's on-demand path) also finds its directory
    const other = path.join(dir, 'other', 'cache.db');
    SH.importBucket(other, GOOD_ROOT, 2, SH.verifyBucketBytes(GOOD_ROOT, 2, fileOf(null, 'buckets/00002.db.gz')));
    assert.equal(fs.existsSync(other), true);
  });
});

test('SF10 a bucket the host does not have (404): the root is refreshed and the bucket asked for once more under it; still missing, it is uncovered', async () => {
  const p2 = caPathOf(GOOD_ROOT, 2); const p4 = caPathOf(GOOD_ROOT, 4);
  // (a) the second request finds it (a root the host had just replaced, say)
  let n2 = 0;
  await serve(async ({ base, cache }) => {
    const get = F.shardSource(base);
    await F.refreshRoot({ get, cachePath: cache, ...opts() });
    let refreshed = 0;
    const f = await F.fetchBuckets({ get, cachePath: cache, buckets: [2, 3], ...opts(), refresh: async () => { refreshed += 1; return null; } });
    assert.deepEqual(f.imported, [2, 3]); assert.deepEqual(f.failed, []);
    assert.equal(refreshed, 1); assert.equal(n2, 2);
  }, { over: { [p2]: (req, res) => { n2 += 1; if (n2 === 1) { res.writeHead(404); return res.end(); } res.writeHead(200); return res.end(fileOf(null, 'buckets/00002.db.gz')); } } });
  // (b) still missing: one refresh for the whole call, each bucket asked twice, then listed as failed (uncovered)
  const asked = { [p2]: 0, [p4]: 0 };
  const gone = (p) => (req, res) => { asked[p] += 1; res.writeHead(404); res.end(); };
  await serve(async ({ base, cache }) => {
    const get = F.shardSource(base);
    await F.refreshRoot({ get, cachePath: cache, ...opts() });
    let refreshed = 0;
    const f = await F.fetchBuckets({ get, cachePath: cache, buckets: [2, 3, 4], ...opts(), refresh: async () => { refreshed += 1; return null; } });
    assert.deepEqual(f.imported, [3]); assert.deepEqual(f.failed.map((x) => x.i), [2, 4]);
    assert.match(f.failed[0].why, /HTTP 404/);
    assert.equal(refreshed, 1); assert.deepEqual(asked, { [p2]: 2, [p4]: 2 });
    // (c) with no refresh given (a caller that cannot refresh), a 404 is not asked again
    asked[p2] = 0;
    const g = await F.fetchBuckets({ get, cachePath: cache, buckets: [2], ...opts() });
    assert.deepEqual(g.failed.map((x) => x.i), [2]); assert.equal(asked[p2], 1);
  }, { over: { [p2]: gone(p2), [p4]: gone(p4) } });
  // (d) another failure (503) is not a missing bucket: no refresh, no second request
  let n5 = 0;
  await serve(async ({ base, cache }) => {
    const get = F.shardSource(base);
    await F.refreshRoot({ get, cachePath: cache, ...opts() });
    let refreshed = 0;
    const f = await F.fetchBuckets({ get, cachePath: cache, buckets: [2], ...opts(), refresh: async () => { refreshed += 1; return null; } });
    assert.deepEqual(f.failed.map((x) => x.i), [2]); assert.equal(refreshed, 0); assert.equal(n5, 1);
  }, { over: { [p2]: (req, res) => { n5 += 1; res.writeHead(503); res.end(); } } });
  // (e) init's setup refreshes the root itself (a 304 here) before asking again
  await serve(async ({ base, seen, cache }) => {
    const r = await F.setUpSeedCache({ get: F.shardSource(base), cachePath: cache, names: ['pkg-b'], ...opts() });
    assert.equal(r.ok, true); assert.deepEqual(r.failed.map((x) => x.i), [2]);
    assert.equal(seen.filter((s) => s.rel === 'root.json.gz').length, 2, 'the root once at setup, once after the 404');
    assert.equal(seen.filter((s) => s.rel === p2).length, 2);
  }, { over: { [p2]: (req, res) => { res.writeHead(404); res.end(); } } });
});
