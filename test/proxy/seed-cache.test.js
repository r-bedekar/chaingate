// Since 0.1.6: the seed cache in the proxy. With `seed_cache_url` set (on unless `"seed_cache": false`), the proxy reads the seed
// cache instead of a full seed. Before deciding a package whose bucket the cache does not hold, it fetches that bucket, waiting
// at most 5 seconds; past that the package is uncovered (the no-evidence choice decides) and the bucket keeps downloading for the
// next request. The root is refreshed at start and hourly; buckets a new root changes are fetched again. The bucket host here is
// a local server serving the seed lane's fixture unchanged. Written before the code.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateConfig, ConfigUnreadable, writeConfig, DEFAULT_POLICY, DEFAULT_SEED_CACHE_URL } from '../../config-store.js';
import { loadConfig } from '../../proxy/config.js';
import { createProxyServer } from '../../proxy/server.js';
import * as SH from '../../seed/v3/shards.js';
import { docFor, LIVE } from '../seed-v3/u05-fixtures.mjs';
import { fixtureRel, caPathOf } from '../helpers/shards-host.mjs';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'shards-1.0');
const EXPECTED = JSON.parse(fs.readFileSync(path.join(FIX, 'good', 'expected.json'), 'utf8'));
const SEED_KEY = crypto.createPublicKey(fs.readFileSync(path.join(FIX, 'good', 'fixture-seed-pub.pem')));
const NOW = Date.parse(EXPECTED.now);
const good = (rel) => fs.readFileSync(path.join(FIX, 'good', rel));
const ROOT = SH.verifyRoot({ rootBytes: good('root.json'), sig: good('root.json.sig'), keysBytes: good('keys.json'),
  keysSig: good('keys.json.sig'), seedKey: SEED_KEY, now: NOW, bits: 3 });

const listen = (srv) => new Promise((r) => srv.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${srv.address().port}`)));
const close = (srv) => new Promise((r) => srv.close(() => r()));
const get = (url) => new Promise((resolve, reject) => {
  http.get(url, { agent: false }, (res) => {
    let b = ''; res.setEncoding('utf8'); res.on('data', (x) => { b += x; });
    res.on('end', () => { let json = null; try { json = JSON.parse(b); } catch { /* not JSON */ } resolve({ status: res.statusCode, json }); });
  }).on('error', reject);
});

// ------------------------------------------------------------------------------------------------ configuration
test('SC1 seed_cache_url is an https base URL (the published host when unset); seed_cache is true or false', () => {
  assert.equal(DEFAULT_SEED_CACHE_URL, 'https://shards.cgsec.dev/');
  assert.deepEqual(validateConfig({}).seedCache, { url: DEFAULT_SEED_CACHE_URL, enabled: true });
  assert.deepEqual(validateConfig({ seed_cache_url: 'https://seed.example/shards/' }).seedCache, { url: 'https://seed.example/shards/', enabled: true });
  assert.deepEqual(validateConfig({ seed_cache_url: 'https://seed.example/shards/', seed_cache: false }).seedCache,
    { url: 'https://seed.example/shards/', enabled: false });
  for (const bad of [{ seed_cache_url: 'http://seed.example/' }, { seed_cache_url: 7 }, { seed_cache: 'yes' }]) {
    assert.throws(() => validateConfig(bad), ConfigUnreadable, JSON.stringify(bad));
  }
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'cg016-sc-'));
  try {
    writeConfig(path.join(home, 'config.json'), { policy: DEFAULT_POLICY, advisory_feed: false, seed_cache_url: 'https://seed.example/shards/' });
    const c = loadConfig({ CHAINGATE_HOME: home });
    assert.equal(c.seedCacheUrl, 'https://seed.example/shards/');
    assert.equal(c.seedCachePath, path.join(home, 'seed-cache', 'chaingate-seed.db'));
    assert.equal(c.seedV3Path, null, 'no cache yet and no bundle: nothing to read');
    writeConfig(path.join(home, 'config.json'), { policy: DEFAULT_POLICY, advisory_feed: false, seed_cache_url: 'https://seed.example/shards/', seed_cache: false });
    assert.equal(loadConfig({ CHAINGATE_HOME: home }).seedCacheUrl, null);
  } finally { fs.rmSync(home, { recursive: true, force: true }); }
});

test('SC2 a cache holding a bucket replaces the full seed: the proxy reads it, authenticated', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'cg016-sc-'));
  try {
    writeConfig(path.join(home, 'config.json'), { policy: DEFAULT_POLICY, advisory_feed: false, seed_cache_url: 'https://seed.example/shards/' });
    const cache = path.join(home, 'seed-cache', 'chaingate-seed.db');
    fs.mkdirSync(path.dirname(cache));
    SH.importBucket(cache, ROOT, 2, SH.verifyBucketBytes(ROOT, 2, good('buckets/00002.db.gz')));
    const c = loadConfig({ CHAINGATE_HOME: home });
    assert.equal(c.seedV3Path, cache); assert.equal(c.seedV3Trust, 'authenticated'); assert.equal(c.seedV3BundleId, null);
    assert.equal(c.policyOnUnusableInput, DEFAULT_POLICY.on_unusable_input);
  } finally { fs.rmSync(home, { recursive: true, force: true }); }
});

// ------------------------------------------------------------------------------------------------ the proxy
/** The bucket host (the fixture, or `down`: every request refused) and a registry with pkg-b's document. */
async function withProxy({ held = [0], down = false, slowMs = 0, waitMs = 5_000, missing = [] } = {}, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg016-scp-'));
  const cache = path.join(dir, 'chaingate-seed.db');
  for (const i of held) SH.importBucket(cache, ROOT, i, SH.verifyBucketBytes(ROOT, i, good(`buckets/${String(i).padStart(5, '0')}.db.gz`)));
  const seen = [];
  const host = http.createServer((req, res) => {
    const rel = decodeURIComponent(new URL(req.url, 'http://x').pathname.slice(1));
    seen.push(rel);
    if (down || missing.some((i) => rel === caPathOf(ROOT, i))) { res.writeHead(down ? 503 : 404); return res.end(); }
    let body; try { body = good(fixtureRel(rel)); } catch { res.writeHead(404); return res.end(); }
    setTimeout(() => { res.writeHead(200, { etag: `"${crypto.createHash('sha256').update(body).digest('hex').slice(0, 16)}"` }); res.end(body); },
      rel.startsWith('buckets/') ? slowMs : 0);
  });
  const docs = { 'pkg-b': docFor('pkg-b'), 'pkg-e': docFor('pkg-e') };
  const upstream = http.createServer((req, res) => {
    const url = decodeURIComponent(req.url).slice(1);
    if (url.includes('/-/')) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); return res.end('tarball-bytes'); }
    if (docs[url]) { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify(docs[url])); }
    res.writeHead(404, { 'content-type': 'application/json' }); return res.end('{}');
  });
  const hostUrl = `${await listen(host)}/`; const upstreamUrl = await listen(upstream);
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: upstreamUrl, witnessDbPath: path.join(dir, 'witness.db'),
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000, seedV3Path: cache, seedV3Trust: 'authenticated',
    policyOnUnusableInput: LIVE.on_unusable_input, policyOnNoEvidence: LIVE.on_no_evidence,
    seedCacheUrl: hostUrl, seedCachePath: cache, seedCacheKey: SEED_KEY, seedCacheBits: 3, seedCacheNow: () => NOW, seedCacheWaitMs: waitMs });
  const base = await listen(proxy);
  const realErr = console.error; console.error = () => {};
  try { return await fn({ base, proxy, seen, cache }); } finally {
    console.error = realErr; await close(proxy); await close(upstream); await close(host); fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('SC7 a proxy whose seed cache directory does not exist yet (started after `init --seed`): its first root refresh creates the cache', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg016-scp7-'));
  const cache = path.join(dir, 'seed-cache', 'chaingate-seed.db');
  const host = http.createServer((req, res) => {
    const rel = decodeURIComponent(new URL(req.url, 'http://x').pathname.slice(1));
    let body; try { body = good(fixtureRel(rel)); } catch { res.writeHead(404); return res.end(); }
    res.writeHead(200); res.end(body);
  });
  const upstream = http.createServer((req, res) => { res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}'); });
  const hostUrl = `${await listen(host)}/`; const upstreamUrl = await listen(upstream);
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: upstreamUrl, witnessDbPath: path.join(dir, 'witness.db'),
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000, seedCacheUrl: hostUrl, seedCachePath: cache, seedCacheKey: SEED_KEY,
    seedCacheBits: 3, seedCacheNow: () => NOW });
  const realErr = console.error; const logged = []; console.error = (...a) => { logged.push(a.join(' ')); };
  try {
    await listen(proxy);
    const r = await proxy.refreshSeedCache();
    assert.equal(r?.outcome, 'accepted', JSON.stringify({ r, logged }));
    assert.equal(fs.existsSync(cache), true);
    assert.ok(!logged.some((l) => /directory does not exist/.test(l)), logged.join('\n'));
  } finally {
    console.error = realErr; await close(proxy); await close(upstream); await close(host); fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('SC3 a package whose bucket the cache does not hold: the proxy fetches it before deciding, and the seed\'s pin BLOCKs', async () => {
  await withProxy({ held: [0] }, async ({ base, proxy, seen }) => {
    const pk = await get(`${base}/pkg-b`);
    assert.equal(pk.status, 200);
    assert.ok(!('1.1.0' in pk.json.versions), 'the version the seed pins is removed from the metadata npm sees');
    assert.ok(seen.includes(caPathOf(ROOT, 2)));
    assert.equal(proxy.seedCacheState().buckets_held, 2);
    const t = await get(`${base}/pkg-b/-/pkg-b-1.1.0.tgz`);
    assert.equal(t.status, 403);
  });
});

test('SC4 a bucket host that is down or slow: the decision waits at most the bound, the package is uncovered (WARN, served), and the bucket arrives for the next request', async () => {
  await withProxy({ held: [0], down: true, waitMs: 300 }, async ({ base, proxy }) => {
    const t0 = Date.now();
    const pk = await get(`${base}/pkg-b`);
    assert.ok(Date.now() - t0 < 4_000, 'no longer than the wait and the request itself');
    assert.equal(pk.status, 200); assert.ok('1.1.0' in pk.json.versions, 'uncovered warns; it does not block');
    assert.equal(proxy.seedCacheState().buckets_held, 1);
  });
  await withProxy({ held: [0], slowMs: 1_000, waitMs: 200 }, async ({ base, proxy }) => {
    const first = await get(`${base}/pkg-b`);
    assert.ok('1.1.0' in first.json.versions, 'decided before the slow bucket arrived');
    await proxy.seedCacheIdle();
    assert.equal(proxy.seedCacheState().buckets_held, 2, 'the bucket kept downloading');
    const again = await get(`${base}/pkg-b`);
    assert.ok(!('1.1.0' in again.json.versions), 'the next decision has the bucket and the pin');
  });
});

test('SC6 a bucket the host does not have (404): the proxy refreshes the root and asks once more; still missing, the package is uncovered (WARN, served)', async () => {
  await withProxy({ held: [0], missing: [2] }, async ({ base, proxy, seen }) => {
    await proxy.seedCacheIdle();
    const roots = seen.filter((r) => r === 'root.json.gz').length;
    const pk = await get(`${base}/pkg-b`);
    assert.equal(pk.status, 200); assert.ok('1.1.0' in pk.json.versions, 'uncovered warns; it does not block');
    await proxy.seedCacheIdle();
    assert.equal(seen.filter((r) => r === caPathOf(ROOT, 2)).length, 2, 'asked twice');
    assert.equal(seen.filter((r) => r === 'root.json.gz').length, roots + 1, 'the root refreshed once in between');
    assert.equal(proxy.seedCacheState().buckets_held, 1);
  });
});

test('SC5 the root refresh: a 304 changes nothing; the state names the root, its age and the last fetch', async () => {
  await withProxy({ held: [2] }, async ({ proxy, seen }) => {
    const r = await proxy.refreshSeedCache();
    assert.ok(['same', 'accepted'].includes(r.outcome), JSON.stringify(r));
    const r2 = await proxy.refreshSeedCache();
    assert.equal(r2.outcome, 'same');
    assert.equal(seen.filter((x) => x === 'root.json.gz').length, 2);
    const st = proxy.seedCacheState();
    assert.equal(st.root_cut_at, ROOT.cut_at); assert.equal(st.buckets_held, 1); assert.equal(st.last_fetch.outcome, 'same');
  });
});
