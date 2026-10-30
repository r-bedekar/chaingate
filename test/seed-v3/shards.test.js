// Since 0.1.6: seed shards 1.0 (contract 1.3 seeds split into buckets of packages under a signed root). The reader side of the
// contract's rules for opening a cache: the root verifies first (canonical bytes, a shards key named by a key list
// the seed key signs, valid at the reader's time, the signature over the root's sha256 hex), then each bucket only whole, in
// order: its size, its sha256, one gzip stream under raw_bytes_max, staged in a temporary database, its logical digest, read
// layout, bucket rule and lineage ids, then imported in one transaction. The fixture is the seed lane's signed toy set (per-run
// keys, public keys only; bucket_bits 3, so these tests pass bits 3 and production refuses anything but 14), loaded unchanged.
// Its second version carries the contract 1.3 lineage pair (tag family 0.3) and read-layout rows in bucket 3.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import * as SH from '../../seed/v3/shards.js';
import L from '../../seed/v3/logical.js';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'shards-1.0');
const sums = fs.readFileSync(path.join(FIX, 'SHA256SUMS'));
assert.equal(crypto.createHash('sha256').update(sums).digest('hex'), '24bf04ed18fe2a2b7ae11e354038921c0033a86db223be932874306bcf2e5c5d');
for (const line of sums.toString('ascii').trim().split('\n')) {
  const [h, f] = line.split(/\s+/);
  assert.equal(crypto.createHash('sha256').update(fs.readFileSync(path.join(FIX, f))).digest('hex'), h, `${f} is the seed lane's, unchanged`);
}
const EXPECTED = JSON.parse(fs.readFileSync(path.join(FIX, 'good', 'expected.json'), 'utf8'));
const CASES = JSON.parse(fs.readFileSync(path.join(FIX, 'cases', 'cases.json'), 'utf8'));
const SEED_KEY = crypto.createPublicKey(fs.readFileSync(path.join(FIX, 'good', 'fixture-seed-pub.pem')));
const NOW = Date.parse(EXPECTED.now);
// a case's file if it replaces it, else the good one
const fileOf = (c, rel) => fs.readFileSync(path.join(FIX, c && c.replaces.includes(rel) ? path.join('cases', c.name) : 'good', rel));
const rootOf = (c = null, now = NOW, bits = 3) => SH.verifyRoot({ rootBytes: fileOf(c, 'root.json'), sig: fileOf(c, 'root.json.sig'),
  keysBytes: fileOf(c, 'keys.json'), keysSig: fileOf(c, 'keys.json.sig'), seedKey: SEED_KEY, now, bits });
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'cg016-shards-'));

test('SH1 the good root verifies at the reader\'s time; the production path refuses any bucket_bits but 14', () => {
  const root = rootOf();
  assert.equal(root.shards_contract, 'cft-seed-v3-shards-1.0');
  assert.equal(root.seed_contract, 'cft-seed-v3-contract-1.3');
  assert.equal(root.signing_key_id, EXPECTED.signing_key_id);
  assert.equal(root.buckets.length, 8);
  assert.equal(SH.BUCKET_BITS, 14);
  assert.throws(() => rootOf(null, NOW, SH.BUCKET_BITS), (e) => e instanceof SH.ShardRefused && /bucket_bits/.test(e.message));
  for (const [name, i] of Object.entries(EXPECTED.bucket_of)) assert.equal(SH.bucketOf(name, 3), i, name);
  assert.equal(SH.bucketOf('pkg-a'), SH.bucketOf('pkg-a', 14));
  assert.ok(SH.bucketOf('pkg-a') < 16384);
});

test('SH2 every bucket verifies and imports whole; all eight give the full seed\'s logical digest; pins arrive by name', () => {
  const root = rootOf(); const dir = tmp(); const cache = path.join(dir, 'cache.db');
  try {
    for (let i = 0; i < 8; i += 1) {
      const raw = SH.verifyBucketBytes(root, i, fileOf(null, `buckets/${String(i).padStart(5, '0')}.db.gz`));
      SH.importBucket(cache, root, i, raw);
    }
    const db = new Database(cache, { readonly: true });
    try {
      assert.equal(L.logicalDigestOfDb(db), EXPECTED.seed_logical_digest);
      const pins = db.prepare('SELECT package_name, version FROM known_malicious_pins ORDER BY package_name').all().map((r) => [r.package_name, r.version]);
      assert.deepEqual(pins, EXPECTED.pins);
      assert.deepEqual(SH.cacheBuckets(db).map((b) => b.i), [0, 1, 2, 3, 4, 5, 6, 7]);
    } finally { db.close(); }
    // importing a bucket again replaces its rows: nothing doubles
    SH.importBucket(cache, root, 3, SH.verifyBucketBytes(root, 3, fileOf(null, 'buckets/00003.db.gz')));
    const again = new Database(cache, { readonly: true });
    try { assert.equal(L.logicalDigestOfDb(again), EXPECTED.seed_logical_digest); } finally { again.close(); }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

const WHY = {
  gz_sha256: /gz_sha256/, gz_bytes: /gz_bytes/, raw_bytes_max: /raw_bytes_max/, 'root signature': /root signature/,
  rl1_digest: /rl1_digest differs from the root/, canonical: /canonical/, 'key manifest signature': /key manifest signature/, 'shards key': /shards key/, 'valid at': /valid at/,
};
test('SH3 every refusal case of the fixture is refused, for its stated reason, and nothing of a refused bucket is imported', () => {
  assert.equal(CASES.length, 11);
  for (const c of CASES) {
    const re = Object.entries(WHY).find(([k]) => c.reason.startsWith(k))?.[1];
    assert.ok(re, `a pattern for ${c.reason}`);
    const at = Date.parse(c.at);
    const bucketCase = c.replaces.some((f) => f.startsWith('buckets/'));
    if (!bucketCase) { assert.throws(() => rootOf(c, at), (e) => e instanceof SH.ShardRefused && re.test(e.message), `${c.name}: ${c.reason}`); continue; }
    const root = rootOf(c, at); const dir = tmp(); const cache = path.join(dir, 'cache.db');
    try {
      SH.importBucket(cache, root, 0, SH.verifyBucketBytes(root, 0, fileOf(c, 'buckets/00000.db.gz')));
      const before = fs.readFileSync(cache);
      assert.throws(() => SH.importBucket(cache, root, 3, SH.verifyBucketBytes(root, 3, fileOf(c, 'buckets/00003.db.gz'))),
        (e) => e instanceof SH.ShardRefused && re.test(e.message), `${c.name}: ${c.reason}`);
      assert.ok(fs.readFileSync(cache).equals(before), `${c.name}: the cache is unchanged`);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  }
});

test('SH4 exactly one complete gzip stream: a second member, trailing bytes or a bad checksum are refused, even with a matching hash', () => {
  const raw = Buffer.from('x'.repeat(1000));
  const one = zlib.gzipSync(raw);
  const entry = (gz) => ({ shards_contract: 'cft-seed-v3-shards-1.0', raw_bytes_max: 4096,
    buckets: [{ i: 0, gz_bytes: gz.length, gz_sha256: crypto.createHash('sha256').update(gz).digest('hex') }] });
  assert.ok(SH.verifyBucketBytes(entry(one), 0, one).equals(raw));
  const two = Buffer.concat([one, zlib.gzipSync(Buffer.from('y'))]);
  assert.throws(() => SH.verifyBucketBytes(entry(two), 0, two), /one complete gzip stream/);
  const trail = Buffer.concat([one, Buffer.from([0])]);
  assert.throws(() => SH.verifyBucketBytes(entry(trail), 0, trail), /one complete gzip stream/);
  const badCrc = Buffer.from(one); badCrc[badCrc.length - 5] ^= 0xff;
  assert.throws(() => SH.verifyBucketBytes(entry(badCrc), 0, badCrc), /checksum/);
  const big = zlib.gzipSync(Buffer.alloc(5000));
  assert.throws(() => SH.verifyBucketBytes(entry(big), 0, big), /raw_bytes_max/);
  assert.throws(() => SH.verifyBucketBytes(entry(one), 1, one), /not listed/);
});

test('SH5 canonicalJson writes what Python json.dumps(sort_keys, compact, ensure_ascii=False) writes', () => {
  assert.equal(SH.canonicalJson({ b: 1, a: [null, true, 'x\u00e9\n"'], c: { z: 0, y: -2 } }), '{"a":[null,true,"x\u00e9\\n\\""],"b":1,"c":{"y":-2,"z":0}}');
  assert.throws(() => SH.canonicalJson({ a: 1.5 }), /integer/);
  assert.equal(SH.canonicalJson(JSON.parse(fileOf(null, 'root.json').toString('utf8'))), fileOf(null, 'root.json').toString('utf8'));
});

test('SH6 a newer root keeps the buckets it lists with the same logical digest and drops the others (their packages uncovered)', () => {
  const root = rootOf(); const dir = tmp(); const cache = path.join(dir, 'cache.db');
  try {
    for (let i = 0; i < 8; i += 1) SH.importBucket(cache, root, i, SH.verifyBucketBytes(root, i, fileOf(null, `buckets/${String(i).padStart(5, '0')}.db.gz`)));
    // setRoot takes a root already verified; a later one whose bucket 3 changed (only its digest matters here)
    const next = JSON.parse(JSON.stringify(root)); next.cut_at = '2026-10-30T12:00:00Z'; next.buckets[3].logical = 'f'.repeat(64);
    Object.defineProperty(next, 'digest', { value: 'e'.repeat(64) });
    assert.deepEqual(SH.setRoot(cache, next), { kept: 7, dropped: 1 });
    const db = new Database(cache, { readonly: true });
    try {
      assert.deepEqual(SH.cacheBuckets(db).map((b) => b.i), [0, 1, 2, 4, 5, 6, 7]);
      assert.ok(SH.cacheBuckets(db).every((b) => b.confirmed_cut_at === next.cut_at));
      const names = db.prepare('SELECT package_name FROM packages ORDER BY package_name').pluck().all();
      for (const n of ['pkg-a', 'pkg-d']) assert.ok(!names.includes(n), `${n} (bucket 3) is gone`);
      assert.ok(names.includes('pkg-b'));
      assert.deepEqual(db.prepare('SELECT package_name FROM known_malicious_pins').pluck().all(), ['pkg-b'], 'bucket 3\'s pin by name went with it');
    } finally { db.close(); }
    assert.throws(() => SH.setRoot(cache, root), /not later/, 'an older root grants nothing');
    assert.throws(() => SH.importBucket(cache, root, 3, SH.verifyBucketBytes(root, 3, fileOf(null, 'buckets/00003.db.gz'))), /another root/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// changed with the cache reads (shards-cache.test.js): a cache is opened on its stored root, not on a file digest
test('SH7 a cache with every bucket of one root is read by the 0.1.6 seed reader as a contract 1.3 seed', async () => {
  const R = (await import('../../seed/v3/reader.js')).default;
  const root = rootOf(); const dir = tmp(); const cache = path.join(dir, 'chaingate-seed.db');
  try {
    for (let i = 0; i < 8; i += 1) SH.importBucket(cache, root, i, SH.verifyBucketBytes(root, i, fileOf(null, `buckets/${String(i).padStart(5, '0')}.db.gz`)));
    const rep = R.verify(cache, { trust: R.TRUST_AUTHENTICATED, pubkey: SEED_KEY, shardBits: 3, now: () => NOW });
    assert.equal(rep.authenticated, true); assert.equal(rep.shard_cache.buckets_held, 8);
    assert.equal(rep.ok, true, JSON.stringify(Object.entries(rep.checks).filter(([, v]) => v !== true)));
    assert.equal(rep.meta.seed_contract_version, 'cft-seed-v3-contract-1.3');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
