// Since 0.1.6: reading a seed cache (seed shards 1.0) that holds only some buckets of one root.
// The cache opens on its stored root: the key list the seed key signs, the shards key in it valid at the root's cut, the
// root's signature, its metadata and every held bucket listed with the same logical digest. A held bucket's rows are re-hashed
// the first time a lookup touches it. A package whose bucket is not held is uncovered, never clean: no history and no recorded
// advisory are checked (the pins feed still is), and the no-evidence choice decides. A package absent from a held bucket is not
// in the seed, as with a full seed. A root older than 7 days is stated on every decision. Written before the code.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import * as SH from '../../seed/v3/shards.js';
import R from '../../seed/v3/reader.js';
import G from '../../seed/v3/gate.js';
import POL from '../../seed/v3/policy.js';
import { inputFromPackument } from '../../cli/check-record.js';
import { docFor, LIVE } from './u05-fixtures.mjs';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'shards-1.0');
const EXPECTED = JSON.parse(fs.readFileSync(path.join(FIX, 'good', 'expected.json'), 'utf8'));
const SEED_KEY = crypto.createPublicKey(fs.readFileSync(path.join(FIX, 'good', 'fixture-seed-pub.pem')));
const NOW = Date.parse(EXPECTED.now);
const D = 24 * 3600e3;
const good = (rel) => fs.readFileSync(path.join(FIX, 'good', rel));
const ROOT = SH.verifyRoot({ rootBytes: good('root.json'), sig: good('root.json.sig'), keysBytes: good('keys.json'),
  keysSig: good('keys.json.sig'), seedKey: SEED_KEY, now: NOW, bits: 3 });

function withCache(buckets, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg016-cache-')); const cache = path.join(dir, 'chaingate-seed.db');
  try {
    for (const i of buckets) SH.importBucket(cache, ROOT, i, SH.verifyBucketBytes(ROOT, i, good(`buckets/${String(i).padStart(5, '0')}.db.gz`)));
    return fn(cache, dir);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
const open = (cache, over = {}) => R.openSeed(cache, { trust: R.TRUST_AUTHENTICATED, pubkey: SEED_KEY, shardBits: 3, now: () => NOW, ...over });
const evalOf = (seed, name, version, opts = {}) => G.evaluateCandidate(seed, { config: LIVE, domainVersionCount: 'from-packument', ...opts },
  inputFromPackument(docFor(name, [[version, '2026-10-20T00:00:00.000Z']]), name, version));
const rowOf = (dec, gate) => dec.results.find((x) => x.gate === gate);
// a name the seed does not hold whose bucket is `i`
const absentIn = (i) => { for (let n = 0; ; n += 1) if (SH.bucketOf(`zz-absent-${n}`, 3) === i) return `zz-absent-${n}`; };

test('CC1 a cache holding some buckets opens on its stored root, authenticated by the seed key, with no file signature', () => {
  withCache([2, 3], (cache) => {
    assert.ok(!fs.existsSync(`${cache}.sig`) && !fs.existsSync(`${cache}.sha256`));
    const seed = open(cache);
    try {
      assert.equal(seed.report.authenticated, true);
      assert.equal(seed.meta.seed_contract_version, 'cft-seed-v3-contract-1.3');
      assert.deepEqual({ ...seed.report.shard_cache, root_digest: null },
        { root_cut_at: ROOT.cut_at, root_digest: null, buckets_held: 2, buckets_total: 8, root_age_days: 0 });
      assert.equal(seed.report.shard_cache.root_digest, ROOT.digest);
    } finally { seed.close(); }
    // another seed key: the key list does not verify
    const other = crypto.generateKeyPairSync('ed25519').publicKey;
    assert.throws(() => open(cache, { pubkey: other }), (e) => e instanceof R.SeedRefused && /shard_root/.test(e.message) && /seed key/.test(e.message));
    // the production reader reads 14 bits only
    assert.throws(() => open(cache, { shardBits: undefined }), (e) => e instanceof R.SeedRefused && /bucket_bits/.test(e.message));
  });
});

test('CC2 a changed stored root, metadata that is not the root\'s, or a held bucket the root does not list refuse the cache', () => {
  const variants = {
    'root bytes': (db) => db.prepare("UPDATE shard_root SET root_json = replace(root_json, '\"pin_count\":2', '\"pin_count\":3')").run(),
    'no proof': (db) => db.prepare('UPDATE shard_root SET root_sig = NULL').run(),
    metadata: (db) => db.prepare("UPDATE seed_metadata SET value = 'x' WHERE key = 'corpus_snapshot_id'").run(),
    'bucket digest': (db) => db.prepare("UPDATE shard_buckets SET logical = ? WHERE i = 3").run('0'.repeat(64)),
  };
  for (const [name, change] of Object.entries(variants)) {
    withCache([2, 3], (cache) => {
      const db = new Database(cache); try { change(db); } finally { db.close(); }
      assert.throws(() => open(cache), (e) => e instanceof R.SeedRefused && /shard_root/.test(e.message), name);
    });
  }
});

test('CC3 lookups: a held package reads as the full cache does; absent from a held bucket is not in the seed; an unheld bucket is uncovered', () => {
  withCache([0, 1, 2, 3, 4, 5, 6, 7], (fullPath) => withCache([2, 3], (cache) => {
    const full = open(fullPath); const part = open(cache);
    try {
      for (const [name, v] of [['pkg-b', '1.1.0'], ['pkg-a', '2.3.0'], ['pkg-d', '2.0.0']]) {
        assert.deepEqual(G.resolvePlacement(part, name, v, 1767225600), G.resolvePlacement(full, name, v, 1767225600), name);
      }
      assert.equal(POL.lookupPin(part, 'pkg-b', '1.1.0').pin.origin, 'seed');
      assert.equal(POL.lookupPin(part, 'pkg-gone', '6.6.6').pin.origin, 'seed', 'a pin for a package the seed does not represent');
      const absent = G.resolvePlacement(part, absentIn(2), '1.0.0', 1767225600);
      assert.equal(absent.kind, G.PLACEMENTS.UNCOVERED_PACKAGE); assert.equal(absent.reason, 'the seed does not cover this package');
      const p = POL.lookupPin(part, absentIn(3), '1.0.0'); assert.equal(p.pin, null); assert.equal(p.error, null); assert.equal(p.uncovered, undefined);
      const unheld = G.resolvePlacement(part, 'pkg-e', '1.0.0', 1767225600);
      assert.equal(unheld.kind, G.PLACEMENTS.UNCOVERED_PACKAGE);
      assert.match(unheld.reason, /seed cache does not hold this package's bucket \(4\)/);
      const up = POL.lookupPin(part, 'pkg-e', '1.0.0');
      assert.equal(up.pin, null); assert.equal(up.error, null); assert.match(up.uncovered, /bucket \(4\)/);
    } finally { full.close(); part.close(); }
  }));
  // a pinned version whose bucket is not held: no seed answer, but the pins feed is still read
  withCache([0, 4], (cache) => {
    const seed = open(cache);
    try {
      const none = POL.lookupPin(seed, 'pkg-b', '1.1.0');
      assert.equal(none.pin, null); assert.match(none.uncovered, /bucket \(2\)/);
      const feed = POL.lookupPin(seed, 'pkg-b', '1.1.0', () => ({ advisory_id: 'MAL-X', source: 'osv', feed_cut_at: '2026-10-29T11:00:00Z' }));
      assert.equal(feed.pin.origin, 'feed');
    } finally { seed.close(); }
  });
});

test('CC4 through the gate: an unheld bucket is never clean; the no-evidence choice decides; a held pin or a feed pin BLOCKs', () => {
  withCache([0, 4], (cache) => {
    const seed = open(cache);
    try {
      const out = evalOf(seed, 'pkg-b', '1.1.0');
      assert.equal(out.decision.disposition, 'WARN');
      assert.equal(out.decision.evidence_complete, false);
      assert.match(rowOf(out.decision, POL.PIN_GATE).detail, /^not checked: the seed cache does not hold this package's bucket \(2\)/);
      assert.equal(rowOf(out.decision, POL.PIN_GATE).result, 'SKIP');
      const cov = out.decision.results.filter((x) => x.gate === 'seed-v3:coverage' && x.result === 'WARN');
      assert.equal(cov.length, 1); assert.match(cov[0].detail, /bucket \(2\)/);
      assert.ok(out.decision.not_evaluated.some((m) => m.name === 'pin' && /bucket \(2\)/.test(m.reason)));
      // the operator's explicit fail-open still says what was not checked
      const open2 = evalOf(seed, 'pkg-b', '1.1.0', { config: { ...LIVE, on_no_evidence: 'ALLOW' } });
      assert.equal(open2.decision.disposition, 'ALLOW'); assert.equal(open2.decision.evidence_complete, false);
      const feed = evalOf(seed, 'pkg-b', '1.1.0', { pinOverlay: (n, v) => (n === 'pkg-b' && v === '1.1.0'
        ? { advisory_id: 'MAL-X', source: 'osv', feed_cut_at: '2026-10-29T11:00:00Z' } : null) });
      assert.equal(feed.decision.disposition, 'BLOCK');
    } finally { seed.close(); }
  });
  withCache([2], (cache) => {
    const seed = open(cache);
    try { assert.equal(evalOf(seed, 'pkg-b', '1.1.0').decision.disposition, 'BLOCK'); } finally { seed.close(); }
  });
});

test('CC5 a held bucket whose rows changed after import is refused at its first lookup; other buckets still answer', () => {
  withCache([2, 3], (cache) => {
    const db = new Database(cache);
    try {
      db.prepare("UPDATE spine SET version = version || '-x' WHERE lineage_id IN (SELECT l.id FROM lineages l JOIN packages p ON p.id = l.package_id WHERE p.package_name = 'pkg-d')").run();
    } finally { db.close(); }
    const seed = open(cache);
    try {
      const out = evalOf(seed, 'pkg-a', '1.0.0');
      assert.equal(out.decision.disposition, 'BLOCK', 'LIVE: an unusable input blocks');
      assert.match(rowOf(out.decision, 'seed-v3:input').detail, /bucket 3: its rows no longer match the root/);
      const pin = POL.lookupPin(seed, 'pkg-gone', '6.6.6');
      assert.equal(pin.pin, null); assert.match(pin.error.message, /bucket 3/);
      assert.equal(evalOf(seed, 'pkg-b', '1.1.0').decision.disposition, 'BLOCK');
      assert.equal(POL.lookupPin(seed, 'pkg-b', '1.1.0').pin.origin, 'seed', 'bucket 2 is sound');
    } finally { seed.close(); }
  });
});

test('CC6 a root older than 7 days is stated on every decision; a younger one is not', () => {
  withCache([2], (cache) => {
    const old = open(cache, { now: () => NOW + 8 * D });
    try {
      assert.equal(old.report.shard_cache.root_age_days, 8);
      for (const [n, v] of [['pkg-b', '1.1.0'], ['pkg-e', '1.0.0']]) {
        const rows = evalOf(old, n, v).decision.results.filter((x) => x.gate === 'seed-v3:coverage' && /seed cache's root was cut 2026-10-29T12:00:00Z, 8 days ago/.test(x.detail));
        assert.equal(rows.length, 1, n); assert.equal(rows[0].result, 'SKIP');
      }
    } finally { old.close(); }
    const young = open(cache, { now: () => NOW + 2 * D });
    try {
      assert.ok(!evalOf(young, 'pkg-b', '1.1.0').decision.results.some((x) => /seed cache's root was cut/.test(x.detail)));
    } finally { young.close(); }
  });
});
