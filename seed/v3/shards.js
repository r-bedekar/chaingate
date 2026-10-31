// Since 0.1.6: seed shards 1.0 (cft-seed-v3-shards-1.0), the reader side. A contract 1.3 seed is published as buckets of
// packages (the first 14 bits of sha256 of the package name) under a signed root that names each bucket by its logical digest,
// its gzip sha256 and size, with a decompression bound. Ported by hand from the seed side (chaingate-ops tools/seedgen/shards.py:
// bucket_of, verify_bucket, assemble; the root signature rule of verify_root) and the contract text's rules for opening a cache.
//
// Trust comes only from the root: a key list the seed key signs names the shards key, valid at the reader's time, and that key
// signs the sha256 hex of the canonical root bytes. A bucket is checked before anything of it is decompressed or opened (size,
// then sha256 against the root), decompressed under the root's bound as exactly one gzip stream, staged in a temporary database,
// re-hashed to its logical digest with the bucket rule and the lineage ids checked, and only then imported, whole, in one
// transaction. The cache holds one current root; a bucket is valid only while that root lists its logical digest.
import crypto, { verify as cryptoVerify } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import Database from 'better-sqlite3';
import L from './logical.js';
import RL from './read-layout.js';
import { verifyKeyManifest, PinsFeedRefused } from '../../witness/pins-feed.js';

export const SHARDS_CONTRACT = 'cft-seed-v3-shards-1.0';
export const SHARD_SEED_CONTRACT = 'cft-seed-v3-contract-1.3';
export const SHARD_LINEAGE_ID_RULE = 'pkg4096-1';
export const BUCKET_BITS = 14;
export const BUCKET_HASH = 'sha256-prefix';
export const SHARD_LIMITS = Object.freeze({ rootBytes: 32 * 1024 * 1024, bucketGzBytes: 64 * 1024 * 1024, rawBytesMax: 256 * 1024 * 1024 });
const LINEAGE_STRIDE = 4096;
// the relations a bucket carries (writer TABLES_IN_DIGEST without seed_metadata), then its read-layout rows
const BUCKET_TABLES = L.TABLES_IN_DIGEST.filter((t) => t !== 'seed_metadata');
const PACKAGE_COL = { packages: 'id', lineages: 'package_id', dep_names: 'package_id', [RL.RL1_TABLE]: 'package_id' };
const LINEAGE_KEYED = ['lineage_state', 'spine', 'cross_links', 'events'];
const DIGEST_ORDER = { ...L.ORDER, [RL.RL1_TABLE]: 'package_id' };
const HEX64 = /^[0-9a-f]{64}$/;
const TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const KEY_ID = /^ed25519:[0-9a-f]{16}$/;

export class ShardRefused extends Error {
  constructor(why) { super(why); this.name = 'ShardRefused'; this.why = why; }
}
const refuse = (why) => { throw new ShardRefused(why); };
const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const isCount = (x) => Number.isInteger(x) && x >= 0;
const sha256Hex = (b) => crypto.createHash('sha256').update(b).digest('hex');

/** The bucket of a package name: the first `bits` bits of sha256(utf8(name)). */
export function bucketOf(name, bits = BUCKET_BITS) {
  const d = crypto.createHash('sha256').update(String(name), 'utf8').digest();
  return d.readUInt16BE(0) >> (16 - bits);
}

/** JSON as Python's json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False) writes it; integers only. */
export function canonicalJson(o) {
  if (o === null || typeof o === 'boolean' || typeof o === 'string') return JSON.stringify(o);
  if (typeof o === 'number') {
    if (!Number.isSafeInteger(o)) throw new TypeError(`canonical JSON carries an integer only, got ${o}`);
    return String(o);
  }
  if (Array.isArray(o)) return `[${o.map(canonicalJson).join(',')}]`;
  if (isObj(o)) return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(',')}}`;
  throw new TypeError(`canonical JSON cannot carry ${typeof o}`);
}

function checkFields(root, bits) {
  if (root.shards_contract !== SHARDS_CONTRACT) refuse(`the root is not ${SHARDS_CONTRACT} (${JSON.stringify(root.shards_contract)})`);
  if (root.seed_contract !== SHARD_SEED_CONTRACT) refuse(`the root's seed contract is not ${SHARD_SEED_CONTRACT}`);
  if (root.lineage_id_rule !== SHARD_LINEAGE_ID_RULE) refuse(`the root's lineage_id_rule is not ${SHARD_LINEAGE_ID_RULE}`);
  if (root.bucket_hash !== BUCKET_HASH) refuse(`the root's bucket_hash is not ${BUCKET_HASH}`);
  if (root.bucket_bits !== bits) refuse(`the root's bucket_bits is ${JSON.stringify(root.bucket_bits)}; this reader reads ${bits}`);
  if (!TS.test(root.cut_at ?? '')) refuse('the root has no cut_at');
  if (!(Number.isInteger(root.raw_bytes_max) && root.raw_bytes_max > 0 && root.raw_bytes_max <= SHARD_LIMITS.rawBytesMax)) {
    refuse('the root declares no usable raw_bytes_max');
  }
  if (!HEX64.test(root.seed_logical_digest ?? '')) refuse('the root has no seed_logical_digest');
  const m = root.seed_metadata;
  if (!isObj(m) || !Object.values(m).every((v) => typeof v === 'string')) refuse('the root\'s seed_metadata is not a set of strings');
  if (m.contract_version !== root.seed_contract || m.lineage_id_rule !== root.lineage_id_rule) refuse('the root\'s seed_metadata disagrees with the root');
  const n = 2 ** bits;
  if (!Array.isArray(root.buckets) || root.buckets.length !== n) refuse(`the root does not list ${n} buckets`);
  root.buckets.forEach((b, i) => {
    const ok = isObj(b) && b.i === i && HEX64.test(b.logical ?? '') && HEX64.test(b.gz_sha256 ?? '')
      && Number.isInteger(b.gz_bytes) && b.gz_bytes > 0 && b.gz_bytes <= SHARD_LIMITS.bucketGzBytes
      && isCount(b.packages) && isCount(b.pins) && (b.rl1_digest === null || HEX64.test(b.rl1_digest ?? ''));
    if (!ok) refuse(`the root's entry for bucket ${i} is malformed`);
  });
}

/**
 * The root, verified first. Returns the root object, with `digest` (sha256 hex of its bytes) beside it.
 * `bits` is BUCKET_BITS in production; the seed lane's toy fixture uses 3.
 */
export function verifyRoot({ rootBytes, sig, keysBytes, keysSig, seedKey, now = Date.now(), bits = BUCKET_BITS }) {
  if (!Buffer.isBuffer(rootBytes) || rootBytes.length > SHARD_LIMITS.rootBytes) refuse('the root is missing or too large');
  if (!Buffer.isBuffer(sig) || sig.length !== 64) refuse('the root signature is not 64 bytes');
  const text = rootBytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(rootBytes)) refuse('the root is not UTF-8');
  let root;
  try { root = JSON.parse(text); } catch { refuse('the root is not JSON'); }
  if (!isObj(root)) refuse('the root is not a JSON object');
  let canon;
  try { canon = canonicalJson(root); } catch (e) { refuse(`the root is not canonical JSON (${e.message})`); }
  if (canon !== text) refuse('the root is not canonical JSON');
  let keys;
  try { keys = verifyKeyManifest(keysBytes, keysSig, { seedKey, role: 'shards' }); } catch (e) {
    if (e instanceof PinsFeedRefused) refuse(e.why);
    throw e;
  }
  if (!KEY_ID.test(root.signing_key_id ?? '')) refuse('the root names no signing key');
  const key = keys.find((k) => k.key_id === root.signing_key_id);
  if (!key) refuse(`the root's signing key ${root.signing_key_id} is not a shards key in the key list`);
  if (!(key.from <= now && now < key.to)) refuse(`shards key ${key.key_id} is not valid at ${new Date(now).toISOString()}`);
  const digest = sha256Hex(rootBytes);
  if (!cryptoVerify(null, Buffer.from(digest, 'ascii'), key.key, sig)) refuse('the root signature does not verify');
  checkFields(root, bits);
  Object.defineProperty(root, 'digest', { value: digest, enumerable: false });
  // what proves it, kept with the root in a cache so the cache is checked again each time it is opened
  Object.defineProperty(root, 'proof', { value: { rootBytes, sig, keysBytes, keysSig }, enumerable: false });
  return root;
}

/** Exactly one complete gzip member, decompressed to at most `cap` bytes, its CRC32 and size checked. */
function gunzipOne(gz, cap, at) {
  if (gz.length < 18 || gz[0] !== 0x1f || gz[1] !== 0x8b || gz[2] !== 8) refuse(`${at}: not one complete gzip stream (header)`);
  const flg = gz[3];
  if (flg & 0xe0) refuse(`${at}: not one complete gzip stream (reserved flags)`);
  let p = 10;
  if (flg & 4) { if (p + 2 > gz.length) refuse(`${at}: not one complete gzip stream (extra field)`); p += 2 + gz.readUInt16LE(p); }
  for (const bit of [8, 16]) {
    if (flg & bit) { const z = gz.indexOf(0, p); if (z < 0) refuse(`${at}: not one complete gzip stream (name)`); p = z + 1; }
  }
  if (flg & 2) p += 2;
  if (p > gz.length - 8) refuse(`${at}: not one complete gzip stream (truncated)`);
  let out;
  try { out = zlib.inflateRawSync(gz.subarray(p, gz.length - 8), { maxOutputLength: cap, info: true }); } catch (e) {
    if (e?.code === 'ERR_BUFFER_TOO_LARGE') refuse(`${at}: decompresses past raw_bytes_max (${cap})`);
    refuse(`${at}: not one complete gzip stream (${e.message})`);
  }
  if (out.engine.bytesWritten !== gz.length - 8 - p) refuse(`${at}: not one complete gzip stream (bytes after the stream)`);
  const raw = out.buffer;
  if (gz.readUInt32LE(gz.length - 8) !== zlib.crc32(raw) || gz.readUInt32LE(gz.length - 4) !== (raw.length >>> 0)) {
    refuse(`${at}: the gzip checksum or size does not match`);
  }
  return raw;
}

/** root.json.gz: exactly one gzip stream, at most the root bound when decompressed. */
export function gunzipRoot(gz) {
  if (!Buffer.isBuffer(gz) || gz.length > SHARD_LIMITS.rootBytes) refuse('root.json.gz is missing or too large');
  return gunzipOne(gz, SHARD_LIMITS.rootBytes, 'root.json.gz');
}

/** A bucket's bytes: size, sha256 against the root, then one gzip stream under raw_bytes_max. Returns the raw file. */
export function verifyBucketBytes(root, i, gz) {
  const e = Array.isArray(root?.buckets) ? root.buckets.find((b) => b && b.i === i) : null;
  if (!e) refuse(`bucket ${i} is not listed in the root`);
  if (!Buffer.isBuffer(gz)) refuse(`bucket ${i}: no bytes`);
  if (gz.length > e.gz_bytes) refuse(`bucket ${i}: longer than its gz_bytes (${e.gz_bytes})`);
  if (gz.length !== e.gz_bytes) refuse(`bucket ${i}: shorter than its gz_bytes (${e.gz_bytes})`);
  if (sha256Hex(gz) !== e.gz_sha256) refuse(`bucket ${i}: gz_sha256 differs from the root`);
  return gunzipOne(gz, root.raw_bytes_max, `bucket ${i}`);
}

const tablesOf = (db, schema = 'main') => new Set(db.prepare(`SELECT name FROM ${schema}.sqlite_master WHERE type = 'table'`).all().map((r) => r.name));

/** The rows of a staged bucket, checked: logical digest, read layout, no metadata, the bucket rule, the lineage ids. */
function checkStaged(db, root, i) {
  const e = root.buckets[i]; const at = `bucket ${i}`;
  if (db.prepare('PRAGMA quick_check').pluck().get() !== 'ok') refuse(`${at}: not a sound database file`);
  const tables = tablesOf(db);
  for (const t of BUCKET_TABLES) if (!tables.has(t) && t !== 'cross_links') refuse(`${at}: no table ${t}`);
  const logical = L.digestTables(db, [...BUCKET_TABLES, RL.RL1_TABLE], DIGEST_ORDER, new Set(['cross_links', RL.RL1_TABLE]));
  if (logical !== e.logical) refuse(`${at}: logical digest differs from the root`);
  const rl1 = tables.has(RL.RL1_TABLE)
    ? db.prepare(`SELECT ${RL.RL1_COLUMNS.join(', ')} FROM ${RL.RL1_TABLE} ORDER BY package_id`).all() : [];
  if ((rl1.length ? RL.contentDigest(rl1) : null) !== e.rl1_digest) refuse(`${at}: rl1_digest differs from the root`);
  if (tables.has('seed_metadata') && db.prepare('SELECT count(*) FROM seed_metadata').pluck().get()) refuse(`${at}: carries seed_metadata (the root's)`);
  const names = db.prepare('SELECT package_name FROM packages UNION SELECT package_name FROM known_malicious_pins').pluck().all();
  const foreign = names.filter((n) => bucketOf(n, root.bucket_bits) !== i).length;
  let orphans = 0;
  for (const t of LINEAGE_KEYED) {
    if (tables.has(t)) orphans += db.prepare(`SELECT count(*) FROM ${t} WHERE lineage_id NOT IN (SELECT id FROM lineages)`).pluck().get();
  }
  orphans += db.prepare('SELECT count(*) FROM lineages WHERE package_id NOT IN (SELECT id FROM packages)').pluck().get();
  orphans += db.prepare('SELECT count(*) FROM dep_names WHERE package_id NOT IN (SELECT id FROM packages)').pluck().get();
  if (foreign || orphans) refuse(`${at}: bucket rule broken (${foreign} name(s) of other buckets, ${orphans} row(s) of no package here)`);
  const badIds = db.prepare('SELECT count(*) FROM lineages WHERE ord < 0 OR ord >= ? OR id != package_id * ? + ord').pluck()
    .get(LINEAGE_STRIDE, LINEAGE_STRIDE);
  if (badIds) refuse(`${at}: ${badIds} lineage(s) whose id is not package_id * ${LINEAGE_STRIDE} + ord`);
}

const CACHE_DDL = `
CREATE TABLE IF NOT EXISTS shard_root (id INTEGER PRIMARY KEY CHECK (id = 1), digest TEXT NOT NULL, cut_at TEXT NOT NULL,
  root_json TEXT NOT NULL, root_sig BLOB, keys_json BLOB, keys_sig BLOB,
  set_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')));
CREATE TABLE IF NOT EXISTS shard_buckets (i INTEGER PRIMARY KEY, logical TEXT NOT NULL, confirmed_cut_at TEXT NOT NULL,
  imported_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')));
CREATE TABLE IF NOT EXISTS shard_bucket_packages (i INTEGER NOT NULL, package_id INTEGER NOT NULL, PRIMARY KEY (i, package_id)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS shard_bucket_pins (i INTEGER NOT NULL, package_name TEXT NOT NULL, PRIMARY KEY (i, package_name)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS shard_fetch (id INTEGER PRIMARY KEY CHECK (id = 1), root_etag TEXT, attempted_at TEXT, outcome TEXT,
  why TEXT, accepted_at TEXT);
`;
const DDL_ONLY = /^CREATE (?:TABLE|UNIQUE INDEX|INDEX) /;

/** The cache for writing, its directory made when missing (a proxy may start before `init` made it); a new one gets the seed
 * writer's page size. */
function openCache(cachePath) {
  fs.mkdirSync(path.dirname(path.resolve(cachePath)), { recursive: true });
  const fresh = !fs.existsSync(cachePath);
  const db = new Database(cachePath);
  if (fresh) db.pragma('page_size = 8192');
  db.pragma('journal_mode = DELETE');
  db.pragma('foreign_keys = OFF');           // as the seed writer and the reference import: a pin may name no package here
  db.exec(CACHE_DDL);
  return db;
}

/** The last root fetch as recorded: { root_etag, attempted_at, outcome, why, accepted_at }, or null. */
export function readFetch(db) {
  const t = tablesOf(db);
  return t.has('shard_fetch') ? (db.prepare('SELECT root_etag, attempted_at, outcome, why, accepted_at FROM shard_fetch WHERE id = 1').get() ?? null) : null;
}

/** Record a root fetch's outcome (the ETag only when given; accepted_at only on an accepted root). */
export function recordFetch(cachePath, { outcome, why = null, etag, accepted = false, at = new Date().toISOString() }) {
  const db = openCache(cachePath);
  try {
    db.prepare(`INSERT INTO shard_fetch (id, root_etag, attempted_at, outcome, why, accepted_at) VALUES (1, @etag, @at, @outcome, @why, @acc)
      ON CONFLICT(id) DO UPDATE SET root_etag = coalesce(@etag, root_etag), attempted_at = @at, outcome = @outcome, why = @why,
        accepted_at = coalesce(@acc, accepted_at)`).run({ etag: etag ?? null, at, outcome, why, acc: accepted ? at : null });
  } finally { db.close(); }
}

/** Delete every row bucket `i` brought into the cache (its packages and their rows, its pins by name), inside a transaction. */
function dropBucketRows(db, i) {
  const pkgs = '(SELECT package_id FROM shard_bucket_packages WHERE i = @i)';
  const tables = tablesOf(db);
  for (const t of LINEAGE_KEYED) {
    if (tables.has(t)) db.prepare(`DELETE FROM ${t} WHERE lineage_id IN (SELECT id FROM lineages WHERE package_id IN ${pkgs})`).run({ i });
  }
  for (const [t, col] of Object.entries(PACKAGE_COL)) if (tables.has(t)) db.prepare(`DELETE FROM ${t} WHERE ${col} IN ${pkgs}`).run({ i });
  db.prepare('DELETE FROM known_malicious_pins WHERE package_name IN (SELECT package_name FROM shard_bucket_pins WHERE i = @i)').run({ i });
  db.prepare('DELETE FROM shard_bucket_packages WHERE i = @i').run({ i });
  db.prepare('DELETE FROM shard_bucket_pins WHERE i = @i').run({ i });
  db.prepare('DELETE FROM shard_buckets WHERE i = @i').run({ i });
}

/**
 * Make `root` the cache's one current root (its cut_at later than the one held). Buckets the new root lists
 * with the same logical digest are kept and confirmed; every other bucket's rows are deleted, so its packages are uncovered until
 * it is imported again. seed_metadata becomes the root's. A root from verifyRoot carries its signature and key list, which
 * are stored with it; a cache whose root has none is refused when opened.
 */
export function setRoot(cachePath, root, rootBytes) {
  const db = openCache(cachePath);
  try {
    const held = db.prepare('SELECT digest, cut_at FROM shard_root WHERE id = 1').get();
    if (held?.digest === root.digest) return { kept: db.prepare('SELECT count(*) FROM shard_buckets').pluck().get(), dropped: 0 };
    if (held && !(root.cut_at > held.cut_at)) refuse(`the root of ${root.cut_at} is not later than the cache's root of ${held.cut_at}`);
    let kept = 0; let dropped = 0;
    db.transaction(() => {
      for (const b of db.prepare('SELECT i, logical FROM shard_buckets').all()) {
        if (root.buckets[b.i]?.logical === b.logical) {
          db.prepare('UPDATE shard_buckets SET confirmed_cut_at = ? WHERE i = ?').run(root.cut_at, b.i); kept += 1;
        } else { dropBucketRows(db, b.i); dropped += 1; }
      }
      // the writer's table, so a cache holding a root and no bucket yet already states the root's metadata
      db.exec('CREATE TABLE IF NOT EXISTS seed_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID');
      {
        db.prepare('DELETE FROM seed_metadata').run();
        const ins = db.prepare('INSERT INTO seed_metadata (key, value) VALUES (?, ?)');
        for (const [k, v] of Object.entries(root.seed_metadata).sort()) ins.run(k, v);
      }
      const proof = root.proof ?? {};
      const bytes = proof.rootBytes ?? rootBytes;
      db.prepare(`INSERT INTO shard_root (id, digest, cut_at, root_json, root_sig, keys_json, keys_sig)
        VALUES (1, @digest, @cut_at, @json, @sig, @keys, @keysSig)
        ON CONFLICT(id) DO UPDATE SET digest = @digest, cut_at = @cut_at, root_json = @json, root_sig = @sig, keys_json = @keys,
          keys_sig = @keysSig, set_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`)
        .run({ digest: root.digest, cut_at: root.cut_at, json: bytes ? bytes.toString('utf8') : canonicalJson(root),
          sig: proof.sig ?? null, keys: proof.keysBytes ?? null, keysSig: proof.keysSig ?? null });
    })();
    return { kept, dropped };
  } finally { db.close(); }
}

/**
 * A bucket's rows: stage `raw` (from verifyBucketBytes) in a temporary database beside the cache, check it, then
 * replace bucket `i` in the cache in one transaction. A cache with no root takes this one; a cache under another root refuses.
 */
export function importBucket(cachePath, root, i, raw) {
  fs.mkdirSync(path.dirname(path.resolve(cachePath)), { recursive: true });
  const dir = fs.mkdtempSync(path.join(path.dirname(path.resolve(cachePath)), '.shard-stage-'));
  const staged = path.join(dir, `${String(i).padStart(5, '0')}.db`);
  try {
    fs.writeFileSync(staged, raw);
    const sdb = new Database(staged, { readonly: true, fileMustExist: true });
    let ddl;
    try {
      checkStaged(sdb, root, i);
      ddl = sdb.prepare("SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY type DESC, name").all();
    } finally { sdb.close(); }
    for (const d of ddl) if (!DDL_ONLY.test(d.sql)) refuse(`bucket ${i}: carries a schema statement that is not a table or an index`);
    if (!fs.existsSync(cachePath)) openCache(cachePath).close();
    const heldDb = new Database(cachePath, { readonly: true });
    let held;
    try { held = heldDb.prepare('SELECT digest FROM shard_root WHERE id = 1').get(); } finally { heldDb.close(); }
    if (!held) setRoot(cachePath, root);
    else if (held.digest !== root.digest) refuse(`bucket ${i}: the cache is under another root; set this root first`);
    const db = openCache(cachePath);
    try {
      db.prepare('ATTACH DATABASE ? AS b').run(staged);
      try {
        db.transaction(() => {
          const have = tablesOf(db);
          for (const d of ddl) {
            if (d.type === 'table' && !have.has(d.name)) db.exec(d.sql);
            if (d.type === 'index') db.exec(d.sql.replace(/^CREATE (UNIQUE )?INDEX /, 'CREATE $1INDEX IF NOT EXISTS '));
          }
          // the cache's metadata is the root's; the first bucket brings the table
          if (!db.prepare('SELECT count(*) FROM seed_metadata').pluck().get()) {
            const ins = db.prepare('INSERT INTO seed_metadata (key, value) VALUES (?, ?)');
            for (const [k, v] of Object.entries(root.seed_metadata).sort()) ins.run(k, v);
          }
          dropBucketRows(db, i);
          const btables = tablesOf(db, 'b');
          for (const t of [...BUCKET_TABLES, RL.RL1_TABLE]) {
            if (!btables.has(t)) continue;
            const cols = db.prepare(`PRAGMA b.table_info(${t})`).all().map((c) => c.name).join(', ');
            db.prepare(`INSERT INTO main.${t} (${cols}) SELECT ${cols} FROM b.${t}`).run();
          }
          db.prepare('INSERT INTO shard_bucket_packages (i, package_id) SELECT ?, id FROM b.packages').run(i);
          db.prepare('INSERT OR IGNORE INTO shard_bucket_pins (i, package_name) SELECT DISTINCT ?, package_name FROM b.known_malicious_pins').run(i);
          db.prepare('INSERT INTO shard_buckets (i, logical, confirmed_cut_at) VALUES (?, ?, ?)').run(i, root.buckets[i].logical, root.cut_at);
        })();
      } finally { db.prepare('DETACH DATABASE b').run(); }
    } finally { db.close(); }
    return { i, logical: root.buckets[i].logical };
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

/** The buckets a cache holds: { i, logical, confirmed_cut_at, imported_at }, by bucket id. */
export function cacheBuckets(db) {
  return db.prepare('SELECT i, logical, confirmed_cut_at, imported_at FROM shard_buckets ORDER BY i').all();
}

/**
 * The cache checked as it is opened: its stored root verified again (the key list against the seed key, the shards key valid at
 * the root's cut, the signature), the cache's seed_metadata exactly the root's, and every held bucket listed by the root with the
 * same logical digest. Rows are not re-hashed here; bucketRowsProblem does that per bucket at its first lookup. With no seed key
 * (an unsigned development seed) the signature is not checked and the result says so. Returns { root, held: Map(i -> logical),
 * authenticated }.
 */
export function checkCache(db, { seedKey = null, bits = BUCKET_BITS } = {}) {
  const tables = tablesOf(db);
  if (!tables.has('shard_root') || !tables.has('shard_buckets')) refuse('the cache has no root');
  const s = db.prepare('SELECT digest, cut_at, root_json, root_sig, keys_json, keys_sig FROM shard_root WHERE id = 1').get();
  if (!s) refuse('the cache has no root');
  const rootBytes = Buffer.from(s.root_json, 'utf8');
  let root;
  if (seedKey) {
    if (!s.root_sig || !s.keys_json || !s.keys_sig) refuse('the cache\'s root carries no signature or key list');
    root = verifyRoot({ rootBytes, sig: Buffer.from(s.root_sig), keysBytes: Buffer.from(s.keys_json), keysSig: Buffer.from(s.keys_sig),
      seedKey, now: Date.parse(s.cut_at), bits });
  } else {
    try { root = JSON.parse(s.root_json); } catch { refuse('the cache\'s root is not JSON'); }
    if (!isObj(root)) refuse('the cache\'s root is not a JSON object');
    checkFields(root, bits);
    Object.defineProperty(root, 'digest', { value: sha256Hex(rootBytes), enumerable: false });
  }
  if (root.digest !== s.digest || root.cut_at !== s.cut_at) refuse('the cache\'s root differs from its recorded digest or cut');
  const meta = tables.has('seed_metadata') ? Object.fromEntries(db.prepare('SELECT key, value FROM seed_metadata').raw(true).all()) : {};
  if (canonicalJson(meta) !== canonicalJson(root.seed_metadata)) refuse('the cache\'s seed_metadata is not its root\'s');
  const held = new Map();
  for (const b of cacheBuckets(db)) {
    if (root.buckets[b.i]?.logical !== b.logical) refuse(`the cache holds bucket ${b.i} with a logical digest its root does not list`);
    held.set(b.i, b.logical);
  }
  return { root, held, authenticated: Boolean(seedKey) };
}

/** Bucket `i`'s rows inside a cache re-hashed against its root entry: null when they match, else what differs. */
export function bucketRowsProblem(db, root, i) {
  const e = root.buckets[i]; const at = `bucket ${i}`;
  const P = '(SELECT package_id FROM shard_bucket_packages WHERE i = @i)';
  const where = { packages: `id IN ${P}`, known_malicious_pins: 'package_name IN (SELECT package_name FROM shard_bucket_pins WHERE i = @i)' };
  for (const [t, col] of Object.entries(PACKAGE_COL)) if (t !== 'packages') where[t] = `${col} IN ${P}`;
  for (const t of LINEAGE_KEYED) where[t] = `lineage_id IN (SELECT id FROM lineages WHERE package_id IN ${P})`;
  const tables = tablesOf(db);
  const logical = L.digestTables(db, [...BUCKET_TABLES, RL.RL1_TABLE], DIGEST_ORDER, new Set(['cross_links', RL.RL1_TABLE]),
    { where, params: { i } });
  if (logical !== e.logical) return `${at}: its rows no longer match the root (logical digest differs)`;
  const rl1 = tables.has(RL.RL1_TABLE)
    ? db.prepare(`SELECT ${RL.RL1_COLUMNS.join(', ')} FROM ${RL.RL1_TABLE} WHERE ${where[RL.RL1_TABLE]} ORDER BY package_id`).all({ i }) : [];
  if ((rl1.length ? RL.contentDigest(rl1) : null) !== e.rl1_digest) return `${at}: its rows no longer match the root (rl1_digest differs)`;
  return null;
}

export default { SHARDS_CONTRACT, SHARD_SEED_CONTRACT, SHARD_LINEAGE_ID_RULE, BUCKET_BITS, BUCKET_HASH, SHARD_LIMITS, ShardRefused,
  bucketOf, canonicalJson, verifyRoot, gunzipRoot, verifyBucketBytes, setRoot, importBucket, cacheBuckets, checkCache, bucketRowsProblem,
  readFetch, recordFetch };
