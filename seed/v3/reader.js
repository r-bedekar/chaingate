// The offline v3 seed reader in native JavaScript. Mirrors tools/seedgen/reader.py:
// compatibility declared AND checked; trust before use, modes explicit; candidate facts
// supplied, never invented; read-only and offline; check evaluates; coverage is an outcome;
// why is derived, deterministic, inert and complete; full-corpus capability.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import Database from 'better-sqlite3';
import K from './contract.js';
import C from './checker.js';
import RL from './read-layout.js';
import SH from './shards.js';
import { pyStrip } from './normalize.js';
import { CAPS, FileRefused, openRegular, readBounded, readBoundedIfPresent, sha256Regular } from './bounded-file.js';

const SUPPORTED_SCHEMA_VERSIONS = [3];
// 1.1: advisory pins are keyed by package NAME, so a pin no longer presumes a represented package.
// Its pin table carries `package_name` with an index on (package_name, version); see pinLayoutProblem().
const SEED_CONTRACT_1_0 = 'cft-seed-v3-contract-1.0';
const SEED_CONTRACT_1_1 = 'cft-seed-v3-contract-1.1';
// 1.2: chains per (lineage key, tag family) in `lineages.tag_family`, and `cross_links` for every
// predecessor that is not the previous row of its own chain. Read ONLY together with the pipeline-key identifiers below; a
// 1.1 reader would take ord - 1 as every predecessor, so it refuses 1.2 by its contract version.
const SEED_CONTRACT_1_2 = 'cft-seed-v3-contract-1.2';
// 1.3 (since 0.1.6): 1.2 with package-scoped lineage ids, lineages.id = package_id * 4096 + ord, carried by every column that
// names a lineage and declared as `lineage_id_rule`. Read under every 1.2 rule plus the id rule, which is checked on the rows,
// not trusted from the key (the seed side's reader.py lineage_id_rule_problem). Ids reach about 9.5e9: exact in a JS number.
const SEED_CONTRACT_1_3 = 'cft-seed-v3-contract-1.3';
const LINEAGE_ID_RULE_1_3 = 'pkg4096-1';
const LINEAGE_ID_STRIDE_1_3 = 4096;
const RL2_CONTRACTS = Object.freeze([SEED_CONTRACT_1_2, SEED_CONTRACT_1_3]);
const SUPPORTED_SEED_CONTRACT_VERSIONS = [SEED_CONTRACT_1_0, SEED_CONTRACT_1_1, SEED_CONTRACT_1_2, SEED_CONTRACT_1_3];
const PIPEKEY_CHANNEL_A = 'infra5d-1.2+fu2final+norm1+sizeshrink+pipekey1';
// since 0.1.6: the Channel-A stamp of a 1.3 seed, grouped by tag family 0.3 (the prerelease's platform tokens join its family)
const PLATFAM_CHANNEL_A = `${PIPEKEY_CHANNEL_A}+platfam1`;
// This reader's own literals for what a 1.2 seed must declare, as the seed side's reader.py and versions.py pin them. The
// stub instant and the tag-family definition decide predecessors, so a seed built under others would disagree with the gate.
const RL2_IDENTIFIERS = Object.freeze({
  lineage_rule_version: 'fu2-final+e1e4e5+pipekey1+stubpred1',
  stub_detector_effective_at: '2026-10-13T22:00:00+00:00',
  storage_layout: 'wr1/noeidx/p8k/pinname1/xlink1',
  tag_family_fixture: '{"sha256":"f4be8bc5ab9eaeb5a59eef8c4f206483cfc545a3aba8e90437fde21c542a7061","version":"lineage-tag-family-cases-0.2"}',
});
// A 1.3 seed: the same, under its own lineage pair (tag family 0.3). Each contract is read only under its own pair.
const RL2_IDENTIFIERS_1_3 = Object.freeze({
  ...RL2_IDENTIFIERS,
  lineage_rule_version: 'fu2-final+e1e4e5+pipekey1+stubpred1+platfam1',
  tag_family_fixture: '{"sha256":"82f551e75df644954b7813dc6fcb804369f67e0c565b3e318ccf31d8971ffe37","version":"lineage-tag-family-cases-0.3"}',
});
const CHANNEL_A_BY_CONTRACT = Object.freeze({ [SEED_CONTRACT_1_2]: PIPEKEY_CHANNEL_A, [SEED_CONTRACT_1_3]: PLATFAM_CHANNEL_A });
const CROSS_LINK_COLUMNS = ['lineage_id', 'ord', 'pred_lineage_id', 'pred_ord', 'pred_version', 'pred_size_bytes', 'pred_tool_key'];
const IMPLEMENTED_DETECTION_CONTRACT = K.CONTRACT_VERSION;
const REQUIRED_TABLES = ['seed_metadata', 'packages', 'lineages', 'lineage_state', 'spine', 'events'];
const SUPPORTED_RULE_VERSIONS = {
  channel_a: ['infra5d-1.2+fu2final+norm1+sizeshrink', PIPEKEY_CHANNEL_A, PLATFAM_CHANNEL_A],
  dac_trajectory: ['dac-trajectory-1.0'],
};
const REQUIRED_BINDING_KEYS = ['schema_version', 'contract_version', 'corpus_snapshot_digest',
  'history_cutoff', 'rule_versions'];

const TRUST_AUTHENTICATED = 'authenticated';
const TRUST_UNSIGNED_DEV = 'unsigned-development';
const TRUST_MODES = [TRUST_AUTHENTICATED, TRUST_UNSIGNED_DEV];

// The candidate boundary, declared independently here and compared against the Python spec by test.
const HEX_SHA256 = 64;
const HEX_MD5 = 32;
const MAX_PUBLISHED_S = 4102444800;
const PROVIDER_CLASSES = ['unknown', 'privacy', 'free-webmail', 'verified-corporate', 'unverified'];
const CANDIDATE_SPEC = {
  package_name:       { type: 'string',  nullable: false, allow_empty: false },
  version:            { type: 'string',  nullable: false, allow_empty: false },
  published_s:        { type: 'integer', nullable: true,  min: 0, max: MAX_PUBLISHED_S },
  lineage_id:         { type: 'integer', nullable: true,  min: 1 },
  ord:                { type: 'integer', nullable: true,  min: 0 },
  identity_digest:    { type: 'hex',     nullable: true,  length: HEX_SHA256 },
  tuple_digest:       { type: 'hex',     nullable: true,  length: HEX_SHA256 },
  maint_digest:       { type: 'hex',     nullable: false, length: HEX_MD5, allow_empty: true },
  tool_name:          { type: 'string',  nullable: false, allow_empty: true },
  tool_key:           { type: 'number',  nullable: false, min: 0 },
  provenance_present: { type: 'boolean', nullable: false },
  publish_method:     { type: 'string',  nullable: false, allow_empty: true },
  has_scripts:        { type: 'boolean', nullable: false },
  body_digest:        { type: 'hex',     nullable: false, length: HEX_MD5, allow_empty: true },
  head_present:       { type: 'boolean', nullable: false },
  repo_digest:        { type: 'hex',     nullable: true,  length: HEX_SHA256 },
  size_bytes:         { type: 'integer', nullable: true,  min: 0 },
  provider_class:     { type: 'enum',    nullable: false, values: PROVIDER_CLASSES },
};
const CANDIDATE_REQUIRED = Object.keys(CANDIDATE_SPEC);

class SeedRefused extends Error {
  constructor(reasons) { super(reasons.join('; ')); this.name = 'SeedRefused'; this.reasons = reasons; }
}
class CandidateRejected extends Error {
  constructor(reasons) { super(reasons.join('; ')); this.name = 'CandidateRejected'; this.reasons = reasons; }
}

// Through one non-blocking descriptor that must be a regular file, read from explicit positions.
function sha256File(p) { return sha256Regular(p); }

/** What a refusal says, without the path the caller already names. */
const whyOf = (e) => (e instanceof FileRefused ? e.why : `${e.name}: ${e.message}`);

const isHex = (v, n) => v.length === n && /^[0-9a-f]*$/.test(v);

/**
 * The pin layout a 1.1 seed must carry, or null. A 1.1 seed is looked up by name, so a seed that DECLARES 1.1 without
 * the name column or its index would either fail every lookup or scan the table per release: refused by name instead.
 * A 1.0 seed is not checked here; its layout is unchanged from the reader that shipped with it.
 */
function pinLayoutProblem(db, tables) {
  if (!tables.has('known_malicious_pins')) return 'missing table known_malicious_pins';
  const cols = db.prepare("SELECT name FROM pragma_table_info('known_malicious_pins')").all().map((r) => r.name);
  if (!cols.includes('package_name')) {
    return `known_malicious_pins has no package_name column (columns: ${cols.join(', ')})`;
  }
  const indexed = db.prepare("SELECT name FROM pragma_index_list('known_malicious_pins')").all().some((ix) => {
    const keys = db.prepare('SELECT name FROM pragma_index_info(?) ORDER BY seqno').all(ix.name).map((r) => r.name);
    return keys[0] === 'package_name' && keys[1] === 'version';
  });
  return indexed ? null : 'known_malicious_pins has no index on (package_name, version)';
}

/** The lineage layout a 1.2 seed must carry, or null; the seed side's reader.py rl2_layout_problem. */
/** The lineage ids a 1.3 seed must carry, checked on the rows, or null. */
function lineageIdRuleProblem(db, tables, declared) {
  if (declared !== LINEAGE_ID_RULE_1_3) {
    return `seed declares ${SEED_CONTRACT_1_3} with lineage_id_rule=${JSON.stringify(declared ?? null)}; this reader implements ${LINEAGE_ID_RULE_1_3}`;
  }
  if (!tables.has('lineages')) return 'missing table lineages';
  const n = db.prepare('SELECT count(*) AS n FROM lineages WHERE ord < 0 OR ord >= ? OR id != package_id * ? + ord')
    .get(LINEAGE_ID_STRIDE_1_3, LINEAGE_ID_STRIDE_1_3).n;
  return n ? `${n} lineage(s) whose id is not package_id * ${LINEAGE_ID_STRIDE_1_3} + ord (${LINEAGE_ID_RULE_1_3})` : null;
}

function rl2LayoutProblem(db, tables) {
  if (!tables.has('cross_links')) return 'missing table cross_links';
  const cols = db.prepare("PRAGMA table_info('cross_links')").all().map((r) => r.name);
  const missing = CROSS_LINK_COLUMNS.filter((c) => !cols.includes(c));
  if (missing.length) return `cross_links lacks ${missing.join(', ')} (columns: ${cols.join(', ')})`;
  if (!db.prepare("PRAGMA table_info('lineages')").all().some((r) => r.name === 'tag_family')) return 'lineages has no tag_family column';
  return null;
}

// Python's int() strips Python whitespace, which is not JavaScript's; and [0-9] rather than \d
// because Python's \d also matches e.g. ARABIC-INDIC digits that int() would then convert.
const pyTrimForVersion = (v) => pyStrip(v);

/** null when acceptable, else the reason it is not. JS has no integer type, so integrality is checked. */
function validateField(name, value, spec) {
  const t = spec.type;
  if (value === null || value === undefined) {
    return spec.nullable ? null : `${name}: null is not a legitimate value here — state what was observed`;
  }
  if (t === 'boolean') {
    return typeof value === 'boolean' ? null
      : `${name}: must be a boolean stating what was observed, got ${JSON.stringify(value)}`;
  }
  if (typeof value === 'boolean') return `${name}: must be ${t}, not a boolean`;
  if (t === 'integer') {
    if (typeof value !== 'number' || !Number.isInteger(value)) {
      return `${name}: must be an integer, got ${JSON.stringify(value)}`;
    }
    // JSON.parse silently rounds beyond 2^53-1: 9007199254740993 arrives as ...992. Accepting that
    // records a DIFFERENT number than the caller supplied, so it is refused.
    if (!Number.isSafeInteger(value)) {
      return `${name}: ${value} is outside the exactly-representable integer range `
        + `(|v| <= ${Number.MAX_SAFE_INTEGER}); JSON parsing would have altered it`;
    }
    if ('min' in spec && value < spec.min) return `${name}: must be >= ${spec.min}, got ${value}`;
    if ('max' in spec && value > spec.max) return `${name}: must be <= ${spec.max}, got ${value}`;
    return null;
  }
  if (t === 'number') {
    if (typeof value !== 'number') return `${name}: must be a number, got ${JSON.stringify(value)}`;
    if (!Number.isFinite(value)) return `${name}: must be finite, got ${value}`;
    if ('min' in spec && value < spec.min) return `${name}: must be >= ${spec.min}, got ${value}`;
    return null;
  }
  if (t === 'string' || t === 'hex' || t === 'enum') {
    if (typeof value !== 'string') return `${name}: must be a string, got ${JSON.stringify(value)}`;
    if (t === 'enum') {
      return spec.values.includes(value) ? null
        : `${name}: must be one of ${JSON.stringify(spec.values)}, got ${JSON.stringify(value)}`;
    }
    if (value === '') return spec.allow_empty ? null : `${name}: must not be empty`;
    if (t === 'hex' && !isHex(value, spec.length)) {
      return `${name}: must be ${spec.length} lowercase hex characters, got ${JSON.stringify(value)}`;
    }
    return null;
  }
  return `${name}: unknown spec type ${t}`;
}

function candidateFromMapping(d) {
  if (d === null || typeof d !== 'object' || Array.isArray(d)) {
    throw new CandidateRejected([`candidate must be a JSON object, got ${Array.isArray(d) ? 'array' : typeof d}`]);
  }
  const problems = [];
  const missing = CANDIDATE_REQUIRED.filter((k) => !(k in d));
  const unknown = Object.keys(d).filter((k) => !(k in CANDIDATE_SPEC)).sort();
  if (missing.length) {
    problems.push('missing required candidate fields (state them explicitly; they are facts about a '
      + `real release, not defaults): ${missing.join(', ')}`);
  }
  if (unknown.length) problems.push(`unknown candidate fields: ${unknown.join(', ')}`);
  for (const [k, spec] of Object.entries(CANDIDATE_SPEC)) {
    if (k in d) { const bad = validateField(k, d[k], spec); if (bad) problems.push(bad); }
  }
  if (problems.length) throw new CandidateRejected(problems);
  const out = {};
  for (const k of CANDIDATE_REQUIRED) out[k] = d[k] === undefined ? null : d[k];
  return out;
}

/**
 * Resolve a trusted public key from a PATH or from a KEY the caller already holds.
 *
 * `pubkeyPath` alone forced every caller to have the anchor on disk. The runtime's anchor is an
 * embedded literal — a pinned key compiled into the CLI, with rotation requiring a release — so
 * insisting on a file meant the proxy passed no key at all and authenticated trust was never
 * actually checked. `pubkey` accepts that literal directly: a KeyObject, a PEM/DER buffer, or a
 * base64 SPKI string.
 */
function resolvePubkey({ pubkeyPath = null, pubkey = null }) {
  if (pubkey) {
    if (typeof pubkey === 'object' && typeof pubkey.export === 'function') return pubkey;
    if (Buffer.isBuffer(pubkey)) return crypto.createPublicKey(pubkey);
    if (typeof pubkey === 'string') {
      return pubkey.includes('-----BEGIN')
        ? crypto.createPublicKey(pubkey)
        : crypto.createPublicKey({ key: Buffer.from(pubkey, 'base64'), format: 'der', type: 'spki' });
    }
    throw new TypeError('pubkey must be a KeyObject, a PEM/DER buffer, or a base64 SPKI string');
  }
  if (pubkeyPath) return crypto.createPublicKey(readBounded(pubkeyPath, CAPS.key));
  return null;
}

const DAY_MS = 24 * 3600e3;
/** A seed cache whose root is older than this states it on every decision. */
const SHARD_ROOT_STALE_DAYS = 7;

// `shardBits` and `now` exist for the seed shards tests (a toy root of 3 bits; a fixed clock); production passes neither.
function verify(dbPath, { trust = TRUST_AUTHENTICATED, pubkeyPath = null, pubkey = null, expect = null, verifyDigest = true,
  shardBits = SH.BUCKET_BITS, now = Date.now } = {}) {
  let trustedKey = null;
  let trustedKeyError = null;
  try { trustedKey = resolvePubkey({ pubkeyPath, pubkey }); } catch (e) { trustedKeyError = `${e.name}: ${e.message}`; }
  if (!TRUST_MODES.includes(trust)) throw new Error(`trust must be one of ${JSON.stringify(TRUST_MODES)}`);
  const checks = {}; let meta = {}; let readLayout = null; let cache = null;
  const base = { trust_mode: trust, authenticated: false, path: String(dbPath) };
  if (!fs.existsSync(dbPath)) return { ...base, ok: false, checks: { present: `no such file: ${dbPath}` }, meta: {} };
  checks.present = true;
  // Before SQLite opens it by path: a FIFO or a device there would block that open.
  try { fs.closeSync(openRegular(dbPath).fd); } catch (e) {
    return { ...base, ok: false, checks: { ...checks, openable: whyOf(e) }, meta: {} };
  }

  let db;
  try { db = new Database(dbPath, { readonly: true, fileMustExist: true }); }
  catch (e) { return { ...base, ok: false, checks: { ...checks, openable: `${e.name}: ${e.message}` }, meta: {} }; }
  try {
    let tables;
    try {
      tables = new Set(db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((r) => r.name));
    } catch (e) {
      return { ...base, ok: false, meta: {}, checks: { ...checks, readable_sqlite: `not a readable SQLite database: ${e.message}` } };
    }
    checks.readable_sqlite = true;
    // Since 0.1.6: a seed cache (seed shards 1.0) holds some buckets of one signed root and is checked on that root, not on a
    // file digest and signature: see shards.js checkCache. Its rows are re-hashed per bucket at the first lookup (Seed).
    if (tables.has('shard_root')) {
      try {
        cache = SH.checkCache(db, { seedKey: trustedKey, bits: shardBits });
        cache.opts = { seedKey: trustedKey, bits: shardBits };
        checks.shard_root = true;
      } catch (e) {
        checks.shard_root = e instanceof SH.ShardRefused ? e.why : `${e.name}: ${e.message}`;
      }
    }
    const missing = REQUIRED_TABLES.filter((t) => !tables.has(t));
    checks.required_tables = missing.length ? `missing: ${missing.join(', ')}` : true;
    if (!tables.has('seed_metadata')) {
      checks.schema_version = 'seed_metadata is absent — the seed cannot state its schema';
      return { ...base, ok: false, checks, meta: {} };
    }
    const raw = {};
    try { for (const r of db.prepare('SELECT key, value FROM seed_metadata').all()) raw[r.key] = r.value; }
    catch (e) { return { ...base, ok: false, meta: {}, checks: { ...checks, seed_metadata_readable: `unreadable: ${e.message}` } }; }
    meta = C.loadSeedMeta(db);
    for (const k of ['corpus_snapshot_id', 'history_policy', 'storage_layout', 'selection_mode',
      'lineage_rule_version', 'selection_rule_version', 'K']) if (k in raw) meta[k] = raw[k];

    // Number.parseInt('3garbage') is 3, so the lenient parse ACCEPTED a seed whose schema_version is
    // not a number at all. Python's int() raises. The declared version must be exactly an integer.
    const svRaw = raw.schema_version;
    const svI = (typeof svRaw === 'number' && Number.isInteger(svRaw)) ? svRaw
      : (typeof svRaw === 'string' && /^[+-]?[0-9]+$/.test(pyTrimForVersion(svRaw)) ? Number(pyTrimForVersion(svRaw)) : null);
    checks.schema_version = (svI !== null && SUPPORTED_SCHEMA_VERSIONS.includes(svI)) ? true
      : `seed declares schema_version=${JSON.stringify(raw.schema_version)}; this reader implements ${JSON.stringify(SUPPORTED_SCHEMA_VERSIONS)}`;
    checks.seed_contract_version = SUPPORTED_SEED_CONTRACT_VERSIONS.includes(raw.contract_version) ? true
      : `seed declares contract_version=${JSON.stringify(raw.contract_version)}; this reader implements ${JSON.stringify(SUPPORTED_SEED_CONTRACT_VERSIONS)}`;
    meta.seed_contract_version = raw.contract_version === undefined ? null : raw.contract_version;
    meta.detection_contract_version = IMPLEMENTED_DETECTION_CONTRACT;
    if (raw.contract_version === SEED_CONTRACT_1_1 || RL2_CONTRACTS.includes(raw.contract_version)) {
      const bad = pinLayoutProblem(db, tables);
      checks.pin_layout = bad === null ? true : `seed declares ${raw.contract_version} but ${bad}`;
    }
    if (RL2_CONTRACTS.includes(raw.contract_version)) {
      const bad = rl2LayoutProblem(db, tables);
      checks.rl2_layout = bad === null ? true : `seed declares ${raw.contract_version} but ${bad}`;
      const ids = raw.contract_version === SEED_CONTRACT_1_3 ? RL2_IDENTIFIERS_1_3 : RL2_IDENTIFIERS;
      for (const [k, want] of Object.entries(ids)) {
        checks[k] = raw[k] === want ? true
          : `seed declares ${raw.contract_version} with ${k}=${JSON.stringify(raw[k] ?? null)}; this reader reads it only under ${want}`;
      }
    }
    if (raw.contract_version === SEED_CONTRACT_1_3) {
      const bad = lineageIdRuleProblem(db, tables, raw.lineage_id_rule);
      checks.lineage_id_rule = bad === null ? true : bad;
    } else if ('lineage_id_rule' in raw) {
      checks.lineage_id_rule = `seed declares ${JSON.stringify(raw.contract_version ?? null)} but carries lineage_id_rule=${JSON.stringify(raw.lineage_id_rule)}; `
        + `the lineage id rule is a ${SEED_CONTRACT_1_3} identifier`;
    }

    const absent = REQUIRED_BINDING_KEYS.filter((k) => !raw[k]);
    checks.required_bindings = absent.length ? `seed_metadata is missing or empty for: ${absent.join(', ')}` : true;

    const rv = meta.rule_versions;
    if (!rv || typeof rv !== 'object') {
      checks.rule_versions = `rule_versions missing or unreadable: ${JSON.stringify(rv)}`;
    } else {
      const bad = Object.entries(SUPPORTED_RULE_VERSIONS)
        .filter(([fam, okv]) => !okv.includes(rv[fam])).map(([fam]) => `${fam}=${JSON.stringify(rv[fam])}`);
      const extra = Object.keys(rv).filter((k) => !(k in SUPPORTED_RULE_VERSIONS)).sort();
      if (bad.length) {
        checks.rule_versions = `this reader does not implement: ${bad.join(', ')} `
          + `(supported: ${JSON.stringify(SUPPORTED_RULE_VERSIONS)})`;
      } else if (extra.length) {
        checks.rule_versions = `seed carries rule families this reader does not implement: ${JSON.stringify(extra)}`;
      } else if (rv.channel_a !== (CHANNEL_A_BY_CONTRACT[raw.contract_version] ?? rv.channel_a)
        || (!RL2_CONTRACTS.includes(raw.contract_version) && Object.values(CHANNEL_A_BY_CONTRACT).includes(rv.channel_a))) {
        // no inference: the pipeline-key rule and the rl2 layout come together, each contract under its own stamp, or the seed is
        // refused
        checks.rule_versions = `channel_a=${JSON.stringify(rv.channel_a)} with contract_version=${JSON.stringify(raw.contract_version)}: `
          + `a ${SEED_CONTRACT_1_2} seed is read only under ${PIPEKEY_CHANNEL_A}, a ${SEED_CONTRACT_1_3} seed only under `
          + `${PLATFAM_CHANNEL_A}, and neither rule from any other contract`;
      } else checks.rule_versions = true;
    }
    // EXPERIMENTAL read layout (read-layout.js): checked only when the seed declares one; a legacy seed's report is unchanged
    // a cache holding only some buckets checks the read layout of the packages it holds; the whole-seed digest needs every bucket
    const partial = cache !== null && cache.held.size < cache.root.buckets.length;
    const rl = RL.verifyReadLayout(db, raw, tables, { partial });
    if (rl !== null) { checks.read_layout = rl; readLayout = { id: raw.read_layout, digest: raw.read_layout_digest ?? null }; }
  } finally { db.close(); }

  if (checks.shard_root !== undefined) return cacheReport({ base, checks, meta, readLayout, cache, trust, trustedKey, trustedKeyError, expect, now });

  const shaSide = `${dbPath}.sha256`;
  // The digest this reader actually computed over the bytes it opened. Reported, not just checked:
  // a caller asking "is the running process using the seed I installed?" needs the identity of what
  // was loaded, and a path is not an identity -- two hosts, or a symlink before and after an update,
  // can carry the same path over different bytes.
  let contentSha256 = null;
  if (verifyDigest) {
    let side = null;
    try { side = readBoundedIfPresent(shaSide, CAPS.sidecar); } catch (e) {
      checks.content_digest = `sidecar ${path.basename(shaSide)}: ${whyOf(e)}`;
    }
    if (side !== null) {
      const parts = side.toString('utf8').split(/\s+/).filter(Boolean);
      if (!parts.length) checks.content_digest = `sidecar ${path.basename(shaSide)} is empty`;
      else {
        let actual = null;
        try { actual = sha256File(dbPath); } catch (e) { checks.content_digest = `${path.basename(dbPath)}: ${whyOf(e)}`; }
        if (actual !== null) {
          contentSha256 = actual;
          checks.content_digest = actual === parts[0] ? true : `content digest ${actual} != sidecar ${parts[0]}`;
        }
      }
    } else if (checks.content_digest === undefined) checks.content_digest = `no sidecar digest at ${path.basename(shaSide)}`;
  }

  const sigPath = `${dbPath}.sig`;
  let authenticated = false;
  if (trustedKeyError !== null) {
    checks.trusted_key = `the supplied public key could not be read: ${trustedKeyError}`;
  }
  if (fs.existsSync(sigPath) && trustedKey) {
    checks.signature = verifySignature(dbPath, sigPath, trustedKey);
    authenticated = checks.signature === true;
  } else if (fs.existsSync(sigPath)) {
    checks.signature = `a signature is present at ${path.basename(sigPath)} but no trusted public key was `
      + 'supplied — refusing to treat a signed seed as unsigned';
  } else if (trust === TRUST_AUTHENTICATED) {
    checks.signature = `no signature at ${path.basename(sigPath)}; trust mode '${TRUST_AUTHENTICATED}' requires `
      + `a pinned key and a valid signature (use '${TRUST_UNSIGNED_DEV}' explicitly for internal unsigned builds)`;
  }
  if (trust === TRUST_AUTHENTICATED && !trustedKey) {
    checks.trusted_key = `trust mode '${TRUST_AUTHENTICATED}' requires a pinned public key; none was supplied`;
  }
  expectChecks(checks, meta, expect);
  return { ...base, authenticated, content_sha256: contentSha256,
    ok: Object.values(checks).every((v) => v === true), checks, meta, ...(readLayout ? { read_layout: readLayout } : {}) };
}

function expectChecks(checks, meta, expect) {
  for (const [k, want] of Object.entries(expect || {})) {
    const got = meta[k] === undefined ? null : meta[k];
    checks[`expect.${k}`] = got === want ? true
      : `seed says ${JSON.stringify(got)}, caller expected ${JSON.stringify(want)}`;
  }
}

/**
 * The report for a seed cache. Its trust is its stored root's: authenticated when the key list verifies against the pinned seed
 * key and the root against the shards key it names; there is no file digest or signature, since imports change the file. The
 * checked root and held buckets travel with the report, not enumerated, for the Seed that opens it.
 */
function cacheReport({ base, checks, meta, readLayout, cache, trust, trustedKey, trustedKeyError, expect, now }) {
  if (trustedKeyError !== null) checks.trusted_key = `the supplied public key could not be read: ${trustedKeyError}`;
  if (trust === TRUST_AUTHENTICATED && !trustedKey) {
    checks.trusted_key = `trust mode '${TRUST_AUTHENTICATED}' requires a pinned public key; none was supplied`;
  }
  expectChecks(checks, meta, expect);
  const shardCache = cache ? { root_cut_at: cache.root.cut_at, root_digest: cache.root.digest, buckets_held: cache.held.size,
    buckets_total: cache.root.buckets.length, root_age_days: Math.max(0, Math.floor((now() - Date.parse(cache.root.cut_at)) / DAY_MS)) } : null;
  const rep = { ...base, authenticated: Boolean(cache?.authenticated && checks.shard_root === true), content_sha256: null,
    ok: Object.values(checks).every((v) => v === true), checks, meta, ...(readLayout ? { read_layout: readLayout } : {}), shard_cache: shardCache };
  Object.defineProperty(rep, 'cache', { value: cache, enumerable: false });
  return rep;
}

/** The signed MESSAGE is the 64-character ASCII hex digest, matching sign.py and seed_verify.js. */
function verifySignature(dbPath, sigPath, keyOrPath) {
  try {
    const pub = typeof keyOrPath === 'string'
      ? crypto.createPublicKey(readBounded(keyOrPath, CAPS.key)) : keyOrPath;
    // the signature first: it is bounded, and refusing it must not cost a hash of the whole database
    const sig = readBounded(sigPath, CAPS.sidecar);
    const ok = crypto.verify(null, Buffer.from(sha256File(dbPath), 'ascii'), pub, sig);
    return ok ? true : 'signature does not verify against the pinned key';
  } catch (e) { return whyOf(e); }
}

class Seed {
  constructor(dbPath, report, { now = Date.now } = {}) {
    this.path = dbPath; this.report = report; this.meta = report.meta;
    this.db = new Database(dbPath, { readonly: true, fileMustExist: true });
    this._cache = new Map();
    // since 0.1.6, a seed cache: its checked root, the buckets it holds, and each held bucket's row check once done
    this.shards = report.cache ? { root: report.cache.root, held: report.cache.held, opts: report.cache.opts, checked: new Map() } : null;
    this.now = now;
  }
  /**
   * A seed cache only: read the held buckets again after an import under the same root. A held bucket the root does not list
   * with that digest is refused at its next lookup, as at open; a bucket imported again is checked again.
   */
  reloadHeld() {
    if (!this.shards) return;
    const held = new Map();
    for (const b of SH.cacheBuckets(this.db)) {
      held.set(b.i, b.logical);
      if (this.shards.held.get(b.i) !== b.logical) this.shards.checked.delete(b.i);
      if (this.shards.root.buckets[b.i]?.logical !== b.logical) {
        this.shards.checked.set(b.i, `bucket ${b.i}: the cache holds a logical digest its root does not list`);
      }
    }
    this.shards.held = held;
    this._cache.clear();
  }
  /** Take over another Seed's file, report and state (a seed cache under a new root, opened and verified); this one's closes. */
  adopt(next) {
    const old = this.db;
    Object.assign(this, { path: next.path, report: next.report, meta: next.meta, db: next.db, shards: next.shards, now: next.now });
    this._cache = new Map();
    old.close();
  }
  /** A seed cache only: the bucket a package name falls in and whether the cache holds it; null for a full seed. */
  bucketOf(name) {
    if (!this.shards) return null;
    const i = SH.bucketOf(name, this.shards.root.bucket_bits);
    return { i, held: this.shards.held.has(i) };
  }
  /** Why a package is uncovered because its bucket is not held, or null. */
  uncoveredReason(name) {
    const b = this.bucketOf(name);
    return b && !b.held ? `the seed cache does not hold this package's bucket (${b.i})` : null;
  }
  /** Before a held bucket answers its first lookup, its rows are re-hashed against the root; a mismatch refuses that bucket. */
  touch(name) {
    const b = this.bucketOf(name);
    if (!b || !b.held) return;
    if (!this.shards.checked.has(b.i)) this.shards.checked.set(b.i, SH.bucketRowsProblem(this.db, this.shards.root, b.i));
    const problem = this.shards.checked.get(b.i);
    if (problem) throw new SeedRefused([problem]);
  }
  /** A seed cache whose root is older than 7 days says so; null otherwise. */
  staleness() {
    if (!this.shards) return null;
    const cut = this.shards.root.cut_at; const age = this.now() - Date.parse(cut);
    if (!(age > SHARD_ROOT_STALE_DAYS * DAY_MS)) return null;
    return `the seed cache's root was cut ${cut}, ${Math.floor(age / DAY_MS)} days ago (over ${SHARD_ROOT_STALE_DAYS}): `
      + 'newer seed data may be missing';
  }
  package(name) {
    this.touch(name);
    if (this._cache.has(name)) return this._cache.get(name);
    const pv = C.loadPackage(this.db, name, this.meta);
    if (this._cache.size > 64) this._cache.delete(this._cache.keys().next().value);
    this._cache.set(name, pv);
    return pv;
  }
  check(candidate) { return C.check(this.package(candidate.package_name), candidate, this.meta); }
  close() { this.db.close(); }
}

function openSeed(dbPath, opts = {}) {
  const rep = verify(dbPath, opts);
  if (!rep.ok) {
    throw new SeedRefused(Object.entries(rep.checks).filter(([, v]) => v !== true).map(([k, v]) => `${k}: ${v}`));
  }
  return new Seed(dbPath, rep, { now: opts.now });
}

export {
  SUPPORTED_SCHEMA_VERSIONS, SUPPORTED_SEED_CONTRACT_VERSIONS, SEED_CONTRACT_1_0, SEED_CONTRACT_1_1,
  SEED_CONTRACT_1_2, SEED_CONTRACT_1_3, LINEAGE_ID_RULE_1_3, RL2_CONTRACTS, PIPEKEY_CHANNEL_A, PLATFAM_CHANNEL_A, RL2_IDENTIFIERS, RL2_IDENTIFIERS_1_3, CROSS_LINK_COLUMNS,
  IMPLEMENTED_DETECTION_CONTRACT, REQUIRED_TABLES, SUPPORTED_RULE_VERSIONS, REQUIRED_BINDING_KEYS,
  TRUST_AUTHENTICATED, TRUST_UNSIGNED_DEV, TRUST_MODES,
  CANDIDATE_SPEC, CANDIDATE_REQUIRED, PROVIDER_CLASSES,
  SeedRefused, CandidateRejected, sha256File, validateField, candidateFromMapping,
  verify, verifySignature, Seed, openSeed,
};


// A default export as well: the consumer is used both as `import R from` and
// `import { verify } from`, and the runtime package is ESM.
export default { SUPPORTED_SCHEMA_VERSIONS, SUPPORTED_SEED_CONTRACT_VERSIONS, SEED_CONTRACT_1_0,
  SEED_CONTRACT_1_1, SEED_CONTRACT_1_2, SEED_CONTRACT_1_3, LINEAGE_ID_RULE_1_3, RL2_CONTRACTS, PIPEKEY_CHANNEL_A, PLATFAM_CHANNEL_A, RL2_IDENTIFIERS, RL2_IDENTIFIERS_1_3, CROSS_LINK_COLUMNS, IMPLEMENTED_DETECTION_CONTRACT, REQUIRED_TABLES, SUPPORTED_RULE_VERSIONS,
  REQUIRED_BINDING_KEYS, TRUST_AUTHENTICATED, TRUST_UNSIGNED_DEV, TRUST_MODES, CANDIDATE_SPEC,
  CANDIDATE_REQUIRED, PROVIDER_CLASSES, SeedRefused, CandidateRejected, sha256File,
  validateField, candidateFromMapping, verify, verifySignature, Seed, openSeed
};