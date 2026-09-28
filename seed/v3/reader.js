// CFT-04 — the offline v3 seed reader in native JavaScript. Mirrors tools/seedgen/reader.py:
// R1 compatibility declared AND checked · R2 trust before use, modes explicit · R2.1 candidate facts
// supplied never invented · R3 read-only and offline · R4 check evaluates · R5 coverage is an outcome
// · R6 why is derived, deterministic, inert and complete · R7 full-corpus capability.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import Database from 'better-sqlite3';
import K from './contract.js';
import C from './checker.js';
import { pyStrip } from './normalize.js';

const SUPPORTED_SCHEMA_VERSIONS = [3];
const SUPPORTED_SEED_CONTRACT_VERSIONS = ['cft-seed-v3-contract-1.0'];
const IMPLEMENTED_DETECTION_CONTRACT = K.CONTRACT_VERSION;
const REQUIRED_TABLES = ['seed_metadata', 'packages', 'lineages', 'lineage_state', 'spine', 'events'];
const SUPPORTED_RULE_VERSIONS = {
  channel_a: ['infra5d-1.2+fu2final+norm1+sizeshrink'],
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

function sha256File(p) {
  const h = crypto.createHash('sha256');
  const fd = fs.openSync(p, 'r');
  try {
    const buf = Buffer.alloc(1 << 22);
    let n;
    while ((n = fs.readSync(fd, buf, 0, buf.length, null)) > 0) h.update(buf.subarray(0, n));
  } finally { fs.closeSync(fd); }
  return h.digest('hex');
}

const isHex = (v, n) => v.length === n && /^[0-9a-f]*$/.test(v);

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
  if (pubkeyPath) return crypto.createPublicKey(fs.readFileSync(pubkeyPath));
  return null;
}

function verify(dbPath, { trust = TRUST_AUTHENTICATED, pubkeyPath = null, pubkey = null, expect = null, verifyDigest = true } = {}) {
  let trustedKey = null;
  let trustedKeyError = null;
  try { trustedKey = resolvePubkey({ pubkeyPath, pubkey }); } catch (e) { trustedKeyError = `${e.name}: ${e.message}`; }
  if (!TRUST_MODES.includes(trust)) throw new Error(`trust must be one of ${JSON.stringify(TRUST_MODES)}`);
  const checks = {}; let meta = {};
  const base = { trust_mode: trust, authenticated: false, path: String(dbPath) };
  if (!fs.existsSync(dbPath)) return { ...base, ok: false, checks: { present: `no such file: ${dbPath}` }, meta: {} };
  checks.present = true;

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
      } else checks.rule_versions = true;
    }
  } finally { db.close(); }

  const shaSide = `${dbPath}.sha256`;
  // The digest this reader actually computed over the bytes it opened. Reported, not just checked:
  // a caller asking "is the running process using the seed I installed?" needs the identity of what
  // was loaded, and a path is not an identity -- two hosts, or a symlink before and after an update,
  // can carry the same path over different bytes.
  let contentSha256 = null;
  if (verifyDigest) {
    if (fs.existsSync(shaSide)) {
      const parts = fs.readFileSync(shaSide, 'utf8').split(/\s+/).filter(Boolean);
      if (!parts.length) checks.content_digest = `sidecar ${path.basename(shaSide)} is empty`;
      else {
        const actual = sha256File(dbPath);
        contentSha256 = actual;
        checks.content_digest = actual === parts[0] ? true : `content digest ${actual} != sidecar ${parts[0]}`;
      }
    } else checks.content_digest = `no sidecar digest at ${path.basename(shaSide)}`;
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
  for (const [k, want] of Object.entries(expect || {})) {
    const got = meta[k] === undefined ? null : meta[k];
    checks[`expect.${k}`] = got === want ? true
      : `seed says ${JSON.stringify(got)}, caller expected ${JSON.stringify(want)}`;
  }
  return { ...base, authenticated, content_sha256: contentSha256,
    ok: Object.values(checks).every((v) => v === true), checks, meta };
}

/** The signed MESSAGE is the 64-character ASCII hex digest, matching sign.py and seed_verify.js. */
function verifySignature(dbPath, sigPath, keyOrPath) {
  try {
    const pub = typeof keyOrPath === 'string'
      ? crypto.createPublicKey(fs.readFileSync(keyOrPath)) : keyOrPath;
    const ok = crypto.verify(null, Buffer.from(sha256File(dbPath), 'ascii'), pub, fs.readFileSync(sigPath));
    return ok ? true : 'signature does not verify against the pinned key';
  } catch (e) { return `${e.name}: ${e.message}`; }
}

class Seed {
  constructor(dbPath, report) {
    this.path = dbPath; this.report = report; this.meta = report.meta;
    this.db = new Database(dbPath, { readonly: true, fileMustExist: true });
    this._cache = new Map();
  }
  package(name) {
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
  return new Seed(dbPath, rep);
}

export {
  SUPPORTED_SCHEMA_VERSIONS, SUPPORTED_SEED_CONTRACT_VERSIONS, IMPLEMENTED_DETECTION_CONTRACT,
  REQUIRED_TABLES, SUPPORTED_RULE_VERSIONS, REQUIRED_BINDING_KEYS,
  TRUST_AUTHENTICATED, TRUST_UNSIGNED_DEV, TRUST_MODES,
  CANDIDATE_SPEC, CANDIDATE_REQUIRED, PROVIDER_CLASSES,
  SeedRefused, CandidateRejected, sha256File, validateField, candidateFromMapping,
  verify, verifySignature, Seed, openSeed,
};


// A default export as well: the consumer is used both as `import R from` and
// `import { verify } from`, and the runtime package is ESM.
export default { SUPPORTED_SCHEMA_VERSIONS, SUPPORTED_SEED_CONTRACT_VERSIONS,
  IMPLEMENTED_DETECTION_CONTRACT, REQUIRED_TABLES, SUPPORTED_RULE_VERSIONS,
  REQUIRED_BINDING_KEYS, TRUST_AUTHENTICATED, TRUST_UNSIGNED_DEV, TRUST_MODES, CANDIDATE_SPEC,
  CANDIDATE_REQUIRED, PROVIDER_CLASSES, SeedRefused, CandidateRejected, sha256File,
  validateField, candidateFromMapping, verify, verifySignature, Seed, openSeed
};