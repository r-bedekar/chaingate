import { homedir } from 'node:os';
import { join } from 'node:path';
import { readConfigStrict, validateConfig, requireCompletePolicy,
  ConfigUnreadable } from '../config-store.js';
import { resolveActiveBundle, verifyBundleDir } from '../cli/seed-bundle.js';

const DEFAULTS = {
  port: 6173,
  host: '127.0.0.1',
  upstream: 'https://registry.npmjs.org',
  headersTimeoutMs: 10_000,
  bodyTimeoutMs: 30_000,
  witnessDbPath: join(homedir(), '.chaingate', 'witness.db'),
  releaseAgeHours: 72,
  // The v3 detection seed. It is NOT the witness DB: `chaingate init` copies a v1 seed over the
  // witness database, but a v3 seed has none of the version-level tables the runtime writes, so it
  // ships alongside and is opened READ-ONLY. Absent by default -- the v3 path is opt-in.
  seedV3Path: null,
  // Trust mode for that seed. `authenticated` requires a verifying signature; the development mode
  // must be asked for by name, and the proxy says so at startup.
  seedV3Trust: 'authenticated',
  // The two genuinely unlocked policy choices (CFT-05 §3). Unset means policy declines to decide,
  // which is NOT an allow.
  policyOnUnusableInput: null,
  policyOnNoEvidence: null,
};

// The domain version count is INTERNAL and is not an operator setting. It is a package-scoped
// quantity the writer computes, and a packument carries exactly that population, so the runtime
// derives it from the document in hand. There is no number to enter and no switch to set: an
// operator cannot be expected to know how many versions of a package were published from a domain,
// and a wrong answer silently changes provider_class.
const DOMAIN_VERSION_COUNT_SOURCE = 'from-packument';

function toInt(name, value, fallback) {
  if (value == null || value === '') return fallback;
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`${name} must be a positive integer, got ${value}`);
  }
  return n;
}

/** Like toInt, but 0 is VALID — it is the value an operator states for an unavailable domain count,
 *  and it is not "unknown": it asserts the domain has no other versions. */
function toNonNegativeInt(name, value) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0) {
    throw new Error(`${name} must be a non-negative integer, got ${value}`);
  }
  return n;
}

/**
 * What this host is configured to do, resolved ONCE.
 *
 * `seeds/active` is the single record of which bundle is active. It is resolved to a concrete
 * directory here and that directory is pinned for the life of the process: opening the database,
 * its digest sidecar and its signature as three separate traversals of the symlink would let an
 * activation landing between them serve one bundle's database against another's digest, and an
 * atomic swap of the link does not prevent that — the race is across opens, not within one.
 *
 * Configuration holds the operator's POLICY only. Identity and trust come from the bundle.
 */
function readPersisted(env) {
  const base = env.CHAINGATE_HOME || join(homedir(), '.chaingate');
  const file = join(base, 'config.json');
  const cfg = readConfigStrict(file);                     // throws ConfigUnreadable if damaged
  const active = resolveActiveBundle(base);

  const empty = { source: cfg ? file : null, base, seedV3Path: null, seedV3Trust: null,
    seedV3BundleDir: null, seedV3BundleId: null, seedV3Expected: null,
    policyOnUnusableInput: null, policyOnNoEvidence: null };
  if (!active) return empty;

  // The bundle says what it is; it is verified through the PINNED directory.
  const verdict = verifyBundleDir(active.dir);
  if (!verdict.ok) {
    throw new ConfigUnreadable(join(base, 'seeds', 'active'),
      `the active bundle ${active.id} is not usable: ${verdict.why}`);
  }
  const policy = validateConfig(cfg || {}, file).policy;
  requireCompletePolicy(policy, file);

  return {
    source: file,
    base,
    seedV3Path: active.files.db,                    // inside the PINNED directory, not via the link
    seedV3Trust: verdict.identity.trust,
    seedV3BundleDir: active.dir,
    seedV3BundleId: verdict.identity.bundle_id,
    seedV3Expected: verdict.identity,
    policyOnUnusableInput: policy.on_unusable_input,
    policyOnNoEvidence: policy.on_no_evidence,
  };
}

export function loadConfig(env = process.env, overrides = {}) {
  const persisted = readPersisted(env);
  const base = {
    port: toInt('CHAINGATE_PORT', env.CHAINGATE_PORT, DEFAULTS.port),
    host: env.CHAINGATE_HOST ?? DEFAULTS.host,
    upstream: (env.CHAINGATE_UPSTREAM ?? DEFAULTS.upstream).replace(/\/+$/, ''),
    headersTimeoutMs: toInt(
      'CHAINGATE_UPSTREAM_HEADERS_TIMEOUT_MS',
      env.CHAINGATE_UPSTREAM_HEADERS_TIMEOUT_MS ?? env.CHAINGATE_UPSTREAM_TIMEOUT_MS,
      DEFAULTS.headersTimeoutMs,
    ),
    bodyTimeoutMs: toInt(
      'CHAINGATE_UPSTREAM_BODY_TIMEOUT_MS',
      env.CHAINGATE_UPSTREAM_BODY_TIMEOUT_MS,
      DEFAULTS.bodyTimeoutMs,
    ),
    witnessDbPath: env.CHAINGATE_WITNESS_DB ?? DEFAULTS.witnessDbPath,
    releaseAgeHours: toInt(
      'CHAINGATE_RELEASE_AGE_HOURS',
      env.CHAINGATE_RELEASE_AGE_HOURS,
      DEFAULTS.releaseAgeHours,
    ),
    // PERSISTED configuration first, environment as an override. With no CHAINGATE_* set at all
    // the proxy still starts with whatever `chaingate init` recorded -- the shell that happens to
    // launch it does not decide how it behaves.
    seedV3Path: env.CHAINGATE_SEED_V3 || persisted.seedV3Path,
    seedV3Trust: env.CHAINGATE_SEED_V3_TRUST || persisted.seedV3Trust || DEFAULTS.seedV3Trust,
    seedV3BundleId: persisted.seedV3BundleId,
    seedV3BundleDir: persisted.seedV3BundleDir,
    seedV3Expected: persisted.seedV3Expected,
    policyOnUnusableInput:
      env.CHAINGATE_POLICY_ON_UNUSABLE_INPUT || persisted.policyOnUnusableInput,
    policyOnNoEvidence: env.CHAINGATE_POLICY_ON_NO_EVIDENCE || persisted.policyOnNoEvidence,
    domainVersionCount: DOMAIN_VERSION_COUNT_SOURCE,
    configSource: persisted.source,
    chaingateBase: persisted.base,
  };
  return { ...base, ...overrides };
}

export { ConfigUnreadable };
