// The ChainGate configuration file: ONE validator, used by the CLI and by the proxy.
//
// These two used to disagree. The CLI's reader returned `null` for anything it could not parse, so a
// damaged file looked like a fresh install; the proxy had its own stricter check added later. A file
// that one half accepts and the other rejects is worse than either rule on its own, because which
// behaviour you get depends on which program looked at it. So there is one function here and both
// import it.
//
// The rule it encodes: an ABSENT file is the legitimate pre-v3 state, and anything else that cannot
// be read as a complete, consistent configuration is a REFUSAL. A host that was configured to
// enforce must never be talked out of it by a corrupt file.

import { existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { CAPS, FileRefused, readBounded } from './seed/v3/bounded-file.js';

export const CONFIG_VERSION = 1;

export const TRUST_MODES = Object.freeze(['authenticated', 'unsigned-development']);

// The two genuinely unlocked policy choices, and the values a gate that ENFORCES can
// act on. `REFUSE_TO_DECIDE` is not among them: it produces no disposition, and the runner cannot
// tell that apart from permission.
export const POLICY_VALUES = Object.freeze({
  on_unusable_input: Object.freeze(['BLOCK', 'WARN']),
  on_no_evidence: Object.freeze(['WARN', 'ALLOW']),
});
export const DEFAULT_POLICY = Object.freeze({
  on_unusable_input: 'BLOCK',
  on_no_evidence: 'WARN',
});

export class ConfigUnreadable extends Error {
  constructor(file, why) {
    super(`chaingate: configuration at ${file} is not usable: ${why}\n`
      + '  A host that HAS been configured must not fall back to "no seed configured": that turns\n'
      + '  a damaged file into silently disabled detection.\n'
      + '  Fix: repair the file, or re-run `chaingate init --seed <bundle>` to rewrite it.');
    this.name = 'ConfigUnreadable';
    this.file = file;
    this.why = why;
  }
}

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isObjOnly = isObj;
/** 0.1.6: the published advisory feed, used when the configuration names none (`"advisory_feed": false` turns it off). */
export const DEFAULT_ADVISORY_FEED_URL = 'https://raw.githubusercontent.com/cgsec-labs/chaingate-pins/main/pins/';

/** 0.1.6: the published seed cache host (buckets of the seed under a signed root); `"seed_cache": false` turns it off. */
export const DEFAULT_SEED_CACHE_URL = 'https://shards.cgsec.dev/';

export const DEFAULT_STATIC_WALK_WAIT_MS = 10_000;

export function isHttpsUrl(v) {
  if (typeof v !== 'string' || v.length > 2048) return false;
  try { const u = new URL(v); return u.protocol === 'https:' && !u.username && !u.password && !u.search && !u.hash; } catch { return false; }
}

/**
 * Validate a parsed configuration. Throws `ConfigUnreadable` on anything that would leave the CLI
 * and the proxy disagreeing.
 *
 * @returns {{policy: {on_unusable_input: string|null, on_no_evidence: string|null}}}
 */
export function validateConfig(cfg, file = '(in memory)') {
  const bad = (why) => { throw new ConfigUnreadable(file, why); };
  if (!isObj(cfg)) bad('top level is not an object');
  if (cfg.config_version !== undefined && !Number.isInteger(cfg.config_version)) {
    bad('config_version is not an integer');
  }

  // NOTE WHAT IS *NOT* HERE. The identity and trust of the active seed are deliberately absent:
  // `seeds/active` is the one record of which bundle is active, and the bundle's own manifest is
  // the one record of what it is. Writing either of them here as well would be a second copy of the
  // same fact, and an interrupted update would leave the two disagreeing — the split state this
  // layout exists to prevent. What lives here is the operator's POLICY, which belongs to the host
  // rather than to any bundle.
  if (cfg.seed_v3 !== undefined) {
    bad('seed_v3 no longer belongs in configuration: which bundle is active is recorded by the '
      + '`seeds/active` link, and its identity by that bundle\'s manifest. Re-run '
      + '`chaingate init --seed <bundle>` to migrate.');
  }

  const policy = cfg.policy;
  if (policy !== undefined && policy !== null && !isObj(policy)) bad('policy is not an object');
  const resolved = {};
  for (const [k, values] of Object.entries(POLICY_VALUES)) {
    const v = policy?.[k];
    if (v === undefined || v === null) { resolved[k] = null; continue; }
    if (!values.includes(v)) {
      bad(`policy.${k} must be one of ${values.join(' or ')}, got ${JSON.stringify(v)}`);
    }
    resolved[k] = v;
  }

  // Optional bounds on the proxy's in-memory record of BLOCKs it could not store. Only their type is
  // checked here; the proxy checks the ranges when it starts and refuses to start, by name, on a bad value.
  const caps = {};
  for (const [key, out] of [['unstored_block_cap_entries', 'entries'], ['unstored_block_cap_bytes', 'bytes']]) {
    const v = cfg[key];
    if (v === undefined || v === null) { caps[out] = null; continue; }
    if (!Number.isInteger(v)) bad(`${key} must be an integer, got ${JSON.stringify(v)}`);
    caps[out] = v;
  }

  // 0.1.5: the per-user switch that holds an armed download while the tarball static checks read it. Off by default;
  // anything but a boolean refuses, so a typo can never switch it on or off silently.
  const sw = cfg.static_withhold;
  if (sw !== undefined && sw !== null && typeof sw !== 'boolean') {
    bad(`static_withhold must be true or false, got ${JSON.stringify(sw)}`);
  }

  // 0.1.6: how long a download waits for a tarball-check walk slot when all are busy, in milliseconds (default 10 s); past it
  // the download is served unwalked and read at its next download. 0 never waits.
  const ww = cfg.static_walk_wait_ms;
  if (ww !== undefined && ww !== null && !(Number.isInteger(ww) && ww >= 0 && ww <= 60_000)) {
    bad(`static_walk_wait_ms must be a whole number of milliseconds from 0 to 60000, got ${JSON.stringify(ww)}`);
  }

  // 0.1.6: the advisory feed (internally the pins feed). `advisory_feed_url` is an https base URL, the published feed when unset;
  // the proxy fetches it at start and hourly unless `advisory_feed` is false. A wrong type or a URL that is not https refuses.
  const pf = cfg.advisory_feed;
  if (pf !== undefined && pf !== null && typeof pf !== 'boolean') bad(`advisory_feed must be true or false, got ${JSON.stringify(pf)}`);
  const pu = cfg.advisory_feed_url;
  if (pu !== undefined && pu !== null && !isHttpsUrl(pu)) bad(`advisory_feed_url must be an https URL, got ${JSON.stringify(pu)}`);
  const pinsFeed = { url: pu ?? DEFAULT_ADVISORY_FEED_URL, enabled: pf !== false };

  // 0.1.6: the seed cache. `seed_cache_url` is an https base URL, the published host when unset; while on, the proxy reads the
  // seed cache instead of a full seed and fetches the buckets it needs. `seed_cache: false` turns it off.
  const sc = cfg.seed_cache;
  if (sc !== undefined && sc !== null && typeof sc !== 'boolean') bad(`seed_cache must be true or false, got ${JSON.stringify(sc)}`);
  const su = cfg.seed_cache_url;
  if (su !== undefined && su !== null && !isHttpsUrl(su)) bad(`seed_cache_url must be an https URL, got ${JSON.stringify(su)}`);
  const seedCache = { url: su ?? DEFAULT_SEED_CACHE_URL, enabled: sc !== false };

  return { policy: resolved, caps, staticWithhold: sw === true, staticWalkWaitMs: ww ?? DEFAULT_STATIC_WALK_WAIT_MS, pinsFeed, seedCache };
}

/**
 * Read and validate. `null` means there is no configuration — the pre-v3 state. Anything present
 * but unusable throws.
 */
/**
 * A host with an active bundle is a host that ENFORCES, and enforcement cannot proceed on an
 * unresolved policy. The caller knows whether a bundle is active; this turns that into a refusal.
 */
export function requireCompletePolicy(policy, file = '(configuration)') {
  const missing = Object.keys(POLICY_VALUES).filter((k) => !policy?.[k]);
  if (missing.length) {
    throw new ConfigUnreadable(file,
      `a seed bundle is active but policy ${missing.join(' and ')} is unset; an unresolved policy `
      + 'produces no disposition, which enforcement cannot tell apart from permission');
  }
  return policy;
}

export function readConfigStrict(file) {
  if (!existsSync(file)) return null;
  let parsed;
  try {
    // one non-blocking descriptor, a regular file of at most CAPS.config bytes
    parsed = JSON.parse(readBounded(file, CAPS.config).toString('utf8'));
  } catch (err) {
    throw new ConfigUnreadable(file, err instanceof FileRefused ? err.why : err.message);
  }
  validateConfig(parsed, file);
  return parsed;
}

/** Write a configuration, validating it FIRST: nothing unusable is ever persisted. */
export function writeConfig(file, config) {
  const merged = { config_version: CONFIG_VERSION, ...config };
  validateConfig(merged, file);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(merged, null, 2)}\n`);
  return merged;
}
