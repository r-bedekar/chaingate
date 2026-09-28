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

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export const CONFIG_VERSION = 1;

export const TRUST_MODES = Object.freeze(['authenticated', 'unsigned-development']);

// The two genuinely unlocked policy choices (CFT-05 §3), and the values a gate that ENFORCES can
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

  return { policy: resolved };
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
    parsed = JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    throw new ConfigUnreadable(file, err.message);
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
