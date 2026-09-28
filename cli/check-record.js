// U-01 — build one `chaingate.check/1` record.
//
// Three shapes, and an absent member is OMITTED, never null-filled (plan §3.7):
//   evaluated   seed, candidate, finding, decision, effective, explanation
//   refused     seed, decision, effective, explanation        (no candidate, no finding: none exists)
//   tool_error  error                                          (nothing was evaluated)
//
// The evaluation itself is `evaluateCandidate` from seed/v3/gate.js — the gate's own path, so a
// check and an install decide the same way by construction. Nothing here re-decides anything.
//
// THE OVERRIDE RULE, one rule for the CLI and the consumer: `decision.disposition` is always the
// evaluated one and is never rewritten. `effective.action` is ALLOW with basis "override" and the
// override's provenance when an exact-version override exists; otherwise it is the evaluated
// disposition with basis "evaluation". The exit code follows `effective.action`.
import { createHash } from 'node:crypto';
import G from '../seed/v3/gate.js';
import { explain } from '../seed/v3/explain.js';

export const CHECK_SCHEMA_ID = 'chaingate.check/1';
export const RESULT = Object.freeze({ EVALUATED: 'evaluated', REFUSED: 'refused', TOOL_ERROR: 'tool_error' });
export const EXIT_FOR_ACTION = Object.freeze({ ALLOW: 0, WARN: 2, BLOCK: 3 });
export const EXIT_TOOL_ERROR = 4;

const sha256 = (s) => createHash('sha256').update(s).digest('hex');

/** Canonical JSON (sorted keys, no whitespace) — used to digest the policy configuration. */
function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
}

/** The digest of the NORMALISED policy configuration: the exact choices that decided. */
export function policyConfigSha256(normalisedConfig) {
  return sha256(canonical(normalisedConfig));
}

/** The seed identity a result is bound to, from an open reader Seed and the active bundle id. */
export function seedIdentity(seed, bundleId = null) {
  const r = seed.report;
  return {
    bundle_id: bundleId,
    sha256: r.content_sha256,
    trust: r.trust_mode,
    authenticated: r.authenticated === true,
    contract_version: seed.meta.contract_version,
    rule_versions: seed.meta.rule_versions,
    corpus_snapshot_digest: seed.meta.corpus_snapshot_digest,
  };
}

/**
 * The gate input the proxy derives from a packument document (plan §3.3): `versions[ver]` as the
 * raw manifest, `time[ver]` as publishedAt (absent -> undefined, which the gate passes as null),
 * `versions{}` as rawVersions. Nothing is synthesized: a version the document does not carry has no
 * manifest, and the gate refuses it exactly as it refuses a missing manifest.
 */
export function inputFromPackument(doc, packageName, version) {
  const versions = doc && typeof doc.versions === 'object' && doc.versions !== null
    && !Array.isArray(doc.versions) ? doc.versions : undefined;
  const time = doc && typeof doc.time === 'object' && doc.time !== null ? doc.time : {};
  const own = (o, k) => o !== undefined && Object.prototype.hasOwnProperty.call(o, k);
  return {
    packageName,
    version,
    rawManifest: own(versions, version) ? versions[version] : undefined,
    publishedAt: own(time, version) ? time[version] : undefined,
    rawVersions: versions,
  };
}

/** Apply the one override rule. */
export function effectiveFrom(disposition, override) {
  if (override) {
    return { action: 'ALLOW', basis: 'override', override: {
      reason: override.reason ?? '(no reason)', created_at: override.created_at ?? null, scope: 'exact-version' } };
  }
  return { action: disposition, basis: 'evaluation' };
}

function common(tool, request) {
  return { schema: CHECK_SCHEMA_ID, result: null, tool: { name: tool.name, version: tool.version }, request };
}

/** A tool error: nothing was evaluated, so nothing but the error is reported. */
export function toolErrorRecord({ tool, request, code, message }) {
  const rec = common(tool, request);
  rec.result = RESULT.TOOL_ERROR;
  rec.error = { code, message };
  return rec;
}

/**
 * Evaluate one candidate and build its record.
 *
 * @param {object} a
 *   a.seed               an open reader Seed (read-only)
 *   a.bundleId           the active bundle id, or null when the seed was named directly
 *   a.policy             the operator's policy configuration (both open choices set)
 *   a.domainVersionCount 'from-packument', as the proxy wires it
 *   a.input              the gate input (see inputFromPackument)
 *   a.request            { package, version, source? }
 *   a.override           the exact-version override row, or null
 *   a.tool               { name, version }
 */
export function buildCheckRecord({ seed, bundleId = null, policy, domainVersionCount, input, request,
  override = null, tool }) {
  const normalised = G.validateEvaluationConfig({ config: policy, domainVersionCount });
  const { decision, finding, placement } = G.evaluateCandidate(seed, { config: policy, domainVersionCount },
    input);
  if (decision.disposition === null) {
    // Unreachable: validateEvaluationConfig refuses an unresolved policy. Named rather than assumed,
    // because silence here would read as permission.
    throw new Error(`policy returned no disposition ([${decision.undecided.join(', ')}] unresolved)`);
  }

  const rec = common(tool, request);
  rec.result = finding ? RESULT.EVALUATED : RESULT.REFUSED;
  rec.seed = seedIdentity(seed, bundleId);
  if (finding) {
    rec.candidate = {
      candidate_digest: finding.candidate.candidate_digest,
      placement: { kind: placement.kind, reason: placement.reason, lineage_id: placement.lineage_id,
        ord: placement.ord, channel_a_usable: placement.channel_a_usable },
    };
    rec.finding = finding;
  }
  rec.decision = {
    policy_version: decision.policy_version,
    policy_config_sha256: policyConfigSha256(normalised),
    disposition: decision.disposition,
    results: decision.results,
    evidence_complete: decision.evidence_complete,
    not_evaluated: decision.not_evaluated,
  };
  rec.effective = effectiveFrom(decision.disposition, override);
  rec.explanation = explain(rec);
  return rec;
}

/** The exit code a record implies: it follows `effective.action`. */
export function exitCodeFor(rec) {
  if (rec.result === RESULT.TOOL_ERROR) return EXIT_TOOL_ERROR;
  const code = EXIT_FOR_ACTION[rec.effective.action];
  return code === undefined ? EXIT_TOOL_ERROR : code;
}
