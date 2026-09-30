// U-01 — build one check record: `chaingate.check/2` since 0.1.3 (U-05 Amendment 1), `/1` before.
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

export const CHECK_SCHEMA_ID = 'chaingate.check/2';

/**
 * The combinations a check record may carry, one per schema (U-05 Amendment 1). 0.1.3 writes only /2; /1 records are
 * what 0.1.2 and earlier wrote, and are still read. Anything else -- including a /1 record claiming policy 1.1 or a
 * 1.1 seed, which no release ever wrote -- is refused by name, never guessed at.
 */
export const SUPPORTED_RECORDS = Object.freeze({
  'chaingate.check/1': Object.freeze({ explain_version: 'chaingate-explain-1', policy_version: 'cft-policy-1.0',
    detection_contract_version: 'cft-detection-contract-1.0', seed_contract_versions: ['cft-seed-v3-contract-1.0'] }),
  'chaingate.check/2': Object.freeze({ explain_version: 'chaingate-explain-2', policy_version: 'cft-policy-1.1',
    detection_contract_version: 'cft-detection-contract-1.0',
    seed_contract_versions: ['cft-seed-v3-contract-1.0', 'cft-seed-v3-contract-1.1'] }),
});
export const CHECK_SCHEMA_IDS = Object.freeze(Object.keys(SUPPORTED_RECORDS));

/**
 * Why a saved record is not one this runtime reads, or [] when it is. Checks the version combination, and that a
 * refused explanation's `decided_by` (/2) is exactly the decision's deciding rows -- the structured attribution must
 * say what the decision says. Shape is the schema's job; this is about meaning.
 */
export function recordCompatibility(rec) {
  if (!rec || typeof rec !== 'object') return ['the record is not an object'];
  if (typeof rec.schema !== 'string' || !Object.hasOwn(SUPPORTED_RECORDS, rec.schema)) {
    return [`schema ${JSON.stringify(rec.schema ?? null)} is not supported (supported: ${CHECK_SCHEMA_IDS.join(', ')})`];
  }
  if (rec.result === 'tool_error') return [];
  const want = SUPPORTED_RECORDS[rec.schema];
  const p = [];
  const got = (v) => JSON.stringify(v ?? null);
  const d = rec.decision || {};
  const s = rec.explanation && rec.explanation.structured ? rec.explanation.structured : {};
  if (d.policy_version !== want.policy_version) {
    p.push(`decision.policy_version ${got(d.policy_version)}: ${rec.schema} records carry ${want.policy_version}`);
  }
  if (s.explain_version !== want.explain_version) {
    p.push(`explanation.structured.explain_version ${got(s.explain_version)}: ${rec.schema} records carry ${want.explain_version}`);
  }
  if (!want.seed_contract_versions.includes(rec.seed && rec.seed.contract_version)) {
    p.push(`seed.contract_version ${got(rec.seed && rec.seed.contract_version)}: ${rec.schema} records carry `
      + `${want.seed_contract_versions.join(' or ')}`);
  }
  if (rec.result === 'evaluated' && (!rec.finding || rec.finding.contract_version !== want.detection_contract_version)) {
    p.push(`finding.contract_version ${got(rec.finding && rec.finding.contract_version)}: ${rec.schema} records carry `
      + `${want.detection_contract_version}`);
  }
  if (rec.result === 'refused') {
    const has = Object.hasOwn(s, 'decided_by');
    if (rec.schema === 'chaingate.check/1' && has) {
      p.push('explanation.structured.decided_by is not a member of a chaingate.check/1 refused explanation');
    }
    if (rec.schema === 'chaingate.check/2') {
      const deciding = (Array.isArray(d.results) ? d.results : []).filter((x) => x && x.result === d.disposition)
        .map((x) => ({ gate: x.gate, detail: x.detail }));
      if (!has || !Array.isArray(s.decided_by)) p.push('explanation.structured.decided_by is missing');
      else if (JSON.stringify(s.decided_by.map((x) => ({ gate: x && x.gate, detail: x && x.detail })))
        !== JSON.stringify(deciding)) {
        p.push("explanation.structured.decided_by does not match the decision's deciding rows");
      }
    }
  }
  return p;
}
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
