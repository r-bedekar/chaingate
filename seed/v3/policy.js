// CFT-05 — the POLICY contract. Versioned SEPARATELY from the detection contract, and deliberately
// so: detection says what was observed, policy says what to do about it, and the two move at
// different speeds. A finding carries evidence and coverage and NO disposition (CFT-03 D, LOCKED).
// This module is the only place where evidence becomes an action, it never writes back into a
// finding, and nothing in the detection path imports it.
//
// WHAT IS ALREADY LOCKED, and therefore is not re-decided here
// ------------------------------------------------------------
// The shipped pilot (`gates/index.js`, D1) fixes the shape and the arithmetic:
//
//   * four per-gate result values: ALLOW / SKIP / WARN / BLOCK, and three dispositions:
//     ALLOW / WARN / BLOCK;
//   * aggregation: any BLOCK -> BLOCK, else any WARN -> WARN, else ALLOW. SKIP does not count and
//     never escalates;
//   * N-warnings-escalate-to-BLOCK was REMOVED to prevent cry-wolf, so a pattern-derived signal
//     warns and does not block;
//   * "any BLOCK in results is a true-positive-by-construction signal" — a BLOCK must rest on a
//     recorded fact about this exact artifact, not on an inference from history;
//   * an override short-circuits to ALLOW without running anything;
//   * insufficient history is SKIP (first-seen poisoning protection), not a pass and not a block.
//
// Channel-A and the DAC trajectory are both threshold-over-history rules — inference, not recorded
// fact — so under the locked criterion they WARN. A `known_malicious_pins` row is the other kind:
// it names this package at this exact version in a recorded advisory, which is what
// true-positive-by-construction means, so it blocks on the same criterion that lets content-hash
// block. Neither of those is an open choice; both follow from rules already in force.
//
// WHAT IS GENUINELY OPEN, and therefore is NOT decided here
// ---------------------------------------------------------
// Two questions the pilot never had to answer, because it had no notion of an evidence artifact
// that could be untrustworthy or silent:
//
//   on_unusable_input   the seed was refused, or the candidate was rejected. There is NO finding.
//   on_no_evidence      a finding exists but nothing in it was evaluated (an uncovered package, a
//                       cold start, a stale seed).
//
// D1's fail-open covers ONE broken gate among several that still produced evidence. Extending it to
// "the whole evidence source is unusable" would be a new policy, and inventing it here is exactly
// the move that turns missing evidence into a clean result. So this module REFUSES TO DECIDE until
// an operator sets them, and says which ones are unset. A refusal to decide is not an ALLOW.

import K from './contract.js';

const POLICY_CONTRACT_VERSION = 'cft-policy-1.0';
const IMPLEMENTED_DETECTION_CONTRACT = K.CONTRACT_VERSION;

const ALLOW = 'ALLOW';
const WARN = 'WARN';
const BLOCK = 'BLOCK';
const SKIP = 'SKIP';
const DISPOSITIONS = Object.freeze([ALLOW, WARN, BLOCK]);

/** The two genuinely unlocked choices, with the values an operator may pick and what each means. */
const OPEN_CHOICES = Object.freeze({
  on_unusable_input: {
    question: 'The seed was refused or the candidate rejected, so no finding exists. What then?',
    values: {
      BLOCK: 'fail closed: treat an unusable evidence source as a reason to refuse the release',
      WARN: 'proceed, but never silently: the decision records that nothing was checked',
      REFUSE_TO_DECIDE: 'return no disposition at all and let the caller decide; the default',
    },
    why_open: 'D1 fails open for ONE broken gate among several that still produced evidence. It '
      + 'never ruled on the whole evidence source being unusable.',
  },
  on_no_evidence: {
    question: 'A finding exists but nothing in it was evaluated (uncovered package, cold start, '
      + 'stale seed). What then?',
    values: {
      WARN: 'surface it: a release nobody could check is not a release that checked out',
      ALLOW: 'treat absence of evidence as absence of a problem, as D1 does for a skipped gate',
      REFUSE_TO_DECIDE: 'return no disposition at all; the default',
    },
    why_open: 'D1 SKIPs a gate it cannot run and lets the rest decide. Here there is no rest.',
  },
});
const OPEN_CHOICE_KEYS = Object.freeze(Object.keys(OPEN_CHOICES));

class PolicyConfigInvalid extends Error {
  constructor(msg) { super(msg); this.name = 'PolicyConfigInvalid'; }
}

/**
 * Validate an operator's policy configuration. Unset is allowed and means "refuse to decide"; an
 * unrecognised key or value is not, because a typo must never read as a chosen policy.
 */
function normaliseConfig(config = {}) {
  if (config === null || typeof config !== 'object' || Array.isArray(config)) {
    throw new PolicyConfigInvalid('policy config must be an object');
  }
  const unknown = Object.keys(config).filter((k) => !(k in OPEN_CHOICES));
  if (unknown.length) {
    throw new PolicyConfigInvalid(`unknown policy choices [${unknown.sort().join(', ')}]; this `
      + `policy version has exactly [${OPEN_CHOICE_KEYS.join(', ')}]`);
  }
  const out = {};
  for (const k of OPEN_CHOICE_KEYS) {
    const v = config[k] === undefined ? 'REFUSE_TO_DECIDE' : config[k];
    if (!(v in OPEN_CHOICES[k].values)) {
      throw new PolicyConfigInvalid(`${k}=${JSON.stringify(v)} is not one of `
        + `[${Object.keys(OPEN_CHOICES[k].values).join(', ')}]`);
    }
    out[k] = v;
  }
  return out;
}

const r = (gate, result, detail) => ({ gate, result, detail });

/** D1's aggregation, unchanged: any BLOCK -> BLOCK, else any WARN -> WARN, else ALLOW. */
function aggregate(results) {
  if (results.some((x) => x.result === BLOCK)) return BLOCK;
  if (results.some((x) => x.result === WARN)) return WARN;
  return ALLOW;
}

/**
 * Every group and predicate a finding could not evaluate, with the reason it gives.
 *
 * When the caller states that Channel-A could not be PLACED, its reason replaces the checker's.
 * The checker reports `uncovered_package` whenever it cannot find the lineage, which is a false
 * statement about a package the seed covers; the caller knows which of the FU-2 outcomes actually
 * applies and says so. The finding itself is never rewritten -- this is policy's record, not the
 * detection contract's.
 */
function notEvaluated(finding, placement = null) {
  const out = [];
  const unplaced = placement && placement.channel_a_usable === false;
  const scan = (where, obj, override) => {
    for (const [name, tri] of Object.entries(obj || {})) {
      if (override) out.push({ where, name, reason: override, stated_by: 'placement' });
      else if (tri && tri.coverage !== K.EVALUATED) out.push({ where, name, reason: tri.reason ?? null });
    }
  };
  const channelAReason = unplaced ? (placement.reason || placement.kind) : null;
  scan('channel_a.group', finding.channel_a.groups, channelAReason);
  scan('channel_a.publisher_constituent', finding.channel_a.publisher_constituents, channelAReason);
  scan('dac_trajectory.predicate', finding.dac_trajectory.predicates, null);
  return out;
}

/** Turn one aggregate's thresholds into gate results. Determinacy is not decoration: an
 *  indeterminate threshold is a "could not tell", which SKIPs and marks the evidence incomplete. */
function thresholdResults(prefix, agg) {
  const out = [];
  for (const t of agg.thresholds) {
    const [lo, hi] = t.interval;
    const name = `${prefix}:${t.name}`;
    if (t.threshold_determinacy === 'determinate' && t.threshold_result === true) {
      out.push(r(name, WARN, `${agg.n_broke}/${agg.M} witnesses broke, threshold ${t.threshold} `
        + '(threshold over history: warns, never blocks — D1)'));
    } else if (t.threshold_determinacy === 'determinate') {
      out.push(r(name, ALLOW, `${agg.n_broke}/${agg.M} broke, threshold ${t.threshold} cannot be `
        + `reached (retained interval [${lo}, ${hi}])`));
    } else {
      out.push(r(name, SKIP, `indeterminate: ${agg.n_unevaluable} of ${agg.M} unevaluable, retained `
        + `interval [${lo}, ${hi}] spans threshold ${t.threshold} — NOT a clean result`));
    }
  }
  return out;
}

/**
 * Map one finding (plus any recorded pin for the same package and version) to a disposition.
 *
 * @param {object|null} finding   a CFT-03 finding, or null when there is none
 * @param {object} ctx
 *   ctx.pin        a known_malicious_pins row for THIS package and version, or null
 *   ctx.refusal    the SeedRefused / CandidateRejected that prevented evaluation, or null
 *   ctx.config     the operator's answers to OPEN_CHOICES
 *   ctx.override   an override row (D1 short-circuit), or null
 * @returns {object} a decision. `disposition` is null when policy declines to decide; it is never
 *   ALLOW merely because something could not be established.
 */
function decide(finding, ctx = {}) {
  const { pin = null, refusal = null, override = null } = ctx;
  const config = normaliseConfig(ctx.config || {});
  const base = {
    placement: null,
    channel_a_usable: null,
    policy_version: POLICY_CONTRACT_VERSION,
    detection_contract_version: finding ? finding.contract_version : null,
    package: finding ? finding.candidate.package : (ctx.packageName ?? null),
    version: finding ? finding.candidate.version : (ctx.version ?? null),
    // Read from the FINDING, so a decision record shows which provider class the evidence carried.
    // It is derived from a domain version count the consumer supplies or computes, and a recorded
    // decision that omits it cannot be re-read later to see which classification applied.
    provider_class: finding ? (finding.candidate.provider_class ?? null) : null,
    seed: finding ? finding.seed : null,
    override: null,
    undecided: [],
  };

  // D1: an override short-circuits to ALLOW and nothing else runs. Kept verbatim, including that it
  // outranks a pin — an operator who has pinned an exception has made a decision policy must honour
  // and record, not quietly reverse.
  if (override) {
    const reason = override.reason ?? '(no reason)';
    return {
      ...base,
      disposition: ALLOW,
      results: [r('override', ALLOW, `override: ${reason}`)],
      evidence_complete: false,
      not_evaluated: [{ where: 'policy', name: 'override', reason: 'gates did not run' }],
      override: { reason, created_at: override.created_at ?? null },
    };
  }

  // 1. UNSUPPORTED INPUT or TRUST FAILURE. There is no finding, so there is nothing to be clean.
  if (refusal || !finding) {
    const detail = refusal
      ? `${refusal.name || 'refused'}: ${(refusal.reasons || [refusal.message]).join('; ')}`
      : 'no finding was produced';
    const choice = config.on_unusable_input;
    const results = [r('seed-v3:input', choice === 'BLOCK' ? BLOCK : (choice === 'WARN' ? WARN : SKIP),
      detail)];
    return {
      ...base,
      disposition: choice === 'REFUSE_TO_DECIDE' ? null : aggregate(results),
      results,
      evidence_complete: false,
      not_evaluated: [{ where: 'policy', name: 'input', reason: detail }],
      undecided: choice === 'REFUSE_TO_DECIDE' ? ['on_unusable_input'] : [],
    };
  }

  // A finding produced under a detection contract this policy version was not written against is an
  // unsupported input too: the field meanings are exactly what policy is reading.
  if (finding.contract_version !== IMPLEMENTED_DETECTION_CONTRACT) {
    const detail = `finding declares detection contract ${finding.contract_version}; this policy `
      + `implements ${IMPLEMENTED_DETECTION_CONTRACT}`;
    const choice = config.on_unusable_input;
    const results = [r('seed-v3:input', choice === 'BLOCK' ? BLOCK : (choice === 'WARN' ? WARN : SKIP),
      detail)];
    return {
      ...base,
      disposition: choice === 'REFUSE_TO_DECIDE' ? null : aggregate(results),
      results,
      evidence_complete: false,
      not_evaluated: [{ where: 'policy', name: 'detection_contract_version', reason: detail }],
      undecided: choice === 'REFUSE_TO_DECIDE' ? ['on_unusable_input'] : [],
    };
  }

  // PLACEMENT. Channel-A compares a release against its predecessor in a lineage; the DAC
  // trajectory reads prior versions across the whole package by publication time and never needs a
  // lineage; an advisory pin names an exact version and needs neither. So an unresolved placement
  // costs Channel-A and NOTHING ELSE -- discarding the finding wholesale would throw away results
  // that remain independently evaluable.
  const placement = ctx.placement || null;
  const channelAUsable = !placement || placement.channel_a_usable !== false;
  const missing = notEvaluated(finding, placement);
  const results = [];

  // 2. KNOWN-MALWARE PIN — a recorded advisory naming this exact version. Locked criterion, not a
  //    choice: this is the same true-positive-by-construction standard that lets content-hash block.
  if (pin) {
    results.push(r('seed-v3:known-malicious-pin', BLOCK,
      `recorded advisory ${pin.advisory_id} pins ${base.package}@${base.version}`
      + `${pin.source ? ` (source ${pin.source})` : ''}`));
  } else {
    results.push(r('seed-v3:known-malicious-pin', ALLOW, 'no recorded advisory pins this version'));
  }

  // 3. TRAJECTORY AND CHANNEL-A THRESHOLDS — inference over history, so WARN at most.
  if (channelAUsable) {
    results.push(...thresholdResults('seed-v3:channel-a', finding.channel_a));
  } else {
    // NOT a clean result, and not a threshold result either: the comparison did not happen.
    results.push(r('seed-v3:channel-a', SKIP,
      `not evaluated — ${placement.reason || placement.kind}. Channel-A compares this release `
      + 'against its lineage predecessor, and this release could not be placed; the thresholds in '
      + 'the finding are over an empty comparison and are NOT used.'));
  }
  results.push(...thresholdResults('seed-v3:dac-trajectory', finding.dac_trajectory));

  // 4. INCOMPLETE EVIDENCE. Never folded into the disposition silently: it is a SKIP with the
  //    reasons named, it sets evidence_complete=false, and when NOTHING was evaluated the
  //    disposition itself is an open question rather than an ALLOW by default.
  // What counts as "something was evaluated" must ignore a Channel-A aggregate the placement just
  // invalidated, or an unplaced release would look evidenced when only the discarded half was.
  const evaluatedAnything = (channelAUsable && finding.channel_a.n_evaluable > 0)
    || finding.dac_trajectory.n_evaluable > 0;
  if (missing.length) {
    const reasons = [...new Set(missing.map((m) => m.reason))].sort();
    results.push(r('seed-v3:coverage', SKIP,
      `${missing.length} of ${finding.channel_a.M + K.PUBLISHER_CONSTITUENTS.length
        + finding.dac_trajectory.M} observations NOT_EVALUATED (${reasons.join(', ')})`));
  }
  const undecided = [];
  let disposition = aggregate(results);
  if (!evaluatedAnything) {
    const choice = config.on_no_evidence;
    if (choice === 'REFUSE_TO_DECIDE') {
      undecided.push('on_no_evidence');
      // A pin is a recorded fact and stands on its own even with no history to evaluate.
      disposition = pin ? BLOCK : null;
    } else if (choice === WARN) {
      results.push(r('seed-v3:coverage', WARN, 'nothing in this finding was evaluated'));
      disposition = aggregate(results);
    }
    // ALLOW: D1's fail-open, chosen explicitly by an operator rather than arrived at by omission.
  }

  return {
    ...base,
    disposition,
    results,
    placement: placement ? placement.kind : null,
    channel_a_usable: channelAUsable,
    evidence_complete: missing.length === 0,
    not_evaluated: missing,
    undecided,
  };
}

/** Look up a recorded advisory pin for one package and version. Read-only, and its own query so the
 *  detection path never has to know this table exists. */
function pinFor(seed, packageName, version) {
  const row = seed.db.prepare(
    'SELECT k.advisory_id AS advisory_id, k.source AS source FROM known_malicious_pins k '
    + 'JOIN packages p ON p.id = k.package_id WHERE p.package_name = ? AND k.version = ? LIMIT 1',
  ).get(packageName, version);
  return row || null;
}

export {
  POLICY_CONTRACT_VERSION, IMPLEMENTED_DETECTION_CONTRACT, DISPOSITIONS, OPEN_CHOICES,
  OPEN_CHOICE_KEYS, PolicyConfigInvalid, normaliseConfig, aggregate, notEvaluated,
  thresholdResults, decide, pinFor, ALLOW, WARN, BLOCK, SKIP,
};
export default {
  POLICY_CONTRACT_VERSION, IMPLEMENTED_DETECTION_CONTRACT, DISPOSITIONS, OPEN_CHOICES,
  OPEN_CHOICE_KEYS, PolicyConfigInvalid, normaliseConfig, aggregate, notEvaluated,
  thresholdResults, decide, pinFor, ALLOW, WARN, BLOCK, SKIP,
};
