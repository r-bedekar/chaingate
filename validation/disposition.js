// Canonical disposition function — Section 11 step 7.
//
// Encodes the GATE CONTRACT from patterns/publisher.js as a pure,
// deterministic transformation of publisher.extract() output. No I/O,
// no randomness, no clock reads. The V2 publisher-identity gate
// (step 3 of sub-step 4) imports this module directly — the disposition
// logic lives here, not in the gate, so validation harnesses (step 8)
// can exercise it without constructing a full gate input.
//
// =====================================================================
// DISPOSITION CONTRACT
// =====================================================================
//
// Input:  the object returned by publisher.extract(). Must contain
//         tenure[], transitions[], identity_profile, shape, signals.
// Output: { disposition: 'BLOCK'|'WARN'|'ALLOW', reasons: string[] }.
//
// Axes (in application order, matching GATE CONTRACT):
//
//   1. SUFFICIENCY — !signals.has_sufficient_history short-circuits
//      to ALLOW. Every downstream axis is mathematically defined on
//      thin history but not statistically meaningful; applying K=10
//      against a 3-version package misclassifies every first
//      contribution as a cold handoff.
//
//   2. PER-TRANSITION 2×2 — for each transition, route by
//      (is_overlap_window_W3, is_known_contributor_K10):
//        (T, T) recurring_member      → ALLOW
//        (T, F) new_committee_member  → ALLOW
//        (F, T) returning_dormant     → ALLOW
//        (F, F) cold_handoff          → severity pipeline
//
//   3. COLD-HANDOFF SEVERITY — prior_tenure_versions is the primary
//      severity axis. Below HIGH_PRIOR_TENURE the cell is rotation
//      churn (committees producing many 1-version tenure blocks
//      generate (F,F) transitions with prior_tenure=1); it MUST NOT
//      escalate. At or above HIGH, shape drives the base: solo (or
//      unknown, treated conservatively as solo) → BLOCK; committee
//      or alternating → WARN. Committee/alternating upgrade to BLOCK
//      only at EXCEPTIONAL_PRIOR_TENURE.
//
//   4. PROVIDER MODIFIER — supplementary, on cold-handoff only, and
//      only when the incoming block introduces a NEW domain (domain's
//      first_seen_in_package_ms equals the block's first_published
//      timestamp). privacy-incoming combined with
//      has_unverified_domain anywhere in the package is the strongest
//      provider-derived combo and upgrades WARN → BLOCK at HIGH+
//      prior_tenure. Privacy or unverified alone only annotates the
//      reason string. Provider MUST NOT drive disposition on the
//      other three cells.
//
//   5. DOMAIN STABILITY — context modifier on cold-handoff only, when
//      the incoming domain is new. churning packages are more tolerant
//      of new domains (de-escalate BLOCK → WARN on non-solo shapes).
//      stable packages are less tolerant (escalate WARN → BLOCK on
//      non-solo shapes). mixed is no-op. Stability MUST NOT drive
//      disposition on the other three cells.
//
// Package disposition = max (BLOCK > WARN > ALLOW) across transitions.
//
// The reasons[] array carries one string per transition plus the
// short-circuit detail when applicable. Order matches transitions[]
// so a reader can trace the package verdict back to the exact release.
// =====================================================================

// Severity thresholds on prior_tenure_versions for the cold-handoff cell.
// Starter values — calibrated in step 8 against the seed corpus.
//
// HIGH_PRIOR_TENURE: below this, a (F,F) transition is rotation churn
// (a committee cycling through 1-version drive-bys generates many (F,F)
// cells with prior_tenure=1; these must NOT escalate). Catches
// event-stream class (prior_tenure=27) and axios-class (prior_tenure=8)
// while allowing fixtures 3c-B/C/D/E (prior_tenure=1 rotation churn).
//
// EXCEPTIONAL_PRIOR_TENURE: committee/alternating shapes normally WARN
// on (F,F), but at this threshold we upgrade to BLOCK — a 20-version
// tenure was active enough that the cold handoff is not committee
// churn regardless of shape.
const HIGH_PRIOR_TENURE = 5;
const EXCEPTIONAL_PRIOR_TENURE = 20;

const ORDER = { ALLOW: 0, WARN: 1, BLOCK: 2 };

function escalate(current, next) {
  return ORDER[next] > ORDER[current] ? next : current;
}

function classifyCell(t) {
  const overlap = t.is_overlap_window_W3;
  const known = t.is_known_contributor_K10;
  if (overlap && known) return 'recurring_member';
  if (overlap && !known) return 'new_committee_member';
  if (!overlap && known) return 'returning_dormant';
  return 'cold_handoff';
}

// Incoming block introduces a NEW domain iff its domain first appears
// at this transition. domain===null (bare-name identity) is treated as
// not-new — the modifier keys off a domain-identity proxy, not on an
// identity anomaly.
function incomingIntroducesNewDomain(incoming) {
  return (
    incoming &&
    incoming.domain !== null &&
    incoming.first_seen_in_package_ms === incoming.first_published_at_ms
  );
}

function evaluateTransition(t, tenure, shape, identityProfile) {
  const cell = classifyCell(t);
  if (cell !== 'cold_handoff') {
    return { disposition: 'ALLOW', reason: `${cell} @ ${t.at_version}` };
  }

  const priorTenure = t.prior_tenure_versions;
  if (priorTenure < HIGH_PRIOR_TENURE) {
    return {
      disposition: 'ALLOW',
      reason:
        `cold_handoff @ ${t.at_version} (rotation churn, ` +
        `prior_tenure=${priorTenure})`,
    };
  }

  // shape='unknown' is conservative-as-solo per GATE CONTRACT Addition 3.
  const effectiveShape = shape === 'unknown' ? 'solo' : shape;
  let d;
  if (effectiveShape === 'solo') {
    d = 'BLOCK';
  } else if (priorTenure >= EXCEPTIONAL_PRIOR_TENURE) {
    d = 'BLOCK';
  } else {
    d = 'WARN';
  }

  const parts = [
    `cold_handoff @ ${t.at_version}`,
    `shape=${shape}`,
    `prior_tenure=${priorTenure}`,
  ];

  const incoming = tenure[t.from_index + 1];
  const newDomain = incomingIntroducesNewDomain(incoming);

  if (newDomain) {
    const provider = incoming.provider;
    if (provider === 'privacy' || provider === 'unverified') {
      parts.push(`new_domain=${incoming.domain} (${provider})`);
    }
    const combo =
      provider === 'privacy' && identityProfile.has_unverified_domain;
    if (combo && priorTenure >= HIGH_PRIOR_TENURE && d === 'WARN') {
      d = 'BLOCK';
      parts.push('privacy+unverified combo');
    }

    // Stability modifies only on non-solo shapes. Solo with a new
    // privacy domain after HIGH tenure is the attacker signature and
    // MUST NOT de-escalate.
    const stability = identityProfile.domain_stability;
    if (effectiveShape !== 'solo') {
      if (stability === 'churning' && d === 'BLOCK') {
        d = 'WARN';
        parts.push('stability=churning (de-escalated)');
      } else if (stability === 'stable' && d === 'WARN') {
        d = 'BLOCK';
        parts.push('stability=stable (escalated)');
      }
    }
  }

  return { disposition: d, reason: parts.join(' | ') };
}

export function disposition(extracted) {
  if (!extracted || typeof extracted !== 'object') {
    throw new Error('disposition: input must be a non-null object');
  }
  const { tenure, transitions, identity_profile, shape, signals } = extracted;
  if (!Array.isArray(tenure) || !Array.isArray(transitions)) {
    throw new Error(
      'disposition: input must carry array tenure and transitions',
    );
  }
  if (!signals || typeof signals !== 'object') {
    throw new Error('disposition: input.signals must be an object');
  }
  if (!identity_profile || typeof identity_profile !== 'object') {
    throw new Error('disposition: input.identity_profile must be an object');
  }
  if (typeof shape !== 'string') {
    throw new Error('disposition: input.shape must be a string');
  }

  if (!signals.has_sufficient_history) {
    return {
      disposition: 'ALLOW',
      reasons: [
        `insufficient history (observed_versions_count=` +
          `${signals.observed_versions_count ?? 0})`,
      ],
    };
  }

  if (transitions.length === 0) {
    return {
      disposition: 'ALLOW',
      reasons: ['no transitions observed'],
    };
  }

  let pkg = 'ALLOW';
  const reasons = [];
  for (const t of transitions) {
    const r = evaluateTransition(t, tenure, shape, identity_profile);
    reasons.push(`${r.disposition}: ${r.reason}`);
    pkg = escalate(pkg, r.disposition);
  }
  return { disposition: pkg, reasons };
}

export default disposition;

// Exported for tests + step 8 calibration. Do NOT consume these from
// runtime code — the gate reads disposition() only.
export const __thresholds = {
  HIGH_PRIOR_TENURE,
  EXCEPTIONAL_PRIOR_TENURE,
};
