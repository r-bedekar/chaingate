import { classifyProvider, extractDomain } from '../patterns/provider.js';

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
//      only at EXCEPTIONAL_PRIOR_TENURE *and* with at least one
//      co-signal on the transition — see CO-SIGNAL REQUIREMENT
//      (publisher.js GATE CONTRACT Addition 3) and hasCoSignal()
//      below. Committee members accumulate long tenures as a matter
//      of course (e.g., express's dougwilson 150-version block), so
//      prior_tenure alone is not a reliable attack signal on
//      committee shapes — the co-signal requirement closes that gap
//      without weakening the solo (event-stream / axios) path.
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
//      the incoming domain is new. On non-solo shapes, churning
//      packages are more tolerant of new domains and de-escalate
//      BLOCK → WARN. Stability MUST NOT escalate on its own — a
//      non-solo BLOCK requires an active co-signal (Addition 3); a
//      "stable" package absent any co-signal is a legitimate
//      long-serving committee, not an attack. mixed is no-op.
//      Stability MUST NOT drive disposition on the other three cells.
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

// Co-signal: short handoff gap. A cold handoff within this window of
// the prior block's last release is itself a co-signal — legitimate
// committee handoffs almost always have >1 day between releases
// (planning, review, coordination). An incoming maintainer publishing
// within hours of gaining ownership is the axios / shai-hulud shape.
// 24h is the coarsest threshold that still separates the observed
// attack cadence from legitimate committee coordination; narrower
// windows (1h, 6h) would still catch the known-attack cases but
// risk false positives on automated release pipelines that batch a
// handoff and a follow-up patch.
const SHORT_GAP_MS = 24 * 60 * 60 * 1000;

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

// Co-signal detector for the non-solo cold-handoff cell. Returns
// { present: boolean, labels: string[] } so the caller can both gate
// the disposition and append a reason annotation. Order of checks
// matches the three classes documented in GATE CONTRACT Addition 3
// (a = new domain class, b = provenance break, c = short gap); any
// one is sufficient to escalate, all observed are labeled.
//
// Why these three and not others:
//   - The (F,F) + long prior_tenure combination is already the
//     strongest per-event identity signal available at this layer.
//     The co-signals are the three independent axes that the
//     publisher pattern observes — domain class, provenance state,
//     release cadence. Each fires on a published-observable feature,
//     none requires a live network call, and each on its own has
//     been empirically sufficient to flag a known attack in the
//     validation corpus (axios: short gap + privacy domain; shai-hulud:
//     short gap; ua-parser-js: unverified domain after baseline).
//   - free-webmail is deliberately NOT a co-signal: legitimate
//     committee members frequently use gmail addresses, and treating
//     gmail-as-new-domain as escalation would fire on express's
//     celebrated dougwilson → ulisesgascon handoff.
function hasCoSignal(t, prior, incoming, identityProfile, provenanceOutput = null) {
  const labels = [];

  // (a) New domain class — privacy or unverified. Free-webmail and
  //     verified-corporate are NOT co-signals here.
  if (incoming && incomingIntroducesNewDomain(incoming)) {
    const p = incoming.provider;
    if (p === 'privacy' || p === 'unverified') {
      labels.push(`co-signal: new ${p} domain ${incoming.domain}`);
    }
  }

  // (b) Provenance method break — UNION of two sources:
  //
  //     Legacy (block-level): the package had established a provenance
  //     baseline (prior block's last release carried provenance=true)
  //     and the incoming block's first release drops it (anything
  //     other than true — false or unobserved). Two null-vs-null
  //     blocks do NOT fire — no break if no baseline existed.
  //
  //     Phase-3 extension (pattern-level): the provenance pattern
  //     fires provenance_regression=true at the incoming version T.
  //     This catches the case the block-level reading misses —
  //     baseline established over multiple blocks culminating in a
  //     regression mid-stream — and the case where the attack does
  //     NOT cross a block boundary (same-identity intra-block
  //     regression would not flip the block-level bits but will be
  //     flagged here via the pattern).
  //
  //     Either source satisfies the co-signal; the labels array
  //     carries exactly one break-class entry, specific to whichever
  //     source fired. When both fire the pattern-level label wins —
  //     it carries the version anchor for downstream explainability.
  const perVersionSignal =
    provenanceOutput && t ? findPerVersionSignal(provenanceOutput, t.at_version) : null;
  const patternRegression =
    perVersionSignal && perVersionSignal.provenance_regression === true;
  const blockLevelBreak =
    prior &&
    incoming &&
    prior.last_provenance_present === true &&
    incoming.first_provenance_present !== true;
  if (patternRegression) {
    labels.push(`co-signal: provenance regression @ ${perVersionSignal.version}`);
  } else if (blockLevelBreak) {
    labels.push('co-signal: provenance break');
  }

  // (c) Short handoff gap. See SHORT_GAP_MS for rationale.
  if (typeof t.gap_ms === 'number' && t.gap_ms < SHORT_GAP_MS) {
    labels.push(`co-signal: gap_ms=${t.gap_ms} (<${SHORT_GAP_MS})`);
  }

  // identityProfile reserved for future co-signals that cross
  // individual transitions (e.g., per-package privacy-provider
  // density). Unused today; kept in the signature so callers don't
  // need to refactor their call sites when it becomes load-bearing.
  void identityProfile;

  return { present: labels.length > 0, labels };
}

// ---------------------------------------------------------------------------
// Provenance interaction helpers (Phase 3).
//
// These helpers correlate provenance-pattern per-version signals with
// publisher-pattern per-transition cells per the GATE CONTRACT
// interaction table in patterns/provenance.js (lines 107-127). None
// of them have effect when provenanceOutput is null — backward
// compatibility lives at the call sites.
// ---------------------------------------------------------------------------

// Locate the provenance per-version record that corresponds to a
// publisher-side version anchor (either a transition's incoming
// version, or a bare version string for the no-transition case).
// Returns null when the version is not present in provenanceOutput —
// this can happen for rows the provenance normalizer dropped
// (duplicate version, missing timestamp) but publisher retained, or
// vice versa. null is a graceful no-op signal: the caller proceeds
// without provenance input, matching the "unknown is not evidence"
// invariant.
function findPerVersionSignal(provenanceOutput, version) {
  if (!provenanceOutput || !Array.isArray(provenanceOutput.perVersion)) return null;
  for (const v of provenanceOutput.perVersion) {
    if (v && v.version === version) return v;
  }
  return null;
}

// Machine-publisher detector — see patterns/provenance.js
// MACHINE_PUBLISHER_EMAIL. Duplicated here (not imported) so the
// disposition layer doesn't take a runtime dependency on a pattern
// constant; calibration changes to the pattern's machine-matcher are
// expected to remain narrow, and the disposition layer's read of
// "who is the incoming publisher" is conceptually independent of the
// pattern's "who carried the baseline" read.
const MACHINE_PUBLISHER_EMAIL_RE = /^npm-oidc-no-reply@github\.com$/i;

function isMachinePublisher(email) {
  if (typeof email !== 'string' || email.length === 0) return false;
  return MACHINE_PUBLISHER_EMAIL_RE.test(email.trim());
}

// Build the domain→version-count map that classifyProvider needs, by
// consuming provenance-pattern perVersion records (one entry per
// observed version, each carrying incoming_publisher.email). This
// re-derives what patterns/publisher.js computed internally without
// re-scanning raw packument rows — the spec's "consume only pattern
// output" rule. Null / missing emails contribute no entry.
function buildDomainCountMap(provenanceOutput) {
  const counts = new Map();
  if (!provenanceOutput || !Array.isArray(provenanceOutput.perVersion)) {
    return counts;
  }
  for (const v of provenanceOutput.perVersion) {
    const email = v && v.incoming_publisher ? v.incoming_publisher.email : null;
    const domain = extractDomain(email);
    if (domain === null) continue;
    counts.set(domain, (counts.get(domain) ?? 0) + 1);
  }
  return counts;
}

// Prior-domain set at version T. Consumes provenance perVersion
// entries strictly before T (by published_at_ms) and returns the set
// of their extracted email domains. This matches the GATE CONTRACT
// escalator (a) definition: "set of all domains seen in prior
// versions of the package's publisher history."
//
// Using provenance perVersion (not publisher.tenure) means intra-
// block email rotations are visible — publisher.tenure collapses
// them into a single block domain. The axios@1.14.1 case is exactly
// this: jasonsaayman remains the account login across the attack,
// publisher sees one tenure block with block.domain=<earliest
// email's domain>, but the per-version row stream shows proton.me
// as an email appearing only at version 1.14.1. Prior set computed
// this way correctly excludes proton.me.
function buildPriorDomainSet(provenanceOutput, incomingPublishedAtMs) {
  const set = new Set();
  if (!provenanceOutput || !Array.isArray(provenanceOutput.perVersion)) return set;
  for (const v of provenanceOutput.perVersion) {
    if (!v || typeof v.published_at_ms !== 'number') continue;
    if (v.published_at_ms >= incomingPublishedAtMs) continue;
    const email = v.incoming_publisher ? v.incoming_publisher.email : null;
    const domain = extractDomain(email);
    if (domain !== null) set.add(domain);
  }
  return set;
}

// Four-escalator evaluation for the recurring_member / no-transition
// cell. Each rule fires INDEPENDENTLY against the incoming version
// T's data; any fire flips `fired` true. The `escalators` array is
// what reason-string construction reads to name which rules tripped.
//
// Rule bodies per GATE CONTRACT (patterns/provenance.js lines
// 144-167):
//
//   (a) new_domain       — incoming email's domain is not in the set
//                          of domains seen in prior versions.
//   (b) privacy          — classifyProvider on incoming domain
//                          returns 'privacy'.
//   (c) unverified       — classifyProvider on incoming domain
//                          returns 'unverified'.
//   (d) machine_to_human — prior_baseline_carriers.any_machine is
//                          true AND the incoming publisher is NOT a
//                          machine-identity email.
//
// transitionIndex is currently unused — escalator evaluation reads
// its anchor from perVersionSignal — but retained in the signature
// so future escalator extensions that need the publisher-side
// transition context (e.g., a "cross-cell escalator") don't require
// a call-site refactor.
function hasProvenanceEscalator(perVersionSignal, publisherOutput, provenanceOutput, transitionIndex) {
  void publisherOutput;
  void transitionIndex;
  const escalators = [];
  if (!perVersionSignal || !perVersionSignal.incoming_publisher) {
    return { fired: false, escalators };
  }
  const incomingEmail = perVersionSignal.incoming_publisher.email;
  const incomingDomain = extractDomain(incomingEmail);

  // (a) new_domain — requires a non-null incoming domain to be
  //     meaningful (a bare-name identity has no domain to compare).
  if (incomingDomain !== null) {
    const prior = buildPriorDomainSet(provenanceOutput, perVersionSignal.published_at_ms);
    if (!prior.has(incomingDomain)) {
      escalators.push('new_domain');
    }
  }

  // (b)(c) privacy / unverified — classifyProvider with a
  //     domain-count map reconstructed from provenance perVersion.
  if (incomingDomain !== null) {
    const counts = buildDomainCountMap(provenanceOutput);
    const providerClass = classifyProvider(incomingDomain, counts);
    if (providerClass === 'privacy') escalators.push('privacy');
    if (providerClass === 'unverified') escalators.push('unverified');
  }

  // (d) machine_to_human — prior baseline was carried (in part) by
  //     the GitHub Actions OIDC bot AND the incoming publisher is
  //     not itself that bot (or any other known-machine pattern).
  //     Fires on axios@1.14.1 (machine-carried baseline, human-CLI
  //     incoming) but not on axios@1.13.3 (human-OIDC baseline, so
  //     any_machine=false on the streak carriers).
  const carriers = perVersionSignal.prior_baseline_carriers;
  if (carriers && carriers.any_machine === true && !isMachinePublisher(incomingEmail)) {
    escalators.push('machine_to_human');
  }

  return { fired: escalators.length > 0, escalators };
}

// Interaction-table evaluator for the same-identity cells
// (recurring_member, new_committee_member, returning_dormant, and
// the no-transition head-of-package case). Input is the perVersion
// provenance signal; output is a provenance-driven disposition
// delta that the caller merges with the publisher-side baseResult.
//
// Returns { disposition, reasonParts }:
//   disposition — the OVERRIDE to apply (caller escalates to max).
//     'ALLOW' when provenance is silent / pattern has no fire.
//     'WARN' when regression fires without escalator.
//     'BLOCK' when regression fires AND at least one escalator
//     (only on recurring_member or no-transition cells; the
//     new_committee / returning_dormant cells cap at WARN per the
//     interaction table).
//   reasonParts — array of strings to concatenate into the reason
//     string; empty when disposition is ALLOW (caller keeps the
//     publisher-side reason unchanged).
//
// "Same as prior identity" row. The incoming publisher login has
// appeared before in this package (either intra-block, or at a
// transition boundary where the returning login matches a prior
// block's identity). Escalators are evaluated; any fire → BLOCK,
// otherwise WARN.
function evaluateProvenanceSameIdentity(perVersionSignal, publisherOutput, provenanceOutput, transitionIndex) {
  if (!perVersionSignal) return { disposition: 'ALLOW', reasonParts: [] };
  if (!perVersionSignal.in_scope) return { disposition: 'ALLOW', reasonParts: [] };
  if (!perVersionSignal.provenance_regression) return { disposition: 'ALLOW', reasonParts: [] };
  const parts = [`provenance_regression @ ${perVersionSignal.version}`];
  const esc = hasProvenanceEscalator(perVersionSignal, publisherOutput, provenanceOutput, transitionIndex);
  if (esc.fired) {
    parts.push(`escalators=[${esc.escalators.join(',')}]`);
    return { disposition: 'BLOCK', reasonParts: parts };
  }
  parts.push('regression without escalators');
  return { disposition: 'WARN', reasonParts: parts };
}

// Identity-continuity check: has the given login appeared in any
// tenure block whose first version published strictly before the
// given timestamp? This is the amended GATE CONTRACT routing
// key (patterns/provenance.js DISPOSITION INTERACTION TABLE). It
// is slice-invariant: unlike publisher's K=10 is_known_contributor,
// this fires on the FIRST reappearance of a login regardless of
// how many prior versions the fixture captures.
//
// Intra-block version v (not the block's first version): the
// containing block has first_published_at_ms strictly less than v's
// — this function returns true. ✓
// Transition-boundary version v (first version of block k): blocks
// before k with the same identity have first < v's — returns true if
// any exists, false otherwise. ✓
function incomingIdentityWasSeenBefore(tenure, incomingIdentity, publishedAtMs) {
  for (const b of tenure) {
    if (b.identity !== incomingIdentity) continue;
    if (b.first_published_at_ms < publishedAtMs) return true;
  }
  return false;
}

// Locate the tenure block containing a given timestamp. Each block
// occupies a contiguous first_published_at_ms..last_published_at_ms
// range and the ranges do not overlap (publisher.js guarantees).
function tenureBlockAt(tenure, publishedAtMs) {
  for (const b of tenure) {
    if (publishedAtMs >= b.first_published_at_ms && publishedAtMs <= b.last_published_at_ms) {
      return b;
    }
  }
  return null;
}

function evaluateTransition(t, tenure, shape, identityProfile, provenanceOutput = null) {
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

  const parts = [
    `cold_handoff @ ${t.at_version}`,
    `shape=${shape}`,
    `prior_tenure=${priorTenure}`,
  ];

  const prior = tenure[t.from_index];
  const incoming = tenure[t.from_index + 1];
  const newDomain = incomingIntroducesNewDomain(incoming);

  // Base disposition. On non-solo shapes at EXCEPTIONAL prior_tenure,
  // escalating from WARN → BLOCK requires a co-signal (GATE CONTRACT
  // Addition 3 — committee members accumulate long tenures through
  // legitimate activity; tenure length alone is not a reliable attack
  // signal for committees). Solo shapes escalate unconditionally at
  // HIGH: a solo package changing hands after a long tenure IS the
  // ownership event and has no legitimate committee-churn reading.
  let d;
  if (effectiveShape === 'solo') {
    d = 'BLOCK';
  } else if (priorTenure >= EXCEPTIONAL_PRIOR_TENURE) {
    const co = hasCoSignal(t, prior, incoming, identityProfile, provenanceOutput);
    if (co.present) {
      d = 'BLOCK';
      for (const label of co.labels) parts.push(label);
    } else {
      d = 'WARN';
      parts.push('no co-signal (committee tenure alone does not BLOCK)');
    }
  } else {
    d = 'WARN';
  }

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
    // LOAD-BEARING CARVE-OUT — do not remove the non-solo guard.
    //
    // On the cold-handoff cell, shape=solo + new privacy domain +
    // prior_tenure>=HIGH IS the axios-class attacker signature
    // (fixture 3c-F). The package's domain history inevitably reads
    // as 'churning' because the NEW privacy domain lands in the final
    // CHURNING_WINDOW rows — churning is a mechanical consequence of
    // the attack, not an exonerating context signal. Letting
    // stability=churning de-escalate BLOCK→WARN here would ALLOW the
    // exact attack this function was built to catch.
    //
    // The de-escalation is reserved for committee / alternating
    // shapes where churning genuinely means "this package rotates
    // domains as a matter of course, a new one isn't news." Solo
    // packages don't have that excuse — a solo package seeing a new
    // domain IS the event.
    //
    // Stability is DE-ESCALATION-ONLY on non-solo shapes. A previous
    // revision escalated stability=stable + new-domain cold handoffs
    // from WARN → BLOCK, but Addition 3 makes co-signal the sole
    // non-solo escalation path — a long-serving committee with no
    // co-signal firing is a legitimate handoff, not an attack. The
    // baseline train run caught 5 committee/alternating FPs driven
    // by this escalation (fs-extra, ioredis, style-loader, ws,
    // eslint-plugin-import). Keep this a one-way valve.
    //
    // If you're touching this guard, verify 3c-F still BLOCKs:
    //   node --test test/validation/disposition.test.js
    if (effectiveShape !== 'solo') {
      if (stability === 'churning' && d === 'BLOCK') {
        d = 'WARN';
        parts.push('stability=churning (de-escalated)');
      }
    }
  }

  return { disposition: d, reason: parts.join(' | ') };
}

// disposition(publisherOutput, provenanceOutput?, transitionIndex?)
//
// PRIMARY INPUT — publisherOutput — the object returned by
// patterns/publisher.js extract(). Must carry tenure[], transitions[],
// identity_profile, shape, signals. This remains the sole required
// argument; single-arg callers continue to work unchanged.
//
// OPTIONAL — provenanceOutput — the object returned by
// patterns/provenance.js extract(). When null/undefined, disposition
// behaves exactly as the Phase-2 single-arg form: no provenance
// interaction table, no four-escalator evaluation, no provenance_
// regression co-signal extension. Existing disposition tests must
// continue passing without modification to their inputs.
//
// OPTIONAL — transitionIndex — integer index into publisherOutput.
// transitions[] identifying a specific transition to evaluate. When
// null the function iterates every transition and returns a
// package-level verdict (existing behavior). Callers that need a
// single-transition verdict (unit tests, targeted diagnostics) pass
// the index; the return shape is unchanged but `reasons` will carry
// exactly one entry.
//
// ROUTING (provenance ↔ publisher) — identity-continuity keyed per
// the amended GATE CONTRACT interaction table (patterns/provenance.js).
//
//   Pass 1 iterates publisher transitions[]. For each transition
//   whose incoming identity is GENUINELY NEW (never appeared in any
//   prior block), evaluateTransition() applies publisher-cell-driven
//   severity (cold_handoff shape/tenure/co-signals, including the
//   Phase-3 provenance_regression co-signal extension).
//
//   Pass 2 iterates provenanceOutput.perVersion[]. For each in-scope
//   record with provenance_regression=true whose incoming identity
//   matches any prior block (transition-boundary or intra-block — the
//   former returning login, the latter by definition same-identity),
//   the same-identity interaction row applies: WARN, or BLOCK if any
//   of the four escalators fire.
//
//   Versions where the identity is genuinely new are NOT evaluated
//   in Pass 2 — Pass 1 already covers them, and double-counting would
//   inflate the reason list.
export function disposition(publisherOutput, provenanceOutput = null, transitionIndex = null) {
  const extracted = publisherOutput;
  if (!extracted || typeof extracted !== 'object') {
    throw new Error('disposition: input must be a non-null object');
  }
  if (provenanceOutput !== null && provenanceOutput !== undefined) {
    if (typeof provenanceOutput !== 'object') {
      throw new Error('disposition: provenanceOutput must be an object or null');
    }
    if (!Array.isArray(provenanceOutput.perVersion)) {
      throw new Error('disposition: provenanceOutput.perVersion must be an array');
    }
  }
  if (transitionIndex !== null && transitionIndex !== undefined) {
    if (!Number.isInteger(transitionIndex) || transitionIndex < 0) {
      throw new Error('disposition: transitionIndex must be a non-negative integer or null');
    }
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

  if (transitionIndex !== null && transitionIndex !== undefined) {
    if (transitionIndex >= transitions.length) {
      throw new Error(
        `disposition: transitionIndex ${transitionIndex} out of range ` +
          `(transitions.length=${transitions.length})`,
      );
    }
  }

  // Phase-2 backward-compat path: provenanceOutput not supplied.
  // Preserves existing single-arg callers byte-for-byte.
  if (!provenanceOutput) {
    if (transitions.length === 0) {
      return { disposition: 'ALLOW', reasons: ['no transitions observed'] };
    }
    const targetIndices =
      transitionIndex === null || transitionIndex === undefined
        ? transitions.map((_, i) => i)
        : [transitionIndex];
    let pkg = 'ALLOW';
    const reasons = [];
    for (const i of targetIndices) {
      const t = transitions[i];
      const r = evaluateTransition(t, tenure, shape, identity_profile, null);
      reasons.push(`${r.disposition}: ${r.reason}`);
      pkg = escalate(pkg, r.disposition);
    }
    return { disposition: pkg, reasons };
  }

  // Phase-3 path: route by IDENTITY CONTINUITY per the amended GATE
  // CONTRACT interaction table (patterns/provenance.js). Two passes:
  //
  //   Pass 1 — publisher-cell-driven transitions where the incoming
  //     identity is GENUINELY NEW (never seen before in this package).
  //     evaluateTransition handles cold_handoff severity, co-signals,
  //     and the new_committee shape-capped WARN. Same-identity
  //     transitions are SKIPPED in this pass — they fall through to
  //     Pass 2.
  //
  //   Pass 2 — identity-continuity-driven perVersion evaluation. For
  //     every in-scope perVersion record, determine whether the
  //     incoming identity has appeared in any prior block. If yes,
  //     route via the "same as prior identity" row (escalators
  //     evaluated; any fire → BLOCK, else WARN on regression). If no
  //     AND the version sits at a publisher transition, the version
  //     is covered by Pass 1 and we don't double-count it here.
  //
  // Each reason line is attributed to exactly one pass; the package
  // verdict is the escalate-max across both.
  const transitionByVersion = new Map();
  for (let i = 0; i < transitions.length; i += 1) {
    transitionByVersion.set(transitions[i].at_version, i);
  }

  let pkg = 'ALLOW';
  const reasons = [];

  // Pass 1 — new-identity transitions (publisher-cell-driven).
  for (let i = 0; i < transitions.length; i += 1) {
    if (transitionIndex !== null && transitionIndex !== undefined && i !== transitionIndex) {
      continue;
    }
    const t = transitions[i];
    const incomingBlock = tenure[t.from_index + 1];
    const incomingIdentity = incomingBlock ? incomingBlock.identity : null;
    const sameAsPrior =
      incomingIdentity !== null &&
      incomingIdentityWasSeenBefore(tenure, incomingIdentity, t.at_published_at_ms);
    if (sameAsPrior) continue;
    const r = evaluateTransition(t, tenure, shape, identity_profile, provenanceOutput);
    reasons.push(`${r.disposition}: ${r.reason}`);
    pkg = escalate(pkg, r.disposition);
  }

  // Pass 2 — same-identity perVersion evaluation. When transitionIndex
  // scopes to one transition, restrict Pass 2 to the perVersion entry
  // at that transition's at_version (and only when its identity is
  // same-as-prior — otherwise Pass 1 already covered it).
  const perVersionToScan =
    transitionIndex !== null && transitionIndex !== undefined
      ? provenanceOutput.perVersion.filter(
          (v) => v.version === transitions[transitionIndex].at_version,
        )
      : provenanceOutput.perVersion;

  for (const v of perVersionToScan) {
    if (!v || !v.in_scope) continue;
    if (!v.provenance_regression) continue;
    const blk = tenureBlockAt(tenure, v.published_at_ms);
    if (!blk) continue;
    const identity = blk.identity;
    const sameAsPrior = incomingIdentityWasSeenBefore(tenure, identity, v.published_at_ms);
    if (!sameAsPrior) {
      // Genuinely new identity. Publisher-cell path (Pass 1) covers
      // this version; don't double-count here.
      continue;
    }
    const tIdx = transitionByVersion.has(v.version)
      ? transitionByVersion.get(v.version)
      : null;
    const r = evaluateProvenanceSameIdentity(v, extracted, provenanceOutput, tIdx);
    if (r.disposition !== 'ALLOW') {
      reasons.push(`${r.disposition}: ${r.reasonParts.join(' | ')}`);
      pkg = escalate(pkg, r.disposition);
    }
  }

  if (reasons.length === 0) {
    reasons.push(transitions.length === 0 ? 'no transitions observed' : 'no escalating signals');
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
