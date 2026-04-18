// Publisher pattern — Section 11 step 2 of docs/V2_DESIGN.md.
//
// Extracts tenure, transitions, identity profile, and multi-maintainer
// shape from a package's observed publisher history. Deterministic,
// pure function over sorted version rows. No external calls.
//
// =====================================================================
// GATE CONTRACT — READ BEFORE CONSUMING PATTERN OUTPUT
// =====================================================================
// The publisher pattern emits per-transition feature booleans. The
// disposition gate (Section 11 step 3) MUST evaluate each transition
// against THREE axes per event, not against any single aggregate:
//
//   axis 1: is_overlap_window_W3     — recency    (sub-step 2d)
//   axis 2: is_known_contributor_K10 — historicity (sub-step 2e)
//   axis 3: prior_tenure_versions    — severity    (sub-step 2c)
//
// SUFFICIENCY AXIS (sub-step 2f — cross-cuts the three axes above).
//   Before applying any of the three axes, the gate MUST check:
//
//     signals.has_sufficient_history
//
//   When false, the gate MUST short-circuit to ALLOW with an
//   "insufficient history" detail. Every downstream signal above is
//   mathematically well-defined on thin history but NOT statistically
//   meaningful. Applying K=10 against a package with 3 visible versions
//   would misclassify every first contribution as a cold handoff.
//
//   has_sufficient_history is observed_versions_count >=
//   MIN_HISTORY_DEPTH (constants.js — currently 8). Same threshold the
//   gate runner uses for V1 first-seen poisoning protection; the
//   pattern emits the verdict so the gate can short-circuit without
//   re-deriving it.
//
// The 2×2 of (axis 1, axis 2) identifies transition SHAPE:
//
//   (true,  true)  — active recurring committee member      ALLOW
//   (true,  false) — new committee member (first K-1 rel.)  ALLOW
//   (false, true)  — returning dormant maintainer           ALLOW
//   (false, false) — cold handoff — disposition depends on axis 3
//
// axis 3 (prior_tenure_versions) is the SEVERITY MULTIPLIER for the
// cold-handoff cell:
//
//   (false, false) AND prior_tenure_versions >= HIGH_THRESHOLD
//     → BLOCK (the attacker shape — e.g., event-stream class)
//   (false, false) AND prior_tenure_versions small
//     → WARN (committee churn, not an attack)
//
// The 2×2 alone is NOT sufficient for disposition. A transition with
// (false, false) and prior_tenure=1 is committee churn. The same cell
// with prior_tenure=147 is a takeover. The gate MUST read prior_tenure
// on every (false, false) transition.
//
// signals.has_overlap_transition exists for DISPLAY ONLY — summary
// counters in decision logs, metric emission, etc. The gate MUST NOT
// consume it for disposition logic. Reading the aggregate as a shortcut
// misclassifies every non-trivial package (one legitimate rotation
// followed by a takeover will have has_overlap_transition=true).
//
// AGGREGATE SHORTCUT POLICY (sub-step 2f). Some signals CAN be
// shortcut on; others cannot. The full policy is documented inline
// on `extractSignals` — read it before adding a gate that reads the
// signals object. TL;DR:
//
//   SAFE to shortcut: the 2×2 cell histogram
//     (cold_handoff_count, new_committee_member_count,
//      returning_dormant_count, recurring_member_count) and
//     max_cold_handoff_prior_tenure — definition bakes in the cell
//     filter, so the aggregate IS the disposition question.
//
//   UNSAFE to shortcut: has_overlap_transition — OR across
//     heterogeneous transitions, misleads on mixed packages.
// =====================================================================
//
// Why this matters (competitive positioning):
//   Other tools treat every publisher change equally, or ignore the
//   signal entirely. This module is built around tenure-weighted
//   transitions — a new identity after 147 stable versions is a very
//   different signal from a new identity in an already-rotating
//   committee. The output is deterministic and explainable, which is
//   what makes it usable in regulated environments where ML confidence
//   scores are rejected.
//
// Validation corpus (packages confirmed present in the 130-entry
// seed — collector/seeds/npm_top.txt):
//
//   Attack fixtures:
//     axios          — 2026, email → protonmail.me (tenure + provider)
//     event-stream   — 2018, dominictarr → right9ctrl handoff
//                       (canonical tenure-weighted case)
//     ua-parser-js   — 2021, token theft with same publisher
//                       (NEGATIVE: publisher pattern must NOT fire)
//     chalk          — MAL-2025-46969
//
//   Legitimate-evolution fixtures:
//     moment   — multi-maintainer, committee shape
//     express  — committee shape
//     lodash   — solo / dominant maintainer baseline
//     debug    — TJ Holowaychuk era, legitimate later transitions
//
//   NOT in the seed — do not use as fixtures without adding to the
//   collector or building a synthetic test harness:
//     faker (marak → mikemcneil handoff), request
//
// Deferment registry (live in docs/V2_DESIGN.md §0 — mirrored here so
// anyone editing this file sees what's intentionally NOT done yet):
//   sub-step 2f — signals aggregation (max_prior_tenure etc.)
//   sub-step 3  — identity_profile (domain/provider/similarity) + shape
//   sub-step 4  — calibrate.js (derive K, W from seed) + corpus validation
//   sub-step 5  — cross-package campaign detection (STRETCH)
//   step 3      — V2 publisher-identity gate wiring

import { MIN_HISTORY_DEPTH } from '../constants.js';
import { normalizeIdentity } from './identity.js';
import { compareSemver } from './semver.js';

// Window size for overlap detection (sub-step 2d, definition (a)).
// "How many most-recent tenure blocks we consider when asking whether an
// incoming identity has appeared before." W=3 is a defensible starter
// value, not a magic number — it catches rotation in 2–5 person
// committees (the common shape across the 130-package seed) while
// keeping the window tight enough that reappearances after multi-block
// silence count as cold, not overlap.
//
// Subject to revision in sub-step 4 (calibrate.js) against the seed.
// Changing this constant will flip fixtures H and I in
// test/patterns/publisher.test.js — that is BY DESIGN, the regression
// alarm that tells a future contributor calibration moved.
const WINDOW_W = 3;

// Threshold for known_contributor detection (sub-step 2e).
// "How many prior releases does an incoming identity need to be treated
// as a known contributor?" K=10 is a defensible starter — above the
// drive-by range (1–3 patches) but reachable by legitimate committee
// members within a few months of active participation. Distinguishes
// returning-dormant-maintainer (ALLOW-biasing) from cold-handoff
// attacker (BLOCK-biasing when paired with high prior_tenure).
//
// Subject to revision in sub-step 4. Changing this constant will flip
// fixtures L and M — the inclusive >= K boundary guard.
const WINDOW_K = 10;

function validateInput(input) {
  if (!input || typeof input !== 'object') {
    throw new Error('publisher.extract: input must be a non-null object');
  }
  if (typeof input.packageName !== 'string' || input.packageName.length === 0) {
    throw new Error('publisher.extract: input.packageName must be a non-empty string');
  }
  if (!Array.isArray(input.history)) {
    throw new Error('publisher.extract: input.history must be an array');
  }
}

// Normalize + filter: drop rows missing identity, timestamp, or version.
// Return { rows, skipped } where rows are ready for sort and downstream
// analysis, and skipped counts rows the caller should report in signals.
// A row without any ONE of (identity, integer timestamp, non-empty string
// version) is unusable for tenure/transition anchoring — never fabricate.
function normalizeAndFilter(history) {
  const rows = [];
  let skipped = 0;
  for (const raw of history) {
    const identity = normalizeIdentity(raw?.publisher_email, raw?.publisher_name);
    const tsRaw = raw?.published_at_ms;
    const ts = Number.isInteger(tsRaw) ? tsRaw : null;
    const version =
      typeof raw?.version === 'string' && raw.version.length > 0 ? raw.version : null;
    if (!identity || ts === null || !version) {
      skipped += 1;
      continue;
    }
    rows.push({ version, identity, published_at_ms: ts });
  }
  return { rows, skipped };
}

// Sort by published_at_ms ascending (primary), breaking ties by semver
// ascending (secondary), and finally by identity string (tertiary).
//
// Deliberately NOT semver-first: attackers that backport under old
// version numbers would exploit semver-sorted tools.
//
// The identity tertiary key exists because (ts, semver) does NOT uniquely
// order rows when a version is republished under a different publisher
// (same ts + same version + different identity → compareSemver === 0).
// Without a tertiary key, two equivalent inputs in different orders can
// produce different tenure blocks — a silent determinism hole that
// surfaces as drift in calibration diffs. Integer-order string compare
// is locale-independent and cheap.
function sortRows(rows) {
  return rows.slice().sort((a, b) => {
    if (a.published_at_ms !== b.published_at_ms) {
      return a.published_at_ms < b.published_at_ms ? -1 : 1;
    }
    const semver = compareSemver(a.version ?? '', b.version ?? '');
    if (semver !== 0) return semver;
    if (a.identity < b.identity) return -1;
    if (a.identity > b.identity) return 1;
    return 0;
  });
}

// Extract tenure blocks: maximal runs of consecutive versions by the same
// identity in the sorted sequence. Returns [] for empty input. Each block
// carries first/last version + timestamp and a count so downstream
// transition/signals logic can compute prior_tenure without re-scanning.
//
// Determinism note: duration_ms is last_ts - first_ts (integer arithmetic
// only). A single-version block has duration_ms = 0 — not "undefined" or
// "null" — so consumers can treat tenure as a dense numeric column.
//
// Degraded rows (nulls) are filtered in normalizeAndFilter BEFORE sort,
// so a run like [A, A, A, (null), A, A] collapses into one A-block of 5,
// not two blocks split around the null. This is deliberate: a missing
// row is an observability gap, not a tenure event.
function extractTenure(sortedRows) {
  const tenure = [];
  if (sortedRows.length === 0) return tenure;
  let current = null;
  for (const row of sortedRows) {
    if (current === null || row.identity !== current.identity) {
      if (current !== null) tenure.push(current);
      current = {
        identity: row.identity,
        version_count: 1,
        first_version: row.version,
        last_version: row.version,
        first_published_at_ms: row.published_at_ms,
        last_published_at_ms: row.published_at_ms,
        duration_ms: 0,
      };
    } else {
      current.version_count += 1;
      current.last_version = row.version;
      current.last_published_at_ms = row.published_at_ms;
      current.duration_ms = row.published_at_ms - current.first_published_at_ms;
    }
  }
  tenure.push(current);
  return tenure;
}

// Extract transitions: one record per boundary between adjacent tenure
// blocks. Output length is exactly max(tenure.length - 1, 0).
//
// Each record is a tenure-weighted event, not a boolean "publisher
// changed" — it carries both the prior block's VERSION count and its
// DURATION, plus the visible GAP (first_ts of the incoming block minus
// last_ts of the outgoing block). This decomposition is what lets the
// downstream gate tell apart four shapes that all look identical to a
// "publisher_changed" boolean:
//
//   long tenure + zero gap     → takeover after stable ownership
//   short tenure + huge gap    → dormancy revive (abandoned-package
//                                  takeover, seen in multiple 2024–
//                                  2026 campaigns)
//   short tenure + small gap   → committee rotation
//   long tenure + visible gap  → announced handoff (usually legitimate)
//
// Competitors ship only the boolean. Keeping count and duration separate
// (not summed, not averaged) preserves the ability to distinguish them
// deterministically and explain the distinction in a decision log.
//
// from_index is the tenure-array index of the outgoing block, kept so
// sub-step 2d overlap detection can look up the W-window around a
// transition in O(1) without re-scanning.
function extractTransitions(tenure) {
  const transitions = [];
  for (let i = 1; i < tenure.length; i += 1) {
    const prior = tenure[i - 1];
    const next = tenure[i];
    transitions.push({
      from_identity: prior.identity,
      to_identity: next.identity,
      at_version: next.first_version,
      at_published_at_ms: next.first_published_at_ms,
      prior_tenure_versions: prior.version_count,
      prior_tenure_duration_ms: prior.duration_ms,
      gap_ms: next.first_published_at_ms - prior.last_published_at_ms,
      from_index: i - 1,
    });
  }
  return transitions;
}

// ---------------------------------------------------------------------------
// Overlap detection — sub-step 2d, definition (a), W=WINDOW_W.
//
// SIGNAL SEMANTICS (read carefully before reasoning about this field):
//
//   is_overlap_window_W3 = true
//     → The incoming identity has appeared in the last W tenure blocks.
//     → This is COMMITTEE-SHAPE EVIDENCE.
//     → Bias: ALLOW. A rotating committee produces many true overlaps.
//
//   is_overlap_window_W3 = false
//     → The incoming identity is NEW to the recent contributor set.
//     → This is COLD-HANDOFF EVIDENCE.
//     → Bias: toward BLOCK when combined with long prior_tenure.
//       On its own, means little — every first contribution from a
//       new committee member also reads as false.
//
// The signal is INVERTED relative to the usual "higher = more suspicious"
// convention in security tooling. Keep this in mind when reading the
// gate layer: overlap=true is a de-escalator, overlap=false is a
// prerequisite for escalation (but not sufficient alone).
//
// Definition (a) — "to_identity appears as .identity in any tenure block
// in the window [max(0, i-W+1) .. i] where i = transition.from_index."
//
// Including the from-block in the window is harmless: to_identity !=
// from_identity by construction (tenure = maximal same-identity runs),
// so the from-block can never match. Including it simplifies the
// iteration bounds.
//
// Alternatives explicitly NOT implemented here (see deferment registry):
//   (b) to-identity appears anywhere in prior history — would mislabel
//       resurrected dormant committee members as overlap, missing the
//       dormancy-revive attack shape.
//   (c) to-identity published within last T days — time-windowed,
//       attacker-pacing vulnerable, requires calibration.
//
// Mutates the transition records in place (adds is_overlap_window_W3)
// rather than returning new objects — no cache/downstream concerns,
// transitions are built in the same extract() call.
function extractOverlap(transitions, tenure) {
  for (const t of transitions) {
    const windowStart = Math.max(0, t.from_index - WINDOW_W + 1);
    const windowEnd = t.from_index; // inclusive
    let found = false;
    for (let k = windowStart; k <= windowEnd; k += 1) {
      if (tenure[k].identity === t.to_identity) {
        found = true;
        break;
      }
    }
    t.is_overlap_window_W3 = found;
  }
}

// ---------------------------------------------------------------------------
// Known-contributor detection — sub-step 2e, K=WINDOW_K.
//
// SIGNAL SEMANTICS (read carefully before reasoning about this field):
//
//   is_known_contributor_K10 = true
//     → The incoming identity has published at least K prior versions
//       across all of observable history (not just the recent window).
//     → This is HISTORICITY EVIDENCE — orthogonal to recency.
//     → Bias: ALLOW regardless of overlap. A returning maintainer with
//       15 prior versions after a multi-year gap is still a known
//       contributor; the visible gap is a dormancy signal, not a
//       takeover signal.
//
//   is_known_contributor_K10 = false
//     → The incoming identity is novel at the K threshold.
//     → Combined with overlap=true: "new committee member" — benign,
//       first K-1 releases of a legitimate new maintainer.
//     → Combined with overlap=false: "cold handoff shape" — prerequisite
//       for escalation but NOT sufficient; disposition depends on the
//       severity axis (prior_tenure_versions) per the top-of-file
//       contract.
//
// Companion field `prior_contribution_count` is the raw integer count.
// Emitted alongside the boolean so the gate layer can tier severity
// (e.g., K-1 looks different from 0) and so calibration in sub-step 4
// can sweep K against the seed corpus without re-running extract().
//
// Why count across ALL prior tenure (not just within W):
//   The 2×2 matrix's whole purpose is to separate recency (axis 1) from
//   historicity (axis 2). A W-scoped count would collapse the two back
//   into one axis — specifically, it would make the cell (false, true)
//   unreachable, which is the returning-dormant-maintainer shape we
//   need to distinguish from cold-handoff takeover. That cell is the
//   product-differentiator; competitors don't publish it.
//
// Mutates transition records in place — same pattern as extractOverlap.
// O(n*m) worst case where n = transitions, m = tenure blocks. Fine for
// the sizes we process (≤ few-hundred versions per package).
function extractKnownContributor(transitions, tenure) {
  for (const t of transitions) {
    let count = 0;
    for (let k = 0; k <= t.from_index; k += 1) {
      if (tenure[k].identity === t.to_identity) {
        count += tenure[k].version_count;
      }
    }
    t.prior_contribution_count = count;
    t.is_known_contributor_K10 = count >= WINDOW_K;
  }
}

// ---------------------------------------------------------------------------
// Signals aggregation — sub-step 2f.
//
// Collapses per-transition detail into package-level aggregates, in three
// tiers, so the gate can answer disposition questions cheaply without
// re-scanning `transitions[]`:
//
//   Tier 1 — sufficiency (populated below, step 2 of 2f)
//     observed_versions_count   — valid rows that survived normalizeAndFilter
//     unique_identity_count     — distinct identities across tenure blocks
//     has_sufficient_history    — observed >= MIN_HISTORY_DEPTH (constants.js)
//
//   Tier 2 — severity extrema + 2×2 cell histogram (step 3 of 2f)
//     max_prior_tenure_versions, max_cold_handoff_prior_tenure,
//     cold_handoff_count, new_committee_member_count,
//     returning_dormant_count, recurring_member_count
//
//   Tier 3 — temporal summary (step 4 of 2f)
//     total_history_duration_ms, longest_tenure_versions,
//     longest_tenure_duration_ms
//
// The signals object is ALWAYS a complete numeric record — every field
// defined as an integer/boolean zero-state when no data is present.
// Consumers can read fields unconditionally without `?? 0` guards; this
// is the load-bearing contract that makes the gate's short-circuit path
// simple and inspection-friendly.
//
// Temporal-field caveat (risk #4 decision): normalizeAndFilter drops
// degraded rows BEFORE tenure runs, so total_history_duration_ms and
// longest_tenure_duration_ms reflect the span of OBSERVED rows only.
// A history like [A@day-0, A@day-1000, (null-row at day-500)] reports
// duration = 1000 * DAY_MS — no gap-filling, no interpolation. Missing
// rows are observability gaps, not tenure events.
function extractSignals(rows, tenure, transitions, skippedVersionsCount) {
  // --- Tier 1: sufficiency ---
  const observedVersionsCount = rows.length;
  const identitySet = new Set();
  for (const block of tenure) identitySet.add(block.identity);
  const uniqueIdentityCount = identitySet.size;
  const hasSufficientHistory = observedVersionsCount >= MIN_HISTORY_DEPTH;

  // --- Tier 2: severity extrema + 2×2 cell histogram ---
  //
  // AGGREGATE SHORTCUT POLICY (extends the top-of-file GATE CONTRACT):
  //
  //   SAFE aggregates (gate MAY shortcut on these) — definitionally
  //   answer a disposition question because the 2×2 cell filter is
  //   baked into the aggregate itself:
  //     max_cold_handoff_prior_tenure   — (F,F) only; filter is part
  //                                        of the definition
  //     cold_handoff_count              — (F,F) count
  //     new_committee_member_count      — (T,F) count
  //     returning_dormant_count         — (F,T) count
  //     recurring_member_count          — (T,T) count
  //     max_prior_tenure_versions       — severity-only, no cell
  //                                        filter; safe as a WORST-
  //                                        CASE severity read but not
  //                                        a disposition shortcut on
  //                                        its own (needs the cold-
  //                                        handoff filter to matter)
  //
  //   UNSAFE aggregates (gate MUST NOT shortcut):
  //     has_overlap_transition — OR across heterogeneous transitions.
  //                              A single legitimate rotation sets it
  //                              true regardless of any later cold
  //                              handoff. Display-only. See the
  //                              annotation on the field below.
  //
  // The 2×2 cell histogram — cold_handoff_count,
  // new_committee_member_count, returning_dormant_count,
  // recurring_member_count — is the STANDOUT AGGREGATE. A four-integer
  // shape fingerprint per package that no competing tool publishes,
  // derived deterministically from observable history. An auditor can
  // read the package's entire publisher shape in one line.
  //
  // Zero semantics (risk #3 decision): max_cold_handoff_prior_tenure
  // is 0 when no (F,F) transition exists. Paired with cold_handoff_count
  // (also 0 in that case) this disambiguates from the degenerate state
  // "(F,F) transition with prior_tenure=0" — which cannot arise from a
  // real history anyway, since the smallest tenure block has
  // version_count=1.
  let maxPriorTenureVersions = 0;
  let maxColdHandoffPriorTenure = 0;
  let coldHandoffCount = 0;            // cell (F, F)
  let newCommitteeMemberCount = 0;     // cell (T, F)
  let returningDormantCount = 0;       // cell (F, T)
  let recurringMemberCount = 0;        // cell (T, T)
  for (const t of transitions) {
    if (t.prior_tenure_versions > maxPriorTenureVersions) {
      maxPriorTenureVersions = t.prior_tenure_versions;
    }
    const overlap = t.is_overlap_window_W3;
    const known = t.is_known_contributor_K10;
    if (overlap && known) {
      recurringMemberCount += 1;
    } else if (overlap && !known) {
      newCommitteeMemberCount += 1;
    } else if (!overlap && known) {
      returningDormantCount += 1;
    } else {
      coldHandoffCount += 1;
      if (t.prior_tenure_versions > maxColdHandoffPriorTenure) {
        maxColdHandoffPriorTenure = t.prior_tenure_versions;
      }
    }
  }

  // --- Tier 3: temporal summary ---
  //
  // Anchors severity numbers in calendar time. "Prior tenure of 147
  // versions" means something different across 7 years vs. 7 months;
  // the gate layer can multiply Tier 2 by Tier 3 context when tuning
  // disposition thresholds. Integer-only math over already-integer
  // published_at_ms — no Date.now, no float arithmetic, deterministic
  // across machines.
  //
  // Empty history: every field is 0. A single-block single-version
  // history: total_history_duration_ms=0, longest_tenure_versions=1,
  // longest_tenure_duration_ms=0 (a one-version block has no span).
  //
  // Gap-filling policy (risk #4 decision): degraded rows are already
  // dropped in normalizeAndFilter before tenure runs. A history like
  // [A@day-0, A@day-1000, (null-row @day-500)] reports
  // total_history_duration_ms = 1000 * DAY_MS — span of OBSERVED rows
  // only. No interpolation. Missing rows are observability gaps.
  let totalHistoryDurationMs = 0;
  let longestTenureVersions = 0;
  let longestTenureDurationMs = 0;
  if (tenure.length > 0) {
    totalHistoryDurationMs =
      tenure[tenure.length - 1].last_published_at_ms - tenure[0].first_published_at_ms;
    for (const block of tenure) {
      if (block.version_count > longestTenureVersions) {
        longestTenureVersions = block.version_count;
      }
      if (block.duration_ms > longestTenureDurationMs) {
        longestTenureDurationMs = block.duration_ms;
      }
    }
  }

  return {
    // Tier 1
    observed_versions_count: observedVersionsCount,
    unique_identity_count: uniqueIdentityCount,
    has_sufficient_history: hasSufficientHistory,

    // Tier 2
    max_prior_tenure_versions: maxPriorTenureVersions,
    max_cold_handoff_prior_tenure: maxColdHandoffPriorTenure,
    cold_handoff_count: coldHandoffCount,
    new_committee_member_count: newCommitteeMemberCount,
    returning_dormant_count: returningDormantCount,
    recurring_member_count: recurringMemberCount,

    // Tier 3
    total_history_duration_ms: totalHistoryDurationMs,
    longest_tenure_versions: longestTenureVersions,
    longest_tenure_duration_ms: longestTenureDurationMs,

    // Pre-2f signals kept: these predate the tiered aggregation and are
    // still referenced by tests / future wiring.
    transition_count: transitions.length,
    skipped_versions_count: skippedVersionsCount,
    // GATE CONTRACT — UNSAFE AGGREGATE. DISPLAY ONLY.
    //
    // has_overlap_transition is the OR of is_overlap_window_W3 across
    // all transitions. It answers "did ANY transition look like
    // committee rotation?" — nothing more. The gate MUST NOT shortcut
    // to ALLOW on this aggregate alone: a package with one legitimate
    // rotation followed by a cold-handoff takeover will have it set
    // to true. Use the 2×2 cell histogram (Tier 2) for disposition.
    has_overlap_transition: transitions.some((t) => t.is_overlap_window_W3),
  };
}

export default {
  name: 'publisher',
  version: 1,
  requires: ['history'],

  extract(input) {
    validateInput(input);
    const { rows, skipped } = normalizeAndFilter(input.history);
    // Sort runs even when rows is empty — keeps behaviour uniform and
    // guarantees downstream sub-steps can assume sorted input.
    const sorted = sortRows(rows);
    const tenure = extractTenure(sorted);
    const transitions = extractTransitions(tenure);
    extractOverlap(transitions, tenure);
    extractKnownContributor(transitions, tenure);
    const signals = extractSignals(sorted, tenure, transitions, skipped);

    // Sub-step 2f step 2 (Tier 1) lands here. identity_profile / shape
    // keep the locked contract shape from sub-step 1 and are filled in
    // by step 3. Tier 2 (severity extrema + 2×2 cell histogram) lands
    // in step 3 of 2f; Tier 3 (temporal summary) in step 4 of 2f.
    return {
      tenure,
      transitions,
      identity_profile: {},
      shape: 'unknown',
      signals,
    };
  },
};
