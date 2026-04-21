// Provenance pattern — Section 11 step 2b of docs/V2_DESIGN.md.
//
// Extracts per-version provenance baseline signals from a package's
// observed publish history. Deterministic, pure function over sorted
// version rows. No external calls. No attestation-content parsing —
// the pattern only reads the presence/absence of an attestation and
// who carried the baseline before a regression. Deep verification
// (predicate type, issuer chain, workflow identity) belongs in the
// witness layer and is out of scope here.
//
// =====================================================================
// GATE CONTRACT — READ BEFORE CONSUMING PATTERN OUTPUT
// =====================================================================
// The provenance pattern emits per-version signals, NOT per-transition
// signals. The unit of analysis is the single release being evaluated,
// asking: "did this release break a package-level attestation
// baseline?"
//
// Pattern output pairs with patterns/publisher.js at the disposition
// layer. Two patterns, two units of analysis:
//
//   publisher   → transition (block N → block N+1) → 2×2 cell + shape
//                                                    + severity
//   provenance  → single version (package-level)  → provenance_regression
//
// Disposition reads both. Neither is a strict subset of the other. A
// release can trigger provenance regression without a publisher-layer
// cold handoff (axios@1.14.1 case) and vice versa (event-stream@3.3.6
// case). The combination is NOT a simple OR — severity depends on
// which pattern fired and the supporting context.
//
// BASELINE DEFINITION (per-major, amended 2026-04-21).
//
//   A package has an ESTABLISHED provenance baseline at version T
//   in major M when the last MIN_BASELINE_STREAK versions strictly
//   prior to T WITHIN MAJOR M were all attested
//   (provenance_present === true). Cross-major versions do not
//   contribute to and do not reset major M's streak.
//
//   Starter constant: MIN_BASELINE_STREAK = 3.
//     - 1 is trivially any attested release — false baselines on
//       first-time OIDC users.
//     - 2 rules out one-offs but still fires on OIDC pilots.
//     - 3 requires three consecutive attested releases — enough to
//       say "attested publish is the norm here, not an experiment."
//       axios attack has 4 consecutive machine-OIDC versions before
//       it in the 1.x train, so K=3 detects it; legitimate one-off
//       CI trials do not.
//     - 4+ misses real breaks on packages with shorter release
//       histories.
//   Subject to revision in calibrate.js (Phase 5) against the train
//   set. Corpus diagnostic under K=3 on the full 104-package seed
//   (per-major): 9 of 104 packages fire ≥1 regression, 239 total
//   fires, zero concerning FPs in a 5-sample classification — all
//   non-attack fires lack any escalator and land at WARN.
//
// STREAK COUNTING (per-major, amended 2026-04-21).
//
//   Streaks are counted per major. Each major maintains its own
//   independent streak; a version in major N does not contribute
//   to and does not reset major M's streak. The stream is still
//   ordered by published_at_ms ascending with a stable secondary
//   key (see sortRows() below) — only the streak dimension is
//   partitioned by major.
//
//   prior_consecutive_attested is computed STRICTLY BEFORE version T
//   WITHIN MAJOR M; it counts the run of attested versions in
//   major M immediately preceding T, skipping over versions in
//   other majors. A non-attested version T in major M consumes
//   major M's streak for the purpose of evaluating T, then resets
//   major M's streak to 0; other majors' streaks are untouched.
//
//   This correctly handles the "CLI between OIDC" gap within a
//   major AND the legacy-branch backport case across majors: a
//   single unsigned release in major M fires (if major M's
//   baseline was already reached) and rebuilds from 0 in major M;
//   a CLI release in major N has no effect on major M's streak.
//
// REGRESSION SIGNAL.
//
//   provenance_regression fires at version T iff:
//       baseline_established(T) AND NOT provenance_present(T)
//
//   This is the primary feature disposition reads. It is NOT a
//   disposition itself — WARN vs BLOCK is decided by the disposition
//   layer combining this signal with publisher-pattern output and
//   the four escalator rules below.
//
// PER-VERSION in_scope SEMANTICS (per-major, amended 2026-04-21).
//
//   in_scope is PER-VERSION AND PER-MAJOR. At version T in major M,
//   in_scope=true iff major M has reached MIN_BASELINE_STREAK
//   consecutive attested versions at some point at or before T
//   WITHIN MAJOR M's own stream. Monotonicity applies within a
//   major only — baseline-reached in major M does NOT imply
//   in_scope=true for any version in major N. Each major carries
//   its own sticky baseline-reached bit.
//
//   Attacks on majors that never adopted OIDC (event-stream@3.3.6
//   in major 3, ua-parser-js@0.7.29 in major 0, ua-parser-js@1.0.0
//   in major 1) have in_scope=false at their attack version even
//   if other majors of the same package did adopt OIDC. The
//   provenance pattern has nothing to say about them; silence is
//   correct. Publisher-pattern cold-handoff detection carries
//   those cases independently.
//
// PRIOR BASELINE CARRIERS (per-major, amended 2026-04-21).
//
//   prior_baseline_carriers records WHO was publishing during the
//   current baseline streak within the version's major — up to the
//   version being evaluated, intersected with major M's stream.
//   Cross-major identities do not contribute (they are not in the
//   streak by construction, since the streak is per-major).
//   any_machine distinguishes "CI was the baseline in this major"
//   (GitHub Actions bot with npm-oidc-no-reply@github.com, strongest
//   signal) from "one individual's personal trusted-publisher OIDC
//   was the baseline in this major" (weaker signal — same human who
//   may legitimately revert to CLI). This flag feeds escalator (d)
//   below.
//
// DISPOSITION INTERACTION TABLE (axes: incoming-identity relationship
// to prior history × provenance state at version T).
//
//   incoming identity                 | in_scope=false | in_scope=true, | in_scope=true,
//                                     |                | no regression  | regression
//   --------------------------------- | -------------- | -------------- | -----------------
//   same as any prior identity        | ALLOW          | ALLOW          | WARN, BLOCK if
//   (login matches prior block)       |                |                | any escalator
//                                     |                |                | (a,b,c,d) fires
//   --------------------------------- | -------------- | -------------- | -----------------
//   new identity, committee shape     | ALLOW          | ALLOW          | WARN
//   --------------------------------- | -------------- | -------------- | -----------------
//   new identity, solo cold handoff,  | BLOCK          | BLOCK          | BLOCK (reinforced)
//   high prior tenure                 | (publisher)    | (publisher)    |
//   --------------------------------- | -------------- | -------------- | -----------------
//   new identity, non-solo cold       | WARN (unless   | WARN           | BLOCK — regression
//   handoff                           | co-signals)    |                | is Addition-3
//                                     |                |                | co-signal
//
// AMENDED 2026-04-21. Previously the table keyed on publisher's 2×2
// cell classification (recurring_member / new_committee_member /
// returning_dormant / cold_handoff). Two problems with that keying:
//
//   1. Fixture-scope dependence. Publisher's K=10
//      is_known_contributor threshold counts prior versions of an
//      identity across all observed blocks. A login that has
//      legitimately accumulated 100+ versions in the full registry
//      history may show <10 under a scoped fixture slice (e.g., the
//      axios 1.13.0→1.15.1 slice the Phase-2 multi-branch deferral
//      pins). That flips the publisher cell from recurring_member
//      (T,T) to new_committee_member (T,F) for axios@1.14.1 — but
//      the security question is unchanged: jasonsaayman is the same
//      login on both sides of the transition.
//
//   2. Publisher's cells encode PUBLISHER-PATTERN severity (committee
//      churn vs cold handoff with long tenure, etc.). The provenance
//      question is narrower: has this login been seen before in this
//      package? Reusing the cell labels coupled two decisions that
//      should stay orthogonal.
//
// The amended table routes on IDENTITY CONTINUITY: does the incoming
// publisher's account login match any prior block's identity in this
// package? This is slice-invariant and matches the attack model —
// axios-class attacks push under a login that has appeared before,
// which is what the escalator rules are calibrated to evaluate.
//
// ROUTING DEFINITION.
//
//   Disposition iterates over every per-version provenance record
//   where in_scope=true, not only transition boundaries. For each:
//
//     * version is at a transition boundary AND incoming identity
//       matches any prior block's identity → "same as prior identity"
//       row (escalators evaluated).
//     * version is at a transition boundary AND incoming identity is
//       genuinely new (not seen in prior history) → publisher-cell-
//       driven row: new_committee / cold_handoff / returning_dormant
//       per the publisher pattern's existing severity logic.
//     * version is intra-block (no transition at this version) →
//       "same as prior identity" row by definition: intra-block means
//       the publisher identity is unchanged from the block's start.
//
// Where the table shows BLOCK for in_scope=false, disposition is
// driven by the publisher pattern independently. Provenance pattern
// silence on in_scope=false is correct and does NOT weaken
// publisher-pattern BLOCK — the two patterns are layered, not
// gating. event-stream@3.3.6 is the canonical illustration:
// provenance says nothing (pre-OIDC era, in_scope=false); publisher
// says BLOCK (solo high-tenure cold handoff dominictarr →
// right9ctrl); final disposition is BLOCK.
//
// ESCALATOR RULES (recurring_member / no-transition → BLOCK).
//
//   The case to avoid: a legitimate maintainer pushing an emergency
//   CLI release on a package that normally publishes via CI. axios
//   @1.13.3 is the canonical corpus example and must land at WARN.
//
//   Escalation from WARN to BLOCK on a recurring_member or
//   no-transition cell with provenance_regression=true requires AT
//   LEAST ONE of:
//
//     (a) The incoming release introduces a new email domain for the
//         package — specifically, a domain not seen in any prior
//         version of the publisher history. (axios 1.14.1: proton.me
//         is new. axios 1.13.3: gmail.com is not new.)
//     (b) The incoming email is on a PRIVACY provider class as
//         classified by patterns/provider.js. (axios 1.14.1:
//         proton.me is privacy. axios 1.13.3: gmail.com is webmail,
//         not privacy.)
//     (c) The incoming email is on an UNVERIFIED domain class as
//         classified by patterns/provider.js. (Typosquatted / newly
//         registered, etc.)
//     (d) The prior baseline was MACHINE-attested
//         (prior_baseline_carriers.any_machine=true) and the incoming
//         release is from a non-machine identity. (axios 1.14.1: yes
//         — 1.13.4–1.14.0 were GitHub Actions. axios 1.13.3: no —
//         the prior baseline was jasonsaayman's personal OIDC.)
//
//   axios@1.14.1 satisfies (a), (b), and (d). axios@1.13.3 satisfies
//   none of the four → WARN. This is the canonical split.
//
// RULES THE GATE MUST NOT DO.
//
//   * MUST NOT BLOCK solely on provenance_regression=true. A
//     regression on its own is a WARN-strength signal. BLOCK requires
//     a publisher-layer co-signal OR one of the four escalators.
//   * MUST NOT BLOCK on in_scope=false. A package-version without an
//     attestation history is not an attack target for the provenance
//     pattern. Silence is the correct output.
//   * MUST NOT consume max_consecutive_attested or regression_count
//     package-level aggregates as disposition drivers. These are for
//     display and metrics. Per-version provenance_regression is the
//     only disposition-relevant feature.
//
// WHY THIS LAYERING WORKS.
//
//   The publisher pattern answers "who is publishing" (identity,
//   tenure, rotation). The provenance pattern answers "how is the
//   package published" (attested CI vs raw CLI). These are
//   orthogonal. Previously, publisher.js covered both imperfectly
//   by folding provenance signals into block metadata keyed by
//   identity; that collapsed when identity is preserved across an
//   attack (axios — same jasonsaayman npm login across 1.14.1).
//   Separating concerns restores detection on same-identity attacks
//   that swap publishing infrastructure.
//
// PER-MAJOR RATIONALE (amended 2026-04-21).
//
//   Earlier versions of this contract treated the package's version
//   history as a single ordered stream for streak purposes. That
//   collapsed when a package publishes legacy-branch CLI releases
//   alongside active-branch OIDC releases (axios 1.x OIDC +
//   sporadic 0.30.x CLI backports). A CLI release on the legacy
//   major reset the single-stream streak, so the attack version
//   one release later on the active major saw a pre-regression
//   streak of 2 instead of the true 4 — baseline was not
//   established at the attack version, in_scope was false,
//   regression was suppressed, and disposition demoted from BLOCK
//   to WARN.
//
//   The per-major amendment partitions the streak dimension by
//   SemVer major. Each major carries its own streak, baseline-
//   reached bit, in_scope state, and regression firings. A CLI
//   release in major N has no effect on major M's streak.
//
//   Validated on the 104-package seed (see docs/PROVENANCE_
//   DIAGNOSTIC_FINDINGS.md, 2026-04-21):
//     * axios@1.14.1 on full 135-version history → BLOCK with
//       escalators [new_domain, privacy, machine_to_human]
//       (previously suppressed to WARN).
//     * event-stream@3.3.6, ua-parser-js@0.7.29/0.8.0/1.0.0:
//       in_scope=false under both semantics (majors never
//       adopted OIDC); silence preserved; publisher-pattern
//       BLOCK unchanged.
//     * lodash@4.17.16: publisher-driven BLOCK, provenance
//       silent under both semantics; unchanged.
//     * Corpus FP surface: 9 packages / 239 fires per-major vs
//       17 / 274 prior. All non-attack fires land at WARN
//       (zero escalators) per the 5-sample classification.
//
//   Edge-case handling (no special logic added):
//     * Packages that skip majors (0.x → 2.x): each major is
//       independent. No bridge across the gap.
//     * Mid-major OIDC adoption (CLI then attested within same
//       major): streak starts when the first attested version
//       in that major appears; builds from there. This is
//       identical to current behavior on a single-major package.
//     * Prerelease versions (-alpha, -canary, nightly builds):
//       included in their major's stream with no special
//       handling. Display-layer rollup (deferred, see docs/
//       FUTURE_DIRECTIONS.md) will address WARN volume from
//       CI-alpha/CLI-stable alternation patterns at the UX
//       layer, NOT at the detection layer — benign-pattern
//       detection rules would create attacker-reachable
//       suppression recipes.
// =====================================================================
//
// INPUT SHAPE.
//
//   {
//     packageName: string,        // required, non-empty
//     history: Array<{            // required, array (may be empty)
//       version:             string,                    // non-empty
//       published_at_ms:     integer,                   // ms since epoch
//       publisher_name:      string | null,
//       publisher_email:     string | null,
//       publisher_tool:      string | null,             // e.g. "npm@10.8.2"
//       provenance_present:  0 | 1 | true | false | null,
//     }>
//   }
//
// Rows missing either (version, published_at_ms as integer) are
// skipped and counted in signals.skipped. Unlike publisher.js this
// pattern does NOT require publisher_email to be present on every
// row — a row with null publisher_email can still contribute to
// the attested/unsigned streak count. Only the row at the
// regression-firing position needs a publisher_email for the
// escalator rules to work at the disposition layer.
//
// Empty history is a valid input representing a never-before-seen
// package and does NOT throw. If history is empty (or every row is
// skipped), extract() returns a valid result with
// perVersion: [] and packageRollup: {zero-valued fields}. Empty
// history is distinguished from missing/malformed history (which
// throws in validateInput).
//
// NULL provenance_present semantics. Rows with provenance_present
// === null (or undefined, or any value other than 0/1/true/false)
// are treated as UNKNOWN. Such rows neither contribute to streak
// counting nor fire regression. Only explicit 0/false/1/true
// values drive the signal. This is the conservative choice —
// unknown state is not evidence of regression, and the 5 corpus
// rows with NULL provenance_present are all reconstructed attack
// metadata where absence of a value should not be over-interpreted.
// Implementation note: an unknown row is not "unsigned" — it
// neither extends the streak nor resets it to 0. It is threaded
// through as a skipped-for-signal-purposes row but retained in
// perVersion output for completeness (with provenance_present:
// null and provenance_regression: false).
//
// publisher_tool (e.g. "npm@10.8.2") is captured into the
// per-version signal record for display and metrics ONLY. It is
// not consumed by regression detection or escalator logic in V1.
// Reserved for future pattern extensions (e.g. CLI fingerprint
// change detection, or distinguishing raw `npm publish` from
// third-party tooling).
//
// OUTPUT SHAPE (per-version signal record + package rollup).
//
// Per-version entry (one per accepted row, in sorted order):
//
//   {
//     version:                     string,
//     published_at_ms:             integer,
//     provenance_present:          boolean,
//     prior_consecutive_attested:  integer,   // streak strictly before T
//     baseline_established:        boolean,   // prior_streak >= K
//     provenance_regression:       boolean,   // baseline && !attested
//     in_scope:                    boolean,   // baseline ever reached at or before T
//     prior_baseline_carriers: {              // null if baseline not established
//       identities:  string[],                // unique publisher_names in the streak
//       emails:      string[],                // unique publisher_emails in the streak
//       any_machine: boolean,                 // at least one machine-identity carrier
//       any_human:   boolean,                 // at least one human-identity carrier
//     } | null,
//     incoming_publisher: {
//       name:  string | null,
//       email: string | null,
//       tool:  string | null,
//     },
//   }
//
// Package rollup (aggregate, for display and metrics ONLY — gate MUST
// NOT consume these as disposition drivers):
//
//   {
//     total_versions:              integer,
//     attested_versions:           integer,
//     max_consecutive_attested:    integer,
//     has_baseline_at_head:        boolean,   // baseline state at latest version
//     regression_versions:         string[],
//     regression_count:            integer,
//     machine_attested_versions:   integer,
//     human_attested_versions:     integer,
//     first_attested_version:      string | null,
//     first_baseline_reached_at:   string | null,  // version at which baseline first became true
//   }
//
// SIGNALS OBJECT.
//
//   {
//     skipped:                  integer,   // rows dropped in normalize
//     has_sufficient_history:   boolean,   // observed_versions_count >= MIN_HISTORY_DEPTH
//     min_baseline_streak:      integer,   // K actually used (for logging)
//   }
//
// has_sufficient_history mirrors publisher.js's short-circuit gate.
// A package with fewer than MIN_HISTORY_DEPTH total observed versions
// cannot produce provenance_regression=true even if its visible
// versions happen to form an A-A-A-U pattern — applying K=3 against
// 5-version packages would generate regressions on genuinely
// experimental OIDC adoption.

import { MIN_HISTORY_DEPTH } from '../constants.js';
import { compareSemver, parseSemver } from './semver.js';

// Streak threshold — how many consecutive prior attested versions
// are required before a non-attested release at position T fires
// provenance_regression. Starter value, subject to calibration
// sweep in Phase 5 against the train set.
const MIN_BASELINE_STREAK = 3;

// Machine-identity marker — GitHub Actions bot email. Used by
// extractPriorBaselineCarriers to populate
// prior_baseline_carriers.any_machine. Starter heuristic; future
// calibration may widen this to a pattern set (CI-as-publisher bots
// from other trusted-publisher providers).
const MACHINE_PUBLISHER_EMAIL = 'npm-oidc-no-reply@github.com';

// Major-component extractor used by per-major streak partitioning.
// Uses the shared parseSemver first (strict semver); falls back to
// a leading-digit regex so unusual-but-sort-stable strings like
// "0.0.0-nightly-…" still classify into a coherent major. Returns
// null only for genuinely unparseable versions — those share a
// single null-keyed bucket so they still participate in streak
// counting as a coherent group rather than vanishing.
function extractMajor(version) {
  const parsed = parseSemver(version);
  if (parsed !== null) return parsed.major;
  const m = /^(\d+)\./.exec(version);
  return m ? Number(m[1]) : null;
}

function validateInput(input) {
  if (!input || typeof input !== 'object') {
    throw new Error('provenance.extract: input must be a non-null object');
  }
  if (typeof input.packageName !== 'string' || input.packageName.length === 0) {
    throw new Error('provenance.extract: input.packageName must be a non-empty string');
  }
  if (!Array.isArray(input.history)) {
    throw new Error('provenance.extract: input.history must be an array');
  }
}

// ---------------------------------------------------------------------------
// Step 1 — normalizeAndSortHistory
//
// Row-level validation + deterministic sort. Invalid rows are dropped
// and counted in `skipped`. The output `rows` array is ready for the
// streak walker in Step 2 (computeStreakSignals); each row carries
// normalized fields and a strict-boolean-or-null provenance_present.
//
// Drop criteria:
//   * row is null/not-object
//   * missing non-empty string `version`
//   * missing integer `published_at_ms`
// Any other field may be absent or malformed without dropping the row —
// null publisher_email is explicitly acceptable (GATE CONTRACT input
// shape). The pattern needs version + timestamp to anchor the stream;
// everything else is graceful-degradation.
//
// provenance_present is coerced to strict {true, false, null}:
//   * 1 or true                            → true
//   * 0 or false                            → false
//   * everything else (null, undefined, …) → null  (UNKNOWN)
// This is the load-bearing step for NULL semantics per the GATE
// CONTRACT. Never treat null as unsigned; downstream sees exactly
// three states.
//
// Sort order (finalizes the Phase-1-open tiebreaker decision):
//   primary   — published_at_ms ASC
//   secondary — compareSemver(version) ASC
// No id-based tiebreak — the pattern input shape does not carry id.
// Semver ordering matches patterns/publisher.js sortRows() convention,
// keeps the two patterns aligned, and is deterministic on any two
// accepted rows (non-empty version strings always compare).
//
// Returns { rows, skipped: { count, reasons } } where `reasons` is an
// array of `{ index, reason }` objects — one entry per dropped row in
// input order. Array is ordered so drift diffs stay legible; if the
// count climbs, the reasons tell you why without re-running the load.
//
// Duplicate-version rejection. When two rows share the same `version`
// string, only the first occurrence (in INPUT order) is retained. Any
// later occurrence is dropped with reason 'duplicate_version'. Two
// reasons for this policy:
//   1. The pattern's unit of analysis is "the release at version T."
//      Two rows claiming the same version makes that question
//      ill-posed — which row IS the release? The input is
//      malformed, and silently concatenating a second row into the
//      stream would inflate attested/regression counts without
//      basis.
//   2. Determinism. Without explicit handling, the sort could
//      interleave the duplicates arbitrarily when timestamps also
//      match, causing pattern-cache drift between machines.
// First-seen-wins matches the "trust the earliest observation" bias
// used elsewhere in the collector; callers with genuine version
// collisions (none known in the 104-package seed) would need to
// de-duplicate before calling extract().
function normalizeAndSortHistory(history) {
  const rows = [];
  const reasons = [];
  const seenVersions = new Set();
  for (let i = 0; i < history.length; i += 1) {
    const raw = history[i];
    if (!raw || typeof raw !== 'object') {
      reasons.push({ index: i, reason: 'row is not an object' });
      continue;
    }
    const version =
      typeof raw.version === 'string' && raw.version.length > 0 ? raw.version : null;
    if (version === null) {
      reasons.push({ index: i, reason: 'missing or empty version' });
      continue;
    }
    if (!Number.isInteger(raw.published_at_ms)) {
      reasons.push({ index: i, reason: 'missing or non-integer published_at_ms' });
      continue;
    }
    if (seenVersions.has(version)) {
      reasons.push({ index: i, reason: 'duplicate_version' });
      continue;
    }
    seenVersions.add(version);
    let provenance_present = null;
    if (raw.provenance_present === 1 || raw.provenance_present === true) {
      provenance_present = true;
    } else if (raw.provenance_present === 0 || raw.provenance_present === false) {
      provenance_present = false;
    }
    const publisher_name =
      typeof raw.publisher_name === 'string' && raw.publisher_name.length > 0
        ? raw.publisher_name
        : null;
    const publisher_email =
      typeof raw.publisher_email === 'string' && raw.publisher_email.length > 0
        ? raw.publisher_email.trim().toLowerCase()
        : null;
    const publisher_tool =
      typeof raw.publisher_tool === 'string' && raw.publisher_tool.length > 0
        ? raw.publisher_tool
        : null;
    rows.push({
      version,
      published_at_ms: raw.published_at_ms,
      publisher_name,
      publisher_email,
      publisher_tool,
      provenance_present,
    });
  }
  rows.sort((a, b) => {
    if (a.published_at_ms !== b.published_at_ms) {
      return a.published_at_ms < b.published_at_ms ? -1 : 1;
    }
    return compareSemver(a.version, b.version);
  });
  return { rows, skipped: { count: reasons.length, reasons } };
}

// ---------------------------------------------------------------------------
// Step 2 — computeStreakSignals
//
// Deterministic walk over sortedRows producing a per-version signal
// record. Pure function of the sorted stream and K; no sufficiency
// gate — sufficiency is applied downstream in extract() so the walker
// stays testable in isolation on short fixtures.
//
// SEMANTICS.
//
//   streak             — current count of consecutive attested
//                        versions observed just before the row being
//                        evaluated. Reset by any explicit provenance_
//                        present=false. Unchanged by null (UNKNOWN).
//   baselineEverReached — sticky bit: once the streak reaches K at or
//                        before row T, this stays true for every
//                        subsequent row. Drives in_scope monotonicity.
//
//   Per row T:
//     prior_consecutive_attested := streak (strictly before T)
//     baseline_established       := priorStreak >= K
//     provenance_regression      := baseline_established AND
//                                    provenance_present === false
//     in_scope                   := baselineEverReached AFTER
//                                    updating streak with T's value
//                                    (so the version that first
//                                    COMPLETES the K-streak carries
//                                    in_scope=true — matches design-
//                                    doc first_baseline_reached_at
//                                    semantics: axios@1.13.2 becomes
//                                    in_scope at itself, not 1.13.3)
//
// NULL THREADING.
//
//   A row with provenance_present === null neither contributes to the
//   streak nor fires regression. The streak is preserved across a null
//   row. baseline_established can still be true on a null row if the
//   prior streak is ≥ K, but the regression AND clause fails because
//   provenance_present !== false. This matches the GATE CONTRACT
//   "unknown is not unsigned" invariant.
//
// NOTE ON in_scope vs baseline_established.
//
//   baseline_established answers "does the streak STRICTLY BEFORE T
//   meet the threshold?" — used to decide whether T's unsigned state
//   is a regression. in_scope answers "has the package ever hit
//   baseline up to and including T?" — used to decide whether the
//   pattern has anything to say about T at all. The two align at
//   axios@1.13.3 (baseline AT 3 before, regression fires, in_scope
//   true) and differ at axios@1.13.2 (baseline not yet AT 3 before,
//   no regression, but in_scope TRUE because this version completes
//   the K-streak).
function computeStreakSignals(sortedRows, minBaselineStreak = MIN_BASELINE_STREAK) {
  const signals = [];
  // Per-major state map: each major carries its own streak and
  // sticky baselineEverReached bit. The stream iteration order is
  // still the sorted (time-ascending) order of the full history; we
  // just route each row's signal through its major's state slot.
  const perMajorState = new Map();
  for (const row of sortedRows) {
    const major = extractMajor(row.version);
    let state = perMajorState.get(major);
    if (!state) {
      state = { streak: 0, baselineEverReached: false };
      perMajorState.set(major, state);
    }
    const priorStreak = state.streak;
    const baseline_established = priorStreak >= minBaselineStreak;
    const provenance_regression =
      baseline_established && row.provenance_present === false;
    if (row.provenance_present === true) {
      state.streak = priorStreak + 1;
    } else if (row.provenance_present === false) {
      state.streak = 0;
    } // null: streak unchanged
    if (state.streak >= minBaselineStreak) state.baselineEverReached = true;
    signals.push({
      version: row.version,
      prior_consecutive_attested: priorStreak,
      baseline_established,
      provenance_regression,
      in_scope: state.baselineEverReached,
    });
  }
  return signals;
}

// ---------------------------------------------------------------------------
// Step 3 — extractPriorBaselineCarriers
//
// Returns the identity profile of the versions that carried the
// currently-established baseline into version T. Input is the rows
// strictly before T plus the streak length (prior_consecutive_attested
// at T). The K carriers are the LAST `streakLength` rows of
// rowsBeforeT — by construction those are all attested (else they
// wouldn't be in the streak).
//
// any_machine / any_human heuristic.
//
//   machine = publisher_email exactly matches MACHINE_PUBLISHER_EMAIL
//   (GitHub Actions trusted-publisher bot, the dominant attested-
//   publish identity in the 104-package seed). Starter pattern;
//   future calibration may widen the match to other CI bot addresses
//   as they appear in the corpus.
//
//   human = non-null publisher_email that does NOT match the machine
//   pattern. Rows with null publisher_email contribute neither — we
//   can't tell the shape of an unknown identity, and classifying
//   missing data as "human" would inflate the human signal
//   mechanically. Conservative bias: unknown emails are excluded
//   from both counts.
//
// Ordering / determinism.
//
//   identities and emails are de-duplicated and sorted ASCII ASC so
//   two runs on identical inputs produce byte-identical output
//   (pattern-cache determinism contract).
//
// Empty-streak behaviour.
//
//   If streakLength is 0 or exceeds rowsBeforeT.length, the function
//   still returns a valid object with empty arrays and both flags
//   false. The caller (per-version assembly in Step 4) MUST set
//   prior_baseline_carriers=null when baseline_established=false, so
//   this branch is defensive rather than normal operation.
function extractPriorBaselineCarriers(rowsBeforeT, streakLength) {
  const empty = { identities: [], emails: [], any_machine: false, any_human: false };
  if (!Array.isArray(rowsBeforeT) || streakLength <= 0) return empty;
  const start = Math.max(0, rowsBeforeT.length - streakLength);
  const carriers = rowsBeforeT.slice(start);
  const identitySet = new Set();
  const emailSet = new Set();
  let any_machine = false;
  let any_human = false;
  for (const row of carriers) {
    if (row.publisher_name) identitySet.add(row.publisher_name);
    if (row.publisher_email) {
      emailSet.add(row.publisher_email);
      if (row.publisher_email === MACHINE_PUBLISHER_EMAIL) {
        any_machine = true;
      } else {
        any_human = true;
      }
    }
  }
  return {
    identities: [...identitySet].sort(),
    emails: [...emailSet].sort(),
    any_machine,
    any_human,
  };
}

// ---------------------------------------------------------------------------
// Step 4a — assemblePerVersionRecord
//
// Pure combiner: given a normalized row, its streak signal, and the
// already-computed carrier struct (null when baseline not
// established), emit the per-version record exactly as specified in
// the GATE CONTRACT OUTPUT SHAPE block. No defaults, no derivation
// — every field is explicit so the output is inspection-friendly and
// the caller's responsibility for carriers-vs-null is visible at the
// call site.
function assemblePerVersionRecord(row, streakSignal, carriers) {
  return {
    version: row.version,
    published_at_ms: row.published_at_ms,
    provenance_present: row.provenance_present,
    prior_consecutive_attested: streakSignal.prior_consecutive_attested,
    baseline_established: streakSignal.baseline_established,
    provenance_regression: streakSignal.provenance_regression,
    in_scope: streakSignal.in_scope,
    prior_baseline_carriers: carriers,
    incoming_publisher: {
      name: row.publisher_name,
      email: row.publisher_email,
      tool: row.publisher_tool,
    },
  };
}

// ---------------------------------------------------------------------------
// Step 4b — assemblePackageRollup
//
// Package-level aggregate derived from sortedRows + per-version
// records. Every field is filled (no undefineds) so consumers can
// read without `?? 0` guards — mirrors publisher.js signals contract.
//
// Under per-major streak semantics (amended 2026-04-21), the three
// streak-derived fields are aggregated across the per-major streams:
//
//   max_consecutive_attested — the longest run of consecutive
//     provenance_present===true rows observed in ANY single major's
//     stream. Taking the max across majors preserves the field's
//     "how strong was this package's attestation discipline at its
//     peak" meaning without letting cross-major gaps artificially
//     shrink it. Null rows do NOT break the run within a major (per
//     the UNKNOWN-is-not-unsigned invariant) but do not extend it
//     either — they pass through invisibly.
//
//   has_baseline_at_head — true iff the LATEST row's own major has
//     a streak ≥ K at that point. "Is the baseline currently intact
//     on the major the package is actively releasing into?"
//     Disposition never reads it (GATE CONTRACT MUST-NOT rule);
//     it is a display/metrics field.
//
//   first_baseline_reached_at — earliest version across any major
//     that FIRST completes a K-attested run within its own major.
//     Iterates in time order so the first-across-any-major wins,
//     matching the display semantic "when did this package first
//     reach an attested baseline in any release train."
//
// per_major — new display/metrics breakdown keyed by major number.
// Each entry carries the same shape as the package-level fields but
// scoped to that major's stream. Keys are stringified integers so
// JSON-serialization is stable; a null-major bucket (unparseable
// versions) is stringified as "null". Sorted ascending by key in the
// output for determinism.
//
// Machine/human attested counts mirror the any_machine / any_human
// flag semantics: null-email rows contribute to NEITHER count, even
// if provenance_present===true. Conservative bias; unknown identity
// shouldn't inflate either side.
function assemblePackageRollup(perVersion, sortedRows, minBaselineStreak = MIN_BASELINE_STREAK) {
  const total_versions = sortedRows.length;
  let attested_versions = 0;
  let machine_attested_versions = 0;
  let human_attested_versions = 0;
  let first_attested_version = null;
  for (const row of sortedRows) {
    if (row.provenance_present === true) {
      attested_versions += 1;
      if (first_attested_version === null) first_attested_version = row.version;
      if (row.publisher_email === MACHINE_PUBLISHER_EMAIL) {
        machine_attested_versions += 1;
      } else if (row.publisher_email !== null) {
        human_attested_versions += 1;
      }
    }
  }

  // Per-major streak accumulators. Keyed by major (integer or null);
  // each entry tracks running streak + peak + first-baseline version.
  const perMajorAgg = new Map();
  let max_consecutive_attested = 0;
  let first_baseline_reached_at = null;
  for (const row of sortedRows) {
    const mj = extractMajor(row.version);
    let agg = perMajorAgg.get(mj);
    if (!agg) {
      agg = {
        major: mj,
        total_versions: 0,
        attested_versions: 0,
        streak: 0,
        max_consecutive_attested: 0,
        baseline_reached_at: null,
        regression_versions: [],
      };
      perMajorAgg.set(mj, agg);
    }
    agg.total_versions += 1;
    if (row.provenance_present === true) {
      agg.streak += 1;
      agg.attested_versions += 1;
    } else if (row.provenance_present === false) {
      agg.streak = 0;
    }
    if (agg.streak > agg.max_consecutive_attested) {
      agg.max_consecutive_attested = agg.streak;
    }
    if (agg.streak > max_consecutive_attested) {
      max_consecutive_attested = agg.streak;
    }
    if (agg.baseline_reached_at === null && agg.streak >= minBaselineStreak) {
      agg.baseline_reached_at = row.version;
      if (first_baseline_reached_at === null) first_baseline_reached_at = row.version;
    }
  }
  // has_baseline_at_head reads the streak state of whichever major
  // the final row belongs to (the "active" release train).
  const headMajor =
    sortedRows.length > 0 ? extractMajor(sortedRows[sortedRows.length - 1].version) : null;
  const headAgg = perMajorAgg.get(headMajor);
  const has_baseline_at_head = headAgg ? headAgg.streak >= minBaselineStreak : false;

  const regression_versions = [];
  for (const v of perVersion) {
    if (v.provenance_regression) {
      regression_versions.push(v.version);
      const mj = extractMajor(v.version);
      const agg = perMajorAgg.get(mj);
      if (agg) agg.regression_versions.push(v.version);
    }
  }

  // Stable per-major output: sort keys ascending. Null-major (unparseable)
  // sorts last as "null".
  const per_major = {};
  const sortedKeys = [...perMajorAgg.keys()].sort((a, b) => {
    if (a === null && b === null) return 0;
    if (a === null) return 1;
    if (b === null) return -1;
    return a - b;
  });
  for (const k of sortedKeys) {
    const agg = perMajorAgg.get(k);
    per_major[k === null ? 'null' : String(k)] = {
      total_versions: agg.total_versions,
      attested_versions: agg.attested_versions,
      max_consecutive_attested: agg.max_consecutive_attested,
      baseline_reached_at: agg.baseline_reached_at,
      regression_versions: agg.regression_versions,
    };
  }

  return {
    total_versions,
    attested_versions,
    max_consecutive_attested,
    has_baseline_at_head,
    regression_versions,
    regression_count: regression_versions.length,
    machine_attested_versions,
    human_attested_versions,
    first_attested_version,
    first_baseline_reached_at,
    per_major,
  };
}

// ---------------------------------------------------------------------------
// Step 5 — extract() pipeline
//
// Deterministic pure composition over the four building blocks:
//   normalizeAndSortHistory → computeStreakSignals →
//   extractPriorBaselineCarriers (per regression-firing row) →
//   assemblePerVersionRecord → assemblePackageRollup
//
// Sufficiency short-circuit applies to PER-VERSION signals only:
// below MIN_HISTORY_DEPTH, every per-version entry has
// baseline_established / provenance_regression / in_scope forced to
// false and carriers=null. The rollup still reports raw observable
// aggregates (max_consecutive_attested, first_baseline_reached_at,
// etc.) because those are display/metrics fields and suppressing
// them would hide what the stream actually looks like. Regression
// counts naturally fall to 0 because perVersion was gated.
//
// Empty history is accepted: every sub-function returns valid
// zero/empty outputs, the rollup is all-zeros with null on the
// optional-version fields.
function extractPipeline(input) {
  validateInput(input);
  const { rows: sortedRows, skipped } = normalizeAndSortHistory(input.history);
  const streakSignals = computeStreakSignals(sortedRows);
  const hasSufficientHistory = sortedRows.length >= MIN_HISTORY_DEPTH;

  const perVersion = sortedRows.map((row, i) => {
    const raw = streakSignals[i];
    const gatedBaseline = hasSufficientHistory && raw.baseline_established;
    const gatedRegression = hasSufficientHistory && raw.provenance_regression;
    const gatedInScope = hasSufficientHistory && raw.in_scope;
    // Per-major carriers: the streak feeding baseline_established at T
    // lives entirely within T's own major, so the carrier identities
    // must be drawn from the same-major prior rows only. Filtering
    // rowsBeforeT to the major first keeps extractPriorBaselineCarriers
    // pure (still "last N rows of input"), and cross-major publishers
    // are correctly excluded from the carrier set.
    const rowMajor = extractMajor(row.version);
    const rowsBeforeT = sortedRows.slice(0, i).filter(
      (r) => extractMajor(r.version) === rowMajor,
    );
    const carriers = gatedBaseline
      ? extractPriorBaselineCarriers(rowsBeforeT, raw.prior_consecutive_attested)
      : null;
    return assemblePerVersionRecord(
      row,
      {
        prior_consecutive_attested: raw.prior_consecutive_attested,
        baseline_established: gatedBaseline,
        provenance_regression: gatedRegression,
        in_scope: gatedInScope,
      },
      carriers,
    );
  });

  const packageRollup = assemblePackageRollup(perVersion, sortedRows);
  const signals = {
    skipped: skipped.count,
    has_sufficient_history: hasSufficientHistory,
    min_baseline_streak: MIN_BASELINE_STREAK,
  };
  return { perVersion, packageRollup, signals };
}

export default {
  name: 'provenance',
  version: 1,
  requires: ['history'],
  extract: extractPipeline,
};

export {
  MIN_BASELINE_STREAK,
  MACHINE_PUBLISHER_EMAIL,
  MIN_HISTORY_DEPTH,
  extractMajor,
  normalizeAndSortHistory,
  computeStreakSignals,
  extractPriorBaselineCarriers,
  assemblePerVersionRecord,
  assemblePackageRollup,
};
