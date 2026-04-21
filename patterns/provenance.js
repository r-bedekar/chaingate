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
// BASELINE DEFINITION.
//
//   A package has an ESTABLISHED provenance baseline at version T
//   when the last MIN_BASELINE_STREAK versions strictly prior to T
//   were all attested (provenance_present === true).
//
//   Starter constant: MIN_BASELINE_STREAK = 3.
//     - 1 is trivially any attested release — false baselines on
//       first-time OIDC users.
//     - 2 rules out one-offs but still fires on OIDC pilots.
//     - 3 requires three consecutive attested releases — enough to
//       say "attested publish is the norm here, not an experiment."
//       axios attack has 4 consecutive machine-OIDC versions before
//       it, so K=3 detects it; legitimate one-off CI trials do not.
//     - 4+ misses real breaks on packages with shorter release
//       histories.
//   Subject to revision in calibrate.js (Phase 5) against the train
//   set. Corpus diagnostic under K=3 on the full 104-package seed:
//   17 of 104 packages fire ≥1 regression (16.3%), 274 total fires
//   across the 104-package seed, zero concerning FPs in a 5-sample
//   classification — all non-attack fires lack any escalator and
//   land at WARN.
//
// STREAK COUNTING.
//
//   The streak is contiguous prior attested versions, reset by any
//   non-attested version. Versions are ordered by published_at_ms
//   ascending with a stable secondary key (see sortRows() below).
//
//   prior_consecutive_attested is computed STRICTLY BEFORE version T;
//   it counts the run of attested versions immediately preceding T.
//   A non-attested version T consumes the streak for the purpose of
//   evaluating T, then resets the streak to 0 for the next version.
//
//   This correctly handles the "CLI between OIDC" gap: a single
//   unsigned release fires (if baseline was already reached) and
//   then the streak rebuilds from 0 for subsequent attested
//   releases.
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
// PER-VERSION in_scope SEMANTICS.
//
//   in_scope is a PER-VERSION determination, not per-package. At each
//   version T, in_scope=true iff the package has reached
//   MIN_BASELINE_STREAK consecutive attested versions at some point
//   at or before T (i.e. baseline was first established at some
//   version ≤ T). Once in_scope=true at version T, it remains true
//   for every subsequent version in the ordered stream — this is a
//   monotonic property of history (baseline-reached cannot be
//   un-reached).
//
//   Attacks on packages that never adopted OIDC (event-stream@3.3.6,
//   ua-parser-js@0.7.29) have in_scope=false at their attack version.
//   The provenance pattern has nothing to say about them. Silence is
//   the correct output.
//
// PRIOR BASELINE CARRIERS.
//
//   prior_baseline_carriers records WHO was publishing during the
//   current baseline streak — up to the version being evaluated.
//   any_machine distinguishes "CI was the baseline" (GitHub Actions
//   bot with npm-oidc-no-reply@github.com, strongest signal) from
//   "one individual's personal trusted-publisher OIDC was the
//   baseline" (weaker signal — same human who may legitimately
//   revert to CLI). This flag feeds escalator (d) below.
//
// DISPOSITION INTERACTION TABLE (axes: publisher cell × provenance
// state at version T):
//
//   publisher cell                        | in_scope=false | in_scope=true,      | in_scope=true,
//                                         |                | no regression       | regression
//   ------------------------------------- | -------------- | ------------------- | --------------------------
//   no transition (same identity)         | ALLOW          | ALLOW               | WARN, or BLOCK if any
//                                         |                |                     | escalator (a,b,c,d)
//   recurring_member (T,T)                | ALLOW          | ALLOW               | WARN, or BLOCK if any
//                                         |                |                     | escalator (a,b,c,d)
//   new_committee (T,F)                   | ALLOW          | ALLOW               | WARN
//   returning_dormant (F,T)               | ALLOW          | ALLOW               | WARN
//   cold_handoff (F,F), solo, high tenure | BLOCK          | BLOCK (publisher)   | BLOCK (reinforced)
//   cold_handoff (F,F), non-solo          | WARN (unless   | WARN                | BLOCK — regression is one
//                                         | co-signals)    |                     | of the three accepted
//                                         |                |                     | co-signals per publisher.js
//                                         |                |                     | GATE CONTRACT Addition 3
//                                         |                |                     | (privacy/unverified domain,
//                                         |                |                     | provenance break, short gap)
//                                         |                |                     | — meets escalation bar for
//                                         |                |                     | non-solo cold_handoff BLOCK
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
import { compareSemver } from './semver.js';

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
function normalizeAndSortHistory(history) {
  const rows = [];
  const reasons = [];
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

export default {
  name: 'provenance',
  version: 1,
  requires: ['history'],

  extract(input) {
    validateInput(input);
    // Phase 2 will replace this throw with the streak walker, the
    // per-version signal builder, and the package-rollup
    // aggregator. Until then the pattern is registered, contract-
    // validated, and importable — but calling extract() on a valid
    // input throws so no downstream code silently relies on the
    // skeleton shape before the implementation exists.
    throw new Error('provenance.extract: not yet implemented (Phase 1 skeleton)');
  },
};

export {
  MIN_BASELINE_STREAK,
  MACHINE_PUBLISHER_EMAIL,
  MIN_HISTORY_DEPTH,
  normalizeAndSortHistory,
};
