// Shared constants — one source of truth across layers.
//
// Anything declared here is imported by both `patterns/` and `gates/`.
// Keep this file narrow: only constants that are genuinely cross-layer.
// Layer-specific thresholds (e.g. K=10 in the publisher pattern, W=3 in
// the overlap window) stay with their layer so the read-site and the
// definition stay adjacent.

// First-seen baseline poisoning protection (V2 foundation, Section 7
// item 4 of docs/V2_DESIGN.md). Packages with fewer than this many
// observed prior versions do not carry enough signal to evaluate
// pattern-based gates or compute meaningful per-package patterns — an
// attacker who publishes a brand-new package and has it observed first
// by a target user could poison the baseline.
//
// Consumed by:
//   gates/index.js  — skip pattern-based gates until depth is reached
//                     (content-hash is explicitly exempt).
//   patterns/publisher.js — emit `has_sufficient_history` in the
//                           signals aggregate so the gate layer can
//                           short-circuit to ALLOW on insufficient
//                           depth regardless of which gates run.
//
// Keeping the constant here — not duplicated at each call site — is
// the load-bearing choice: changing the threshold during calibration
// (sub-step 4) touches exactly one line.
export const MIN_HISTORY_DEPTH = 8;
