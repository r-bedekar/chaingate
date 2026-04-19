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

// Provider classification starter lists (V2 sub-step 3a).
//
// These lists are intentionally narrow starter sets. Sub-step 4 corpus
// validation against the 130-package seed will reveal missing entries
// (particularly regional providers: yandex.ru, mail.ru, qq.com, etc.).
// List expansion is a calibration output, not a pre-optimization.
//
// Consumed by:
//   patterns/provider.js — classifyProvider() precedence check:
//     unknown > privacy > free-webmail > verified-corporate > unverified.
//
// Precedence rationale: privacy and free-webmail are inherent meaning
// classes that apply regardless of package context. The package-context
// override (verified-corporate vs unverified) applies only to non-free,
// non-privacy domains.
export const FREE_WEBMAIL_DOMAINS = new Set([
  'gmail.com',
  'googlemail.com',
  'yahoo.com',
  'yahoo.co.uk',
  'hotmail.com',
  'outlook.com',
  'live.com',
  'icloud.com',
  'me.com',
  'aol.com',
]);

export const PRIVACY_PROVIDER_DOMAINS = new Set([
  'protonmail.com',
  'protonmail.ch',
  'protonmail.me',
  'pm.me',
  'proton.me',
  'tutanota.com',
  'tutanota.de',
  'tuta.io',
  'guerrillamail.com',
]);

// Minimum version count across a package's history for a non-free,
// non-privacy domain to classify as verified-corporate. Starter value.
// Sub-step 4 validates; raise if single-version domains false-positive
// as verified-corporate.
export const MIN_VERIFIED_VERSIONS = 2;

// Row count for the domain_stability recency window. A non-null domain
// that appears in the final CHURNING_WINDOW rows but not in any earlier
// row flags churning. Starter value; MIN_HISTORY_DEPTH=8 guarantees the
// window is always well-defined at evaluation time.
//
// The rule is "new-to-window," not "≥ N unique in window" — the latter
// false-positives on natural rotating committees. See patterns/publisher.js
// GATE CONTRACT addition 2 for the consumption semantics.
export const CHURNING_WINDOW = 5;
