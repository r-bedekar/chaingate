// Publisher pattern — Section 11 step 2 of docs/V2_DESIGN.md.
//
// Extracts tenure, transitions, identity profile, and multi-maintainer
// shape from a package's observed publisher history. Deterministic,
// pure function over sorted version rows. No external calls.
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
//   sub-step 2d — overlap detection (definition (a), W=3)
//   sub-step 2e — known_contributor detection (K=10)
//   sub-step 2f — signals aggregation (max_prior_tenure etc.)
//   sub-step 3  — identity_profile (domain/provider/similarity) + shape
//   sub-step 4  — calibrate.js (derive K, W from seed) + corpus validation
//   sub-step 5  — cross-package campaign detection (STRETCH)
//   step 3      — V2 publisher-identity gate wiring

import { normalizeIdentity } from './identity.js';
import { compareSemver } from './semver.js';

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

    // Sub-step 2c stops here. identity_profile / shape keep the locked
    // contract shape from sub-step 1 and are filled in by step 3.
    // max_prior_tenure and has_overlap_transition remain zero-initialized
    // until sub-steps 2d–2f wire them up.
    return {
      tenure,
      transitions,
      identity_profile: {},
      shape: 'unknown',
      signals: {
        transition_count: transitions.length,
        max_prior_tenure: 0,
        has_overlap_transition: false,
        skipped_versions_count: skipped,
      },
    };
  },
};
