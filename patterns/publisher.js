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
//   sub-step 2b — tenure extraction (maximal same-identity runs)
//   sub-step 2c — transitions with prior_tenure + gap
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

// Normalize + filter: drop rows missing either identity or timestamp.
// Return { rows, skipped } where rows are ready for sort and downstream
// analysis, and skipped counts rows the caller should report in signals.
function normalizeAndFilter(history) {
  const rows = [];
  let skipped = 0;
  for (const raw of history) {
    const identity = normalizeIdentity(raw?.publisher_email, raw?.publisher_name);
    const tsRaw = raw?.published_at_ms;
    const ts = Number.isInteger(tsRaw) ? tsRaw : null;
    if (!identity || ts === null) {
      skipped += 1;
      continue;
    }
    rows.push({
      version: typeof raw?.version === 'string' ? raw.version : null,
      identity,
      published_at_ms: ts,
    });
  }
  return { rows, skipped };
}

// Sort by published_at_ms ascending (primary), breaking ties by semver
// ascending (secondary). Deliberately NOT semver-first: attackers that
// backport under old version numbers would exploit semver-sorted tools.
function sortRows(rows) {
  return rows.slice().sort((a, b) => {
    if (a.published_at_ms !== b.published_at_ms) {
      return a.published_at_ms < b.published_at_ms ? -1 : 1;
    }
    return compareSemver(a.version ?? '', b.version ?? '');
  });
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
    const _sorted = sortRows(rows);

    // Sub-step 2a stops here. Tenure/transitions fields keep the locked
    // contract shape from sub-step 1 and will be populated in 2b–2f.
    return {
      tenure: [],
      transitions: [],
      identity_profile: {},
      shape: 'unknown',
      signals: {
        transition_count: 0,
        max_prior_tenure: 0,
        has_overlap_transition: false,
        skipped_versions_count: skipped,
      },
    };
  },
};
