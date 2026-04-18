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
// Implementation sub-steps:
//   1. Scaffold + contract + deterministic no-op stub  ← THIS FILE (today)
//   2. Tenure + transitions (hand-built fixture test)
//   3. Identity profile + shape classification
//   4. Corpus validation + calibrate.js-derived thresholds
//   5. (Stretch) Cross-package campaign detection

export default {
  name: 'publisher',
  version: 1,
  requires: ['history'],

  extract(_input) {
    // Sub-step 1: deterministic no-op that locks the output shape.
    // Every subsequent sub-step fills these fields with real analysis
    // without changing the contract.
    return {
      tenure: [],
      transitions: [],
      identity_profile: {},
      shape: 'unknown',
      signals: {},
    };
  },
};
