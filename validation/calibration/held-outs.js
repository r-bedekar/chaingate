// Locked bucket assignments for the train/test split.
//
// Two parallel lock lists:
//   TEST_SET_HELD_OUT_ATTACKS — Risk 11 (axios, event-stream stay in test).
//   TRAIN_SET_LOCKED_ATTACKS  — Risk 14 (in-scope detectable attacks stay
//                               in train so the calibration sweep has a
//                               real recall signal to maximize against).
//
// Both lists are hardcoded so a future edit cannot silently migrate a
// package across buckets. Every consumer (split generator + validation
// runner) imports the relevant assertion; a violation fails loudly
// instead of drifting silently.
//
// See docs/4_PLAN.md §3 (Train/test split) and §5 Risks 11, 14.

export const TEST_SET_HELD_OUT_ATTACKS = Object.freeze([
  Object.freeze({ package: 'axios', version: '1.14.1' }),
  Object.freeze({ package: 'event-stream', version: '3.3.6' }),
]);

export const TRAIN_SET_LOCKED_ATTACKS = Object.freeze([
  Object.freeze({ package: 'chalk', version: 'MAL-2025-46969' }),
  Object.freeze({ package: 'coa', version: 'TBD' }),
  Object.freeze({ package: 'eslint-config-prettier', version: 'TBD' }),
  Object.freeze({ package: 'rc', version: 'TBD' }),
]);

export const HELD_OUT_PACKAGES = Object.freeze(
  Array.from(new Set(TEST_SET_HELD_OUT_ATTACKS.map((h) => h.package))),
);

export const TRAIN_LOCKED_PACKAGES = Object.freeze(
  Array.from(new Set(TRAIN_SET_LOCKED_ATTACKS.map((h) => h.package))),
);

// Module-load intersection check: the two lock lists must be disjoint.
// A package cannot be simultaneously held out of train and locked into
// train — that contradiction can only happen via edit, so catch it at
// import time before any split/validation code runs.
{
  const heldOut = new Set(HELD_OUT_PACKAGES);
  const overlap = TRAIN_LOCKED_PACKAGES.filter((p) => heldOut.has(p));
  if (overlap.length > 0) {
    throw new Error(
      `TEST_SET_HELD_OUT_ATTACKS and TRAIN_SET_LOCKED_ATTACKS must be ` +
        `disjoint; overlap: ${overlap.join(', ')}`,
    );
  }
}

class HeldOutAssertionError extends Error {
  constructor(message) {
    super(message);
    this.name = 'HeldOutAssertionError';
  }
}

// Called from calibration scripts (sensitivity + sweep). The passed-in
// set is every package name the calibration run will touch; a held-out
// package appearing there means the train/test split is broken.
export function assertHeldOutsNotInTrain(trainPackageNames) {
  const names = normalizeSet(trainPackageNames);
  const leaks = HELD_OUT_PACKAGES.filter((p) => names.has(p));
  if (leaks.length > 0) {
    throw new HeldOutAssertionError(
      `Held-out attack package(s) leaked into train set: ${leaks.join(', ')}. ` +
        `These must be test-only (docs/4_PLAN.md §5 Risk 11). ` +
        `Fix the split in validation/calibration/train-test-split.json.`,
    );
  }
}

// Called from validation/run-validation.js when it executes on the test
// set. Confirms the held-outs are actually present — guards against a
// split that correctly excluded them from train but also dropped them
// from test (e.g., a corpus shrink that didn't regenerate the split).
export function assertHeldOutsInTest(testPackageNames) {
  const names = normalizeSet(testPackageNames);
  const missing = HELD_OUT_PACKAGES.filter((p) => !names.has(p));
  if (missing.length > 0) {
    throw new HeldOutAssertionError(
      `Held-out attack package(s) missing from test set: ${missing.join(', ')}. ` +
        `These must be test-set members (docs/4_PLAN.md §5 Risk 11). ` +
        `Fix the split in validation/calibration/train-test-split.json.`,
    );
  }
}

// Called from the split generator + the validation runner on mode=train.
// Confirms every TRAIN_LOCKED package is actually in train.
export function assertTrainLockedInTrain(trainPackageNames) {
  const names = normalizeSet(trainPackageNames);
  const missing = TRAIN_LOCKED_PACKAGES.filter((p) => !names.has(p));
  if (missing.length > 0) {
    throw new HeldOutAssertionError(
      `Train-locked attack package(s) missing from train set: ${missing.join(', ')}. ` +
        `These must be train-set members (docs/4_PLAN.md §5 Risk 14). ` +
        `Fix the split in validation/calibration/train-test-split.json.`,
    );
  }
}

// Called from the validation runner on mode=test. Symmetric to
// assertHeldOutsNotInTrain — catches a bucket leak from train→test.
export function assertTrainLockedNotInTest(testPackageNames) {
  const names = normalizeSet(testPackageNames);
  const leaks = TRAIN_LOCKED_PACKAGES.filter((p) => names.has(p));
  if (leaks.length > 0) {
    throw new HeldOutAssertionError(
      `Train-locked attack package(s) leaked into test set: ${leaks.join(', ')}. ` +
        `These must be train-only (docs/4_PLAN.md §5 Risk 14). ` +
        `Fix the split in validation/calibration/train-test-split.json.`,
    );
  }
}

function normalizeSet(input) {
  if (input instanceof Set) return input;
  if (Array.isArray(input)) return new Set(input);
  throw new TypeError('expected Set or Array of package names');
}

export { HeldOutAssertionError };
