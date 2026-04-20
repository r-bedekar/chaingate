// Held-out attacks for the test set — Risk 11 mitigation.
//
// Hardcoded so a future edit cannot silently migrate axios or event-stream
// into the train set and invalidate the "we held out the demo attacks"
// research-post claim. Both calibration scripts (which must NOT see these
// packages) and the validation runner (which MUST see them on the test
// set) import this module and call the matching assertion; a violation
// fails loudly instead of drifting silently.
//
// See docs/4_PLAN.md §3 (Train/test split) and §5 Risk 11.

export const TEST_SET_HELD_OUT_ATTACKS = Object.freeze([
  Object.freeze({ package: 'axios', version: '1.14.1' }),
  Object.freeze({ package: 'event-stream', version: '3.3.6' }),
]);

export const HELD_OUT_PACKAGES = Object.freeze(
  Array.from(new Set(TEST_SET_HELD_OUT_ATTACKS.map((h) => h.package))),
);

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

function normalizeSet(input) {
  if (input instanceof Set) return input;
  if (Array.isArray(input)) return new Set(input);
  throw new TypeError('expected Set or Array of package names');
}

export { HeldOutAssertionError };
