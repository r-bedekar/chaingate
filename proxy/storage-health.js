// U-05 gap-closure r2 (owner decision 6), Addendum 1 §B: ONE storage-health state, computed by the running proxy from its
// own signals and used unchanged by /_chaingate/self, `chaingate status`, `chaingate doctor` and the operator text.
//
// Signals (nothing is inferred):
//   - the witness store's per-observation outcome: `failure` if any storage step failed in that observation (failure
//     dominates), `ok` if its transaction committed with at least one decision row inserted, otherwise nothing;
//   - the unstored-BLOCK record: how many BLOCKs are held only in memory, and whether it is FULL (sticky).
// A positive count or FULL is never healthy, whatever the write counters say.

export const STORAGE_STATES = Object.freeze(['full_held', 'full_empty', 'failing_held', 'failing', 'held', 'recovered',
  'healthy', 'no_evidence']);

/** Precedence: FULL, then a failing last outcome, then anything held only in memory, then the write evidence. */
export function storageState({ health = null, count = 0, full = false } = {}) {
  const last = health?.last_outcome ?? null;
  if (full) return count > 0 ? 'full_held' : 'full_empty';
  if (last === 'failure') return count > 0 ? 'failing_held' : 'failing';
  if (count > 0) return 'held';
  if (last === 'ok') return (health?.failure_count ?? 0) > 0 ? 'recovered' : 'healthy';
  return 'no_evidence';
}

/** The `storage` object of /_chaingate/self. */
export function storageReport({ health = null, count = 0, full = false, observationErrors = 0 } = {}) {
  return {
    state: storageState({ health, count, full }),
    ok_count: health?.ok_count ?? 0,
    failure_count: health?.failure_count ?? 0,
    last_outcome: health?.last_outcome ?? null,
    last_ok_at: health?.last_ok_at ?? null,
    last_failure_at: health?.last_failure_at ?? null,
    last_failure: health?.last_failure ?? null,
    observation_errors: observationErrors,
  };
}
