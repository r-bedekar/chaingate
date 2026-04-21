import { test } from 'node:test';
import assert from 'node:assert/strict';

import provenance, {
  MIN_BASELINE_STREAK,
  MACHINE_PUBLISHER_EMAIL,
} from '../../patterns/provenance.js';
import { PATTERN_REGISTRY, validatePattern } from '../../patterns/index.js';

// ---------------------------------------------------------------------------
// Contract tests — skeleton is importable and satisfies the registry shape.
// These run unconditionally; they exercise the parts of the module that
// exist in Phase 1 (metadata + input validation).
// ---------------------------------------------------------------------------

test('provenance: module satisfies the pattern contract', () => {
  assert.doesNotThrow(() => validatePattern(provenance));
  assert.equal(provenance.name, 'provenance');
  assert.equal(provenance.version, 1);
  assert.ok(Array.isArray(provenance.requires));
  assert.ok(provenance.requires.includes('history'));
  assert.equal(typeof provenance.extract, 'function');
});

test('provenance: registered in the pattern registry', () => {
  assert.strictEqual(PATTERN_REGISTRY.provenance, provenance);
});

test('provenance: starter constants exported at expected values', () => {
  assert.equal(MIN_BASELINE_STREAK, 3);
  assert.equal(MACHINE_PUBLISHER_EMAIL, 'npm-oidc-no-reply@github.com');
});

// ---------------------------------------------------------------------------
// Input validation tests — extract() must reject malformed input before
// any Phase 2 logic gets a chance to crash on it.
// ---------------------------------------------------------------------------

test('provenance.extract: rejects non-object input', () => {
  assert.throws(() => provenance.extract(null), /non-null object/);
  assert.throws(() => provenance.extract(undefined), /non-null object/);
  assert.throws(() => provenance.extract('axios'), /non-null object/);
  assert.throws(() => provenance.extract(42), /non-null object/);
});

test('provenance.extract: rejects missing or empty packageName', () => {
  assert.throws(() => provenance.extract({ history: [] }), /packageName/);
  assert.throws(() => provenance.extract({ packageName: '', history: [] }), /packageName/);
  assert.throws(() => provenance.extract({ packageName: 123, history: [] }), /packageName/);
});

test('provenance.extract: rejects non-array history', () => {
  assert.throws(
    () => provenance.extract({ packageName: 'axios' }),
    /history must be an array/,
  );
  assert.throws(
    () => provenance.extract({ packageName: 'axios', history: 'nope' }),
    /history must be an array/,
  );
  assert.throws(
    () => provenance.extract({ packageName: 'axios', history: {} }),
    /history must be an array/,
  );
});

test('provenance.extract: throws "not yet implemented" on valid input (Phase 1 skeleton)', () => {
  // When Phase 2 lands, this test flips to asserting extract() returns
  // the locked output contract shape (per-version entries + rollup +
  // signals). Until then, valid input must produce an explicit
  // not-implemented error so no downstream code relies on a phantom
  // Phase 1 output.
  assert.throws(
    () => provenance.extract({ packageName: 'axios', history: [] }),
    /not yet implemented/,
  );
});

// ---------------------------------------------------------------------------
// Synthetic edge-case fixtures — docs/PATTERNS_PROVENANCE.md Task 3.
// All skipped until Phase 2 implements extract(). Each stub documents
// the exact expected signal at the terminal version so the test body is
// ready to un-skip once the walker exists.
// ---------------------------------------------------------------------------

test('fixture: baseline-boundary-fire (A,A,A,U → regression fires at last)', { skip: true }, () => {
  // TODO(Phase 2): streak walker must produce at the terminal U:
  //   prior_consecutive_attested = 3
  //   baseline_established = true
  //   provenance_regression = true
  assert.fail('pending Phase 2 — streak walker not implemented');
});

test('fixture: baseline-boundary-silent (A,A,U → no regression, streak short)', { skip: true }, () => {
  // TODO(Phase 2): at the terminal U:
  //   prior_consecutive_attested = 2
  //   baseline_established = false
  //   provenance_regression = false
  assert.fail('pending Phase 2 — streak walker not implemented');
});

test('fixture: alternating-stress (A,U × 7 → streak never reaches K, all silent)', { skip: true }, () => {
  // TODO(Phase 2): every U version has prior_streak in {0,1} — never
  // reaches MIN_BASELINE_STREAK=3. No regression fires anywhere.
  assert.fail('pending Phase 2 — streak walker not implemented');
});

test('fixture: all-attested (A × 10 → no regression ever)', { skip: true }, () => {
  // TODO(Phase 2): every version has provenance_regression=false.
  // max_consecutive_attested=10, has_baseline_at_head=true.
  assert.fail('pending Phase 2 — streak walker not implemented');
});

test('fixture: long-unsigned-tail (A,A,A,U×20 → only U₁ fires)', { skip: true }, () => {
  // TODO(Phase 2): regression fires EXACTLY ONCE at U₁ (the first
  // unsigned after the baseline). U₂–U₂₀ all have prior_streak=0
  // (streak reset at U₁) → baseline_established=false → no fire.
  // rollup.regression_count = 1 (not 20).
  assert.fail('pending Phase 2 — streak walker not implemented');
});

test('fixture: below-sufficiency (<MIN_HISTORY_DEPTH total → short-circuit)', { skip: true }, () => {
  // TODO(Phase 2): with A,A,A,U at 4 total versions (< MIN_HISTORY_DEPTH=8),
  // signals.has_sufficient_history=false and no regression fires
  // regardless of streak content. in_scope=false on every version.
  assert.fail('pending Phase 2 — sufficiency short-circuit not implemented');
});

test('fixture: timestamp-tie (two versions, same published_at_ms → deterministic order)', { skip: true }, () => {
  // TODO(Phase 2): two rows with identical published_at_ms, different
  // ids. Running extract() twice must produce byte-identical output.
  // Secondary sort key must be deterministic (candidate: id ASC, or
  // semver ASC — finalize in Phase 2).
  assert.fail('pending Phase 2 — sort-tiebreaker rule not yet fixed');
});

// ---------------------------------------------------------------------------
// Canonical cases — docs/PATTERNS_PROVENANCE.md Task 3. Four real packages
// from the seed. All skipped until Phase 2. Each stub documents the
// expected top-level signal and disposition class.
// ---------------------------------------------------------------------------

test('canonical: axios@1.14.1 — regression + escalators (a,b,d) → BLOCK-class', { skip: true }, () => {
  // TODO(Phase 2): fixture loads axios 1.13.0 → 1.15.1 rows from the
  // seed (attack reconstruction). At 1.14.1:
  //   prior_consecutive_attested = 4
  //   baseline_established = true
  //   provenance_regression = true
  //   prior_baseline_carriers.any_machine = true
  //   incoming_publisher.email = 'ifstap@proton.me'
  // Disposition-layer assertion is Phase 3. Here we assert only the
  // pattern output fields.
  assert.fail('pending Phase 2 — extract() not implemented');
});

test('canonical: axios@1.13.3 — regression, zero escalators → WARN-class', { skip: true }, () => {
  // TODO(Phase 2): same axios fixture, earlier version. At 1.13.3:
  //   prior_consecutive_attested = 3
  //   baseline_established = true
  //   provenance_regression = true
  //   prior_baseline_carriers.any_machine = false  (personal OIDC baseline)
  //   incoming_publisher.email = 'jasonsaayman@gmail.com'  (not new, not privacy)
  // Locks the "legitimate CLI during baseline → WARN" invariant.
  assert.fail('pending Phase 2 — extract() not implemented');
});

test('canonical: event-stream@3.3.6 — pre-OIDC era, pattern silent', { skip: true }, () => {
  // TODO(Phase 2): fixture loads event-stream 3.3.5, 3.3.6. At 3.3.6:
  //   baseline_established = false (no attested versions in history)
  //   provenance_regression = false
  //   in_scope = false
  // Publisher pattern drives BLOCK for this attack; provenance abstains.
  assert.fail('pending Phase 2 — extract() not implemented');
});

test('canonical: lodash@4.17.16 — no OIDC history, must NOT false-positive', { skip: true }, () => {
  // TODO(Phase 2): fixture loads lodash 4.17.15 → 4.17.23. Package
  // has never adopted OIDC. Every version:
  //   baseline_established = false
  //   provenance_regression = false
  //   in_scope = false
  assert.fail('pending Phase 2 — extract() not implemented');
});

test('canonical: ua-parser-js@0.7.29 — pre-OIDC adoption, pattern silent', { skip: true }, () => {
  // TODO(Phase 2): fixture loads ua-parser-js through 0.7.29 only
  // (first OIDC is 2023-08; attack is 2021-10, predates adoption).
  // At 0.7.29:
  //   baseline_established = false
  //   provenance_regression = false
  //   in_scope = false
  // Same faisalman identity throughout — no publisher transition
  // either. Both patterns correctly abstain; attack is outside the
  // scope of either pattern (same-account credential theft).
  assert.fail('pending Phase 2 — extract() not implemented');
});
