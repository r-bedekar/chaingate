import { test } from 'node:test';
import assert from 'node:assert/strict';

import publisher from '../../patterns/publisher.js';
import { PATTERN_REGISTRY, validatePattern } from '../../patterns/index.js';

// ---------------------------------------------------------------------------
// Contract tests (from sub-step 1)
// ---------------------------------------------------------------------------

test('publisher: module satisfies the pattern contract', () => {
  assert.doesNotThrow(() => validatePattern(publisher));
  assert.equal(publisher.name, 'publisher');
  assert.equal(publisher.version, 1);
  assert.ok(Array.isArray(publisher.requires));
  assert.ok(publisher.requires.includes('history'));
  assert.equal(typeof publisher.extract, 'function');
});

test('publisher: registered in the pattern registry', () => {
  assert.strictEqual(PATTERN_REGISTRY.publisher, publisher);
});

test('publisher: extract() is deterministic on identical input', () => {
  const input = { packageName: 'axios', history: [] };
  const a = publisher.extract(input);
  const b = publisher.extract(input);
  assert.deepEqual(a, b);
  assert.equal(JSON.stringify(a), JSON.stringify(b));
});

test('publisher: extract() output matches the locked contract shape', () => {
  const out = publisher.extract({ packageName: 'axios', history: [] });
  assert.ok(Array.isArray(out.tenure), 'tenure must be an array');
  assert.ok(Array.isArray(out.transitions), 'transitions must be an array');
  assert.equal(typeof out.identity_profile, 'object');
  assert.ok(out.identity_profile !== null);
  assert.equal(typeof out.shape, 'string');
  assert.equal(typeof out.signals, 'object');
  assert.ok(out.signals !== null);
});

test('validatePattern: rejects malformed pattern modules', () => {
  assert.throws(() => validatePattern(null), /non-null object/);
  assert.throws(() => validatePattern({}), /name must be/);
  assert.throws(() => validatePattern({ name: 'x' }), /version must be/);
  assert.throws(() => validatePattern({ name: 'x', version: 0 }), /version must be/);
  assert.throws(() => validatePattern({ name: 'x', version: 1 }), /requires must be/);
  assert.throws(
    () => validatePattern({ name: 'x', version: 1, requires: [] }),
    /extract must be/,
  );
  assert.doesNotThrow(() =>
    validatePattern({ name: 'x', version: 1, requires: [], extract: () => ({}) }),
  );
});

// ---------------------------------------------------------------------------
// Sub-step 2a: input validation
// ---------------------------------------------------------------------------

test('publisher.extract: rejects non-object input', () => {
  assert.throws(() => publisher.extract(null), /non-null object/);
  assert.throws(() => publisher.extract(undefined), /non-null object/);
  assert.throws(() => publisher.extract('axios'), /non-null object/);
});

test('publisher.extract: rejects missing or empty packageName', () => {
  assert.throws(() => publisher.extract({ history: [] }), /packageName/);
  assert.throws(() => publisher.extract({ packageName: '', history: [] }), /packageName/);
  assert.throws(() => publisher.extract({ packageName: 123, history: [] }), /packageName/);
});

test('publisher.extract: rejects non-array history', () => {
  assert.throws(() => publisher.extract({ packageName: 'x' }), /history must be an array/);
  assert.throws(
    () => publisher.extract({ packageName: 'x', history: 'nope' }),
    /history must be an array/,
  );
});

test('publisher.extract: empty history yields zero skipped, empty tenure/transitions', () => {
  const out = publisher.extract({ packageName: 'axios', history: [] });
  assert.equal(out.signals.skipped_versions_count, 0);
  assert.equal(out.signals.transition_count, 0);
  assert.equal(out.signals.max_prior_tenure_versions, 0);
  assert.equal(out.signals.has_overlap_transition, false);
  assert.deepEqual(out.tenure, []);
  assert.deepEqual(out.transitions, []);
});

// ---------------------------------------------------------------------------
// Sub-step 2a: Fixture F — degraded history
//
// Mix of valid rows and rows missing identity / timestamp. Step 2a asserts
// that skipped_versions_count matches the degraded rows exactly and that
// no synthetic identities or transitions leak through.
// ---------------------------------------------------------------------------

const fixtureF = {
  packageName: 'degraded-example',
  history: [
    { version: '1.0.0', publisher_email: 'a@x.com', publisher_name: 'Alice', published_at_ms: 1000 },
    // Skip: no identity at all
    { version: '1.0.1', publisher_email: null, publisher_name: null, published_at_ms: 2000 },
    // Skip: no timestamp
    { version: '1.0.2', publisher_email: 'a@x.com', publisher_name: 'Alice', published_at_ms: null },
    // Skip: empty strings
    { version: '1.0.3', publisher_email: '   ', publisher_name: '   ', published_at_ms: 4000 },
    { version: '1.0.4', publisher_email: 'b@y.com', publisher_name: 'Bob', published_at_ms: 5000 },
    // Valid: email-only (name missing is fine — becomes "<email>")
    { version: '1.0.5', publisher_email: 'c@z.com', publisher_name: null, published_at_ms: 6000 },
    // Skip: timestamp is a float, not integer ms
    { version: '1.0.6', publisher_email: 'd@w.com', publisher_name: 'Dan', published_at_ms: 7000.5 },
    // Skip: timestamp is a string
    { version: '1.0.7', publisher_email: 'e@v.com', publisher_name: 'Eve', published_at_ms: '8000' },
  ],
};

test('fixture F: degraded rows counted, not silently included', () => {
  const out = publisher.extract(fixtureF);
  // Out of 8 input rows, 5 are degraded (rows 2, 3, 4, 7, 8).
  assert.equal(out.signals.skipped_versions_count, 5);
  // 3 valid rows (Alice, Bob, <c@z.com>) → 3 tenure blocks → exactly
  // 2 transitions. Crucially NOT 4+ — no synthetic transitions are
  // emitted across the null-row boundaries; those rows are dropped
  // in normalizeAndFilter before tenure/transitions run.
  assert.equal(out.signals.transition_count, 2);
  assert.equal(out.transitions.length, 2);
});

test('fixture F: determinism — identical output on repeat extraction', () => {
  const a = publisher.extract(fixtureF);
  const b = publisher.extract(fixtureF);
  assert.equal(JSON.stringify(a), JSON.stringify(b));
});

test('fixture F: all-degraded history produces empty result without throwing', () => {
  const allBad = {
    packageName: 'all-degraded',
    history: [
      { version: '1.0.0', publisher_email: null, publisher_name: null, published_at_ms: 1000 },
      { version: '1.0.1', publisher_email: 'a@b.com', publisher_name: 'A', published_at_ms: null },
    ],
  };
  const out = publisher.extract(allBad);
  assert.equal(out.signals.skipped_versions_count, 2);
  assert.deepEqual(out.tenure, []);
  assert.deepEqual(out.transitions, []);
});

// ---------------------------------------------------------------------------
// Sub-step 2a: sort stability sanity check
//
// Sort is by published_at_ms ascending, tie-break by semver ascending.
// Sub-steps 2b+ depend on this ordering; we can observe it indirectly
// via determinism of the output, but we also want an explicit regression
// guard for the tie-break path. We re-export nothing, so the test
// exercises the observable property: two permutations of the same input
// produce byte-identical output.
// ---------------------------------------------------------------------------

test('sort: permutation of input with same ts + same version + different identities is deterministic', () => {
  // Determinism regression guard: two rows sharing (published_at_ms,
  // version) but published under different identities must produce the
  // same tenure regardless of input order. Without the identity tertiary
  // key, sortRows would fall back on input order and tenure would drift
  // between calibration runs.
  const rows = [
    { version: '1.0.0', publisher_email: 'a@x.com', publisher_name: 'A', published_at_ms: 1000 },
    { version: '2.0.0', publisher_email: 'a@x.com', publisher_name: 'A', published_at_ms: 2000 },
    // Same ts AND same version, different identities — the degenerate case.
    { version: '2.0.0', publisher_email: 'b@y.com', publisher_name: 'B', published_at_ms: 2000 },
  ];
  const forward = publisher.extract({ packageName: 'dup-ver', history: rows });
  const reversed = publisher.extract({ packageName: 'dup-ver', history: rows.slice().reverse() });
  assert.equal(JSON.stringify(forward), JSON.stringify(reversed));
});

test('sort: permutation of input produces byte-identical output', () => {
  const rows = [
    { version: '1.0.0', publisher_email: 'a@x.com', publisher_name: 'A', published_at_ms: 1000 },
    { version: '1.0.1', publisher_email: 'a@x.com', publisher_name: 'A', published_at_ms: 2000 },
    { version: '1.0.2', publisher_email: 'b@y.com', publisher_name: 'B', published_at_ms: 3000 },
    // Same timestamp — semver tie-break: 1.0.3 before 1.0.10
    { version: '1.0.10', publisher_email: 'b@y.com', publisher_name: 'B', published_at_ms: 4000 },
    { version: '1.0.3', publisher_email: 'b@y.com', publisher_name: 'B', published_at_ms: 4000 },
  ];
  const forward = publisher.extract({ packageName: 'sort-test', history: rows });
  const reversed = publisher.extract({ packageName: 'sort-test', history: rows.slice().reverse() });
  assert.equal(JSON.stringify(forward), JSON.stringify(reversed));
});

// ---------------------------------------------------------------------------
// Sub-step 2b: tenure extraction
//
// A tenure block is a maximal run of consecutive versions in the sorted
// sequence published by the same identity. Fixtures A/B/C are the three
// canonical shapes:
//   A — single handoff (event-stream class)
//   B — rotating committee
//   C — long solo tenure (ua-parser-js class)
// ---------------------------------------------------------------------------

const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;

// buildRowsAbsolute(spec): explicit (identity, offsetMs-from-startMs) per row.
// Used for fixtures that need non-uniform spacing — e.g. a multi-month
// silence followed by one republish (dormancy-revive), or a sub-day gap
// following a many-day active run (rapid unannounced handoff). Each row
// gets a unique patch-level version so semver ordering is total.
function buildRowsAbsolute(spec, startMs = 1_700_000_000_000) {
  return spec.map(([email, offsetMs], i) => ({
    version: `1.0.${i}`,
    publisher_email: email,
    publisher_name: email.split('@')[0],
    published_at_ms: startMs + offsetMs,
  }));
}

// buildRows(spec): generate sorted rows from a compact [identity, count] spec.
// Timestamps start at `startMs` and increment by DAY_MS per version; version
// numbers are patch-only 1.0.x so semver tie-break is exercised naturally.
function buildRows(spec, startMs = 1_700_000_000_000) {
  const rows = [];
  let t = startMs;
  let patch = 0;
  for (const [email, count] of spec) {
    for (let i = 0; i < count; i += 1) {
      rows.push({
        version: `1.0.${patch}`,
        publisher_email: email,
        publisher_name: email.split('@')[0],
        published_at_ms: t,
      });
      t += DAY_MS;
      patch += 1;
    }
  }
  return rows;
}

test('fixture A (event-stream class): 27 → 3 produces 2 tenure blocks', () => {
  const rows = buildRows([
    ['dominictarr@example.com', 27],
    ['right9ctrl@example.com', 3],
  ]);
  const out = publisher.extract({ packageName: 'event-stream', history: rows });
  assert.equal(out.tenure.length, 2);

  const [first, second] = out.tenure;
  assert.equal(first.identity, 'dominictarr <dominictarr@example.com>');
  assert.equal(first.version_count, 27);
  assert.equal(first.first_version, '1.0.0');
  assert.equal(first.last_version, '1.0.26');
  assert.equal(first.duration_ms, 26 * DAY_MS);

  assert.equal(second.identity, 'right9ctrl <right9ctrl@example.com>');
  assert.equal(second.version_count, 3);
  assert.equal(second.first_version, '1.0.27');
  assert.equal(second.last_version, '1.0.29');
  assert.equal(second.duration_ms, 2 * DAY_MS);
});

test('fixture B (committee): 40 rotating identities → 40 blocks of 1', () => {
  const spec = [];
  for (let i = 0; i < 40; i += 1) {
    spec.push([`maintainer${i % 4}-v${i}@example.com`, 1]);
  }
  const rows = buildRows(spec);
  const out = publisher.extract({ packageName: 'express-like', history: rows });

  assert.equal(out.tenure.length, 40);
  for (const block of out.tenure) {
    assert.equal(block.version_count, 1);
    assert.equal(block.duration_ms, 0);
    assert.equal(block.first_version, block.last_version);
    assert.equal(block.first_published_at_ms, block.last_published_at_ms);
  }
});

test('fixture C (ua-parser-js class): 100 versions same identity → 1 block', () => {
  const rows = buildRows([['faisalman@example.com', 100]]);
  const out = publisher.extract({ packageName: 'ua-parser-js', history: rows });

  assert.equal(out.tenure.length, 1);
  const [only] = out.tenure;
  assert.equal(only.identity, 'faisalman <faisalman@example.com>');
  assert.equal(only.version_count, 100);
  assert.equal(only.first_version, '1.0.0');
  assert.equal(only.last_version, '1.0.99');
  assert.equal(only.duration_ms, 99 * DAY_MS);
});

test('tenure: single version → one block, duration_ms = 0', () => {
  const rows = buildRows([['solo@example.com', 1]]);
  const out = publisher.extract({ packageName: 'solo', history: rows });

  assert.equal(out.tenure.length, 1);
  assert.equal(out.tenure[0].version_count, 1);
  assert.equal(out.tenure[0].duration_ms, 0);
  assert.equal(out.tenure[0].first_version, '1.0.0');
  assert.equal(out.tenure[0].last_version, '1.0.0');
});

test('tenure: empty history → empty tenure array', () => {
  const out = publisher.extract({ packageName: 'empty', history: [] });
  assert.deepEqual(out.tenure, []);
});

test('tenure: A/B/A pattern yields 3 distinct blocks (not deduped across gaps)', () => {
  const rows = buildRows([
    ['a@x.com', 2],
    ['b@y.com', 1],
    ['a@x.com', 3],
  ]);
  const out = publisher.extract({ packageName: 'aba', history: rows });

  assert.equal(out.tenure.length, 3);
  assert.equal(out.tenure[0].identity, 'a <a@x.com>');
  assert.equal(out.tenure[0].version_count, 2);
  assert.equal(out.tenure[1].identity, 'b <b@y.com>');
  assert.equal(out.tenure[1].version_count, 1);
  assert.equal(out.tenure[2].identity, 'a <a@x.com>');
  assert.equal(out.tenure[2].version_count, 3);
});

test('tenure: degraded rows in the middle do NOT split a same-identity run', () => {
  // Degraded rows are dropped in normalizeAndFilter before sort, so the
  // surrounding A rows stay contiguous as one tenure block.
  const rows = [
    { version: '1.0.0', publisher_email: 'a@x.com', publisher_name: 'A', published_at_ms: 1_000 },
    { version: '1.0.1', publisher_email: 'a@x.com', publisher_name: 'A', published_at_ms: 2_000 },
    // Degraded — no timestamp
    { version: '1.0.2', publisher_email: 'a@x.com', publisher_name: 'A', published_at_ms: null },
    // Degraded — no identity
    { version: '1.0.3', publisher_email: null, publisher_name: null, published_at_ms: 4_000 },
    { version: '1.0.4', publisher_email: 'a@x.com', publisher_name: 'A', published_at_ms: 5_000 },
  ];
  const out = publisher.extract({ packageName: 'degraded-middle', history: rows });

  assert.equal(out.signals.skipped_versions_count, 2);
  assert.equal(out.tenure.length, 1);
  assert.equal(out.tenure[0].version_count, 3);
  assert.equal(out.tenure[0].first_version, '1.0.0');
  assert.equal(out.tenure[0].last_version, '1.0.4');
  assert.equal(out.tenure[0].duration_ms, 4_000);
});

test('tenure: rows with missing/empty version are skipped, not included', () => {
  const rows = [
    { version: '1.0.0', publisher_email: 'a@x.com', publisher_name: 'A', published_at_ms: 1_000 },
    // Invalid version — not a string
    { version: null, publisher_email: 'a@x.com', publisher_name: 'A', published_at_ms: 2_000 },
    // Invalid version — empty string
    { version: '', publisher_email: 'a@x.com', publisher_name: 'A', published_at_ms: 3_000 },
    // Invalid version — number
    { version: 42, publisher_email: 'a@x.com', publisher_name: 'A', published_at_ms: 4_000 },
    { version: '1.0.1', publisher_email: 'a@x.com', publisher_name: 'A', published_at_ms: 5_000 },
  ];
  const out = publisher.extract({ packageName: 'bad-versions', history: rows });

  assert.equal(out.signals.skipped_versions_count, 3);
  assert.equal(out.tenure.length, 1);
  assert.equal(out.tenure[0].version_count, 2);
  assert.equal(out.tenure[0].first_version, '1.0.0');
  assert.equal(out.tenure[0].last_version, '1.0.1');
});

test('tenure: out-of-order input produces same tenure as sorted input', () => {
  const rows = buildRows([
    ['a@x.com', 3],
    ['b@y.com', 2],
  ]);
  const forward = publisher.extract({ packageName: 'order', history: rows });
  const reversed = publisher.extract({ packageName: 'order', history: rows.slice().reverse() });
  assert.equal(JSON.stringify(forward.tenure), JSON.stringify(reversed.tenure));
  assert.equal(forward.tenure.length, 2);
  assert.equal(forward.tenure[0].version_count, 3);
  assert.equal(forward.tenure[1].version_count, 2);
});

// ---------------------------------------------------------------------------
// Sub-step 2c: transitions with prior_tenure + gap
//
// Each transition is a boundary between adjacent tenure blocks, carrying
// enough numeric context for the downstream gate to tell apart four
// shapes that all look identical to a simple "publisher_changed" boolean.
//
// Fixture matrix:
//   A — single handoff (event-stream class)       → 1 transition
//   B — 40 rotating committee singletons          → 39 transitions
//   C — 100 versions, one identity                → 0 transitions
//   D — dormancy revive (5 active, 730d silent,    → 1 transition, huge gap
//       then new identity) — the shape behind
//       multiple 2024–2026 takeover campaigns
//       (note: NOT the real faker incident, which
//        was intentional self-sabotage, not a
//        takeover — the name is generic on purpose)
//   E — rapid unannounced handoff (10 active,      → 1 transition, 1h gap
//       new identity publishes 1 hour later)
//   A/B/A reappearance (from 2b fixture)           → 2 transitions
// ---------------------------------------------------------------------------

test('transitions: empty history → empty transitions', () => {
  const out = publisher.extract({ packageName: 'empty', history: [] });
  assert.deepEqual(out.transitions, []);
  assert.equal(out.signals.transition_count, 0);
});

test('transitions: single tenure block → zero transitions', () => {
  const rows = buildRows([['solo@example.com', 1]]);
  const out = publisher.extract({ packageName: 'solo', history: rows });
  assert.equal(out.tenure.length, 1);
  assert.equal(out.transitions.length, 0);
  assert.equal(out.signals.transition_count, 0);
});

test('fixture A (event-stream class): exactly 1 transition with tenure-weighted fields', () => {
  const rows = buildRows([
    ['dominictarr@example.com', 27],
    ['right9ctrl@example.com', 3],
  ]);
  const out = publisher.extract({ packageName: 'event-stream', history: rows });

  assert.equal(out.transitions.length, 1);
  assert.equal(out.signals.transition_count, 1);

  const [t] = out.transitions;
  assert.equal(t.from_identity, 'dominictarr <dominictarr@example.com>');
  assert.equal(t.to_identity, 'right9ctrl <right9ctrl@example.com>');
  assert.equal(t.at_version, '1.0.27');
  assert.equal(t.prior_tenure_versions, 27);
  assert.equal(t.prior_tenure_duration_ms, 26 * DAY_MS);
  assert.equal(t.gap_ms, DAY_MS);
  assert.equal(t.from_index, 0);
});

test('fixture B (committee): 40 rotating identities → 39 transitions of uniform shape', () => {
  const spec = [];
  for (let i = 0; i < 40; i += 1) {
    spec.push([`maintainer${i}@example.com`, 1]);
  }
  const rows = buildRows(spec);
  const out = publisher.extract({ packageName: 'committee', history: rows });

  assert.equal(out.transitions.length, 39);
  assert.equal(out.signals.transition_count, 39);

  for (const t of out.transitions) {
    // Every committee hop: previous block held one version, zero
    // duration, and the gap is the uniform stride. The gate's job is
    // to recognize this shape as ALLOW — none of the numeric features
    // individually say "attack".
    assert.equal(t.prior_tenure_versions, 1);
    assert.equal(t.prior_tenure_duration_ms, 0);
    assert.equal(t.gap_ms, DAY_MS);
  }
  // from_index is monotonic 0..38
  for (let i = 0; i < out.transitions.length; i += 1) {
    assert.equal(out.transitions[i].from_index, i);
  }
});

test('fixture C (long solo tenure): 100 same-identity versions → 0 transitions', () => {
  const rows = buildRows([['faisalman@example.com', 100]]);
  const out = publisher.extract({ packageName: 'ua-parser-js', history: rows });

  // Negative test: even 100 consecutive versions under the same
  // identity must NOT fabricate a transition. This is the
  // ua-parser-js-class case (token theft, same publisher) — the
  // publisher pattern must stay silent so other patterns (content
  // hash, install scripts, scope boundary) can carry the signal.
  assert.equal(out.transitions.length, 0);
  assert.equal(out.signals.transition_count, 0);
});

test('fixture D (dormancy-revive): 5 active → 730-day silence → 1 by new identity', () => {
  // Shape behind multiple 2024–2026 abandoned-package takeovers.
  // A short original tenure followed by multi-year silence and a
  // sudden revive under a new identity is the canonical strong
  // signal: the gap itself IS the takeover tell. Without gap_ms,
  // this is indistinguishable from committee rotation.
  const rows = buildRowsAbsolute([
    ['orig@example.com', 0],
    ['orig@example.com', 25 * DAY_MS],
    ['orig@example.com', 50 * DAY_MS],
    ['orig@example.com', 75 * DAY_MS],
    ['orig@example.com', 100 * DAY_MS],
    ['newowner@example.com', 830 * DAY_MS],
  ]);
  const out = publisher.extract({ packageName: 'dormancy-revive', history: rows });

  assert.equal(out.tenure.length, 2);
  assert.equal(out.transitions.length, 1);

  const [t] = out.transitions;
  assert.equal(t.from_identity, 'orig <orig@example.com>');
  assert.equal(t.to_identity, 'newowner <newowner@example.com>');
  assert.equal(t.prior_tenure_versions, 5);
  assert.equal(t.prior_tenure_duration_ms, 100 * DAY_MS);
  assert.equal(t.gap_ms, 730 * DAY_MS);
  assert.equal(t.from_index, 0);
});

test('fixture E (rapid unannounced handoff): 10 active, new identity 1h later', () => {
  // Shape: established contributor, no announcement, new identity
  // publishes an hour after the last legitimate release. The 1-hour
  // gap alongside 10 versions of prior tenure is what distinguishes
  // this from committee rotation (where gap IS typical) and from
  // takeover-after-dormancy (where the gap is enormous).
  const spec = [];
  for (let i = 0; i < 10; i += 1) {
    spec.push(['orig@example.com', i * DAY_MS]);
  }
  spec.push(['attacker@example.com', 9 * DAY_MS + HOUR_MS]);
  const rows = buildRowsAbsolute(spec);
  const out = publisher.extract({ packageName: 'rapid-handoff', history: rows });

  assert.equal(out.transitions.length, 1);
  const [t] = out.transitions;
  assert.equal(t.prior_tenure_versions, 10);
  assert.equal(t.prior_tenure_duration_ms, 9 * DAY_MS);
  assert.equal(t.gap_ms, HOUR_MS);
});

test('transitions: A/B/A reappearance yields 2 transitions with correct from_index sequence', () => {
  const rows = buildRows([
    ['a@x.com', 2],
    ['b@y.com', 1],
    ['a@x.com', 3],
  ]);
  const out = publisher.extract({ packageName: 'aba', history: rows });

  assert.equal(out.transitions.length, 2);
  assert.equal(out.transitions[0].from_identity, 'a <a@x.com>');
  assert.equal(out.transitions[0].to_identity, 'b <b@y.com>');
  assert.equal(out.transitions[0].prior_tenure_versions, 2);
  assert.equal(out.transitions[0].from_index, 0);

  assert.equal(out.transitions[1].from_identity, 'b <b@y.com>');
  assert.equal(out.transitions[1].to_identity, 'a <a@x.com>');
  assert.equal(out.transitions[1].prior_tenure_versions, 1);
  assert.equal(out.transitions[1].prior_tenure_duration_ms, 0);
  assert.equal(out.transitions[1].from_index, 1);
});

test('transitions: invariant — length equals max(tenure.length - 1, 0)', () => {
  const cases = [
    { history: [], expectedTenure: 0, expectedTransitions: 0 },
    { history: buildRows([['a@x.com', 1]]), expectedTenure: 1, expectedTransitions: 0 },
    { history: buildRows([['a@x.com', 3]]), expectedTenure: 1, expectedTransitions: 0 },
    { history: buildRows([['a@x.com', 1], ['b@y.com', 1]]), expectedTenure: 2, expectedTransitions: 1 },
    {
      history: buildRows([
        ['a@x.com', 2], ['b@y.com', 1], ['c@z.com', 4], ['d@w.com', 1],
      ]),
      expectedTenure: 4,
      expectedTransitions: 3,
    },
  ];
  for (const { history, expectedTenure, expectedTransitions } of cases) {
    const out = publisher.extract({ packageName: 'invariant', history });
    assert.equal(out.tenure.length, expectedTenure);
    assert.equal(out.transitions.length, expectedTransitions);
    assert.equal(out.signals.transition_count, expectedTransitions);
  }
});

test('transitions: determinism — permuted input produces byte-identical transitions', () => {
  const rows = buildRowsAbsolute([
    ['a@x.com', 0],
    ['a@x.com', 10 * DAY_MS],
    ['b@y.com', 20 * DAY_MS],
    ['a@x.com', 30 * DAY_MS],
  ]);
  const forward = publisher.extract({ packageName: 'perm', history: rows });
  const reversed = publisher.extract({ packageName: 'perm', history: rows.slice().reverse() });
  assert.equal(JSON.stringify(forward.transitions), JSON.stringify(reversed.transitions));
});

// ---------------------------------------------------------------------------
// Sub-step 2d: overlap detection (W=3, definition (a))
//
// Fixtures F, H, I below are the BOUNDARY-REGRESSION CORE — locked as
// test-first so the exact W=3 boundary is pinned down before any
// implementation touches publisher.js. The sort-tertiary-key hole in 2b
// was found only post-commit; this time the boundary fixtures exist
// before the code does.
//
//   F — committee-of-3 rotation (A,B,C,A,B,C,A,B,C)
//       Canonical POSITIVE: from transition #3 onward every incoming
//       identity is within the last 3 contributor blocks. 6 of 8
//       transitions overlap.
//
//   H — W=3 boundary OUTSIDE (A,B,C,D,A)
//       A reappears at block 4, which is 4 tenure blocks after its
//       original block 0. Window for the final transition is
//       [B, C, D] — A must NOT be flagged as overlap. This is the
//       fixture that catches off-by-one errors in the window bounds.
//
//   I — W=3 boundary INSIDE (A,B,C,A)
//       A reappears at block 3, exactly 3 tenure blocks after its
//       original block 0. Window for the final transition is
//       [A, B, C] — A MUST be flagged as overlap. Pair with H: the
//       two together pin the window to exactly [max(0, i-W+1) .. i].
//
// Expected to be RED until sub-step 2d step 2 lands extractOverlap.
// ---------------------------------------------------------------------------

test('fixture F (committee-of-3 rotation): transitions #0,#1 cold, #2–#7 overlap', () => {
  // A,B,C,A,B,C,A,B,C → 9 tenure blocks → 8 transitions.
  // First two hops exit the visible-history window (no prior occurrence
  // of B, then of C). From transition #2 onward, the rotation has
  // enough tail that every incoming identity sits in the last 3 blocks.
  const rows = buildRows([
    ['a@x.com', 1], ['b@y.com', 1], ['c@z.com', 1],
    ['a@x.com', 1], ['b@y.com', 1], ['c@z.com', 1],
    ['a@x.com', 1], ['b@y.com', 1], ['c@z.com', 1],
  ]);
  const out = publisher.extract({ packageName: 'committee-rotation', history: rows });

  assert.equal(out.tenure.length, 9);
  assert.equal(out.transitions.length, 8);

  const expected = [false, false, true, true, true, true, true, true];
  for (let i = 0; i < expected.length; i += 1) {
    assert.equal(
      out.transitions[i].is_overlap_window_W3,
      expected[i],
      `transition[${i}] (${out.transitions[i].from_identity} → ${out.transitions[i].to_identity}) overlap mismatch`,
    );
  }

  // Aggregate: committee shape produces has_overlap_transition=true.
  assert.equal(out.signals.has_overlap_transition, true);
});

test('fixture H (W=3 boundary OUTSIDE, A,B,C,D,A): A just outside window, no overlap', () => {
  // A sits at block 0. Final transition D→A has from_index=3; the
  // window [max(0, 3-2) .. 3] = [1, 2, 3] = [B, C, D]. A is NOT in
  // that window — reappearance happened one block too late. This is
  // the failure mode an off-by-one in the window bounds would hide.
  const rows = buildRows([
    ['a@x.com', 1], ['b@y.com', 1], ['c@z.com', 1],
    ['d@w.com', 1], ['a@x.com', 1],
  ]);
  const out = publisher.extract({ packageName: 'w3-outside', history: rows });

  assert.equal(out.tenure.length, 5);
  assert.equal(out.transitions.length, 4);

  for (let i = 0; i < out.transitions.length; i += 1) {
    assert.equal(
      out.transitions[i].is_overlap_window_W3,
      false,
      `transition[${i}] (${out.transitions[i].from_identity} → ${out.transitions[i].to_identity}) must NOT overlap — A is 4 blocks back, outside W=3`,
    );
  }

  assert.equal(out.signals.has_overlap_transition, false);
});

test('fixture I (W=3 boundary INSIDE, A,B,C,A): A just inside window, overlap fires', () => {
  // A sits at block 0. Final transition C→A has from_index=2; the
  // window [max(0, 2-2) .. 2] = [0, 1, 2] = [A, B, C]. A IS in
  // that window — reappearance exactly at the W=3 edge. Paired with
  // fixture H this pins the window bounds to [max(0, i-W+1) .. i].
  const rows = buildRows([
    ['a@x.com', 1], ['b@y.com', 1], ['c@z.com', 1], ['a@x.com', 1],
  ]);
  const out = publisher.extract({ packageName: 'w3-inside', history: rows });

  assert.equal(out.tenure.length, 4);
  assert.equal(out.transitions.length, 3);

  assert.equal(out.transitions[0].is_overlap_window_W3, false);
  assert.equal(out.transitions[1].is_overlap_window_W3, false);
  assert.equal(
    out.transitions[2].is_overlap_window_W3,
    true,
    'final transition C→A: A is exactly 3 blocks back, at the inclusive W=3 edge',
  );

  assert.equal(out.signals.has_overlap_transition, true);
});

// ---------------------------------------------------------------------------
// Sub-step 2d: remaining fixture matrix
//
// F, H, I are the boundary-regression core (above). These are the
// broader coverage cases — canonical cold handoffs, the solo-only
// case that produces no transitions, and the aggregate-signal table.
// Together with F/H/I this is the complete 2d matrix.
// ---------------------------------------------------------------------------

test('fixture A overlap: event-stream cold handoff → is_overlap=false', () => {
  // Canonical cold-handoff shape: right9ctrl has never contributed
  // before. The single transition must be marked non-overlapping —
  // that's the field that turns a noisy "publisher_changed" boolean
  // into an audit-grade signal.
  const rows = buildRows([
    ['dominictarr@example.com', 27],
    ['right9ctrl@example.com', 3],
  ]);
  const out = publisher.extract({ packageName: 'event-stream', history: rows });

  assert.equal(out.transitions.length, 1);
  assert.equal(out.transitions[0].is_overlap_window_W3, false);
  assert.equal(out.signals.has_overlap_transition, false);
});

test('fixture B overlap: 40 distinct committee singletons → all cold', () => {
  // Deliberately NOT a rotating committee (each identity appears once).
  // Every hop is to a previously-unseen identity; overlap must fire
  // nowhere. Distinguishes "distinct-maintainer sequence" (cold) from
  // "rotating committee" (fixture F, overlap-dominant).
  const spec = [];
  for (let i = 0; i < 40; i += 1) {
    spec.push([`maintainer${i}@example.com`, 1]);
  }
  const rows = buildRows(spec);
  const out = publisher.extract({ packageName: 'distinct-40', history: rows });

  assert.equal(out.transitions.length, 39);
  for (const t of out.transitions) {
    assert.equal(t.is_overlap_window_W3, false);
  }
  assert.equal(out.signals.has_overlap_transition, false);
});

test('fixture C overlap: long solo tenure → vacuous (no transitions, no overlap)', () => {
  const rows = buildRows([['faisalman@example.com', 100]]);
  const out = publisher.extract({ packageName: 'ua-parser-js', history: rows });

  assert.equal(out.transitions.length, 0);
  assert.equal(out.signals.has_overlap_transition, false);
});

test('fixture D overlap: dormancy-revive → is_overlap=false despite long gap', () => {
  // Critical: gap_ms is huge (730 days) but overlap is definitional,
  // not temporal. newowner never published prior — cold regardless
  // of how much time passed. Proves definition (a) is independent of
  // the gap field. This is why we didn't pick definition (c)
  // (time-windowed): it would collapse the distinct signals.
  const rows = buildRowsAbsolute([
    ['orig@example.com', 0],
    ['orig@example.com', 25 * DAY_MS],
    ['orig@example.com', 50 * DAY_MS],
    ['orig@example.com', 75 * DAY_MS],
    ['orig@example.com', 100 * DAY_MS],
    ['newowner@example.com', 830 * DAY_MS],
  ]);
  const out = publisher.extract({ packageName: 'dormancy-revive-overlap', history: rows });

  assert.equal(out.transitions.length, 1);
  assert.equal(out.transitions[0].is_overlap_window_W3, false);
  assert.equal(out.transitions[0].gap_ms, 730 * DAY_MS); // sanity: gap is huge
  assert.equal(out.signals.has_overlap_transition, false);
});

test('fixture G overlap: A/B/A minimal reappearance → [false, true]', () => {
  const rows = buildRows([
    ['a@x.com', 2],
    ['b@y.com', 1],
    ['a@x.com', 3],
  ]);
  const out = publisher.extract({ packageName: 'aba-overlap', history: rows });

  assert.equal(out.transitions.length, 2);
  assert.equal(out.transitions[0].is_overlap_window_W3, false);
  assert.equal(
    out.transitions[1].is_overlap_window_W3,
    true,
    'B→A transition: A is in the window [block[0], block[1]] = [A, B]',
  );
  assert.equal(out.signals.has_overlap_transition, true);
});

test('fixture J overlap: empty history → empty transitions, aggregate false', () => {
  const out = publisher.extract({ packageName: 'empty-overlap', history: [] });
  assert.equal(out.transitions.length, 0);
  assert.equal(out.signals.has_overlap_transition, false);
});

test('fixture K overlap: single block (no transitions) → aggregate false', () => {
  const rows = buildRows([['solo@example.com', 1]]);
  const out = publisher.extract({ packageName: 'single-block', history: rows });
  assert.equal(out.transitions.length, 0);
  assert.equal(out.signals.has_overlap_transition, false);
});

test('overlap: aggregate has_overlap_transition matches per-transition OR', () => {
  // Invariant: signals.has_overlap_transition === transitions.some(is_overlap).
  // Walk a small matrix where the answer is statically known and verify
  // the aggregate is the OR of the per-transition booleans — this is
  // the field the gate contract warns NOT to shortcut on, so it must
  // be structurally correct even when noisy.
  const cases = [
    { rows: [], expected: false },
    { rows: buildRows([['a@x.com', 1]]), expected: false },
    { rows: buildRows([['a@x.com', 1], ['b@y.com', 1]]), expected: false },
    // A/B/A — one overlap
    {
      rows: buildRows([['a@x.com', 1], ['b@y.com', 1], ['a@x.com', 1]]),
      expected: true,
    },
    // A/B/C/D — all cold
    {
      rows: buildRows([
        ['a@x.com', 1], ['b@y.com', 1], ['c@z.com', 1], ['d@w.com', 1],
      ]),
      expected: false,
    },
  ];
  for (const { rows, expected } of cases) {
    const out = publisher.extract({ packageName: 'agg', history: rows });
    const manualOr = out.transitions.some((t) => t.is_overlap_window_W3);
    assert.equal(out.signals.has_overlap_transition, manualOr);
    assert.equal(out.signals.has_overlap_transition, expected);
  }
});

test('overlap: determinism — permuted input produces byte-identical overlap flags', () => {
  // Overlap is computed over sorted tenure; if sort is deterministic
  // (proven by 2b sort-tertiary-key fix), overlap must be too. This
  // is the closing guard — any future change that introduces
  // non-determinism in tenure/transitions/overlap will fail here.
  const rows = buildRowsAbsolute([
    ['a@x.com', 0],
    ['b@y.com', 10 * DAY_MS],
    ['c@z.com', 20 * DAY_MS],
    ['a@x.com', 30 * DAY_MS],
    ['d@w.com', 40 * DAY_MS],
    ['a@x.com', 50 * DAY_MS],
  ]);
  const forward = publisher.extract({ packageName: 'overlap-det', history: rows });
  const reversed = publisher.extract({
    packageName: 'overlap-det',
    history: rows.slice().reverse(),
  });
  assert.equal(JSON.stringify(forward), JSON.stringify(reversed));

  // Sanity-check the overlap pattern against hand-traced windows:
  //   t0 A→B from_index=0 window [0]=[A]           — B? no  → false
  //   t1 B→C from_index=1 window [0,1]=[A,B]       — C? no  → false
  //   t2 C→A from_index=2 window [0,1,2]=[A,B,C]   — A? YES → true
  //   t3 A→D from_index=3 window [1,2,3]=[B,C,A]   — D? no  → false
  //   t4 D→A from_index=4 window [2,3,4]=[C,A,D]   — A? YES → true
  //                                                  (A is at block 3,
  //                                                   still inside W=3)
  assert.deepEqual(
    forward.transitions.map((t) => t.is_overlap_window_W3),
    [false, false, true, false, true],
  );
});

// ---------------------------------------------------------------------------
// Sub-step 2e: known_contributor detection (K=10)
//
// Fixtures L, M, N below are the BOUNDARY-REGRESSION CORE — locked as
// test-first so the K=10 cutoff and the (false, true) "returning-dormant-
// maintainer" cell are pinned before any code touches publisher.js.
//
//   L — K-boundary INSIDE  (A×10, B×1, A×1)
//       Final B→A transition: A has exactly 10 prior versions.
//       is_known_contributor_K10 MUST be true (>= comparison, inclusive).
//
//   M — K-boundary OUTSIDE (A×9, B×1, A×1)
//       Final B→A transition: A has exactly 9 prior versions.
//       is_known_contributor_K10 MUST be false.
//
//       L and M together pin the cutoff to exactly `>= K`. An off-by-
//       one in the comparator (e.g. `> K`) would pass L but flip M.
//
//   N — returning dormant maintainer (A×15, B×5, C×5, D×5, A×1)
//       Final D→A transition: A outside the W=3 overlap window
//       [B, C, D] (overlap_W3=false) AND A has 15 prior versions
//       (is_known_contributor_K10=true). This is cell (false, true)
//       of the 2×2 — the product-differentiating case that every
//       competing tool misclassifies as a cold handoff. Intermediate
//       B/C/D blocks exist specifically to push A out of the W=3
//       overlap window at the return; with fewer intermediate blocks,
//       overlap_W3 would be true and we'd be testing a different
//       2×2 cell.
//
// Expected RED until sub-step 2e step 2 lands extractKnownContributor.
// ---------------------------------------------------------------------------

test('fixture L (K-boundary INSIDE, 10 prior versions): known_contributor fires', () => {
  const rows = buildRows([
    ['a@x.com', 10],
    ['b@y.com', 1],
    ['a@x.com', 1],
  ]);
  const out = publisher.extract({ packageName: 'k-inside', history: rows });

  assert.equal(out.tenure.length, 3);
  assert.equal(out.transitions.length, 2);

  const returnTransition = out.transitions[1];
  assert.equal(returnTransition.from_identity, 'b <b@y.com>');
  assert.equal(returnTransition.to_identity, 'a <a@x.com>');
  assert.equal(
    returnTransition.prior_contribution_count,
    10,
    'A has exactly 10 prior versions — the inclusive K=10 boundary',
  );
  assert.equal(
    returnTransition.is_known_contributor_K10,
    true,
    'prior_contribution_count=10 MUST satisfy the >= K comparison',
  );

  // Sanity: the A→B transition has to_identity=B with 0 prior versions.
  assert.equal(out.transitions[0].prior_contribution_count, 0);
  assert.equal(out.transitions[0].is_known_contributor_K10, false);
});

test('fixture M (K-boundary OUTSIDE, 9 prior versions): known_contributor does NOT fire', () => {
  const rows = buildRows([
    ['a@x.com', 9],
    ['b@y.com', 1],
    ['a@x.com', 1],
  ]);
  const out = publisher.extract({ packageName: 'k-outside', history: rows });

  assert.equal(out.tenure.length, 3);
  assert.equal(out.transitions.length, 2);

  const returnTransition = out.transitions[1];
  assert.equal(returnTransition.to_identity, 'a <a@x.com>');
  assert.equal(
    returnTransition.prior_contribution_count,
    9,
    'A has exactly 9 prior versions — one below the K=10 threshold',
  );
  assert.equal(
    returnTransition.is_known_contributor_K10,
    false,
    'prior_contribution_count=9 MUST NOT satisfy the >= K comparison (off-by-one guard)',
  );
});

test('fixture N (returning dormant maintainer): cell (false, true) fires — the standout case', () => {
  // A contributes 15 versions, then B/C/D each contribute 5 across the
  // intermediate blocks, then A returns for one final release. At that
  // return transition:
  //   - overlap_W3 = false (A at block 0, window at from_index=3 is
  //     [block[1], block[2], block[3]] = [B, C, D] — A not present)
  //   - is_known_contributor_K10 = true (A has 15 prior versions)
  // This is the 2×2 cell that tools without the knownness axis
  // misclassify as a cold handoff. Our pattern layer emits both
  // booleans so the step-3 gate can evaluate the 2×2 per transition.
  const rows = buildRows([
    ['a@x.com', 15],
    ['b@y.com', 5],
    ['c@z.com', 5],
    ['d@w.com', 5],
    ['a@x.com', 1],
  ]);
  const out = publisher.extract({ packageName: 'dormant-return', history: rows });

  assert.equal(out.tenure.length, 5);
  assert.equal(out.transitions.length, 4);

  // Transitions 0, 1, 2 are all cold-and-unknown — this is the
  // (false, false) cell, where disposition depends on prior_tenure
  // (t0's prior_tenure=15 would be escalated by the gate; t1/t2's
  // prior_tenure=5 would not).
  assert.equal(out.transitions[0].to_identity, 'b <b@y.com>');
  assert.equal(out.transitions[0].is_overlap_window_W3, false);
  assert.equal(out.transitions[0].prior_contribution_count, 0);
  assert.equal(out.transitions[0].is_known_contributor_K10, false);

  assert.equal(out.transitions[1].to_identity, 'c <c@z.com>');
  assert.equal(out.transitions[1].is_overlap_window_W3, false);
  assert.equal(out.transitions[1].prior_contribution_count, 0);
  assert.equal(out.transitions[1].is_known_contributor_K10, false);

  assert.equal(out.transitions[2].to_identity, 'd <d@w.com>');
  assert.equal(out.transitions[2].is_overlap_window_W3, false);
  assert.equal(out.transitions[2].prior_contribution_count, 0);
  assert.equal(out.transitions[2].is_known_contributor_K10, false);

  // The standout transition — cell (false, true).
  const returnT = out.transitions[3];
  assert.equal(returnT.from_identity, 'd <d@w.com>');
  assert.equal(returnT.to_identity, 'a <a@x.com>');
  assert.equal(
    returnT.is_overlap_window_W3,
    false,
    'A is at block 0; at from_index=3 the window is blocks [1,2,3]=[B,C,D], A is NOT present',
  );
  assert.equal(
    returnT.prior_contribution_count,
    15,
    'A contributed 15 versions before this transition',
  );
  assert.equal(
    returnT.is_known_contributor_K10,
    true,
    'cell (false, true) — the returning-dormant-maintainer signature',
  );
});

// ---------------------------------------------------------------------------
// Sub-step 2e: remaining fixture matrix
//
// L, M, N are the boundary-regression core (above). These are the broader
// coverage cases — canonical cold handoffs, the committee-rotation regime
// below K, and fixture O: a single trace that exercises all four cells of
// the (overlap × known_contributor) 2×2 matrix in one place.
// ---------------------------------------------------------------------------

test('fixture A known: event-stream cold handoff → known_contributor=false, count=0', () => {
  // right9ctrl has no prior versions. Cell (false, false) with
  // prior_tenure=27 — the canonical takeover shape the step-3 gate
  // escalates via the severity axis. Without the count field, this
  // cell would look identical to committee churn.
  const rows = buildRows([
    ['dominictarr@example.com', 27],
    ['right9ctrl@example.com', 3],
  ]);
  const out = publisher.extract({ packageName: 'event-stream-known', history: rows });

  assert.equal(out.transitions.length, 1);
  assert.equal(out.transitions[0].prior_contribution_count, 0);
  assert.equal(out.transitions[0].is_known_contributor_K10, false);
  assert.equal(out.transitions[0].is_overlap_window_W3, false);
});

test('fixture B known: 40 distinct singletons → every to_identity unknown', () => {
  // Distinct-maintainer sequence, not a rotation. Every incoming
  // identity is novel — 39 transitions, all prior_count=0. Distinguishes
  // from fixture F where rotation accumulates counts over time.
  const spec = [];
  for (let i = 0; i < 40; i += 1) {
    spec.push([`maintainer${i}@example.com`, 1]);
  }
  const rows = buildRows(spec);
  const out = publisher.extract({ packageName: 'distinct-40-known', history: rows });

  assert.equal(out.transitions.length, 39);
  for (const t of out.transitions) {
    assert.equal(t.prior_contribution_count, 0);
    assert.equal(t.is_known_contributor_K10, false);
  }
});

test('fixture C known: long solo tenure → vacuous (no transitions)', () => {
  const rows = buildRows([['faisalman@example.com', 100]]);
  const out = publisher.extract({ packageName: 'ua-parser-js-known', history: rows });
  assert.equal(out.transitions.length, 0);
});

test('fixture D known: dormancy-revive → newowner is NOT a known contributor', () => {
  // Cell (false, false) with short prior_tenure=5. The 730-day gap and
  // cold incoming identity together look like takeover-after-dormancy,
  // but the severity axis (prior_tenure only 5) tells the gate this is
  // closer to short-lived ownership handoff than the event-stream class.
  // Contrast with fixture N, where the returning identity IS known
  // despite the gap.
  const rows = buildRowsAbsolute([
    ['orig@example.com', 0],
    ['orig@example.com', 25 * DAY_MS],
    ['orig@example.com', 50 * DAY_MS],
    ['orig@example.com', 75 * DAY_MS],
    ['orig@example.com', 100 * DAY_MS],
    ['newowner@example.com', 830 * DAY_MS],
  ]);
  const out = publisher.extract({ packageName: 'dormancy-revive-known', history: rows });

  assert.equal(out.transitions.length, 1);
  assert.equal(out.transitions[0].prior_contribution_count, 0);
  assert.equal(out.transitions[0].is_known_contributor_K10, false);
});

test('fixture F known: committee-of-3 rotation → counts accumulate, none reach K=10', () => {
  // A,B,C,A,B,C,A,B,C — cumulative counts by end are 3 each; none
  // cross K=10. This is the legitimate "first K-1 releases" regime —
  // cell (true, false) from t2 onward. The gate MUST allow this cell;
  // it is the ordinary shape of small rotating committees, not an
  // attack. A false positive here would misfire on express/moment/etc.
  const rows = buildRows([
    ['a@x.com', 1], ['b@y.com', 1], ['c@z.com', 1],
    ['a@x.com', 1], ['b@y.com', 1], ['c@z.com', 1],
    ['a@x.com', 1], ['b@y.com', 1], ['c@z.com', 1],
  ]);
  const out = publisher.extract({ packageName: 'committee-known', history: rows });

  assert.equal(out.transitions.length, 8);
  // Hand-traced cumulative counts — regression pin against miscount.
  //   t0 A→B: B prior in [A]           = 0
  //   t1 B→C: C prior in [A,B]         = 0
  //   t2 C→A: A prior in [A,B,C]       = 1
  //   t3 A→B: B prior in [A,B,C,A]     = 1
  //   t4 B→C: C prior in [A,B,C,A,B]   = 1
  //   t5 C→A: A prior in [A,B,C,A,B,C] = 2
  //   t6 A→B: B prior "                = 2
  //   t7 B→C: C prior "                = 2
  const expected = [0, 0, 1, 1, 1, 2, 2, 2];
  for (let i = 0; i < expected.length; i += 1) {
    assert.equal(
      out.transitions[i].prior_contribution_count,
      expected[i],
      `transition[${i}] prior count`,
    );
    assert.equal(out.transitions[i].is_known_contributor_K10, false);
  }
});

test('fixture G known: A/B/A with A×2 → return transition count=2, below K', () => {
  // Minimal reappearance with sub-threshold history. Cell (true, false):
  // A is in the W=3 window (overlap=true) but has only 2 prior versions,
  // below K=10. The gate treats this identically to a new committee
  // member — ALLOW — even though A has appeared before.
  const rows = buildRows([
    ['a@x.com', 2],
    ['b@y.com', 1],
    ['a@x.com', 3],
  ]);
  const out = publisher.extract({ packageName: 'aba-known', history: rows });

  assert.equal(out.transitions.length, 2);
  assert.equal(out.transitions[0].prior_contribution_count, 0);
  assert.equal(out.transitions[0].is_known_contributor_K10, false);
  assert.equal(out.transitions[1].prior_contribution_count, 2);
  assert.equal(out.transitions[1].is_known_contributor_K10, false);
});

test('fixture O (four-cell matrix): all four (overlap, known) cells in one trace', () => {
  // Comprehensive regression guard: a single fixture exercising every
  // cell of the 2×2. Any future change that breaks one axis without
  // touching the other will fail here with a specific cell mismatch.
  //
  // Layout — A×11 up front seeds A as a known contributor before the
  // first transition:
  //   block[0]=A(×11), [1]=B, [2]=A, [3]=B, [4]=C, [5]=D, [6]=E, [7]=A
  //
  // Hand-traced cells (overlap_W3, known_K10):
  //   t0 A→B  from_idx=0, win=[A]           → (F, F) — cold, novel
  //   t1 B→A  from_idx=1, win=[A,B]         → (T, T) — active recurring
  //   t2 A→B  from_idx=2, win=[A,B,A]       → (T, F) — new committee member
  //                                            (B has 1 prior, < K)
  //   t3 B→C  from_idx=3, win=[B,A,B]       → (F, F)
  //   t4 C→D  from_idx=4, win=[A,B,C]       → (F, F)
  //   t5 D→E  from_idx=5, win=[B,C,D]       → (F, F)
  //   t6 E→A  from_idx=6, win=[C,D,E]       → (F, T) — returning dormant
  //                                            (A has 12 prior, >= K)
  const rows = buildRows([
    ['a@x.com', 11],
    ['b@y.com', 1],
    ['a@x.com', 1],
    ['b@y.com', 1],
    ['c@z.com', 1],
    ['d@w.com', 1],
    ['e@v.com', 1],
    ['a@x.com', 1],
  ]);
  const out = publisher.extract({ packageName: 'four-cell', history: rows });

  assert.equal(out.tenure.length, 8);
  assert.equal(out.transitions.length, 7);

  const cells = out.transitions.map((t) => [
    t.is_overlap_window_W3,
    t.is_known_contributor_K10,
  ]);
  assert.deepEqual(cells, [
    [false, false], // t0 A→B — cold handoff shape
    [true,  true ], // t1 B→A — active recurring committee member
    [true,  false], // t2 A→B — new committee member
    [false, false], // t3 B→C
    [false, false], // t4 C→D
    [false, false], // t5 D→E
    [false, true ], // t6 E→A — RETURNING DORMANT MAINTAINER (standout)
  ]);

  // Pin raw counts too — cell truth alone is not enough if a future bug
  // shifted counts while booleans still happened to line up with K=10.
  assert.deepEqual(
    out.transitions.map((t) => t.prior_contribution_count),
    [0, 11, 1, 0, 0, 0, 12],
  );
});

test('known_contributor: determinism — permuted input produces byte-identical fields', () => {
  // Close out 2e with the same determinism guard used for 2d: permute
  // the input and confirm byte-identical output. The existing 2d
  // determinism test already byte-compares the whole extract() output,
  // but a 2e-scoped trace with nonzero counts is a clearer regression
  // signal than a pass through the omnibus case.
  const rows = buildRowsAbsolute([
    ['a@x.com', 0],
    ['a@x.com', 5 * DAY_MS],
    ['a@x.com', 10 * DAY_MS],
    ['b@y.com', 15 * DAY_MS],
    ['a@x.com', 20 * DAY_MS],
  ]);
  const forward = publisher.extract({ packageName: 'known-det', history: rows });
  const reversed = publisher.extract({
    packageName: 'known-det',
    history: rows.slice().reverse(),
  });
  assert.equal(JSON.stringify(forward), JSON.stringify(reversed));

  // And a small sanity anchor so the determinism test also documents
  // expected count for future readers.
  assert.equal(forward.transitions.length, 2);
  assert.equal(forward.transitions[1].to_identity, 'a <a@x.com>');
  assert.equal(forward.transitions[1].prior_contribution_count, 3);
  assert.equal(forward.transitions[1].is_known_contributor_K10, false);
});

// ---------------------------------------------------------------------------
// Sub-step 2f: signals aggregation — RED lock (fixtures P, Q, empty)
//
// 2f collapses per-transition detail into package-level aggregates in
// three tiers:
//
//   Tier 1 — sufficiency:  observed_versions_count, unique_identity_count,
//                          has_sufficient_history
//   Tier 2 — severity:     max_prior_tenure_versions,
//                          max_cold_handoff_prior_tenure,
//                          cold_handoff_count,           (F,F)
//                          new_committee_member_count,   (T,F)
//                          returning_dormant_count,      (F,T) — STANDOUT
//                          recurring_member_count        (T,T)
//   Tier 3 — temporal:     total_history_duration_ms,
//                          longest_tenure_versions,
//                          longest_tenure_duration_ms
//
// Fixtures P/Q/empty below are locked as failing tests before any
// implementation — the L/M/N / F/H/I discipline extended to 2f. The
// four-cell trace from fixture O (sub-step 2e) is reused in P: a single
// trace with every 2×2 cell present plus enough run-length to exercise
// Tier 1 sufficiency and Tier 3 temporal extrema.
//
// Zero semantics (risk #3 decision): max_cold_handoff_prior_tenure is 0
// when no (F,F) transitions exist. Paired with cold_handoff_count=0 this
// disambiguates from "one (F,F) transition with prior_tenure=0" — a
// degenerate state that cannot arise from a real history anyway (the
// smallest tenure block has version_count=1).
// ---------------------------------------------------------------------------

test('fixture P: all three tiers on a full-coverage trace', () => {
  // Layout — 18 rows, 8 tenure blocks, 7 transitions, every 2×2 cell hit:
  //
  //   block[0] A(×11)  → exercises Tier 1 sufficiency (>=8) and
  //                      Tier 3 longest_tenure_versions=11
  //   block[1] B(×1)   t0 A→B  (F, F) prior_tenure=11 — cold, event-stream shape
  //   block[2] A(×1)   t1 B→A  (T, T) prior_tenure=1
  //   block[3] B(×1)   t2 A→B  (T, F) prior_tenure=1
  //   block[4] C(×1)   t3 B→C  (F, F) prior_tenure=1
  //   block[5] D(×1)   t4 C→D  (F, F) prior_tenure=1
  //   block[6] E(×1)   t5 D→E  (F, F) prior_tenure=1
  //   block[7] A(×1)   t6 E→A  (F, T) prior_tenure=1 — returning dormant
  //
  // buildRows places rows one DAY_MS apart from startMs → total span is
  // 17 * DAY_MS across 18 rows.
  const rows = buildRows([
    ['a@x.com', 11],
    ['b@y.com', 1],
    ['a@x.com', 1],
    ['b@y.com', 1],
    ['c@z.com', 1],
    ['d@w.com', 1],
    ['e@v.com', 1],
    ['a@x.com', 1],
  ]);
  const out = publisher.extract({ packageName: 'full-coverage', history: rows });

  // --- Tier 1: sufficiency ---
  assert.equal(out.signals.observed_versions_count, 18);
  assert.equal(out.signals.unique_identity_count, 5);
  assert.equal(out.signals.has_sufficient_history, true);

  // --- Tier 2: severity extrema + 2×2 cell histogram ---
  assert.equal(out.signals.max_prior_tenure_versions, 11);
  assert.equal(out.signals.max_cold_handoff_prior_tenure, 11);
  assert.equal(out.signals.cold_handoff_count, 4);            // cell (F, F)
  assert.equal(out.signals.new_committee_member_count, 1);    // cell (T, F)
  assert.equal(out.signals.returning_dormant_count, 1);       // cell (F, T)
  assert.equal(out.signals.recurring_member_count, 1);        // cell (T, T)

  // --- Tier 3: temporal summary ---
  assert.equal(out.signals.total_history_duration_ms, 17 * DAY_MS);
  assert.equal(out.signals.longest_tenure_versions, 11);
  assert.equal(out.signals.longest_tenure_duration_ms, 10 * DAY_MS);
});

test('fixture Q (insufficient history): has_sufficient_history=false, no zero-case surprises', () => {
  // Three rows — below MIN_HISTORY_DEPTH=8. The gate layer will SKIP
  // pattern-based evaluations; the signals must still be well-defined
  // numeric zeros (not null/undefined) so the gate can read them without
  // defensive guards. This is the zero-semantics fixture.
  const rows = buildRows([['a@x.com', 3]]);
  const out = publisher.extract({ packageName: 'thin-history', history: rows });

  // Tier 1
  assert.equal(out.signals.observed_versions_count, 3);
  assert.equal(out.signals.unique_identity_count, 1);
  assert.equal(out.signals.has_sufficient_history, false);

  // Tier 2 — no transitions, every extremum is 0, every cell count is 0.
  assert.equal(out.signals.max_prior_tenure_versions, 0);
  assert.equal(out.signals.max_cold_handoff_prior_tenure, 0);
  assert.equal(out.signals.cold_handoff_count, 0);
  assert.equal(out.signals.new_committee_member_count, 0);
  assert.equal(out.signals.returning_dormant_count, 0);
  assert.equal(out.signals.recurring_member_count, 0);

  // Tier 3 — one tenure block of 3 versions across 2 DAY_MS spans.
  assert.equal(out.signals.total_history_duration_ms, 2 * DAY_MS);
  assert.equal(out.signals.longest_tenure_versions, 3);
  assert.equal(out.signals.longest_tenure_duration_ms, 2 * DAY_MS);
});

test('fixture empty: no history → every signal is a defined zero / false', () => {
  // Closes the defined-numeric-zero contract. An empty signals object
  // or any undefined field would force every gate that consumes signals
  // to add `?? 0` guards at every read site — the kind of drift the
  // pattern layer exists to prevent.
  const out = publisher.extract({ packageName: 'empty-signals', history: [] });

  assert.equal(out.signals.observed_versions_count, 0);
  assert.equal(out.signals.unique_identity_count, 0);
  assert.equal(out.signals.has_sufficient_history, false);

  assert.equal(out.signals.max_prior_tenure_versions, 0);
  assert.equal(out.signals.max_cold_handoff_prior_tenure, 0);
  assert.equal(out.signals.cold_handoff_count, 0);
  assert.equal(out.signals.new_committee_member_count, 0);
  assert.equal(out.signals.returning_dormant_count, 0);
  assert.equal(out.signals.recurring_member_count, 0);

  assert.equal(out.signals.total_history_duration_ms, 0);
  assert.equal(out.signals.longest_tenure_versions, 0);
  assert.equal(out.signals.longest_tenure_duration_ms, 0);
});

// ---------------------------------------------------------------------------
// Sub-step 2f: invariants
//
// Properties that MUST hold on any input. Each is a one-line regression
// pin: any future change that breaks structural consistency fails here
// with a specific invariant identification, not a deep assertion diff in
// a fixture test. Swept across a small omnibus matrix — empty, thin
// history, solo tenure, committee rotation, full-coverage fixture P —
// so the invariants cover every shape in the design at once.
// ---------------------------------------------------------------------------

test('invariants: 2×2 cell histogram partitions transitions with no remainder', () => {
  // The four cell counts are mutually exclusive and collectively
  // exhaustive — every transition belongs to exactly one cell. If a
  // future change adds a third axis without updating the histogram
  // dispatch, this invariant fails loudly. Load-bearing for the gate's
  // shortcut path: shortcutting on max_cold_handoff_prior_tenure is
  // only safe if cold_handoff_count is an exact count, not a subset.
  const cases = [
    { name: 'empty',      rows: [] },
    { name: 'thin-solo',  rows: buildRows([['a@x.com', 3]]) },
    { name: 'solo-deep',  rows: buildRows([['a@x.com', 50]]) },
    { name: 'committee',  rows: buildRows([
      ['a@x.com', 1], ['b@y.com', 1], ['c@z.com', 1],
      ['a@x.com', 1], ['b@y.com', 1], ['c@z.com', 1],
      ['a@x.com', 1], ['b@y.com', 1], ['c@z.com', 1],
    ]) },
    { name: 'event-stream', rows: buildRows([
      ['dominictarr@example.com', 27],
      ['right9ctrl@example.com', 3],
    ]) },
    { name: 'fixture-P',  rows: buildRows([
      ['a@x.com', 11], ['b@y.com', 1], ['a@x.com', 1], ['b@y.com', 1],
      ['c@z.com', 1],  ['d@w.com', 1], ['e@v.com', 1], ['a@x.com', 1],
    ]) },
  ];
  for (const { name, rows } of cases) {
    const out = publisher.extract({ packageName: name, history: rows });
    const sum =
      out.signals.cold_handoff_count +
      out.signals.new_committee_member_count +
      out.signals.returning_dormant_count +
      out.signals.recurring_member_count;
    assert.equal(
      sum,
      out.signals.transition_count,
      `${name}: cell histogram sum must equal transition_count (got ${sum} vs ${out.signals.transition_count})`,
    );
    assert.equal(
      sum,
      out.transitions.length,
      `${name}: cell histogram sum must equal transitions array length`,
    );
  }
});

test('invariants: max_cold_handoff_prior_tenure <= max_prior_tenure_versions', () => {
  // (F,F) is a subset of all transitions, so the (F,F)-filtered max
  // can never exceed the unfiltered max. A regression that flipped the
  // filter (e.g., computing max over the WRONG cell) would trip here
  // immediately. Also pins the zero-case invariant: when
  // cold_handoff_count=0, max_cold_handoff_prior_tenure MUST be 0.
  const cases = [
    buildRows([]),
    buildRows([['a@x.com', 5]]),
    buildRows([['a@x.com', 10], ['b@y.com', 1], ['a@x.com', 1]]),  // (T,T) return
    buildRows([['a@x.com', 27], ['b@y.com', 3]]),                   // (F,F) cold
    buildRows([
      ['a@x.com', 11], ['b@y.com', 1], ['a@x.com', 1], ['b@y.com', 1],
      ['c@z.com', 1],  ['d@w.com', 1], ['e@v.com', 1], ['a@x.com', 1],
    ]),
  ];
  for (const rows of cases) {
    const out = publisher.extract({ packageName: 'inv-max', history: rows });
    assert.ok(
      out.signals.max_cold_handoff_prior_tenure <= out.signals.max_prior_tenure_versions,
      `subset max must not exceed total max: cold=${out.signals.max_cold_handoff_prior_tenure}, all=${out.signals.max_prior_tenure_versions}`,
    );
    if (out.signals.cold_handoff_count === 0) {
      assert.equal(
        out.signals.max_cold_handoff_prior_tenure,
        0,
        'zero-semantics: no (F,F) transitions ⇒ max_cold_handoff_prior_tenure must be 0',
      );
    }
  }
});

test('invariants: tenure-derived signals are consistent with the tenure array', () => {
  // - observed_versions_count equals the sum of tenure block version_counts
  //   (normalizeAndFilter-survivors partition into blocks with no remainder)
  // - unique_identity_count <= tenure.length (re-appearance collapses
  //   distinct blocks to fewer distinct identities, never more)
  // - longest_tenure_versions >= 1 whenever tenure.length > 0
  //   (a tenure block's minimum version_count is 1 by construction)
  // - total_history_duration_ms >= longest_tenure_duration_ms
  //   (total spans first block's first ts to last block's last ts,
  //    which covers any single block's internal span)
  const cases = [
    { name: 'empty',      rows: [] },
    { name: 'solo-1',     rows: buildRows([['a@x.com', 1]]) },
    { name: 'solo-deep',  rows: buildRows([['a@x.com', 50]]) },
    { name: 'aba',        rows: buildRows([['a@x.com', 2], ['b@y.com', 1], ['a@x.com', 3]]) },
    { name: 'fixture-P',  rows: buildRows([
      ['a@x.com', 11], ['b@y.com', 1], ['a@x.com', 1], ['b@y.com', 1],
      ['c@z.com', 1],  ['d@w.com', 1], ['e@v.com', 1], ['a@x.com', 1],
    ]) },
  ];
  for (const { name, rows } of cases) {
    const out = publisher.extract({ packageName: name, history: rows });
    const tenureSum = out.tenure.reduce((acc, b) => acc + b.version_count, 0);
    assert.equal(
      tenureSum,
      out.signals.observed_versions_count,
      `${name}: tenure version_counts must sum to observed_versions_count`,
    );
    assert.ok(
      out.signals.unique_identity_count <= out.tenure.length,
      `${name}: unique identities (${out.signals.unique_identity_count}) cannot exceed tenure block count (${out.tenure.length})`,
    );
    if (out.tenure.length > 0) {
      assert.ok(
        out.signals.longest_tenure_versions >= 1,
        `${name}: non-empty tenure must have longest_tenure_versions >= 1`,
      );
      assert.ok(
        out.signals.unique_identity_count >= 1,
        `${name}: non-empty tenure must have at least one unique identity`,
      );
    }
    assert.ok(
      out.signals.total_history_duration_ms >= out.signals.longest_tenure_duration_ms,
      `${name}: total_history_duration_ms (${out.signals.total_history_duration_ms}) must cover longest_tenure_duration_ms (${out.signals.longest_tenure_duration_ms})`,
    );
  }
});

test('signals: determinism — permuted input produces byte-identical signals aggregate', () => {
  // Closes 2f test coverage with the same determinism guard used for
  // 2d overlap and 2e known_contributor — permute the input order and
  // confirm byte-identical output. The 2d test already byte-compares
  // extract() output wholesale, but this trace is chosen specifically
  // to populate every Tier 1/2/3 field with a non-trivial value, so a
  // computation-level drift (in addition to an ordering drift) surfaces
  // here with named expected values rather than a deep-diff blob.
  //
  // Layout — 18 rows across non-uniform timing so Tier 3 temporal
  // fields have meaningful magnitudes:
  //   block[0] A(×11) days 0..100 step 10   — 100 DAY_MS span
  //   block[1] B      day 105                — 5-day gap
  //   block[2] A      day 110                — cell (T, T) at this transition
  //   block[3] B      day 115
  //   block[4] C      day 120
  //   block[5] D      day 125
  //   block[6] E      day 130
  //   block[7] A      day 300                — 170-day dormancy
  //                                            cell (F, T) — standout return
  const spec = [];
  for (let i = 0; i < 11; i += 1) spec.push(['a@x.com', i * 10 * DAY_MS]);
  spec.push(['b@y.com', 105 * DAY_MS]);
  spec.push(['a@x.com', 110 * DAY_MS]);
  spec.push(['b@y.com', 115 * DAY_MS]);
  spec.push(['c@z.com', 120 * DAY_MS]);
  spec.push(['d@w.com', 125 * DAY_MS]);
  spec.push(['e@v.com', 130 * DAY_MS]);
  spec.push(['a@x.com', 300 * DAY_MS]);
  const rows = buildRowsAbsolute(spec);

  const forward = publisher.extract({ packageName: 'signals-det', history: rows });
  const reversed = publisher.extract({
    packageName: 'signals-det',
    history: rows.slice().reverse(),
  });
  assert.equal(
    JSON.stringify(forward),
    JSON.stringify(reversed),
    'permuted input must produce byte-identical extract() output',
  );

  // Explicit expected-value anchors — any computation drift in any tier
  // fails here with a named field, not a JSON diff.
  assert.deepEqual(
    {
      // Tier 1
      observed: forward.signals.observed_versions_count,
      identities: forward.signals.unique_identity_count,
      sufficient: forward.signals.has_sufficient_history,
      // Tier 2
      max_prior: forward.signals.max_prior_tenure_versions,
      max_cold: forward.signals.max_cold_handoff_prior_tenure,
      cold: forward.signals.cold_handoff_count,
      new_member: forward.signals.new_committee_member_count,
      returning: forward.signals.returning_dormant_count,
      recurring: forward.signals.recurring_member_count,
      // Tier 3
      total_ms: forward.signals.total_history_duration_ms,
      longest_vers: forward.signals.longest_tenure_versions,
      longest_ms: forward.signals.longest_tenure_duration_ms,
    },
    {
      observed: 18,
      identities: 5,
      sufficient: true,
      max_prior: 11,
      max_cold: 11,
      cold: 4,
      new_member: 1,
      returning: 1,
      recurring: 1,
      total_ms: 300 * DAY_MS,
      longest_vers: 11,
      longest_ms: 100 * DAY_MS,
    },
  );
});

test('invariants: has_sufficient_history boundary at MIN_HISTORY_DEPTH=8', () => {
  // The threshold is inclusive >= MIN_HISTORY_DEPTH (currently 8). Pins
  // the boundary so a future constant change or comparator flip (e.g.,
  // `>` instead of `>=`) breaks a test rather than silently moving the
  // first-seen poisoning protection.
  const at7 = publisher.extract({
    packageName: 'boundary-7',
    history: buildRows([['a@x.com', 7]]),
  });
  assert.equal(at7.signals.observed_versions_count, 7);
  assert.equal(at7.signals.has_sufficient_history, false);

  const at8 = publisher.extract({
    packageName: 'boundary-8',
    history: buildRows([['a@x.com', 8]]),
  });
  assert.equal(at8.signals.observed_versions_count, 8);
  assert.equal(
    at8.signals.has_sufficient_history,
    true,
    'observed=8 must satisfy the inclusive >= threshold',
  );

  const at9 = publisher.extract({
    packageName: 'boundary-9',
    history: buildRows([['a@x.com', 9]]),
  });
  assert.equal(at9.signals.has_sufficient_history, true);
});

// ---------------------------------------------------------------------------
// Sub-step 3a: identity_profile — RED lock (3a-A … 3a-J + 2 determinism)
//
// Fills the locked-but-stubbed identity_profile contract slot. Each
// tenure block gains three new fields:
//   domain                    — extracted email domain, lowercased (or null)
//   provider                  — verified-corporate | free-webmail |
//                                privacy | unverified | unknown
//   first_seen_in_package_ms  — earliest ts this domain appears in package
//                                (same value across all blocks sharing
//                                 the domain)
//
// The extract() return's identity_profile aggregate becomes:
//   providers_seen           — unique sorted provider classes
//   has_privacy_provider     — any block's provider === 'privacy'
//   has_unverified_domain    — any block's provider === 'unverified'
//   domain_stability         — 'stable' | 'mixed' | 'churning'
//
// Provider precedence (first match wins):
//   1. unknown            — domain is null
//   2. privacy            — domain in PRIVACY_PROVIDER_DOMAINS
//   3. free-webmail       — domain in FREE_WEBMAIL_DOMAINS
//   4. verified-corporate — domain spans >= MIN_VERIFIED_VERSIONS (=2)
//                            versions in this package
//   5. unverified         — fallback for non-free, non-privacy, thin
//
// domain_stability (new-to-window rule; null domains excluded):
//   churning — >=1 non-null domain appears in final CHURNING_WINDOW=5
//              rows but NOT in any earlier row
//   mixed    — not churning AND >= 3 unique non-null domains in history
//   stable   — otherwise
//
// RED-lock discipline continues L/M/N (2e), F/H/I (2d), P/Q/empty (2f).
// Tests assert against new fields; all fail until the sub-step 3a GREEN
// impl lands.
// ---------------------------------------------------------------------------

test('fixture 3a-A: solo corporate (9 × acme.com) → verified-corporate, stable', () => {
  const rows = buildRows([['dev@acme.com', 9]]);
  const out = publisher.extract({ packageName: '3a-A', history: rows });

  assert.equal(out.tenure.length, 1);
  assert.equal(out.tenure[0].domain, 'acme.com');
  assert.equal(out.tenure[0].provider, 'verified-corporate');
  assert.equal(out.tenure[0].first_seen_in_package_ms, rows[0].published_at_ms);

  assert.deepEqual(out.identity_profile.providers_seen, ['verified-corporate']);
  assert.equal(out.identity_profile.has_privacy_provider, false);
  assert.equal(out.identity_profile.has_unverified_domain, false);
  assert.equal(out.identity_profile.domain_stability, 'stable');
});

test('fixture 3a-B: cold handoff to unverified domain (8 acme + 1 new) → churning', () => {
  const rows = buildRows([['dev@acme.com', 8], ['newuser@somerandom.io', 1]]);
  const out = publisher.extract({ packageName: '3a-B', history: rows });

  assert.equal(out.tenure.length, 2);

  // acme.com has 8 versions → above MIN_VERIFIED_VERSIONS → verified-corporate
  assert.equal(out.tenure[0].domain, 'acme.com');
  assert.equal(out.tenure[0].provider, 'verified-corporate');
  assert.equal(out.tenure[0].first_seen_in_package_ms, rows[0].published_at_ms);

  // somerandom.io has 1 version → below threshold → unverified
  assert.equal(out.tenure[1].domain, 'somerandom.io');
  assert.equal(out.tenure[1].provider, 'unverified');
  assert.equal(out.tenure[1].first_seen_in_package_ms, rows[8].published_at_ms);

  // providers_seen is a unique sorted list
  assert.deepEqual(out.identity_profile.providers_seen, ['unverified', 'verified-corporate']);
  assert.equal(out.identity_profile.has_privacy_provider, false);
  assert.equal(out.identity_profile.has_unverified_domain, true);
  // somerandom.io is new-to-window (not in rows 0-3) → churning
  assert.equal(out.identity_profile.domain_stability, 'churning');
});

test('fixture 3a-C: axios-class privacy handoff (8 gmail + 1 protonmail) → churning', () => {
  const rows = buildRows([['jason@gmail.com', 8], ['ifstap@protonmail.me', 1]]);
  const out = publisher.extract({ packageName: '3a-C', history: rows });

  assert.equal(out.tenure.length, 2);

  assert.equal(out.tenure[0].domain, 'gmail.com');
  assert.equal(out.tenure[0].provider, 'free-webmail');

  // protonmail.me → privacy (precedence wins over unverified)
  assert.equal(out.tenure[1].domain, 'protonmail.me');
  assert.equal(out.tenure[1].provider, 'privacy');

  assert.deepEqual(out.identity_profile.providers_seen, ['free-webmail', 'privacy']);
  assert.equal(out.identity_profile.has_privacy_provider, true);
  // protonmail.me is privacy, NOT unverified (precedence)
  assert.equal(out.identity_profile.has_unverified_domain, false);
  assert.equal(out.identity_profile.domain_stability, 'churning');
});

test('fixture 3a-D: legitimate company switch (8 gmail + 1 new acme) → unverified on final', () => {
  // Maintainer moves from personal gmail to company acme — only ONE visible
  // version under the new corporate email. Below MIN_VERIFIED_VERSIONS →
  // unverified. The gate layer uses is_known_contributor + overlap to
  // keep this WARN, not BLOCK. Documents the "unverified alone is not
  // BLOCK" contract rule.
  const rows = buildRows([['dev@gmail.com', 8], ['dev@acme.com', 1]]);
  const out = publisher.extract({ packageName: '3a-D', history: rows });

  assert.equal(out.tenure.length, 2);
  assert.equal(out.tenure[0].provider, 'free-webmail');

  assert.equal(out.tenure[1].domain, 'acme.com');
  assert.equal(out.tenure[1].provider, 'unverified');

  assert.deepEqual(out.identity_profile.providers_seen, ['free-webmail', 'unverified']);
  assert.equal(out.identity_profile.has_privacy_provider, false);
  assert.equal(out.identity_profile.has_unverified_domain, true);
  assert.equal(out.identity_profile.domain_stability, 'churning');
});

test('fixture 3a-E: privacy-first solo (9 × protonmail) → privacy + stable, MUST NOT BLOCK', () => {
  // Legitimate maintainer who uses protonmail as their long-standing
  // publisher email. Single block, no cold handoff. Locks the
  // "privacy alone is not BLOCK" contract rule.
  const rows = buildRows([['maintainer@protonmail.com', 9]]);
  const out = publisher.extract({ packageName: '3a-E', history: rows });

  assert.equal(out.tenure.length, 1);
  assert.equal(out.tenure[0].domain, 'protonmail.com');
  assert.equal(out.tenure[0].provider, 'privacy');

  assert.deepEqual(out.identity_profile.providers_seen, ['privacy']);
  assert.equal(out.identity_profile.has_privacy_provider, true);
  assert.equal(out.identity_profile.has_unverified_domain, false);
  assert.equal(out.identity_profile.domain_stability, 'stable');
});

test('fixture 3a-F: bare-name identities (no emails) → all unknown, stable', () => {
  // 9 rows of publisher_name only — no email. normalizeIdentity returns
  // the bare name; domain extraction returns null; provider is 'unknown'.
  const startMs = 1_700_000_000_000;
  const rows = [];
  for (let i = 0; i < 9; i += 1) {
    rows.push({
      version: `1.0.${i}`,
      publisher_email: '',
      publisher_name: 'dev',
      published_at_ms: startMs + i * DAY_MS,
    });
  }
  const out = publisher.extract({ packageName: '3a-F', history: rows });

  assert.equal(out.tenure.length, 1);
  assert.equal(out.tenure[0].domain, null);
  assert.equal(out.tenure[0].provider, 'unknown');

  assert.deepEqual(out.identity_profile.providers_seen, ['unknown']);
  assert.equal(out.identity_profile.has_privacy_provider, false);
  assert.equal(out.identity_profile.has_unverified_domain, false);
  // Zero non-null domains → not churning; <=2 unique non-null domains → stable
  assert.equal(out.identity_profile.domain_stability, 'stable');
});

test('fixture 3a-G: malformed email in one row → unknown for that block, no crash', () => {
  // 8 clean acme rows + 1 row with publisher_email='not-an-email' (no @).
  // The malformed identity creates a separate block whose domain is null
  // and provider is 'unknown'. Other blocks classify normally.
  const rows = buildRows([['dev@acme.com', 8]]);
  const lastTs = rows[rows.length - 1].published_at_ms;
  rows.push({
    version: '1.0.8',
    publisher_email: 'not-an-email',
    publisher_name: 'bad',
    published_at_ms: lastTs + DAY_MS,
  });
  const out = publisher.extract({ packageName: '3a-G', history: rows });

  assert.equal(out.tenure.length, 2);

  assert.equal(out.tenure[0].domain, 'acme.com');
  assert.equal(out.tenure[0].provider, 'verified-corporate');

  assert.equal(out.tenure[1].domain, null);
  assert.equal(out.tenure[1].provider, 'unknown');

  assert.deepEqual(out.identity_profile.providers_seen, ['unknown', 'verified-corporate']);
  assert.equal(out.identity_profile.has_privacy_provider, false);
  // 'unknown' is NOT 'unverified'
  assert.equal(out.identity_profile.has_unverified_domain, false);
  // Final 5 rows: 4 × acme + 1 × null. acme appears in earlier rows; null
  // excluded from stability. No new-to-window domain → not churning.
  // Full history has 1 unique non-null domain → stable.
  assert.equal(out.identity_profile.domain_stability, 'stable');
});

test('fixture 3a-H: 3-domain committee rotating (a,b,c × 3) → all verified-corporate, mixed', () => {
  // Perfect rotation: each of 3 domains appears 3 times → each clears
  // MIN_VERIFIED_VERSIONS=2 → verified-corporate. Final 5 rows contain
  // domains that ALL appear in earlier rows (no new-to-window) → not
  // churning. Full history has 3 unique non-null domains → mixed.
  const rows = buildRows([
    ['dev@alpha.com', 1], ['dev@beta.com', 1], ['dev@gamma.com', 1],
    ['dev@alpha.com', 1], ['dev@beta.com', 1], ['dev@gamma.com', 1],
    ['dev@alpha.com', 1], ['dev@beta.com', 1], ['dev@gamma.com', 1],
  ]);
  const out = publisher.extract({ packageName: '3a-H', history: rows });

  assert.equal(out.tenure.length, 9);
  for (const block of out.tenure) {
    assert.equal(block.provider, 'verified-corporate');
  }

  assert.deepEqual(out.identity_profile.providers_seen, ['verified-corporate']);
  assert.equal(out.identity_profile.has_privacy_provider, false);
  assert.equal(out.identity_profile.has_unverified_domain, false);
  assert.equal(out.identity_profile.domain_stability, 'mixed');
});

test('fixture 3a-I: corporate domain reintroduction (acme×5, beta×3, acme×1) → both verified-corporate, churning', () => {
  // acme.com appears in 6 versions total (blocks 0 and 2) → verified-corporate
  // for BOTH acme.com blocks — the package-context rule recognizes the
  // domain by its total footprint, not by block identity.
  // beta.io has 3 versions → verified-corporate.
  // first_seen_in_package_ms is the same value for the two acme blocks.
  // Final 5 rows: [acme, beta, beta, beta, acme]. beta.io does NOT appear
  // in rows 0-3 (which are all acme) → new-to-window → churning.
  const rows = buildRows([
    ['dev1@acme.com', 5],
    ['dev2@beta.io', 3],
    ['dev1@acme.com', 1],
  ]);
  const out = publisher.extract({ packageName: '3a-I', history: rows });

  assert.equal(out.tenure.length, 3);

  assert.equal(out.tenure[0].domain, 'acme.com');
  assert.equal(out.tenure[0].provider, 'verified-corporate');
  assert.equal(out.tenure[0].first_seen_in_package_ms, rows[0].published_at_ms);

  assert.equal(out.tenure[1].domain, 'beta.io');
  assert.equal(out.tenure[1].provider, 'verified-corporate');
  assert.equal(out.tenure[1].first_seen_in_package_ms, rows[5].published_at_ms);

  // Reintroduced acme block carries the ORIGINAL first_seen_in_package_ms,
  // not the block's own first_published_at_ms. Key for the gate layer to
  // distinguish "never seen this domain before" from "known domain returns".
  assert.equal(out.tenure[2].domain, 'acme.com');
  assert.equal(out.tenure[2].provider, 'verified-corporate');
  assert.equal(out.tenure[2].first_seen_in_package_ms, rows[0].published_at_ms);

  assert.deepEqual(out.identity_profile.providers_seen, ['verified-corporate']);
  assert.equal(out.identity_profile.has_privacy_provider, false);
  assert.equal(out.identity_profile.has_unverified_domain, false);
  assert.equal(out.identity_profile.domain_stability, 'churning');
});

test('fixture 3a-J: canonical attacker shape (acme×8 + protonmail×1) → privacy + churning, BLOCK candidate', () => {
  // Combined signals fire in the same direction: cold-handoff cell (from
  // the 2×2 matrix), high prior_tenure (8 verified-corporate versions),
  // privacy provider on the to-identity, churning stability. This is the
  // axios-class fixture for the 3a provider signals — the gate reads
  // every provider-derived flag lit up alongside the overlap/known
  // matrix to land at BLOCK.
  const rows = buildRows([['dev@acme.com', 8], ['ifstap@protonmail.me', 1]]);
  const out = publisher.extract({ packageName: '3a-J', history: rows });

  assert.equal(out.tenure.length, 2);
  assert.equal(out.tenure[0].provider, 'verified-corporate');
  assert.equal(out.tenure[1].provider, 'privacy');

  assert.deepEqual(out.identity_profile.providers_seen, ['privacy', 'verified-corporate']);
  assert.equal(out.identity_profile.has_privacy_provider, true);
  // protonmail.me is privacy (precedence), NOT unverified
  assert.equal(out.identity_profile.has_unverified_domain, false);
  assert.equal(out.identity_profile.domain_stability, 'churning');
});

test('identity_profile: determinism — re-extraction produces byte-identical output', () => {
  const rows = buildRows([
    ['dev1@acme.com', 5],
    ['dev2@beta.io', 3],
    ['dev1@acme.com', 1],
  ]);
  const input = { packageName: 'det-3a-1', history: rows };
  const a = publisher.extract(input);
  const b = publisher.extract(input);

  assert.equal(JSON.stringify(a.identity_profile), JSON.stringify(b.identity_profile));
  assert.equal(a.tenure.length, b.tenure.length);
  for (let i = 0; i < a.tenure.length; i += 1) {
    assert.equal(a.tenure[i].domain, b.tenure[i].domain);
    assert.equal(a.tenure[i].provider, b.tenure[i].provider);
    assert.equal(a.tenure[i].first_seen_in_package_ms, b.tenure[i].first_seen_in_package_ms);
  }
});

test('identity_profile: determinism — shuffled input produces identical output after sort', () => {
  const rows = buildRows([
    ['dev1@acme.com', 5],
    ['dev2@beta.io', 3],
    ['dev1@acme.com', 1],
  ]);
  const reversed = [...rows].reverse();

  const forward = publisher.extract({ packageName: 'det-3a-2', history: rows });
  const reverse = publisher.extract({ packageName: 'det-3a-2', history: reversed });

  assert.deepEqual(forward.identity_profile, reverse.identity_profile);
  assert.equal(
    JSON.stringify(forward.tenure.map((t) => ({
      domain: t.domain,
      provider: t.provider,
      first_seen_in_package_ms: t.first_seen_in_package_ms,
    }))),
    JSON.stringify(reverse.tenure.map((t) => ({
      domain: t.domain,
      provider: t.provider,
      first_seen_in_package_ms: t.first_seen_in_package_ms,
    }))),
  );
});
