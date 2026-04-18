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
  assert.equal(out.signals.max_prior_tenure, 0);
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
