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
  // No synthetic transitions emitted on null boundaries in sub-step 2a.
  assert.equal(out.signals.transition_count, 0);
  assert.equal(out.transitions.length, 0);
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
