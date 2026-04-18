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
