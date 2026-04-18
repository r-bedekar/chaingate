import { test } from 'node:test';
import assert from 'node:assert/strict';

import publisher from '../../patterns/publisher.js';
import { PATTERN_REGISTRY, validatePattern } from '../../patterns/index.js';

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
  // Byte-identity via JSON — catches any non-deterministic key order
  // or hidden non-serializable values in the output.
  assert.equal(JSON.stringify(a), JSON.stringify(b));
});

test('publisher: extract() output matches the locked contract shape', () => {
  const out = publisher.extract({ packageName: 'axios', history: [] });
  assert.ok(Array.isArray(out.tenure), 'tenure must be an array');
  assert.ok(Array.isArray(out.transitions), 'transitions must be an array');
  assert.equal(typeof out.identity_profile, 'object', 'identity_profile must be an object');
  assert.ok(out.identity_profile !== null, 'identity_profile must be non-null');
  assert.equal(typeof out.shape, 'string', 'shape must be a string');
  assert.equal(typeof out.signals, 'object', 'signals must be an object');
  assert.ok(out.signals !== null, 'signals must be non-null');
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
