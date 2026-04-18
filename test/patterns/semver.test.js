import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parseSemver, compareSemver } from '../../patterns/semver.js';

test('parseSemver: basic major.minor.patch', () => {
  assert.deepEqual(parseSemver('1.2.3'), { major: 1, minor: 2, patch: 3, prerelease: null });
});

test('parseSemver: prerelease', () => {
  assert.deepEqual(parseSemver('1.2.3-beta'), {
    major: 1, minor: 2, patch: 3, prerelease: 'beta',
  });
  assert.deepEqual(parseSemver('1.2.3-beta.1'), {
    major: 1, minor: 2, patch: 3, prerelease: 'beta.1',
  });
});

test('parseSemver: prerelease + build metadata (build is discarded)', () => {
  assert.deepEqual(parseSemver('1.2.3-alpha.4+build.5'), {
    major: 1, minor: 2, patch: 3, prerelease: 'alpha.4',
  });
});

test('parseSemver: whitespace tolerated', () => {
  assert.deepEqual(parseSemver('  1.2.3  '), { major: 1, minor: 2, patch: 3, prerelease: null });
});

test('parseSemver: invalid returns null', () => {
  assert.equal(parseSemver('not-a-version'), null);
  assert.equal(parseSemver(''), null);
  assert.equal(parseSemver('1.2'), null);
  assert.equal(parseSemver('1.2.3.4'), null);
  assert.equal(parseSemver(null), null);
  assert.equal(parseSemver(undefined), null);
  assert.equal(parseSemver(123), null);
});

test('compareSemver: major takes precedence', () => {
  assert.equal(compareSemver('1.0.0', '2.0.0'), -1);
  assert.equal(compareSemver('2.0.0', '1.0.0'), 1);
});

test('compareSemver: numeric minor — not string', () => {
  // The tricky case: lexical sort would put "10" before "2".
  assert.equal(compareSemver('1.10.0', '1.2.0'), 1);
  assert.equal(compareSemver('1.2.0', '1.10.0'), -1);
});

test('compareSemver: patch ordering', () => {
  assert.equal(compareSemver('1.0.0', '1.0.1'), -1);
  assert.equal(compareSemver('1.0.2', '1.0.1'), 1);
  assert.equal(compareSemver('1.0.0', '1.0.0'), 0);
});

test('compareSemver: prerelease has LOWER precedence than release', () => {
  assert.equal(compareSemver('1.0.0-alpha', '1.0.0'), -1);
  assert.equal(compareSemver('1.0.0', '1.0.0-alpha'), 1);
});

test('compareSemver: prerelease numeric identifiers compare numerically', () => {
  assert.equal(compareSemver('1.0.0-alpha.2', '1.0.0-alpha.10'), -1);
  assert.equal(compareSemver('1.0.0-alpha.10', '1.0.0-alpha.2'), 1);
});

test('compareSemver: prerelease — numeric identifier < non-numeric', () => {
  assert.equal(compareSemver('1.0.0-1', '1.0.0-alpha'), -1);
  assert.equal(compareSemver('1.0.0-alpha', '1.0.0-1'), 1);
});

test('compareSemver: prerelease — longer identifier list wins if prior equal', () => {
  assert.equal(compareSemver('1.0.0-alpha', '1.0.0-alpha.1'), -1);
  assert.equal(compareSemver('1.0.0-alpha.1', '1.0.0-alpha'), 1);
});

test('compareSemver: full semver §11 ordering chain', () => {
  // From semver.org §11.4: 1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta
  //   < 1.0.0-beta < 1.0.0-beta.2 < 1.0.0-beta.11 < 1.0.0-rc.1 < 1.0.0
  const chain = [
    '1.0.0-alpha',
    '1.0.0-alpha.1',
    '1.0.0-alpha.beta',
    '1.0.0-beta',
    '1.0.0-beta.2',
    '1.0.0-beta.11',
    '1.0.0-rc.1',
    '1.0.0',
  ];
  for (let i = 0; i < chain.length - 1; i += 1) {
    assert.equal(
      compareSemver(chain[i], chain[i + 1]),
      -1,
      `${chain[i]} should be < ${chain[i + 1]}`,
    );
  }
});

test('compareSemver: falls back to string comparison on unparseable input', () => {
  assert.equal(compareSemver('foo', 'bar'), 1);    // 'foo' > 'bar' lexically
  assert.equal(compareSemver('bar', 'foo'), -1);
  assert.equal(compareSemver('foo', 'foo'), 0);
  // Even one-sided unparseable triggers the fallback
  assert.equal(compareSemver('1.0.0', 'garbage'), -1); // '1.0.0' < 'garbage' lexically
});

test('compareSemver: determinism — antisymmetric', () => {
  const pairs = [
    ['1.2.3', '1.2.4'],
    ['1.0.0-alpha', '1.0.0'],
    ['0.0.1', '1.0.0'],
    ['foo', '1.0.0'],
  ];
  for (const [a, b] of pairs) {
    const ab = compareSemver(a, b);
    const ba = compareSemver(b, a);
    assert.equal(ab, -ba, `compareSemver(${a}, ${b}) and compareSemver(${b}, ${a}) must be opposite`);
  }
});
