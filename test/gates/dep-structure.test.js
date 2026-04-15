import { test } from 'node:test';
import assert from 'node:assert/strict';

import depStructure from '../../gates/dep-structure.js';

function run({ history = [], incoming, version = '1.7.9' }) {
  return depStructure.evaluate({
    ecosystem: 'npm',
    packageName: 'axios',
    version,
    incoming,
    baseline: history.find((h) => h.version === version) ?? null,
    history,
    config: {},
  });
}

function v(version, dependencies, extra = {}) {
  return { version, dependencies, ...extra };
}

test('empty history → SKIP first-seen', () => {
  const r = run({ history: [], incoming: v('1.7.9', { 'follow-redirects': '^1.15.6' }) });
  assert.equal(r.gate, 'dep-structure');
  assert.equal(r.result, 'SKIP');
  assert.match(r.detail, /no prior versions/);
});

test('history has only current version → SKIP (re-observation first-seen)', () => {
  const r = run({
    history: [v('1.7.9', { a: '1.0.0' })],
    incoming: v('1.7.9', { a: '1.0.0' }),
  });
  assert.equal(r.result, 'SKIP');
});

test('incoming has no dependencies field → ALLOW', () => {
  const r = run({
    history: [v('1.7.8', { a: '1.0.0' })],
    incoming: v('1.7.9', undefined),
  });
  assert.equal(r.result, 'ALLOW');
  assert.match(r.detail, /no runtime dependencies/);
});

test('incoming has empty dependencies object → ALLOW', () => {
  const r = run({
    history: [v('1.7.8', { a: '1.0.0' })],
    incoming: v('1.7.9', {}),
  });
  assert.equal(r.result, 'ALLOW');
});

test('all incoming deps present in prior → ALLOW with stable count', () => {
  const r = run({
    history: [v('1.7.8', { a: '1.0.0', b: '1.0.0' })],
    incoming: v('1.7.9', { a: '1.0.1', b: '1.0.1' }),
  });
  assert.equal(r.result, 'ALLOW');
  assert.match(r.detail, /2 runtime dep/);
});

test('version bump-only on existing dep → ALLOW (not a new name)', () => {
  const r = run({
    history: [v('1.7.8', { 'follow-redirects': '^1.15.6' })],
    incoming: v('1.7.9', { 'follow-redirects': '^1.16.0' }),
  });
  assert.equal(r.result, 'ALLOW');
});

test('one new dep → WARN with the dep name in detail', () => {
  const r = run({
    history: [v('1.7.8', { 'follow-redirects': '^1.15.6' })],
    incoming: v('1.7.9', { 'follow-redirects': '^1.15.6', 'plain-crypto-js': '^1.0.0' }),
  });
  assert.equal(r.result, 'WARN');
  assert.match(r.detail, /plain-crypto-js/);
  assert.match(r.detail, /not in prior 1 version/);
});

test('multiple new deps → WARN with alphabetized names', () => {
  const r = run({
    history: [v('1.7.8', { a: '1.0.0' })],
    incoming: v('1.7.9', { a: '1.0.0', zebra: '1.0.0', banana: '1.0.0', mango: '1.0.0' }),
  });
  assert.equal(r.result, 'WARN');
  // Alphabetical: banana, mango, zebra
  assert.match(r.detail, /banana.*mango.*zebra/);
});

test('dep known in older version (removed then stays gone) → still ALLOW when reappearing', () => {
  // legitimate re-adoption of an old dep should not fire
  const r = run({
    version: '1.8.0',
    history: [
      v('1.7.9', { a: '1.0.0' }), // removed b
      v('1.6.0', { a: '1.0.0', b: '1.0.0' }), // had b
    ],
    incoming: v('1.8.0', { a: '1.0.0', b: '1.0.0' }),
  });
  assert.equal(r.result, 'ALLOW');
});

test('dev/peer/optional dep additions → ignored, ALLOW', () => {
  const r = run({
    history: [v('1.7.8', { a: '1.0.0' })],
    incoming: {
      version: '1.7.9',
      dependencies: { a: '1.0.0' },
      dev_dependencies: { mocha: '^10.2.0' },
      peer_dependencies: { react: '^18.0.0' },
      optional_dependencies: { fsevents: '^2.3.0' },
    },
  });
  assert.equal(r.result, 'ALLOW');
});

test('re-observation: incoming version filtered from history, prior delta surfaces', () => {
  const r = run({
    version: '1.7.9',
    history: [
      v('1.7.9', { a: '1.0.0', malicious: '1.0.0' }),
      v('1.7.8', { a: '1.0.0' }),
    ],
    incoming: v('1.7.9', { a: '1.0.0', malicious: '1.0.0' }),
  });
  assert.equal(r.result, 'WARN');
  assert.match(r.detail, /malicious/);
});

test('MAX_DEPS_DISPLAYED truncates long new-dep lists with "+N more"', () => {
  const deps = {};
  for (const ch of 'abcdefghij') deps[ch] = '1.0.0';
  const r = run({
    history: [v('1.7.8', {})],
    incoming: v('1.7.9', deps),
  });
  assert.equal(r.result, 'WARN');
  assert.match(r.detail, /\+5 more/);
});

test('dependencies is null (malformed) → ALLOW (treat as absent)', () => {
  const r = run({
    history: [v('1.7.8', { a: '1.0.0' })],
    incoming: v('1.7.9', null),
  });
  assert.equal(r.result, 'ALLOW');
});

test('deterministic: same input twice → byte-identical detail', () => {
  const input = {
    history: [v('1.7.8', { a: '1.0.0' })],
    incoming: v('1.7.9', { a: '1.0.0', z: '1.0.0', b: '1.0.0' }),
  };
  assert.equal(run(input).detail, run(input).detail);
});

test('gate name is always dep-structure', () => {
  assert.equal(run({ incoming: v('1.7.9', {}) }).gate, 'dep-structure');
});
