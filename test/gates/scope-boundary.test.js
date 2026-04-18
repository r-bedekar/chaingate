import { test } from 'node:test';
import assert from 'node:assert/strict';

import scopeBoundary from '../../gates/scope-boundary.js';

const FIXED_NOW = Date.parse('2026-04-15T12:00:00.000Z');

function hoursAgo(h) {
  return new Date(FIXED_NOW - h * 60 * 60 * 1000).toISOString();
}

function v(version, deps, extra = {}) {
  return { version, dependencies: deps, ...extra };
}

function makeServices({ cache = {}, enqueued = [] } = {}) {
  return {
    lookupDepFirstPublish(name) {
      const entry = cache[name];
      if (!entry) return { hit: false };
      return { hit: true, status: entry.status ?? 'ok', first_publish: entry.first_publish ?? null };
    },
    enqueueDepLookup(name) {
      enqueued.push(name);
      return true;
    },
    _enqueued: enqueued,
  };
}

function run({
  version = '1.7.9',
  packageName = 'axios',
  history = [],
  incoming,
  services = {},
}) {
  return scopeBoundary.evaluate({
    ecosystem: 'npm',
    packageName,
    version,
    incoming,
    baseline: null,
    history,
    config: { _nowMs: FIXED_NOW },
    services,
  });
}

test('empty history → SKIP', () => {
  const r = run({ incoming: v('1.7.9', { a: '1.0.0' }, { has_install_scripts: 1 }) });
  assert.equal(r.gate, 'scope-boundary');
  assert.equal(r.result, 'SKIP');
});

test('no new deps → ALLOW', () => {
  const r = run({
    history: [v('1.7.8', { a: '1.0.0' })],
    incoming: v('1.7.9', { a: '1.0.0' }, { has_install_scripts: 1 }),
  });
  assert.equal(r.result, 'ALLOW');
  assert.match(r.detail, /no new runtime dependencies/);
});

test('new dep + NO install scripts → ALLOW (low risk)', () => {
  const r = run({
    history: [v('1.7.8', { a: '1.0.0' })],
    incoming: v('1.7.9', { a: '1.0.0', b: '1.0.0' }, { has_install_scripts: 0 }),
  });
  assert.equal(r.result, 'ALLOW');
  assert.match(r.detail, /no install scripts/);
});

test('new dep + install scripts, no lookup service → WARN with note', () => {
  const r = run({
    history: [v('1.7.8', { a: '1.0.0' })],
    incoming: v('1.7.9', { a: '1.0.0', 'bad-dep': '1.0.0' }, { has_install_scripts: 1 }),
  });
  assert.equal(r.result, 'WARN');
  assert.match(r.detail, /bad-dep/);
  assert.match(r.detail, /dep-age check unavailable/);
});

test('new dep + install scripts + cold cache → WARN + enqueues lookup', () => {
  const svc = makeServices();
  const r = run({
    history: [v('1.7.8', { a: '1.0.0' })],
    incoming: v('1.7.9', { a: '1.0.0', 'bad-dep': '1.0.0' }, { has_install_scripts: 1 }),
    services: svc,
  });
  assert.equal(r.result, 'WARN');
  assert.deepEqual(svc._enqueued, ['bad-dep']);
});

test('new dep + install scripts + warm cache, dep age > 24h → WARN', () => {
  const svc = makeServices({
    cache: { 'old-dep': { status: 'ok', first_publish: hoursAgo(48) } },
  });
  const r = run({
    history: [v('1.7.8', { a: '1.0.0' })],
    incoming: v('1.7.9', { a: '1.0.0', 'old-dep': '1.0.0' }, { has_install_scripts: 1 }),
    services: svc,
  });
  assert.equal(r.result, 'WARN');
  assert.match(r.detail, /none freshly published/);
});

test('new dep + install scripts + warm cache, dep age < 24h → WARN (V2-demoted from BLOCK)', () => {
  const svc = makeServices({
    cache: { 'plain-crypto-js': { status: 'ok', first_publish: hoursAgo(3) } },
  });
  const r = run({
    history: [v('1.7.8', { a: '1.0.0' })],
    incoming: v('1.7.9', { a: '1.0.0', 'plain-crypto-js': '1.0.0' }, { has_install_scripts: 1 }),
    services: svc,
  });
  assert.equal(r.result, 'WARN');
  assert.match(r.detail, /plain-crypto-js/);
  assert.match(r.detail, /3h ago/);
  assert.match(r.detail, /install scripts/);
  assert.match(r.detail, /axios@1\.7\.9/);
});

test('new dep at exactly 24h → NOT BLOCK (boundary exclusive)', () => {
  const svc = makeServices({
    cache: { 'edge-dep': { status: 'ok', first_publish: hoursAgo(24) } },
  });
  const r = run({
    history: [v('1.7.8', {})],
    incoming: v('1.7.9', { 'edge-dep': '1.0.0' }, { has_install_scripts: 1 }),
    services: svc,
  });
  assert.equal(r.result, 'WARN');
});

test('multiple new deps, one fresh → WARN names the fresh one (V2-demoted from BLOCK)', () => {
  const svc = makeServices({
    cache: {
      'old-dep': { status: 'ok', first_publish: hoursAgo(200) },
      'fresh-dep': { status: 'ok', first_publish: hoursAgo(2) },
    },
  });
  const r = run({
    history: [v('1.7.8', {})],
    incoming: v('1.7.9', { 'old-dep': '1.0.0', 'fresh-dep': '1.0.0' }, { has_install_scripts: 1 }),
    services: svc,
  });
  assert.equal(r.result, 'WARN');
  assert.match(r.detail, /fresh-dep/);
});

test('vanished dep does NOT escalate → WARN', () => {
  const svc = makeServices({
    cache: { 'gone-dep': { status: 'vanished', first_publish: null } },
  });
  const r = run({
    history: [v('1.7.8', {})],
    incoming: v('1.7.9', { 'gone-dep': '1.0.0' }, { has_install_scripts: 1 }),
    services: svc,
  });
  assert.equal(r.result, 'WARN');
});

test('error-status dep does NOT escalate → WARN', () => {
  const svc = makeServices({
    cache: { 'flaky-dep': { status: 'error', first_publish: null } },
  });
  const r = run({
    history: [v('1.7.8', {})],
    incoming: v('1.7.9', { 'flaky-dep': '1.0.0' }, { has_install_scripts: 1 }),
    services: svc,
  });
  assert.equal(r.result, 'WARN');
});

test('self-loop guard: dep name equals current package → skip that dep', () => {
  // Pathological packument that lists itself as a dep. Don't enqueue
  // ourselves and don't escalate on ourselves.
  const svc = makeServices({
    cache: { 'fresh-dep': { status: 'ok', first_publish: hoursAgo(1) } },
  });
  const r = run({
    packageName: 'fresh-dep',
    version: '1.0.0',
    history: [v('0.9.0', {})],
    incoming: v('1.0.0', { 'fresh-dep': '1.0.0', 'other': '1.0.0' }, { has_install_scripts: 1 }),
    services: svc,
  });
  // 'fresh-dep' self-skipped; 'other' cold → WARN
  assert.equal(r.result, 'WARN');
  // Ensure self was not enqueued
  assert.ok(!svc._enqueued.includes('fresh-dep'));
  assert.ok(svc._enqueued.includes('other'));
});

test('re-observation: history includes current version → filtered out', () => {
  const svc = makeServices();
  const r = run({
    version: '1.7.9',
    history: [
      v('1.7.9', { a: '1.0.0', 'new-dep': '1.0.0' }, { has_install_scripts: 1 }),
      v('1.7.8', { a: '1.0.0' }),
    ],
    incoming: v('1.7.9', { a: '1.0.0', 'new-dep': '1.0.0' }, { has_install_scripts: 1 }),
    services: svc,
  });
  // Self-entry filtered; 'new-dep' is genuinely novel vs 1.7.8
  assert.equal(r.result, 'WARN');
});

test('has_install_scripts=true (boolean) accepted', () => {
  const r = run({
    history: [v('1.7.8', {})],
    incoming: v('1.7.9', { x: '1.0.0' }, { has_install_scripts: true }),
  });
  assert.equal(r.result, 'WARN');
});

test('deterministic: same input twice → byte-identical detail', () => {
  const input = {
    history: [v('1.7.8', {})],
    incoming: v('1.7.9', { a: '1.0.0' }, { has_install_scripts: 1 }),
  };
  assert.equal(run(input).detail, run(input).detail);
});

test('gate name is always scope-boundary', () => {
  assert.equal(run({ incoming: v('1.7.9', {}) }).gate, 'scope-boundary');
});
