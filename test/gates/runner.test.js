import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createGateRunner, DEFAULT_GATE_MODULES } from '../../gates/index.js';

function input(overrides = {}) {
  return {
    ecosystem: 'npm',
    packageName: 'axios',
    version: '1.7.9',
    incoming: {},
    baseline: null,
    history: [],
    config: {},
    ...overrides,
  };
}

const mod = (name, result, detail = '') => ({
  name,
  evaluate: () => ({ gate: name, result, detail }),
});

const silentLogger = { info() {}, warn() {}, error() {} };

test('zero modules, no override → ALLOW', () => {
  const run = createGateRunner({ modules: [], logger: silentLogger });
  const out = run(input());
  assert.equal(out.disposition, 'ALLOW');
  assert.deepEqual(out.results, []);
  assert.equal(out.override, null);
});

test('DEFAULT_GATE_MODULES contains P5.6 gates (content-hash, dep-structure, publisher-identity)', () => {
  const names = DEFAULT_GATE_MODULES.map((m) => m.name);
  assert.ok(names.includes('content-hash'));
  assert.ok(names.includes('dep-structure'));
  assert.ok(names.includes('publisher-identity'));
});

test('one ALLOW module → ALLOW', () => {
  const run = createGateRunner({ modules: [mod('g1', 'ALLOW')], logger: silentLogger });
  const out = run(input());
  assert.equal(out.disposition, 'ALLOW');
  assert.equal(out.results.length, 1);
  assert.equal(out.results[0].gate, 'g1');
});

test('one BLOCK module → BLOCK', () => {
  const run = createGateRunner({ modules: [mod('g1', 'BLOCK', 'bad')], logger: silentLogger });
  assert.equal(run(input()).disposition, 'BLOCK');
});

test('one WARN module → WARN (below threshold 4)', () => {
  const run = createGateRunner({ modules: [mod('g1', 'WARN')], logger: silentLogger });
  assert.equal(run(input()).disposition, 'WARN');
});

test('4 WARN modules → BLOCK (escalated at default threshold)', () => {
  const run = createGateRunner({
    modules: [mod('a', 'WARN'), mod('b', 'WARN'), mod('c', 'WARN'), mod('d', 'WARN')],
    logger: silentLogger,
  });
  assert.equal(run(input()).disposition, 'BLOCK');
});

test('3 WARN modules → WARN (still below threshold 4)', () => {
  const run = createGateRunner({
    modules: [mod('a', 'WARN'), mod('b', 'WARN'), mod('c', 'WARN')],
    logger: silentLogger,
  });
  assert.equal(run(input()).disposition, 'WARN');
});

test('1 BLOCK + 10 WARN → BLOCK (any block wins)', () => {
  const mods = [mod('block', 'BLOCK')];
  for (let i = 0; i < 10; i += 1) mods.push(mod(`w${i}`, 'WARN'));
  const run = createGateRunner({ modules: mods, logger: silentLogger });
  assert.equal(run(input()).disposition, 'BLOCK');
});

test('SKIP does not count toward warns', () => {
  const run = createGateRunner({
    modules: [mod('a', 'SKIP'), mod('b', 'SKIP'), mod('c', 'SKIP'), mod('d', 'SKIP'), mod('e', 'SKIP')],
    logger: silentLogger,
  });
  assert.equal(run(input()).disposition, 'ALLOW');
});

test('override present → short-circuits, modules NOT called', () => {
  let calls = 0;
  const mods = [
    { name: 'should-not-run', evaluate: () => { calls += 1; return { result: 'BLOCK', detail: 'x' }; } },
  ];
  const getOverride = () => ({ reason: 'legit mirror', created_at: '2026-04-15T00:00:00Z' });
  const run = createGateRunner({ modules: mods, getOverride, logger: silentLogger });
  const out = run(input());
  assert.equal(calls, 0);
  assert.equal(out.disposition, 'ALLOW');
  assert.equal(out.results.length, 1);
  assert.equal(out.results[0].gate, 'override');
  assert.equal(out.results[0].result, 'ALLOW');
  assert.match(out.results[0].detail, /override: legit mirror/);
  assert.equal(out.override.reason, 'legit mirror');
});

test('override + BLOCK-ing modules → still ALLOW', () => {
  const getOverride = () => ({ reason: 'approved' });
  const run = createGateRunner({
    modules: [mod('block', 'BLOCK', 'would block')],
    getOverride,
    logger: silentLogger,
  });
  assert.equal(run(input()).disposition, 'ALLOW');
});

test('module throws → caught as SKIP with gate_error detail', () => {
  const mods = [
    { name: 'boom', evaluate: () => { throw new Error('kaboom'); } },
    mod('after', 'ALLOW'),
  ];
  const run = createGateRunner({ modules: mods, logger: silentLogger });
  const out = run(input());
  assert.equal(out.disposition, 'ALLOW');
  assert.equal(out.results.length, 2);
  assert.equal(out.results[0].gate, 'boom');
  assert.equal(out.results[0].result, 'SKIP');
  assert.match(out.results[0].detail, /^gate_error: kaboom$/);
});

test('module returns malformed output → SKIP with malformed detail', () => {
  const mods = [
    { name: 'junk', evaluate: () => null },
    { name: 'junk2', evaluate: () => ({ result: 'INVALID' }) },
    { name: 'junk3', evaluate: () => 'string' },
  ];
  const run = createGateRunner({ modules: mods, logger: silentLogger });
  const out = run(input());
  assert.equal(out.disposition, 'ALLOW');
  for (const r of out.results) {
    assert.equal(r.result, 'SKIP');
    assert.match(r.detail, /malformed/);
  }
});

test('result ordering preserves module insertion order', () => {
  const run = createGateRunner({
    modules: [mod('first', 'ALLOW'), mod('second', 'WARN'), mod('third', 'ALLOW')],
    logger: silentLogger,
  });
  const out = run(input());
  assert.deepEqual(out.results.map((r) => r.gate), ['first', 'second', 'third']);
});

test('config.warnEscalationThreshold overrides default', () => {
  const run = createGateRunner({
    modules: [mod('a', 'WARN'), mod('b', 'WARN')],
    logger: silentLogger,
  });
  assert.equal(run(input({ config: { warnEscalationThreshold: 2 } })).disposition, 'BLOCK');
  assert.equal(run(input({ config: { warnEscalationThreshold: 3 } })).disposition, 'WARN');
});

test('getOverride not provided → runner works, never short-circuits', () => {
  const run = createGateRunner({ modules: [mod('a', 'BLOCK')], logger: silentLogger });
  assert.equal(run(input()).disposition, 'BLOCK');
});

test('getOverride throws → caught, gates still run', () => {
  const getOverride = () => { throw new Error('db down'); };
  const run = createGateRunner({
    modules: [mod('a', 'ALLOW')],
    getOverride,
    logger: silentLogger,
  });
  const out = run(input());
  assert.equal(out.disposition, 'ALLOW');
  assert.equal(out.results.length, 1);
});

test('createGateRunner: non-array modules → throws', () => {
  assert.throws(() => createGateRunner({ modules: 'nope' }), /modules must be an array/);
});
