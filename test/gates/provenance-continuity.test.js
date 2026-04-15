import { test } from 'node:test';
import assert from 'node:assert/strict';

import provenanceContinuity from '../../gates/provenance-continuity.js';

function run({ history = [], incoming, version = '1.7.9' }) {
  return provenanceContinuity.evaluate({
    ecosystem: 'npm',
    packageName: 'axios',
    version,
    incoming,
    baseline: null,
    history,
    config: {},
  });
}

function v(version, provenance_present, extra = {}) {
  return { version, provenance_present, ...extra };
}

test('empty history → SKIP', () => {
  const r = run({ history: [], incoming: v('1.7.9', 1) });
  assert.equal(r.gate, 'provenance-continuity');
  assert.equal(r.result, 'SKIP');
  assert.match(r.detail, /no prior versions/);
});

test('history contains only the current version → SKIP', () => {
  const r = run({
    history: [v('1.7.9', 1)],
    incoming: v('1.7.9', 1),
  });
  assert.equal(r.result, 'SKIP');
});

test('no prior version ever had provenance → SKIP (not a regression)', () => {
  const r = run({
    history: [v('1.7.8', 0), v('1.7.7', 0), v('1.7.6', 0)],
    incoming: v('1.7.9', 0),
  });
  assert.equal(r.result, 'SKIP');
  assert.match(r.detail, /never used OIDC/);
});

test('prior versions had provenance AND incoming has provenance → ALLOW', () => {
  const r = run({
    history: [v('1.7.8', 1), v('1.7.7', 1)],
    incoming: v('1.7.9', 1),
  });
  assert.equal(r.result, 'ALLOW');
  assert.match(r.detail, /OIDC provenance present/);
  assert.match(r.detail, /2\/2 prior/);
});

test('all prior versions had provenance, incoming drops it → WARN with count', () => {
  const r = run({
    history: [v('1.7.8', 1), v('1.7.7', 1), v('1.7.6', 1), v('1.7.5', 1)],
    incoming: v('1.7.9', 0),
  });
  assert.equal(r.result, 'WARN');
  assert.match(r.detail, /provenance missing/);
  assert.match(r.detail, /4 of last 4/);
  assert.match(r.detail, /latest: 1\.7\.8/);
});

test('only some prior versions had provenance, incoming drops it → still WARN', () => {
  // 4 of 10 had provenance → regression is real; aggregation (+ other
  // gates) decides whether to escalate
  const history = [
    v('1.7.8', 1), v('1.7.7', 1), v('1.7.6', 0), v('1.7.5', 1),
    v('1.7.4', 0), v('1.7.3', 1), v('1.7.2', 0), v('1.7.1', 0),
    v('1.7.0', 0), v('1.6.0', 0),
  ];
  const r = run({ history, incoming: v('1.7.9', 0) });
  assert.equal(r.result, 'WARN');
  assert.match(r.detail, /4 of last 10/);
});

test('provenance_present accepts 1 and true interchangeably', () => {
  const r = run({
    history: [v('1.7.8', true)],
    incoming: v('1.7.9', 1),
  });
  assert.equal(r.result, 'ALLOW');
});

test('provenance_present missing (null/undefined) counts as absent', () => {
  const r = run({
    history: [v('1.7.8', 1)],
    incoming: { version: '1.7.9' }, // no provenance_present field
  });
  assert.equal(r.result, 'WARN');
});

test('incoming restores provenance after a dropout in prior → ALLOW', () => {
  // 1.7.8 had a dropout; 1.7.9 picks it back up. That's recovery, not regression.
  const r = run({
    history: [v('1.7.8', 0), v('1.7.7', 1)],
    incoming: v('1.7.9', 1),
  });
  assert.equal(r.result, 'ALLOW');
});

test('re-observation: self-entry in history filtered out', () => {
  const r = run({
    version: '1.7.9',
    history: [v('1.7.9', 0), v('1.7.8', 1)],
    incoming: v('1.7.9', 0),
  });
  assert.equal(r.result, 'WARN');
  assert.match(r.detail, /1 of last 1/);
});

test('deterministic: same input twice → byte-identical detail', () => {
  const input = {
    history: [v('1.7.8', 1), v('1.7.7', 1)],
    incoming: v('1.7.9', 0),
  };
  assert.equal(run(input).detail, run(input).detail);
});

test('gate name is always provenance-continuity', () => {
  assert.equal(run({ incoming: v('1.7.9', 1) }).gate, 'provenance-continuity');
  assert.equal(
    run({ history: [v('1.7.8', 1)], incoming: v('1.7.9', 0) }).gate,
    'provenance-continuity',
  );
});
