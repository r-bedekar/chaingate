import { test } from 'node:test';
import assert from 'node:assert/strict';

import publisherIdentity from '../../gates/publisher-identity.js';

function run({ history = [], incoming, version = '1.7.9' }) {
  return publisherIdentity.evaluate({
    ecosystem: 'npm',
    packageName: 'axios',
    version,
    incoming,
    baseline: history.find((h) => h.version === version) ?? null,
    history,
    config: {},
  });
}

const alice = 'alice@example.com';
const bob = 'bob@example.com';

function v(version, email, extra = {}) {
  return { version, publisher_email: email, publisher_name: email?.split('@')[0] ?? null, ...extra };
}

test('empty history → SKIP first-seen', () => {
  const r = run({ history: [], incoming: v('1.7.9', alice) });
  assert.equal(r.gate, 'publisher-identity');
  assert.equal(r.result, 'SKIP');
  assert.match(r.detail, /no prior versions/);
});

test('history contains only the current version → SKIP', () => {
  const r = run({
    history: [v('1.7.9', alice)],
    incoming: v('1.7.9', alice),
  });
  assert.equal(r.result, 'SKIP');
});

test('prior publisher email null → SKIP (data gap)', () => {
  const r = run({
    history: [v('1.7.8', null)],
    incoming: v('1.7.9', alice),
  });
  assert.equal(r.result, 'SKIP');
  assert.match(r.detail, /prior version has no publisher email/);
});

test('incoming publisher email null → SKIP (data gap)', () => {
  const r = run({
    history: [v('1.7.8', alice)],
    incoming: v('1.7.9', null),
  });
  assert.equal(r.result, 'SKIP');
  assert.match(r.detail, /incoming version has no publisher email/);
});

test('same publisher → ALLOW', () => {
  const r = run({
    history: [v('1.7.8', alice)],
    incoming: v('1.7.9', alice),
  });
  assert.equal(r.result, 'ALLOW');
  assert.match(r.detail, /publisher unchanged/);
  assert.match(r.detail, /alice@example\.com/);
});

test('case-insensitive match → ALLOW (no spurious WARN)', () => {
  const r = run({
    history: [v('1.7.8', 'Alice@Example.com')],
    incoming: v('1.7.9', 'alice@EXAMPLE.COM'),
  });
  assert.equal(r.result, 'ALLOW');
});

test('whitespace-trimmed match → ALLOW', () => {
  const r = run({
    history: [v('1.7.8', '  alice@example.com  ')],
    incoming: v('1.7.9', 'alice@example.com'),
  });
  assert.equal(r.result, 'ALLOW');
});

test('publisher changes across versions → WARN with old → new', () => {
  const r = run({
    history: [v('1.7.8', alice)],
    incoming: v('1.7.9', bob),
  });
  assert.equal(r.result, 'WARN');
  assert.match(r.detail, /publisher changed/);
  assert.match(r.detail, /alice@example\.com/);
  assert.match(r.detail, /bob@example\.com/);
  assert.match(r.detail, /prior version: 1\.7\.8/);
});

test('re-observation: history includes incoming version but prior is alice → ALLOW', () => {
  // Second-seen flow: the version we just observed is in history[0], and the
  // real prior is history[1]. We must filter the self-entry out.
  const r = run({
    version: '1.7.9',
    history: [v('1.7.9', alice), v('1.7.8', alice)],
    incoming: v('1.7.9', alice),
  });
  assert.equal(r.result, 'ALLOW');
});

test('re-observation with spoof attempt: self-entry ignored, prior delta still WARNs', () => {
  const r = run({
    version: '1.7.9',
    history: [v('1.7.9', bob), v('1.7.8', alice)],
    incoming: v('1.7.9', bob),
  });
  assert.equal(r.result, 'WARN');
  assert.match(r.detail, /1\.7\.8/);
});

test('multiple prior versions: compares only latest prior (history[0] after filter)', () => {
  // Legitimate handoff 2 releases ago should NOT fire — we only look at
  // the latest one. If we looked at ALL prior versions we'd WARN forever.
  const r = run({
    version: '1.8.0',
    history: [v('1.7.9', bob), v('1.7.8', alice)],
    incoming: v('1.8.0', bob),
  });
  assert.equal(r.result, 'ALLOW');
});

test('deterministic: same input twice → byte-identical detail', () => {
  const input = { history: [v('1.7.8', alice)], incoming: v('1.7.9', bob) };
  assert.equal(run(input).detail, run(input).detail);
});

test('gate name is always publisher-identity', () => {
  assert.equal(run({ incoming: v('1.7.9', alice) }).gate, 'publisher-identity');
  assert.equal(
    run({ history: [v('1.7.8', alice)], incoming: v('1.7.9', bob) }).gate,
    'publisher-identity',
  );
});
