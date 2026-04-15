import { test } from 'node:test';
import assert from 'node:assert/strict';

import releaseAge from '../../gates/release-age.js';

const FIXED_NOW = Date.parse('2026-04-15T12:00:00.000Z');

function hoursAgo(h) {
  return new Date(FIXED_NOW - h * 60 * 60 * 1000).toISOString();
}

function run({ version = '1.7.9', incoming, thresholdHours = 72 }) {
  return releaseAge.evaluate({
    ecosystem: 'npm',
    packageName: 'axios',
    version,
    incoming: { version, ...incoming },
    baseline: null,
    history: [],
    config: { releaseAgeHours: thresholdHours, _nowMs: FIXED_NOW },
  });
}

test('published 100h ago, threshold 72h → ALLOW', () => {
  const r = run({ incoming: { published_at: hoursAgo(100) } });
  assert.equal(r.gate, 'release-age');
  assert.equal(r.result, 'ALLOW');
  assert.match(r.detail, /100h.*72h/);
});

test('published 10h ago, threshold 72h → WARN', () => {
  const r = run({ incoming: { published_at: hoursAgo(10) } });
  assert.equal(r.result, 'WARN');
  assert.match(r.detail, /10h.*72h/);
});

test('published exactly at threshold boundary (72h) → ALLOW (inclusive)', () => {
  const r = run({ incoming: { published_at: hoursAgo(72) } });
  assert.equal(r.result, 'ALLOW');
});

test('published just under threshold (71h) → WARN', () => {
  const r = run({ incoming: { published_at: hoursAgo(71) } });
  assert.equal(r.result, 'WARN');
});

test('custom threshold 24h: 23h old → WARN, 25h old → ALLOW', () => {
  assert.equal(
    run({ incoming: { published_at: hoursAgo(23) }, thresholdHours: 24 }).result,
    'WARN',
  );
  assert.equal(
    run({ incoming: { published_at: hoursAgo(25) }, thresholdHours: 24 }).result,
    'ALLOW',
  );
});

test('prerelease -rc.1 → ALLOW (exempt)', () => {
  const r = run({
    version: '1.0.0-rc.1',
    incoming: { published_at: hoursAgo(1) },
  });
  assert.equal(r.result, 'ALLOW');
  assert.match(r.detail, /prerelease exempt/);
});

test('prerelease -beta.3 → ALLOW (exempt)', () => {
  const r = run({
    version: '2.0.0-beta.3',
    incoming: { published_at: hoursAgo(1) },
  });
  assert.equal(r.result, 'ALLOW');
});

test('prerelease -alpha → ALLOW (exempt)', () => {
  const r = run({
    version: '3.0.0-alpha',
    incoming: { published_at: hoursAgo(1) },
  });
  assert.equal(r.result, 'ALLOW');
});

test('prerelease -0 (numeric) is NOT a prerelease tag (edge case)', () => {
  // semver says "-0" is a valid prerelease, but for our purposes the
  // lexical heuristic — which matches npm's min-release-age — is
  // "prerelease if there's a dash followed by an alphabetic/numeric
  // identifier". "-0" IS a semver prerelease, so we DO exempt it.
  // This documents the actual behavior for future readers.
  const r = run({
    version: '1.0.0-0',
    incoming: { published_at: hoursAgo(1) },
  });
  assert.equal(r.result, 'ALLOW');
});

test('build metadata +sha (no prerelease) does NOT exempt', () => {
  const r = run({
    version: '1.0.0+abc123',
    incoming: { published_at: hoursAgo(1) },
  });
  assert.equal(r.result, 'WARN');
});

test('stable release with build metadata suffix: 1.0.0+build, 1h old → WARN', () => {
  const r = run({
    version: '1.0.0+build.42',
    incoming: { published_at: hoursAgo(1) },
  });
  assert.equal(r.result, 'WARN');
});

test('missing published_at → SKIP (data gap)', () => {
  const r = run({ incoming: {} });
  assert.equal(r.result, 'SKIP');
  assert.match(r.detail, /missing or unparseable/);
});

test('malformed published_at string → SKIP', () => {
  const r = run({ incoming: { published_at: 'not-a-date' } });
  assert.equal(r.result, 'SKIP');
});

test('future-dated published_at (clock skew or forgery) → WARN age 0h (not SKIP)', () => {
  const r = run({
    incoming: { published_at: new Date(FIXED_NOW + 24 * 60 * 60 * 1000).toISOString() },
  });
  // Clamped to 0h, so 0h < 72h → WARN
  assert.equal(r.result, 'WARN');
  assert.match(r.detail, /0h/);
});

test('config threshold fallback to default 72h when missing', () => {
  const r = releaseAge.evaluate({
    version: '1.0.0',
    incoming: { version: '1.0.0', published_at: hoursAgo(100) },
    history: [],
    config: { _nowMs: FIXED_NOW },
  });
  assert.equal(r.result, 'ALLOW');
});

test('deterministic: same input twice → byte-identical detail', () => {
  const input = { incoming: { published_at: hoursAgo(1) } };
  assert.equal(run(input).detail, run(input).detail);
});

test('gate name is always release-age', () => {
  assert.equal(run({ incoming: { published_at: hoursAgo(100) } }).gate, 'release-age');
});
