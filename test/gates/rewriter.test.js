import { test } from 'node:test';
import assert from 'node:assert/strict';

import { rewritePackument } from '../../gates/rewriter.js';

function mkPackument(versions, distTags = { latest: versions[versions.length - 1] }) {
  const versionsObj = {};
  const time = { created: '2020-01-01T00:00:00Z', modified: '2024-12-23T00:00:00Z' };
  for (const v of versions) {
    versionsObj[v] = { name: 'axios', version: v, dist: { shasum: `sha-${v}` } };
    time[v] = `2024-01-${String(versions.indexOf(v) + 1).padStart(2, '0')}T00:00:00Z`;
  }
  return {
    name: 'axios',
    _id: 'axios',
    _rev: '42-abc',
    'dist-tags': { ...distTags },
    versions: versionsObj,
    time,
    readme: 'hello world',
  };
}

function dec(disposition, detail = '') {
  return { disposition, results: [{ gate: 'stub', result: disposition, detail }] };
}

test('empty decisions → unchanged, changed=false', () => {
  const p = mkPackument(['1.0.0', '1.1.0']);
  const out = rewritePackument(p, new Map());
  assert.equal(out.changed, false);
  assert.equal(out.packument, p);
});

test('all ALLOW → unchanged', () => {
  const p = mkPackument(['1.0.0', '1.1.0']);
  const decisions = new Map([
    ['1.0.0', dec('ALLOW')],
    ['1.1.0', dec('ALLOW')],
  ]);
  const out = rewritePackument(p, decisions);
  assert.equal(out.changed, false);
  assert.equal(out.summary.kept, 2);
});

test('one WARN → kept, summary.warned has entry, changed=false', () => {
  const p = mkPackument(['1.0.0', '1.1.0']);
  const decisions = new Map([
    ['1.0.0', dec('ALLOW')],
    ['1.1.0', dec('WARN', 'publisher changed')],
  ]);
  const out = rewritePackument(p, decisions);
  assert.equal(out.changed, false);
  assert.equal(out.summary.warned.length, 1);
  assert.equal(out.summary.warned[0].version, '1.1.0');
  assert.equal(out.summary.warned[0].reason, 'publisher changed');
});

test('one BLOCK middle version → removed from versions + time', () => {
  const p = mkPackument(['1.0.0', '1.1.0', '1.2.0']);
  const decisions = new Map([['1.1.0', dec('BLOCK', 'hash mismatch')]]);
  const out = rewritePackument(p, decisions);
  assert.equal(out.changed, true);
  assert.equal(Object.keys(out.packument.versions).length, 2);
  assert.ok(!('1.1.0' in out.packument.versions));
  assert.ok(!('1.1.0' in out.packument.time));
  assert.ok('created' in out.packument.time);
  assert.ok('modified' in out.packument.time);
  assert.equal(out.summary.blocked.length, 1);
  assert.equal(out.summary.blocked[0].reason, 'hash mismatch');
});

test('block latest → latest downgrades to next highest non-prerelease', () => {
  const p = mkPackument(['1.0.0', '1.1.0', '1.2.0'], { latest: '1.2.0' });
  const decisions = new Map([['1.2.0', dec('BLOCK')]]);
  const out = rewritePackument(p, decisions);
  assert.equal(out.packument['dist-tags'].latest, '1.1.0');
  assert.deepEqual(out.summary.dist_tag_downgrades, [{ tag: 'latest', from: '1.2.0', to: '1.1.0' }]);
});

test('block latest, only prereleases remain → latest tag dropped', () => {
  const p = mkPackument(['2.0.0-rc.1', '2.0.0-rc.2', '2.0.0'], { latest: '2.0.0' });
  const decisions = new Map([['2.0.0', dec('BLOCK')]]);
  const out = rewritePackument(p, decisions);
  assert.equal(out.packument['dist-tags'].latest, undefined);
  assert.equal(out.summary.dist_tag_downgrades.length, 1);
  assert.equal(out.summary.dist_tag_downgrades[0].to, null);
});

test('block all versions → empty versions/time, dist-tags empty', () => {
  const p = mkPackument(['1.0.0', '1.1.0']);
  const decisions = new Map([
    ['1.0.0', dec('BLOCK')],
    ['1.1.0', dec('BLOCK')],
  ]);
  const out = rewritePackument(p, decisions);
  assert.equal(out.changed, true);
  assert.deepEqual(Object.keys(out.packument.versions), []);
  assert.equal(out.packument['dist-tags'].latest, undefined);
  assert.equal(Object.keys(out.packument['dist-tags']).length, 0);
});

test('block version referenced by beta tag → tag moves to highest remaining prerelease', () => {
  const p = mkPackument(['1.0.0', '1.1.0', '2.0.0-beta.1', '2.0.0-beta.2'], {
    latest: '1.1.0',
    beta: '2.0.0-beta.2',
  });
  const decisions = new Map([['2.0.0-beta.2', dec('BLOCK')]]);
  const out = rewritePackument(p, decisions);
  assert.equal(out.packument['dist-tags'].beta, '2.0.0-beta.1');
  assert.equal(out.packument['dist-tags'].latest, '1.1.0');
});

test('multiple dist-tags pointing at same blocked version move independently', () => {
  const p = mkPackument(['1.0.0', '1.1.0', '1.2.0'], {
    latest: '1.2.0',
    stable: '1.2.0',
  });
  const decisions = new Map([['1.2.0', dec('BLOCK')]]);
  const out = rewritePackument(p, decisions);
  assert.equal(out.packument['dist-tags'].latest, '1.1.0');
  assert.equal(out.packument['dist-tags'].stable, '1.1.0');
  assert.equal(out.summary.dist_tag_downgrades.length, 2);
});

test('input packument not mutated', () => {
  const p = mkPackument(['1.0.0', '1.1.0', '1.2.0'], { latest: '1.2.0' });
  const pSnapshot = JSON.parse(JSON.stringify(p));
  const decisions = new Map([['1.1.0', dec('BLOCK')]]);
  rewritePackument(p, decisions);
  assert.deepEqual(p, pSnapshot);
});

test('invalid semver in versions → filtered from tag candidates, untouched in output', () => {
  const p = mkPackument(['1.0.0', 'not-a-version', '1.1.0'], { latest: '1.1.0' });
  const decisions = new Map([['1.1.0', dec('BLOCK')]]);
  const out = rewritePackument(p, decisions);
  // 'not-a-version' still in output
  assert.ok('not-a-version' in out.packument.versions);
  // But latest tag picked real semver
  assert.equal(out.packument['dist-tags'].latest, '1.0.0');
});

test('no dist-tags field → no error', () => {
  const p = mkPackument(['1.0.0']);
  delete p['dist-tags'];
  const decisions = new Map([['1.0.0', dec('BLOCK')]]);
  const out = rewritePackument(p, decisions);
  assert.equal(out.changed, true);
  assert.deepEqual(Object.keys(out.packument.versions), []);
});

test('dist-tag points at version absent from versions map → left as-is (drift)', () => {
  const p = mkPackument(['1.0.0', '1.1.0'], { latest: '1.1.0', ghost: '99.0.0' });
  const decisions = new Map([['1.0.0', dec('BLOCK')]]);
  const out = rewritePackument(p, decisions);
  assert.equal(out.packument['dist-tags'].ghost, '99.0.0');
  assert.equal(out.packument['dist-tags'].latest, '1.1.0');
});

test('mixed WARN + BLOCK → warned kept, blocked stripped, summary has both', () => {
  const p = mkPackument(['1.0.0', '1.1.0', '1.2.0']);
  const decisions = new Map([
    ['1.0.0', dec('ALLOW')],
    ['1.1.0', dec('WARN', 'new dep')],
    ['1.2.0', dec('BLOCK', 'hash mismatch')],
  ]);
  const out = rewritePackument(p, decisions);
  assert.equal(out.changed, true);
  assert.ok('1.1.0' in out.packument.versions);
  assert.ok(!('1.2.0' in out.packument.versions));
  assert.equal(out.summary.warned.length, 1);
  assert.equal(out.summary.blocked.length, 1);
});

test('non-object packument → returned as-is', () => {
  const out = rewritePackument(null, new Map());
  assert.equal(out.changed, false);
  assert.equal(out.packument, null);
});

test('unknown version (no decision) → kept as ALLOW-unknown', () => {
  const p = mkPackument(['1.0.0', '1.1.0']);
  const decisions = new Map([['1.0.0', dec('BLOCK')]]);
  const out = rewritePackument(p, decisions);
  assert.equal(out.changed, true);
  assert.ok('1.1.0' in out.packument.versions);
  assert.equal(out.summary.kept, 1);
});
