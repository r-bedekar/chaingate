import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { openWitnessDB } from '../../witness/db.js';
import { DepCache } from '../../witness/dep-cache.js';

function tmpDb() {
  const dir = mkdtempSync(join(tmpdir(), 'chaingate-depcache-'));
  const path = join(dir, 'witness.db');
  return { path, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function withCache(fn, opts = {}) {
  const { path, cleanup } = tmpDb();
  const db = openWitnessDB(path);
  db.applySchema();
  const cache = new DepCache(db, opts);
  try {
    fn(cache, db);
  } finally {
    db.close();
    cleanup();
  }
}

test('cold lookup → hit:false', () => {
  withCache((cache) => {
    assert.deepEqual(cache.lookup('never-seen'), { hit: false });
  });
});

test('recordOk then lookup → hit with status ok and first_publish', () => {
  withCache((cache) => {
    cache.recordOk('axios', '2014-08-29T00:00:00.000Z');
    const r = cache.lookup('axios');
    assert.equal(r.hit, true);
    assert.equal(r.status, 'ok');
    assert.equal(r.first_publish, '2014-08-29T00:00:00.000Z');
  });
});

test('recordVanished then lookup → hit with status vanished, first_publish null', () => {
  withCache((cache) => {
    cache.recordVanished('vanished-pkg');
    const r = cache.lookup('vanished-pkg');
    assert.equal(r.hit, true);
    assert.equal(r.status, 'vanished');
    assert.equal(r.first_publish, null);
  });
});

test('recordError inside TTL → hit with status error', () => {
  let fakeNow = 1_000_000_000_000;
  withCache((cache) => {
    cache.recordError('flaky-pkg');
    const r = cache.lookup('flaky-pkg');
    assert.equal(r.hit, true);
    assert.equal(r.status, 'error');
  }, { now: () => fakeNow, errorTtlMs: 5 * 60 * 1000 });
});

test('recordError past TTL → lookup returns cold (hit:false)', () => {
  let fakeNow = 1_000_000_000_000;
  withCache((cache) => {
    cache.recordError('flaky-pkg');
    fakeNow += 10 * 60 * 1000; // advance past 5-min TTL
    assert.deepEqual(cache.lookup('flaky-pkg'), { hit: false });
  }, { now: () => fakeNow, errorTtlMs: 5 * 60 * 1000 });
});

test('recordOk wins over stale error (attempts increments)', () => {
  withCache((cache, db) => {
    cache.recordError('toggly');
    cache.recordOk('toggly', '2020-01-01T00:00:00.000Z');
    const r = cache.lookup('toggly');
    assert.equal(r.status, 'ok');
    assert.equal(r.first_publish, '2020-01-01T00:00:00.000Z');
    const row = db.db.prepare(`SELECT attempts FROM dep_first_publish WHERE package_name='toggly'`).get();
    assert.equal(row.attempts, 2);
  });
});

test('ok status is cached forever (no TTL check)', () => {
  let fakeNow = 1_000_000_000_000;
  withCache((cache) => {
    cache.recordOk('forever', '2020-01-01T00:00:00.000Z');
    fakeNow += 365 * 24 * 60 * 60 * 1000; // one year later
    const r = cache.lookup('forever');
    assert.equal(r.hit, true);
    assert.equal(r.status, 'ok');
  }, { now: () => fakeNow });
});

test('vanished status is cached forever (no TTL check)', () => {
  let fakeNow = 1_000_000_000_000;
  withCache((cache) => {
    cache.recordVanished('gone');
    fakeNow += 365 * 24 * 60 * 60 * 1000;
    const r = cache.lookup('gone');
    assert.equal(r.hit, true);
    assert.equal(r.status, 'vanished');
  }, { now: () => fakeNow });
});

test('empty / non-string package name → cold lookup, no throw', () => {
  withCache((cache) => {
    assert.deepEqual(cache.lookup(''), { hit: false });
    assert.deepEqual(cache.lookup(null), { hit: false });
    assert.deepEqual(cache.lookup(undefined), { hit: false });
    assert.deepEqual(cache.lookup(42), { hit: false });
  });
});

test('constructor requires witness db', () => {
  assert.throws(() => new DepCache(null), /witness db/);
  assert.throws(() => new DepCache({}), /witness db/);
});

test('_purge wipes a single row for testing', () => {
  withCache((cache) => {
    cache.recordOk('a', '2020-01-01T00:00:00Z');
    cache.recordOk('b', '2020-01-01T00:00:00Z');
    cache._purge('a');
    assert.equal(cache.lookup('a').hit, false);
    assert.equal(cache.lookup('b').hit, true);
  });
});
