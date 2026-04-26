import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { openWitnessDB } from '../../witness/db.js';
import { DepCache } from '../../witness/dep-cache.js';
import { createDepFetcher } from '../../proxy/dep-fetcher.js';

function tmpDb() {
  const dir = mkdtempSync(join(tmpdir(), 'chaingate-depfetcher-'));
  const path = join(dir, 'witness.db');
  return { path, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function withCache(fn) {
  const { path, cleanup } = tmpDb();
  const db = openWitnessDB(path);
  db.applySchema();
  const depCache = new DepCache(db);
  return Promise.resolve(fn(depCache, db)).finally(() => {
    db.close();
    cleanup();
  });
}

// Minimal fake upstream: returns a fake undici response object with
// statusCode + body.json() method. We don't use real HTTP.
function fakePackumentResponder(mapping) {
  return async (name) => {
    const entry = mapping[name];
    if (!entry) {
      return { statusCode: 404, body: { json: async () => ({}) } };
    }
    if (entry === 'error') {
      throw new Error('fake network error');
    }
    return {
      statusCode: entry.statusCode ?? 200,
      body: {
        json: async () => entry.body,
      },
    };
  };
}

const silent = { info() {}, warn() {}, error() {} };

test('enqueue then wait → depCache has ok entry with derived first_publish', async () => {
  await withCache(async (depCache) => {
    const fetcher = createDepFetcher({
      depCache,
      fetchPackument: fakePackumentResponder({
        axios: { body: { name: 'axios', time: { created: '2014-08-29T00:00:00.000Z' } } },
      }),
      intervalMs: 0,
      logger: silent,
    });
    fetcher.enqueue('axios');
    await fetcher.stop();
    const r = depCache.lookup('axios');
    assert.equal(r.hit, true);
    assert.equal(r.status, 'ok');
    assert.equal(r.first_publish, '2014-08-29T00:00:00.000Z');
    assert.equal(fetcher.getStats().ok, 1);
  });
});

test('404 from upstream → vanished entry', async () => {
  await withCache(async (depCache) => {
    const fetcher = createDepFetcher({
      depCache,
      fetchPackument: fakePackumentResponder({}),
      intervalMs: 0,
      logger: silent,
    });
    fetcher.enqueue('no-such-pkg');
    await fetcher.stop();
    const r = depCache.lookup('no-such-pkg');
    assert.equal(r.status, 'vanished');
    assert.equal(fetcher.getStats().vanished, 1);
  });
});

test('upstream throw → error entry (fail-open)', async () => {
  await withCache(async (depCache) => {
    const fetcher = createDepFetcher({
      depCache,
      fetchPackument: fakePackumentResponder({ 'flaky-pkg': 'error' }),
      intervalMs: 0,
      logger: silent,
    });
    fetcher.enqueue('flaky-pkg');
    await fetcher.stop();
    const r = depCache.lookup('flaky-pkg');
    assert.equal(r.status, 'error');
    assert.equal(fetcher.getStats().error, 1);
  });
});

test('5xx status → error entry', async () => {
  await withCache(async (depCache) => {
    const fetcher = createDepFetcher({
      depCache,
      fetchPackument: fakePackumentResponder({
        down: { statusCode: 503, body: {} },
      }),
      intervalMs: 0,
      logger: silent,
    });
    fetcher.enqueue('down');
    await fetcher.stop();
    assert.equal(depCache.lookup('down').status, 'error');
  });
});

test('packument with no time.created but version times → uses min version time', async () => {
  await withCache(async (depCache) => {
    const fetcher = createDepFetcher({
      depCache,
      fetchPackument: fakePackumentResponder({
        pkg: {
          body: {
            name: 'pkg',
            time: {
              modified: '2024-01-01T00:00:00.000Z',
              '1.0.0': '2020-06-01T00:00:00.000Z',
              '1.0.1': '2020-07-01T00:00:00.000Z',
              '1.0.2': '2020-05-15T00:00:00.000Z', // earliest
            },
          },
        },
      }),
      intervalMs: 0,
      logger: silent,
    });
    fetcher.enqueue('pkg');
    await fetcher.stop();
    const r = depCache.lookup('pkg');
    assert.equal(r.status, 'ok');
    assert.equal(r.first_publish, '2020-05-15T00:00:00.000Z');
  });
});

test('packument with no time at all → error entry', async () => {
  await withCache(async (depCache) => {
    const fetcher = createDepFetcher({
      depCache,
      fetchPackument: fakePackumentResponder({
        weird: { body: { name: 'weird' } },
      }),
      intervalMs: 0,
      logger: silent,
    });
    fetcher.enqueue('weird');
    await fetcher.stop();
    assert.equal(depCache.lookup('weird').status, 'error');
  });
});

test('dedup: enqueuing the same name twice triggers one fetch', async () => {
  await withCache(async (depCache) => {
    let fetchCount = 0;
    const fetcher = createDepFetcher({
      depCache,
      fetchPackument: async (name) => {
        fetchCount += 1;
        return { statusCode: 200, body: { json: async () => ({ time: { created: '2020-01-01T00:00:00Z' } }) } };
      },
      intervalMs: 0,
      logger: silent,
    });
    fetcher.enqueue('same');
    fetcher.enqueue('same');
    fetcher.enqueue('same');
    await fetcher.stop();
    assert.equal(fetchCount, 1);
  });
});

test('queue-full drops excess enqueues', async () => {
  await withCache(async (depCache) => {
    // Never-resolving fetcher so items stay inflight/queued during test.
    let released;
    const releaseP = new Promise((r) => { released = r; });
    let fetchCalled = 0;
    const fetcher = createDepFetcher({
      depCache,
      fetchPackument: async () => {
        fetchCalled += 1;
        await releaseP;
        return { statusCode: 404, body: { json: async () => ({}) } };
      },
      intervalMs: 0,
      maxQueueSize: 3,
      logger: silent,
    });
    // Queue up to max; first is dispatched into inflight quickly.
    fetcher.enqueue('a');
    fetcher.enqueue('b');
    fetcher.enqueue('c');
    fetcher.enqueue('d');
    const dropped = fetcher.enqueue('e');
    assert.equal(dropped, false);
    assert.ok(fetcher.getStats().dropped >= 1);
    released();
    await fetcher.stop();
  });
});

test('stop() drains inflight and aborts queue', async () => {
  await withCache(async (depCache) => {
    const fetcher = createDepFetcher({
      depCache,
      fetchPackument: fakePackumentResponder({
        a: { body: { time: { created: '2020-01-01T00:00:00Z' } } },
        b: { body: { time: { created: '2020-01-01T00:00:00Z' } } },
      }),
      intervalMs: 0,
      logger: silent,
    });
    fetcher.enqueue('a');
    fetcher.enqueue('b');
    await fetcher.stop();
    // Either both or just 'a' completed. Stop must not hang.
    const stats = fetcher.getStats();
    assert.ok(stats.ok >= 1);
  });
});

test('deriveFirstPublish helper: created beats version times', () => {
  const { _deriveFirstPublish } = createDepFetcher({
    depCache: { recordOk() {}, recordVanished() {}, recordError() {} },
    fetchPackument: async () => {},
  });
  assert.equal(
    _deriveFirstPublish({
      time: {
        created: '2020-01-01T00:00:00Z',
        '1.0.0': '2019-01-01T00:00:00Z',
      },
    }),
    '2020-01-01T00:00:00Z',
  );
});

test('createDepFetcher requires depCache and fetchPackument', () => {
  assert.throws(() => createDepFetcher({ fetchPackument: async () => ({}) }), /depCache/);
  assert.throws(
    () => createDepFetcher({ depCache: { recordOk() {} } }),
    /fetchPackument/,
  );
});
