// U-05 gap-closure r2 (owner decision 6), A1: one logging boundary with a global output budget. Expected values come from
// revision 2 §4 (L-1..L-6), written before this file. What is bounded is the RATE of lines through the boundary; file size
// over unlimited time is not (proxy.log has no rotation, pre-existing).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createLogBoundary } from '../../proxy/log-boundary.js';
import { withProxy, versionsOf, tgz } from '../seed-v3/u05-r2-proxy.mjs';
import { CONFIGS } from '../seed-v3/u05-fixtures.mjs';

function sink() {
  const lines = [];
  return { lines, logger: { info: (m) => lines.push(['info', m]), warn: (m) => lines.push(['warn', m]), error: (m) => lines.push(['error', m]) } };
}
function clock(t0 = 1_000_000) { const c = { t: t0, now: () => c.t, advance: (ms) => { c.t += ms; } }; return c; }

test('L-3 a flood of distinct lines: emitted <= burst + refill*t + summaries; the summary counts what was suppressed', () => {
  const c = clock(); const s = sink();
  const log = createLogBoundary(s.logger, { burst: 300, perSecond: 1, now: c.now, timers: false, stderr: () => {} });
  for (let i = 0; i < 10_000; i += 1) log.warn(`[witness] pkg${i}@1.0.0: BLOCK computed but NOT stored`);
  assert.equal(s.lines.length, 300, 'the burst only');
  c.advance(10_000);
  for (let i = 0; i < 10_000; i += 1) log.warn(`[witness] more${i}@1.0.0`);
  const events = s.lines.filter(([, m]) => !m.startsWith('[log]')).length;
  assert.ok(events <= 300 + 10 + 1, `${events} event lines within burst + refill`);
  c.advance(60_000); log.tick();
  const summaries = s.lines.filter(([, m]) => /^\[log\] suppressed \d+ line/.test(m));
  assert.equal(summaries.length, 1, 'one summary line');
  assert.match(summaries[0][1], /not a complete per-decision record/);
  const st = log.stats();
  assert.equal(st.emitted + st.suppressed, 20_000 + 1, 'every line is either emitted or counted (the +1 is the summary)');
});

test('L-4 a 100 KiB message is cut to the 1 KiB line cap with a marker', () => {
  const s = sink();
  const log = createLogBoundary(s.logger, { timers: false, stderr: () => {} });
  log.warn(`[proxy] internal error: ${'x'.repeat(100 * 1024)}`);
  const [[, m]] = s.lines;
  assert.ok(Buffer.byteLength(m) <= 1024, `${Buffer.byteLength(m)} bytes`);
  assert.match(m, /…\[\+\d+ bytes\]$/);
  assert.equal(log.stats().truncated, 1);
});

test('L-5 transition lines bypass the budget, are emitted on change only, and at most once per channel per minute', () => {
  const c = clock(); const s = sink();
  const log = createLogBoundary(s.logger, { burst: 0, perSecond: 0, now: c.now, timers: false, stderr: () => {} });
  log.warn('an ordinary line is suppressed with no budget');
  log.transition('storage', 'failing', '[witness] decision writes failing');
  log.transition('storage', 'failing', '[witness] decision writes failing (again)');
  log.transition('storage', 'ok', '[witness] decision writes committed again');
  log.transition('storage', 'failing', '[witness] failing once more');
  const t = s.lines.filter(([, m]) => m.startsWith('[witness]'));
  assert.equal(t.length, 1, 'only the first transition within the minute');
  c.advance(60_000); log.tick();
  const t2 = s.lines.filter(([, m]) => m.startsWith('[witness]'));
  assert.equal(t2.length, 1, 'the latest pending value equals the last emitted value (failing): nothing new to say');
  log.transition('storage', 'ok', '[witness] decision writes committed again');
  assert.equal(s.lines.filter(([, m]) => m.startsWith('[witness]')).length, 2, 'a real change after the minute is emitted');
});

test('L-2 (boundary) a sink that throws on every call never throws out; failures are counted; one stderr note per minute', () => {
  const c = clock(); const notes = [];
  const log = createLogBoundary({ warn() { throw new Error('sink down'); }, error() { throw new Error('sink down'); } },
    { now: c.now, timers: false, stderr: (x) => notes.push(x) });
  for (let i = 0; i < 50; i += 1) { log.warn('x'); log.error('y'); log.transition('full', String(i), 'z'); }
  assert.equal(log.stats().failures > 0, true);
  assert.equal(notes.length, 1, 'one fallback note in the minute');
  c.advance(60_000); log.warn('x');
  assert.equal(notes.length, 2);
});

test('silent levels consume no budget (info is a no-op in the shipped logger)', () => {
  const s = sink();
  const log = createLogBoundary(s.logger, { burst: 1, perSecond: 0, timers: false, silentLevels: ['info'], stderr: () => {} });
  for (let i = 0; i < 100; i += 1) log.info('[witness] observed');
  log.warn('[gate] p@1.3.0: BLOCK');
  assert.deepEqual(s.lines.map(([, m]) => m), ['[gate] p@1.3.0: BLOCK']);
});

test('L-1 ordinary operation: the existing [gate] and remember lines still appear', async () => {
  await withProxy({ cfg: CONFIGS.live }, async (h) => {
    const r = await h.get('/p');
    assert.equal(r.status, 200);
    assert.ok(h.logs.some((l) => /^\[gate\] p@1\.3\.0: BLOCK/.test(l)), 'the BLOCK line');
  });
});

test('L-2 (proxy) logging fails on EVERY call: the same statuses and the same served/omitted versions; no unhandled rejection', async () => {
  const rejections = []; const onRej = (e) => rejections.push(e);
  process.on('unhandledRejection', onRej);
  try {
    for (const [name, cfg] of Object.entries(CONFIGS)) {
      await withProxy({ cfg }, async (h) => {
        const real = console.error;
        console.error = () => { throw new Error('injected: every log line fails'); };
        let r; let t; let q;
        try { r = await h.get('/p'); t = await h.get(tgz('p', '1.3.0')); q = await h.get('/q'); } finally { console.error = real; }
        assert.equal(r.status, 200, `${name}: served`);
        assert.ok(!versionsOf(r).includes('1.3.0'), `${name}: the BLOCKed version is still removed`);
        assert.ok(versionsOf(r).includes('1.4.0'), `${name}: the rest is served`);
        assert.equal(t.status, 403, `${name}: the tarball is still refused`);
        assert.equal(q.status, 200, `${name}: other packages unaffected`);
        assert.ok((await h.self()).logging?.failures > 0, `${name}: the failures are counted in /_chaingate/self`);
      });
    }
  } finally { process.off('unhandledRejection', onRej); }
  assert.equal(rejections.length, 0, 'no unhandled rejection');
});

test('L-6 budget exhaustion never changes a disposition (compared with an unlimited budget)', async () => {
  const outcome = async (logBudget) => withProxy({ cfg: CONFIGS.warn, hooks: { logBudget } }, async (h) => {
    const out = [];
    for (const path of ['/p', '/q', '/n', tgz('p', '1.3.0'), tgz('p', '1.4.0'), tgz('q', '1.3.0')]) {
      const r = await h.get(path);
      out.push([path, r.status, versionsOf(r).join(',')]);
    }
    return out;
  });
  assert.deepEqual(await outcome({ burst: 0, perSecond: 0 }), await outcome({ burst: 1e9, perSecond: 1e9 }));
});
