// 0.1.4 Tier 0, A8 — `stale_seed`: an `append` release with registry releases between the seed tip and itself gets a
// coverage row naming k and the tip; Channel-A still compares against the tip (seed-base decision table R1, R7, P3;
// Q1: any k >= 1, never an alert). Expected results: decision tables
// ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-I1-A8-20261011.md, T-A8 S1-S4, written before this file.
//
// Fixture: the U-05 synthetic seed. Package `q` has one lineage (key 1) recording 1.0.0, 1.1.0, 1.2.0; the tip is
// 1.2.0 at TIP_S. `q` carries no advisory pin. The domain version count is a stated integer in the direct cases so
// that adding gap releases to the packument cannot change provider_class (only the gap may differ).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import G from '../../seed/v3/gate.js';
import { buildCheckRecord, inputFromPackument } from '../../cli/check-record.js';
import { createProxyServer } from '../../proxy/server.js';
import { buildSeed, openFixtureSeed, docFor, manifestFor, after, iso, TIP_S, STEP_S, LIVE } from './u05-fixtures.mjs';

const DVC = 3;
const COVERAGE = 'seed-v3:coverage';
const isStale = (x) => x.gate === COVERAGE && x.detail.startsWith('stale_seed');
const TOOL = { name: 'chaingate', version: 'test' };

function withSeed(fn) {
  const s = buildSeed({ layout: '1.1' });
  const seed = openFixtureSeed(s.dbPath);
  try { return fn(seed); } finally { seed.close(); s.cleanup(); }
}
const evaluate = (seed, input) => G.evaluateCandidate(seed, { config: LIVE, domainVersionCount: DVC }, input);

/** S1's results with the S2/S3 row inserted where T-A8 says: right after the dac-trajectory threshold rows. */
function withRowInserted(results, row) {
  const lastDac = results.map((x) => x.gate.startsWith('seed-v3:dac-trajectory')).lastIndexOf(true);
  assert.ok(lastDac >= 0, 'the fixture decision has dac-trajectory rows');
  return [...results.slice(0, lastDac + 1), row, ...results.slice(lastDac + 1)];
}

const GAP_DOC = () => docFor('q', [['1.3.0', after(1)], ['1.4.0', after(2)], ['1.5.0', after(3)]]);
const NO_GAP_DOC = () => docFor('q', [['1.5.0', after(3)]]);

test('A8 S2: append with k=2 -> one stale_seed SKIP row naming k, the gap releases and the tip; nothing else differs', () => {
  withSeed((seed) => {
    const gap = evaluate(seed, inputFromPackument(GAP_DOC(), 'q', '1.5.0'));
    const none = evaluate(seed, inputFromPackument(NO_GAP_DOC(), 'q', '1.5.0'));
    assert.equal(gap.placement.kind, 'append');
    assert.equal(gap.finding.channel_a.predecessor_version, '1.2.0', 'Channel-A still compares against the seed tip (R1)');
    assert.deepEqual(gap.finding, none.finding, 'the finding is unchanged');
    const row = { gate: COVERAGE, result: 'SKIP', detail: 'stale_seed k=2: 2 release(s) published after the seed tip 1.2.0 '
      + 'are not in the seed (1.3.0, 1.4.0); Channel-A compared against 1.2.0' };
    assert.deepEqual(gap.decision.results, withRowInserted(none.decision.results, row));
    for (const k of ['disposition', 'evidence_complete', 'not_evaluated', 'policy_version', 'placement']) {
      assert.deepEqual(gap.decision[k], none.decision[k], `decision.${k} unchanged`);
    }
  });
});

test('A8 S1: append with no gap -> no stale_seed row', () => {
  withSeed((seed) => {
    const none = evaluate(seed, inputFromPackument(NO_GAP_DOC(), 'q', '1.5.0'));
    assert.equal(none.placement.kind, 'append');
    assert.equal(none.decision.results.filter(isStale).length, 0);
  });
});

test('A8 S3: append with no publication times supplied -> a "not checked" row, never a silent k=0', () => {
  withSeed((seed) => {
    const input = inputFromPackument(GAP_DOC(), 'q', '1.5.0');
    const noTimes = { ...input };
    delete noTimes.rawTimes;
    const none = evaluate(seed, inputFromPackument(NO_GAP_DOC(), 'q', '1.5.0'));
    const got = evaluate(seed, noTimes);
    assert.equal(got.placement.kind, 'append', 'the candidate still has its own publishedAt');
    const row = { gate: COVERAGE, result: 'SKIP', detail: 'stale_seed not checked: no packument publication times were '
      + 'supplied; Channel-A compared against the seed tip 1.2.0' };
    assert.deepEqual(got.decision.results, withRowInserted(none.decision.results, row));
    assert.equal(got.decision.disposition, none.decision.disposition);
  });
});

test('A8 the gap counts only same-major, served, timed, non-tied releases strictly between the tip and the candidate', () => {
  withSeed((seed) => {
    const doc = docFor('q', [
      ['1.2.5', iso(TIP_S)],                    // same second as the tip: order not recoverable, not counted
      ['1.3.0', after(1)],                      // counted
      ['1.3.1-beta.1', iso(TIP_S + STEP_S + 10)], // a prerelease of major 1: counted (lineage key is the major)
      ['2.0.0', iso(TIP_S + STEP_S + 20)],      // another major: not counted
      ['1.4.0', undefined],                     // no publication time: not counted
      ['1.6.0', after(4)],                      // published after the candidate: not counted
      ['1.5.0', after(3)],                      // the candidate
    ]);
    doc.time['1.3.5'] = iso(TIP_S + STEP_S + 30); // in time{} but not served (removed): not counted
    doc.time['1.3.6'] = 'not a date';             // unparseable: not counted, and no refusal
    doc.versions['1.3.6'] = manifestFor('q', '1.3.6');
    const got = evaluate(seed, inputFromPackument(doc, 'q', '1.5.0'));
    assert.equal(got.placement.kind, 'append');
    assert.deepEqual(got.decision.results.filter(isStale).map((x) => x.detail), [
      'stale_seed k=2: 2 release(s) published after the seed tip 1.2.0 are not in the seed (1.3.0, 1.3.1-beta.1); '
      + 'Channel-A compared against 1.2.0']);
  });
});

test('A8 more than 10 gap releases: 10 listed in publication order, the rest counted', () => {
  withSeed((seed) => {
    const extra = [];
    for (let i = 0; i < 13; i += 1) extra.push([`1.3.${i}`, iso(TIP_S + 1000 + i)]);
    extra.push(['1.5.0', after(3)]);
    const got = evaluate(seed, inputFromPackument(docFor('q', extra), 'q', '1.5.0'));
    const listed = Array.from({ length: 10 }, (_, i) => `1.3.${i}`).join(', ');
    assert.deepEqual(got.decision.results.filter(isStale).map((x) => x.detail), [
      `stale_seed k=13: 13 release(s) published after the seed tip 1.2.0 are not in the seed (${listed}, … +3 more); `
      + 'Channel-A compared against 1.2.0']);
  });
});

test('A8 S4: recorded, new-major cold start and historical-omitted placements get no stale_seed row', () => {
  withSeed((seed) => {
    const doc = docFor('q', [['1.1.5', iso(TIP_S - 10)], ['1.3.0', after(1)], ['2.0.0', after(2)]]);
    for (const [v, kind] of [['1.1.0', 'recorded'], ['2.0.0', 'new-major-cold-start'], ['1.1.5', 'historical-omitted']]) {
      const got = evaluate(seed, inputFromPackument(doc, 'q', v));
      assert.equal(got.placement.kind, kind, v);
      assert.equal(got.decision.results.filter(isStale).length, 0, `${v} (${kind})`);
    }
  });
});

test('A8 the gate detail is unchanged: the SKIP row never bears the disposition', () => {
  withSeed((seed) => {
    const gate = G.createSeedV3Gate({ seed, config: LIVE, domainVersionCount: DVC });
    const a = gate.evaluate(inputFromPackument(GAP_DOC(), 'q', '1.5.0'));
    const b = gate.evaluate(inputFromPackument(NO_GAP_DOC(), 'q', '1.5.0'));
    // `rows` (group 2a, E11) lists every row, so it carries the coverage row; result and detail are what bears.
    assert.deepEqual({ result: a.result, detail: a.detail }, { result: b.result, detail: b.detail });
  });
});

test('A8 chaingate check carries the row in decision.results (/3 record)', () => {
  withSeed((seed) => {
    const rec = buildCheckRecord({ seed, policy: LIVE, domainVersionCount: DVC,
      input: inputFromPackument(GAP_DOC(), 'q', '1.5.0'), request: { package: 'q', version: '1.5.0' }, tool: TOOL });
    assert.equal(rec.schema, 'chaingate.check/5');   // since 0.1.6
    assert.equal(rec.decision.results.filter(isStale).length, 1);
  });
});

// The proxy's own input path (witness store -> runner -> gate): the store must hand the gate the packument's time{}.
const listen = (srv) => new Promise((resolve) => { srv.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${srv.address().port}`)); });
const close = (srv) => new Promise((resolve) => { srv.close(() => resolve()); });
const get = (url) => new Promise((resolve, reject) => {
  http.get(url, { agent: false }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); }).on('error', reject);
});

test('A8 through the proxy: the witness store passes the time map, so the decision for q@1.5.0 carries k=2', async () => {
  const s = buildSeed({ layout: '1.1' });
  const seed = openFixtureSeed(s.dbPath);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-a8-'));
  const decisions = [];
  const doc = GAP_DOC();
  const upstream = http.createServer((req, res) => {
    if (decodeURIComponent(req.url) === '/q') { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(doc)); return; }
    res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}');
  });
  const upstreamUrl = await listen(upstream);
  const gate = G.createSeedV3Gate({ seed, config: LIVE, domainVersionCount: 'from-packument', onDecision: (d) => decisions.push(d) });
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: upstreamUrl, witnessDbPath: path.join(dir, 'witness.db'),
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000 }, { gateModules: [gate] });
  const proxyUrl = await listen(proxy);
  try {
    assert.equal(await get(`${proxyUrl}/q`), 200);
    const stale = decisions.flatMap((d) => d.results.filter(isStale).map((x) => x.detail));
    assert.ok(stale.includes('stale_seed k=2: 2 release(s) published after the seed tip 1.2.0 are not in the seed '
      + '(1.3.0, 1.4.0); Channel-A compared against 1.2.0'), JSON.stringify(stale));
    assert.ok(!stale.some((x) => x.startsWith('stale_seed not checked')), 'the store supplied the time map');
  } finally {
    await close(proxy); await close(upstream);
    seed.close(); s.cleanup(); fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('A8 the gap index is built once per document (no per-candidate rescan), and only for the versions map it was built with', () => {
  const doc = GAP_DOC();
  const a = G.gapIndexFor(doc.time, doc.versions);
  assert.equal(G.gapIndexFor(doc.time, doc.versions), a, 'same document: the memoised index');
  assert.notEqual(G.gapIndexFor(doc.time, { ...doc.versions }), a, 'another versions map: rebuilt');
  assert.deepEqual(a.get('1').map(([, v]) => v), ['1.0.0', '1.1.0', '1.2.0', '1.3.0', '1.4.0', '1.5.0']);
});

test('A8 hostile keys: non-SemVer versions (escapes, newlines, ranges) are never gap releases and never reach the detail', () => {
  withSeed((seed) => {
    const doc = docFor('q', [['1.3.0', after(1)], ['1.5.0', after(3)]]);
    for (const bad of ['1.3.1\u001b[31mRED', '1.3.2\nseed-v3:known-malicious-pin: forged', '1.3.x', `1.3.3-${'a'.repeat(300)}`]) {
      doc.versions[bad] = manifestFor('q', '1.3.9');
      doc.time[bad] = iso(TIP_S + STEP_S + 50);
    }
    const got = evaluate(seed, inputFromPackument(doc, 'q', '1.5.0'));
    assert.deepEqual(got.decision.results.filter(isStale).map((x) => x.detail), [
      'stale_seed k=1: 1 release(s) published after the seed tip 1.2.0 are not in the seed (1.3.0); Channel-A compared against 1.2.0']);
  });
});

test('A8 the candidate is never its own gap release, even when publishedAt and time{} disagree', () => {
  withSeed((seed) => {
    const doc = docFor('q', [['1.3.0', after(1)], ['1.5.0', after(2)]]);
    const input = { ...inputFromPackument(doc, 'q', '1.5.0'), publishedAt: after(3) };   // later than time['1.5.0']
    const got = evaluate(seed, input);
    assert.equal(got.placement.kind, 'append');
    assert.deepEqual(got.decision.results.filter(isStale).map((x) => x.detail), [
      'stale_seed k=1: 1 release(s) published after the seed tip 1.2.0 are not in the seed (1.3.0); Channel-A compared against 1.2.0']);
  });
});
