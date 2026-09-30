// U-01 A7 — explain() is pure and deterministic, and complete about what it could not see.
//
// U-05 (Amendment 1): the explanation goldens are VERSION-1 explanations of chaingate.check/1 records. Since 0.1.3
// writes /2, the records explained here are the /1 records the RELEASED 0.1.2 produced for the same cases
// (test/fixtures/u05/historical-check-1.json, T1 capture). The goldens are unchanged and still reproduced byte for
// byte; version 2 is tested in u05-check2.test.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { explain } from '../../seed/v3/explain.js';
import { EXPLAIN_GOLDEN_IDS } from './u01-explain-goldens.capture.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GOLDEN = JSON.parse(fs.readFileSync(path.join(HERE, '..', 'fixtures', 'u01-goldens', 'explain.json'), 'utf8'));
const HISTORICAL = JSON.parse(fs.readFileSync(path.join(HERE, '..', 'fixtures', 'u05', 'historical-check-1.json'), 'utf8'));
const RECORDS = EXPLAIN_GOLDEN_IDS.map((id) => HISTORICAL.records.find((r) => r.id === id).record);
const byId = (id) => RECORDS[EXPLAIN_GOLDEN_IDS.indexOf(id)];

function deepFreeze(o) {
  if (o && typeof o === 'object' && !Object.isFrozen(o)) {
    Object.freeze(o);
    for (const v of Object.values(o)) deepFreeze(v);
  }
  return o;
}

/** Run fn with every impure source made to throw: clock, randomness, network, environment. */
function hostile(fn) {
  const saved = { Date: globalThis.Date, random: Math.random, fetch: globalThis.fetch, now: performance.now,
    envDesc: Object.getOwnPropertyDescriptor(process, 'env') };
  const boom = (what) => () => { throw new Error(`explain touched ${what}`); };
  globalThis.Date = new Proxy(saved.Date, { construct: boom('Date'), apply: boom('Date'), get: (t, k) => (k === 'now' ? boom('Date.now') : t[k]) });
  Math.random = boom('Math.random');
  globalThis.fetch = boom('fetch');
  performance.now = boom('performance.now');
  Object.defineProperty(process, 'env', { get: boom('process.env'), configurable: true });
  try { return fn(); } finally {
    globalThis.Date = saved.Date; Math.random = saved.random; globalThis.fetch = saved.fetch;
    performance.now = saved.now; Object.defineProperty(process, 'env', saved.envDesc);
  }
}

test('A7 explain is pure: no clock, randomness, network or environment; input not written; same bytes', () => {
  for (const rec of RECORDS) {
    const input = deepFreeze(structuredClone({ ...rec, explanation: undefined }));
    const a = hostile(() => explain(input));
    const b = hostile(() => explain(input));
    assert.equal(JSON.stringify(a), JSON.stringify(b), 'same input, same bytes');
    assert.equal(JSON.stringify(a), JSON.stringify(rec.explanation), 'equals the explanation in the record');
  }
});

test('A7 explanation goldens are reproduced byte for byte', () => {
  assert.deepEqual(GOLDEN.map((g) => g.id), EXPLAIN_GOLDEN_IDS);
  for (const [i, g] of GOLDEN.entries()) {
    assert.equal(JSON.stringify(RECORDS[i].explanation), JSON.stringify(g.explanation), g.id);
  }
});

test('A7 a publisher constituent NOT_EVALUATED beside a broken one survives in text and structure', () => {
  const e = byId('publisher-broke-beside-unevaluated').explanation;
  const cons = Object.fromEntries(e.structured.channel_a.publisher_constituents.map((c) => [c.name, c]));
  assert.equal(e.structured.channel_a.groups.find((g) => g.name === 'publisher').state, 'BROKE');
  assert.equal(cons.identity.state, 'BROKE');
  assert.deepEqual(cons.maintainers, { name: 'maintainers', state: 'NOT_EVALUATED', reason: 'unsupported_field' });
  assert.ok(e.text.includes('      constituent identity: BROKE'));
  assert.ok(e.text.includes('      constituent maintainers: NOT EVALUATED (unsupported_field)'));
  assert.ok(e.structured.not_evaluated.some((m) => m.where === 'channel_a.publisher_constituent' && m.name === 'maintainers'));
  assert.ok(e.text.some((l) => /NOT a clean bill of health/.test(l)));
});

test('A7 an uncovered package and a cold start are never rendered as clean', () => {
  const u = byId('uncovered').explanation;
  assert.equal(u.structured.evaluated_any, false);
  assert.equal(u.structured.not_evaluated.length, 12);
  assert.ok(u.text.includes('  nothing in this finding was evaluated: this is NOT a clean result'));
  assert.ok(!u.text.some((l) => /: held$/.test(l)), 'no observation of an uncovered package is "held"');

  const c = byId('cold-start-new-major').explanation;
  assert.equal(c.structured.placement.kind, 'new-major-cold-start');
  const unplaced = c.structured.channel_a.groups.concat(c.structured.channel_a.publisher_constituents);
  assert.ok(unplaced.every((s) => s.state === 'NOT_EVALUATED' && /no recorded lineage carries major 2/.test(s.reason)));
  assert.ok(c.text.some((l) => /NOT a clean bill of health/.test(l)));
});

test('A7 a refusal explains the refusal only', () => {
  const r = byId('refuse-malformed-npmuser').explanation;
  assert.equal(r.structured.result, 'refused');
  assert.ok(!('channel_a' in r.structured) && !('dac_trajectory' in r.structured) && !('placement' in r.structured));
  assert.match(r.text[0], /REFUSED: no finding exists for this input/);
  assert.match(r.text[1], /_npmUser is string/);
  assert.equal(r.text.at(-1), '  nothing was evaluated: this is NOT a clean result');
  assert.throws(() => explain({ schema: 'chaingate.check/1', result: 'tool_error' }), /nothing to explain/);
  assert.throws(() => explain({ schema: 'chaingate.check/9', result: 'refused' }), /no explanation for check schema/);
});

test('A7 control: the hostile environment does throw when touched', () => {
  assert.throws(() => hostile(() => Date.now()), /touched Date.now/);
  assert.throws(() => hostile(() => new Date()), /touched Date/);
  assert.throws(() => hostile(() => Math.random()), /touched Math.random/);
  assert.throws(() => hostile(() => process.env.HOME), /touched process.env/);
  assert.ok(typeof Date.now() === 'number' && process.env !== undefined, 'restored afterwards');
});
