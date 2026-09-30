// U-05 Amendment 1 A1 — `chaingate.check/2`: table T-V and T-2 (D3) of U-05-S2-DECISION-TABLES-20260930.md.
//   * /1 is never edited; /2 = /1 + the documented delta, nothing else;
//   * a refused /2 explanation names the deciding advisory in its STRUCTURED form (text-only is not enough);
//   * historical /1 records — captured from the RELEASED 0.1.2 (test/fixtures/u05/historical-check-1.json, T1) —
//     still validate, and still explain byte-for-byte as 0.1.2 explained them;
//   * `why --from` and the CI consumer accept exactly the supported combinations and reject every other by name.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import R from '../../seed/v3/reader.js';
import { explain } from '../../seed/v3/explain.js';
import { buildCheckRecord, inputFromPackument } from '../../cli/check-record.js';
import { explainSaved } from '../../cli/commands/why.js';
import { validateRecord } from '../../examples/ci/chaingate-ci.mjs';
import { syntheticCases, buildSyntheticSeed } from './u01-cases.mjs';
import { EXPLAIN_GOLDEN_IDS } from './u01-explain-goldens.capture.mjs';
import { buildSeed, openFixtureSeed, docFor, after, LIVE, WARNCFG } from './u05-fixtures.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const V3 = path.join(HERE, '..', '..', 'seed', 'v3');
const S1 = path.join(V3, 'chaingate-check-1.schema.json');
const S2 = path.join(V3, 'chaingate-check-2.schema.json');
const FINDING = path.join(HERE, '..', 'fixtures', 'cft03', 'finding.schema.json');
const HIST = JSON.parse(fs.readFileSync(path.join(HERE, '..', 'fixtures', 'u05', 'historical-check-1.json'), 'utf8'));
const EXPLAIN_GOLDEN = JSON.parse(fs.readFileSync(path.join(HERE, '..', 'fixtures', 'u01-goldens', 'explain.json'), 'utf8'));
const read = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
const clone = (o) => JSON.parse(JSON.stringify(o));
const TOOL = { name: 'chaingate', version: 'test' };

let Ajv2020 = null;
try { Ajv2020 = createRequire(import.meta.url)('ajv/dist/2020.js'); } catch { /* not installed */ }
function validators() {
  const Ctor = Ajv2020.default || Ajv2020;
  const ajv = new Ctor({ strict: true, strictRequired: false, allErrors: true });
  ajv.addSchema(read(FINDING));
  return { v1: ajv.compile(read(S1)), v2: fs.existsSync(S2) ? ajv.compile(read(S2)) : null };
}

function pinnedRefusal(cfg, layout = '1.1') {
  const s = buildSeed({ layout });
  const seed = openFixtureSeed(s.dbPath);
  try {
    const doc = docFor('p', [['1.3.0', after(), null]]);
    return buildCheckRecord({ seed, policy: cfg, domainVersionCount: 'from-packument', input: inputFromPackument(doc, 'p', '1.3.0'),
      request: { package: 'p', version: '1.3.0' }, tool: TOOL });
  } finally { seed.close(); s.cleanup(); }
}

// ------------------------------------------------------------------------------------------------ schema
test('T-V /1 is byte-unchanged', () => {
  assert.equal(createHash('sha256').update(fs.readFileSync(S1)).digest('hex'),
    '6386dddff9f916917effe493cd90d4f5a0ba85769d6fb5dc840e42662ce41bef');
});

test('T-V /2 equals /1 plus exactly the documented delta', () => {
  const want = read(S1);
  const got = read(S2);
  want.$id = 'https://chaingate.dev/schemas/chaingate-check-2.json';
  for (const shape of want.oneOf) shape.properties.schema.const = 'chaingate.check/2';
  want.$defs.explanation_evaluated.properties.structured.properties.explain_version.const = 'chaingate-explain-2';
  const ref = want.$defs.explanation_refused.properties.structured;
  ref.properties.explain_version.const = 'chaingate-explain-2';
  ref.required = [...ref.required, 'decided_by'];
  ref.properties.decided_by = clone(want.$defs.explanation_evaluated.properties.structured.properties.decided_by);
  // title and description are prose and may name /2; nothing else may differ
  want.title = got.title; want.description = got.description;
  assert.deepEqual(got, want);
});

// ------------------------------------------------------------------------------------------------ records
test('T-V 0.1.3 writes /2: every synthetic golden case and the pinned refusals validate under /2',
  { skip: Ajv2020 ? false : 'ajv not installed (U-01 A9 pins it as a devDependency)' }, () => {
    const { v1, v2 } = validators();
    assert.ok(v2, 'the /2 schema exists');
    const { dir, dbPath } = buildSyntheticSeed();
    const seed = R.openSeed(dbPath, { trust: R.TRUST_UNSIGNED_DEV });
    try {
      for (const c of syntheticCases()) {
        const rec = buildCheckRecord({ seed, policy: c.policy, domainVersionCount: 'from-packument',
          input: inputFromPackument(c.doc, c.doc.name, c.version), request: { package: c.doc.name, version: c.version }, tool: TOOL });
        assert.equal(rec.schema, 'chaingate.check/2', c.id);
        assert.ok(v2(rec), `${c.id}: ${JSON.stringify(v2.errors)}`);
        assert.equal(v1(rec), false, `${c.id}: a /2 record is not a /1 record`);
      }
    } finally { seed.close(); fs.rmSync(dir, { recursive: true, force: true }); }
    for (const cfg of [LIVE, WARNCFG]) assert.ok(v2(pinnedRefusal(cfg)), JSON.stringify(v2.errors));
  });

test('T-V a refused /2 explanation names the deciding advisory in its STRUCTURED form, and the text says the same', () => {
  const live = pinnedRefusal(LIVE);
  assert.equal(live.result, 'refused');
  const s = live.explanation.structured;
  assert.equal(s.explain_version, 'chaingate-explain-2');
  assert.deepEqual(s.decided_by.map((x) => x.gate), ['seed-v3:known-malicious-pin', 'seed-v3:input']);
  assert.match(s.decided_by[0].detail, /recorded advisory ADV-P-130 pins p@1\.3\.0/);
  const reason = 'Error: no raw packument manifest supplied for p@1.3.0';
  assert.deepEqual(live.explanation.text, [
    'p@1.3.0: BLOCK — REFUSED: no finding exists for this input',
    `  reason: ${reason}`,
    '  evaluated disposition: BLOCK under cft-policy-1.1',
    '  decided by:',
    '    seed-v3:known-malicious-pin: recorded advisory ADV-P-130 pins p@1.3.0 (source synthetic-fixture)',
    `    seed-v3:input: ${reason}`,
    '  no finding was evaluated: this is NOT a clean result',
  ]);
  const warn = pinnedRefusal(WARNCFG);
  assert.deepEqual(warn.explanation.structured.decided_by.map((x) => x.gate), ['seed-v3:known-malicious-pin'],
    'under WARN only the pin decides');
  assert.equal(warn.effective.action, 'BLOCK');
});

// ------------------------------------------------------------------------------------------------ T-2 D3
test('T-2 D3 the 0.1.3 explanation of each explain-golden case is the enumerated transform of the frozen golden', () => {
  const { dir, dbPath } = buildSyntheticSeed();
  const seed = R.openSeed(dbPath, { trust: R.TRUST_UNSIGNED_DEV });
  try {
    const cases = new Map(syntheticCases().map((c) => [c.id, c]));
    for (const id of EXPLAIN_GOLDEN_IDS) {
      const c = cases.get(id);
      const rec = buildCheckRecord({ seed, policy: c.policy, domainVersionCount: 'from-packument',
        input: inputFromPackument(c.doc, c.doc.name, c.version), request: { package: c.doc.name, version: c.version },
        tool: { name: 'chaingate', version: 'golden' } });
      const g = clone(EXPLAIN_GOLDEN.find((x) => x.id === id).explanation);
      const pol = (t) => t.replaceAll('cft-policy-1.0', 'cft-policy-1.1');
      let want;
      if (g.structured.result === 'evaluated') {
        want = { text: g.text.map(pol), structured: JSON.parse(pol(JSON.stringify(g.structured))) };
        want.structured.explain_version = 'chaingate-explain-2';
      } else {
        // refused: an unpinned refusal is decided by the input row alone
        const reason = g.structured.refusal;
        const [head] = g.text;
        want = {
          text: [head, `  reason: ${reason}`, `  evaluated disposition: ${g.structured.disposition} under cft-policy-1.1`,
            '  decided by:', `    seed-v3:input: ${reason}`, '  no finding was evaluated: this is NOT a clean result'],
          structured: { ...g.structured, explain_version: 'chaingate-explain-2',
            decided_by: [{ gate: 'seed-v3:input', detail: reason }] },
        };
      }
      assert.deepEqual(rec.explanation, want, id);
    }
  } finally { seed.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

// ------------------------------------------------------------------------------------------------ historical /1
test('T-V historical /1 records from the released 0.1.2 still validate and explain byte-for-byte',
  { skip: Ajv2020 ? false : 'ajv not installed' }, () => {
    const { v1 } = validators();
    assert.equal(HIST.captured_with, '@cgsec/chaingate 0.1.2');
    assert.equal(HIST.records.length, 13);
    for (const { id, record } of HIST.records) {
      assert.equal(record.schema, 'chaingate.check/1', id);
      assert.ok(v1(record), `${id}: ${JSON.stringify(v1.errors)}`);
      const again = explain(record);
      assert.equal(JSON.stringify(again), JSON.stringify(record.explanation), `${id}: re-explained byte-for-byte`);
      const g = EXPLAIN_GOLDEN.find((x) => x.id === id);
      if (g) assert.deepEqual(record.explanation, g.explanation, `${id}: equals the frozen explanation golden`);
    }
  });

// ------------------------------------------------------------------------------------------------ combinations
const hist = (id) => clone(HIST.records.find((r) => r.id === id).record);
const evaluated1 = () => hist('allow-append');
const refused1 = () => hist('refuse-missing-manifest');
const refused2 = () => clone(pinnedRefusal(LIVE));
const evaluated2 = () => {
  const s = buildSeed({ layout: '1.1' });
  const seed = openFixtureSeed(s.dbPath);
  try {
    return clone(buildCheckRecord({ seed, policy: LIVE, domainVersionCount: 'from-packument',
      input: inputFromPackument(docFor('p', [['1.4.0', after()]]), 'p', '1.4.0'), request: { package: 'p', version: '1.4.0' }, tool: TOOL }));
  } finally { seed.close(); s.cleanup(); }
};

const MUTATIONS = [
  ['/1 with explain-2', evaluated1, (r) => { r.explanation.structured.explain_version = 'chaingate-explain-2'; }, /explain_version/],
  ['/2 with explain-1', evaluated2, (r) => { r.explanation.structured.explain_version = 'chaingate-explain-1'; }, /explain_version/],
  ['/1 with policy 1.1', evaluated1, (r) => { r.decision.policy_version = 'cft-policy-1.1'; }, /policy_version/],
  ['/2 with policy 1.0', evaluated2, (r) => { r.decision.policy_version = 'cft-policy-1.0'; }, /policy_version/],
  ['/1 with seed contract 1.1', evaluated1, (r) => { r.seed.contract_version = 'cft-seed-v3-contract-1.1'; }, /seed\.contract_version/],
  ['/2 with an unknown seed contract', evaluated2, (r) => { r.seed.contract_version = 'cft-seed-v3-contract-9.9'; }, /seed\.contract_version/],
  ['/2 with detection contract 1.1', evaluated2, (r) => { r.finding.contract_version = 'cft-detection-contract-1.1'; }, /finding\.contract_version/],
  ['/1 with detection contract 1.1', evaluated1, (r) => { r.finding.contract_version = 'cft-detection-contract-1.1'; }, /finding\.contract_version/],
  ['an unknown schema id', evaluated2, (r) => { r.schema = 'chaingate.check/3'; }, /schema/],
  ['/2 refused without decided_by', refused2, (r) => { delete r.explanation.structured.decided_by; }, /decided_by/],
  ['/2 refused whose decided_by omits the pin', refused2, (r) => { r.explanation.structured.decided_by.shift(); }, /decided_by/],
  ['/1 refused carrying decided_by', refused1, (r) => { r.explanation.structured.decided_by = []; }, /decided_by/],
];

test('T-V the CI consumer accepts both supported combinations and rejects every other by name', () => {
  for (const [label, make] of [['/1 evaluated', evaluated1], ['/1 refused', refused1], ['/2 evaluated', evaluated2], ['/2 refused', refused2]]) {
    assert.deepEqual(validateRecord(make()), [], label);
  }
  for (const [label, make, mutate, names] of MUTATIONS) {
    const r = make(); mutate(r);
    const problems = validateRecord(r);
    assert.ok(problems.length > 0, `${label}: must be rejected`);
    assert.ok(problems.some((m) => names.test(m)), `${label}: must name the member (${JSON.stringify(problems)})`);
  }
});

test('T-V why --from explains both supported combinations and refuses every other by name', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'u05-why-'));
  const save = (r, n) => { const f = path.join(dir, `${n}.json`); fs.writeFileSync(f, JSON.stringify(r)); return f; };
  try {
    for (const [label, make] of [['/1 evaluated', evaluated1], ['/1 refused', refused1], ['/2 evaluated', evaluated2], ['/2 refused', refused2]]) {
      const rec = make();
      const out = explainSaved(save(rec, label.replace(/\W/g, '_')));
      assert.equal(out.error, undefined, `${label}: ${out.error}`);
      assert.equal(JSON.stringify(out.explanation), JSON.stringify(rec.explanation), `${label}: same bytes as the saved explanation`);
    }
    MUTATIONS.forEach(([label, make, mutate, names], i) => {
      const r = make(); mutate(r);
      const out = explainSaved(save(r, `m${i}`));
      assert.ok(out.error, `${label}: must be refused`);
      assert.match(out.error, names, `${label}: must name the member`);
    });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
