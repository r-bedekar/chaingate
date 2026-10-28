// U-05 Amendment 1 A1 — `chaingate.check/2`: table T-V and T-2 (D3) of U-05-S2-DECISION-TABLES-20260930.md.
//   * /1 is never edited; /2 = /1 + the documented delta, nothing else;
//   * a refused /2 explanation names the deciding advisory in its STRUCTURED form (text-only is not enough);
//   * historical /1 records — captured from the RELEASED 0.1.2 (test/fixtures/u05/historical-check-1.json, T1) —
//     still validate, and still explain byte-for-byte as 0.1.2 explained them;
//   * `why --from` and the CI consumer accept exactly the supported combinations and reject every other by name.
// 0.1.4 I1 (decision tables 0.1.4-IMPL-DECISION-TABLES-I1-A8-20261011.md, T-V3 and T-2' E1-E4): this runtime writes
// `chaingate.check/3` (cft-policy-1.2, explanation version 2 unchanged). /1 and /2 are never edited and still read; the
// historical /2 records are the REAL ones the 0.1.3 source wrote (test/fixtures/cft014/historical-check-2.json), the
// same way the /1 records were captured from 0.1.2.
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
import { explanationG2a } from './cft014-g2a-transform.mjs';
import { plainWording } from './cft015-plain-wording.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const V3 = path.join(HERE, '..', '..', 'seed', 'v3');
const S1 = path.join(V3, 'chaingate-check-1.schema.json');
const S2 = path.join(V3, 'chaingate-check-2.schema.json');
const S3 = path.join(V3, 'chaingate-check-3.schema.json');
const S5 = path.join(V3, 'chaingate-check-5.schema.json');   // what 0.1.6 writes
const FINDING = path.join(HERE, '..', 'fixtures', 'cft03', 'finding.schema.json');
const HIST = JSON.parse(fs.readFileSync(path.join(HERE, '..', 'fixtures', 'u05', 'historical-check-1.json'), 'utf8'));
const HIST2 = JSON.parse(fs.readFileSync(path.join(HERE, '..', 'fixtures', 'cft014', 'historical-check-2.json'), 'utf8'));
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
  return { v1: ajv.compile(read(S1)), v2: fs.existsSync(S2) ? ajv.compile(read(S2)) : null,
    v3: fs.existsSync(S3) ? ajv.compile(read(S3)) : null, v5: fs.existsSync(S5) ? ajv.compile(read(S5)) : null };
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

test('T-V3 /2 is byte-unchanged (the schema 0.1.3 shipped)', () => {
  assert.equal(createHash('sha256').update(fs.readFileSync(S2)).digest('hex'),
    '788a3f670d9d841c2deea096f56ba0bb0bae85916b4c2dbad56efbafe0f10802');
});

test('T-V3 /3 equals /2 with exactly the schema const changed and NOTE added to result_row (group 2a E9)', () => {
  const want = read(S2);
  const got = read(S3);
  want.$id = 'https://chaingate.dev/schemas/chaingate-check-3.json';
  for (const shape of want.oneOf) shape.properties.schema.const = 'chaingate.check/3';
  want.$defs.result_row.properties.result.enum = [...want.$defs.result_row.properties.result.enum, 'NOTE'];   // E9
  // title and description are prose and may name /3; nothing else may differ (explain_version stays 2)
  want.title = got.title; want.description = got.description;
  assert.deepEqual(got, want);
});

// ------------------------------------------------------------------------------------------------ records
test('T-V3 0.1.4 wrote /3 (E3), 0.1.6 writes /5: every synthetic golden case and the pinned refusals validate under /5, and as /3 once relabelled',
  { skip: Ajv2020 ? false : 'ajv not installed (U-01 A9 pins it as a devDependency)' }, () => {
    const { v1, v2, v3, v5 } = validators();
    assert.ok(v3, 'the /3 schema exists'); assert.ok(v5, 'the /5 schema exists');
    const { dir, dbPath } = buildSyntheticSeed();
    const seed = R.openSeed(dbPath, { trust: R.TRUST_UNSIGNED_DEV });
    try {
      for (const c of syntheticCases()) {
        const rec = buildCheckRecord({ seed, policy: c.policy, domainVersionCount: 'from-packument',
          input: inputFromPackument(c.doc, c.doc.name, c.version), request: { package: c.doc.name, version: c.version }, tool: TOOL });
        assert.equal(rec.schema, 'chaingate.check/5', c.id);
        assert.ok(v5(rec), `${c.id}: ${JSON.stringify(v5.errors)}`);
        // a synthetic case whose strict row warns carries the re-tier member, and every one is `raised` (no row moved); without
        // that member the same record labelled /3 is a /3 shape (the 0.1.4 format holds)
        if ('retier' in rec.decision) assert.equal(rec.decision.retier.placement, 'raised', c.id);
        const { retier, ...decision3 } = rec.decision;
        const as3 = { ...rec, schema: 'chaingate.check/3', decision: decision3 };
        assert.ok(v3(as3), `${c.id}: ${JSON.stringify(v3.errors)}`);
        assert.equal(v2(as3), false, `${c.id}: a /3 record is not a /2 record`);
        assert.equal(v1(as3), false, `${c.id}: a /3 record is not a /1 record`);
      }
    } finally { seed.close(); fs.rmSync(dir, { recursive: true, force: true }); }
    for (const cfg of [LIVE, WARNCFG]) assert.ok(v5(pinnedRefusal(cfg)), JSON.stringify(v5.errors));
  });

test('T-V a refused /3 explanation names the deciding advisory in its STRUCTURED form, and the text says the same', () => {
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
    '  evaluated disposition: BLOCK under cft-policy-1.3',   // E4; 1.3 since 0.1.6
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
test('T-2 D3 + E1/E4 the 0.1.4 explanation of each explain-golden case is the enumerated transform of the frozen golden', () => {
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
      // U-05 D1/D3 took the 1.0 golden to 1.1; I1 E1/E4 take it on to 1.2, 0.1.6 to 1.3. The explanation version stays 2.
      const pol = (t) => t.replaceAll('cft-policy-1.0', 'cft-policy-1.3');
      let want;
      if (g.structured.result === 'evaluated') {
        want = { text: g.text.map(pol), structured: JSON.parse(pol(JSON.stringify(g.structured))) };
        want.structured.explain_version = 'chaingate-explain-2';
        want = explanationG2a(want).explanation;     // 0.1.4 group 2a E6/E7, from the golden's own rows
      } else {
        // refused: an unpinned refusal is decided by the input row alone
        const reason = g.structured.refusal;
        const [head] = g.text;
        want = {
          text: [head, `  reason: ${reason}`, `  evaluated disposition: ${g.structured.disposition} under cft-policy-1.3`,
            '  decided by:', `    seed-v3:input: ${reason}`, '  no finding was evaluated: this is NOT a clean result'],
          structured: { ...g.structured, explain_version: 'chaingate-explain-2',
            decided_by: [{ gate: 'seed-v3:input', detail: reason }] },
        };
      }
      assert.deepEqual(rec.explanation, plainWording(want), id);   // 0.1.5 plain wording
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

test('T-V3 historical /2 records from the 0.1.3 source still validate under /2 and explain byte-for-byte',
  { skip: Ajv2020 ? false : 'ajv not installed' }, () => {
    const { v2, v3 } = validators();
    assert.equal(HIST2.captured_with, '@cgsec/chaingate 0.1.3 source b66edfdd (tag cgsec-chaingate-v0.1.3)');
    assert.deepEqual(HIST2.records.map((r) => r.id), ['evaluated-append-live', 'refused-pinned-live', 'refused-pinned-warn']);
    for (const { id, record } of HIST2.records) {
      assert.equal(record.schema, 'chaingate.check/2', id);
      assert.equal(record.decision.policy_version, 'cft-policy-1.1', id);
      assert.ok(v2(record), `${id}: ${JSON.stringify(v2.errors)}`);
      assert.equal(v3(record), false, `${id}: a /2 record is not a /3 record`);
      const again = explain(record);
      assert.equal(JSON.stringify(again), JSON.stringify(record.explanation), `${id}: re-explained byte-for-byte`);
    }
  });

// ------------------------------------------------------------------------------------------------ combinations
const hist = (id) => clone(HIST.records.find((r) => r.id === id).record);
const hist2 = (id) => clone(HIST2.records.find((r) => r.id === id).record);
const evaluated1 = () => hist('allow-append');
const refused1 = () => hist('refuse-missing-manifest');
const refused2 = () => hist2('refused-pinned-live');
const evaluated2 = () => hist2('evaluated-append-live');
// 0.1.6 writes /5; a /3 record (0.1.4) is the same record relabelled with 0.1.4's policy id (no /5-only member is present)
const as3 = (r) => { r.schema = 'chaingate.check/3'; r.decision.policy_version = 'cft-policy-1.2'; r.explanation = explain(r); return r; };
const refused5 = () => clone(pinnedRefusal(LIVE));
const refused3 = () => as3(refused5());
const evaluated3 = () => as3(evaluated5());
const evaluated5 = () => {
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
  ['/3 with explain-1', evaluated3, (r) => { r.explanation.structured.explain_version = 'chaingate-explain-1'; }, /explain_version/],
  ['/3 with policy 1.1', evaluated3, (r) => { r.decision.policy_version = 'cft-policy-1.1'; }, /policy_version/],
  ['/2 with policy 1.2', evaluated2, (r) => { r.decision.policy_version = 'cft-policy-1.2'; }, /policy_version/],
  ['/3 with an unknown seed contract', evaluated3, (r) => { r.seed.contract_version = 'cft-seed-v3-contract-9.9'; }, /seed\.contract_version/],
  ['/3 with detection contract 1.1', evaluated3, (r) => { r.finding.contract_version = 'cft-detection-contract-1.1'; }, /finding\.contract_version/],
  ['an unknown schema id', evaluated3, (r) => { r.schema = 'chaingate.check/9'; }, /schema/],
  ['/3 refused without decided_by', refused3, (r) => { delete r.explanation.structured.decided_by; }, /decided_by/],
  ['/3 refused whose decided_by omits the pin', refused3, (r) => { r.explanation.structured.decided_by.shift(); }, /decided_by/],
  ['/2 refused without decided_by', refused2, (r) => { delete r.explanation.structured.decided_by; }, /decided_by/],
  ['/2 refused whose decided_by omits the pin', refused2, (r) => { r.explanation.structured.decided_by.shift(); }, /decided_by/],
  ['/1 refused carrying decided_by', refused1, (r) => { r.explanation.structured.decided_by = []; }, /decided_by/],
];

test('T-V the CI consumer accepts every supported combination (/1, /2, /3, /5) and rejects every other by name', () => {
  for (const [label, make] of [['/1 evaluated', evaluated1], ['/1 refused', refused1], ['/2 evaluated', evaluated2], ['/2 refused', refused2],
    ['/3 evaluated', evaluated3], ['/3 refused', refused3], ['/5 evaluated', evaluated5], ['/5 refused', refused5]]) {
    assert.deepEqual(validateRecord(make()), [], label);
  }
  for (const [label, make, mutate, names] of MUTATIONS) {
    const r = make(); mutate(r);
    const problems = validateRecord(r);
    assert.ok(problems.length > 0, `${label}: must be rejected`);
    assert.ok(problems.some((m) => names.test(m)), `${label}: must name the member (${JSON.stringify(problems)})`);
  }
});

test('T-V why --from explains every supported combination (/1, /2, /3, /5) and refuses every other by name', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'u05-why-'));
  const save = (r, n) => { const f = path.join(dir, `${n}.json`); fs.writeFileSync(f, JSON.stringify(r)); return f; };
  try {
    for (const [label, make] of [['/1 evaluated', evaluated1], ['/1 refused', refused1], ['/2 evaluated', evaluated2], ['/2 refused', refused2],
    ['/3 evaluated', evaluated3], ['/3 refused', refused3], ['/5 evaluated', evaluated5], ['/5 refused', refused5]]) {
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
