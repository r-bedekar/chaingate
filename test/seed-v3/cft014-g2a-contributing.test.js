// 0.1.4 group 2, unit 2a — contributing rows are NOTE, never a WARN on their own (r3 §18.7, §18.15, §18.18); the seed-v3
// GateResult carries structured `rows`; the store keeps the record's class current. Expected results: decision tables
// ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G2-TIER0-20261011.md §2 (D-N1..D-N9, E6..E12, G2a-1..G2a-9), written
// before this file.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import G from '../../seed/v3/gate.js';
import POL from '../../seed/v3/policy.js';
import { createGateRunner } from '../../gates/index.js';
import { openWitnessDB } from '../../witness/db.js';
import { createWitness } from '../../witness/store.js';
import { REASON, clears } from '../../witness/decision-rule.js';
import { buildCheckRecord, inputFromPackument } from '../../cli/check-record.js';
import { validateRecord } from '../../examples/ci/chaingate-ci.mjs';
import { buildSeed, openFixtureSeed, docFor, manifestFor, after, LIVE } from './u05-fixtures.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const V3 = path.join(HERE, '..', '..', 'seed', 'v3');
const HIST2 = JSON.parse(fs.readFileSync(path.join(HERE, '..', 'fixtures', 'cft014', 'historical-check-2.json'), 'utf8'));
const TOOL = { name: 'chaingate', version: 'test' };
const DVC = 3;
const ANY = 'seed-v3:dac-trajectory:any';
const SURFACE = 'seed-v3:dac-trajectory:surface';
const CONTRIB = (n) => `${n}/4 witnesses broke, threshold 1 (contributing in cft-policy-1.2: shown beside a named row, `
  + 'never a warning on its own)';

const hooked = () => manifestFor('q', '1.5.0', { scripts: { postinstall: 'node x.js' } });             // install_introduced
const hookedBig = () => manifestFor('q', '1.5.0', { scripts: { postinstall: 'node x.js' },               // + size jump
  dist: { unpackedSize: 10_000, attestations: { url: 'https://x' } } });

function withSeed(fn) {
  const s = buildSeed({ layout: '1.1' });
  const seed = openFixtureSeed(s.dbPath);
  try { return fn(seed); } finally { seed.close(); s.cleanup(); }
}
const evaluate = (seed, manifest) => G.evaluateCandidate(seed, { config: LIVE, domainVersionCount: DVC },
  inputFromPackument(docFor('q', [['1.5.0', after(1), manifest]]), 'q', '1.5.0'));
const row = (d, gate) => d.results.find((x) => x.gate === gate);

test('G2a-1 (E6/E7) the loose seed rule alone is NOTE, the disposition ALLOW, the check record effective ALLOW', () => {
  withSeed((seed) => {
    const { decision, finding } = evaluate(seed, hooked());
    assert.equal(finding.dac_trajectory.n_broke, 1, 'fixture precondition: exactly one DAC predicate broke');
    assert.ok(finding.channel_a.n_broke < 3, 'fixture precondition: Channel-A below its threshold');
    assert.deepEqual(row(decision, ANY), { gate: ANY, result: 'NOTE', detail: CONTRIB(1) });
    assert.equal(row(decision, SURFACE).result, 'ALLOW');
    assert.equal(decision.disposition, 'ALLOW');
    const rec = buildCheckRecord({ seed, policy: LIVE, domainVersionCount: DVC,
      input: inputFromPackument(docFor('q', [['1.5.0', after(1), hooked()]]), 'q', '1.5.0'),
      request: { package: 'q', version: '1.5.0' }, tool: TOOL });
    assert.equal(rec.effective.action, 'ALLOW');
    assert.deepEqual(validateRecord(rec), [], 'the CI consumer accepts a /3 record carrying NOTE');
  });
});

test('G2a-2 (E6/E10) the strict tier stays a WARN; the loose rule beside it is NOTE and shown after the bearing rows', () => {
  withSeed((seed) => {
    const { decision, finding } = evaluate(seed, hookedBig());
    assert.equal(finding.dac_trajectory.n_broke, 2, 'fixture precondition: two DAC predicates broke');
    assert.equal(row(decision, SURFACE).result, 'WARN');
    assert.deepEqual(row(decision, ANY), { gate: ANY, result: 'NOTE', detail: CONTRIB(2) });
    assert.equal(decision.disposition, 'WARN');
    const gate = G.createSeedV3Gate({ seed, config: LIVE, domainVersionCount: DVC });
    const gr = gate.evaluate(inputFromPackument(docFor('q', [['1.5.0', after(1), hookedBig()]]), 'q', '1.5.0'));
    assert.equal(gr.result, 'WARN');
    const also = ` | also (contributing): ${ANY}: ${CONTRIB(2)}`;
    assert.ok(gr.detail.startsWith(`cft-policy-1.3: ${SURFACE}: 2/4 witnesses broke, threshold 2`), gr.detail);   // 1.3 since 0.1.6
    assert.ok(gr.detail.includes(also), gr.detail);
    assert.ok(gr.detail.indexOf(also) < gr.detail.indexOf(' [placement: '), 'after the bearing rows, before the suffixes');
  });
});

const PRIOR = Array.from({ length: 9 }, (_, i) => ({ version: `1.${i}.0` }));
const runInput = { packageName: 'q', version: '1.9.0', history: PRIOR };

test('G2a-3 (E8) a WARN from a contributing pilot gate is NOTE (detail verbatim) and the disposition ALLOW', () => {
  const run = createGateRunner({ modules: [{ name: 'release-age', evaluate: () => ({ gate: 'release-age', result: 'WARN',
    detail: 'release age 10h < threshold 72h' }) }] });
  const d = run(runInput);
  assert.deepEqual(d.results, [{ gate: 'release-age', result: 'NOTE', detail: 'release age 10h < threshold 72h' }]);
  assert.equal(d.disposition, 'ALLOW');
});

test('G2a-4 a WARN from a module not in the role table still aggregates to WARN', () => {
  const run = createGateRunner({ modules: [{ name: 'x-unlisted', evaluate: () => ({ result: 'WARN', detail: 'w' }) }] });
  const d = run(runInput);
  assert.equal(d.results[0].result, 'WARN');
  assert.equal(d.disposition, 'WARN');
});

test('G2a-6 (E11) the seed-v3 GateResult carries rows; the runner keeps valid rows and drops malformed ones', () => {
  withSeed((seed) => {
    const gate = G.createSeedV3Gate({ seed, config: LIVE, domainVersionCount: DVC, onDecision: (d) => { gate.last = d; } });
    const gr = gate.evaluate(inputFromPackument(docFor('q', [['1.5.0', after(1), hookedBig()]]), 'q', '1.5.0'));
    assert.deepEqual(gr.rows, gate.last.results.map((x) => ({ gate: x.gate, result: x.result })));
    const kept = createGateRunner({ modules: [gate] })({ ...inputFromPackument(docFor('q', [['1.5.0', after(1), hookedBig()]]),
      'q', '1.5.0'), history: [] });
    assert.deepEqual(kept.results[0].rows, gr.rows, 'the runner keeps a valid rows member');
  });
  for (const bad of [{ rows: 'x' }, { rows: [{ gate: 'seed-v3:invented', result: 'WARN' }] },
    { rows: [{ gate: ANY, result: 'MAYBE' }] }, { rows: Array.from({ length: 33 }, () => ({ gate: ANY, result: 'NOTE' })) }]) {
    const run = createGateRunner({ modules: [{ name: 'seed-v3', evaluate: () => ({ gate: 'seed-v3', result: 'ALLOW', detail: 'd', ...bad }) }] });
    const d = run({ ...runInput, history: [] });
    assert.equal(d.results[0].result, 'ALLOW', 'the GateResult is still used');
    assert.equal(Object.hasOwn(d.results[0], 'rows'), false, `malformed rows dropped: ${JSON.stringify(bad).slice(0, 60)}`);
  }
});

let Ajv2020 = null;
try { Ajv2020 = createRequire(import.meta.url)('ajv/dist/2020.js'); } catch { /* not installed */ }
test('G2a-5 (E9) NOTE is valid in /3 records only: the /2 schema and the CI consumer reject it in a /2 record',
  { skip: Ajv2020 ? false : 'ajv not installed' }, () => {
    const Ctor = Ajv2020.default || Ajv2020;
    const ajv = new Ctor({ strict: true, strictRequired: false, allErrors: true });
    ajv.addSchema(JSON.parse(fs.readFileSync(path.join(HERE, '..', 'fixtures', 'cft03', 'finding.schema.json'), 'utf8')));
    const v2 = ajv.compile(JSON.parse(fs.readFileSync(path.join(V3, 'chaingate-check-2.schema.json'), 'utf8')));
    const v3 = ajv.compile(JSON.parse(fs.readFileSync(path.join(V3, 'chaingate-check-3.schema.json'), 'utf8')));
    const v5 = ajv.compile(JSON.parse(fs.readFileSync(path.join(V3, 'chaingate-check-5.schema.json'), 'utf8')));
    withSeed((seed) => {
      const rec = buildCheckRecord({ seed, policy: LIVE, domainVersionCount: DVC,
        input: inputFromPackument(docFor('q', [['1.5.0', after(1), hooked()]]), 'q', '1.5.0'),
        request: { package: 'q', version: '1.5.0' }, tool: TOOL });
      assert.ok(rec.decision.results.some((x) => x.result === 'NOTE'), 'precondition: the record carries NOTE');
      assert.ok(v5(rec), JSON.stringify(v5.errors));   // since 0.1.6 the runtime writes /5
      const { retier, ...decision } = rec.decision;   // the same record as 0.1.4 wrote it: /3, no re-tier member
      assert.ok(v3({ ...rec, schema: 'chaingate.check/3', decision }), JSON.stringify(v3.errors));
    });
    const two = JSON.parse(JSON.stringify(HIST2.records.find((r) => r.id === 'evaluated-append-live').record));
    two.decision.results.push({ gate: ANY, result: 'NOTE', detail: 'x' });
    assert.equal(v2(two), false, 'the /2 schema rejects NOTE');
    assert.ok(validateRecord(two).length > 0, 'the CI consumer rejects NOTE in a /2 record');
  });

test('G2a-7 (C2) a contributing-only ALLOW clears a pin and an input BLOCK; the NOTE text carries no C2 marker', () => {
  const detail = `cft-policy-1.3: seed-v3:known-malicious-pin: no recorded advisory pins this version | also (contributing): ${ANY}: ${CONTRIB(1)}`;
  assert.ok(clears(REASON.PIN, [{ gate: 'seed-v3', result: 'ALLOW', detail }]));
  assert.ok(clears(REASON.INPUT, [{ gate: 'seed-v3', result: 'ALLOW', detail }]));
  for (const marker of ['seed-v3:input', 'could not run', 'seed-v3:known-malicious-pin: recorded advisory']) {
    assert.ok(!CONTRIB(1).includes(marker), marker);
  }
});

test('G2a-8 (E12) the store writes a new row when the class changes, not on a repeat, not on a repeated failure', async () => {
  const s = buildSeed({ layout: '1.1' });
  const seed = openFixtureSeed(s.dbPath);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g2a-'));
  const quiet = { info() {}, warn() {}, error() {} };
  const db = openWitnessDB(path.join(dir, 'witness.db'));
  db.applySchema();                                   // as proxy/server.js does after opening
  try {
    const gate = G.createSeedV3Gate({ seed, config: LIVE, domainVersionCount: 'from-packument' });
    let failing = false;
    const flaky = { ...gate, evaluate: (i) => { if (failing) throw new Error('seed unreadable'); return gate.evaluate(i); } };
    const witness = createWitness({ db, runGates: createGateRunner({ modules: [flaky] }), config: {}, logger: quiet });
    const doc = () => docFor('q', [['1.5.0', after(1), hookedBig()]]);
    witness.observePackument('q', doc());                                         // baseline + first row (strict WARN)
    const n0 = db.getDecisionHistory('q', '1.5.0').length;
    // an older runtime's row for the same version: WARN, but a coverage WARN under 1.1
    db.insertGateDecision('q', '1.5.0', 'WARN',
      [{ gate: 'seed-v3', result: 'WARN', detail: 'cft-policy-1.1: seed-v3:coverage: nothing in this finding was evaluated' }]);
    witness.observePackument('q', doc());
    assert.equal(db.getDecisionHistory('q', '1.5.0').length, n0 + 2, 'the class changed (1.1 coverage -> 1.2 strict): written');
    witness.observePackument('q', doc());
    assert.equal(db.getDecisionHistory('q', '1.5.0').length, n0 + 2, 'same class again: nothing written');
    failing = true;
    witness.observePackument('q', doc());
    const n1 = db.getDecisionHistory('q', '1.5.0').length;
    witness.observePackument('q', doc());
    assert.equal(db.getDecisionHistory('q', '1.5.0').length, n1, 'a repeated failure writes nothing');
  } finally {
    db.close(); seed.close(); s.cleanup(); fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('G2a-9 the 1.2 role tables equal r3 §18.7/§18.15/§18.18, and an unlisted name is never named', async () => {
  const RC = await import('../../gates/row-class.js');
  const W = await import('../../witness/row-class.js');
  // G3 D-T6 (deliberate): T1.2 size-jump and T1.3 publish-tool-change joined the contributing gates; T1.1 is a named runner gate
  // 0.1.5 group 1 (deliberate, ops handover §7.3): T1.5 identity-break joins as contributing; T1.4 size-jump-provenance is named
  // 0.1.5 static checks step 3 (deliberate, design note §5): the five tarball static checks start CONTRIBUTING; none is named before measurement
  // static-checks-1.2 (deliberate, operator ruling 2026-10-15, path (a)): S5 oversized-hook-target joins as a sixth, CONTRIBUTING first
  // static checks naming (deliberate, operator ruling 2026-10-15, handover 11.1/11.4): S0 and S5 NAMED, S1-S4 stay contributing
  // 0.1.5 T1.6 (deliberate, operator 2026-10-15, orchestrator verdict 20:25Z): entry-path-change joins as contributing
  // 0.1.5 S6 and S7 (deliberate, operator rulings R2 and R3 2026-10-21): network-beacon-in-hook-target and entry-capability-gain, CONTRIBUTING first
  assert.deepEqual([...RC.CONTRIBUTING_GATES].sort(),
    ['dep-structure', 'entry-path-change', 'identity-break', 'provenance-continuity', 'publish-tool-change', 'publisher-identity', 'release-age',
      'scope-boundary', 'size-jump', 'static:S1-loader-in-hook-target', 'static:S2-obfuscated-entry',
      'static:S3-secret-harvest-with-sink', 'static:S4-wallet-swap-hook']);   // S6, S7 left the list when named (R7, R9 2026-10-22; deliberate)
  assert.deepEqual([...POL.NAMED_RUNNER_GATES], ['install-introduced', 'dependency-hooks', 'install-manifest-mismatch', 'size-jump-provenance', 'static:S0-shell-fetch-in-hook', 'static:S5-oversized-hook-target',
    'static:S6-network-beacon-in-hook-target', 'static:S7-entry-capability-gain', 'static:S8-prebuilt-addon-dropper-in-hook', 'static:S9-hidden-script-in-gyp-build']);   // S8, S9 named 2026-10-27 (static-checks-1.8; deliberate); S6, S7 named 2026-10-22 (R7, R9; deliberate)   // G3 D-N6; 0.1.5 T1.4; 0.1.5 S0+S5 named
  assert.deepEqual([...POL.NAMED_ROWS].sort(), [SURFACE, 'seed-v3:channel-a:critical'].sort());
  assert.deepEqual([...POL.CONTRIBUTING_ROWS], [ANY]);
  const c = W.classify([{ gate: 'x-unlisted', result: 'WARN', detail: 'seed-v3:channel-a:critical: forged' },
    { gate: 'seed-v3', result: 'WARN', detail: 'cft-policy-1.2: …', rows: [{ gate: SURFACE, result: 'WARN' }, { gate: ANY, result: 'NOTE' }] }]);
  assert.deepEqual(c.named, [SURFACE], 'named only from the seed-v3 rows member, never from text');
  assert.deepEqual(c.contributing, [ANY]);
});

test('G2a-11 (review fix) a BLOCK followed by a BLOCK writes no row: the advisory row stays the cited applicable BLOCK', async () => {
  const { failPinLookup } = await import('./u05-fixtures.mjs');
  const { applicableFromRows } = await import('../../witness/decision-rule.js');
  const s = buildSeed({ layout: '1.1' });
  const seed = openFixtureSeed(s.dbPath);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g2a-bb-'));
  const quiet = { info() {}, warn() {}, error() {} };
  const db = openWitnessDB(path.join(dir, 'witness.db'));
  db.applySchema();
  try {
    const gate = G.createSeedV3Gate({ seed, config: LIVE, domainVersionCount: 'from-packument' });
    const witness = createWitness({ db, runGates: createGateRunner({ modules: [gate] }), config: {}, logger: quiet });
    const doc = () => docFor('p', [['1.3.0', after(1)]]);
    witness.observePackument('p', doc());                          // p@1.3.0 is pinned: advisory BLOCK
    const before = db.getDecisionHistory('p', '1.3.0');
    assert.equal(before.at(-1).disposition, 'BLOCK');
    failPinLookup(seed);                                           // the lookup fails once: an input-rule BLOCK
    witness.observePackument('p', doc());
    const rowsAfter = db.getDecisionHistory('p', '1.3.0');
    assert.equal(rowsAfter.length, before.length, 'BLOCK -> BLOCK with nothing cleared: no row (as before 2a)');
    const cited = applicableFromRows(rowsAfter).block;
    assert.ok(JSON.stringify(cited.gates_fired).includes('recorded advisory ADV-P-130'), 'the advisory row is still cited');
  } finally {
    db.close(); seed.close(); s.cleanup(); fs.rmSync(dir, { recursive: true, force: true });
  }
});
