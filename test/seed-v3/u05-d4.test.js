// U-05 S2 — D4 under cft-policy-1.1: tables T-P, T-L and T-G of U-05-S2-DECISION-TABLES-20260930.md.
// Expected values come from those tables, not from runtime output. Written and run failing-first on a6cb8e4.
//
// Cases c1 (stub-only rows) and c2 (undated rows) differ from b only in WHY the writer leaves the package
// unrepresented; at the runtime all three are "pin row present, no `packages` row". The writer side is S3.
import test from 'node:test';
import assert from 'node:assert/strict';
import R from '../../seed/v3/reader.js';
import G from '../../seed/v3/gate.js';
import POL from '../../seed/v3/policy.js';
import { buildCheckRecord } from '../../cli/check-record.js';
import {
  buildSeed, openFixtureSeed, docFor, gateInput, failPinLookup, namingRow, manifestFor, after,
  CONFIGS, LIVE, WARNCFG, PINS, PINS_1_0, SEED_CONTRACT_1_1,
} from './u05-fixtures.mjs';

const DVC = 'from-packument';
const evalCase = (seed, config, doc, version) => G.evaluateCandidate(seed, { config, domainVersionCount: DVC },
  gateInput(doc, version)).decision;
const inputRow = (d) => d.results.find((x) => x.gate === 'seed-v3:input');
const pinRow = (d) => d.results.find((x) => x.gate === 'seed-v3:known-malicious-pin');
const withSeed = (layout, fn) => {
  const s = buildSeed({ layout });
  const seed = openFixtureSeed(s.dbPath);
  try { return fn(seed); } finally { seed.close(); s.cleanup(); }
};

// ---------------------------------------------------------------------------------------------- T-G
for (const layout of ['1.0', '1.1']) {
  test(`T-G a/d [seed ${layout}] a pinned append and a pinned new-major cold start BLOCK naming the advisory`, () => {
    withSeed(layout, (seed) => {
      for (const [name, cfg] of Object.entries(CONFIGS)) {
        const a = evalCase(seed, cfg, docFor('p', [['1.3.0', after()]]), '1.3.0');
        assert.equal(a.disposition, 'BLOCK', `a ${name}`);
        assert.ok(namingRow(a.results, 'ADV-P-130'), `a ${name} names ADV-P-130`);
        assert.equal(a.placement, 'append');
        assert.equal(a.policy_version, 'cft-policy-1.1');
        const d = evalCase(seed, cfg, docFor('p', [['2.0.0', after()]]), '2.0.0');
        assert.equal(d.disposition, 'BLOCK', `d ${name}`);
        assert.ok(namingRow(d.results, 'ADV-P-200'));
        assert.equal(d.placement, 'new-major-cold-start');
      }
    });
  });

  test(`T-G e [seed ${layout}] no manifest: BLOCK under BOTH settings, pin row first, input row beside it`, () => {
    withSeed(layout, (seed) => {
      for (const [name, cfg] of Object.entries(CONFIGS)) {
        for (const [label, doc] of [['manifest null', docFor('p', [['1.3.0', after(), null]])],
          ['version absent from the document', docFor('p')]]) {
          const d = evalCase(seed, cfg, doc, '1.3.0');
          assert.equal(d.disposition, 'BLOCK', `${label} ${name}`);
          assert.equal(d.results[0].gate, 'seed-v3:known-malicious-pin', `${label} ${name}: pin row first`);
          assert.ok(namingRow(d.results, 'ADV-P-130'), `${label} ${name}: names the advisory`);
          assert.equal(inputRow(d).result, cfg.on_unusable_input, `${label} ${name}: the input row keeps the input rule`);
          assert.ok(d.not_evaluated.some((m) => m.where === 'policy' && m.name === 'input'));
          assert.equal(d.policy_version, 'cft-policy-1.1');
        }
      }
    });
  });

  test(`T-G e2 [seed ${layout}] adapter exception: BLOCK under both settings, naming the advisory`, () => {
    withSeed(layout, (seed) => {
      for (const [name, cfg] of Object.entries(CONFIGS)) {
        const d = evalCase(seed, cfg, docFor('p', [['1.3.0', after(), manifestFor('p', '1.3.0', { _npmUser: 'alice' })]]), '1.3.0');
        assert.equal(d.disposition, 'BLOCK', name);
        assert.ok(namingRow(d.results, 'ADV-P-130'), name);
        assert.match(inputRow(d).detail, /PackumentRejected/);
        assert.equal(inputRow(d).result, cfg.on_unusable_input);
      }
    });
  });

  test(`T-P ob.4 [seed ${layout}] a pin found before seed.check survives a later evaluation error`, () => {
    withSeed(layout, (seed) => {
      seed.check = () => { throw new Error('injected check failure'); };
      for (const [name, cfg] of Object.entries(CONFIGS)) {
        const d = evalCase(seed, cfg, docFor('p', [['1.3.0', after()]]), '1.3.0');
        assert.equal(d.disposition, 'BLOCK', name);
        assert.ok(namingRow(d.results, 'ADV-P-130'), name);
        assert.match(inputRow(d).detail, /injected check failure/);
      }
    });
  });

  test(`T-P P1b/P3b [seed ${layout}] a lookup that throws is recorded and the input rule applies; never "no advisory"`, () => {
    withSeed(layout, (seed) => {
      failPinLookup(seed);
      for (const [name, cfg] of Object.entries(CONFIGS)) {
        for (const [label, doc] of [['evaluated', docFor('p', [['1.3.0', after()]])],
          ['refused', docFor('p', [['1.3.0', after(), null]])]]) {
          const d = evalCase(seed, cfg, doc, '1.3.0');
          assert.equal(d.disposition, cfg.on_unusable_input, `${label} ${name}`);
          const pr = pinRow(d);
          assert.ok(pr, `${label} ${name}: a pin row states the lookup state`);
          assert.equal(pr.result, 'SKIP');
          assert.match(pr.detail, /lookup FAILED/);
          assert.doesNotMatch(pr.detail, /no recorded advisory/);
          assert.equal(inputRow(d).result, cfg.on_unusable_input);
          assert.ok(d.not_evaluated.some((m) => m.where === 'policy' && m.name === 'pin_lookup'
            && /injected pin lookup failure/.test(m.reason)), `${label} ${name}: pin_lookup recorded`);
          assert.equal(d.evidence_complete, false);
        }
      }
    });
  });

  test(`T-G isolation [seed ${layout}] only the pinned package+version changes`, () => {
    withSeed(layout, (seed) => {
      const q = evalCase(seed, WARNCFG, docFor('q', [['1.3.0', after(), null]]), '1.3.0');
      assert.equal(q.disposition, 'WARN', 'q@1.3.0: same version string, other package');
      assert.deepEqual(q.results.map((x) => x.gate), ['seed-v3:input'], 'P1c: results identical in shape to 1.0');
      const p4 = evalCase(seed, WARNCFG, docFor('p', [['1.4.0', after(), null]]), '1.4.0');
      assert.equal(p4.disposition, 'WARN', 'p@1.4.0: other version, same package');
      assert.equal(evalCase(seed, LIVE, docFor('p', [['1.4.0', after()]]), '1.4.0').disposition, 'ALLOW');
    });
  });
}

test('T-G b [seed 1.1] an UNREPRESENTED pinned package BLOCKs naming the advisory; coverage unchanged', () => {
  withSeed('1.1', (seed) => {
    for (const [name, cfg] of Object.entries(CONFIGS)) {
      const d = evalCase(seed, cfg, docFor('u', [['1.0.0', after()]], { seeded: [] }), '1.0.0');
      assert.equal(d.disposition, 'BLOCK', name);
      assert.ok(namingRow(d.results, 'ADV-U-100'), name);
      assert.equal(d.placement, 'uncovered-package');
    }
  });
});

test('T-G b/f [seed 1.0] the same package stays WARN on a 1.0 seed: an orphan pin row is invisible (case f control)', () => {
  withSeed('1.0', (seed) => {
    assert.equal(seed.db.prepare("SELECT COUNT(*) AS n FROM known_malicious_pins WHERE package_id = 9001").get().n, 1,
      'the orphan row IS present');
    const d = evalCase(seed, LIVE, docFor('u', [['1.0.0', after()]], { seeded: [] }), '1.0.0');
    assert.equal(d.disposition, 'WARN');
    assert.equal(namingRow(d.results, 'ADV-U-100'), undefined);
    assert.equal(POL.pinFor(seed, 'u', '1.0.0'), null);
  });
});

test('T-G e3 contract mismatch through policy.decide: BLOCK under both settings, naming the advisory', () => {
  withSeed('1.0', (seed) => {
    const doc = docFor('p', [['1.3.0', after()]]);
    const pl = G.resolvePlacement(seed, 'p', '1.3.0', Math.floor(Date.parse(after()) / 1000));
    const finding = G.evaluateCandidate(seed, { config: LIVE, domainVersionCount: DVC }, gateInput(doc, '1.3.0')).finding;
    assert.ok(finding, 'the control evaluates');
    const pin = POL.pinFor(seed, 'p', '1.3.0');
    for (const [name, cfg] of Object.entries(CONFIGS)) {
      const d = POL.decide({ ...finding, contract_version: 'some-other-contract' },
        { pin, config: cfg, placement: pl, packageName: 'p', version: '1.3.0' });
      assert.equal(d.disposition, 'BLOCK', name);
      assert.ok(namingRow(d.results, 'ADV-P-130'), name);
      assert.equal(inputRow(d).result, cfg.on_unusable_input);
      assert.ok(d.not_evaluated.some((m) => m.where === 'policy' && m.name === 'detection_contract_version'));
    }
  });
});

test('T-P P0 an exact-version override still outranks a pin, on the evaluated and the refused path (unchanged)', () => {
  withSeed('1.0', (seed) => {
    const finding = G.evaluateCandidate(seed, { config: LIVE, domainVersionCount: DVC },
      gateInput(docFor('p', [['1.3.0', after()]]), '1.3.0')).finding;
    const pin = POL.pinFor(seed, 'p', '1.3.0');
    const override = { reason: 'operator exception', created_at: '2026-09-30T00:00:00Z' };
    assert.equal(POL.decide(finding, { pin, override, config: LIVE }).disposition, 'ALLOW');
    assert.equal(POL.decide(null, { refusal: new Error('x'), pin, override, config: WARNCFG,
      packageName: 'p', version: '1.3.0' }).disposition, 'ALLOW');
  });
});

test('T-P P1a a pin decides even when on_unusable_input is REFUSE_TO_DECIDE, and the open choice is still named', () => {
  const d = POL.decide(null, { refusal: new Error('x'), pin: { advisory_id: 'ADV-P-130', source: 's' }, config: {},
    packageName: 'p', version: '1.3.0' });
  assert.equal(d.disposition, 'BLOCK');
  assert.deepEqual(d.undecided, ['on_unusable_input']);
  assert.equal(d.policy_version, 'cft-policy-1.1');
});

test('T-G agreement: the gate detail, the gate decision and the check record carry the same deciding rows', () => {
  withSeed('1.1', (seed) => {
    const doc = docFor('p', [['1.3.0', after(), null]]);
    let dec = null;
    const gate = G.createSeedV3Gate({ seed, config: WARNCFG, domainVersionCount: DVC, onDecision: (d) => { dec = d; } });
    const gr = gate.evaluate(gateInput(doc, '1.3.0'));
    assert.equal(gr.result, 'BLOCK');
    assert.match(gr.detail, /^cft-policy-1\.1: seed-v3:known-malicious-pin: recorded advisory ADV-P-130 pins p@1\.3\.0/);
    const rec = buildCheckRecord({ seed, policy: WARNCFG, domainVersionCount: DVC,
      input: gateInput(doc, '1.3.0'), request: { package: 'p', version: '1.3.0' },
      tool: { name: 'chaingate', version: 'test' } });
    assert.equal(rec.result, 'refused');
    assert.deepEqual(rec.decision.results, dec.results);
    assert.equal(rec.effective.action, 'BLOCK');
  });
});

// ---------------------------------------------------------------------------------------------- T-L
test('T-L a 1.1 seed opens; lookup is by name, lowest advisory_id first', () => {
  const s = buildSeed({ layout: '1.1', pins: [...PINS, { pkgId: 1, name: 'p', version: '1.3.0', advisory: 'ADV-P-129' }] });
  const seed = openFixtureSeed(s.dbPath);
  try {
    assert.equal(seed.meta.seed_contract_version, SEED_CONTRACT_1_1);
    assert.equal(POL.pinFor(seed, 'p', '1.3.0').advisory_id, 'ADV-P-129');
    assert.equal(POL.pinFor(seed, 'u', '1.0.0').advisory_id, 'ADV-U-100');
    assert.equal(POL.pinFor(seed, 'p', '1.4.0'), null);
  } finally { seed.close(); s.cleanup(); }
});

test('T-L a 1.1 seed without the name column or without the (package_name, version) index is refused by name', () => {
  const noName = buildSeed({ layout: '1.1', pinsSql: PINS_1_0, pins: PINS.filter((k) => k.pkgId !== 9001) });
  const noIndex = buildSeed({ layout: '1.1', pinsSql: `CREATE TABLE known_malicious_pins (package_id INTEGER NOT NULL,
    package_name TEXT NOT NULL, version TEXT NOT NULL, advisory_id TEXT NOT NULL, source TEXT NOT NULL,
    PRIMARY KEY (package_id, version, advisory_id)) WITHOUT ROWID;` });
  try {
    assert.throws(() => openFixtureSeed(noName.dbPath), (e) => e instanceof R.SeedRefused
      && /known_malicious_pins/.test(e.message) && /package_name/.test(e.message));
    assert.throws(() => openFixtureSeed(noIndex.dbPath), (e) => e instanceof R.SeedRefused && /index/.test(e.message));
  } finally { noName.cleanup(); noIndex.cleanup(); }
});

test('T-L both seed contracts are supported, and nothing else', () => {
  assert.deepEqual([...R.SUPPORTED_SEED_CONTRACT_VERSIONS].sort(),
    ['cft-seed-v3-contract-1.0', 'cft-seed-v3-contract-1.1']);
  const s = buildSeed({ layout: '1.1', contract: 'cft-seed-v3-contract-1.2' });
  try {
    assert.throws(() => openFixtureSeed(s.dbPath), (e) => e instanceof R.SeedRefused && /contract_version/.test(e.message));
  } finally { s.cleanup(); }
});
