// U-05 S2 — the all-stub placement fix (revision 2 §3.3; table T-S of U-05-S2-DECISION-TABLES-20260930.md). The
// held finding: a takedown-stub release of a package the seed does not represent reported `uncovered-package`. Only the
// decision's placement (and the Channel-A reasons it states) changes; the finding and every disposition do not.
import test from 'node:test';
import assert from 'node:assert/strict';
import G from '../../seed/v3/gate.js';
import { buildSeed, openFixtureSeed, docFor, gateInput, after, BASE_S } from './u05-fixtures.mjs';

const STUB_REASON = /0\.0\.x-security takedown stub \(FU-2 E4\)/;
const ts = Math.floor(Date.parse(after()) / 1000);

test('T-S absent package + stub candidate -> ineligible-stub with the E4 reason; a non-stub stays uncovered-package', () => {
  const s = buildSeed();
  const seed = openFixtureSeed(s.dbPath);
  try {
    const stub = G.resolvePlacement(seed, 's', '0.0.1-security', ts);
    assert.equal(stub.kind, 'ineligible-stub');
    assert.match(stub.reason, STUB_REASON);
    assert.equal(stub.channel_a_usable, false);
    assert.equal(G.resolvePlacement(seed, 's', '0.0.1-security', null).kind, 'ineligible-stub', 'no time: E4 still first');
    assert.equal(G.resolvePlacement(seed, 's', '1.0.0', ts).kind, 'uncovered-package');
    assert.equal(G.resolvePlacement(seed, 'p', '0.0.2-security', ts).kind, 'ineligible-stub', 'represented: unchanged');
    assert.equal(G.resolvePlacement(seed, 'p', '1.1.0', BASE_S).kind, 'recorded', 'recorded outranks: unchanged');
  } finally { seed.close(); s.cleanup(); }
});

test('T-S dispositions unchanged under both on_no_evidence values; the finding still says uncovered_package', () => {
  const s = buildSeed();
  const seed = openFixtureSeed(s.dbPath);
  try {
    const doc = docFor('s', [['0.0.1-security', after()]], { seeded: [] });
    for (const [noEv, want] of [['WARN', 'WARN'], ['ALLOW', 'ALLOW']]) {
      const { decision, finding } = G.evaluateCandidate(seed,
        { config: { on_unusable_input: 'BLOCK', on_no_evidence: noEv }, domainVersionCount: 'from-packument' },
        gateInput(doc, '0.0.1-security'));
      assert.equal(decision.disposition, want, `on_no_evidence=${noEv}`);
      assert.equal(decision.placement, 'ineligible-stub');
      assert.equal(finding.channel_a.groups.publisher.reason, 'uncovered_package', 'detection contract untouched');
      const ca = decision.not_evaluated.filter((m) => m.where.startsWith('channel_a'));
      assert.ok(ca.length > 0 && ca.every((m) => STUB_REASON.test(m.reason) && m.stated_by === 'placement'));
    }
  } finally { seed.close(); s.cleanup(); }
});
