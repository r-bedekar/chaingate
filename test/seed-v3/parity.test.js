// JS↔fixture parity over the exact rc3-bound pack. Skipped with a reason when the artifact is absent.
//
// The fixture pack is bound to ONE seed: its manifest carries that seed's corpus_snapshot_digest and
// rule_versions, and acceptance checks them before comparing. A pack from a different build fails on
// BINDING rather than producing a misleading divergence count.
import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import P from '../../seed/v3/parity.js';
import R from '../../seed/v3/reader.js';

// The gated candidate is an internal artifact; no absolute path is baked in. Set CFT04_CANDIDATE to
// a candidate directory (containing chaingate-seed.db and fixtures/) to run these; otherwise they skip.
const CAND = process.env.CFT04_CANDIDATE || '';
const SEED = path.join(CAND, 'chaingate-seed.db');
const FIXTURES = path.join(CAND, 'fixtures');
const present = Boolean(CAND) && fs.existsSync(SEED) && fs.existsSync(path.join(FIXTURES, 'fixtures.jsonl'));
const DEV = { trust: R.TRUST_UNSIGNED_DEV };

test('key order is not semantic — the comparison must be stable', () => {
  const a = { x: 1, y: { p: 2, q: 3 }, z: [1, { m: 1, n: 2 }] };
  const b = { z: [1, { n: 2, m: 1 }], y: { q: 3, p: 2 }, x: 1 };
  assert.ok(P.eq(a, b), 'reordered keys must compare equal');
  assert.ok(!P.eq(a, { ...a, x: 2 }), 'a real difference must not');
});

test('the structural diff and the equality test agree', () => {
  // They disagreed once: stringify said "different", diff found nothing, and every record was
  // reported as diverging with zero itemised differences.
  const a = { g: { k: [true, 'EVALUATED', null] } };
  const b = { g: { k: [false, 'EVALUATED', null] } };
  const out = []; P.diff('', a, b, out);
  assert.strictEqual(out.length, 1);
  assert.ok(!P.eq(a, b));
  const same = []; P.diff('', a, JSON.parse(JSON.stringify(a)), same);
  assert.strictEqual(same.length, 0);
  assert.ok(P.eq(a, JSON.parse(JSON.stringify(a))));
});

test('parity: the JS evaluator reproduces the rc3-bound pack with zero divergences',
  { skip: present ? false : 'set CFT04_CANDIDATE to a gated candidate directory to run this', timeout: 600000 },
  async () => {
    const r = await P.run(FIXTURES, SEED, DEV);
    assert.strictEqual(r.acceptance.artifacts_present, true);
    assert.strictEqual(r.acceptance.fixtures_digest_recomputed, true, 'the pack digest must be RECOMPUTED');
    assert.strictEqual(r.acceptance.oracle_defect_count_zero, true);
    assert.strictEqual(r.acceptance['seed_binding.corpus_snapshot_digest'], true);
    assert.strictEqual(r.acceptance['seed_binding.rule_versions'], true);
    assert.strictEqual(r.acceptance.membership_unique, true);
    assert.strictEqual(r.acceptance.record_count_matches_manifest, true);
    assert.strictEqual(r.candidates, 152804, 'the rc3-bound pack');
    assert.strictEqual(r.disagreeing, 0, JSON.stringify(r.items.slice(0, 3)));
    assert.strictEqual(r.status, 'PASS');
  });

test('a pack bound to a DIFFERENT seed fails on binding, not on a divergence count',
  { skip: present ? false : 'set CFT04_CANDIDATE to a gated candidate directory to run this' },
  () => {
    const seed = R.openSeed(SEED, DEV);
    try {
      const fake = { ...seed, meta: { ...seed.meta, corpus_snapshot_digest: '0'.repeat(64) } };
      const { checks } = P.acceptance(FIXTURES, fake);
      assert.notStrictEqual(checks['seed_binding.corpus_snapshot_digest'], true);
    } finally { seed.close(); }
  });
