// Since 0.1.6: static-checks-1.8.1, recon's v6.22 mirrored (facts only). A run's distinct_chars is counted over at most its first
// FACTS_LIMITS.distinctCharsBytes (64 KiB): base64 and hex runs, and a hex-escape run's digits. A run of at most 64 KiB gives the 1.8
// value; chars and magic are unchanged; the encoded-runs facts name their basis. Every regex, marker list, row rule, gate, class,
// role and notice is 1.8's. The hand-off is recon's constants file, byte for byte (sealed recon v6.22, static-checks.mjs d6e243d7).
// Written before the code.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';

const SC = () => import('../../proxy/static-checks.js');
const RAW = fs.readFileSync(new URL('../fixtures/cft016/static-checks-1.8.1-constants.json', import.meta.url));
const K = JSON.parse(RAW.toString('utf8'));

test('E1 the hand-off is recon\'s file byte for byte, plain ASCII; the version, the limits and both run patterns are its', async () => {
  const S = await SC();
  assert.equal(createHash('sha256').update(RAW).digest('hex'), 'c20c5aeaacafdee70f50858596ede72541eef56c04891cf9aa2cea4473eb0105');
  assert.ok(RAW.every((b) => b < 0x80));
  assert.equal(K.static_checks_version, 'static-checks-1.8.1');
  assert.equal(S.STATIC_CHECKS_VERSION, 'static-checks-1.9');   // declared: 1.9 changes S0 and S6 only (cft016-static-checks-1.9); the 1.8.1 facts are unchanged
  assert.deepEqual({ ...S.FACTS_LIMITS }, K.facts_limits);
  assert.equal(S.FACTS_NOTE, K.facts_note);
});

test('E2 distinct_chars over the first 64 KiB of a run; a run of at most 64 KiB keeps the 1.8 value; chars and magic unchanged', async () => {
  const S = await SC();
  const long = `x=${'A'.repeat(65_536)}${'BCDEFGH'.repeat(2_000)};`;
  const [r] = S.encodedRuns(long);
  assert.equal(r.kind, 'base64'); assert.equal(r.chars, 65_536 + 14_000); assert.equal(r.distinct_chars, 1, 'only the first 64 KiB is counted');
  const short = `x=${'QUJD'.repeat(200)}${'xyz0'.repeat(50)};`;
  const [s] = S.encodedRuns(short);
  assert.equal(s.distinct_chars, new Set(`${'QUJD'.repeat(200)}${'xyz0'.repeat(50)}`).size, 'the 1.8 value');
  const esc = `s="${'\\x41'.repeat(40_000)}${'\\x7e'.repeat(100)}"`;
  const [h] = S.encodedRuns(esc);
  assert.equal(h.kind, 'hex-escape'); assert.equal(h.chars, 80_200); assert.equal(h.distinct_chars, 2, 'the digits 4 and 1 in the first 64 KiB');
});

test('E3 the encoded-runs facts state their basis', async () => {
  const S = await SC();
  const data = Buffer.from(`x=${'QUJD'.repeat(200)};`);
  const x = S.staticFacts({ members: [S.memberFacts({ path: 'index.js', size: data.length, data })], archiveComplete: true });
  assert.equal(x.encoded_runs?.distinct_chars_basis, K.encoded_runs.distinct_chars_basis, JSON.stringify(x).slice(0, 300));
  assert.equal(x.encoded_runs.runs, 1);
});
