// str.lower() is EXACT, proved over every scalar value rather than over chosen examples.
//
// `pyLower` is a generated per-code-point table plus one contextual rule (U+03A3 -> final or small
// sigma, decided by the characters around it). A table alone hashed every Greek word ending in sigma
// differently from the producer, and nothing threw: the install-body digest was simply wrong. Hand-
// picked vectors could not have shown the combination is right, so CPython digests four context
// probes per code point (make_lower_proof.py) and this recomputes them.

import test from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import N from '../../seed/v3/normalize.js';

const DIRNAME = dirname(fileURLToPath(import.meta.url));
const PROOF = JSON.parse(readFileSync(join(DIRNAME, '..', '..', 'seed', 'v3', 'lower-proof.json'), 'utf8'));
const SIGMA = 'Σ';
const SEP = Buffer.from([0x1e]);

const probes = (cp) => {
  const c = String.fromCodePoint(cp);
  return [c, c + SIGMA, `A${c}${SIGMA}`, `A${SIGMA}${c}`];
};

function blockDigest(start) {
  const h = crypto.createHash('sha256');
  const end = Math.min(start + PROOF.block_size, PROOF.max_cp);
  for (let cp = start; cp < end; cp += 1) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue;
    for (const s of probes(cp)) {
      h.update(Buffer.from(N.pyLower(s), 'utf8'));
      h.update(SEP);
    }
  }
  return h.digest('hex');
}

test('pyLower reproduces CPython str.lower() for every scalar value, in every sigma context', () => {
  const bad = [];
  for (const [hex, want] of Object.entries(PROOF.blocks)) {
    const start = Number.parseInt(hex, 16);
    if (blockDigest(start) !== want) bad.push(`U+${start.toString(16).toUpperCase()}`);
    if (bad.length >= 5) break;
  }
  assert.deepStrictEqual(bad, [],
    `blocks differ; inspect with: make_lower_proof.py --dump 0x${bad[0]?.slice(2) || '0'}`);
});

test('the contextual rule is the point: a per-character table gets these wrong', () => {
  // Greek "OS": the sigma is FINAL because a cased letter precedes it and nothing cased follows.
  assert.strictEqual(N.pyLower('ΟΣ'), 'ος');
  // ...but not when a cased letter follows it.
  assert.strictEqual(N.pyLower('ΟΣΑ'), 'οσα');
  // ...and not when nothing cased precedes it.
  assert.strictEqual(N.pyLower('Σ'), 'σ');
  assert.strictEqual(N.pyLower('ΣΣ'), 'σς');
  // Case-ignorable characters are SKIPPED, not treated as cased: a full stop between the letter and
  // the sigma leaves it final, and one after it does too.
  assert.strictEqual(N.pyLower('A.Σ'), 'a.ς');
  assert.strictEqual(N.pyLower('AΣ.'), 'aς.');
  assert.strictEqual(N.pyLower('AΣ.B'), 'aσ.b');
  // U+0345 is both Cased and Case_Ignorable; the skip is applied first, so it does not stop the scan.
  assert.strictEqual(N.pyLower('ͅΣ'), 'ͅσ');
  // A multi-character lowering still comes from the table (U+0130 -> i + combining dot above).
  assert.strictEqual(N.pyLower('İ'), 'i̇');
});

test('the install-body digest carries the contextual rule, which is where it actually mattered', () => {
  // `" ".join(body.lower().split())` then md5. A table-only lower produced a DIFFERENT digest here
  // for every script body containing a word that ends in sigma.
  const [has, digest] = N.installBodyDigest('ΟΣ', null, null);
  assert.strictEqual(has, 1);
  const want = crypto.createHash('md5').update('ος', 'utf8').digest('hex');
  assert.strictEqual(digest, want);
  assert.notStrictEqual(digest, crypto.createHash('md5').update('οσ', 'utf8').digest('hex'));
});
