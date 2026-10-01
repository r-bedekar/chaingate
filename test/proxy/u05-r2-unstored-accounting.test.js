// U-05 gap-closure r2 (owner decision 6), B-r2: the bounded unstored-BLOCK record. Expected values come from revision 2
// §3.2–§3.6 and §9 (R-1..R-10), written before this file. Accounting model (§3.3):
//   entry   E = 2*(len(version) + len(detail) + sum(len(gates)) + 24) + C_ENTRY
//   package P = 2*len(name) + C_PKG                     total T = sum(E) + sum(P) + C_FIXED
// Correction recorded (not a retune): revision 2 §9 R-3 wrote "12 gates -> 8 + `+4 more`", which contradicts the governing
// field rule in §3.2 ("at most 8 names ... `+N more` is appended WITHIN the limit"). The test follows §3.2: 7 names plus
// "+5 more" = 8 elements.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createUnstoredBlocks, validateCaps, LIMITS, DEFAULT_CAPS } from '../../proxy/unstored-blocks.js';

const { NAME_MAX, VERSION_MAX, DETAIL_MAX, C_ENTRY, C_PKG, C_FIXED } = LIMITS;
const BIG = { entries: 1_000_000, bytes: 1024 ** 3 };
const blockUnstored = (detail = 'pinned by ADV-1', gates = ['seed-v3']) => ({ disposition: 'BLOCK', persisted: false,
  results: gates.map((g) => ({ gate: g, result: 'BLOCK', detail })) });
const blockStored = { disposition: 'BLOCK', results: [{ gate: 'seed-v3', result: 'BLOCK', detail: 'x' }] };
const evaluatedAllow = { disposition: 'ALLOW', results: [{ gate: 'seed-v3', result: 'ALLOW', detail: 'ok' }] };
const failureWarn = { disposition: 'WARN', evaluated: false, persisted: false, results: [] };
const overrideAllow = { disposition: 'ALLOW', results: [{ gate: 'override', result: 'ALLOW', detail: 'override: x' }] };
const cost = (name, version, detail, gates, newPkg = true) => 2 * (version.length + detail.length
  + gates.reduce((a, g) => a + g.length, 0) + 24) + C_ENTRY + (newPkg ? 2 * name.length + C_PKG : 0);
const lines = () => { const out = []; return { out, log: { warn: (m) => out.push(m), error: (m) => out.push(m), info() {} } }; };

test('defaults and limits are the proposed values (measurement candidates, not RAM promises)', () => {
  assert.deepEqual(DEFAULT_CAPS, { entries: 50_000, bytes: 64 * 1024 * 1024 });
  assert.deepEqual([NAME_MAX, VERSION_MAX, DETAIL_MAX, LIMITS.GATES_MAX, LIMITS.GATE_NAME_MAX], [214, 256, 160, 8, 64]);
  assert.deepEqual([C_ENTRY, C_PKG, C_FIXED], [256, 192, 65536]);
});

test('R-1 identities of exactly 214 / 256 characters are retained; T follows the formula', () => {
  const r = createUnstoredBlocks({ caps: BIG });
  const name = 'a'.repeat(NAME_MAX); const version = `1.0.0-${'b'.repeat(VERSION_MAX - 6)}`;
  assert.equal(version.length, VERSION_MAX);
  r.note(name, version, blockUnstored('d'));
  assert.ok(r.get(name, version), 'retained exactly');
  assert.equal(r.full, false);
  assert.equal(r.estimatedBytes, C_FIXED + cost(name, version, 'd', ['seed-v3']));
  assert.equal(r.recompute(), r.estimatedBytes);
});

test('R-2 a 215-character name or a 257-character version is never truncated: the record enters FULL', () => {
  for (const [name, version] of [['a'.repeat(NAME_MAX + 1), '1.0.0'], ['p', `1.0.0-${'b'.repeat(VERSION_MAX - 5)}`]]) {
    const { out, log } = lines();
    const r = createUnstoredBlocks({ caps: BIG, log });
    r.note(name, version, blockUnstored());
    assert.equal(r.get(name, version), null, 'not retained in any form');
    assert.equal(r.count, 0);
    assert.equal(r.full, true, 'FULL: the BLOCK is enforced by the FULL refusal instead');
    const d = r.describe();
    assert.equal(d.identity_rejected, 1); assert.equal(d.overflowed, 1);
    assert.ok(out.some((l) => /FULL/.test(l)), 'the transition is logged');
    assert.equal(r.recompute(), r.estimatedBytes); assert.equal(r.estimatedBytes, C_FIXED);
  }
});

test('R-3 maximum payloads: detail clipped to 160 with a marker; at most 8 gate names (7 + "+5 more"); identity untouched', () => {
  const r = createUnstoredBlocks({ caps: BIG });
  const gates = Array.from({ length: 12 }, (_, i) => `gate-${i}-${'g'.repeat(70)}`);
  r.note('p', '1.3.0', blockUnstored('d'.repeat(300), gates));
  const e = r.get('p', '1.3.0');
  assert.equal(e.detail.length, DETAIL_MAX); assert.ok(e.detail.endsWith('…'));
  assert.equal(e.gates.length, LIMITS.GATES_MAX);
  assert.equal(e.gates.at(-1), '+5 more');
  for (const g of e.gates.slice(0, 7)) assert.ok(g.length <= LIMITS.GATE_NAME_MAX);
  assert.equal(r.recompute(), r.estimatedBytes);
});

test('R-4 a growing replacement that does not fit keeps the old entry (still protected); only the timestamp moves', () => {
  let t = 1_000;
  const now = () => t;
  const first = cost('p', '1.3.0', 'short', ['seed-v3']);
  const r = createUnstoredBlocks({ caps: { entries: 10, bytes: C_FIXED + first + 10 }, now });
  r.note('p', '1.3.0', blockUnstored('short'));
  const before = r.estimatedBytes;
  t = 2_000;
  r.note('p', '1.3.0', blockUnstored('a much longer detail that would not fit in the remaining budget'));
  const e = r.get('p', '1.3.0');
  assert.equal(e.detail, 'short', 'old detail kept');
  assert.equal(e.remembered_at, new Date(2_000).toISOString(), 'timestamp updated');
  assert.equal(r.estimatedBytes, before, 'T unchanged');
  assert.equal(r.describe().replacement_detail_kept, 1);
  assert.equal(r.full, false, 'a replacement never sends the record to FULL: the key stays protected');
});

test('R-5 10,000 replacements of one key: count 1, T always equal to a recomputation', () => {
  const r = createUnstoredBlocks({ caps: BIG });
  for (let i = 0; i < 10_000; i += 1) {
    r.note('p', '1.3.0', blockUnstored('x'.repeat(i % 200)));
    if (i % 997 === 0) assert.equal(r.recompute(), r.estimatedBytes);
  }
  assert.equal(r.count, 1);
  assert.equal(r.recompute(), r.estimatedBytes);
});

test('R-7 many packages with one version each, then all forgotten: T returns exactly to C_FIXED', () => {
  const r = createUnstoredBlocks({ caps: BIG });
  for (let i = 0; i < 2_000; i += 1) r.note(`pkg-${i}`, '1.0.0', blockUnstored());
  assert.equal(r.count, 2_000);
  assert.equal(r.recompute(), r.estimatedBytes);
  for (let i = 0; i < 2_000; i += 1) r.note(`pkg-${i}`, '1.0.0', blockStored);
  assert.equal(r.count, 0);
  assert.equal(r.estimatedBytes, C_FIXED);
});

test('R-8 (record level) overflow: entry cap and byte cap; FULL is sticky; Table M keeps working while FULL', () => {
  const { out, log } = lines();
  const r = createUnstoredBlocks({ caps: { entries: 3, bytes: BIG.bytes }, log });
  for (const v of ['1', '2', '3']) r.note('p', v, blockUnstored());
  assert.equal(r.full, false);
  r.note('p', '4', blockUnstored());
  assert.equal(r.full, true); assert.equal(r.get('p', '4'), null); assert.equal(r.describe().overflowed, 1);
  r.note('p', '1', blockUnstored('replaced while FULL'));
  assert.equal(r.get('p', '1').detail, 'replaced while FULL', 'replacements continue');
  for (const v of ['1', '2', '3']) r.note('p', v, blockStored);
  assert.equal(r.count, 0); assert.equal(r.full, true, 'FULL stays after the record empties (until the process exits)');
  assert.equal(out.filter((l) => /FULL/.test(l)).length, 1, 'one FULL transition line');
  const byBytes = createUnstoredBlocks({ caps: { entries: 1000, bytes: C_FIXED + cost('p', '1', 'd', ['seed-v3']) } });
  byBytes.note('p', '1', blockUnstored('d'));
  byBytes.note('p', '2', blockUnstored('d'));
  assert.equal(byBytes.full, true, 'the byte cap binds before the entry cap');
});

test('Table M is unchanged: stored BLOCK forgets; evaluated non-BLOCK forgets; failure and override-based ALLOW keep', () => {
  const r = createUnstoredBlocks({ caps: BIG });
  r.note('p', '1', blockUnstored()); r.note('p', '1', failureWarn); assert.ok(r.get('p', '1'));
  r.note('p', '1', overrideAllow); assert.ok(r.get('p', '1'));
  r.note('p', '1', evaluatedAllow); assert.equal(r.get('p', '1'), null);
  r.note('p', '2', blockUnstored()); r.note('p', '2', blockStored); assert.equal(r.get('p', '2'), null);
  assert.equal(r.estimatedBytes, C_FIXED);
});

test('R-9 invalid caps are refused by name; the cap minimum always admits one maximum entry', () => {
  for (const bad of [0, -1, 1.5, 'x', NaN, 1e8, Infinity]) {
    assert.throws(() => validateCaps({ entries: bad, bytes: DEFAULT_CAPS.bytes }), /unstored_block_cap_entries/, String(bad));
  }
  for (const bad of [512 * 1024, 0, 'x', 1.5, 5 * 1024 ** 3]) {
    assert.throws(() => validateCaps({ entries: 10, bytes: bad }), /unstored_block_cap_bytes/, String(bad));
  }
  assert.deepEqual(validateCaps({ entries: 1, bytes: 1024 * 1024 }), { entries: 1, bytes: 1024 * 1024 });
  assert.deepEqual(validateCaps({}), DEFAULT_CAPS, 'unset = the defaults');
  const r = createUnstoredBlocks({ caps: { entries: 1, bytes: 1024 * 1024 } });
  r.note('a'.repeat(NAME_MAX), `1.0.0-${'b'.repeat(VERSION_MAX - 6)}`, blockUnstored('d'.repeat(300), Array.from({ length: 12 }, () => 'g'.repeat(70))));
  assert.equal(r.count, 1, 'a maximum-size entry in a new package fits an empty record at the minimum caps');
});

test('R-10 property: 100,000 random operations keep T == recomputation <= cap and count <= cap', () => {
  let seed = 0x5eed;
  const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
  const caps = { entries: 500, bytes: 256 * 1024 };
  const r = createUnstoredBlocks({ caps });
  let wasFull = false;
  for (let i = 0; i < 100_000; i += 1) {
    const name = `pkg${Math.floor(rnd() * 60)}`; const version = `1.${Math.floor(rnd() * 20)}.0`;
    const k = rnd();
    const d = k < 0.5 ? blockUnstored('d'.repeat(Math.floor(rnd() * 400)), ['seed-v3', 'content-hash'].slice(0, 1 + Math.floor(rnd() * 2)))
      : k < 0.7 ? blockStored : k < 0.8 ? evaluatedAllow : k < 0.9 ? failureWarn : overrideAllow;
    r.note(name, version, d);
    if (i % 1000 === 0 || i === 99_999) {
      assert.equal(r.recompute(), r.estimatedBytes, `T == recompute at op ${i}`);
      assert.ok(r.estimatedBytes <= caps.bytes, `T <= cap at op ${i}`);
      assert.ok(r.count <= caps.entries, `count <= cap at op ${i}`);
    }
    if (wasFull) assert.equal(r.full, true, 'FULL is sticky');
    wasFull = r.full;
  }
});

test('describe() reports caps, the estimate, FULL state and a bounded sample of at most 50 keys', () => {
  const r = createUnstoredBlocks({ caps: BIG });
  for (let i = 0; i < 80; i += 1) r.note('p', `1.0.${i}`, blockUnstored());
  const d = r.describe();
  assert.equal(d.count, 80);
  assert.deepEqual(d.cap, { entries: BIG.entries, bytes_estimated: BIG.bytes });
  assert.equal(d.estimated_bytes, r.estimatedBytes);
  assert.equal(d.full, false); assert.equal(d.full_since, null);
  assert.equal(d.sample.length, 50); assert.ok(d.sample.every((k) => /^p@1\.0\.\d+$/.test(k)));
  assert.match(d.note, /NOT stored/);
});
