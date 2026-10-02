// U-05 owner decision 10: the failure rows of the expected decision table (U-05-OWNER-DECISION-10-C1-C2-SCOPE-20261002.md
// §3.1, written before this file), in every configuration: V-B (v3 seed, on_unusable_input BLOCK: the default), V-W
// (v3 seed, WARN), N (no v3 seed: legacy seed or --no-seed). Run failing-first on 8f90e6a.
//   step 1  version not derivable from the file name     V-B 503-E   V-W serve   N serve
//   step 5a applicable BLOCK, evaluation failed            403 in every configuration
//   step 5c evaluation failed, no applicable BLOCK          V-B 503-E   V-W serve   N serve   (never marked evaluated)
//   step 5d decision history unreadable, nothing held       V-B 503-L   V-W serve (D-1)       N 503-L (D-2)
//           ... with a held BLOCK                           403 in every configuration (D-1 exception)
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { seed, registry, proxy, tarball, packument, failingWitness, tmp, stopAll, safely } from '../helpers/u05-d10.mjs';

const silence = () => { const e = console.error; const w = console.warn; console.error = () => {}; console.warn = () => {}; return () => { console.error = e; console.warn = w; }; };
const CONFIGS = { 'V-B': { policy: 'BLOCK', v3: true }, 'V-W': { policy: 'WARN', v3: true }, N: { policy: 'BLOCK', v3: false } };
const EVAL_FAILED = { 'V-B': [503, 'chaingate_evaluation_failed'], 'V-W': [200, null], N: [200, null] };

async function world(t, key, { witnessFn = null } = {}) {
  const dir = tmp('ft'); const reg = await registry(); const s = seed();
  const restore = silence();
  const witness = witnessFn ? witnessFn(dir) : path.join(dir, 'witness.db');
  const px = await proxy({ upstream: reg.url, witness, seedDb: s.dbPath, ...CONFIGS[key] });
  t.after(async () => { await stopAll(); restore(); await safely(() => reg.close()); await safely(() => s.cleanup());
    await safely(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })); });
  return { reg, px, witness, s };
}

const FAILURES = {
  'the requested version is absent from the metadata': (reg) => reg,                         // p@9.9.9 below
  'the metadata is malformed': (reg) => reg.set('p', { malformed: true }),
  'the metadata request answers 500': (reg) => reg.set('p', { status: 500 }),
  'the metadata connection is reset': (reg) => reg.set('p', { reset: true }),
};

for (const key of Object.keys(CONFIGS)) {
  for (const [what, arrange] of Object.entries(FAILURES)) {
    test(`T-5c (${key}) ${what}: ${EVAL_FAILED[key][0]}; never marked evaluated`, async (t) => {
      const w = await world(t, key); arrange(w.reg);
      const version = what.startsWith('the requested version') ? '9.9.9' : '1.4.0';
      const r1 = await tarball(w.px, 'p', version);
      assert.equal(r1.status, EVAL_FAILED[key][0], `${r1.status} ${r1.json?.error ?? ''}`);
      if (EVAL_FAILED[key][1]) assert.equal(r1.json?.error, EVAL_FAILED[key][1]);
      const n = w.reg.count('packument', '/p');
      await tarball(w.px, 'p', version);
      assert.equal(w.reg.count('packument', '/p'), n + 1, 'the next request tries the evaluation again');
    });
  }

  test(`T-1 (${key}) a version that cannot be derived from the file name: ${EVAL_FAILED[key][0]}`, async (t) => {
    const w = await world(t, key);
    const r = await tarball(w.px, 'p', null, 'not-p-anything.tgz');
    assert.equal(r.status, EVAL_FAILED[key][0], `${r.status} ${r.json?.error ?? ''}`);
  });

  test(`T-5a (${key}) an applicable stored BLOCK is refused even when the evaluation fails`, async (t) => {
    const w = await world(t, key);
    w.reg.set('p', { mode: { '1.4.0': 'real' } }); await packument(w.px, 'p');
    w.reg.set('p', { mode: { '1.4.0': 'alt' } }); await packument(w.px, 'p');       // content-hash BLOCK stored
    await w.px.stop();
    const px = await proxy({ upstream: w.reg.url, witness: w.witness, seedDb: w.s.dbPath, ...CONFIGS[key] });
    t.after(() => px.stop());
    w.reg.set('p', { status: 500 });
    const r = await tarball(px, 'p', '1.4.0');
    assert.equal(r.status, 403, `${r.status} ${r.json?.error ?? ''}`);
  });

  test(`T-5d (${key}) the decision history cannot be read: ${key === 'V-W' ? 'served (D-1)' : '503 (D-2 for N)'}`, async (t) => {
    const w = await world(t, key);
    await packument(w.px, 'p');                                     // evaluated in this process
    const db = w.px.px.witnessDb;
    const boom = () => { throw new Error('injected: the decision history cannot be read'); };
    for (const m of ['getLatestDecision', 'getLatestNonOverrideDecision', 'getApplicableDecision']) if (typeof db[m] === 'function') db[m] = boom;
    const r = await tarball(w.px, 'p', '1.4.0');
    if (key === 'V-W') assert.equal(r.status, 200, 'D-1: explicitly configured WARN availability');
    else {
      assert.equal(r.status, 503, `${r.status} ${r.json?.error ?? ''}`);
      assert.equal(r.json?.error, 'chaingate_decision_lookup_failed');
    }
  });

  test(`T-5d (${key}) the history cannot be read but a BLOCK is held in memory: refused (D-1 exception)`, async (t) => {
    const w = await world(t, key, { witnessFn: (dir) => failingWitness(dir) });
    w.reg.set('p', { mode: { '1.4.0': 'real' } }); await packument(w.px, 'p');
    w.reg.set('p', { mode: { '1.4.0': 'alt' } }); await packument(w.px, 'p');       // content-hash BLOCK, held
    const db = w.px.px.witnessDb;
    const boom = () => { throw new Error('injected: the decision history cannot be read'); };
    for (const m of ['getLatestDecision', 'getLatestNonOverrideDecision', 'getApplicableDecision']) if (typeof db[m] === 'function') db[m] = boom;
    const r = await tarball(w.px, 'p', '1.4.0');
    assert.equal(r.status, 403, `${r.status} ${r.json?.error ?? ''}`);
  });

  test(`T-ok (${key}) the healthy path: an evaluated, clean version is served`, async (t) => {
    const w = await world(t, key);
    assert.equal((await tarball(w.px, 'p', '1.4.0')).status, 200);
  });
}
