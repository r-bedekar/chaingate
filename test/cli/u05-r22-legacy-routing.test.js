// U-05 R2-2 legacy part, routing (O1 approved; Addendum 1 §5 P-R1..P-R3, Addendum 2 §3.3): no implicit legacy download or
// replacement; `--force` never means "replace the witness database"; `--no-seed` never downloads; contradictory flags
// are refused; a legacy seed is never installed on a v3 host. Through the REAL commands (child processes, network
// denied, so any download attempt is visible as "Downloading" and refused). Data preservation: decisions and overrides
// before and after every route.
//
// This is the ONE R2-2 test file whose success paths let `init` start a proxy (it is what init does). The safety net in
// runCli stops it, and every case here runs sequentially in this file, so two proxies never contend for the port.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { activeBundleId, seedsDir } from '../../cli/seed-bundle.js';
import { v3Host, v3Source, freshHome, runCli, exists } from '../helpers/u05-r22.mjs';
import { testKey, buildLegacySeed, legacyWitness, snapshot } from '../helpers/u05-r22-legacy.mjs';

const key = testKey();
const LOCAL = { decisions: [{ pkg: 'alpha', ver: '1.0.0', disposition: 'BLOCK', at: '2026-02-01 00:00:00' }],
  overrides: [{ pkg: 'beta', ver: '2.0.0', reason: 'kept' }] };
const local = (w) => { const s = snapshot(w); return { d: s.rows.gate_decisions, o: s.rows.overrides }; };
const noDownload = (r, what) => assert.doesNotMatch(r.out, /Downloading/, `${what}: a download was attempted\n${r.out}`);

/** A legacy-only host: witness.db installed from a legacy seed, with local decisions and overrides, no sidecars (the
 *  test key is not the pinned key, so the integrity gate would treat a test-signed pair as tampering). */
function legacyHost({ witness = true } = {}) {
  const { home, base } = freshHome('legacy');
  const seed = buildLegacySeed(path.join(home, 'seed-old'), { key, seedVersion: '2026.test.old' });
  const w = path.join(base, 'witness.db');
  if (witness) legacyWitness(base, { from: 'seed', seed, local: LOCAL, sidecars: false });
  return { home, base, seed, witness: w, cleanup: () => fs.rmSync(home, { recursive: true, force: true }) };
}

test('LR1 init --force on a v3 host: no download, and the witness database is not replaced', async () => {
  const h = await v3Host();
  try {
    legacyWitness(h.base, { from: 'runtime', local: LOCAL });
    const before = local(h.base + '/witness.db');
    const r = await runCli(h.base, ['init', '--force'], { timeoutMs: 60000 });
    noDownload(r, 'init --force');
    assert.deepEqual(local(path.join(h.base, 'witness.db')), before, 'decisions and overrides unchanged');
    assert.equal(activeBundleId(h.base), h.id);
  } finally { h.cleanup(); }
});

test('LR2 v3 activation with witness.db missing, plain init: an EMPTY witness database is created, nothing downloaded', async () => {
  const h = await v3Host();
  try {
    fs.rmSync(path.join(h.base, 'witness.db'));
    const r = await runCli(h.base, ['init'], { timeoutMs: 60000 });
    noDownload(r, 'plain init');
    assert.match(r.out, /a new, empty witness database was created; earlier decisions and overrides were not restored/);
    assert.equal(exists(path.join(h.base, 'witness.db')), true);
    assert.deepEqual(snapshot(path.join(h.base, 'witness.db')).rows.versions, [], 'empty: no legacy seed in it');
  } finally { h.cleanup(); }
});

test('LR3 update-seed --seed <non-v3 file>: refused; no download; nothing changed', async () => {
  const h = legacyHost();
  try {
    const before = snapshot(h.witness);
    const r = await runCli(h.base, ['update-seed', '--seed', h.seed.db], { timeoutMs: 30000 });
    assert.equal(r.code, 1, r.out);
    noDownload(r, 'update-seed --seed <legacy>');
    assert.match(r.out, /update-seed --seed accepts v3 bundles/);
    assert.deepEqual(snapshot(h.witness).rows, before.rows);
  } finally { h.cleanup(); }
});

test('LR4 guard: plain update-seed on a v3 host refuses and downloads nothing', async () => {
  const h = await v3Host();
  try {
    const r = await runCli(h.base, ['update-seed'], { timeoutMs: 30000 });
    assert.equal(r.code, 1); noDownload(r, 'plain update-seed'); assert.match(r.out, /not available/);
  } finally { h.cleanup(); }
});

test('LR5 init --force --no-seed on a legacy host: no download; decisions and overrides kept', async () => {
  const h = legacyHost();
  try {
    const before = local(h.witness);
    const r = await runCli(h.base, ['init', '--force', '--no-seed'], { timeoutMs: 60000 });
    noDownload(r, 'init --force --no-seed');
    assert.deepEqual(local(h.witness), before);
  } finally { h.cleanup(); }
});

test('LR6 --seed together with --no-seed is refused as contradictory; nothing is done', async () => {
  const h = legacyHost();
  try {
    const before = snapshot(h.witness).rows;
    const r = await runCli(h.base, ['init', '--seed', h.seed.db, '--no-seed'], { timeoutMs: 30000 });
    assert.equal(r.code, 1, r.out); assert.match(r.out, /contradict/);
    assert.equal(r.spawnedProxy, undefined);
    assert.deepEqual(snapshot(h.witness).rows, before);
  } finally { h.cleanup(); }
});

test('LR7 init --seed <legacy db> on a v3 host is refused: a legacy seed is never installed there', async () => {
  const h = await v3Host(); const l = legacyHost({ witness: false });
  try {
    legacyWitness(h.base, { from: 'runtime', local: LOCAL });
    const before = snapshot(path.join(h.base, 'witness.db')).rows;
    for (const args of [['init', '--seed', l.seed.db], ['init', '--seed', l.seed.db, '--force']]) {
      const r = await runCli(h.base, args, { timeoutMs: 30000 });
      assert.equal(r.code, 1, `${args.join(' ')}\n${r.out}`);
      assert.match(r.out, /legacy witness seed is not installed on a v3 host/);
      assert.equal(r.spawnedProxy, undefined);
    }
    assert.deepEqual(snapshot(path.join(h.base, 'witness.db')).rows, before);
  } finally { l.cleanup(); h.cleanup(); }
});

test('LR8 init --seed <legacy db> without --force on an existing witness database: refused with the remedy', async () => {
  const h = legacyHost();
  try {
    const before = snapshot(h.witness).rows;
    const r = await runCli(h.base, ['init', '--seed', h.seed.db], { timeoutMs: 30000 });
    assert.equal(r.code, 1, r.out); assert.match(r.out, /add --force/);
    assert.equal(r.spawnedProxy, undefined);
    assert.deepEqual(snapshot(h.witness).rows, before);
  } finally { h.cleanup(); }
});

test('LR9 a broken v3 activation with plain init keeps the ActivationBroken refusal; nothing downloaded', async () => {
  const h = await v3Host();
  try {
    fs.renameSync(path.join(seedsDir(h.base), h.id), path.join(seedsDir(h.base), `${h.id}.moved`));
    fs.rmSync(path.join(h.base, 'witness.db'));
    const r = await runCli(h.base, ['init'], { timeoutMs: 30000 });
    assert.equal(r.code, 1, r.out); noDownload(r, 'init on a broken activation');
    assert.match(r.out, /does not resolve/);
    assert.equal(r.spawnedProxy, undefined);
  } finally { h.cleanup(); }
});

test('LR10 the legacy route still requires a verified signature: an unsigned legacy seed is refused', async () => {
  const h = legacyHost({ witness: false });
  try {
    fs.rmSync(h.seed.sig);
    const r = await runCli(h.base, ['init', '--seed', h.seed.db], { timeoutMs: 30000 });
    assert.equal(r.code, 1, r.out);
    assert.match(r.out, /signature/i);
    assert.equal(exists(h.witness), false, 'nothing installed');
    assert.equal(r.spawnedProxy, undefined);
  } finally { h.cleanup(); }
});
