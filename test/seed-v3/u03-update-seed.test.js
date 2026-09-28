// U-03 — automatic v3 seed download is not available, so plain `update-seed` on a host whose detection
// runs from a v3 bundle must REFUSE clearly, download nothing and change nothing, while restart, a
// local `--seed` update and `--rollback` keep working. A legacy-only host keeps its legacy behaviour.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import Database from 'better-sqlite3';
import updateSeed from '../../cli/commands/update-seed.js';
import { resolvePaths } from '../../cli/paths.js';
import { stageBundle, activateBundle, activeBundleId, previousBundleId } from '../../cli/seed-bundle.js';
import { openWitnessDB } from '../../witness/db.js';
import { buildSyntheticSeed } from './u01-cases.mjs';

const sha = (f) => createHash('sha256').update(fs.readFileSync(f)).digest('hex');

/** Two DISTINCT v3 bundles (B differs from A in its corpus snapshot digest). */
function twoBundles(dir) {
  const a = buildSyntheticSeed();
  const bDir = path.join(dir, 'bundle-b'); fs.mkdirSync(bDir);
  const b = path.join(bDir, 'chaingate-seed.db');
  fs.copyFileSync(a.dbPath, b);
  const db = new Database(b);
  db.prepare("UPDATE seed_metadata SET value = ? WHERE key = 'corpus_snapshot_digest'").run('e'.repeat(64));
  db.close();
  fs.writeFileSync(`${b}.sha256`, `${sha(b)}  chaingate-seed.db\n`);
  return { A: a.dbPath, B: b, cleanupA: () => fs.rmSync(a.dir, { recursive: true, force: true }) };
}

function host({ v3 = true } = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'u03-update-'));
  const base = path.join(home, '.chaingate');
  fs.mkdirSync(base, { recursive: true });
  const seeds = twoBundles(home);
  let aId = null;
  if (v3) {
    aId = stageBundle({ dbPath: seeds.A, sha256Path: `${seeds.A}.sha256` }, base, { trust: 'unsigned-development' }).dir_name;
    activateBundle(base, aId);
  }
  const w = openWitnessDB(path.join(base, 'witness.db')).applySchema();
  w.insertOverride('p', '1.3.0', 'kept across everything'); w.close();
  const calls = { fetch: 0 };
  const deps = {
    fetchSeedBundle: async () => { calls.fetch += 1; throw new Error('test stub: no network'); },
    verifySeed: async () => { throw new Error('test stub'); },
    assertIntegrity: async () => ({ ok: true }),
    resolvePaths: (scope) => resolvePaths(scope, process.cwd(), { CHAINGATE_HOME: base }),
  };
  return { home, base, seeds, aId, deps, calls, witness: path.join(base, 'witness.db'),
    cleanup: () => { seeds.cleanupA(); fs.rmSync(home, { recursive: true, force: true }); } };
}

/** Run a command, capturing stderr. */
async function run(fn) {
  const err = []; const out = [];
  const e = console.error; const l = console.log;
  console.error = (...a) => err.push(a.join(' ')); console.log = (...a) => out.push(a.join(' '));
  try { return { code: await fn(), err: err.join('\n'), out: out.join('\n') }; } finally { console.error = e; console.log = l; }
}

test('plain update-seed on a v3 host REFUSES: no download, witness and activation unchanged', async () => {
  const h = host();
  try {
    const before = sha(h.witness);
    for (const args of [[], ['--force']]) {
      const r = await run(() => updateSeed(args, h.deps));
      assert.equal(r.code, 1, `update-seed ${args.join(' ')}: exit 1`);
      assert.equal(h.calls.fetch, 0, 'nothing was downloaded');
      assert.match(r.err, /Automatic download of v3 detection seeds is not available/);
      assert.match(r.err, new RegExp(`v3 bundle ${h.aId}`));
      assert.match(r.err, /Nothing was changed/);
      assert.match(r.err, /update-seed --seed <bundle>/);
      assert.equal(sha(h.witness), before, 'witness.db byte-identical');
      assert.equal(activeBundleId(h.base), h.aId, 'active bundle unchanged');
    }
  } finally { h.cleanup(); }
});

test('local update and rollback still work on a v3 host, and plain update-seed still refuses in between', async () => {
  const h = host();
  try {
    const up = await run(() => updateSeed(['--seed', h.seeds.B, '--unsigned-development'], h.deps));
    assert.equal(up.code, 0, up.err);
    const bId = activeBundleId(h.base);
    assert.notEqual(bId, h.aId, 'the local bundle is now active');
    assert.equal(previousBundleId(h.base), h.aId);

    const refused = await run(() => updateSeed([], h.deps));
    assert.equal(refused.code, 1);
    assert.equal(activeBundleId(h.base), bId, 'refusal left B active');

    const back = await run(() => updateSeed(['--rollback'], h.deps));
    assert.equal(back.code, 0, back.err);
    assert.equal(activeBundleId(h.base), h.aId, 'rolled back to A');
    assert.equal(h.calls.fetch, 0);
    const w = openWitnessDB(h.witness, { readonly: true });
    try { assert.equal(w.getOverride('p', '1.3.0').reason, 'kept across everything'); } finally { w.close(); }
  } finally { h.cleanup(); }
});

test('a v3 activation record that does not resolve also refuses (never falls back to the legacy download)', async () => {
  const h = host();
  try {
    fs.rmSync(path.join(h.base, 'seeds', h.aId), { recursive: true, force: true });   // dangling seeds/active
    const r = await run(() => updateSeed([], h.deps));
    assert.equal(r.code, 1);
    assert.equal(h.calls.fetch, 0);
    assert.match(r.err, /Automatic download of v3 detection seeds is not available/);
  } finally { h.cleanup(); }
});

test('a legacy-only host keeps its legacy download path (the refusal is v3-specific)', async () => {
  const h = host({ v3: false });
  try {
    const r = await run(() => updateSeed([], h.deps));
    assert.equal(h.calls.fetch, 1, 'the legacy path attempted its download, as before');
    assert.equal(r.code, 1, 'and reported the stubbed download failure');
    assert.match(r.err, /Download failed: test stub: no network/);
  } finally { h.cleanup(); }
});
