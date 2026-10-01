// U-05 R2-2 legacy part, owner decision 7 requirements 1 and 2: the in-place refresh against the REAL schema (a witness
// installed from a legacy seed: test/fixtures/bundle-schema.sql; and one created by the runtime: witness/db.js), and the
// semantics of the seed's own decisions and overrides. Through `update-seed` (the legacy download route) with its
// existing `deps`: the download is a local copy of a synthetic signed seed, verification is real with a TEST key.
// Validation is logical: every row, relationships and EFFECTIVE decisions, not counts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

import updateSeed from '../../cli/commands/update-seed.js';
import { resolvePaths } from '../../cli/paths.js';
import { verifySeed } from '../../witness/seed_verify.js';
import { freshHome } from '../helpers/u05-r22.mjs';
import { testKey, buildLegacySeed, legacyWitness, snapshot, effective, project, DEFAULT_PKGS, NEW_PKGS }
  from '../helpers/u05-r22-legacy.mjs';

const key = testKey();
const REPLACED = ['packages', 'versions', 'version_files', 'attack_labels', 'seed_metadata'];

function host() {
  const { home, base } = freshHome('refresh');
  const stage = path.join(home, 'stage');
  return { home, base, stage, w: path.join(base, 'witness.db'), cleanup: () => fs.rmSync(home, { recursive: true, force: true }) };
}
/** update-seed's deps: the "download" is a fresh copy of `seed` (the old route renames it away); real verification. */
const deps = (h, seed) => ({
  fetchSeedBundle: async () => {
    const d = fs.mkdtempSync(path.join(h.stage + '-')); const out = {};
    for (const [k, f] of [['dbPath', seed.db], ['sha256Path', seed.sha], ['sigPath', seed.sig]]) {
      out[k] = path.join(d, path.basename(f)); fs.copyFileSync(f, out[k]);
    }
    return out;
  },
  verifySeed: (db, sha, sig) => verifySeed(db, sha, sig, { pubkey: key.publicKey }),
  assertIntegrity: async () => ({ ok: true }),
  resolvePaths: (scope) => resolvePaths(scope, process.cwd(), { CHAINGATE_HOME: h.base }),
});
async function run(fn) {
  const out = []; const l = console.log; const e = console.error;
  console.log = (...a) => out.push(a.join(' ')); console.error = (...a) => out.push(a.join(' '));
  try { return { code: await fn(), out: out.join('\n') }; } finally { console.log = l; console.error = e; }
}
const cols = (db, t) => { const d = new Database(db, { readonly: true }); try { return d.pragma(`table_info(${t})`).map((c) => c.name); } finally { d.close(); } };
const versionPackageNames = (db) => { const d = new Database(db, { readonly: true }); try {
  return d.prepare('SELECT v.id, v.version, p.package_name FROM versions v JOIN packages p ON p.id = v.package_id ORDER BY v.id').all();
} finally { d.close(); } };

const LOCAL = {
  decisions: [
    { id: 5, pkg: 'alpha', ver: '1.0.0', disposition: 'BLOCK', at: '2026-02-01 00:00:00' },
    { id: 6, pkg: 'beta', ver: '2.0.0', disposition: 'WARN', at: '2026-02-02 00:00:00' },
    { id: 7, pkg: 'alpha', ver: '1.1.0', disposition: 'ALLOW', at: '2026-02-03 00:00:00', gates: [{ gate: 'override', result: 'ALLOW' }] },
  ],
  overrides: [{ id: 3, pkg: 'alpha', ver: '1.1.0', reason: 'local override' }],
  baselines: [{ pkg: 'delta', ver: '9.9.9' }],
  depCache: [{ name: 'left-pad', at: '2016-03-01T00:00:00Z' }],
};

for (const from of ['seed', 'runtime']) {
  test(`R1 (${from}-created witness) the seed tables equal the new seed; local tables and effective decisions unchanged`, async () => {
    const h = host();
    try {
      const old = buildLegacySeed(path.join(h.home, 'old'), { key, seedVersion: '2026.test.old', pkgs: DEFAULT_PKGS });
      const neu = buildLegacySeed(path.join(h.home, 'new'), { key, seedVersion: '2026.test.new', pkgs: NEW_PKGS,
        decisions: [{ pkg: 'gamma', ver: '3.0.0', disposition: 'BLOCK', at: '2026-03-01 00:00:00' }],
        overrides: [{ pkg: 'gamma', ver: '3.0.0', reason: 'seed override' }] });
      legacyWitness(h.base, { from, seed: old, local: LOCAL, sidecars: false });
      const before = snapshot(h.w); const effBefore = effective(h.w);
      const r = await run(() => updateSeed([], deps(h, neu)));
      assert.equal(r.code, 0, r.out);
      const after = snapshot(h.w); const seed = snapshot(neu.db);
      // every replaced table equals the seed's on the columns both have (row for row, by key)
      for (const t of REPLACED) {
        if (!after.tables.includes(t)) { assert.equal(from, 'runtime', `${t} missing`); continue; }
        const both = cols(h.w, t).filter((c) => cols(neu.db, t).includes(c));
        assert.deepEqual(project(after.rows[t], both), project(seed.rows[t], both), `${t} equals the seed`);
      }
      assert.deepEqual(after.fk, [], 'every relationship resolves');
      assert.equal(after.integrity, 'ok');
      assert.deepEqual(versionPackageNames(h.w), versionPackageNames(neu.db), 'each version belongs to the seed\'s package');
      // local tables: every local row unchanged, ids included; only the seed's rows for NEW keys are added
      assert.deepEqual(after.rows.gate_decisions.slice(0, before.rows.gate_decisions.length), before.rows.gate_decisions,
        'local decisions unchanged and not renumbered');
      assert.deepEqual(after.rows.gate_decisions.slice(before.rows.gate_decisions.length).map((d) => `${d.package_name}@${d.version}`),
        ['gamma@3.0.0'], 'only the seed decision for a key with no local history was imported');
      assert.deepEqual(after.rows.overrides.filter((o) => o.package_name === 'alpha'), before.rows.overrides);
      assert.deepEqual(after.rows.dep_first_publish, before.rows.dep_first_publish, 'the local dep cache is kept');
      // effective decisions: equal for every key that had one
      const effAfter = effective(h.w);
      for (const k of Object.keys(effBefore)) assert.deepEqual(effAfter[k], effBefore[k], `effective decision for ${k}`);
      // the approved replace semantics: a baseline observed only locally is not retained (as before R2-2)
      assert.equal(after.rows.packages.some((p) => p.package_name === 'delta'), false);
      if (from === 'runtime') assert.match(r.out, /not carried|attack_labels/);
    } finally { h.cleanup(); }
  });
}

// ---- refusals: nothing committed, the witness logically unchanged ----------------------------------------------------
const refusalCases = [
  ['R3 the seed lacks a required table (version_files)', { drop: ['version_files'] }, /no version_files table/],
  ['R4 the seed lacks a runtime column (versions.license)', { sql: 'ALTER TABLE versions DROP COLUMN license;' }, /no license column/],
  ['R8 the seed breaks a relationship (a version of a missing package)',
    { sql: "PRAGMA foreign_keys = OFF; INSERT INTO versions (id, package_id, version) VALUES (999, 77, '0.0.1');" }, /relationship/],
];
for (const [name, opts, why] of refusalCases) {
  test(`${name}: refused before anything is committed; the witness is unchanged`, async () => {
    const h = host();
    try {
      const old = buildLegacySeed(path.join(h.home, 'old'), { key, seedVersion: '2026.test.old' });
      const neu = buildLegacySeed(path.join(h.home, 'new'), { key, seedVersion: '2026.test.new', pkgs: NEW_PKGS, ...opts });
      legacyWitness(h.base, { from: 'seed', seed: old, local: LOCAL, sidecars: false });
      const before = snapshot(h.w);
      const r = await run(() => updateSeed([], deps(h, neu)));
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, why);
      assert.match(r.out, /nothing was (changed|committed)/);
      assert.deepEqual(snapshot(h.w).rows, before.rows);
      assert.equal(fs.existsSync(path.join(h.base, 'witness.db.install-pending.json')), false, 'no marker left behind');
    } finally { h.cleanup(); }
  });
}

test('R5 the witness has a required column the seed lacks: refused, unchanged', async () => {
  const h = host();
  try {
    const old = buildLegacySeed(path.join(h.home, 'old'), { key, seedVersion: '2026.test.old' });
    legacyWitness(h.base, { from: 'seed', seed: old, local: LOCAL, sidecars: false });
    // a NOT NULL column without a default, present only in the witness
    const d = new Database(h.w); d.exec(`CREATE TABLE seed_metadata_new (key TEXT PRIMARY KEY, value TEXT NOT NULL, origin TEXT NOT NULL);
      INSERT INTO seed_metadata_new SELECT key, value, 'local' FROM seed_metadata; DROP TABLE seed_metadata;
      ALTER TABLE seed_metadata_new RENAME TO seed_metadata;`); d.close();
    const neu = buildLegacySeed(path.join(h.home, 'new'), { key, seedVersion: '2026.test.new', pkgs: NEW_PKGS });
    const before = snapshot(h.w);
    const r = await run(() => updateSeed([], deps(h, neu)));
    assert.equal(r.code, 1, r.out); assert.match(r.out, /seed_metadata\.origin is required/);
    assert.deepEqual(snapshot(h.w).rows, before.rows);
  } finally { h.cleanup(); }
});

test('R6 an older-schema witness (lacking a runtime column) is refused in place, with the remedy', async () => {
  const h = host();
  try {
    const old = buildLegacySeed(path.join(h.home, 'old'), { key, seedVersion: '2026.test.old', sql: 'ALTER TABLE versions DROP COLUMN license;' });
    // built with raw SQL: the runtime itself cannot prepare its statements on such a witness (found by r22L-ff1, where
    // the setup through openWitnessDB failed instead of the case under test)
    fs.mkdirSync(h.base, { recursive: true }); fs.copyFileSync(old.db, h.w);
    { const d = new Database(h.w); d.prepare("INSERT INTO gate_decisions (id, package_name, version, disposition, gates_fired, decided_at) VALUES (5, 'alpha', '1.0.0', 'BLOCK', '[]', '2026-02-01 00:00:00')").run(); d.close(); }
    const neu = buildLegacySeed(path.join(h.home, 'new'), { key, seedVersion: '2026.test.new', pkgs: NEW_PKGS });
    const before = snapshot(h.w);
    const r = await run(() => updateSeed([], deps(h, neu)));
    assert.equal(r.code, 1, r.out); assert.match(r.out, /older schema/);
    assert.deepEqual(snapshot(h.w).rows, before.rows);
  } finally { h.cleanup(); }
});

test('R7 optional table: a seed without attack_labels CLEARS the witness copy (never mixed with the old seed\'s)', async () => {
  const h = host();
  try {
    const old = buildLegacySeed(path.join(h.home, 'old'), { key, seedVersion: '2026.test.old' });
    legacyWitness(h.base, { from: 'seed', seed: old, local: LOCAL, sidecars: false });
    assert.ok(snapshot(h.w).rows.attack_labels.length > 0);
    const neu = buildLegacySeed(path.join(h.home, 'new'), { key, seedVersion: '2026.test.new', pkgs: NEW_PKGS, drop: ['attack_labels'] });
    const r = await run(() => updateSeed([], deps(h, neu)));
    assert.equal(r.code, 0, r.out);
    assert.deepEqual(snapshot(h.w).rows.attack_labels, []);
  } finally { h.cleanup(); }
});

// ---- requirement 2: the seed's own decisions and overrides ------------------------------------------------------------
test('D-a colliding numeric ids: an unrelated seed decision with a local row\'s id is imported; the local row keeps its id', async () => {
  const h = host();
  try {
    const old = buildLegacySeed(path.join(h.home, 'old'), { key, seedVersion: '2026.test.old' });
    const neu = buildLegacySeed(path.join(h.home, 'new'), { key, seedVersion: '2026.test.new', pkgs: NEW_PKGS,
      decisions: [{ id: 5, pkg: 'zeta', ver: '1.0.0', disposition: 'BLOCK', at: '2026-03-01 00:00:00' }] });
    legacyWitness(h.base, { from: 'seed', seed: old, local: LOCAL, sidecars: false });
    const before = snapshot(h.w).rows.gate_decisions;
    const r = await run(() => updateSeed([], deps(h, neu)));
    assert.equal(r.code, 0, r.out);
    const after = snapshot(h.w).rows.gate_decisions;
    assert.deepEqual(after.find((d) => d.id === 5), before.find((d) => d.id === 5), 'local id 5 is still the local row');
    const z = after.filter((d) => d.package_name === 'zeta');
    assert.equal(z.length, 1, 'the unrelated seed row was imported, not dropped by the id collision');
    assert.notEqual(z[0].id, 5);
  } finally { h.cleanup(); }
});

test('D-b conflicting seed/local decisions for the same version: the local history and effective decision stand', async () => {
  const h = host();
  try {
    const old = buildLegacySeed(path.join(h.home, 'old'), { key, seedVersion: '2026.test.old' });
    const neu = buildLegacySeed(path.join(h.home, 'new'), { key, seedVersion: '2026.test.new', pkgs: NEW_PKGS,
      decisions: [{ pkg: 'beta', ver: '2.0.0', disposition: 'BLOCK', at: '2026-09-09 00:00:00' }] });   // later than local
    legacyWitness(h.base, { from: 'seed', seed: old, local: LOCAL, sidecars: false });
    const eff = effective(h.w)['beta@2.0.0'];
    const r = await run(() => updateSeed([], deps(h, neu)));
    assert.equal(r.code, 0, r.out);
    assert.deepEqual(effective(h.w)['beta@2.0.0'], eff, 'a seed row must not outrank local history');
    assert.equal(snapshot(h.w).rows.gate_decisions.filter((d) => d.package_name === 'beta').length, 1);
  } finally { h.cleanup(); }
});

test('D-c equal timestamps and different dispositions: seed ties keep the seed\'s order; local ties are not touched', async () => {
  const h = host();
  try {
    const old = buildLegacySeed(path.join(h.home, 'old'), { key, seedVersion: '2026.test.old' });
    const T = '2026-03-03 03:03:03';
    const neu = buildLegacySeed(path.join(h.home, 'new'), { key, seedVersion: '2026.test.new', pkgs: NEW_PKGS, decisions: [
      { id: 40, pkg: 'gamma', ver: '3.0.0', disposition: 'ALLOW', at: T }, { id: 41, pkg: 'gamma', ver: '3.0.0', disposition: 'BLOCK', at: T },
      { id: 42, pkg: 'alpha', ver: '1.0.0', disposition: 'ALLOW', at: '2026-02-01 00:00:00' }] });                   // ties the local row
    legacyWitness(h.base, { from: 'seed', seed: old, local: LOCAL, sidecars: false });
    const effAlpha = effective(h.w)['alpha@1.0.0'];
    const r = await run(() => updateSeed([], deps(h, neu)));
    assert.equal(r.code, 0, r.out);
    const e = effective(h.w);
    assert.equal(e['gamma@3.0.0'].latest.disposition, 'BLOCK', 'the seed\'s own tie order (id 41 after 40) is kept');
    assert.deepEqual(e['alpha@1.0.0'], effAlpha, 'an equal-timestamp seed row does not change the local effective decision');
  } finally { h.cleanup(); }
});

test('D-d local override precedence: a seed override for the same version never replaces the local one', async () => {
  const h = host();
  try {
    const old = buildLegacySeed(path.join(h.home, 'old'), { key, seedVersion: '2026.test.old' });
    const neu = buildLegacySeed(path.join(h.home, 'new'), { key, seedVersion: '2026.test.new', pkgs: NEW_PKGS,
      overrides: [{ id: 3, pkg: 'alpha', ver: '1.1.0', reason: 'seed says otherwise' }, { pkg: 'gamma', ver: '3.0.0', reason: 'seed only' }] });
    legacyWitness(h.base, { from: 'seed', seed: old, local: LOCAL, sidecars: false });
    const before = snapshot(h.w).rows.overrides;
    const r = await run(() => updateSeed([], deps(h, neu)));
    assert.equal(r.code, 0, r.out);
    const after = snapshot(h.w).rows.overrides;
    assert.deepEqual(after.find((o) => o.package_name === 'alpha'), before.find((o) => o.package_name === 'alpha'));
    assert.equal(after.filter((o) => o.package_name === 'gamma').length, 1, 'a seed-only override is imported');
  } finally { h.cleanup(); }
});

test('D-e repeated refreshes import nothing twice (no duplicates on retry)', async () => {
  const h = host();
  try {
    const old = buildLegacySeed(path.join(h.home, 'old'), { key, seedVersion: '2026.test.old' });
    const neu = buildLegacySeed(path.join(h.home, 'new'), { key, seedVersion: '2026.test.new', pkgs: NEW_PKGS,
      decisions: [{ pkg: 'gamma', ver: '3.0.0', disposition: 'BLOCK', at: '2026-03-01 00:00:00' }],
      overrides: [{ pkg: 'gamma', ver: '3.0.0', reason: 'seed only' }] });
    legacyWitness(h.base, { from: 'seed', seed: old, local: LOCAL, sidecars: false });
    assert.equal((await run(() => updateSeed([], deps(h, neu)))).code, 0);
    const once = snapshot(h.w);
    for (let i = 0; i < 2; i += 1) assert.equal((await run(() => updateSeed(['--force'], deps(h, neu)))).code, 0);
    const thrice = snapshot(h.w);
    assert.deepEqual(thrice.rows.gate_decisions, once.rows.gate_decisions);
    assert.deepEqual(thrice.rows.overrides, once.rows.overrides);
  } finally { h.cleanup(); }
});
