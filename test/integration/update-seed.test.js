// End-to-end integration test for `chaingate update-seed`.
//
// Exercises the real updateSeed function with deps injected (C1):
// real I/O against tmpdir, real witness DB writes, real schema/swap/
// migration. The only mocked surfaces are the network fetch, the
// signature-verify, and the integrity-gate — those have their own
// dedicated coverage and aren't what this test is about.
//
// The job here is to lock down everything *downstream* of verification:
// seed-version readback, atomic swap, applySchema running post-swap
// (proves dep_first_publish lands in the local DB even when the bundle
// predates that runtime field), and gate_decisions / overrides
// preservation across the swap.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync, rmSync, copyFileSync, mkdirSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import updateSeed from '../../cli/commands/update-seed.js';
import { openWitnessDB } from '../../witness/db.js';
import { EXIT } from '../../cli/constants.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = join(__dirname, '..', 'fixtures', 'test-seed-bundle');
const FIXTURE_DB = join(FIXTURE_DIR, 'chaingate-seed.db');
const FIXTURE_SHA256 = join(FIXTURE_DIR, 'chaingate-seed.db.sha256');
const FIXTURE_SIG = join(FIXTURE_DIR, 'chaingate-seed.db.sig');

const DRIFT_FIXTURE_DIR = join(__dirname, '..', 'fixtures', 'test-seed-bundle-drifted');
const DRIFT_FIXTURE_DB = join(DRIFT_FIXTURE_DIR, 'chaingate-seed.db');
const DRIFT_FIXTURE_SHA256 = join(DRIFT_FIXTURE_DIR, 'chaingate-seed.db.sha256');
const DRIFT_FIXTURE_SIG = join(DRIFT_FIXTURE_DIR, 'chaingate-seed.db.sig');

function mkTmpHome() {
  return mkdtempSync(join(tmpdir(), 'chaingate-update-seed-int-'));
}

function buildPaths(home) {
  const base = join(home, '.chaingate');
  mkdirSync(base, { recursive: true });
  return {
    base,
    witnessDb: join(base, 'witness.db'),
    witnessDbSha256: join(base, 'witness.db.sha256'),
    witnessDbSig: join(base, 'witness.db.sig'),
    pidFile: join(base, 'proxy.pid'),
    logFile: join(base, 'proxy.log'),
    configFile: join(base, 'config.json'),
  };
}

function seedLocalDb(paths, { existingSeedVersion = '2026.test.0' } = {}) {
  const db = openWitnessDB(paths.witnessDb);
  db.applySchema();
  db.setSeedMetadata('seed_version', existingSeedVersion);
  db.insertGateDecision('preserved-pkg', '0.1.0', 'WARN', [
    { gate: 'fixture', result: 'WARN', detail: 'must-survive-swap' },
  ]);
  db.insertOverride('preserved-pkg', '0.2.0', 'allowed per fixture');
  db.close();
}

function stageBundle(stageDir, sources = {
  db: FIXTURE_DB, sha256: FIXTURE_SHA256, sig: FIXTURE_SIG,
}) {
  mkdirSync(stageDir, { recursive: true });
  const dbPath = join(stageDir, 'chaingate-seed.db');
  const sha256Path = join(stageDir, 'chaingate-seed.db.sha256');
  const sigPath = join(stageDir, 'chaingate-seed.db.sig');
  copyFileSync(sources.db, dbPath);
  copyFileSync(sources.sha256, sha256Path);
  copyFileSync(sources.sig, sigPath);
  return { dbPath, sha256Path, sigPath };
}

function captureConsole() {
  const origLog = console.log;
  const origErr = console.error;
  const captured = [];
  console.log = (...a) => captured.push(['log', a.join(' ')]);
  console.error = (...a) => captured.push(['err', a.join(' ')]);
  return {
    captured,
    restore: () => {
      console.log = origLog;
      console.error = origErr;
    },
  };
}

test('update-seed integration: fixture bundle → swap, applySchema, decisions/overrides preserved', async () => {
  const home = mkTmpHome();
  const stage = join(home, 'stage');
  const paths = buildPaths(home);

  seedLocalDb(paths);
  const bundle = stageBundle(stage);

  const deps = {
    fetchSeedBundle: async () => bundle,
    verifySeed: async () => ({ fingerprint: 'ed25519:test-fixture' }),
    assertIntegrity: async () => ({ ok: true }),
    resolvePaths: () => paths,
  };

  const cap = captureConsole();
  let exitCode;
  try {
    exitCode = await updateSeed([], deps);
  } finally {
    cap.restore();
  }

  // 1. Exit cleanly.
  assert.equal(exitCode, EXIT.OK, 'updateSeed should exit OK');

  // 2. No SQLite readonly/busy errors anywhere in captured output. Hop-1 +
  // hop-2 regression guard: if applySchema ever ran on a RO handle again,
  // SQLITE_READONLY would surface here.
  const flat = cap.captured.map(([, msg]) => msg).join('\n');
  assert.ok(
    !/SQLITE_READONLY/.test(flat),
    `unexpected SQLITE_READONLY in output:\n${flat}`,
  );
  assert.ok(
    !/SQLITE_BUSY/.test(flat),
    `unexpected SQLITE_BUSY in output:\n${flat}`,
  );

  // 3. Inspect the swapped-in witness DB.
  const inspector = openWitnessDB(paths.witnessDb, { readonly: true });
  try {
    // 3a. seed_version reflects the fixture.
    assert.equal(
      inspector.getSeedMetadata('seed_version'),
      '2026.test.1',
      'seed_version should match fixture',
    );

    // 3b. dep_first_publish table exists — proves applySchema ran post-swap
    // against a bundle that did not include it (the v2 install-ceremony fix).
    const tables = new Set(
      inspector.db
        .prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
        .all()
        .map((r) => r.name),
    );
    assert.ok(
      tables.has('dep_first_publish'),
      'dep_first_publish must be present after applySchema runs post-swap',
    );

    // 3c. gate_decisions row from the pre-swap local DB preserved.
    const decisionCount = inspector.db
      .prepare(
        `SELECT COUNT(*) AS n FROM gate_decisions
         WHERE package_name = ? AND version = ?`,
      )
      .get('preserved-pkg', '0.1.0').n;
    assert.equal(decisionCount, 1, 'gate_decisions row must survive the swap');

    // 3d. overrides row from the pre-swap local DB preserved.
    const override = inspector.getOverride('preserved-pkg', '0.2.0');
    assert.ok(override, 'overrides row must survive the swap');
    assert.equal(override.reason, 'allowed per fixture');
  } finally {
    inspector.close();
    rmSync(home, { recursive: true, force: true });
  }
});

test('schema-gap recovery: bundle missing dep_first_publish gets the table after applySchema post-swap', async () => {
  const home = mkTmpHome();
  const stage = join(home, 'stage');
  const paths = buildPaths(home);

  seedLocalDb(paths);
  const bundle = stageBundle(stage, {
    db: DRIFT_FIXTURE_DB, sha256: DRIFT_FIXTURE_SHA256, sig: DRIFT_FIXTURE_SIG,
  });

  // Pre-swap audit: confirm the staged bundle (the file that's about to be
  // renamed into place as the new local witness DB) genuinely lacks
  // dep_first_publish. Without this, an accidentally-happy fixture would
  // silently neuter the recovery assertion below into a tautology.
  {
    const probe = openWitnessDB(bundle.dbPath, { readonly: true });
    const hit = probe.db
      .prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name='dep_first_publish'`)
      .all();
    probe.close();
    console.log(`pre-swap dep_first_publish present: ${hit.length > 0}`);
    assert.equal(hit.length, 0, 'drift fixture must lack dep_first_publish before the swap');
  }

  const deps = {
    fetchSeedBundle: async () => bundle,
    verifySeed: async () => ({ fingerprint: 'ed25519:test-fixture' }),
    assertIntegrity: async () => ({ ok: true }),
    resolvePaths: () => paths,
  };

  const cap = captureConsole();
  let exitCode;
  try {
    exitCode = await updateSeed([], deps);
  } finally {
    cap.restore();
  }

  assert.equal(exitCode, EXIT.OK, 'updateSeed should exit OK');

  const flat = cap.captured.map(([, msg]) => msg).join('\n');
  assert.ok(
    !/SQLITE_READONLY/.test(flat),
    `unexpected SQLITE_READONLY in output:\n${flat}`,
  );
  assert.ok(
    !/SQLITE_BUSY/.test(flat),
    `unexpected SQLITE_BUSY in output:\n${flat}`,
  );

  const inspector = openWitnessDB(paths.witnessDb, { readonly: true });
  try {
    // Drifted bundle landed (not the happy-path one).
    assert.equal(
      inspector.getSeedMetadata('seed_version'),
      '2026.test.1.drifted',
      'seed_version should match drift fixture',
    );

    // Critical assertion: dep_first_publish was absent from the bundle (proven
    // above), the swap placed an absent-it DB at the local path, then
    // applySchema post-swap created it. This is the install-ceremony recovery
    // mechanism that hop-2 of Phase 5a was about.
    const tables = new Set(
      inspector.db
        .prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
        .all()
        .map((r) => r.name),
    );
    console.log(`post-swap dep_first_publish present: ${tables.has('dep_first_publish')}`);
    assert.ok(
      tables.has('dep_first_publish'),
      'dep_first_publish must be created by applySchema post-swap',
    );

    // Shape check, not just presence: column names match runtime contract.
    const cols = inspector.db.pragma('table_info(dep_first_publish)');
    const colNames = cols.map((c) => c.name).sort();
    assert.deepEqual(
      colNames,
      ['attempts', 'cached_at', 'first_publish', 'package_name', 'status'],
      'dep_first_publish columns must match the runtime SCHEMA contract',
    );
    const pk = cols.find((c) => c.name === 'package_name');
    assert.equal(pk.pk, 1, 'package_name must be the primary key');

    // Preserved across swap.
    const decisionCount = inspector.db
      .prepare(
        `SELECT COUNT(*) AS n FROM gate_decisions
         WHERE package_name = ? AND version = ?`,
      )
      .get('preserved-pkg', '0.1.0').n;
    assert.equal(decisionCount, 1, 'gate_decisions row must survive the swap');

    const override = inspector.getOverride('preserved-pkg', '0.2.0');
    assert.ok(override, 'overrides row must survive the swap');
    assert.equal(override.reason, 'allowed per fixture');
  } finally {
    inspector.close();
    rmSync(home, { recursive: true, force: true });
  }
});
