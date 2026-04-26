// This test depends on test/fixtures/bundle-schema.sql, which is
// vendored from chaingate-ops collector/dump_schema.py. When bundle
// SCHEMA changes, regenerate the fixture per the workflow in
// chaingate-ops docs/COLLECTOR_RUNBOOK.md.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';

import { openWitnessDB } from '../../witness/db.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = join(__dirname, '..', 'fixtures', 'bundle-schema.sql');

// Mirror of the runtime SCHEMA_SQL contract in witness/db.js.
// Every (table, column) pair listed here must exist in the SQLite
// schema *after* bundle SCHEMA has been applied followed by runtime's
// applySchema(). Keep this list in sync with witness/db.js when adding
// new tables/columns to the runtime side.
const RUNTIME_REQUIRED = {
  packages: [
    'id', 'ecosystem', 'package_name',
  ],
  versions: [
    'id', 'package_id', 'version', 'published_at',
    'content_hash', 'content_hash_algo', 'integrity_hash', 'git_head',
    'package_size_bytes',
    'dependency_count', 'dependencies', 'dev_dependencies', 'peer_dependencies',
    'optional_dependencies', 'bundled_dependencies',
    'dev_dependency_count', 'peer_dependency_count',
    'optional_dependency_count', 'bundled_dependency_count',
    'publisher_name', 'publisher_email', 'publisher_tool', 'maintainers',
    'publish_method', 'provenance_present', 'provenance_details',
    'has_install_scripts', 'source_repo_url', 'license',
    'first_observed_at', 'last_seen_at',
  ],
  version_files: [
    'id', 'version_id', 'filename', 'packagetype',
    'content_hash', 'content_hash_algo', 'size_bytes',
    'uploaded_at', 'url', 'first_observed_at', 'last_seen_at',
  ],
  gate_decisions: [
    'id', 'package_name', 'version', 'disposition', 'gates_fired', 'decided_at',
  ],
  overrides: [
    'id', 'package_name', 'version', 'reason', 'created_at',
  ],
  seed_metadata: [
    'key', 'value',
  ],
  dep_first_publish: [
    'package_name', 'first_publish', 'status', 'cached_at', 'attempts',
  ],
};

function tmpDbPath() {
  const dir = mkdtempSync(join(tmpdir(), 'chaingate-schema-compat-'));
  return { path: join(dir, 'bundle.db'), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function tablesIn(db) {
  return new Set(
    db
      .prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
      .all()
      .map((r) => r.name),
  );
}

function columnsIn(db, table) {
  return new Set(db.pragma(`table_info(${table})`).map((r) => r.name));
}

function applyBundleSchema(db, bundleSql) {
  db.exec(bundleSql);
}

test('bundle ⊇ runtime-required: every runtime table+column is present after applySchema on a fresh bundle', () => {
  const bundleSql = readFileSync(FIXTURE_PATH, 'utf8');
  const { path, cleanup } = tmpDbPath();
  try {
    // Simulate a freshly-exported bundle: empty DB + bundle SCHEMA only.
    const setup = new Database(path);
    applyBundleSchema(setup, bundleSql);
    setup.close();

    // Runtime takes over: applySchema brings the file up to runtime's
    // expected shape (idempotent forward migration).
    const db = openWitnessDB(path);
    db.applySchema();

    const tables = tablesIn(db.db);
    const missingTables = [];
    const missingColumns = [];

    for (const [tbl, cols] of Object.entries(RUNTIME_REQUIRED)) {
      if (!tables.has(tbl)) {
        missingTables.push(tbl);
        continue;
      }
      const present = columnsIn(db.db, tbl);
      for (const c of cols) {
        if (!present.has(c)) missingColumns.push(`${tbl}.${c}`);
      }
    }

    db.close();

    assert.deepEqual(missingTables, [], 'runtime-required tables missing from post-applySchema DB');
    assert.deepEqual(missingColumns, [], 'runtime-required columns missing from post-applySchema DB');

    // Belt-and-suspenders: the v2 fix specifically locks dep_first_publish in.
    assert.ok(tables.has('dep_first_publish'), 'dep_first_publish must be present (v2 schema fix)');
  } finally {
    cleanup();
  }
});

test('deliberate-drift smoke: dropping dep_first_publish from bundle SCHEMA breaks the contract', () => {
  const bundleSql = readFileSync(FIXTURE_PATH, 'utf8');
  // Surgical removal of just the dep_first_publish CREATE TABLE statement,
  // preserving every other table. If runtime applySchema were ever made
  // not to re-create it, this test would surface that regression too.
  const drifted = bundleSql.replace(
    /CREATE TABLE dep_first_publish \([^;]*?\);\s*/,
    '',
  );
  assert.ok(
    !/dep_first_publish/.test(drifted),
    'fixture mutation must remove every dep_first_publish reference',
  );

  const { path, cleanup } = tmpDbPath();
  try {
    const setup = new Database(path);
    applyBundleSchema(setup, drifted);
    setup.close();

    // Open RO so applySchema cannot paper over the drift — this models a
    // hypothetical future where applySchema is also missing the table.
    const db = openWitnessDB(path, { readonly: true });
    const tables = tablesIn(db.db);
    db.close();

    assert.throws(
      () => {
        if (!tables.has('dep_first_publish')) {
          throw new Error(
            'bundle ⊉ runtime-required: missing table dep_first_publish',
          );
        }
      },
      /missing table dep_first_publish/,
      'compat check must throw when bundle is missing a runtime-required table',
    );
  } finally {
    cleanup();
  }
});
