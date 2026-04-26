// Build a minimal signed seed bundle for the update-seed integration test.
// Generates an ephemeral ed25519 keypair, builds a small SQLite DB matching
// the bundle SCHEMA, signs the sha256-hex with the throwaway private key,
// and writes .db / .sha256 / .sig into this directory.
//
// The throwaway private key is generated at build time and discarded. Only
// the public artifacts (.db, .sha256, .sig) are committed. Production
// signature verification is covered by test/witness/seed_verify.test.js;
// the integration test mocks verifySeed and exercises everything downstream.
//
// Regenerate (happy path):  node test/fixtures/test-seed-bundle/build.js
// Regenerate (drift variant): node test/fixtures/test-seed-bundle/build.js --drift
//
// --drift writes to ../test-seed-bundle-drifted/ instead, with the
// dep_first_publish CREATE TABLE removed from SCHEMA before exec — used
// by the schema-gap recovery integration test.

import {
  generateKeyPairSync,
  createHash,
  sign as cryptoSign,
} from 'node:crypto';
import { readFileSync, writeFileSync, unlinkSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BUNDLE_SCHEMA_PATH = join(__dirname, '..', 'bundle-schema.sql');

const drift = process.argv.includes('--drift');
const OUT_DIR = drift
  ? join(__dirname, '..', 'test-seed-bundle-drifted')
  : __dirname;
const DB_PATH = join(OUT_DIR, 'chaingate-seed.db');
const SHA256_PATH = join(OUT_DIR, 'chaingate-seed.db.sha256');
const SIG_PATH = join(OUT_DIR, 'chaingate-seed.db.sig');

const SEED_VERSION = drift ? '2026.test.1.drifted' : '2026.test.1';
const EXPORTED_AT = '2026-04-26T00:00:00Z';

function main() {
  if (drift) {
    mkdirSync(OUT_DIR, { recursive: true });
  }
  for (const p of [DB_PATH, SHA256_PATH, SIG_PATH]) {
    if (existsSync(p)) unlinkSync(p);
  }

  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const spkiB64 = publicKey
    .export({ type: 'spki', format: 'der' })
    .toString('base64');

  let schema = readFileSync(BUNDLE_SCHEMA_PATH, 'utf8');
  if (drift) {
    // Simulates a pre-Option-C bundle (e.g., seed-v2.1) that predates the
    // dep_first_publish addition. The post-swap applySchema in update-seed.js
    // is the recovery mechanism this fixture exists to test. Same in-memory
    // mutation as schema-compat.test.js's deliberate-drift test, kept
    // structurally identical so a reviewer can recognize the pattern.
    schema = schema.replace(
      /CREATE TABLE dep_first_publish \([^;]*?\);\s*/,
      '',
    );
    if (/dep_first_publish/.test(schema)) {
      throw new Error('drift mutation failed to remove all dep_first_publish references');
    }
  }
  const db = new Database(DB_PATH);
  db.exec('PRAGMA foreign_keys = ON');
  db.exec(schema);

  db.prepare(
    `INSERT INTO packages (id, ecosystem, package_name) VALUES (?, 'npm', ?)`,
  ).run(1, 'fixture-pkg');

  db.prepare(
    `INSERT INTO versions
       (id, package_id, version, published_at, integrity_hash,
        dependency_count, dependencies,
        publisher_name, publisher_email,
        provenance_present, has_install_scripts)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    1, 1, '1.0.0',
    '2024-01-01T00:00:00.000Z',
    'sha512-fixture==',
    0, '{}',
    'fixture-publisher', 'fixture@example.invalid',
    0, 0,
  );

  const meta = [
    ['schema_version', '2'],
    ['seed_version', SEED_VERSION],
    ['exported_at', EXPORTED_AT],
    ['signing_key_fingerprint', 'ed25519:test-fixture'],
    ['signing_pubkey_spki_b64', spkiB64],
    ['row_count_packages', '1'],
    ['row_count_versions', '1'],
  ];
  const insertMeta = db.prepare(
    `INSERT INTO seed_metadata (key, value) VALUES (?, ?)`,
  );
  for (const [k, v] of meta) insertMeta.run(k, v);

  db.exec('VACUUM');
  db.close();

  const dbBytes = readFileSync(DB_PATH);
  const sha256Hex = createHash('sha256').update(dbBytes).digest('hex');
  writeFileSync(SHA256_PATH, sha256Hex + '\n');

  // Match export_seed.py convention: sign the hex string bytes, raw 64-byte
  // Ed25519 signature. node:crypto.sign(null, data, key) for Ed25519.
  const sig = cryptoSign(null, Buffer.from(sha256Hex, 'ascii'), privateKey);
  if (sig.length !== 64) {
    throw new Error(`expected 64-byte ed25519 sig, got ${sig.length}`);
  }
  writeFileSync(SIG_PATH, sig);

  console.log(`built fixture seed bundle${drift ? ' (drifted: no dep_first_publish)' : ''}:`);
  console.log(`  ${DB_PATH}`);
  console.log(`  ${SHA256_PATH}    ${sha256Hex}`);
  console.log(`  ${SIG_PATH}    (${sig.length} bytes)`);
  console.log(`  seed_version=${SEED_VERSION}`);
  console.log(`  pubkey spki_b64=${spkiB64}`);
  console.log(`  privkey: discarded (throwaway, regenerable)`);
}

main();
