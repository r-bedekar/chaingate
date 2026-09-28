// Trust modes, compatibility enforcement and input refusal — the JS side of the amended CFT-04 R1/R2,
// mirroring tools/tests/test_cft04_reader_review.py. Tiny synthetic seeds and an ephemeral key only.
import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import Database from 'better-sqlite3';
import R from '../../seed/v3/reader.js';

const GOOD_RULES = { channel_a: 'infra5d-1.2+fu2final+norm1+sizeshrink', dac_trajectory: 'dac-trajectory-1.0' };
const DEV = { trust: R.TRUST_UNSIGNED_DEV };

function tmpdir() { return fs.mkdtempSync(path.join(os.tmpdir(), 'cft04-js-')); }

function tinySeed(dir, overrides = {}, drop = []) {
  const db = path.join(dir, 'seed.db');
  const con = new Database(db);
  con.exec('CREATE TABLE seed_metadata (key TEXT PRIMARY KEY, value TEXT)');
  for (const t of R.REQUIRED_TABLES) if (t !== 'seed_metadata') con.exec(`CREATE TABLE ${t} (placeholder INTEGER)`);
  const meta = {
    schema_version: '3', contract_version: 'cft-seed-v3-contract-1.0',
    rule_versions: JSON.stringify(GOOD_RULES), corpus_snapshot_digest: 'a'.repeat(64),
    history_cutoff: '2026-09-19T20:50:26Z', ...overrides,
  };
  for (const k of drop) delete meta[k];
  const ins = con.prepare('INSERT INTO seed_metadata VALUES (?, ?)');
  for (const [k, v] of Object.entries(meta)) ins.run(k, v);
  con.close();
  restamp(db);
  return db;
}
function restamp(db) {
  const d = R.sha256File(db);
  fs.writeFileSync(`${db}.sha256`, `${d}\n`);
  return d;
}
function keypair(dir) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const pub = path.join(dir, 'ephemeral-test-public.pem');
  fs.writeFileSync(pub, publicKey.export({ type: 'spki', format: 'pem' }));
  return { privateKey, pub };
}

// --- trust modes --------------------------------------------------------------------------------
test('the signed message is the ASCII hex digest, matching sign.py and seed_verify.js', () => {
  const dir = tmpdir(); const db = tinySeed(dir); const { privateKey, pub } = keypair(dir);
  fs.writeFileSync(`${db}.sig`, crypto.sign(null, Buffer.from(restamp(db), 'ascii'), privateKey));
  const rep = R.verify(db, { trust: R.TRUST_AUTHENTICATED, pubkeyPath: pub });
  assert.strictEqual(rep.ok, true, JSON.stringify(rep.checks));
  assert.strictEqual(rep.authenticated, true);
});

test('a present signature is never ignored, in either mode', () => {
  const dir = tmpdir(); const db = tinySeed(dir);
  fs.writeFileSync(`${db}.sig`, Buffer.from('invalid signature'));
  for (const trust of R.TRUST_MODES) {
    const rep = R.verify(db, { trust });
    assert.strictEqual(rep.ok, false);
    assert.match(String(rep.checks.signature), /no trusted public key/);
  }
});

test('an invalid signature against the pinned key is refused', () => {
  const dir = tmpdir(); const db = tinySeed(dir); const { pub } = keypair(dir);
  fs.writeFileSync(`${db}.sig`, Buffer.alloc(64));
  const rep = R.verify(db, { trust: R.TRUST_UNSIGNED_DEV, pubkeyPath: pub });
  assert.strictEqual(rep.ok, false);
  assert.match(String(rep.checks.signature), /does not verify/);
});

test('authenticated is the DEFAULT and requires both a key and a signature', () => {
  const dir = tmpdir(); const db = tinySeed(dir); const { pub } = keypair(dir);
  assert.strictEqual(R.verify(db).ok, false, 'an unsigned seed must not pass by default');
  const noSig = R.verify(db, { trust: R.TRUST_AUTHENTICATED, pubkeyPath: pub });
  assert.match(String(noSig.checks.signature), /requires a pinned key and a valid signature/);
  const noKey = R.verify(db, { trust: R.TRUST_AUTHENTICATED });
  assert.ok('trusted_key' in noKey.checks);
});

test('unsigned-development must be stated and is reported as unauthenticated', () => {
  const dir = tmpdir(); const db = tinySeed(dir);
  const rep = R.verify(db, DEV);
  assert.strictEqual(rep.ok, true, JSON.stringify(rep.checks));
  assert.strictEqual(rep.authenticated, false);
  assert.strictEqual(rep.trust_mode, R.TRUST_UNSIGNED_DEV);
});

test('an unknown trust mode is rejected outright', () => {
  assert.throws(() => R.verify('/nonexistent', { trust: 'whatever' }), /trust must be one of/);
});

// --- compatibility, not mere presence -------------------------------------------------------------
test('an unimplemented rule version is refused', () => {
  const dir = tmpdir();
  const db = tinySeed(dir, { rule_versions: JSON.stringify({ channel_a: 'unknown-999', dac_trajectory: 'unknown-999' }) });
  const rep = R.verify(db, DEV);
  assert.strictEqual(rep.ok, false);
  assert.match(String(rep.checks.rule_versions), /does not implement/);
});

test('an unknown rule FAMILY is refused', () => {
  const dir = tmpdir();
  const db = tinySeed(dir, { rule_versions: JSON.stringify({ ...GOOD_RULES, some_new_family: '1.0' }) });
  const rep = R.verify(db, DEV);
  assert.strictEqual(rep.ok, false);
  assert.match(String(rep.checks.rule_versions), /rule families this reader does not implement/);
});

for (const key of ['corpus_snapshot_digest', 'history_cutoff', 'rule_versions']) {
  test(`a missing mandatory binding is refused: ${key}`, () => {
    const dir = tmpdir(); const db = tinySeed(dir, {}, [key]);
    const rep = R.verify(db, DEV);
    assert.strictEqual(rep.ok, false);
    const said = `${rep.checks.required_bindings} ${rep.checks.rule_versions}`;
    assert.ok(said.includes(key) || rep.checks.rule_versions !== true, said);
  });
}

test('an unimplemented schema_version is refused, and open throws a refusal', () => {
  const dir = tmpdir(); const db = tinySeed(dir, { schema_version: '4' });
  assert.strictEqual(R.verify(db, DEV).ok, false);
  assert.throws(() => R.openSeed(db, DEV), R.SeedRefused);
});

test('a seed that cannot state its schema is refused before any query', () => {
  const dir = tmpdir(); const db = tinySeed(dir);
  const con = new Database(db); con.exec('DROP TABLE seed_metadata'); con.close(); restamp(db);
  const rep = R.verify(db, DEV);
  assert.strictEqual(rep.ok, false);
  assert.match(String(rep.checks.schema_version), /seed_metadata is absent/);
});

test('the two contract_version namespaces are not conflated', () => {
  const dir = tmpdir(); const db = tinySeed(dir);
  const rep = R.verify(db, DEV);
  assert.strictEqual(rep.meta.seed_contract_version, 'cft-seed-v3-contract-1.0');
  assert.strictEqual(rep.meta.detection_contract_version, R.IMPLEMENTED_DETECTION_CONTRACT);
  assert.notStrictEqual(rep.meta.seed_contract_version, rep.meta.detection_contract_version);
  assert.ok('seed_contract_version' in rep.checks && !('contract_version' in rep.checks));
});

// --- malformed input gives named refusals, never tracebacks ---------------------------------------
test('an empty sha256 sidecar is a named refusal', () => {
  const dir = tmpdir(); const db = tinySeed(dir);
  fs.writeFileSync(`${db}.sha256`, '');
  assert.match(String(R.verify(db, DEV).checks.content_digest), /is empty/);
});

test('a digest mismatch is a named refusal', () => {
  const dir = tmpdir(); const db = tinySeed(dir);
  fs.writeFileSync(`${db}.sha256`, `${'0'.repeat(64)}\n`);
  assert.match(String(R.verify(db, DEV).checks.content_digest), /content digest .* != sidecar/);
});

test('a non-SQLite file is a named refusal, not a DatabaseError', () => {
  const dir = tmpdir(); const db = path.join(dir, 'not-a-seed.db');
  fs.writeFileSync(db, Buffer.from('not a sqlite database'.repeat(16)));
  const rep = R.verify(db, DEV);
  assert.strictEqual(rep.ok, false);
  assert.ok(rep.checks.openable !== undefined || rep.checks.readable_sqlite !== undefined, JSON.stringify(rep.checks));
  assert.throws(() => R.openSeed(db, DEV), R.SeedRefused);
});

test('an absent file is a named refusal', () => {
  const rep = R.verify(path.join(tmpdir(), 'nope.db'), DEV);
  assert.strictEqual(rep.ok, false);
  assert.match(String(rep.checks.present), /no such file/);
});

test('an out-of-band expectation is enforced', () => {
  const dir = tmpdir(); const db = tinySeed(dir);
  const rep = R.verify(db, { ...DEV, expect: { corpus_snapshot_digest: '0'.repeat(64) } });
  assert.strictEqual(rep.ok, false);
  assert.notStrictEqual(rep.checks['expect.corpus_snapshot_digest'], true);
});
