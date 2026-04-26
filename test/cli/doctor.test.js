// Tests for cli/commands/doctor.js. Covers:
//   - aggregateExit() severity matrix (unit)
//   - classifySelfWitnessSeverity() reason matrix (unit)
//   - doctor() integration paths that don't require crypto
//     (missing witness db; missing/skipped seed-sig artifacts;
//      tampered sig produces tamper severity using injected pubkey-mismatch)
//   - Gate-3 G3-2c regression: doctor exits OK after applySchema mutates
//     witness.db, when persisted .sha256/.sig pair is genuine. Conditional
//     on seed_export/ presence — mirrors the existing seed_verify.test.js
//     smoke pattern.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  copyFileSync,
  rmSync,
  existsSync,
  readFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  generateKeyPairSync,
  sign as cryptoSign,
  randomBytes,
} from 'node:crypto';

import doctor, {
  aggregateExit,
  classifySelfWitnessSeverity,
} from '../../cli/commands/doctor.js';
import { EXIT } from '../../cli/constants.js';
import { openWitnessDB } from '../../witness/db.js';
import { sha256File } from '../../witness/seed_verify.js';

// ── aggregateExit unit tests ─────────────────────────────────────────────

test('aggregateExit: empty checks → OK', () => {
  assert.equal(aggregateExit([]), EXIT.OK);
});

test('aggregateExit: all pass → OK', () => {
  const r = aggregateExit([
    { name: 'a', pass: true },
    { name: 'b', pass: true },
  ]);
  assert.equal(r, EXIT.OK);
});

test('aggregateExit: any tamper → INTEGRITY_TAMPER (highest precedence)', () => {
  const r = aggregateExit([
    { name: 'a', pass: true },
    { name: 'b', pass: false, severity: 'tamper' },
    { name: 'c', pass: false, severity: 'unverifiable' },
    { name: 'd', pass: false }, // would be ERROR alone
  ]);
  assert.equal(r, EXIT.INTEGRITY_TAMPER);
});

test('aggregateExit: non-severity fail (no tamper) → ERROR', () => {
  const r = aggregateExit([
    { name: 'a', pass: true },
    { name: 'b', pass: false }, // operational fail
  ]);
  assert.equal(r, EXIT.ERROR);
});

test('aggregateExit: ERROR beats unverifiable when both present', () => {
  const r = aggregateExit([
    { name: 'a', pass: false }, // operational
    { name: 'b', pass: false, severity: 'unverifiable' },
  ]);
  assert.equal(r, EXIT.ERROR);
});

test('aggregateExit: any unverifiable (no tamper, no plain-fail) → INTEGRITY_UNVERIFIABLE', () => {
  const r = aggregateExit([
    { name: 'a', pass: true },
    { name: 'b', pass: false, severity: 'unverifiable' },
  ]);
  assert.equal(r, EXIT.INTEGRITY_UNVERIFIABLE);
});

test('aggregateExit: skipped is informational, does not affect exit', () => {
  const r = aggregateExit([
    { name: 'a', pass: true },
    { name: 'b', pass: false, severity: 'skipped' },
  ]);
  assert.equal(r, EXIT.OK);
});

test('aggregateExit: tamper + skipped → INTEGRITY_TAMPER (skipped ignored)', () => {
  const r = aggregateExit([
    { name: 'a', pass: false, severity: 'tamper' },
    { name: 'b', pass: false, severity: 'skipped' },
  ]);
  assert.equal(r, EXIT.INTEGRITY_TAMPER);
});

test('aggregateExit: unverifiable + skipped → INTEGRITY_UNVERIFIABLE', () => {
  const r = aggregateExit([
    { name: 'a', pass: true },
    { name: 'b', pass: false, severity: 'unverifiable' },
    { name: 'c', pass: false, severity: 'skipped' },
  ]);
  assert.equal(r, EXIT.INTEGRITY_UNVERIFIABLE);
});

// ── classifySelfWitnessSeverity unit tests (reason matrix) ───────────────
//
// Encodes the v3 working-doc table for self-witness display severity:
//
//   status        | reason                    | witnessHasCG | severity
//   --------------+---------------------------+--------------+--------------
//   verified      | (any)                     | (any)        | null (pass)
//   tamper        | (any)                     | (any)        | 'tamper'
//   unverifiable  | not_in_witness            | true         | 'unverifiable'
//   unverifiable  | not_in_witness            | false        | 'skipped'
//   unverifiable  | lockfile_missing          | (any)        | 'skipped'
//   unverifiable  | install_root_not_found    | (any)        | 'unverifiable'
//   unverifiable  | witness_read_failed       | (any)        | 'unverifiable'

test('classifySelfWitnessSeverity: verified → null', () => {
  assert.equal(
    classifySelfWitnessSeverity({ status: 'verified', reason: 'integrity_match' }, true),
    null,
  );
  assert.equal(
    classifySelfWitnessSeverity({ status: 'verified', reason: 'integrity_match' }, false),
    null,
  );
});

test('classifySelfWitnessSeverity: tamper → "tamper"', () => {
  assert.equal(
    classifySelfWitnessSeverity({ status: 'tamper', reason: 'integrity_mismatch' }, true),
    'tamper',
  );
});

test('classifySelfWitnessSeverity: not_in_witness + witness has chaingate → "unverifiable"', () => {
  assert.equal(
    classifySelfWitnessSeverity({ status: 'unverifiable', reason: 'not_in_witness' }, true),
    'unverifiable',
  );
});

test('classifySelfWitnessSeverity: not_in_witness + witness empty (pre-publish) → "skipped"', () => {
  assert.equal(
    classifySelfWitnessSeverity({ status: 'unverifiable', reason: 'not_in_witness' }, false),
    'skipped',
  );
});

test('classifySelfWitnessSeverity: lockfile_missing → "skipped"', () => {
  assert.equal(
    classifySelfWitnessSeverity({ status: 'unverifiable', reason: 'lockfile_missing' }, false),
    'skipped',
  );
  assert.equal(
    classifySelfWitnessSeverity({ status: 'unverifiable', reason: 'lockfile_missing' }, true),
    'skipped',
  );
});

test('classifySelfWitnessSeverity: install_root_not_found → "unverifiable"', () => {
  assert.equal(
    classifySelfWitnessSeverity({ status: 'unverifiable', reason: 'install_root_not_found' }, false),
    'unverifiable',
  );
});

test('classifySelfWitnessSeverity: witness_read_failed → "unverifiable"', () => {
  assert.equal(
    classifySelfWitnessSeverity({ status: 'unverifiable', reason: 'witness_read_failed' }, false),
    'unverifiable',
  );
});

// ── doctor() integration helpers ─────────────────────────────────────────

function makeProjectFixture() {
  const root = mkdtempSync(join(tmpdir(), 'chaingate-doctor-'));
  const cgDir = join(root, '.chaingate');
  mkdirSync(cgDir, { recursive: true });
  return {
    root,
    cgDir,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

// Build an empty-but-valid witness.db at the fixture path. applySchema is
// idempotent — running it produces a real schema-shaped witness DB.
function writeEmptyWitnessDb(dbPath) {
  const db = openWitnessDB(dbPath, { readonly: false });
  db.applySchema();
  db.close();
}

// Run doctor(args) against a fixture and return parsed JSON checks + exit
// code. doctor reads paths from process.cwd() when scope is 'project', so
// chdir into the fixture before calling.
async function runDoctorJson(fixture, extraArgs = []) {
  const prevCwd = process.cwd();
  const captured = [];
  const prevLog = console.log;
  console.log = (line) => captured.push(line);
  process.chdir(fixture.root);
  let exitCode;
  try {
    exitCode = await doctor(['--scope', 'project', '--json', ...extraArgs]);
  } finally {
    console.log = prevLog;
    process.chdir(prevCwd);
  }
  // doctor logs the JSON as a single string when --json is set
  const json = JSON.parse(captured.join('\n'));
  return { exit: exitCode, checks: json };
}

function findCheck(checks, name) {
  return checks.find((c) => c.name === name);
}

// ── doctor() integration: seed-signature paths ───────────────────────────

test('doctor: missing witness DB → seed-signature severity=unverifiable', async () => {
  const f = makeProjectFixture();
  try {
    // No witness.db at all
    const { checks } = await runDoctorJson(f);
    const c = findCheck(checks, 'seed-signature');
    assert.ok(c, 'seed-signature check should be present');
    assert.equal(c.pass, false);
    assert.equal(c.severity, 'unverifiable');
    assert.match(c.detail, /no witness database/);
  } finally {
    f.cleanup();
  }
});

test('doctor: witness DB present but no .sha256/.sig → severity=skipped', async () => {
  const f = makeProjectFixture();
  try {
    writeEmptyWitnessDb(join(f.cgDir, 'witness.db'));
    const { checks } = await runDoctorJson(f);
    const c = findCheck(checks, 'seed-signature');
    assert.equal(c.pass, false);
    assert.equal(c.severity, 'skipped');
    assert.match(c.detail, /no persisted/);
  } finally {
    f.cleanup();
  }
});

test('doctor: missing .sha256 only → severity=skipped', async () => {
  const f = makeProjectFixture();
  try {
    writeEmptyWitnessDb(join(f.cgDir, 'witness.db'));
    // Write only .sig, not .sha256
    writeFileSync(join(f.cgDir, 'witness.db.sig'), randomBytes(64));
    const { checks } = await runDoctorJson(f);
    const c = findCheck(checks, 'seed-signature');
    assert.equal(c.severity, 'skipped');
  } finally {
    f.cleanup();
  }
});

test('doctor: missing .sig only → severity=skipped', async () => {
  const f = makeProjectFixture();
  try {
    writeEmptyWitnessDb(join(f.cgDir, 'witness.db'));
    // Write only .sha256, not .sig
    writeFileSync(
      join(f.cgDir, 'witness.db.sha256'),
      'a'.repeat(64) + '\n',
    );
    const { checks } = await runDoctorJson(f);
    const c = findCheck(checks, 'seed-signature');
    assert.equal(c.severity, 'skipped');
  } finally {
    f.cleanup();
  }
});

// Persisted artifacts present but signed with a key the runtime doesn't
// trust → SEED_SIG_INVALID against the embedded PUBKEY → severity 'tamper'.
// This proves the tamper path fires correctly under the new primitive.
test('doctor: artifacts signed with non-pinned key → severity=tamper', async () => {
  const f = makeProjectFixture();
  try {
    const dbPath = join(f.cgDir, 'witness.db');
    writeEmptyWitnessDb(dbPath);
    // Sign a hash with a fresh random key (NOT the embedded pinned key) —
    // the runtime's verifyPersistedSignature will reject this.
    const hash = await sha256File(dbPath);
    writeFileSync(join(f.cgDir, 'witness.db.sha256'), hash + '\n');
    const { privateKey } = generateKeyPairSync('ed25519');
    const sig = cryptoSign(null, Buffer.from(hash, 'ascii'), privateKey);
    writeFileSync(join(f.cgDir, 'witness.db.sig'), sig);

    const { checks } = await runDoctorJson(f);
    const c = findCheck(checks, 'seed-signature');
    assert.equal(c.pass, false);
    assert.equal(c.severity, 'tamper');
    assert.match(c.detail, /SEED_SIG_INVALID/);
  } finally {
    f.cleanup();
  }
});

// ── Gate-3 G3-2c regression: post-applySchema, doctor's seed-signature
//    check must still pass against the genuine signed bundle. Pre-fix, this
//    was the smoking-gun failure: applySchema (proxy startup) mutated
//    witness.db, doctor's verifySeed re-hashed it, hash mismatch → TAMPER.
//    Post-fix, verifyPersistedSignature does not re-hash live DB.
//
//    Conditional: requires the real signed bundle in seed_export/ since
//    the runtime only verifies against the embedded pinned pubkey. Mirrors
//    the existing seed_export/ smoke test in seed_verify.test.js.

test('doctor: Gate-3 G3-2c — seed-signature passes after applySchema mutates witness.db', async (t) => {
  const realDb = join(process.cwd(), 'seed_export', 'chaingate-seed.db');
  const realSha = join(process.cwd(), 'seed_export', 'chaingate-seed.db.sha256');
  const realSig = join(process.cwd(), 'seed_export', 'chaingate-seed.db.sig');
  if (!existsSync(realSha) || !existsSync(realSig) || !existsSync(realDb)) {
    t.skip('no real seed_export/ bundle present — Gate-3 doctor smoke skipped');
    return;
  }

  const f = makeProjectFixture();
  try {
    const dbPath = join(f.cgDir, 'witness.db');
    const shaPath = join(f.cgDir, 'witness.db.sha256');
    const sigPath = join(f.cgDir, 'witness.db.sig');

    // Stage the real signed bundle as if init had just run
    copyFileSync(realDb, dbPath);
    copyFileSync(realSha, shaPath);
    copyFileSync(realSig, sigPath);

    // Sanity: persisted .sha256 matches DB right now (pre-mutation)
    const preHash = await sha256File(dbPath);
    assert.equal(preHash, readFileSync(shaPath, 'utf8').trim());

    // Simulate the proxy-startup applySchema that broke G3-2c. This is the
    // exact mutation: idempotent forward migration on a real, signed DB.
    const db = openWitnessDB(dbPath, { readonly: false });
    db.applySchema();
    db.close();

    // Confirm the mutation actually changed the bytes — without this the
    // test wouldn't be exercising the regression scenario at all.
    const postHash = await sha256File(dbPath);
    assert.notEqual(postHash, preHash, 'applySchema should have mutated DB bytes');

    // Now the test that matters: doctor's seed-signature check passes
    // against the persisted .sha256/.sig pair, regardless of mutated DB.
    const { checks } = await runDoctorJson(f);
    const c = findCheck(checks, 'seed-signature');
    assert.equal(c.pass, true, `seed-signature should pass; got: ${JSON.stringify(c)}`);
    assert.equal(c.severity, undefined);
    assert.match(c.detail, /Ed25519 signature verified/);
  } finally {
    f.cleanup();
  }
});
