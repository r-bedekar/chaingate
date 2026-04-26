import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateKeyPairSync,
  createPublicKey,
  createPrivateKey,
  sign as cryptoSign,
  randomBytes,
} from 'node:crypto';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';

import {
  verifySeed,
  verifyPersistedSignature,
  sha256File,
  SeedVerificationError,
} from '../../witness/seed_verify.js';

function tinySeedDb(path) {
  const db = new Database(path);
  db.exec(`
    CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);
    INSERT INTO t (v) VALUES ('a'), ('b'), ('c');
  `);
  db.close();
}

function writeHex(path, hex) {
  writeFileSync(path, hex + '\n');
}

function signBundle(dbPath, sha256Path, sigPath, privKey) {
  const hash = readFileSync(sha256Path, 'utf8').trim();
  const sig = cryptoSign(null, Buffer.from(hash, 'ascii'), privKey);
  writeFileSync(sigPath, sig);
}

function makeBundle() {
  const dir = mkdtempSync(join(tmpdir(), 'chaingate-seedverify-'));
  const dbPath = join(dir, 'chaingate-seed.db');
  const shaPath = join(dir, 'chaingate-seed.db.sha256');
  const sigPath = join(dir, 'chaingate-seed.db.sig');
  tinySeedDb(dbPath);

  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { dir, dbPath, shaPath, sigPath, publicKey, privateKey };
}

async function finalize(bundle) {
  const hash = await sha256File(bundle.dbPath);
  writeHex(bundle.shaPath, hash);
  signBundle(bundle.dbPath, bundle.shaPath, bundle.sigPath, bundle.privateKey);
  return hash;
}

test('happy path: verifySeed passes on a correctly-signed bundle', async () => {
  const bundle = makeBundle();
  try {
    await finalize(bundle);
    const result = await verifySeed(
      bundle.dbPath,
      bundle.shaPath,
      bundle.sigPath,
      { pubkey: bundle.publicKey },
    );
    assert.ok(result.sha256);
    assert.match(result.sha256, /^[0-9a-f]{64}$/);
    assert.equal(result.dbPath, bundle.dbPath);
  } finally {
    rmSync(bundle.dir, { recursive: true, force: true });
  }
});

test('sha256File streams and matches node:crypto', async () => {
  const bundle = makeBundle();
  try {
    const hash = await sha256File(bundle.dbPath);
    assert.match(hash, /^[0-9a-f]{64}$/);
    // second read should match
    const hash2 = await sha256File(bundle.dbPath);
    assert.equal(hash, hash2);
  } finally {
    rmSync(bundle.dir, { recursive: true, force: true });
  }
});

test('tamper db bytes → hash mismatch error', async () => {
  const bundle = makeBundle();
  try {
    await finalize(bundle);
    // Corrupt the DB after the sha256 was computed
    const buf = readFileSync(bundle.dbPath);
    buf[100] = buf[100] ^ 0xff;
    writeFileSync(bundle.dbPath, buf);

    await assert.rejects(
      () => verifySeed(bundle.dbPath, bundle.shaPath, bundle.sigPath, {
        pubkey: bundle.publicKey,
      }),
      (err) => {
        assert.ok(err instanceof SeedVerificationError);
        assert.equal(err.code, 'SEED_HASH_MISMATCH');
        return true;
      },
    );
  } finally {
    rmSync(bundle.dir, { recursive: true, force: true });
  }
});

test('swap sig with 64 random bytes → Ed25519 verify fails', async () => {
  const bundle = makeBundle();
  try {
    await finalize(bundle);
    writeFileSync(bundle.sigPath, randomBytes(64));

    await assert.rejects(
      () => verifySeed(bundle.dbPath, bundle.shaPath, bundle.sigPath, {
        pubkey: bundle.publicKey,
      }),
      (err) => {
        assert.ok(err instanceof SeedVerificationError);
        assert.equal(err.code, 'SEED_SIG_INVALID');
        return true;
      },
    );
  } finally {
    rmSync(bundle.dir, { recursive: true, force: true });
  }
});

test('tamper db + update sha256 to match → sig still fails (key-binding)', async () => {
  const bundle = makeBundle();
  try {
    await finalize(bundle);

    // Corrupt the db
    const buf = readFileSync(bundle.dbPath);
    buf[200] = buf[200] ^ 0x5a;
    writeFileSync(bundle.dbPath, buf);

    // Recompute sha256 so hash-check passes — but do NOT re-sign.
    const newHash = await sha256File(bundle.dbPath);
    writeHex(bundle.shaPath, newHash);

    await assert.rejects(
      () => verifySeed(bundle.dbPath, bundle.shaPath, bundle.sigPath, {
        pubkey: bundle.publicKey,
      }),
      (err) => {
        assert.ok(err instanceof SeedVerificationError);
        assert.equal(err.code, 'SEED_SIG_INVALID');
        return true;
      },
    );
  } finally {
    rmSync(bundle.dir, { recursive: true, force: true });
  }
});

test('sig from wrong key fails against embedded pubkey', async () => {
  const bundle = makeBundle();
  try {
    await finalize(bundle);
    // Re-sign with a different key, but still verify against bundle.publicKey
    const { privateKey: otherPriv } = generateKeyPairSync('ed25519');
    signBundle(bundle.dbPath, bundle.shaPath, bundle.sigPath, otherPriv);

    await assert.rejects(
      () => verifySeed(bundle.dbPath, bundle.shaPath, bundle.sigPath, {
        pubkey: bundle.publicKey,
      }),
      (err) => {
        assert.ok(err instanceof SeedVerificationError);
        assert.equal(err.code, 'SEED_SIG_INVALID');
        return true;
      },
    );
  } finally {
    rmSync(bundle.dir, { recursive: true, force: true });
  }
});

test('malformed sha256 file → SEED_SHA256_MALFORMED', async () => {
  const bundle = makeBundle();
  try {
    writeFileSync(bundle.shaPath, 'not a hash\n');
    writeFileSync(bundle.sigPath, randomBytes(64));
    await assert.rejects(
      () => verifySeed(bundle.dbPath, bundle.shaPath, bundle.sigPath, {
        pubkey: bundle.publicKey,
      }),
      (err) => {
        assert.equal(err.code, 'SEED_SHA256_MALFORMED');
        return true;
      },
    );
  } finally {
    rmSync(bundle.dir, { recursive: true, force: true });
  }
});

test('wrong-length signature → SEED_SIG_MALFORMED', async () => {
  const bundle = makeBundle();
  try {
    await finalize(bundle);
    writeFileSync(bundle.sigPath, randomBytes(32)); // wrong size
    await assert.rejects(
      () => verifySeed(bundle.dbPath, bundle.shaPath, bundle.sigPath, {
        pubkey: bundle.publicKey,
      }),
      (err) => {
        assert.equal(err.code, 'SEED_SIG_MALFORMED');
        return true;
      },
    );
  } finally {
    rmSync(bundle.dir, { recursive: true, force: true });
  }
});

// ---- verifyPersistedSignature --------------------------------------------
//
// The post-install primitive: verifies .sha256/.sig cryptographically over
// each other, deliberately decoupled from any live DB state. Doctor and
// integrity-gate use this; install paths still use verifySeed.

test('verifyPersistedSignature: passes on correctly-signed artifacts', async () => {
  const bundle = makeBundle();
  try {
    await finalize(bundle);
    const result = await verifyPersistedSignature(
      bundle.shaPath,
      bundle.sigPath,
      { pubkey: bundle.publicKey },
    );
    assert.match(result.sha256, /^[0-9a-f]{64}$/);
    assert.equal(typeof result.fingerprint, 'string');
  } finally {
    rmSync(bundle.dir, { recursive: true, force: true });
  }
});

test('verifyPersistedSignature: sig from wrong key → SEED_SIG_INVALID', async () => {
  const bundle = makeBundle();
  try {
    await finalize(bundle);
    const { privateKey: otherPriv } = generateKeyPairSync('ed25519');
    signBundle(bundle.dbPath, bundle.shaPath, bundle.sigPath, otherPriv);

    await assert.rejects(
      () => verifyPersistedSignature(bundle.shaPath, bundle.sigPath, {
        pubkey: bundle.publicKey,
      }),
      (err) => {
        assert.ok(err instanceof SeedVerificationError);
        assert.equal(err.code, 'SEED_SIG_INVALID');
        return true;
      },
    );
  } finally {
    rmSync(bundle.dir, { recursive: true, force: true });
  }
});

test('verifyPersistedSignature: missing .sha256 → SEED_SHA256_READ_FAILED', async () => {
  const bundle = makeBundle();
  try {
    await finalize(bundle);
    rmSync(bundle.shaPath);
    await assert.rejects(
      () => verifyPersistedSignature(bundle.shaPath, bundle.sigPath, {
        pubkey: bundle.publicKey,
      }),
      (err) => {
        assert.equal(err.code, 'SEED_SHA256_READ_FAILED');
        return true;
      },
    );
  } finally {
    rmSync(bundle.dir, { recursive: true, force: true });
  }
});

test('verifyPersistedSignature: missing .sig → SEED_SIG_READ_FAILED', async () => {
  const bundle = makeBundle();
  try {
    await finalize(bundle);
    rmSync(bundle.sigPath);
    await assert.rejects(
      () => verifyPersistedSignature(bundle.shaPath, bundle.sigPath, {
        pubkey: bundle.publicKey,
      }),
      (err) => {
        assert.equal(err.code, 'SEED_SIG_READ_FAILED');
        return true;
      },
    );
  } finally {
    rmSync(bundle.dir, { recursive: true, force: true });
  }
});

test('verifyPersistedSignature: malformed .sha256 → SEED_SHA256_MALFORMED', async () => {
  const bundle = makeBundle();
  try {
    writeFileSync(bundle.shaPath, 'not a hash\n');
    writeFileSync(bundle.sigPath, randomBytes(64));
    await assert.rejects(
      () => verifyPersistedSignature(bundle.shaPath, bundle.sigPath, {
        pubkey: bundle.publicKey,
      }),
      (err) => {
        assert.equal(err.code, 'SEED_SHA256_MALFORMED');
        return true;
      },
    );
  } finally {
    rmSync(bundle.dir, { recursive: true, force: true });
  }
});

test('verifyPersistedSignature: wrong-length sig → SEED_SIG_MALFORMED', async () => {
  const bundle = makeBundle();
  try {
    await finalize(bundle);
    writeFileSync(bundle.sigPath, randomBytes(32));
    await assert.rejects(
      () => verifyPersistedSignature(bundle.shaPath, bundle.sigPath, {
        pubkey: bundle.publicKey,
      }),
      (err) => {
        assert.equal(err.code, 'SEED_SIG_MALFORMED');
        return true;
      },
    );
  } finally {
    rmSync(bundle.dir, { recursive: true, force: true });
  }
});

// The property that fixes Gate-3: post-install, witness.db legitimately
// mutates (applySchema, gate decisions). verifyPersistedSignature must
// remain a pass for the same .sha256/.sig regardless of dbPath bytes.
test('verifyPersistedSignature: result is decoupled from DB state', async () => {
  const bundle = makeBundle();
  try {
    await finalize(bundle);

    const before = await verifyPersistedSignature(bundle.shaPath, bundle.sigPath, {
      pubkey: bundle.publicKey,
    });
    assert.match(before.sha256, /^[0-9a-f]{64}$/);

    // Mutate the DB bytes — this is what applySchema effectively does to a
    // live witness.db post-init.
    const buf = readFileSync(bundle.dbPath);
    buf[100] = buf[100] ^ 0xff;
    writeFileSync(bundle.dbPath, buf);

    const after = await verifyPersistedSignature(bundle.shaPath, bundle.sigPath, {
      pubkey: bundle.publicKey,
    });
    assert.equal(after.sha256, before.sha256);
    assert.equal(after.fingerprint, before.fingerprint);
  } finally {
    rmSync(bundle.dir, { recursive: true, force: true });
  }
});

test('real bundle from seed_export/ verifies against embedded pubkey (smoke)', async (t) => {
  // This test is gated on the real seed being present. If seed_export/ is
  // absent, skip — CI will not have it.
  const real = {
    db: join(process.cwd(), 'seed_export', 'chaingate-seed.db'),
    sha: join(process.cwd(), 'seed_export', 'chaingate-seed.db.sha256'),
    sig: join(process.cwd(), 'seed_export', 'chaingate-seed.db.sig'),
  };
  try {
    readFileSync(real.sha);
  } catch {
    t.skip('no real seed_export/ bundle present');
    return;
  }
  const result = await verifySeed(real.db, real.sha, real.sig);
  assert.match(result.sha256, /^[0-9a-f]{64}$/);
  assert.equal(result.fingerprint, 'ed25519:09f6c9fdb8f5a2ea');
});
