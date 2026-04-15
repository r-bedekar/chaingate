import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { createReadStream, readFileSync } from 'node:fs';

// Embedded literal — the only trust anchor in the CLI.
// Generated from /home/vps_admin/.chaingate-signing/privkey.pem on 2026-04-14.
// Rotation requires a new CLI release.
export const CHAINGATE_SEED_PUBKEY_B64 =
  'MCowBQYDK2VwAyEAP2W40LmbxTrDqDKaOpbfWD/xrbSPW4hz6RqQxZFte5E=';
export const CHAINGATE_SEED_PUBKEY_FINGERPRINT = 'ed25519:09f6c9fdb8f5a2ea';

const PUBKEY = createPublicKey({
  key: Buffer.from(CHAINGATE_SEED_PUBKEY_B64, 'base64'),
  format: 'der',
  type: 'spki',
});

export class SeedVerificationError extends Error {
  constructor(message, { code } = {}) {
    super(message);
    this.name = 'SeedVerificationError';
    this.code = code ?? 'SEED_VERIFY_FAILED';
  }
}

export function sha256File(path) {
  return new Promise((resolve, reject) => {
    const h = createHash('sha256');
    const stream = createReadStream(path);
    stream.on('data', (chunk) => h.update(chunk));
    stream.on('end', () => resolve(h.digest('hex')));
    stream.on('error', reject);
  });
}

/**
 * Verify a seed bundle.
 *
 * @param {string} dbPath       Path to chaingate-seed.db
 * @param {string} sha256Path   Path to chaingate-seed.db.sha256 (hex string, trailing newline OK)
 * @param {string} sigPath      Path to chaingate-seed.db.sig (raw 64-byte Ed25519 signature)
 * @param {{pubkey?: import('node:crypto').KeyObject}} [opts]  Inject alt pubkey for tests only.
 * @throws {SeedVerificationError}
 */
export async function verifySeed(dbPath, sha256Path, sigPath, opts = {}) {
  const pubkey = opts.pubkey ?? PUBKEY;

  let claimedHash;
  try {
    claimedHash = readFileSync(sha256Path, 'utf8').trim();
  } catch (err) {
    throw new SeedVerificationError(
      `cannot read sha256 file: ${sha256Path}: ${err.message}`,
      { code: 'SEED_SHA256_READ_FAILED' },
    );
  }
  if (!/^[0-9a-f]{64}$/.test(claimedHash)) {
    throw new SeedVerificationError(
      `sha256 file is not a 64-char hex string: ${sha256Path}`,
      { code: 'SEED_SHA256_MALFORMED' },
    );
  }

  let sig;
  try {
    sig = readFileSync(sigPath);
  } catch (err) {
    throw new SeedVerificationError(
      `cannot read signature file: ${sigPath}: ${err.message}`,
      { code: 'SEED_SIG_READ_FAILED' },
    );
  }
  if (sig.length !== 64) {
    throw new SeedVerificationError(
      `signature is ${sig.length} bytes, expected 64 (Ed25519 raw)`,
      { code: 'SEED_SIG_MALFORMED' },
    );
  }

  const localHash = await sha256File(dbPath);
  if (localHash !== claimedHash) {
    throw new SeedVerificationError(
      `seed hash mismatch: local=${localHash} claimed=${claimedHash}`,
      { code: 'SEED_HASH_MISMATCH' },
    );
  }

  // Ed25519: the `algorithm` parameter MUST be null — Ed25519 is pre-hashed
  // by the signing primitive itself. We sign the hex string bytes (ASCII).
  const ok = cryptoVerify(null, Buffer.from(claimedHash, 'ascii'), pubkey, sig);
  if (!ok) {
    throw new SeedVerificationError(
      'Ed25519 signature verification failed',
      { code: 'SEED_SIG_INVALID' },
    );
  }

  return {
    sha256: claimedHash,
    fingerprint: CHAINGATE_SEED_PUBKEY_FINGERPRINT,
    dbPath,
  };
}
