import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { CAPS, FileRefused, readBounded, sha256Regular } from '../seed/v3/bounded-file.js';

// Embedded literal — the only trust anchor in the CLI.
// Generated from the project signing key on 2026-04-14.
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

/**
 * SHA-256 of a regular file, through one non-blocking descriptor read from explicit positions (U-05 R2-2 (c)): a FIFO
 * or a device is refused instead of stalling the command. Async for its existing callers.
 */
export async function sha256File(path) {
  try { return sha256Regular(path); } catch (err) {
    if (err instanceof FileRefused) throw new SeedVerificationError(`refused ${path}: ${err.why}`, { code: 'SEED_FILE_REFUSED' });
    throw err;
  }
}

/** A sidecar, at most CAPS.sidecar bytes through one descriptor; a refusal is SEED_FILE_REFUSED. */
function readSidecar(path, readFailedCode, what) {
  try { return readBounded(path, CAPS.sidecar); } catch (err) {
    if (err instanceof FileRefused) throw new SeedVerificationError(`refused ${path}: ${err.why}`, { code: 'SEED_FILE_REFUSED' });
    throw new SeedVerificationError(`cannot read ${what}: ${path}: ${err.message}`, { code: readFailedCode });
  }
}

/**
 * Verify a persisted .sha256/.sig pair without touching any DB file.
 *
 * Reads the .sha256 (hex string) and .sig (raw 64-byte Ed25519 signature)
 * and verifies the signature is over the .sha256 contents using the pinned
 * pubkey. Decoupled from any live DB state by design — this is the
 * post-install primitive (doctor / integrity-gate) where witness.db is a
 * mutable runtime database and re-hashing it is meaningless.
 *
 * @param {string} sha256Path
 * @param {string} sigPath
 * @param {{pubkey?: import('node:crypto').KeyObject}} [opts]  Inject alt pubkey for tests only.
 * @throws {SeedVerificationError}
 * @returns {Promise<{sha256: string, fingerprint: string}>}
 */
export async function verifyPersistedSignature(sha256Path, sigPath, opts = {}) {
  const pubkey = opts.pubkey ?? PUBKEY;

  const claimedHash = readSidecar(sha256Path, 'SEED_SHA256_READ_FAILED', 'sha256 file').toString('utf8').trim();
  if (!/^[0-9a-f]{64}$/.test(claimedHash)) {
    throw new SeedVerificationError(
      `sha256 file is not a 64-char hex string: ${sha256Path}`,
      { code: 'SEED_SHA256_MALFORMED' },
    );
  }

  const sig = readSidecar(sigPath, 'SEED_SIG_READ_FAILED', 'signature file');
  if (sig.length !== 64) {
    throw new SeedVerificationError(
      `signature is ${sig.length} bytes, expected 64 (Ed25519 raw)`,
      { code: 'SEED_SIG_MALFORMED' },
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
  };
}

/**
 * Install-time verification of bytes ALREADY STAGED privately (U-05 R2-2 (d)): the signature over the claimed digest --
 * the sidecar bytes read once, bounded -- and that digest equal to the one computed over the STAGED bytes. Nothing is
 * read by path here, so nothing about the caller's files can change between the check and the install. Same order and
 * codes as verifySeed.
 *
 * @param {{digest: string, sha256Bytes: Buffer|null, sigBytes: Buffer|null}} staged
 * @param {{pubkey?: import('node:crypto').KeyObject}} [opts]  Inject alt pubkey for tests only.
 * @throws {SeedVerificationError}
 */
export function verifyStagedSeed({ digest, sha256Bytes, sigBytes }, opts = {}) {
  const pubkey = opts.pubkey ?? PUBKEY;
  if (!sha256Bytes) {
    throw new SeedVerificationError('the seed has no .sha256 beside it', { code: 'SEED_SHA256_READ_FAILED' });
  }
  const claimedHash = Buffer.from(sha256Bytes).toString('utf8').trim();
  if (!/^[0-9a-f]{64}$/.test(claimedHash)) {
    throw new SeedVerificationError('the .sha256 is not a 64-char hex string', { code: 'SEED_SHA256_MALFORMED' });
  }
  if (!sigBytes) throw new SeedVerificationError('the seed has no signature', { code: 'SEED_SIG_READ_FAILED' });
  if (sigBytes.length !== 64) {
    throw new SeedVerificationError(`signature is ${sigBytes.length} bytes, expected 64 (Ed25519 raw)`,
      { code: 'SEED_SIG_MALFORMED' });
  }
  if (!cryptoVerify(null, Buffer.from(claimedHash, 'ascii'), pubkey, sigBytes)) {
    throw new SeedVerificationError('Ed25519 signature verification failed', { code: 'SEED_SIG_INVALID' });
  }
  if (digest !== claimedHash) {
    throw new SeedVerificationError(`seed hash mismatch: staged=${digest} claimed=${claimedHash}`,
      { code: 'SEED_HASH_MISMATCH' });
  }
  return { sha256: claimedHash, fingerprint: CHAINGATE_SEED_PUBKEY_FINGERPRINT };
}

/**
 * Verify a seed bundle at install time.
 *
 * Composes verifyPersistedSignature (signature over claimed hash) with a
 * live re-hash of the bundle's DB file (defends against transit corruption
 * and registry tampering of the bundle bytes). Intended for install-time
 * paths only (init, update-seed). Post-install callers should use
 * verifyPersistedSignature directly — see its docstring.
 *
 * @param {string} dbPath       Path to chaingate-seed.db
 * @param {string} sha256Path   Path to chaingate-seed.db.sha256 (hex string, trailing newline OK)
 * @param {string} sigPath      Path to chaingate-seed.db.sig (raw 64-byte Ed25519 signature)
 * @param {{pubkey?: import('node:crypto').KeyObject}} [opts]  Inject alt pubkey for tests only.
 * @throws {SeedVerificationError}
 */
export async function verifySeed(dbPath, sha256Path, sigPath, opts = {}) {
  const { sha256: claimedHash, fingerprint } = await verifyPersistedSignature(
    sha256Path,
    sigPath,
    opts,
  );

  const localHash = await sha256File(dbPath);
  if (localHash !== claimedHash) {
    throw new SeedVerificationError(
      `seed hash mismatch: local=${localHash} claimed=${claimedHash}`,
      { code: 'SEED_HASH_MISMATCH' },
    );
  }

  return {
    sha256: claimedHash,
    fingerprint,
    dbPath,
  };
}
