// Integrity gate — the refuse-to-run check composed from the two independent
// trust signals the doctor uses:
//
//   1. self-witness: installed chaingate's npm integrity matches the witness
//      baseline for its version (npm publish pipeline ↔ seed signing key).
//   2. seed-signature: the local witness.db hash still matches the persisted
//      .sha256, and the .sig verifies with the embedded Ed25519 pubkey.
//
// Commands that mutate state (init, update-seed) or start long-lived processes
// (start) call this before proceeding. If either signal reports tamper, the
// command aborts with EXIT.INTEGRITY_TAMPER. `unverifiable` is soft by default
// (bootstrap / pre-publish / --no-seed) but becomes hard-fail once the witness
// has at least one chaingate entry — the witness state IS the policy, no flag
// required.
//
// Seed-sig is skipped when either the .sha256 or .sig is missing — older
// installs predate the persisted-artifact step in init. That's treated as
// unverifiable, not tamper.

import { existsSync } from 'node:fs';
import { fmt } from './format.js';
import { openWitnessDB } from '../witness/db.js';
import { verifySeed } from '../witness/seed_verify.js';
import { checkSelfWitness, hasAnyChaingateInWitness } from './self-witness.js';
import { EXIT } from './constants.js';

export async function assertIntegrity(paths, { startFileUrl, command } = {}) {
  if (!existsSync(paths.witnessDb)) {
    // No DB at all — commands that need one will fail with a better message.
    // Nothing to integrity-check here.
    return { ok: true, skipped: 'no_witness_db' };
  }

  let db = null;
  let selfResult;
  let witnessHasChaingate = false;
  try {
    db = openWitnessDB(paths.witnessDb, { readonly: true });
    witnessHasChaingate = hasAnyChaingateInWitness(db);
    selfResult = checkSelfWitness(db, startFileUrl ? { startFileUrl } : {});
  } catch (err) {
    printTamperBanner(command, `witness read failed: ${err.message}`);
    return { ok: false, exit: EXIT.INTEGRITY_UNVERIFIABLE };
  } finally {
    if (db) try { db.close(); } catch { /* noop */ }
  }

  if (selfResult.status === 'tamper') {
    printTamperBanner(command, `self-witness: ${selfResult.detail}`);
    return { ok: false, exit: EXIT.INTEGRITY_TAMPER };
  }

  if (selfResult.status === 'unverifiable' && witnessHasChaingate) {
    // Auto-tightening: once chaingate is known to the witness, anything less
    // than a verified match is refused.
    printTamperBanner(command, `self-witness unverifiable but witness has chaingate entries: ${selfResult.detail}`);
    return { ok: false, exit: EXIT.INTEGRITY_UNVERIFIABLE };
  }

  // Seed-signature: only enforced when the persisted artifacts exist.
  if (existsSync(paths.witnessDbSha256) && existsSync(paths.witnessDbSig)) {
    try {
      await verifySeed(paths.witnessDb, paths.witnessDbSha256, paths.witnessDbSig);
    } catch (err) {
      printTamperBanner(command, `seed-signature: ${err.code ?? 'verify_failed'}: ${err.message}`);
      return { ok: false, exit: EXIT.INTEGRITY_TAMPER };
    }
  }

  return { ok: true, selfResult };
}

function printTamperBanner(command, detail) {
  const where = command ? ` before \`chaingate ${command}\`` : '';
  console.error('');
  console.error(fmt.red('TAMPER / INTEGRITY CHECK FAILED' + where));
  console.error(fmt.red(`  ${detail}`));
  console.error(fmt.dim('  Run `chaingate doctor` for full diagnostics.'));
  console.error(fmt.dim('  Reinstall chaingate from a trusted source before continuing.'));
  console.error('');
}
