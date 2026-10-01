import { existsSync, renameSync, unlinkSync, copyFileSync } from 'node:fs';
import { join } from 'node:path';
import { fmt } from '../format.js';
import { resolvePaths as defaultResolvePaths } from '../paths.js';
import { fetchSeedBundle as defaultFetchSeedBundle } from '../seed-download.js';
import { verifySeed as defaultVerifySeed, verifyStagedSeed } from '../../witness/seed_verify.js';
import { openWitnessDB } from '../../witness/db.js';
import { assertIntegrity as defaultAssertIntegrity } from '../integrity-gate.js';
import { EXIT } from '../constants.js';
import { stageIncoming, finishStagedBundle, activateBundle, rollbackActivation, activeBundleId,
  previousBundleId, verifyBundleDir, seedsDir } from '../seed-bundle.js';
import { readConfigStrict } from '../../config-store.js';

function parseArgs(args) {
  const opts = { scope: 'user', force: false, seedPath: null, rollback: false,
    unsignedDev: false };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--scope' && args[i + 1]) opts.scope = args[++i];
    if (args[i] === '--force') opts.force = true;
    if (args[i] === '--seed' && args[i + 1]) opts.seedPath = args[++i];
    if (args[i] === '--rollback') opts.rollback = true;
    // Accepting an unsigned seed is its OWN decision, named. `--force` is a generic "I know what
    // I am doing" for ordinary obstacles and must not double as "skip authentication".
    if (args[i] === '--unsigned-development') opts.unsignedDev = true;
  }
  return opts;
}

/**
 * Replace the v3 detection seed, or put the previous one back.
 *
 * SAFE means three things here, none of which the v1 path needed:
 *   * the incoming bundle is verified and confirmed to BE a v3 seed before anything is replaced;
 *   * the swap is a rename, so a proxy starting concurrently sees the old file or the new one and
 *     never a half-written one, and the previous seed is kept for `--rollback`;
 *   * the WITNESS DATABASE IS NOT TOUCHED. Runtime state — baselines, decisions, overrides — lives
 *     in a different file on purpose, and replacing evidence must not discard the record of what was
 *     decided under the evidence that came before.
 */
export async function updateSeedV3(opts, paths, deps, staged = null) {
  // Which bundle is active is ONE record — the `seeds/active` link. Nothing here rewrites a second
  // copy of that fact, so an interrupted update leaves the previously active bundle active and a
  // rollback is a swap back rather than a restore of files.
  if (opts.rollback) {
    const prev = previousBundleId(paths.base);
    if (!prev) {
      console.error(fmt.fail('No previous bundle recorded to roll back to.'));
      return EXIT.ERROR;
    }
    let identity;
    try {
      identity = rollbackActivation(paths.base);
    } catch (err) {
      console.error(fmt.fail(err.message));
      console.error('  The currently active bundle is unchanged.');
      return EXIT.ERROR;
    }
    console.log(fmt.ok(`Rolled back to bundle ${identity.bundle_id}`));
    console.log(fmt.dim(`  sha256 ${identity.sha256.slice(0, 16)}... trust ${identity.trust}`));
    console.log(fmt.dim('  Restart the proxy to load it: chaingate stop && chaingate init'));
    console.log(fmt.dim('  Witness state untouched: decisions taken under it are still recorded.'));
    return EXIT.OK;
  }

  // `staged`: the privately staged copy (R2-2 (d)). Trust is decided on ITS digest and the sidecar bytes read once.
  const hasSig = staged.sigBytes !== null;
  const activeId = activeBundleId(paths.base);
  const activeIdentity = activeId
    ? (verifyBundleDir(join(seedsDir(paths.base), activeId)).identity || {}) : {};
  const previousTrust = activeIdentity.trust || 'authenticated';

  let trust;
  if (hasSig) {
    try {
      (deps.verifyStagedSeed ?? verifyStagedSeed)({ digest: staged.digest, sha256Bytes: staged.sha256Bytes,
        sigBytes: staged.sigBytes });
    } catch (err) {
      console.error(fmt.fail(`Seed signature verification FAILED: ${err.message}`));
      console.error('  The active bundle is unchanged.');
      return EXIT.ERROR;
    }
    trust = 'authenticated';
  } else if (opts.unsignedDev) {
    trust = 'unsigned-development';
    console.log(fmt.warn('Incoming bundle has no signature; installing as unsigned-development'));
  } else {
    console.error(fmt.fail('Incoming v3 seed has no signature.'));
    if (opts.force) {
      console.error('  --force does not skip authentication: it is a generic override and this is');
      console.error('  a trust decision. Pass --unsigned-development to say so explicitly.');
    } else {
      console.error(`  The active bundle is ${previousTrust}. Pass --unsigned-development to`);
      console.error('  accept an unsigned one, which is recorded in the bundle as such.');
    }
    console.error('  The active bundle is unchanged.');
    return EXIT.ERROR;
  }

  let installed;
  try {
    installed = finishStagedBundle(staged, paths.base, { trust });
  } catch (err) {
    console.error(fmt.fail(`v3 seed bundle rejected: ${err.message}`));
    console.error('  Nothing was installed or activated; the active bundle is unchanged.');
    return EXIT.ERROR;
  }

  let identity;
  try {
    identity = activateBundle(paths.base, installed.dir_name);
  } catch (err) {
    console.error(fmt.fail(`activation refused: ${err.message}`));
    console.error('  The previously active bundle is still active.');
    return EXIT.ERROR;
  }

  console.log(fmt.ok(`Bundle ${identity.bundle_id} active`
    + `${installed.reused ? ' (already installed; re-verified)' : ''}`));
  console.log(fmt.dim(`  sha256 ${identity.sha256.slice(0, 16)}... `
    + `snapshot ${String(identity.corpus_snapshot_digest).slice(0, 12)}... trust ${identity.trust}`));
  console.log(fmt.dim(`  Previous bundle ${activeId || '(none)'} kept for `
    + '`chaingate update-seed --rollback`.'));
  console.log(fmt.dim('  Restart the proxy to load it: chaingate stop && chaingate init'));
  console.log(fmt.dim('  Witness state untouched.'));
  return EXIT.OK;
}

export default async function updateSeed(
  args,
  deps = {
    fetchSeedBundle: defaultFetchSeedBundle,
    verifySeed: defaultVerifySeed,
    assertIntegrity: defaultAssertIntegrity,
    resolvePaths: defaultResolvePaths,
  },
) {
  const opts = parseArgs(args);
  const paths = deps.resolvePaths(opts.scope);

  // The v3 detection seed has its own lifecycle: it is not the witness database, and replacing it
  // must not touch runtime state. `--rollback`, or `--seed <bundle>` naming a v3 seed, take it.
  if (opts.rollback) return updateSeedV3(opts, paths, deps);
  if (opts.seedPath) {
    // PRIVATE STAGING FIRST (U-05 R2-2 (d)): the supplied file is opened once as a regular file, admitted for space and
    // copied; it is classified, verified and installed from the STAGED copy and never read again.
    let staged;
    try { staged = stageIncoming(opts.seedPath, paths.base, { seam: deps.seam, hooks: deps.hooks }); } catch (err) {
      console.error(fmt.fail(`The seed was not accepted: ${err.message}`));
      console.error('  Nothing was installed or activated; the active bundle is unchanged.');
      return EXIT.ERROR;
    }
    for (const w of staged.warnings) console.log(fmt.warn(w));
    try {
      if (staged.info.schemaVersion === 3) return await updateSeedV3(opts, paths, deps, staged);
    } finally { staged.discard(); }
    // not a v3 seed: the legacy route below (its routing is the legacy part of R2-2)
  }

  // AUTOMATIC v3 SEED DOWNLOAD IS NOT AVAILABLE. Without --seed this command downloads the LEGACY
  // witness bundle (seed-v2.x) and swaps it into witness.db; it never touches the active v3 detection
  // bundle. On a host whose detection runs from a v3 bundle that would report "Seed updated" while
  // detection stayed exactly as it was. Refuse before downloading anything, and change nothing:
  // restart (`chaingate init`), a local update (`--seed <bundle>`) and `--rollback` are unaffected.
  if (!opts.seedPath) {
    let v3Active = null;
    try { v3Active = activeBundleId(paths.base); } catch { v3Active = '(a v3 activation record that does not resolve)'; }
    if (v3Active) {
      console.error(fmt.fail('Automatic download of v3 detection seeds is not available.'));
      console.error(`  This host's detection runs from v3 bundle ${v3Active}. Without --seed, update-seed would only`);
      console.error('  replace the legacy witness database and leave detection unchanged, so it refuses. Nothing was changed.');
      console.error('  To install a v3 bundle you have:   chaingate update-seed --seed <bundle>/chaingate-seed.db [--unsigned-development]');
      console.error('  To return to the previous bundle:  chaingate update-seed --rollback');
      return EXIT.ERROR;
    }
  }

  if (!existsSync(paths.witnessDb)) {
    console.error(fmt.fail('No witness database found. Run `chaingate init` first.'));
    return EXIT.ERROR;
  }

  // Refuse to run if the installed chaingate + current seed don't pass
  // self-witness / seed-signature checks. Fetching and swapping the witness
  // on a tampered install would launder the attack.
  const gate = await deps.assertIntegrity(paths, { command: 'update-seed' });
  if (!gate.ok) return gate.exit;

  // 1. Download + verify
  console.log('Downloading latest seed...');
  let bundle;
  try {
    bundle = await deps.fetchSeedBundle();
  } catch (err) {
    console.error(fmt.fail(`Download failed: ${err.message}`));
    return EXIT.ERROR;
  }

  console.log('Verifying signature...');
  try {
    await deps.verifySeed(bundle.dbPath, bundle.sha256Path, bundle.sigPath);
  } catch (err) {
    console.error(fmt.fail(`Verification failed: ${err.message}`));
    return EXIT.ERROR;
  }

  // 2. Compare seed versions
  const newDb = openWitnessDB(bundle.dbPath, { readonly: true });
  const newVersion = newDb.getSeedMetadata('seed_version');
  newDb.close();

  const currentDb = openWitnessDB(paths.witnessDb, { readonly: true });
  const currentVersion = currentDb.getSeedMetadata('seed_version');
  const currentCounts = currentDb.getStoreCounts();
  currentDb.close();

  if (newVersion === currentVersion && !opts.force) {
    console.log(fmt.ok(`Already up to date (${currentVersion})`));
    return EXIT.OK;
  }

  // 3. Atomic swap — preserve gate_decisions and overrides
  console.log('Migrating local decisions and overrides...');
  const newDbRw = openWitnessDB(bundle.dbPath);
  try {
    // Attach the current DB and copy user data across
    newDbRw.db.exec(`ATTACH DATABASE '${paths.witnessDb}' AS old`);
    newDbRw.db.exec(`
      INSERT OR IGNORE INTO gate_decisions (package_name, version, disposition, gates_fired, decided_at)
      SELECT package_name, version, disposition, gates_fired, decided_at FROM old.gate_decisions
    `);
    newDbRw.db.exec(`
      INSERT OR REPLACE INTO overrides (package_name, version, reason, created_at)
      SELECT package_name, version, reason, created_at FROM old.overrides
    `);
    newDbRw.db.exec('DETACH DATABASE old');
  } finally {
    newDbRw.close();
  }

  // 4. Rename swap
  const backupPath = paths.witnessDb + '.bak';
  renameSync(paths.witnessDb, backupPath);
  try {
    renameSync(bundle.dbPath, paths.witnessDb);
  } catch (err) {
    // Restore backup on failure
    renameSync(backupPath, paths.witnessDb);
    console.error(fmt.fail(`Swap failed: ${err.message}`));
    return EXIT.ERROR;
  }
  try { unlinkSync(backupPath); } catch { /* ok */ }

  // Forward-migrate the swapped-in bundle: covers the case where the bundle
  // predates a runtime schema addition (e.g. dep_first_publish). Idempotent —
  // runs CREATE TABLE IF NOT EXISTS, no-op when bundle already matches.
  const migrateDb = openWitnessDB(paths.witnessDb);
  migrateDb.applySchema();
  migrateDb.close();

  // Refresh persisted sig artifacts so doctor can re-verify the new bundle.
  try {
    copyFileSync(bundle.sha256Path, paths.witnessDbSha256);
    copyFileSync(bundle.sigPath, paths.witnessDbSig);
  } catch (err) {
    console.error(fmt.warn(`Seed swapped but sig artifacts not persisted: ${err.message}`));
    console.error('  `chaingate doctor` seed-signature check will fail until next update-seed.');
  }

  // 5. Report
  const updatedDb = openWitnessDB(paths.witnessDb, { readonly: true });
  const newCounts = updatedDb.getStoreCounts();
  updatedDb.close();

  const pkgDelta = newCounts.packages - currentCounts.packages;
  const verDelta = newCounts.versions - currentCounts.versions;

  console.log(fmt.ok(`Seed updated: ${currentVersion ?? 'none'} to ${newVersion}`));
  console.log(fmt.dim(`  Packages: ${newCounts.packages} (${pkgDelta >= 0 ? '+' : ''}${pkgDelta})`));
  console.log(fmt.dim(`  Versions: ${newCounts.versions} (${verDelta >= 0 ? '+' : ''}${verDelta})`));

  return EXIT.OK;
}
