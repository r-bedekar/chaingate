import { existsSync, renameSync, unlinkSync, copyFileSync } from 'node:fs';
import { join } from 'node:path';
import { fmt } from '../format.js';
import { resolvePaths } from '../paths.js';
import { fetchSeedBundle } from '../seed-download.js';
import { verifySeed } from '../../witness/seed_verify.js';
import { openWitnessDB } from '../../witness/db.js';
import { assertIntegrity } from '../integrity-gate.js';
import { EXIT } from '../constants.js';

function parseArgs(args) {
  const opts = { scope: 'user', force: false };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--scope' && args[i + 1]) opts.scope = args[++i];
    if (args[i] === '--force') opts.force = true;
  }
  return opts;
}

export default async function updateSeed(args) {
  const opts = parseArgs(args);
  const paths = resolvePaths(opts.scope);

  if (!existsSync(paths.witnessDb)) {
    console.error(fmt.fail('No witness database found. Run `chaingate init` first.'));
    return EXIT.ERROR;
  }

  // Refuse to run if the installed chaingate + current seed don't pass
  // self-witness / seed-signature checks. Fetching and swapping the witness
  // on a tampered install would launder the attack.
  const gate = await assertIntegrity(paths, { command: 'update-seed' });
  if (!gate.ok) return gate.exit;

  // 1. Download + verify
  console.log('Downloading latest seed...');
  let bundle;
  try {
    bundle = await fetchSeedBundle();
  } catch (err) {
    console.error(fmt.fail(`Download failed: ${err.message}`));
    return EXIT.ERROR;
  }

  console.log('Verifying signature...');
  try {
    await verifySeed(bundle.dbPath, bundle.sha256Path, bundle.sigPath);
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

  console.log(fmt.ok(`Seed updated: ${currentVersion ?? 'none'} → ${newVersion}`));
  console.log(fmt.dim(`  Packages: ${newCounts.packages} (${pkgDelta >= 0 ? '+' : ''}${pkgDelta})`));
  console.log(fmt.dim(`  Versions: ${newCounts.versions} (${verDelta >= 0 ? '+' : ''}${verDelta})`));

  return EXIT.OK;
}
