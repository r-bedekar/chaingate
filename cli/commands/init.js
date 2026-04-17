import { mkdirSync, existsSync, copyFileSync, accessSync, constants as fsConstants } from 'node:fs';
import { fmt } from '../format.js';
import { resolvePaths } from '../paths.js';
import { npmrcPath, readCurrentRegistry, applyChaingateBlock, findScopedRegistries } from '../npmrc.js';
import { readPid, spawnProxy, isPortInUse, waitForPort } from '../proxy-control.js';
import { fetchSeedBundle } from '../seed-download.js';
import { verifySeed } from '../../witness/seed_verify.js';
import { openWitnessDB } from '../../witness/db.js';
import { DEFAULT_PORT, DEFAULT_HOST, DEFAULT_UPSTREAM, EXIT } from '../constants.js';

function parseArgs(args) {
  const opts = { scope: 'user', noSeed: false, seedPath: null, force: false, dryRun: false };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--scope' && args[i + 1]) opts.scope = args[++i];
    else if (args[i] === '--no-seed') opts.noSeed = true;
    else if (args[i] === '--seed' && args[i + 1]) opts.seedPath = args[++i];
    else if (args[i] === '--force') opts.force = true;
    else if (args[i] === '--dry-run') opts.dryRun = true;
  }
  return opts;
}

export default async function init(args) {
  const opts = parseArgs(args);
  const paths = resolvePaths(opts.scope);

  if (opts.dryRun) {
    const rc = npmrcPath(opts.scope);
    const existingRegistry = readCurrentRegistry(rc);
    const scopedRegs = findScopedRegistries(rc);
    const existingPid = readPid(paths.pidFile);
    const registryUrl = `http://${DEFAULT_HOST}:${DEFAULT_PORT}`;

    console.log(fmt.dim('(dry-run — no changes will be made)'));
    console.log('');
    console.log('Planned actions:');
    console.log(`  1. Create directory: ${paths.base}`);
    if (existingPid) {
      console.log(`  2. Skip proxy spawn (already running, pid ${existingPid}; --force would reinitialize)`);
    } else {
      console.log(`  2. Spawn proxy on ${registryUrl}`);
    }
    if (opts.noSeed) {
      console.log('  3. Skip seed (--no-seed); empty witness DB will be created');
    } else if (opts.seedPath) {
      console.log(`  3. Verify and install local seed: ${opts.seedPath}`);
    } else {
      console.log('  3. Download + verify seed from GitHub Release');
    }
    if (existingRegistry && existingRegistry !== DEFAULT_UPSTREAM) {
      console.log(`  4. Chain through existing upstream: ${existingRegistry}`);
    } else {
      console.log(`  4. Use default upstream: ${DEFAULT_UPSTREAM}`);
    }
    console.log(`  5. Patch .npmrc (${rc}) with chaingate block → registry=${registryUrl}`);
    if (scopedRegs.length > 0) {
      console.log(`     (${scopedRegs.length} scoped registries will be preserved)`);
    }
    console.log('');
    console.log('Re-run without --dry-run to apply.');
    return EXIT.OK;
  }

  // 1. Create chaingate directory
  try {
    mkdirSync(paths.base, { recursive: true });
  } catch (err) {
    console.error(fmt.fail(`Cannot create ${paths.base}: ${err.message}`));
    return EXIT.ERROR;
  }

  // Verify writable
  try {
    accessSync(paths.base, fsConstants.W_OK);
  } catch {
    console.error(fmt.fail(`${paths.base} is not writable`));
    return EXIT.ERROR;
  }

  // 2. Check for existing installation
  const existingPid = readPid(paths.pidFile);
  if (existingPid && !opts.force) {
    console.log(fmt.warn(`Proxy already running (pid ${existingPid}). Use --force to reinitialize.`));
    return EXIT.OK;
  }

  // 3. Seed handling
  if (!opts.noSeed && !existsSync(paths.witnessDb) || opts.force) {
    if (opts.seedPath) {
      // Local seed
      const sha256Path = opts.seedPath + '.sha256';
      const sigPath = opts.seedPath + '.sig';
      console.log('Verifying local seed...');
      try {
        await verifySeed(opts.seedPath, sha256Path, sigPath);
      } catch (err) {
        console.error(fmt.fail(`Seed verification failed: ${err.message}`));
        return EXIT.ERROR;
      }
      copyFileSync(opts.seedPath, paths.witnessDb);
      console.log(fmt.ok('Local seed verified and copied'));
    } else {
      // Download from GH Release
      console.log('Downloading seed database...');
      let bundle;
      try {
        bundle = await fetchSeedBundle();
      } catch (err) {
        console.error(fmt.fail(`Seed download failed: ${err.message}`));
        console.error('  Use --no-seed to skip, or --seed <path> for a local copy.');
        return EXIT.ERROR;
      }
      console.log('Verifying Ed25519 signature...');
      try {
        const result = await verifySeed(bundle.dbPath, bundle.sha256Path, bundle.sigPath);
        console.log(fmt.ok(`Seed verified (${result.fingerprint})`));
      } catch (err) {
        console.error(fmt.fail(`Seed verification failed: ${err.message}`));
        return EXIT.ERROR;
      }
      copyFileSync(bundle.dbPath, paths.witnessDb);
    }
  } else if (existsSync(paths.witnessDb)) {
    console.log(fmt.ok('Existing witness database found'));
  } else if (opts.noSeed) {
    // Create empty DB with schema
    const db = openWitnessDB(paths.witnessDb);
    db.close();
    console.log(fmt.ok('Empty witness database created'));
  }

  // Load DB to get counts
  let storeCounts = { packages: 0, versions: 0, files: 0 };
  try {
    const db = openWitnessDB(paths.witnessDb);
    storeCounts = db.getStoreCounts();
    db.close();
  } catch { /* proceed anyway */ }

  // 4. Detect existing registry and configure upstream
  const rc = npmrcPath(opts.scope);
  const existingRegistry = readCurrentRegistry(rc);
  let upstream = DEFAULT_UPSTREAM;

  if (existingRegistry && existingRegistry !== DEFAULT_UPSTREAM) {
    console.log(fmt.warn(`Existing registry detected: ${existingRegistry}`));
    console.log('  ChainGate will chain through it as upstream.');
    upstream = existingRegistry;
  }

  const scopedRegs = findScopedRegistries(rc);
  if (scopedRegs.length > 0) {
    console.log(fmt.dim(`  (${scopedRegs.length} scoped registries preserved)`));
  }

  // 5. Check port availability
  const port = DEFAULT_PORT;
  const host = DEFAULT_HOST;
  const portBusy = await isPortInUse(port, host);
  if (portBusy && !existingPid) {
    console.error(fmt.fail(`Port ${port} is already in use by another process.`));
    console.error(`  Set CHAINGATE_PORT to use a different port.`);
    return EXIT.ERROR;
  }

  // 6. Patch .npmrc
  const registryUrl = `http://${host}:${port}`;
  applyChaingateBlock(rc, registryUrl);
  console.log(fmt.ok(`.npmrc updated (${rc})`));

  // 7. Spawn proxy
  if (!existingPid) {
    const env = {};
    if (upstream !== DEFAULT_UPSTREAM) {
      env.CHAINGATE_UPSTREAM = upstream;
    }
    env.CHAINGATE_WITNESS_DB = paths.witnessDb;
    env.CHAINGATE_PORT = String(port);
    env.CHAINGATE_HOST = host;

    const pid = spawnProxy({ pidFile: paths.pidFile, logFile: paths.logFile, env });
    const ready = await waitForPort(port, host, 5000);
    if (ready) {
      console.log(fmt.ok(`Proxy running on ${registryUrl} (pid ${pid})`));
    } else {
      console.log(fmt.warn(`Proxy spawned (pid ${pid}) but port not ready yet. Check ${paths.logFile}`));
    }
  } else {
    console.log(fmt.ok(`Proxy already running (pid ${existingPid})`));
  }

  // 8. Summary
  if (upstream !== DEFAULT_UPSTREAM) {
    console.log(fmt.dim(`  Upstream: ${upstream} (chained)`));
  }
  console.log(`\nReady. ${storeCounts.packages} packages, ${storeCounts.versions} versions in witness store.`);

  return EXIT.OK;
}
