import { mkdirSync, existsSync, copyFileSync, accessSync, constants as fsConstants } from 'node:fs';
import { fmt } from '../format.js';
import { resolvePaths } from '../paths.js';
import { npmrcPath, readCurrentRegistry, applyChaingateBlock, findScopedRegistries } from '../npmrc.js';
import { readPid, readPidRecord, spawnProxy, isPortInUse, waitForProxyReady, stopProxy,
  isAlive } from '../proxy-control.js';
import { fetchSeedBundle } from '../seed-download.js';
import { verifySeed, verifyStagedSeed } from '../../witness/seed_verify.js';
import { openWitnessDB } from '../../witness/db.js';
import { assertIntegrity } from '../integrity-gate.js';
import { DEFAULT_PORT, DEFAULT_HOST, DEFAULT_UPSTREAM, EXIT } from '../constants.js';
import { stageIncoming, finishStagedBundle, activateBundle, resolveActiveBundle,
  verifyBundleDir, withSeedMutation, ActivationRecoveryRefused } from '../seed-bundle.js';
import { LockUnavailable } from '../seed-mutation-lock.js';
import { reportSeedPrologue } from './update-seed.js';
import { readConfigStrict, writeConfig, validateConfig, DEFAULT_POLICY,
  POLICY_VALUES } from '../../config-store.js';

function parseArgs(args) {
  const opts = { scope: 'user', noSeed: false, seedPath: null, force: false, dryRun: false,
    unsignedDev: false };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--scope' && args[i + 1]) opts.scope = args[++i];
    else if (args[i] === '--no-seed') opts.noSeed = true;
    else if (args[i] === '--seed' && args[i + 1]) opts.seedPath = args[++i];
    else if (args[i] === '--force') opts.force = true;
    else if (args[i] === '--dry-run') opts.dryRun = true;
    // A v3 seed with no signature is only usable if the operator asks for it BY NAME, and the
    // choice is recorded so a later start cannot quietly treat it as authenticated.
    else if (args[i] === '--unsigned-development') opts.unsignedDev = true;
  }
  return opts;
}

/** `init --force` may start a new proxy only once the old one is known to be gone (U-05 gap-closure r2, revision 2 §6). */
export function restartAllowed(outcome) {
  return outcome === 'stopped' || outcome === 'not_running';
}

/**
 * Seeds and the witness database: everything `init` writes that a seed command also writes. It runs under the
 * seed-mutation lock (U-05 R2-2 (b)), after recovery and cleanup, and returns `{ exit }` to stop init, or what a
 * started proxy must report back.
 */
async function installSeeds(opts, paths, deps, lock) {
  // 3a. A v3 detection seed is installed BESIDE the witness database, never over it: it is
  //     evidence, it is opened read-only, and the runtime keeps writing its own state elsewhere.
  //     Everything needed to start later is recorded in config.json, so no environment is required.
  let intended = null;                  // the identity a started proxy must report back
  let v3Installed = false;
  // PRIVATE STAGING FIRST (U-05 R2-2 (d)): a supplied seed is opened once as a regular file, admitted for space and
  // copied; it is classified (SQLite opens only the staged copy), verified and installed from that copy.
  let staged = null;
  if (opts.seedPath) {
    try { staged = stageIncoming(opts.seedPath, paths.base, { seam: deps.seam, hooks: deps.hooks, lock }); } catch (err) {
      console.error(fmt.fail(`The seed was not accepted: ${err.message}`));
      console.error('  Nothing was installed and .npmrc was not touched.');
      return { exit: EXIT.ERROR };
    }
    for (const w of staged.warnings) console.log(fmt.warn(w));
    if (staged.info.schemaVersion !== 3) { staged.discard(); staged = null; }   // legacy: the route below
  }
  if (staged) try {                       // the staged copy is discarded on every exit from this branch
    // POLICY FIRST, strictly. A policy the gate cannot act on means the proxy will not start, and
    // discovering that after a bundle is installed and .npmrc redirected is the wrong order.
    let policy;
    try {
      const existing = readConfigStrict(paths.configFile) || {};
      policy = { ...DEFAULT_POLICY, ...(existing.policy || {}) };
      validateConfig({ ...existing, policy }, paths.configFile);
    } catch (err) {
      console.error(fmt.fail(err.message));
      console.error('  Nothing was installed and .npmrc was not touched.');
      return { exit: EXIT.ERROR };
    }

    // TRUST, decided on the STAGED digest before the bundle is finished, and recorded in the bundle itself.
    const hasSig = staged.sigBytes !== null;
    let trust;
    if (hasSig) {
      console.log('Verifying v3 seed signature...');
      try {
        verifyStagedSeed({ digest: staged.digest, sha256Bytes: staged.sha256Bytes, sigBytes: staged.sigBytes });
        trust = 'authenticated';
        console.log(fmt.ok('v3 seed signature verified'));
      } catch (err) {
        console.error(fmt.fail(`Seed signature verification FAILED: ${err.message}`));
        console.error('  ChainGate refuses to import an unverified seed. Aborting.');
        return { exit: EXIT.ERROR };
      }
    } else if (opts.unsignedDev) {
      trust = 'unsigned-development';
      console.log(fmt.warn('v3 seed has no signature; installing as unsigned-development'));
    } else {
      console.error(fmt.fail('v3 seed has no .sig and --unsigned-development was not given.'));
      console.error('  A seed is authenticated by default; asking for the development mode is');
      console.error('  how you say out loud that this one is not.');
      return { exit: EXIT.ERROR };
    }

    // FINISH: the staged copy, digest-checked, sidecar written from the staged bytes, and OPENED WITH
    // THE READER — all before anything in use is touched. A retained bundle with the same identity is
    // re-verified rather than assumed, and reports its own state.
    let installed;
    try {
      installed = finishStagedBundle(staged, paths.base, { trust, lock });
    } catch (err) {
      console.error(fmt.fail(`v3 seed bundle rejected: ${err.message}`));
      console.error('  Nothing was installed or activated.');
      return { exit: EXIT.ERROR };
    }

    // The operator's policy is host state and is written before activation; which bundle is active
    // is recorded ONLY by the link the next step swaps.
    writeConfig(paths.configFile, { policy });
    let identity;
    try {
      identity = activateBundle(paths.base, installed.dir_name, { lock, hooks: deps.hooks });
    } catch (err) {
      console.error(fmt.fail(`activation refused: ${err.message}`));
      console.error('  The previously active bundle, if any, is still active.');
      return { exit: EXIT.ERROR };
    }

    console.log(fmt.ok(`v3 seed bundle ${identity.bundle_id} active`
      + `${installed.reused ? ' (already installed; re-verified)' : ''}`));
    console.log(fmt.dim(`  sha256 ${identity.sha256.slice(0, 16)}...  `
      + `snapshot ${String(identity.corpus_snapshot_digest).slice(0, 12)}...  `
      + `trust ${identity.trust}${identity.authenticated ? ' (authenticated)' : ''}`));
    console.log(fmt.dim(`  policy on_unusable_input=${policy.on_unusable_input} `
      + `on_no_evidence=${policy.on_no_evidence}  (edit ${paths.configFile} to change)`));
    if (installed.replaced_damaged) {
      console.log(fmt.warn(`  replaced a damaged retained bundle: ${installed.replaced_damaged}`));
    }
    intended = { bundle_id: identity.bundle_id, sha256: identity.sha256, trust: identity.trust,
      policy };

    if (!existsSync(paths.witnessDb)) {
      const db = openWitnessDB(paths.witnessDb);
      db.applySchema();
      db.close();
      console.log(fmt.ok('Witness database created (writable, separate from the seed)'));
    } else {
      console.log(fmt.ok('Using the existing witness database (writable, separate from the seed)'));
    }
    opts.seedPath = null;
    opts.noSeed = true;
    v3Installed = true;
  } finally { staged.discard(); }

  // 3. Seed handling (v1: the seed IS the witness database)
  //    `--force` must not drag a v3 installation back through this: it downloaded a v1 bundle over
  //    the witness database that had just been created beside the v3 seed.
  if (!v3Installed && ((!opts.noSeed && !existsSync(paths.witnessDb)) || opts.force)) {
    if (opts.seedPath) {
      // Local seed
      const sha256Path = opts.seedPath + '.sha256';
      const sigPath = opts.seedPath + '.sig';
      console.log('Verifying local seed...');
      try {
        await verifySeed(opts.seedPath, sha256Path, sigPath);
      } catch (err) {
        console.error(fmt.fail(`Seed signature verification FAILED: ${err.message}`));
        console.error('  This seed bundle cannot be trusted: it may be tampered with or corrupted.');
        console.error('  ChainGate refuses to import an unverified seed. Aborting.');
        return { exit: EXIT.ERROR };
      }
      copyFileSync(opts.seedPath, paths.witnessDb);
      // Persist sig artifacts so `chaingate doctor` can re-verify on every run.
      copyFileSync(sha256Path, paths.witnessDbSha256);
      copyFileSync(sigPath, paths.witnessDbSig);
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
        return { exit: EXIT.ERROR };
      }
      console.log('Verifying Ed25519 signature...');
      try {
        const result = await verifySeed(bundle.dbPath, bundle.sha256Path, bundle.sigPath);
        console.log(fmt.ok(`Seed verified (${result.fingerprint})`));
      } catch (err) {
        console.error(fmt.fail(`Seed signature verification FAILED: ${err.message}`));
        console.error('  This seed bundle cannot be trusted: it may be tampered with or corrupted.');
        console.error('  ChainGate refuses to import an unverified seed. Aborting.');
        return { exit: EXIT.ERROR };
      }
      copyFileSync(bundle.dbPath, paths.witnessDb);
      copyFileSync(bundle.sha256Path, paths.witnessDbSha256);
      copyFileSync(bundle.sigPath, paths.witnessDbSig);
      // Say what was, and was not, installed: this is the LEGACY witness seed. The v3 detection seed
      // is never downloaded automatically; it must be supplied.
      console.log(fmt.warn('Installed the LEGACY witness seed only. The v3 detection seed is not downloaded '
        + 'automatically; install it with `chaingate init --seed <bundle>/chaingate-seed.db` '
        + '(add --unsigned-development for an unsigned bundle).'));
    }
  } else if (v3Installed) {
    // the witness database was created or reused beside the v3 seed above, and reported there
  } else if (existsSync(paths.witnessDb)) {
    console.log(fmt.ok('Existing witness database found'));
  } else if (opts.noSeed) {
    // Create empty DB with schema
    const db = openWitnessDB(paths.witnessDb);
    db.applySchema();
    db.close();
    console.log(fmt.ok('Empty witness database created'));
  }

  return { intended, v3Installed };
}

/**
 * @param {string[]} args
 * @param {{seam?: object, hooks?: object}} [deps]  test seams for staging (space figures, named copy points); inert otherwise
 */
export default async function init(args, deps = {}) {
  const opts = parseArgs(args);
  const paths = resolvePaths(opts.scope);

  if (opts.dryRun) {
    const rc = npmrcPath(opts.scope);
    const existingRegistry = readCurrentRegistry(rc);
    const scopedRegs = findScopedRegistries(rc);
    const existingPid = readPid(paths.pidFile);
    const registryUrl = `http://${DEFAULT_HOST}:${DEFAULT_PORT}`;

    console.log(fmt.dim('(dry-run: no changes will be made)'));
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
    console.log(`  5. Patch .npmrc (${rc}) with chaingate block: registry=${registryUrl}`);
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

  // Refuse to re-init on top of a compromised install. No-op on first-run
  // (no witnessDb yet → assertIntegrity short-circuits with skipped).
  const gate = await assertIntegrity(paths, { command: 'init' });
  if (!gate.ok) return gate.exit;

  // 2. Check for existing installation
  const pidRecord = readPidRecord(paths.pidFile);
  if (pidRecord?.state === 'indeterminate') {
    console.error(fmt.fail(`The operating system refused the liveness check for the recorded pid ${pidRecord.pid} `
      + `(${pidRecord.code}). It was not established whether it is the ChainGate proxy, so init will not start or restart one.`));
    console.error(`  Inspect pid ${pidRecord.pid} with your operating system tools, then run \`chaingate stop\`.`);
    return EXIT.ERROR;
  }
  const existingPid = readPid(paths.pidFile);
  if (existingPid && !opts.force) {
    console.log(fmt.warn(`Proxy already running (pid ${existingPid}). Use --force to reinitialize.`));
    return EXIT.OK;
  }

  // 3. Seeds and the witness database, under the seed-mutation lock (U-05 R2-2 (b)): taken after the proxy checks
  //    above and released before a proxy is started below; readers never wait on it.
  let seeded;
  try {
    seeded = await withSeedMutation(paths.base, (lock) => installSeeds(opts, paths, deps, lock),
      { hooks: deps.hooks, report: reportSeedPrologue });
  } catch (err) {
    if (!(err instanceof LockUnavailable || err instanceof ActivationRecoveryRefused)) throw err;
    console.error(fmt.fail(err.message));
    console.error('  .npmrc was not touched.');
    return EXIT.ERROR;
  }
  if (seeded.exit !== undefined) return seeded.exit;
  const { intended } = seeded;

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
    console.error(`  ChainGate's proxy always uses ${host}:${port}. Stop whatever is listening there, then run init again.`);
    return EXIT.ERROR;
  }

  // 6. Start the proxy, and only redirect npm once the RIGHT process is serving.
  //    A listening port says something bound it. Readiness here means the running process reports
  //    the bundle digest, trust mode and policy that were just configured — a path proves nothing,
  //    since the same path spans different bytes across an update.
  const registryUrl = `http://${host}:${port}`;

  /**
   * What the running proxy says it loaded, or null.
   *
   * The request carries its OWN deadline. Without one it inherits whatever the platform's default
   * happens to be, so a proxy that accepts the connection and then never answers would hang `init`
   * indefinitely — after a bounded connection wait, which makes the bound on the connection
   * pointless. Readiness is "listening AND answering with the right evidence", so the budget has to
   * cover both halves.
   */
  const runningIdentity = async (timeoutMs = 10000) => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), Math.max(timeoutMs, 1));
    try {
      const resp = await fetch(`${registryUrl}/_chaingate/self`, { signal: ctrl.signal });
      if (!resp.ok) return null;
      return await resp.json();
    } catch { return null; } finally { clearTimeout(timer); }
  };
  /** Does it match what was just configured? Returns a list of disagreements. */
  const mismatches = (self) => {
    if (!intended) return [];
    const got = self?.seed_v3;
    if (!got) return ['no v3 seed loaded'];
    const out = [];
    if (got.sha256 !== intended.sha256) {
      out.push(`seed digest ${String(got.sha256).slice(0, 16)}... != `
        + `${intended.sha256.slice(0, 16)}...`);
    }
    if (got.bundle_id !== intended.bundle_id) {
      out.push(`bundle ${got.bundle_id} != ${intended.bundle_id}`);
    }
    if (got.trust !== intended.trust) out.push(`trust ${got.trust} != ${intended.trust}`);
    for (const k of Object.keys(POLICY_VALUES)) {
      if (got.policy?.[k] !== intended.policy[k]) {
        out.push(`policy ${k} ${got.policy?.[k]} != ${intended.policy[k]}`);
      }
    }
    return out;
  };

  const childEnv = () => {
    const env = {};
    if (upstream !== DEFAULT_UPSTREAM) env.CHAINGATE_UPSTREAM = upstream;
    env.CHAINGATE_WITNESS_DB = paths.witnessDb;
    env.CHAINGATE_PORT = String(port);
    env.CHAINGATE_HOST = host;
    // The SELECTED base directory, handed to the process this command starts. Internal plumbing
    // between a command and its child — not something an operator sets.
    env.CHAINGATE_HOME = paths.base;
    return env;
  };

  let running = existingPid && isAlive(existingPid) ? existingPid : null;
  if (running) {
    const self = await runningIdentity();
    const diff = mismatches(self);
    if (diff.length === 0) {
      console.log(fmt.ok(`Proxy already running (pid ${running}) with the configured seed`));
    } else if (opts.force) {
      // A CONTROLLED restart: stop the old process, start a new one, and re-check identity.
      console.log(fmt.warn(`Restarting proxy (pid ${running}) to activate the new bundle...`));
      const stopped = await stopProxy(paths.pidFile, { port, host });
      if (!restartAllowed(stopped.outcome)) {
        console.error(fmt.fail(`The running proxy was not stopped (${stopped.outcome}): ${stopped.detail}`));
        console.error('  No new proxy was started and .npmrc was left as it is.');
        return EXIT.ERROR;
      }
      running = null;
    } else {
      // Or say so plainly, rather than leaving the operator to assume the new seed is in force.
      console.log(fmt.warn('Bundle INSTALLED AND ACTIVATED, but NOT YET LOADED by the running proxy.'));
      for (const d of diff) console.log(fmt.dim(`    ${d}`));
      console.log(fmt.dim(`  The proxy (pid ${running}) is still serving what it loaded at start-up.`));
      console.log(fmt.dim('  Activate it with: chaingate stop && chaingate init   (or re-run with --force)'));
      console.log(fmt.dim('  .npmrc was left as it is.'));
      return EXIT.OK;
    }
  }

  if (!running) {
    const pid = spawnProxy({ pidFile: paths.pidFile, logFile: paths.logFile, env: childEnv() });
    // ONE budget for becoming ready, spanning BOTH the connection wait and the identity answer.
    // Inside it the bound is the child's liveness, not a stopwatch: a real seed is gigabytes and the
    // proxy opens it BEFORE it listens, so "slow" and "dead" must be told apart rather than
    // collapsed into one short deadline.
    const READY_BUDGET_MS = 180000;
    const budgetFrom = Date.now();
    const started = await waitForProxyReady({ port, host, pid, ceilingMs: READY_BUDGET_MS });
    if (!started.ready) {
      console.error(fmt.fail(started.why === 'exited'
        ? `Proxy (pid ${pid}) exited before it began listening. See ${paths.logFile}`
        : `Proxy (pid ${pid}) did not begin listening within its `
          + `${Math.round(started.waitedMs / 1000)}s budget. It is still running; it may simply need `
          + `longer, or it may be stuck. See ${paths.logFile}`));
      console.error('  .npmrc was NOT redirected: npm keeps using its current registry.');
      return EXIT.ERROR;
    }
    if (started.waitedMs > 5000) {
      console.log(fmt.dim(`  (seed opened in ${(started.waitedMs / 1000).toFixed(1)}s)`));
    }
    // Whatever is left of the budget after the connection wait bounds the identity answer. The
    // budget is STRICT end to end: no floor, no grace. A start-up that spent the whole budget
    // becoming reachable has nothing left in which to be asked what it loaded, and is reported as
    // exactly that — the message below names which half ran out.
    const self = await runningIdentity(Math.max(READY_BUDGET_MS - (Date.now() - budgetFrom), 1));
    if (!self) {
      console.error(fmt.fail('Proxy is listening but did not answer /_chaingate/self in time.'));
      console.error(`  .npmrc was NOT redirected. See ${paths.logFile}`);
      return EXIT.ERROR;
    }
    const diff = mismatches(self);
    if (diff.length) {
      console.error(fmt.fail('Proxy started, but not with what was just configured:'));
      for (const d of diff) console.error(`    ${d}`);
      console.error('  .npmrc was NOT redirected.');
      return EXIT.ERROR;
    }
    console.log(fmt.ok(`Proxy running on ${registryUrl} (pid ${pid})`));
    if (self.seed_v3) {
      console.log(fmt.dim(`  active bundle ${self.seed_v3.bundle_id} `
        + `sha256 ${String(self.seed_v3.sha256).slice(0, 16)}...`));
      console.log(fmt.dim(`  trust ${self.seed_v3.trust}`
        + `${self.seed_v3.authenticated ? ' (authenticated)' : ''}`
        + `  policy ${JSON.stringify(self.seed_v3.policy)}`));
    }
  }

  // 7. Only now redirect npm at it.
  applyChaingateBlock(rc, registryUrl);
  console.log(fmt.ok(`.npmrc updated (${rc})`));

  // 8. Summary
  if (upstream !== DEFAULT_UPSTREAM) {
    console.log(fmt.dim(`  Upstream: ${upstream} (chained)`));
  }
  console.log(`\nReady. ${storeCounts.packages} packages, ${storeCounts.versions} versions in witness store.`);

  return EXIT.OK;
}
