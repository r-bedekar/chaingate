import { existsSync, accessSync, constants as fsConstants, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { fmt } from '../format.js';
import { resolvePaths } from '../paths.js';
import { npmrcPath } from '../npmrc.js';
import { readPid, isPortInUse } from '../proxy-control.js';
import { openWitnessDB } from '../../witness/db.js';
import { verifyPersistedSignature } from '../../witness/seed_verify.js';
import { checkSelfWitness, hasAnyChaingateInWitness } from '../self-witness.js';
import { DEFAULT_PORT, DEFAULT_HOST, NPMRC_MARKER_START, EXIT } from '../constants.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
let CLI_VERSION = 'unknown';
try {
  const pkg = JSON.parse(readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf8'));
  if (pkg?.version) CLI_VERSION = pkg.version;
} catch { /* keep 'unknown' */ }

async function fetchProxySelf(host, port, timeoutMs = 1500) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const resp = await fetch(`http://${host}:${port}/_chaingate/self`, {
      signal: ctrl.signal,
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return await resp.json();
  } finally {
    clearTimeout(timer);
  }
}

// Each check pushes { name, pass, detail, severity? } where severity is:
//   'tamper'        — cryptographic disagreement, an attack signal (exit 5)
//   'unverifiable'  — check should have run but could not (real problem) (exit 6)
//   'skipped'       — check does not apply in this environment (exit 0,
//                     informational only, e.g. --no-seed install lacks
//                     .sha256/.sig; pre-publish chaingate isn't yet in the
//                     witness store)
//   (absent)        — hard pass/fail in the pre-V2 operational sense (exit 0 or 1)
//
// Ordering: tamper > non-severity-fails > unverifiable > OK. 'skipped'
// coexists with OK as a no-op for exit determination.
export function aggregateExit(checks) {
  if (checks.some((c) => c.severity === 'tamper')) return EXIT.INTEGRITY_TAMPER;
  if (checks.some((c) => !c.pass && !c.severity)) return EXIT.ERROR;
  if (checks.some((c) => c.severity === 'unverifiable')) return EXIT.INTEGRITY_UNVERIFIABLE;
  return EXIT.OK;
}

// Translate a self-witness check result + witness state into a doctor
// display severity. Pure function, exported for testing. Two reasons can
// be skipped: lockfile_missing (non-npm install path, e.g. tarball-style
// global install) and not_in_witness when the witness has zero chaingate
// entries (pre-publish, expected). Any other unverifiable reason — or
// not_in_witness when the witness already knows about chaingate (stale
// local seed) — is a real problem.
export function classifySelfWitnessSeverity(selfResult, witnessHasChaingate) {
  if (selfResult.status === 'verified') return null;
  if (selfResult.status === 'tamper') return 'tamper';
  if (selfResult.reason === 'lockfile_missing') return 'skipped';
  if (selfResult.reason === 'not_in_witness' && !witnessHasChaingate) return 'skipped';
  return 'unverifiable';
}

function parseArgs(args) {
  const opts = { scope: 'user', json: false };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--scope' && args[i + 1]) opts.scope = args[++i];
    if (args[i] === '--json') opts.json = true;
  }
  return opts;
}

export default async function doctor(args) {
  const opts = parseArgs(args);
  const paths = resolvePaths(opts.scope);
  const checks = [];

  // 1. Chaingate directory exists and is writable
  {
    const ok = existsSync(paths.base);
    let writable = false;
    if (ok) try { accessSync(paths.base, fsConstants.W_OK); writable = true; } catch {}
    checks.push({
      name: 'chaingate-dir',
      pass: ok && writable,
      detail: ok ? (writable ? paths.base : `${paths.base} (not writable)`) : 'missing — run `chaingate init`',
    });
  }

  // 2. Witness database exists and is readable
  {
    let pass = false;
    let detail = 'missing';
    if (existsSync(paths.witnessDb)) {
      try {
        const db = openWitnessDB(paths.witnessDb, { readonly: true });
        const counts = db.getStoreCounts();
        db.close();
        pass = true;
        detail = `${counts.packages} packages, ${counts.versions} versions`;
      } catch (err) {
        detail = `corrupt or locked: ${err.message}`;
      }
    }
    checks.push({ name: 'witness-db', pass, detail });
  }

  // 3. Proxy PID alive
  {
    const pid = readPid(paths.pidFile);
    checks.push({
      name: 'proxy-pid',
      pass: !!pid,
      detail: pid ? `running (pid ${pid})` : 'not running',
    });
  }

  // 4. Proxy port responding
  {
    const responding = await isPortInUse(DEFAULT_PORT, DEFAULT_HOST);
    checks.push({
      name: 'proxy-port',
      pass: responding,
      detail: responding ? `${DEFAULT_HOST}:${DEFAULT_PORT} accepting connections` : `${DEFAULT_HOST}:${DEFAULT_PORT} not responding`,
    });
  }

  // 5. .npmrc has chaingate block
  {
    const rc = npmrcPath(opts.scope);
    let pass = false;
    let detail = `${rc} missing`;
    if (existsSync(rc)) {
      const content = readFileSync(rc, 'utf8');
      pass = content.includes(NPMRC_MARKER_START);
      detail = pass ? `${rc} has chaingate block` : `${rc} missing chaingate block`;
    }
    checks.push({ name: 'npmrc-block', pass, detail });
  }

  // 6. Seed signature — Ed25519 verification of the persisted .sha256/.sig
  //    pair only. Does NOT re-hash the live witness.db: that file legitimately
  //    mutates after install (applySchema migrations, gate decisions), so a
  //    live-DB hash check fires false-positive TAMPER under normal use. What
  //    this proves is "the install came from a bundle signed by the pinned
  //    Ed25519 key" — the trust anchor that matters post-install. Install-time
  //    bundle hashing still happens via verifySeed in init/update-seed.
  {
    if (!existsSync(paths.witnessDb)) {
      checks.push({
        name: 'seed-signature',
        pass: false,
        severity: 'unverifiable',
        detail: 'no witness database to verify',
      });
    } else if (!existsSync(paths.witnessDbSha256) || !existsSync(paths.witnessDbSig)) {
      checks.push({
        name: 'seed-signature',
        pass: false,
        severity: 'skipped',
        detail: 'no persisted .sha256/.sig (expected for --no-seed installs)',
      });
    } else {
      try {
        const result = await verifyPersistedSignature(
          paths.witnessDbSha256,
          paths.witnessDbSig,
        );
        checks.push({
          name: 'seed-signature',
          pass: true,
          detail: `Ed25519 signature verified (${result.fingerprint})`,
        });
      } catch (err) {
        checks.push({
          name: 'seed-signature',
          pass: false,
          severity: 'tamper',
          detail: `${err.code ?? 'verify_failed'}: ${err.message}`,
        });
      }
    }
  }

  // 7. Self-witness — installed chaingate integrity vs witness-recorded baseline.
  //    Severity comes from classifySelfWitnessSeverity, which separates
  //    "check found a problem" (tamper / unverifiable) from "check doesn't
  //    apply here" (skipped). Pre-publish state and tarball-style global
  //    installs are skipped, not unverifiable. See cli/self-witness.js for
  //    the underlying status/reason codes.
  {
    if (!existsSync(paths.witnessDb)) {
      checks.push({
        name: 'self-witness',
        pass: false,
        severity: 'unverifiable',
        detail: 'no witness database',
      });
    } else {
      let db = null;
      try {
        db = openWitnessDB(paths.witnessDb, { readonly: true });
        const r = checkSelfWitness(db);
        const witnessHasCG = hasAnyChaingateInWitness(db);
        const severity = classifySelfWitnessSeverity(r, witnessHasCG);
        if (severity === null) {
          checks.push({
            name: 'self-witness',
            pass: true,
            detail: r.detail,
          });
        } else {
          checks.push({
            name: 'self-witness',
            pass: false,
            severity,
            detail: r.detail,
          });
        }
      } catch (err) {
        checks.push({
          name: 'self-witness',
          pass: false,
          severity: 'unverifiable',
          detail: `witness read failed: ${err.message}`,
        });
      } finally {
        if (db) try { db.close(); } catch {}
      }
    }
  }

  // 8. Proxy identity — confirm the running proxy matches the installed CLI
  //    (version + pid) via the loopback /_chaingate/self endpoint. A version
  //    or pid mismatch means the running proxy is not the one just installed —
  //    a tamper signal (exit 5). Unreachable when the proxy is down is not
  //    a tamper signal; just skip.
  {
    const pidFromFile = readPid(paths.pidFile);
    if (!pidFromFile) {
      checks.push({
        name: 'proxy-identity',
        pass: true,
        detail: 'proxy not running (skipped)',
      });
    } else {
      try {
        const self = await fetchProxySelf(DEFAULT_HOST, DEFAULT_PORT);
        const versionMatch = self.version === CLI_VERSION;
        const pidMatch = Number(self.pid) === Number(pidFromFile);
        if (versionMatch && pidMatch) {
          checks.push({
            name: 'proxy-identity',
            pass: true,
            detail: `matches installed CLI (v${self.version}, pid ${self.pid})`,
          });
        } else {
          checks.push({
            name: 'proxy-identity',
            pass: false,
            severity: 'tamper',
            detail: `mismatch — proxy version=${self.version} cli=${CLI_VERSION}; proxy pid=${self.pid} pidfile=${pidFromFile}`,
          });
        }
      } catch (err) {
        checks.push({
          name: 'proxy-identity',
          pass: false,
          detail: `self-endpoint unreachable: ${err.message}`,
        });
      }
    }
  }

  // Output
  if (opts.json) {
    console.log(JSON.stringify(checks, null, 2));
    return aggregateExit(checks);
  }

  console.log(fmt.bold('ChainGate Doctor\n'));
  for (const c of checks) {
    let icon;
    if (c.pass) icon = fmt.ok(c.name);
    else if (c.severity === 'tamper') icon = fmt.fail(`${c.name} [TAMPER]`);
    else if (c.severity === 'unverifiable') icon = fmt.warn(`${c.name} [unverifiable]`);
    else if (c.severity === 'skipped') icon = fmt.skip(`${c.name} [skipped]`);
    else icon = fmt.fail(c.name);
    console.log(`  ${icon}  ${fmt.dim(c.detail)}`);
  }

  const exitCode = aggregateExit(checks);
  const skippedCount = checks.filter((c) => c.severity === 'skipped').length;
  console.log('');
  if (exitCode === EXIT.OK) {
    if (skippedCount > 0) {
      console.log(fmt.green('All applicable checks passed.'));
      console.log(fmt.dim(`  ${skippedCount} check(s) skipped (not applicable to this install).`));
    } else {
      console.log(fmt.green('All checks passed.'));
    }
  } else if (exitCode === EXIT.INTEGRITY_TAMPER) {
    console.log(fmt.red('TAMPER signal — cryptographic checks disagree.'));
    console.log(fmt.red('  Do not use this installation. Reinstall chaingate from a trusted source.'));
  } else if (exitCode === EXIT.INTEGRITY_UNVERIFIABLE) {
    console.log(fmt.yellow('Unverifiable — integrity checks could not complete.'));
    console.log(fmt.dim('  Expected for pre-publish, dev, or --no-seed installs. See detail above.'));
  } else {
    const fails = checks.filter((c) => !c.pass).length;
    console.log(fmt.red(`${fails} check(s) failed.`));
  }

  return exitCode;
}
