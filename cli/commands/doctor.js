import { existsSync, accessSync, constants as fsConstants } from 'node:fs';
import { fmt, renderTable } from '../format.js';
import { resolvePaths } from '../paths.js';
import { npmrcPath } from '../npmrc.js';
import { readPid, isPortInUse } from '../proxy-control.js';
import { openWitnessDB } from '../../witness/db.js';
import { DEFAULT_PORT, DEFAULT_HOST, NPMRC_MARKER_START, EXIT } from '../constants.js';
import { readFileSync } from 'node:fs';

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

  // 6. Seed signature (quick check — verify pubkey fingerprint matches)
  {
    let pass = false;
    let detail = 'no seed metadata';
    if (existsSync(paths.witnessDb)) {
      try {
        const db = openWitnessDB(paths.witnessDb, { readonly: true });
        const fp = db.getSeedMetadata('signing_key_fingerprint');
        db.close();
        if (fp) {
          const { CHAINGATE_SEED_PUBKEY_FINGERPRINT } = await import('../../witness/seed_verify.js');
          pass = fp === CHAINGATE_SEED_PUBKEY_FINGERPRINT;
          detail = pass ? `fingerprint matches (${fp})` : `fingerprint mismatch: db=${fp}`;
        } else {
          detail = 'no seed (observing from live traffic)';
          pass = true; // --no-seed is valid
        }
      } catch (err) {
        detail = err.message;
      }
    }
    checks.push({ name: 'seed-integrity', pass, detail });
  }

  // Output
  if (opts.json) {
    console.log(JSON.stringify(checks, null, 2));
    return checks.every((c) => c.pass) ? EXIT.OK : EXIT.ERROR;
  }

  console.log(fmt.bold('ChainGate Doctor\n'));
  for (const c of checks) {
    const icon = c.pass ? fmt.ok(c.name) : fmt.fail(c.name);
    console.log(`  ${icon}  ${fmt.dim(c.detail)}`);
  }

  const failures = checks.filter((c) => !c.pass);
  if (failures.length === 0) {
    console.log(`\n${fmt.green('All checks passed.')}`);
    return EXIT.OK;
  }

  console.log(`\n${fmt.red(`${failures.length} check(s) failed.`)}`);
  return EXIT.ERROR;
}
