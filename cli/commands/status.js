import { existsSync, readFileSync } from 'node:fs';
import { fmt, renderTable, colorDisposition } from '../format.js';
import { resolvePaths } from '../paths.js';
import { readPidRecord, fetchSelf } from '../proxy-control.js';
import { describeStorage } from '../storage-check.js';
import { openWitnessDB } from '../../witness/db.js';
import { resolveActiveBundle, bundleFiles, ActivationBroken } from '../seed-bundle.js';
import { DEFAULT_PORT, DEFAULT_HOST, EXIT } from '../constants.js';

function parseArgs(args) {
  const opts = { scope: 'user', json: false };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--scope' && args[i + 1]) opts.scope = args[++i];
    if (args[i] === '--json') opts.json = true;
  }
  return opts;
}

export default async function status(args) {
  const opts = parseArgs(args);
  const paths = resolvePaths(opts.scope);

  if (!existsSync(paths.witnessDb)) {
    console.error(fmt.fail('No witness database found. Run `chaingate init` first.'));
    return EXIT.ERROR;
  }

  // The v3 detection seed: what the activation record points at, from the bundle's recorded
  // manifest. Status does not re-hash a 1.9 GB database; `chaingate doctor` verifies it.
  let seedV3 = { active: false };
  try {
    const a = resolveActiveBundle(paths.base);
    if (a) {
      let m = {};
      try { m = JSON.parse(readFileSync(bundleFiles(a.dir).manifest, 'utf8')); } catch { /* reported below */ }
      seedV3 = { active: true, bundle_id: a.id, sha256: m.sha256 ?? null, trust: m.trust ?? null,
        signed: m.signed ?? null, corpus_snapshot_digest: m.corpus_snapshot_digest ?? null,
        staged_at: m.staged_at ?? null, verified: false };
    }
  } catch (err) {
    if (!(err instanceof ActivationBroken)) throw err;
    seedV3 = { active: false, broken: true, link: err.link };
  }

  const db = openWitnessDB(paths.witnessDb, { readonly: true });

  try {
    const counts = db.getStoreCounts();
    const stats = db.getDecisionStats();
    const recent = db.getRecentDecisions(5);
    const seedVersion = db.getSeedMetadata('seed_version');
    const seedExported = db.getSeedMetadata('exported_at');
    // The proxy process: three-state liveness, and what it says about itself (U-05 gap-closure r2, Addendum 1 §B). Its
    // in-memory BLOCK count is the PROCESS's state; the decision totals above are what the database holds.
    const pidRecord = readPidRecord(paths.pidFile);
    const pid = pidRecord?.state === 'alive' ? pidRecord.pid : null;
    let self = null;
    if (pid) {
      const r = await fetchSelf(DEFAULT_HOST, DEFAULT_PORT, 1500);
      if (r.ok) self = r.json;
    }

    if (opts.json) {
      console.log(JSON.stringify({
        store: counts,
        decisions: stats,
        recent,
        seed: { version: seedVersion, exported_at: seedExported },
        seed_v3: seedV3,
        proxy: { running: !!pid, pid, port: DEFAULT_PORT, host: DEFAULT_HOST,
          pid_state: pidRecord?.state ?? 'none', responding: Boolean(self),
          storage: self?.storage ?? null, unstored_blocks: self?.unstored_blocks ?? null, self },
      }, null, 2));
      return seedV3.broken ? EXIT.ERROR : EXIT.OK;
    }

    const proxyStatus = pid
      ? (self ? fmt.green(`running on ${DEFAULT_HOST}:${DEFAULT_PORT} (pid ${pid})`)
        : fmt.yellow(`running (pid ${pid}), not answering on ${DEFAULT_HOST}:${DEFAULT_PORT}`))
      : pidRecord?.state === 'indeterminate'
        ? fmt.yellow(`pid ${pidRecord.pid}: liveness check refused (${pidRecord.code}); not established whether it is running`)
        : fmt.red('stopped');
    const storageState = self?.storage?.state;
    const storageText = describeStorage(self);

    const seedLine = seedVersion
      ? `${seedVersion} (exported ${seedExported ?? 'unknown'})`
      : fmt.dim('none installed (v3 detection does not need it)');

    const v3Line = seedV3.broken
      ? fmt.red(`BROKEN: the activation link ${seedV3.link} does not resolve. Run \`chaingate update-seed --rollback\` or \`chaingate init --seed <bundle>\``)
      : seedV3.active
        ? `bundle ${seedV3.bundle_id}  sha256 ${String(seedV3.sha256 ?? 'unknown').slice(0, 16)}...  trust ${seedV3.trust ?? 'unknown'}`
          + fmt.dim('  (recorded; `chaingate doctor` verifies it)')
        : fmt.dim('none active (run `chaingate init --seed <bundle>`)');

    console.log(renderTable([
      ['Witness store:', `${counts.packages} packages, ${counts.versions} versions, ${counts.files} files`],
      ['Detection seed (v3):', v3Line],
      ['Legacy witness seed:', seedLine],
      ['Proxy:', proxyStatus],
      ...(storageText && storageState !== 'healthy' && storageState !== 'no_evidence'
        ? [['Decision storage:', (['recovered'].includes(storageState) ? fmt.dim : fmt.red)(storageText)]] : []),
      ['Decisions:', `${stats.total} total, ${stats.ALLOW} ALLOW, ${stats.WARN} WARN, ${stats.BLOCK} BLOCK`],
    ]));

    if (recent.length > 0) {
      console.log(`\n  ${fmt.bold('Recent decisions:')}`);
      for (const d of recent) {
        const disp = colorDisposition(d.disposition);
        const time = d.decided_at ?? '';
        console.log(`    ${d.package_name}@${d.version}  ${disp}  ${fmt.dim(time)}`);
      }
    }
  } finally {
    db.close();
  }

  return seedV3.broken ? EXIT.ERROR : EXIT.OK;
}
