import { existsSync } from 'node:fs';
import { fmt, renderTable, colorDisposition } from '../format.js';
import { resolvePaths } from '../paths.js';
import { readPid } from '../proxy-control.js';
import { openWitnessDB } from '../../witness/db.js';
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

  const db = openWitnessDB(paths.witnessDb, { readonly: true });

  try {
    const counts = db.getStoreCounts();
    const stats = db.getDecisionStats();
    const recent = db.getRecentDecisions(5);
    const seedVersion = db.getSeedMetadata('seed_version');
    const seedExported = db.getSeedMetadata('exported_at');
    const pid = readPid(paths.pidFile);

    if (opts.json) {
      console.log(JSON.stringify({
        store: counts,
        decisions: stats,
        recent,
        seed: { version: seedVersion, exported_at: seedExported },
        proxy: { running: !!pid, pid, port: DEFAULT_PORT, host: DEFAULT_HOST },
      }, null, 2));
      return EXIT.OK;
    }

    const proxyStatus = pid
      ? fmt.green(`running on ${DEFAULT_HOST}:${DEFAULT_PORT} (pid ${pid})`)
      : fmt.red('stopped');

    const seedLine = seedVersion
      ? `${seedVersion} (exported ${seedExported ?? 'unknown'})`
      : fmt.dim('none (observing from live traffic)');

    console.log(renderTable([
      ['Witness store:', `${counts.packages} packages, ${counts.versions} versions, ${counts.files} files`],
      ['Seed version:', seedLine],
      ['Proxy:', proxyStatus],
      ['Decisions:', `${stats.total} total · ${stats.ALLOW} ALLOW · ${stats.WARN} WARN · ${stats.BLOCK} BLOCK`],
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

  return EXIT.OK;
}
