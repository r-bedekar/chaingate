import { existsSync } from 'node:fs';
import { fmt, colorDisposition } from '../format.js';
import { resolvePaths } from '../paths.js';
import { openWitnessDB } from '../../witness/db.js';
import { EXIT } from '../constants.js';

function parseArgs(args) {
  const opts = { scope: 'user', json: false, limit: 20, target: null };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--scope' && args[i + 1]) opts.scope = args[++i];
    else if (args[i] === '--json') opts.json = true;
    else if (args[i] === '--limit' && args[i + 1]) opts.limit = parseInt(args[++i], 10) || 20;
    else if (!args[i].startsWith('-') && !opts.target) opts.target = args[i];
  }
  return opts;
}

export default async function history(args) {
  const opts = parseArgs(args);

  if (!opts.target) {
    console.error('Usage: chaingate history <package> [--limit N]');
    return EXIT.ERROR;
  }

  const paths = resolvePaths(opts.scope);
  if (!existsSync(paths.witnessDb)) {
    console.error(fmt.fail('No witness database found. Run `chaingate init` first.'));
    return EXIT.ERROR;
  }

  const db = openWitnessDB(paths.witnessDb, { readonly: true });
  try {
    const versions = db.getHistory(opts.target).slice(0, opts.limit);

    if (versions.length === 0) {
      console.log(fmt.dim(`No versions found for ${opts.target}`));
      return EXIT.OK;
    }

    if (opts.json) {
      console.log(JSON.stringify(versions, null, 2));
      return EXIT.OK;
    }

    console.log(fmt.bold(`${opts.target} — ${versions.length} versions\n`));

    for (const v of versions) {
      const decision = db.getLatestDecision(opts.target, v.version);
      const disp = decision ? colorDisposition(decision.disposition) : fmt.dim('—');
      const pub = v.published_at ? fmt.dim(v.published_at.slice(0, 10)) : fmt.dim('unknown');
      const publisher = v.publisher_email ? fmt.dim(v.publisher_email) : '';
      const method = v.publish_method ? fmt.dim(`[${v.publish_method}]`) : '';
      const deps = v.dependency_count != null ? fmt.dim(`${v.dependency_count} deps`) : '';
      const provenance = v.provenance_present ? fmt.green('sigstore') : '';

      const parts = [publisher, method, deps, provenance].filter(Boolean).join('  ');
      console.log(`  ${v.version.padEnd(16)} ${disp.padEnd(20)} ${pub}  ${parts}`);
    }
  } finally {
    db.close();
  }

  return EXIT.OK;
}
