import { existsSync } from 'node:fs';
import { fmt } from '../format.js';
import { resolvePaths } from '../paths.js';
import { openWitnessDB } from '../../witness/db.js';
import { EXIT } from '../constants.js';

function parseArgs(args) {
  const opts = { scope: 'user', json: false, subcommand: null, target: null };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--scope' && args[i + 1]) opts.scope = args[++i];
    else if (args[i] === '--json') opts.json = true;
    else if (!args[i].startsWith('-') && !opts.subcommand) opts.subcommand = args[i];
    else if (!args[i].startsWith('-') && opts.subcommand && !opts.target) opts.target = args[i];
  }
  return opts;
}

function parseTarget(target) {
  if (!target) return null;
  const at = target.lastIndexOf('@');
  if (at <= 0) return null;
  return { name: target.slice(0, at), version: target.slice(at + 1) };
}

export default async function overrides(args) {
  const opts = parseArgs(args);
  const sub = opts.subcommand ?? 'list';

  if (sub !== 'list' && sub !== 'revoke') {
    console.error('Usage: chaingate overrides [list|revoke <package>@<version>]');
    return EXIT.ERROR;
  }

  const paths = resolvePaths(opts.scope);
  if (!existsSync(paths.witnessDb)) {
    console.error(fmt.fail('No witness database found. Run `chaingate init` first.'));
    return EXIT.ERROR;
  }

  const db = openWitnessDB(paths.witnessDb);
  try {
    if (sub === 'list') {
      const rows = db.listOverrides();
      if (opts.json) {
        console.log(JSON.stringify(rows, null, 2));
        return EXIT.OK;
      }
      if (rows.length === 0) {
        console.log(fmt.dim('No active overrides.'));
        return EXIT.OK;
      }
      console.log(fmt.bold(`${rows.length} override(s):\n`));
      for (const r of rows) {
        console.log(`  ${r.package_name}@${r.version}`);
        console.log(fmt.dim(`    Reason: ${r.reason}`));
        console.log(fmt.dim(`    Created: ${r.created_at}`));
      }
      return EXIT.OK;
    }

    // revoke
    const parsed = parseTarget(opts.target);
    if (!parsed) {
      console.error('Usage: chaingate overrides revoke <package>@<version>');
      return EXIT.ERROR;
    }
    const deleted = db.deleteOverride(parsed.name, parsed.version);
    if (deleted) {
      console.log(fmt.ok(`Override revoked: ${parsed.name}@${parsed.version}`));
    } else {
      console.log(fmt.dim(`No override found for ${parsed.name}@${parsed.version}`));
    }
    return EXIT.OK;
  } finally {
    db.close();
  }
}
