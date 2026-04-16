import { existsSync } from 'node:fs';
import { fmt } from '../format.js';
import { resolvePaths } from '../paths.js';
import { openWitnessDB } from '../../witness/db.js';
import { EXIT } from '../constants.js';

function parseArgs(args) {
  const opts = { scope: 'user', reason: null, target: null };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--scope' && args[i + 1]) opts.scope = args[++i];
    else if (args[i] === '--reason' && args[i + 1]) opts.reason = args[++i];
    else if (!args[i].startsWith('-') && !opts.target) opts.target = args[i];
  }
  return opts;
}

function parseTarget(target) {
  if (!target) return null;
  const at = target.lastIndexOf('@');
  if (at <= 0) return null;
  return { name: target.slice(0, at), version: target.slice(at + 1) };
}

export default async function allow(args) {
  const opts = parseArgs(args);
  const parsed = parseTarget(opts.target);

  if (!parsed) {
    console.error('Usage: chaingate allow <package>@<version> --reason "..."');
    return EXIT.ERROR;
  }
  if (!opts.reason) {
    console.error('--reason is required. Explain why this override is safe.');
    return EXIT.ERROR;
  }

  const paths = resolvePaths(opts.scope);
  if (!existsSync(paths.witnessDb)) {
    console.error(fmt.fail('No witness database found. Run `chaingate init` first.'));
    return EXIT.ERROR;
  }

  const db = openWitnessDB(paths.witnessDb);
  try {
    db.insertOverride(parsed.name, parsed.version, opts.reason);
    console.log(fmt.ok(`Override recorded: ${parsed.name}@${parsed.version}`));
    console.log(fmt.dim(`  Reason: ${opts.reason}`));
    console.log(fmt.dim('  Takes effect on next install (no restart needed).'));
  } finally {
    db.close();
  }

  return EXIT.OK;
}
