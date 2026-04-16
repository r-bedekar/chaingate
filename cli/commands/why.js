import { existsSync } from 'node:fs';
import { fmt, colorDisposition, renderGate } from '../format.js';
import { resolvePaths } from '../paths.js';
import { openWitnessDB } from '../../witness/db.js';
import { EXIT } from '../constants.js';

function parseArgs(args) {
  const opts = { scope: 'user', json: false, target: null };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--scope' && args[i + 1]) opts.scope = args[++i];
    else if (args[i] === '--json') opts.json = true;
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

export default async function why(args) {
  const opts = parseArgs(args);
  const parsed = parseTarget(opts.target);

  if (!parsed) {
    console.error('Usage: chaingate why <package>@<version>');
    return EXIT.ERROR;
  }

  const paths = resolvePaths(opts.scope);
  if (!existsSync(paths.witnessDb)) {
    console.error(fmt.fail('No witness database found. Run `chaingate init` first.'));
    return EXIT.ERROR;
  }

  const db = openWitnessDB(paths.witnessDb, { readonly: true });
  try {
    const decision = db.getLatestDecision(parsed.name, parsed.version);
    if (!decision) {
      console.error(fmt.dim(`No decision found for ${parsed.name}@${parsed.version}`));
      console.error(fmt.dim('Install the package through the proxy first.'));
      return EXIT.ERROR;
    }

    const override = db.getOverride(parsed.name, parsed.version);

    if (opts.json) {
      console.log(JSON.stringify({ ...decision, override }, null, 2));
      return EXIT.OK;
    }

    const disp = colorDisposition(decision.disposition);
    console.log(`${fmt.bold(parsed.name)}@${parsed.version}  ${disp}  ${fmt.dim(decision.decided_at)}`);

    if (override) {
      console.log(fmt.cyan(`  Override active: "${override.reason}" (${override.created_at})`));
    }

    if (decision.gates_fired.length === 0) {
      console.log(fmt.dim('  No gate details recorded.'));
    } else {
      console.log('');
      for (const gate of decision.gates_fired) {
        console.log(renderGate(gate));
      }
    }
  } finally {
    db.close();
  }

  return EXIT.OK;
}
