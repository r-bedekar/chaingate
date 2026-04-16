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

export default async function check(args) {
  const opts = parseArgs(args);
  const parsed = parseTarget(opts.target);

  if (!parsed) {
    console.error('Usage: chaingate check <package>@<version>');
    console.error('Exit codes: 0=ALLOW, 2=WARN, 3=BLOCK, 4=tool error');
    return EXIT.TOOL_ERROR;
  }

  const paths = resolvePaths(opts.scope);
  if (!existsSync(paths.witnessDb)) {
    console.error(fmt.fail('No witness database found. Run `chaingate init` first.'));
    return EXIT.TOOL_ERROR;
  }

  const db = openWitnessDB(paths.witnessDb, { readonly: true });
  try {
    const decision = db.getLatestDecision(parsed.name, parsed.version);
    if (!decision) {
      if (opts.json) {
        console.log(JSON.stringify({ error: 'no_decision', package: parsed.name, version: parsed.version }));
      } else {
        console.error(fmt.dim(`No decision found for ${parsed.name}@${parsed.version}`));
      }
      return EXIT.TOOL_ERROR;
    }

    const override = db.getOverride(parsed.name, parsed.version);

    if (opts.json) {
      console.log(JSON.stringify({
        package: parsed.name,
        version: parsed.version,
        disposition: override ? 'ALLOW' : decision.disposition,
        override: override ? { reason: override.reason } : null,
        gates_fired: decision.gates_fired,
        decided_at: decision.decided_at,
      }));
    } else {
      const effectiveDisp = override ? 'ALLOW' : decision.disposition;
      console.log(`${parsed.name}@${parsed.version}: ${colorDisposition(effectiveDisp)}`);
      if (override) {
        console.log(fmt.cyan(`  Override: ${override.reason}`));
      }
    }

    if (override) return EXIT.OK;

    switch (decision.disposition) {
      case 'ALLOW': return EXIT.OK;
      case 'WARN': return EXIT.WARN;
      case 'BLOCK': return EXIT.BLOCK;
      default: return EXIT.TOOL_ERROR;
    }
  } finally {
    db.close();
  }
}
