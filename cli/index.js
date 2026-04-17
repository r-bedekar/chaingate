#!/usr/bin/env node
import { EXIT } from './constants.js';

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8'));

const COMMANDS = {
  init: () => import('./commands/init.js'),
  status: () => import('./commands/status.js'),
  allow: () => import('./commands/allow.js'),
  stop: () => import('./commands/stop.js'),
  'update-seed': () => import('./commands/update-seed.js'),
  why: () => import('./commands/why.js'),
  history: () => import('./commands/history.js'),
  doctor: () => import('./commands/doctor.js'),
  check: () => import('./commands/check.js'),
  overrides: () => import('./commands/overrides.js'),
};

function printUsage() {
  console.log(`Usage: chaingate <command> [options]

Commands:
  init              Set up ChainGate (download seed, start proxy, patch .npmrc)
  status            Show witness store stats, proxy state, recent decisions
  allow <p@v>       Override a WARN/BLOCK for a specific package version
  stop              Stop the proxy and restore .npmrc
  update-seed       Download and verify the latest seed database
  why <p@v>         Explain the gate decision for a package version
  history <pkg>     Show the version timeline for a package
  doctor            Check local invariants (6 health checks)
  check <p@v>       Check a package version (CI-friendly exit codes)
  overrides         List or revoke overrides

Options:
  --help            Show this help message
  --json            Output as JSON (where supported)
  --no-color        Disable colored output
  --scope <s>       user (default) or project
`);
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('--help') && !args[0]) {
    printUsage();
    process.exit(EXIT.OK);
  }

  const cmd = args[0];
  if (cmd === '--help' || cmd === '-h') {
    printUsage();
    process.exit(EXIT.OK);
  }
  if (cmd === '--version' || cmd === '-v') {
    console.log(`chaingate ${pkg.version}`);
    process.exit(EXIT.OK);
  }

  const loader = COMMANDS[cmd];
  if (!loader) {
    console.error(`Unknown command: ${cmd}\nRun 'chaingate --help' for usage.`);
    process.exit(EXIT.ERROR);
  }

  const cmdArgs = args.slice(1);

  // Per-command --help: show usage hint without running the command
  if (cmdArgs.includes('--help') || cmdArgs.includes('-h')) {
    const HELP = {
      init: 'chaingate init [--no-seed] [--seed <path>] [--scope user|project] [--force] [--dry-run]',
      status: 'chaingate status [--json] [--scope user|project]',
      allow: 'chaingate allow <package>@<version> --reason "..." [--scope user|project]',
      stop: 'chaingate stop [--scope user|project]',
      'update-seed': 'chaingate update-seed [--force] [--scope user|project]',
      why: 'chaingate why <package>@<version> [--json] [--scope user|project]',
      history: 'chaingate history <package> [--limit N] [--json] [--scope user|project]',
      doctor: 'chaingate doctor [--json] [--scope user|project]',
      check: 'chaingate check <package>@<version> [--json] [--scope user|project]\n  Exit codes: 0=ALLOW, 2=WARN, 3=BLOCK, 4=tool error',
      overrides: 'chaingate overrides [list|revoke <package>@<version>] [--json] [--scope user|project]',
    };
    console.log(HELP[cmd] ?? `chaingate ${cmd}`);
    process.exit(EXIT.OK);
  }

  const mod = await loader();

  try {
    const code = await mod.default(cmdArgs);
    process.exit(code ?? EXIT.OK);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(EXIT.ERROR);
  }
}

main();
