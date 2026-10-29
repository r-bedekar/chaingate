#!/usr/bin/env node
import { EXIT } from './constants.js';
import { COMMAND_HELP } from './help.js';
import { classifyNativeSqliteError, probeNativeSqlite, nativeSqliteHelp } from './native-sqlite.js';

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
  'update-advisories': () => import('./commands/update-advisories.js'),
  why: () => import('./commands/why.js'),
  history: () => import('./commands/history.js'),
  doctor: () => import('./commands/doctor.js'),
  check: () => import('./commands/check.js'),
  overrides: () => import('./commands/overrides.js'),
  report: () => import('./commands/report.js'),
  accept: () => import('./commands/accept.js'),
  pin: () => import('./commands/pin.js'),
  unpin: () => import('./commands/unpin.js'),
};

function printUsage() {
  console.log(`Usage: chaingate <command> [options]

Commands:
  init              Set up ChainGate (download seed, start proxy, patch .npmrc)
  status            Show witness store stats, proxy state, recent decisions
  allow <p@v>       Override a WARN/BLOCK for a specific package version
  stop              Stop the proxy and restore .npmrc
  update-seed       Download and verify the latest seed database
  update-advisories Fetch the signed advisory feed of known malicious versions now
  why <p@v>         The recorded decision for a version (or --packument <file> | --from <file>)
  history <pkg>     Show the version timeline for a package
  doctor            Check local invariants (6 health checks)
  check <p@v>       Evaluate a release from --packument <file> (CI exit codes)
  overrides         List or revoke overrides
  report            What the proxy served and refused in the last install (--all | --since <dur>)
  accept <p@v>      Accept a named warning for one version (quiets its notice; never overrides a BLOCK)
  pin <p@v>         Stay on a version: withhold newer ones in its major until unpin
  unpin <pkg>       Remove a package's pins

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
    console.log(COMMAND_HELP[cmd] ?? `chaingate ${cmd}`);
    process.exit(EXIT.OK);
  }

  const mod = await loader();

  try {
    const code = await mod.default(cmdArgs);
    process.exit(code ?? EXIT.OK);
  } catch (err) {
    const nativeKind = classifyNativeSqliteError(err);
    // A missing native module reports every path it tried; the first line says what happened.
    console.error(`Error: ${nativeKind ? String(err.message).split('\n')[0] : err.message}`);
    if (nativeKind) {
      const { version } = probeNativeSqlite();
      console.error('');
      for (const line of nativeSqliteHelp(nativeKind, version)) console.error(line);
    }
    process.exit(EXIT.ERROR);
  }
}

main();
