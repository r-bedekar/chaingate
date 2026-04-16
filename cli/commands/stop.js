import { fmt } from '../format.js';
import { resolvePaths } from '../paths.js';
import { npmrcPath, removeChaingateBlock } from '../npmrc.js';
import { stopProxy } from '../proxy-control.js';
import { EXIT } from '../constants.js';

function parseArgs(args) {
  const opts = { scope: 'user' };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--scope' && args[i + 1]) opts.scope = args[++i];
  }
  return opts;
}

export default async function stop(args) {
  const opts = parseArgs(args);
  const paths = resolvePaths(opts.scope);

  // 1. Stop proxy
  const killed = stopProxy(paths.pidFile);
  if (killed) {
    console.log(fmt.ok('Proxy stopped'));
  } else {
    console.log(fmt.dim('Proxy was not running'));
  }

  // 2. Restore .npmrc
  const rc = npmrcPath(opts.scope);
  const removed = removeChaingateBlock(rc);
  if (removed) {
    console.log(fmt.ok(`.npmrc restored (${rc})`));
  } else {
    console.log(fmt.dim('.npmrc had no chaingate block'));
  }

  return EXIT.OK;
}
