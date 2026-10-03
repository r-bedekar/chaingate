import { fmt } from '../format.js';
import { resolvePaths } from '../paths.js';
import { npmrcPath, removeChaingateBlock } from '../npmrc.js';
import { stopProxy } from '../proxy-control.js';
import { DEFAULT_PORT, DEFAULT_HOST, EXIT } from '../constants.js';

function parseArgs(args) {
  const opts = { scope: 'user' };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--scope' && args[i + 1]) opts.scope = args[++i];
  }
  return opts;
}

// The .npmrc block is removed only when this scope's proxy is known to be gone (U-05 gap-closure r2, revision 2 §6). On
// any other outcome it is left in place and the command says so, without claiming which process npm is talking to.
const SUCCESS = new Set(['not_running', 'stopped', 'stopped_port_taken']);

/**
 * Stop the proxy and restore .npmrc, returning what happened. `chaingate stop` prints `lines`; tests call this with their
 * own paths and port.
 */
export async function runStop({ pidFile, npmrcFile, port = DEFAULT_PORT, host = DEFAULT_HOST, ...stopOpts }) {
  const r = await stopProxy(pidFile, { port, host, ...stopOpts });
  const lines = [];
  let npmrcRestored = false;
  if (r.outcome === 'stopped') lines.push(fmt.ok('Proxy stopped'));
  else if (r.outcome === 'stopped_port_taken') {
    lines.push(fmt.ok('Proxy stopped'));
    lines.push(fmt.warn(`  ${r.detail}`));
  } else if (r.outcome === 'not_running') {
    lines.push(fmt.dim('Proxy was not running'));
    if (/in use by/.test(r.detail)) lines.push(fmt.warn(`  ${r.detail}`));
  } else {
    const head = { timeout: 'Proxy did NOT stop within the wait', unverified: 'Proxy NOT stopped: ownership not established',
      permission_denied: 'Proxy NOT stopped: the liveness check was refused' }[r.outcome];
    lines.push(fmt.fail(head));
    lines.push(fmt.dim(`  ${r.detail}`));
  }
  if (SUCCESS.has(r.outcome)) {
    npmrcRestored = removeChaingateBlock(npmrcFile);
    lines.push(npmrcRestored ? fmt.ok(`.npmrc restored (${npmrcFile})`) : fmt.dim('.npmrc had no chaingate block'));
  } else {
    lines.push(fmt.dim(`  The ChainGate block in ${npmrcFile} (registry=http://${host}:${port}) was left in place.`));
  }
  return { ...r, npmrcRestored, exit: SUCCESS.has(r.outcome) ? EXIT.OK : EXIT.ERROR, lines };
}

export default async function stop(args) {
  const opts = parseArgs(args);
  const paths = resolvePaths(opts.scope);
  const r = await runStop({ pidFile: paths.pidFile, npmrcFile: npmrcPath(opts.scope) });
  for (const l of r.lines) console.log(l);
  return r.exit;
}
