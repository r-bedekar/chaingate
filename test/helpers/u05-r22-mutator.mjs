// U-05 R2-2 (b) child harness: run the REAL `init` or `update-seed` command function in this process, with every named
// hook point (`deps.hooks.<name>`) reported, and optionally paused or killed at one of them.
//   node u05-r22-mutator.mjs <base> <init|update-seed> [args...]
//   env U05_PAUSE_AT=<hook>  print "AT <hook>" and BLOCK (synchronously) until a line arrives on stdin
//   env U05_KILL_AT=<hook>   print "AT <hook>" and SIGKILL this process there
//   env U05_AT_NTH=<n>       act at the n-th time that hook is reached (default 1)
// Hooks are called synchronously inside the code under test, so the pause is a blocking read of stdin, not an await.
import fs from 'node:fs';

const [base, command, ...args] = process.argv.slice(2);
process.env.CHAINGATE_HOME = base;
const pauseAt = process.env.U05_PAUSE_AT || null;
const killAt = process.env.U05_KILL_AT || null;
const nth = Number(process.env.U05_AT_NTH || 1);
const seen = {};
const say = (m) => fs.writeSync(1, `${m}\n`);

function onHook(name) {
  seen[name] = (seen[name] || 0) + 1;
  say(`HOOK ${name} ${seen[name]}`);
  if (seen[name] !== nth) return;
  if (name === killAt) { say(`AT ${name}`); process.kill(process.pid, 'SIGKILL'); }
  if (name === pauseAt) {
    say(`AT ${name}`);
    const b = Buffer.alloc(1);
    while (fs.readSync(0, b, 0, 1, null) === 1 && b[0] !== 0x0a) { /* wait for a newline */ }
    say(`GO ${name}`);
  }
}
// every property is a hook function, so `hooks.anything?.()` reaches onHook
const hooks = new Proxy({}, { get: (_, name) => (typeof name === 'string' ? (...a) => onHook(name, ...a) : undefined) });

const { resolvePaths } = await import('../../cli/paths.js');
let code;
if (command === 'update-seed') {
  const { fetchSeedBundle } = await import('../../cli/seed-download.js');
  const { verifySeed } = await import('../../witness/seed_verify.js');
  const { assertIntegrity } = await import('../../cli/integrity-gate.js');
  const updateSeed = (await import('../../cli/commands/update-seed.js')).default;
  code = await updateSeed(args, { fetchSeedBundle, verifySeed, assertIntegrity,
    resolvePaths: (scope) => resolvePaths(scope, process.cwd(), { CHAINGATE_HOME: base }), hooks });
} else if (command === 'init') {
  const init = (await import('../../cli/commands/init.js')).default;
  code = await init(args, { hooks });
} else {
  throw new Error(`unknown command ${command}`);
}
say(`EXIT ${code}`);
process.exitCode = code;
