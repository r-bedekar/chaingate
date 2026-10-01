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
const seedVerify = await import('../../witness/seed_verify.js');
const gate = await import('../../cli/integrity-gate.js');
// Legacy-route tests: U05_LEGACY_BUNDLE names a directory holding a synthetic signed legacy seed (its "download" is a
// fresh copy of it), and U05_TEST_SPKI the TEST public key every verification uses here. The product has no such inputs.
const testKey = process.env.U05_TEST_SPKI ? (await import('node:crypto')).createPublicKey(
  { key: Buffer.from(process.env.U05_TEST_SPKI, 'base64'), format: 'der', type: 'spki' }) : null;
const bundleDir = process.env.U05_LEGACY_BUNDLE || null;
const legacyDeps = {
  ...(bundleDir ? { fetchSeedBundle: async () => {
    const d = fs.mkdtempSync(`${bundleDir}-dl-`); const out = { dir: d };
    for (const [k, n] of [['dbPath', 'chaingate-seed.db'], ['sha256Path', 'chaingate-seed.db.sha256'], ['sigPath', 'chaingate-seed.db.sig']]) {
      out[k] = `${d}/${n}`; fs.copyFileSync(`${bundleDir}/${n}`, out[k]);
    }
    out.cleanup = () => { fs.rmSync(d, { recursive: true, force: true }); return null; };
    return out;
  } } : {}),
  ...(testKey ? {
    verifySeed: (db, sha, sig) => seedVerify.verifySeed(db, sha, sig, { pubkey: testKey }),
    verifyStagedSeed: (st) => seedVerify.verifyStagedSeed(st, { pubkey: testKey }),
    assertIntegrity: (p, o) => gate.assertIntegrity(p, { ...o, pubkey: testKey }),
  } : {}),
};
let code;
if (command === 'update-seed') {
  const { fetchSeedBundle } = await import('../../cli/seed-download.js');
  const updateSeed = (await import('../../cli/commands/update-seed.js')).default;
  code = await updateSeed(args, { fetchSeedBundle, verifySeed: seedVerify.verifySeed, assertIntegrity: gate.assertIntegrity,
    resolvePaths: (scope) => resolvePaths(scope, process.cwd(), { CHAINGATE_HOME: base }), hooks, ...legacyDeps });
} else if (command === 'init') {
  const init = (await import('../../cli/commands/init.js')).default;
  code = await init(args, { hooks, ...legacyDeps });
} else {
  throw new Error(`unknown command ${command}`);
}
say(`EXIT ${code}`);
process.exitCode = code;
