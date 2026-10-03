// U-05 gap-closure r2 (owner decision 6), A2: a truthful, ownership-checked `chaingate stop`. Expected values come from
// revision 2 §6 and Addendum 1 §D (S-1..S-11), written before this file. Fake proxies are small Node child processes
// written to the test's temporary directory; they listen on ephemeral loopback ports. Nothing outside the temporary
// directory is signalled except the children this file starts.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { probePid, readPidRecord, stopProxy, isPortInUse } from '../../cli/proxy-control.js';
import { runStop } from '../../cli/commands/stop.js';
import { restartAllowed } from '../../cli/commands/init.js';
import { NPMRC_MARKER_START, NPMRC_MARKER_END } from '../../cli/constants.js';

const FAKE = `import http from 'node:http';
import fs from 'node:fs';
import { spawn } from 'node:child_process';
const [mode, raw] = process.argv.slice(2);
const opt = JSON.parse(raw || '{}');
setTimeout(() => process.exit(0), opt.lifetimeMs ?? 30000).unref();
if (mode === 'listener') {
  if (opt.pidOut) fs.writeFileSync(opt.pidOut, String(process.pid));
  const s = http.createServer((q, r) => { r.writeHead(200, { 'content-type': 'application/json' });
    r.end(JSON.stringify({ service: opt.service || 'something-else', pid: process.pid })); });
  s.listen(opt.port, '127.0.0.1');
} else {
  const srv = http.createServer((req, res) => {
    if (opt.self === 'hang') return;
    if (opt.self === 'garbage') { res.writeHead(200); res.end('not json'); return; }
    const pid = opt.self === 'otherpid' ? process.pid + 100000 : process.pid;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ service: opt.service || 'chaingate-proxy', version: '0.1.3', pid }));
  });
  let myPort = null;
  srv.listen(0, '127.0.0.1', () => { myPort = srv.address().port; process.stdout.write('READY ' + myPort + '\\n'); });
  process.on('SIGTERM', () => {
    if (opt.ignoreTerm) return;
    setTimeout(() => {
      srv.close(); srv.closeAllConnections?.();
      if (opt.takeover) {
        spawn(process.execPath, [process.argv[1], 'listener', JSON.stringify({ port: myPort, pidOut: opt.pidOut })],
          { detached: true, stdio: 'ignore' }).unref();
      }
      setTimeout(() => process.exit(0), opt.takeover ? 700 : 0);
    }, opt.exitDelayMs ?? 0);
  });
}
`;

const children = [];
function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'u05-r2-stop-')); }
async function fake(dir, opt = {}) {
  const script = path.join(dir, 'fake-proxy.mjs');
  if (!fs.existsSync(script)) fs.writeFileSync(script, FAKE);
  const child = spawn(process.execPath, [script, 'proxy', JSON.stringify(opt)], { stdio: ['ignore', 'pipe', 'ignore'] });
  children.push(child);
  const port = await new Promise((resolve, reject) => {
    let buf = '';
    child.stdout.on('data', (d) => { buf += d; const m = buf.match(/READY (\d+)/); if (m) resolve(Number(m[1])); });
    child.on('exit', () => reject(new Error('fake proxy exited early')));
  });
  const pidFile = path.join(dir, 'proxy.pid');
  fs.writeFileSync(pidFile, String(child.pid));
  return { child, port, pidFile, alive: () => probePid(child.pid).state === 'alive' };
}
const fast = { selfTimeoutMs: 500, waitMs: 3000, pollMs: 50 };
test.after(() => { for (const c of children) { try { c.kill('SIGKILL'); } catch { /* gone */ } } });

test('probePid is three-state: alive, dead, indeterminate (EPERM and any other error)', () => {
  assert.equal(probePid(process.pid).state, 'alive');
  const err = (code) => () => { const e = new Error(code); e.code = code; throw e; };
  assert.equal(probePid(1234, err('ESRCH')).state, 'dead');
  assert.deepEqual(probePid(1234, err('EPERM')), { state: 'indeterminate', code: 'EPERM' });
  assert.deepEqual(probePid(1234, err('EINVAL')), { state: 'indeterminate', code: 'EINVAL' });
});

test('S-1 a proxy that takes 1 s to exit: STOPPED is reported only after the pid is gone AND the port is closed', async () => {
  const dir = tmp();
  const f = await fake(dir, { exitDelayMs: 1000 });
  const r = await stopProxy(f.pidFile, { port: f.port, ...fast });
  assert.equal(r.outcome, 'stopped');
  assert.equal(await isPortInUse(f.port), false, 'port closed when stop returns');
  assert.equal(f.alive(), false, 'process gone when stop returns');
  assert.equal(fs.existsSync(f.pidFile), false, 'record removed');
});

test('S-2 a stale record (dead pid) and a malformed record: NOT_RUNNING, record removed', async () => {
  const dir = tmp();
  const dead = spawn(process.execPath, ['-e', 'process.exit(0)']);
  await new Promise((r) => dead.on('exit', r));
  const pidFile = path.join(dir, 'proxy.pid');
  fs.writeFileSync(pidFile, String(dead.pid));
  assert.equal((await stopProxy(pidFile, { port: 9, ...fast })).outcome, 'not_running');
  assert.equal(fs.existsSync(pidFile), false);
  fs.writeFileSync(pidFile, 'abc');
  assert.equal(readPidRecord(pidFile).state, 'malformed');
  assert.equal((await stopProxy(pidFile, { port: 9, ...fast })).outcome, 'not_running');
  assert.equal(fs.existsSync(pidFile), false);
});

test('S-3 EPERM on the liveness check: PERMISSION_DENIED; nothing signalled; record kept; the text claims no ownership', async () => {
  const dir = tmp();
  const f = await fake(dir);
  const signals = [];
  const kill = (pid, sig) => { signals.push(sig); const e = new Error('EPERM'); e.code = 'EPERM'; throw e; };
  const r = await stopProxy(f.pidFile, { port: f.port, kill, ...fast });
  assert.equal(r.outcome, 'permission_denied');
  assert.deepEqual(signals, [0], 'only the liveness probe; no SIGTERM');
  assert.ok(fs.existsSync(f.pidFile));
  assert.match(r.detail, /not established whether it is the ChainGate proxy/);
  assert.ok(f.alive());
});

for (const [label, opt, why] of [
  ['S-4 self answers with another pid', { self: 'otherpid' }, /pid/],
  ['S-5 a non-ChainGate service answers', { service: 'something-else' }, /service/],
  ['S-6 wedged: accepts TCP, never answers', { self: 'hang' }, /no answer|did not answer/],
  ['S-6b answers with non-JSON', { self: 'garbage' }, /JSON/],
]) {
  test(`${label}: UNVERIFIED; nothing signalled; record kept`, async () => {
    const dir = tmp();
    const f = await fake(dir, opt);
    const t0 = Date.now();
    const r = await stopProxy(f.pidFile, { port: f.port, ...fast });
    assert.equal(r.outcome, 'unverified');
    assert.match(r.detail, why);
    assert.ok(Date.now() - t0 < 2500, 'bounded by the self timeout');
    assert.ok(f.alive(), 'not signalled');
    assert.ok(fs.existsSync(f.pidFile));
  });
}

test('S-7 ignores SIGTERM: TIMEOUT within the deadline; record kept', { skip: process.platform === 'win32' ? 'POSIX signal semantics: on Windows SIGTERM is TerminateProcess and cannot be ignored or handled' : false }, async () => {
  const dir = tmp();
  const f = await fake(dir, { ignoreTerm: true });
  const t0 = Date.now();
  const r = await stopProxy(f.pidFile, { port: f.port, ...fast, waitMs: 1500 });
  assert.equal(r.outcome, 'timeout');
  assert.ok(Date.now() - t0 < 1500 + 500 + 1500, 'bounded');
  assert.ok(fs.existsSync(f.pidFile));
  assert.match(r.detail, /alive/);
});

test('S-8 the owned proxy exits and another listener takes the port: STOPPED_PORT_TAKEN naming it', { skip: process.platform === 'win32' ? 'POSIX signal semantics: on Windows SIGTERM is TerminateProcess and cannot be ignored or handled' : false }, async () => {
  const dir = tmp();
  const pidOut = path.join(dir, 'listener.pid');
  const f = await fake(dir, { takeover: true, pidOut });   // on SIGTERM: closes, a detached listener binds ITS port, exits
  const r = await stopProxy(f.pidFile, { port: f.port, ...fast });
  try {
    assert.equal(r.outcome, 'stopped_port_taken');
    assert.match(r.detail, /something-else/, 'names what now answers on the port');
    assert.equal(fs.existsSync(f.pidFile), false, 'our record is removed: our process is gone');
  } finally {
    if (fs.existsSync(pidOut)) { try { process.kill(Number(fs.readFileSync(pidOut, 'utf8')), 'SIGKILL'); } catch { /* gone */ } }
  }
});

test('S-9 the process exits between the check and the signal (ESRCH): STOPPED', async () => {
  const dir = tmp();
  const f = await fake(dir);
  const kill = (pid, sig) => {
    if (sig === 0 || sig === undefined) return process.kill(pid, 0);
    process.kill(pid, 'SIGKILL');
    const e = new Error('ESRCH'); e.code = 'ESRCH'; throw e;
  };
  const r = await stopProxy(f.pidFile, { port: f.port, kill, ...fast });
  assert.equal(r.outcome, 'stopped');
});

test('S-10 .npmrc: only the ChainGate block is removed on success; byte-identical on an unsuccessful stop', { skip: process.platform === 'win32' ? 'POSIX signal semantics: on Windows SIGTERM is TerminateProcess and cannot be ignored or handled' : false }, async () => {
  const dir = tmp();
  const head = 'registry=https://registry.example/\r\n//registry.example/:_authToken=X\r\n@scope:registry=https://s.example/\r\n';
  const tail = 'save-exact=true\n';
  const content = `${head}\n${NPMRC_MARKER_START}\nregistry=http://127.0.0.1:6173\n${NPMRC_MARKER_END}\n${tail}`;
  const npmrcFile = path.join(dir, '.npmrc');

  fs.writeFileSync(npmrcFile, content);
  const stuck = await fake(dir, { ignoreTerm: true });
  const bad = await runStop({ pidFile: stuck.pidFile, npmrcFile, port: stuck.port, ...fast, waitMs: 800 });
  assert.equal(bad.outcome, 'timeout'); assert.equal(bad.exit, 1);
  assert.equal(fs.readFileSync(npmrcFile, 'utf8'), content, 'unchanged byte for byte');
  assert.ok(bad.lines.some((l) => /left in place/.test(l)));
  assert.ok(!bad.lines.some((l) => /npm (is|keeps) talking/.test(l)), 'no claim about which process serves npm');
  stuck.child.kill('SIGKILL');

  const ok = await fake(dir);
  const good = await runStop({ pidFile: ok.pidFile, npmrcFile, port: ok.port, ...fast });
  assert.equal(good.outcome, 'stopped'); assert.equal(good.exit, 0);
  assert.equal(fs.readFileSync(npmrcFile, 'utf8'), `${head}\n${tail}`,
    'everything outside the block preserved (CRLF lines, the token line, scoped registries, lines after the block)');
});

test('S-11 init --force restarts only after STOPPED or NOT_RUNNING', () => {
  for (const o of ['stopped', 'not_running']) assert.equal(restartAllowed(o), true, o);
  for (const o of ['timeout', 'unverified', 'permission_denied', 'stopped_port_taken']) assert.equal(restartAllowed(o), false, o);
});
