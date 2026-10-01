import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, unlinkSync, existsSync, openSync } from 'node:fs';
import http from 'node:http';
import { createConnection } from 'node:net';
import { DEFAULT_PORT, DEFAULT_HOST } from './constants.js';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SERVER_ENTRY = join(__dirname, '..', 'proxy', 'server.js');

/**
 * Check if a process with the given PID is alive.
 */
export function isAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/**
 * Is this pid alive? THREE answers, never two (U-05 gap-closure r2): `alive` (signal 0 delivered), `dead` (ESRCH), or
 * `indeterminate` (EPERM or any other error) -- which says only that the operating system refused the check, not that
 * the pid is ours, and not that it is gone. `isAlive` above folds `indeterminate` into "not alive"; nothing that signals
 * or cleans up may rely on it.
 */
export function probePid(pid, kill = process.kill) {
  try {
    kill(pid, 0);
    return { state: 'alive' };
  } catch (err) {
    if (err?.code === 'ESRCH') return { state: 'dead' };
    return { state: 'indeterminate', code: err?.code ?? 'unknown' };
  }
}

/**
 * The pid record, with its three-state liveness: null (no record), { pid: null, state: 'malformed' }, or
 * { pid, state, code? }. The file stays a plain pid (other readers, e.g. the acceptance harness, parse it as a number).
 */
export function readPidRecord(pidFile, { kill = process.kill } = {}) {
  if (!existsSync(pidFile)) return null;
  const raw = readFileSync(pidFile, 'utf8').trim();
  const pid = /^\d+$/.test(raw) ? parseInt(raw, 10) : NaN;
  if (!Number.isFinite(pid) || pid <= 0) return { pid: null, state: 'malformed' };
  return { pid, ...probePid(pid, kill) };
}

/**
 * Read the PID from a pid file. Returns null if missing or stale.
 */
export function readPid(pidFile) {
  if (!existsSync(pidFile)) return null;
  const raw = readFileSync(pidFile, 'utf8').trim();
  const pid = parseInt(raw, 10);
  if (!Number.isFinite(pid) || pid <= 0) return null;
  return isAlive(pid) ? pid : null;
}

/**
 * Spawn the proxy as a detached background process.
 * Stdout/stderr go to logFile. PID is written to pidFile.
 *
 * @param {{pidFile: string, logFile: string, env?: Record<string,string>}} opts
 * @returns {number} The child PID.
 */
export function spawnProxy({ pidFile, logFile, env = {} }) {
  const logFd = openSync(logFile, 'a');

  const child = spawn(process.execPath, [SERVER_ENTRY], {
    detached: true,
    stdio: ['ignore', logFd, logFd],
    env: { ...process.env, ...env },
  });

  child.unref();
  writeFileSync(pidFile, String(child.pid), 'utf8');
  return child.pid;
}

/** GET /_chaingate/self with its own deadline and a 64 KiB response cap. Never throws. */
export function fetchSelf(host, port, timeoutMs = 1500) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (r) => { if (!done) { done = true; clearTimeout(timer); resolve(r); } };
    const req = http.get({ host, port, path: '/_chaingate/self', agent: false, timeout: timeoutMs }, (res) => {
      let size = 0; const chunks = [];
      res.on('data', (c) => {
        size += c.length;
        if (size > 65536) { req.destroy(); finish({ ok: false, why: 'answered with more than 64 KiB' }); return; }
        chunks.push(c);
      });
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(body); } catch { /* not JSON */ }
        if (res.statusCode !== 200) finish({ ok: false, why: `answered HTTP ${res.statusCode}` });
        else if (!json || typeof json !== 'object' || Array.isArray(json)) finish({ ok: false, why: 'answered, but not with a JSON object' });
        else finish({ ok: true, json });
      });
      res.on('error', (e) => finish({ ok: false, why: `answer failed (${e.message})` }));
    });
    req.on('timeout', () => { req.destroy(); finish({ ok: false, why: `no answer within ${timeoutMs} ms` }); });
    req.on('error', (e) => finish({ ok: false, why: e.code === 'ECONNREFUSED' ? 'nothing is listening' : `connection failed (${e.code ?? e.message})` }));
    const timer = setTimeout(() => { req.destroy(); finish({ ok: false, why: `no answer within ${timeoutMs} ms` }); }, timeoutMs + 100);
  });
}

/** What answered on the port, in words, for messages. */
function describeListener(r) {
  if (!r.ok) return r.why;
  const j = r.json;
  return j.service === 'chaingate-proxy'
    ? `a ChainGate proxy (pid ${j.pid}, version ${j.version ?? 'unknown'})`
    : `a service that calls itself ${JSON.stringify(String(j.service ?? 'nothing'))}`;
}

export const STOP_OUTCOMES = Object.freeze(['not_running', 'stopped', 'stopped_port_taken', 'timeout', 'unverified',
  'permission_denied']);

/**
 * Stop the proxy recorded in `pidFile`, truthfully (U-05 gap-closure r2, revision 2 §6, Addendum 1 §D).
 *
 * Nothing is signalled unless the recorded pid is alive AND the process answering /_chaingate/self on the port says it
 * is the ChainGate proxy with that same pid; the pid is probed again immediately before SIGTERM. "Stopped" is reported
 * only when the pid is gone AND the port refuses connections, within one bounded wait -- never an arbitrary sleep.
 * A PID-reuse window of milliseconds remains between the last probe and SIGTERM; with signals it cannot be removed.
 *
 * @returns {Promise<{outcome, pid, detail, waitedMs?}>}  outcome in STOP_OUTCOMES. The pid record is removed only for
 *          not_running, stopped and stopped_port_taken.
 */
export async function stopProxy(pidFile, { port = DEFAULT_PORT, host = DEFAULT_HOST, waitMs = 8000, selfTimeoutMs = 1500,
  pollMs = 100, kill = process.kill } = {}) {
  const removeRecord = () => { try { unlinkSync(pidFile); } catch { /* already gone */ } };
  const rec = readPidRecord(pidFile, { kill });
  if (!rec || rec.state === 'malformed' || rec.state === 'dead') {
    if (rec) removeRecord();
    const listening = await isPortInUse(port, host);
    const extra = listening ? `; ${host}:${port} is in use by ${describeListener(await fetchSelf(host, port, selfTimeoutMs))}, `
      + 'which this command did not start and did not stop' : '';
    const what = !rec ? 'no pid record' : rec.state === 'malformed' ? 'the pid record was not a pid (removed)'
      : `pid ${rec.pid} is not running (stale record removed)`;
    return { outcome: 'not_running', pid: rec?.pid ?? null, detail: `${what}${extra}` };
  }
  const { pid } = rec;
  const denied = (code) => ({ outcome: 'permission_denied', pid,
    detail: `the operating system refused the liveness check for pid ${pid} (${code}): this user cannot signal that pid. `
      + 'It was not established whether it is the ChainGate proxy. Nothing was signalled; the pid record was left in place' });
  if (rec.state === 'indeterminate') return denied(rec.code);

  const self = await fetchSelf(host, port, selfTimeoutMs);
  const owned = self.ok && self.json.service === 'chaingate-proxy' && Number.isInteger(self.json.pid) && self.json.pid === pid;
  if (!owned) {
    const why = !self.ok ? `${host}:${port} ${self.why}`
      : self.json.service !== 'chaingate-proxy'
        ? `${host}:${port} is answered by a service that calls itself ${JSON.stringify(String(self.json.service ?? 'nothing'))}, not chaingate-proxy`
        : `the ChainGate proxy on ${host}:${port} reports pid ${self.json.pid}, not the recorded pid ${pid}`;
    return { outcome: 'unverified', pid,
      detail: `pid ${pid} is alive, but it was not established that it is this ChainGate proxy: ${why}. Nothing was `
        + `signalled; the pid record was left in place. If you are sure pid ${pid} is the proxy, stop it with your `
        + 'operating system tools, then run `chaingate stop` again' };
  }

  const again = probePid(pid, kill);                 // as late as possible before the signal
  if (again.state === 'indeterminate') return denied(again.code);
  const started = Date.now();
  if (again.state === 'alive') {
    try {
      kill(pid, 'SIGTERM');
    } catch (err) {
      if (err?.code !== 'ESRCH') return denied(err?.code ?? 'unknown');   // ESRCH: it exited in between
    }
  }
  for (;;) {
    const p = probePid(pid, kill).state;
    const listening = await isPortInUse(port, host);
    if (p === 'dead' && !listening) {
      removeRecord();
      return { outcome: 'stopped', pid, waitedMs: Date.now() - started, detail: `pid ${pid} exited and ${host}:${port} is closed` };
    }
    if (p === 'dead' && listening) {
      removeRecord();
      return { outcome: 'stopped_port_taken', pid, waitedMs: Date.now() - started,
        detail: `pid ${pid} exited, but ${host}:${port} is now answered by ${describeListener(await fetchSelf(host, port, selfTimeoutMs))}` };
    }
    if (Date.now() - started >= waitMs) {
      return { outcome: 'timeout', pid, waitedMs: Date.now() - started,
        detail: `after ${Math.round((Date.now() - started) / 100) / 10} s: pid ${pid} is ${p === 'alive' ? 'still alive' : `in state ${p}`}, `
          + `${host}:${port} is ${listening ? 'still accepting connections' : 'closed'}. The pid record was left in place` };
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
}

/**
 * Wait until a TCP port accepts connections, or timeout.
 * @param {number} port
 * @param {string} host
 * @param {number} timeoutMs
 * @returns {Promise<boolean>}
 */
export function waitForPort(port, host = '127.0.0.1', timeoutMs = 5000) {
  return new Promise((resolve) => {
    const deadline = Date.now() + timeoutMs;
    const attempt = () => {
      if (Date.now() > deadline) return resolve(false);
      const sock = createConnection({ port, host }, () => {
        sock.destroy();
        resolve(true);
      });
      sock.on('error', () => {
        sock.destroy();
        setTimeout(attempt, 150);
      });
    };
    attempt();
  });
}

/**
 * Wait for a freshly spawned proxy to become reachable.
 *
 * A FLAT deadline is wrong here. The proxy opens and validates the seed BEFORE it listens, and a
 * real seed is gigabytes: the 5 s that was ample for a fixture expires long before a production
 * bundle is open, so `init` declared a healthy start-up dead, refused to redirect .npmrc and exited
 * non-zero while the proxy came up seconds later. Waiting longer by itself is no better — it just
 * trades a false failure for a slow one when the process really is dead.
 *
 * So the bound is the CHILD ITSELF: keep waiting while the process is alive, stop the moment it is
 * not, and report which of the two happened. `ceilingMs` remains only as a backstop against a
 * process that is alive but permanently wedged.
 *
 * @returns {Promise<{ready: boolean, why: 'ready'|'exited'|'timeout', waitedMs: number}>}
 */
export function waitForProxyReady({ port, host = '127.0.0.1', pid, ceilingMs = 180000,
  pollMs = 150, connect = createConnection }) {
  return new Promise((resolve) => {
    const started = Date.now();
    let settled = false;
    let sock = null;
    let pollTimer = null;
    let ceiling = null;

    const dropSocket = () => {
      if (!sock) return;
      const s = sock; sock = null;
      s.removeAllListeners(); s.destroy();
    };
    const done = (ready, why) => {
      if (settled) return;
      settled = true;
      clearTimeout(pollTimer); clearTimeout(ceiling);
      dropSocket();                                  // never leave a half-open socket behind
      resolve({ ready, why, waitedMs: Date.now() - started });
    };

    // ONE deadline over the WHOLE wait, armed once and independent of socket state. Checking the
    // ceiling inside the error handler was not a deadline at all: a connect that STALLS — SYN sent,
    // nothing back — never errors, so the check never ran and the wait could outlive its budget
    // indefinitely.
    ceiling = setTimeout(() => done(false, 'timeout'), ceilingMs);

    const attempt = () => {
      if (settled) return;
      // `connect` is injectable so a test can hand in a socket that NEVER settles. A stalled
      // connect cannot be produced deterministically from the network side: a reserved address
      // may be blackholed on one network and rejected at once on another (RFC 5737 §4 reserves
      // TEST-NET for documentation, nothing more).
      sock = connect({ port, host }, () => {
        dropSocket();
        done(true, 'ready');
      });
      // A stalled connect must not wedge the loop either: time the attempt out and retry, which also
      // keeps the liveness check below running while the port is unresponsive.
      sock.setTimeout(Math.max(pollMs * 4, 1000), () => { retry(); });
      sock.on('error', () => { retry(); });
    };
    const retry = () => {
      dropSocket();
      if (settled) return;
      if (pid !== undefined && !isAlive(pid)) return done(false, 'exited');
      pollTimer = setTimeout(attempt, pollMs);
    };

    attempt();
  });
}

/**
 * Check if a port is already in use.
 * @returns {Promise<boolean>}
 */
export function isPortInUse(port, host = '127.0.0.1') {
  return new Promise((resolve) => {
    const sock = createConnection({ port, host }, () => {
      sock.destroy();
      resolve(true);
    });
    sock.on('error', () => {
      sock.destroy();
      resolve(false);
    });
  });
}
