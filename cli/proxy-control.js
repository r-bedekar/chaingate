import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, unlinkSync, existsSync, openSync } from 'node:fs';
import { createConnection } from 'node:net';
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

/**
 * Send SIGTERM to the proxy and clean up the PID file.
 * @returns {boolean} true if a process was killed.
 */
export function stopProxy(pidFile) {
  const pid = readPid(pidFile);
  if (pid == null) {
    // Clean up stale pid file
    if (existsSync(pidFile)) unlinkSync(pidFile);
    return false;
  }
  try {
    process.kill(pid, 'SIGTERM');
  } catch {
    // Already dead
  }
  try { unlinkSync(pidFile); } catch { /* ok */ }
  return true;
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
