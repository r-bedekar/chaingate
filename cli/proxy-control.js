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
