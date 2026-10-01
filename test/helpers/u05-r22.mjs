// U-05 R2-2 shared test helpers: synthetic hosts, the real CLI and proxy entry points as child processes with hard
// timeouts, FIFOs and padded files. Synthetic inputs only; every host lives in a fresh temporary directory.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { buildSyntheticSeed } from '../seed-v3/u01-cases.mjs';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
export const CLI = path.join(ROOT, 'cli', 'index.js');
export const PROXY = path.join(ROOT, 'proxy', 'server.js');
export const METER = path.join(ROOT, 'test', 'helpers', 'fs-read-meter.mjs');

export const sha256 = (f) => createHash('sha256').update(fs.readFileSync(f)).digest('hex');
export const plain = (s) => String(s).replace(/\x1b\[[0-9;]*m/g, '');
export const exists = (p) => { try { fs.lstatSync(p); return true; } catch { return false; } };

/** mkfifo is POSIX; Windows has named pipes instead (qualified natively, R2-2 §3.3). */
export const canFifo = process.platform !== 'win32'
  && spawnSync('mkfifo', ['--version'], { stdio: 'ignore' }).status === 0;
export function mkfifo(p) {
  const r = spawnSync('mkfifo', [p]);
  if (r.status !== 0) throw new Error(`mkfifo ${p}: ${r.stderr}`);
  return p;
}

/** Replace a file (even a read-only bundle file) with `bytes`, or with a FIFO. */
export function replaceWith(p, bytes) { try { fs.chmodSync(p, 0o644); } catch { /* absent */ } fs.rmSync(p, { force: true }); fs.writeFileSync(p, bytes); }
export function replaceWithFifo(p) { try { fs.chmodSync(p, 0o644); } catch { /* absent */ } fs.rmSync(p, { force: true }); return mkfifo(p); }
/** `text` followed by whitespace padding to exactly `size` bytes: still parses as before, only longer. */
export const padded = (text, size) => Buffer.concat([Buffer.from(text), Buffer.alloc(size - Buffer.byteLength(text), 0x20)]);
/** A sparse file of `size` bytes (no disk blocks used). */
export function sparse(p, size) { try { fs.chmodSync(p, 0o644); } catch { /* absent */ } fs.rmSync(p, { force: true }); const fd = fs.openSync(p, 'w'); fs.ftruncateSync(fd, size); fs.closeSync(fd); }

/** A fresh home with an empty ChainGate base. */
export function freshHome(tag = 'r22') {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), `cg-${tag}-`));
  const base = path.join(home, '.chaingate'); fs.mkdirSync(base, { recursive: true });
  return { home, base };
}

/** A synthetic v3 seed source directory: chaingate-seed.db + .sha256 (unsigned). */
export function v3Source() {
  const s = buildSyntheticSeed();
  return { dir: s.dir, db: s.dbPath, sha: `${s.dbPath}.sha256`, sig: `${s.dbPath}.sig`,
    cleanup: () => fs.rmSync(s.dir, { recursive: true, force: true }) };
}

/** A host with one active, unsigned-development v3 bundle, a policy and an empty witness database. */
export async function v3Host({ tag } = {}) {
  const { stageBundle, activateBundle, bundleFiles, seedsDir } = await import('../../cli/seed-bundle.js');
  const { openWitnessDB } = await import('../../witness/db.js');
  const { home, base } = freshHome(tag);
  const src = v3Source();
  const id = stageBundle({ dbPath: src.db, sha256Path: src.sha }, base, { trust: 'unsigned-development' }).dir_name;
  activateBundle(base, id);
  openWitnessDB(path.join(base, 'witness.db')).applySchema().close();
  fs.writeFileSync(path.join(base, 'config.json'),
    `${JSON.stringify({ config_version: 1, policy: { on_unusable_input: 'BLOCK', on_no_evidence: 'ALLOW' } }, null, 2)}\n`);
  const dir = path.join(seedsDir(base), id);
  return { home, base, id, dir, files: bundleFiles(dir), src,
    cleanup: () => { fs.rmSync(home, { recursive: true, force: true }); src.cleanup(); } };
}

/**
 * Run a Node entry point (or `cmd`) in a child process with a HARD timeout. `timedOut` true means it was still running (for these
 * tests: blocked) when the deadline passed, and was killed.
 */
export function runNode(args, { env = {}, home, timeoutMs = 15000, cwd = ROOT, nodeArgs = [], cmd = process.execPath } = {}) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const childEnv = { ...process.env, ...env };
    if (home) { childEnv.HOME = home; childEnv.USERPROFILE = home; }
    const c = spawn(cmd, [...nodeArgs, ...args], { cwd, env: childEnv, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = ''; let stderr = ''; let timedOut = false;
    c.stdout.on('data', (d) => { stdout += d; }); c.stderr.on('data', (d) => { stderr += d; });
    const timer = setTimeout(() => { timedOut = true; c.kill('SIGKILL'); }, timeoutMs);
    c.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, timedOut, ms: Date.now() - t0, stdout: plain(stdout), stderr: plain(stderr),
        out: plain(stdout + stderr) });
    });
  });
}

/**
 * The real `chaingate` CLI against `base`. Safety net: if the command started a (detached) proxy, it is killed and
 * reported as `spawnedProxy`, so a test that expected a refusal fails loudly instead of leaving a process behind.
 */
export async function runCli(base, args, opts = {}) {
  const pidFile = path.join(base, 'proxy.pid');
  const before = exists(pidFile) ? fs.readFileSync(pidFile, 'utf8').trim() : null;
  const r = await runNode([CLI, ...args],
    { ...opts, env: { CHAINGATE_HOME: base, ...(opts.env || {}) }, home: opts.home ?? path.dirname(base) });
  const after = exists(pidFile) ? fs.readFileSync(pidFile, 'utf8').trim() : null;
  if (after && after !== before && /^\d+$/.test(after)) {
    r.spawnedProxy = Number(after);
    try { process.kill(r.spawnedProxy, 'SIGKILL'); } catch { /* already gone */ }
  }
  return r;
}

/** A free loopback port (bound and released). */
export function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer(); s.unref(); s.on('error', reject);
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}

/** The real proxy entry (`node proxy/server.js`) against `base`; resolves when it exits or is killed. */
export async function runProxyEntry(base, { timeoutMs = 15000, env = {} } = {}) {
  const port = await freePort();
  return runNode([PROXY], { timeoutMs, home: path.dirname(base),
    env: { CHAINGATE_HOME: base, CHAINGATE_WITNESS_DB: path.join(base, 'witness.db'), CHAINGATE_PORT: String(port),
      CHAINGATE_HOST: '127.0.0.1', CHAINGATE_UPSTREAM: 'http://127.0.0.1:9', ...env } });
}

/** A child running `script` (a module under test/helpers) with the read meter; returns its result and the accesses. */
export async function metered(script, args, { timeoutMs = 60000 } = {}) {
  const outFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cg-meter-')), 'accesses.json');
  const r = await runNode([script, ...args], { timeoutMs, nodeArgs: ['--import', METER], env: { U05_READ_METER_OUT: outFile } });
  let accesses = [];
  try { accesses = JSON.parse(fs.readFileSync(outFile, 'utf8')); } catch { /* the child died before writing */ }
  fs.rmSync(path.dirname(outFile), { recursive: true, force: true });
  return { ...r, accesses };
}
