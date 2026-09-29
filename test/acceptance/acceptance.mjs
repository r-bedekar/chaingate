#!/usr/bin/env node
// ChainGate public-install acceptance (U-04). Cross-platform: Windows, macOS, Linux.
//
//   node acceptance.mjs --mode standard --launcher global
//   node acceptance.mjs --mode standard --launcher local --package <spec|tarball>
//   options: --fixtures <dir> (default ./fixtures, from make-fixtures.mjs)  --report <file>  --keep
//
// MODES. `standard` is the acceptance run for a normal, NON-elevated account: an elevated (Windows
// administrator / root) account is refused before anything runs. `hosted` is for CI runners, which
// may be elevated (GitHub's Windows runners are); its report says "hosted compatibility", and it is
// not standard-account acceptance. Neither substitutes for the other.
//
// SAFETY. Everything runs in a disposable project folder whose path contains a space and a
// non-ASCII character, with `--scope project`. CHAINGATE_* variables are removed from every process
// it starts, so the user's own ~/.chaingate and ~/.npmrc are never used (it checks that the user
// .npmrc is byte-identical afterwards). It refuses to start if anything is listening on the ChainGate
// port. Every probe has a timeout. The report is saved after every step and on failure or
// interruption, and the run always stops the proxy it started (by the disposable project's pid file)
// and removes its folder unless --keep.
import { spawnSync, execSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import net from 'node:net';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WIN = process.platform === 'win32';
const argv = process.argv.slice(2);
const opt = (name, dflt) => { const i = argv.indexOf(`--${name}`); return i >= 0 ? argv[i + 1] : dflt; };
const MODE = opt('mode', 'standard');
const LAUNCHER_MODE = opt('launcher', 'global');
const PACKAGE = opt('package', '@cgsec/chaingate');
const KEEP = argv.includes('--keep');
const FIX = path.resolve(opt('fixtures', path.join(HERE, 'fixtures')));
const REPORT = path.resolve(opt('report', path.join(HERE, 'acceptance-report.json')));
const PORT = 6173;
const CMD_TIMEOUT_MS = 180_000;
const PROBE_TIMEOUT_MS = 3_000;

if (!['standard', 'hosted'].includes(MODE) || !['global', 'local'].includes(LAUNCHER_MODE)) {
  console.error('usage: node acceptance.mjs --mode standard|hosted --launcher global|local [--package <spec>]');
  process.exit(2);
}

// Child environment: no CHAINGATE_* variable may redirect the run to the user's real directories.
const CHILD_ENV = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^CHAINGATE_/i.test(k)));
const strippedVars = Object.keys(process.env).filter((k) => /^CHAINGATE_/i.test(k));

const results = [];
const report = { started: new Date().toISOString(), mode: MODE,
  label: MODE === 'standard' ? 'standard-account acceptance' : 'hosted compatibility (may be elevated; NOT standard-account acceptance)',
  launcher_mode: LAUNCHER_MODE, package: PACKAGE, env: {}, results, finished: null, summary: null, aborted: null };
function save() {
  try {
    report.summary = { pass: results.filter((r) => r.ok === true).length, fail: results.filter((r) => r.ok === false).length };
    const tmp = `${REPORT}.tmp-${process.pid}`;
    fs.writeFileSync(tmp, JSON.stringify(report, null, 2)); fs.renameSync(tmp, REPORT);
  } catch (e) { console.error(`could not save the report: ${e.message}`); }
}
function record(step, ok, detail = '', extra = {}) {
  results.push({ step, ok: ok === null ? null : Boolean(ok), detail: String(detail).slice(0, 600), at: new Date().toISOString(), ...extra });
  const mark = ok === null ? 'INFO' : ok ? 'PASS' : 'FAIL';
  console.log(`${mark.padEnd(4)}  ${step}${detail ? `  -- ${String(detail).split('\n')[0].slice(0, 160)}` : ''}`);
  save();
}
const sh = (cmd) => { try { return execSync(cmd, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: CHILD_ENV, timeout: 60_000 }).trim(); } catch (e) { return `ERR ${e.status}: ${(e.stderr || e.message || '').toString().trim().split('\n')[0]}`; } };
const sha = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const q = (s) => `"${String(s).replace(/"/g, '\\"')}"`;

function portOpen(port) {   // true if ANYTHING accepts a TCP connection on 127.0.0.1:port
  return new Promise((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port });
    const done = (v) => { s.destroy(); resolve(v); };
    s.setTimeout(PROBE_TIMEOUT_MS, () => done(false));
    s.once('connect', () => done(true));
    s.once('error', () => done(false));
  });
}
async function self() {
  try { const r = await fetch(`http://127.0.0.1:${PORT}/_chaingate/self`, { signal: AbortSignal.timeout(PROBE_TIMEOUT_MS) }); return r.ok ? await r.json() : null; }
  catch { return null; }
}

let root = null; let proj = null; let launcher = null;
function cg(args, { timeout = CMD_TIMEOUT_MS } = {}) {
  const r = WIN
    ? spawnSync([q(launcher), ...args.map(q)].join(' '), { cwd: proj, encoding: 'utf8', shell: true, timeout, env: CHILD_ENV })
    : spawnSync(launcher, args, { cwd: proj, encoding: 'utf8', timeout, env: CHILD_ENV });
  const timedOut = r.error?.code === 'ETIMEDOUT';
  return { status: timedOut ? 'timeout' : r.status, out: `${r.stdout ?? ''}${r.stderr ?? ''}${timedOut ? `\n[timed out after ${timeout} ms]` : ''}`.trim(), stdout: r.stdout ?? '' };
}
const P = ['--scope', 'project'];

let cleaned = false;
function cleanup() {
  if (cleaned) return; cleaned = true;
  try {
    if (proj && launcher && fs.existsSync(path.join(proj, '.chaingate'))) cg(['stop', ...P], { timeout: 60_000 });
    const pidFile = proj && path.join(proj, '.chaingate', 'proxy.pid');
    if (pidFile && fs.existsSync(pidFile)) {   // only the proxy of THIS disposable project
      const pid = Number(fs.readFileSync(pidFile, 'utf8').trim());
      if (pid > 0) { try { process.kill(pid, 0); process.kill(pid); record('cleanup: stopped a leftover proxy of this run', null, `pid ${pid}`); } catch { /* already gone */ } }
    }
  } catch (e) { record('cleanup error', false, e.message); }
  if (root && !KEEP) { try { fs.rmSync(root, { recursive: true, force: true }); } catch (e) { record('cleanup: could not remove the disposable folder', false, `${root}: ${e.message}`); } }
  report.finished = new Date().toISOString();
  save();
}
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => { report.aborted = `interrupted by ${sig}`; record('run interrupted', false, sig); cleanup(); process.exit(130); });
}

async function main() {
  // ── environment ─────────────────────────────────────────────────────────────────────────────────
  report.env = {
    platform: process.platform, arch: process.arch, os_release: os.release(), os_version: os.version?.() ?? null,
    node: process.version, npm: sh('npm -v'),
    npm_has_allow_scripts: sh('npm config get allow-scripts') !== 'undefined',
    elevated: WIN ? (spawnSync('net', ['session'], { stdio: 'ignore', timeout: 30_000 }).status === 0) : (process.getuid?.() === 0),
    developer_mode: WIN ? /0x1/.test(sh('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock" /v AllowDevelopmentWithoutDevLicense')) : null,
    chaingate_vars_stripped: strippedVars,
  };
  record('environment', null, JSON.stringify(report.env));
  if (MODE === 'standard') {
    if (report.env.elevated) {
      record('standard mode: account is NOT elevated', false, 'this account is elevated (administrator/root); standard-account acceptance refused. Re-run from a normal account.');
      report.aborted = 'elevated account in standard mode'; return;
    }
    record('standard mode: account is NOT elevated', true);
  } else {
    record('hosted mode: elevation recorded (compatibility run, not standard-account acceptance)', null, `elevated: ${report.env.elevated}`);
  }

  // ── refuse an occupied port (anything listening, not only ChainGate) ───────────────────────────
  if (await portOpen(PORT)) {
    record(`port ${PORT} is free`, false, 'something is listening on 127.0.0.1:6173; stop it and re-run (nothing was changed)');
    report.aborted = 'port occupied'; return;
  }
  record(`port ${PORT} is free`, true);

  // ── filesystem primitives seed activation relies on (information only) ────────────────────────
  {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'chaingate fsprobe zoë '));
    const res = {};
    const tryIt = (k, fn) => { try { fn(); res[k] = 'ok'; } catch (e) { res[k] = `${e.code || e.name}: ${e.message.split('\n')[0]}`; } };
    fs.mkdirSync(path.join(d, 'bundle-1')); fs.mkdirSync(path.join(d, 'bundle-2'));
    tryIt('symlink_dir_relative', () => fs.symlinkSync('bundle-1', path.join(d, 'active')));
    tryIt('symlink_tmp_then_rename_over_existing', () => { fs.symlinkSync('bundle-2', path.join(d, 'active.tmp')); fs.renameSync(path.join(d, 'active.tmp'), path.join(d, 'active')); });
    tryIt('readlink_after_swap', () => { const t = fs.readlinkSync(path.join(d, 'active')); if (!/bundle-2$/.test(t)) throw new Error(`points at ${t}`); });
    tryIt('junction_absolute', () => fs.symlinkSync(path.join(d, 'bundle-1'), path.join(d, 'junction'), 'junction'));
    fs.rmSync(d, { recursive: true, force: true });
    report.fs_primitives = res;
    record('filesystem primitives (information for the activation design)', null, JSON.stringify(res));
  }

  // ── disposable project folder (space + non-ASCII) ──────────────────────────────────────────────
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'chaingate accept zoë '));
  proj = path.join(root, 'project'); fs.mkdirSync(proj);
  report.project = proj;
  record('disposable project path contains a space and a non-ASCII character', /\s/.test(proj) && /[^\x00-\x7f]/.test(proj), proj);

  // ── the launcher ───────────────────────────────────────────────────────────────────────────────
  if (LAUNCHER_MODE === 'local') {
    // Project installs approve install scripts in package.json (`allowScripts`); npm rejects
    // --allow-scripts on the command line for project installs. Older npm ignores the field.
    fs.writeFileSync(path.join(proj, 'package.json'), JSON.stringify({ name: 'chaingate-accept', private: true,
      allowScripts: { 'better-sqlite3': true } }, null, 2));
    const inst = WIN
      ? spawnSync(`npm install ${q(PACKAGE)} --no-audit --no-fund`, { cwd: proj, encoding: 'utf8', shell: true, timeout: 600_000, env: CHILD_ENV })
      : spawnSync('npm', ['install', PACKAGE, '--no-audit', '--no-fund'], { cwd: proj, encoding: 'utf8', timeout: 600_000, env: CHILD_ENV });
    record('project install (allowScripts approves only better-sqlite3)', inst.status === 0, (`${inst.stdout ?? ''}${inst.stderr ?? ''}`).trim().split('\n').slice(-3).join(' | '));
    launcher = path.join(proj, 'node_modules', '.bin', WIN ? 'chaingate.cmd' : 'chaingate');
  } else {
    const prefix = sh('npm prefix -g');
    launcher = WIN ? path.join(prefix, 'chaingate.cmd') : path.join(prefix, 'bin', 'chaingate');
  }
  if (!fs.existsSync(launcher)) { record('normal CLI launcher present', false, launcher); report.aborted = 'no launcher'; return; }
  record('normal CLI launcher present', true, launcher);

  const cases = JSON.parse(fs.readFileSync(path.join(FIX, 'cases.json'), 'utf8'));
  const seed = (n) => path.join(FIX, `seed-${n}`, 'chaingate-seed.db');
  const seedsDir = () => path.join(proj, '.chaingate', 'seeds');

  const v = cg(['--version']);
  record('chaingate --version', v.status === 0, v.out);

  const userNpmrc = sh('npm config get userconfig');
  const userNpmrcBefore = fs.existsSync(userNpmrc) ? sha(userNpmrc) : 'absent';
  const eol = WIN ? '\r\n' : '\n';
  const projNpmrcOriginal = ['; unrelated settings kept by ChainGate', '//registry.npmjs.org/:_authToken=npm_EXAMPLEONLY', '@corp:registry=https://npm.corp.example/', 'save-exact=true'].join(eol) + eol;
  fs.writeFileSync(path.join(proj, '.npmrc'), projNpmrcOriginal);

  const d0 = cg(['doctor', ...P, '--json']);
  let native = null; try { native = JSON.parse(d0.stdout).find((c) => c.name === 'native-sqlite'); } catch { /* older CLI */ }
  record('native SQLite module loads (doctor native-sqlite)', native ? native.pass : null, native ? native.detail : 'check not reported by this version');

  // ── import, activate, start ────────────────────────────────────────────────────────────────────
  const init = cg(['init', ...P, '--seed', seed('A'), '--unsigned-development']);
  let activeKind = 'absent';
  try { const l = fs.lstatSync(path.join(seedsDir(), 'active')); activeKind = l.isSymbolicLink() ? 'symlink' : l.isDirectory() ? 'directory' : 'other'; } catch { /* absent */ }
  record('seed A imported and activated (activation link created)', activeKind !== 'absent', `active: ${activeKind}; init exit ${init.status}: ${init.out.split('\n').slice(-3).join(' | ')}`);
  record('init --seed A --unsigned-development (import + activate + start proxy)', init.status === 0, init.out.split('\n').slice(-6).join(' | '));
  const s = await self();
  record('proxy started and reports seed A', s?.seed_v3?.sha256 === cases.seedA_sha256, JSON.stringify(s?.seed_v3 ?? s));
  if (init.status !== 0 || !s) { report.aborted = 'init did not start a working proxy; later steps depend on it'; return; }

  // ── status, doctor ─────────────────────────────────────────────────────────────────────────────
  const st = cg(['status', ...P, '--json']);
  let stj = null; try { stj = JSON.parse(st.stdout); } catch { /* older CLI */ }
  record('status reports the active v3 seed', st.status === 0 && (stj?.seed_v3 ? stj.seed_v3.active === true && stj.seed_v3.sha256 === cases.seedA_sha256 : null),
    stj?.seed_v3 ? JSON.stringify(stj.seed_v3).slice(0, 200) : `exit ${st.status} (no seed_v3 field in this version)`);
  const doc = cg(['doctor', ...P, '--json']);
  let checks = []; try { checks = JSON.parse(doc.stdout); } catch { /* reported */ }
  const need = ['seed-v3', 'proxy-pid', 'proxy-port', 'npmrc-block'];
  const bad = need.filter((n) => !checks.find((c) => c.name === n)?.pass);
  record('doctor: seed-v3, proxy-pid, proxy-port, npmrc-block pass', checks.length > 0 && bad.length === 0, bad.length ? `failing: ${bad}` : `exit ${doc.status}`);
  const rcDuring = fs.readFileSync(path.join(proj, '.npmrc'), 'utf8');
  record('project .npmrc keeps every unrelated line verbatim while ChainGate runs',
    projNpmrcOriginal.split(eol).filter(Boolean).every((l) => rcDuring.includes(l + eol)) && /registry=http:\/\/127\.0\.0\.1:6173/.test(rcDuring));

  // ── fresh check / why ──────────────────────────────────────────────────────────────────────────
  for (const c of cases.cases) {
    const r = cg(['check', `${c.package}@${c.version}`, '--packument', path.join(FIX, c.packument), '--json', ...P]);
    let rec = null; try { rec = JSON.parse(r.stdout); } catch { /* reported */ }
    record(`check ${c.id}: ${c.effective}, exit ${c.exit}`, r.status === c.exit && rec?.result === 'evaluated' && rec?.effective?.action === c.effective,
      `exit ${r.status}, result ${rec?.result}, effective ${rec?.effective?.action}`);
    const w = cg(['why', `${c.package}@${c.version}`, '--packument', path.join(FIX, c.packument), ...P]);
    record(`why ${c.id}`, [0, 2, 3].includes(w.status) && w.out.includes(`${c.package}@${c.version}`), `exit ${w.status}`);
  }

  // ── stop / restart, update, rollback ───────────────────────────────────────────────────────────
  async function restart(label, want) {
    const a = cg(['stop', ...P]); const b = cg(['init', ...P]); const r = await self();
    record(`${label}: stop + restart`, a.status === 0 && b.status === 0 && (want ? r?.seed_v3?.sha256 === want : true),
      `stop ${a.status}, init ${b.status}, seed ${r?.seed_v3?.sha256?.slice(0, 12) ?? 'none'}`);
  }
  await restart('restart on seed A', cases.seedA_sha256);
  const up = cg(['update-seed', ...P, '--seed', seed('B'), '--unsigned-development']);
  record('update-seed --seed B', up.status === 0, up.out.split('\n').slice(-3).join(' | '));
  await restart('restart on seed B', cases.seedB_sha256);
  const rb = cg(['update-seed', ...P, '--rollback']);
  record('update-seed --rollback', rb.status === 0, rb.out.split('\n').slice(-3).join(' | '));
  await restart('restart after rollback (seed A)', cases.seedA_sha256);

  // ── failed update keeps the previous seed ──────────────────────────────────────────────────────
  const badUp = cg(['update-seed', ...P, '--seed', seed('BAD'), '--unsigned-development']);
  record('update with a seed whose digest does not match is REFUSED', badUp.status !== 0, `exit ${badUp.status}: ${badUp.out.split('\n')[0]}`);
  await restart('previous seed A still active and usable after the refused update', cases.seedA_sha256);

  // ── interrupted activation leftovers ───────────────────────────────────────────────────────────
  const stale = path.join(seedsDir(), 'active.switching-424242');
  try { fs.writeFileSync(stale, 'leftover from an interrupted switch'); } catch (e) { record('create interrupted-switch leftover', false, e.message); }
  await restart('restart with an interrupted-switch leftover present', cases.seedA_sha256);
  fs.rmSync(stale, { force: true });

  // ── broken activation fails closed ─────────────────────────────────────────────────────────────
  cg(['stop', ...P]);
  let activeId = null;
  try { activeId = path.basename(fs.realpathSync(path.join(seedsDir(), 'active'))); } catch (e) { record('resolve the active bundle', false, e.message); }
  if (activeId) {
    const moved = path.join(seedsDir(), `${activeId}.moved-aside`);
    fs.renameSync(path.join(seedsDir(), activeId), moved);
    try {
      const bi = cg(['init', ...P]);
      const bs = await self();
      record('broken activation (bundle missing): init REFUSES, no proxy runs without its seed', bi.status !== 0 && bs === null, `init exit ${bi.status}`);
      const bd = cg(['doctor', ...P, '--json']);
      let sv = null; let json = false; try { sv = JSON.parse(bd.stdout).find((c) => c.name === 'seed-v3'); json = true; } catch { /* not JSON */ }
      record('broken activation: doctor --json returns valid JSON with a FAILED seed-v3 check (never "no seed")',
        bd.status !== 0 && json && sv && sv.pass === false && /does not resolve/.test(sv.detail) && !/no v3 bundle active/.test(sv.detail),
        json ? `exit ${bd.status}; seed-v3: ${sv?.detail}` : `exit ${bd.status}; output was not JSON: ${bd.out.split('\n')[0].slice(0, 120)}`);
      const bst = cg(['status', ...P]);
      record('broken activation: status says BROKEN and exits non-zero', bst.status !== 0 && /BROKEN/.test(bst.out), `exit ${bst.status}`);
    } finally {
      fs.renameSync(moved, path.join(seedsDir(), activeId));
    }
    await restart('recovered after the bundle is restored', cases.seedA_sha256);
  }

  // ── stop, and configuration preserved ──────────────────────────────────────────────────────────
  const fin = cg(['stop', ...P]);
  record('final stop, and nothing listens on the port', fin.status === 0 && !(await portOpen(PORT)), fin.out.split('\n').join(' | '));
  record('project .npmrc byte-identical after stop', fs.readFileSync(path.join(proj, '.npmrc'), 'utf8') === projNpmrcOriginal);
  record('user .npmrc untouched', (fs.existsSync(userNpmrc) ? sha(userNpmrc) : 'absent') === userNpmrcBefore, userNpmrc);
}

try {
  await main();
} catch (e) {
  report.aborted = `harness error: ${e.message}`;
  record('harness error', false, e.stack || e.message);
} finally {
  cleanup();
  const failed = results.filter((r) => r.ok === false).length;
  console.log(`\n[${report.label}] ${report.summary.pass} passed, ${report.summary.fail} failed${report.aborted ? ` (stopped: ${report.aborted})` : ''}. Report: ${REPORT}`);
  process.exitCode = failed || report.aborted ? 1 : 0;
}
