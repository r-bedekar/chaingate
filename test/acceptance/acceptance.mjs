#!/usr/bin/env node
// ChainGate public-install acceptance (U-04). Cross-platform: Windows, macOS, Linux.
//
//   node acceptance.mjs --mode standard --launcher global
//   node acceptance.mjs --mode standard --launcher local --package <spec|tarball>
//   options: --fixtures <dir> (default ./fixtures, from make-fixtures.mjs)  --report <file>  --keep
//            --project-approval before|after   (local only: allowScripts written before `npm install`, or
//            the install first and then `npm approve-scripts better-sqlite3` + `npm rebuild better-sqlite3`)
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
const APPROVAL = opt('project-approval', 'before');
const KEEP = argv.includes('--keep');
const FIX = path.resolve(opt('fixtures', path.join(HERE, 'fixtures')));
const REPORT = path.resolve(opt('report', path.join(HERE, 'acceptance-report.json')));
const PORT = 6173;
const CMD_TIMEOUT_MS = 180_000;
const PROBE_TIMEOUT_MS = 3_000;

if (!['standard', 'hosted'].includes(MODE) || !['global', 'local'].includes(LAUNCHER_MODE) || !['before', 'after'].includes(APPROVAL)) {
  console.error('usage: node acceptance.mjs --mode standard|hosted --launcher global|local [--package <spec>]');
  process.exit(2);
}

// Child environment: no CHAINGATE_* variable may redirect the run to the user's real directories.
const CHILD_ENV = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^CHAINGATE_/i.test(k)));
const strippedVars = Object.keys(process.env).filter((k) => /^CHAINGATE_/i.test(k));

const results = [];
const report = { started: new Date().toISOString(), mode: MODE,
  label: MODE === 'standard' ? 'standard-account acceptance' : 'hosted compatibility (may be elevated; NOT standard-account acceptance)',
  launcher_mode: LAUNCHER_MODE, project_approval: LAUNCHER_MODE === 'local' ? APPROVAL : null, package: PACKAGE, env: {}, results, finished: null, summary: null, aborted: null };
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
    const npmIn = (args) => (WIN
      ? spawnSync(`npm ${args.map(q).join(' ')}`, { cwd: proj, encoding: 'utf8', shell: true, timeout: 600_000, env: CHILD_ENV })
      : spawnSync('npm', args, { cwd: proj, encoding: 'utf8', timeout: 600_000, env: CHILD_ENV }));
    const tail = (r) => (`${r.stdout ?? ''}${r.stderr ?? ''}`).trim().split('\n').slice(-3).join(' | ');
    const pkg = { name: 'chaingate-accept', private: true };
    if (APPROVAL === 'before') pkg.allowScripts = { 'better-sqlite3': true };
    fs.writeFileSync(path.join(proj, 'package.json'), JSON.stringify(pkg, null, 2));
    const inst = npmIn(['install', PACKAGE, '--no-audit', '--no-fund']);
    record(`project install (approval ${APPROVAL} install)`, inst.status === 0, tail(inst));
    const own = `${inst.stdout || ''}${inst.stderr || ''}`.split(/\r?\n/).filter((l) => /install-scripts/.test(l) && l.includes('@cgsec/chaingate'));
    record('npm does not list an install script of @cgsec/chaingate itself', own.length === 0, own.join(' | '));
    launcher = path.join(proj, 'node_modules', '.bin', WIN ? 'chaingate.cmd' : 'chaingate');
    if (APPROVAL === 'after') {
      const probe = spawnSync(process.execPath, ['-e', "new (require('better-sqlite3'))(':memory:').close()"], { cwd: proj, encoding: 'utf8', env: CHILD_ENV, timeout: 60_000 });
      const blocked = probe.status !== 0;
      record('install scripts before approval', null, blocked ? 'better-sqlite3 native part NOT built (npm blocked the script)' : 'built (this npm ran the script without approval)');
      if (blocked && fs.existsSync(launcher)) {
        const dg = cg(['doctor', ...P, '--json']);
        let nc = null; try { nc = JSON.parse(dg.stdout).find((c) => c.name === 'native-sqlite'); } catch { /* */ }
        record('doctor reports the missing native module before approval', nc && nc.pass === false, nc ? nc.detail : `doctor exit ${dg.status}`);
      }
      const hasApprove = npmIn(['approve-scripts', '--allow-scripts-pending']).status === 0;
      if (hasApprove) {
        const ap = npmIn(['approve-scripts', 'better-sqlite3']);
        record('npm approve-scripts better-sqlite3', ap.status === 0, tail(ap));
        let allow = null; try { allow = JSON.parse(fs.readFileSync(path.join(proj, 'package.json'), 'utf8')).allowScripts; } catch { /* */ }
        record('allowScripts now names only better-sqlite3', allow && Object.keys(allow).length === 1 && /^better-sqlite3(@|$)/.test(Object.keys(allow)[0]), JSON.stringify(allow));
        const rb = npmIn(['rebuild', 'better-sqlite3']);
        record('npm rebuild better-sqlite3', rb.status === 0, tail(rb));
      } else {
        record('npm approve-scripts', null, 'not available in this npm (it runs install scripts without approval)');
      }
    }
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

  // The activation record: seeds/activation.json on Windows (0.1.2+), the seeds/active symlink elsewhere.
  const activeRecord = () => {
    try { const j = JSON.parse(fs.readFileSync(path.join(seedsDir(), 'activation.json'), 'utf8')); return { kind: 'activation.json', id: j.active }; } catch { /* none */ }
    try { const l = fs.lstatSync(path.join(seedsDir(), 'active'));
      return { kind: l.isSymbolicLink() ? 'symlink' : l.isDirectory() ? 'directory' : 'other', id: path.basename(fs.realpathSync(path.join(seedsDir(), 'active'))) }; } catch { /* absent or dangling */ }
    return { kind: 'absent', id: null };
  };

  // ── onboarding from an archive (U-05 S6, option M; SEEDS.md "Verify the download") ────────────
  // Two digests: the ARCHIVE's (the download arrived intact) and the DATABASE's (the content). The extracted database is
  // checked against the TRUSTED database digest before anything is imported; the .sha256 file inside the same archive
  // comes from the same place as the database and proves nothing on its own. Fixtures from before 0.1.3 have no archives.
  let seedA = seed('A');
  if (cases.archives) {
    // The archive is copied in and extracted by its RELATIVE name: GNU tar (Git Bash on Windows) reads `D:\...` as a
    // remote host; bsdtar (Windows, macOS) and GNU tar (Linux) both accept this form.
    const unpack = (name) => {
      const d = path.join(proj, `unpacked-${name}`); fs.mkdirSync(d, { recursive: true });
      fs.copyFileSync(path.join(FIX, cases.archives[name]), path.join(d, cases.archives[name]));
      const r = spawnSync('tar', ['-xzf', cases.archives[name]], { encoding: 'utf8', timeout: 120_000, cwd: d });
      return { ok: r.status === 0, db: path.join(d, 'chaingate-seed.db'), err: `${r.stderr || r.error || ''}`.trim() };
    };
    const archiveA = path.join(FIX, cases.archives.A);
    record('archive: the download matches the recorded ARCHIVE SHA-256', sha(archiveA) === cases.archiveA_sha256, cases.archiveA_sha256.slice(0, 16));
    const tampered = path.join(proj, 'tampered.tar.gz');
    const tb = fs.readFileSync(archiveA); tb[tb.length >> 1] ^= 0xff; fs.writeFileSync(tampered, tb);
    record('archive: a tampered archive fails the archive SHA-256 (stop before extracting)', sha(tampered) !== cases.archiveA_sha256, '');
    const ua = unpack('A');
    const dbOk = ua.ok && sha(ua.db) === cases.seedA_sha256;
    const sidecarOk = ua.ok && fs.readFileSync(`${ua.db}.sha256`, 'utf8').trim() === cases.seedA_sha256;
    record('archive: extracted; the database matches the TRUSTED DATABASE SHA-256, and its .sha256 file agrees', dbOk && sidecarOk, ua.err);
    const us = unpack('SUBST');
    const selfConsistent = us.ok && fs.readFileSync(`${us.db}.sha256`, 'utf8').trim() === sha(us.db);
    record('archive: a substituted archive is self-consistent (its own .sha256 matches) yet FAILS the trusted database SHA-256: stop before init',
      selfConsistent && sha(us.db) !== cases.seedA_sha256, us.err);
    if (dbOk && sidecarOk) seedA = ua.db;
    report.seed_from_archive = seedA !== seed('A');
  }

  // ── import, activate, start ────────────────────────────────────────────────────────────────────
  const npmrcNow = () => fs.readFileSync(path.join(proj, '.npmrc'), 'utf8');
  const unflagged = cg(['init', ...P, '--seed', seedA]);
  record('init --seed WITHOUT --unsigned-development refuses the unsigned seed: nothing activated, .npmrc untouched, no proxy',
    unflagged.status !== 0 && activeRecord().kind === 'absent' && npmrcNow() === projNpmrcOriginal && (await self()) === null,
    `exit ${unflagged.status}: ${unflagged.out.split('\n').slice(-2).join(' | ')}`);
  const init = cg(['init', ...P, '--seed', seedA, '--unsigned-development']);
  const activeKind = activeRecord().kind;
  report.activation_record = activeKind;
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
  const stales = [path.join(seedsDir(), 'active.switching-424242'), path.join(seedsDir(), 'activation.json.tmp-424242')];
  for (const stale of stales) {
    try { fs.writeFileSync(stale, '{"leftover from an interrupted switch'); } catch (e) { record('create interrupted-switch leftover', false, e.message); }
  }
  await restart('restart with interrupted-switch leftovers present (symlink and record temporaries)', cases.seedA_sha256);
  for (const stale of stales) fs.rmSync(stale, { force: true });

  // ── broken activation fails closed ─────────────────────────────────────────────────────────────
  cg(['stop', ...P]);
  const activeId = activeRecord().id;
  if (!activeId) record('resolve the active bundle', false, 'no activation record found');
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
