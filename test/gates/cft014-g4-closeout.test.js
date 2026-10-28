// 0.1.4 group 4 — closeout (G4-1..G4-4): T1.1 names the hook command (B1/B18), doctor counts failed checks only (A11), the
// README names both npm approval commands (A12), review-counterexamples leaves no temp folder (A13). Expected results:
// decision tables ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G4-CLOSEOUT-20261012.md, written before this file.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import installIntroduced from '../../gates/install-introduced.js';
import { failedCount } from '../../cli/commands/doctor.js';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const at = (h) => new Date(Date.parse('2026-01-01T00:00:00Z') + h * 3_600_000).toISOString();
const run = (scripts) => installIntroduced.evaluate({ version: '1.1.0', rawVersions: { '1.0.0': {}, '1.1.0': { scripts } },
  rawTimes: { '1.0.0': at(0), '1.1.0': at(48) } });

test('G4-1 (D-C1) the T1.1 detail names each hook and its command, sanitised and capped', () => {
  assert.match(run({ postinstall: 'node lib/setup.mjs' }).detail, /^postinstall \(node lib\/setup\.mjs\) present; no earlier version \(settled 24 h: 1 version\) had an install hook$/);
  assert.match(run({ preinstall: ['a', 'b'] }).detail, /^preinstall \(\[list\]\) present/);
  const long = run({ install: `node ${'x'.repeat(300)}` }).detail;
  assert.ok(long.includes(`install (node ${'x'.repeat(75)}…)`), long);
  const evil = run({ postinstall: 'node a.js\u001b[2J\u202e\u009b\u061c\u200e\u2066\u007f\ufeff\u000d\u000afake' }).detail;
  assert.ok(!/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/.test(evil), JSON.stringify(evil));
  assert.ok(evil.includes('postinstall (node a.js[2Jfake)'), evil);       // control/bidi characters gone; plain text stays
});

test('G4-2 (D-C2) doctor counts failed checks only; skipped checks are never failures', () => {
  const checks = [{ pass: false }, { pass: false, severity: 'unverifiable' },
    { pass: false, severity: 'skipped' }, { pass: true, severity: 'skipped' }, { pass: false, severity: 'skipped' }];
  assert.equal(failedCount(checks), 2);
});

test('G4-3 (D-C3) the README names both npm approval commands with the version they were checked on', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  assert.ok(readme.includes('npm approve-scripts better-sqlite3'));
  assert.ok(readme.includes('npm install-scripts approve better-sqlite3'));
  assert.match(readme, /npm 11\.19\.0/);
});

test('G4-4 (D-C4) review-counterexamples leaves no cft04-cx- folder behind', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g4-'));
  try {
    const r = spawnSync(process.execPath, ['--test', '--test-reporter=tap', path.join(ROOT, 'test/seed-v3/review-counterexamples.test.js')],
      // no NODE_TEST_CONTEXT (node:test would refuse a nested run) and no CFT04_CANDIDATE (the rc3-gated cases are not
      // what this checks, and are slow under a full suite's load)
      { env: (({ NODE_TEST_CONTEXT: _c, CFT04_CANDIDATE: _r, ...rest }) => ({ ...rest, TMPDIR: tmp, TEMP: tmp, TMP: tmp }))(process.env), encoding: 'utf8',
        timeout: 300_000 });
    assert.equal(r.status, 0, String(r.stderr));
    assert.match(String(r.stdout), /# pass [1-9]/, JSON.stringify({ status: r.status, signal: r.signal, error: r.error?.message, stdout: r.stdout, stderr: r.stderr }));
    assert.deepEqual(fs.readdirSync(tmp).filter((n) => n.startsWith('cft04-cx-')), []);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('G4-5 (dated note 1) no literal bidi or invisible format characters in the product source or the 0.1.4 tests (Trojan Source guard)', () => {
  const bad = /[\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/;
  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name))
    : (/\.m?js$/.test(e.name) ? [path.join(dir, e.name)] : [])));   // code only: the JSON test vectors carry them on purpose
  const files = [...['cli', 'proxy', 'gates', 'witness', 'seed', 'patterns'].flatMap((d) => walk(path.join(ROOT, d))),
    ...['constants.js', 'config-store.js'].map((f) => path.join(ROOT, f)).filter((f) => fs.existsSync(f)),
    ...walk(path.join(ROOT, 'test')).filter((f) => path.basename(f).startsWith('cft014-'))];
  const hits = files.filter((f) => bad.test(fs.readFileSync(f, 'utf8'))).map((f) => path.relative(ROOT, f));
  assert.deepEqual(hits, [], 'use \\u escapes, never the literal characters');
});
