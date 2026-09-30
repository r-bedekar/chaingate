// U-05 (0.1.3 cleanup): what doctor, init and self-witness tell a user must be accurate.
//   * doctor shows every skipped check as skipped, so the icons agree with the skipped count;
//   * the legacy seed-signature check names the LEGACY seed, not "--no-seed installs" only;
//   * self-witness says what it compares (npm's recorded integrity vs the witness baseline), that it
//     does not hash installed files, and that normal global installs have nothing to compare;
//   * a v3 init reports the witness database once;
//   * CLI output strings outside the frozen explanation text use plain punctuation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';

import doctor from '../../cli/commands/doctor.js';
import { stageBundle, activateBundle } from '../../cli/seed-bundle.js';
import { openWitnessDB } from '../../witness/db.js';
import { checkSelfWitness, OWN_PACKAGE_NAME } from '../../cli/self-witness.js';
import { classifySelfWitnessSeverity } from '../../cli/commands/doctor.js';
import { buildSyntheticSeed } from '../seed-v3/u01-cases.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

async function capture(fn) {
  const out = []; const l = console.log; const e = console.error;
  console.log = (...a) => out.push(a.join(' ')); console.error = (...a) => out.push(a.join(' '));
  try { return { code: await fn(), out: out.join('\n') }; } finally { console.log = l; console.error = e; }
}
const plain = (s) => s.replace(/\x1b\[[0-9;]*m/g, '');

function host() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'chaingate-u05-'));
  const base = path.join(home, '.chaingate'); fs.mkdirSync(base, { recursive: true });
  const seed = buildSyntheticSeed();
  const id = stageBundle({ dbPath: seed.dbPath, sha256Path: `${seed.dbPath}.sha256` }, base, { trust: 'unsigned-development' }).dir_name;
  activateBundle(base, id);
  openWitnessDB(path.join(base, 'witness.db')).applySchema().close();
  const prev = process.env.CHAINGATE_HOME; process.env.CHAINGATE_HOME = base;
  return { base, cleanup: () => {
    if (prev === undefined) delete process.env.CHAINGATE_HOME; else process.env.CHAINGATE_HOME = prev;
    fs.rmSync(home, { recursive: true, force: true }); fs.rmSync(seed.dir, { recursive: true, force: true });
  } };
}

test('doctor: every check whose severity is skipped is shown as [skipped], matching the JSON', async () => {
  const h = host();
  try {
    const j = await capture(() => doctor(['--json']));
    const checks = JSON.parse(j.out);
    const skipped = checks.filter((c) => c.severity === 'skipped').map((c) => c.name);
    assert.ok(skipped.includes('seed-v3-rollback'), 'a fresh host has no previous bundle: rollback is skipped');
    assert.equal(checks.find((c) => c.name === 'seed-v3-rollback').pass, true, 'JSON fields are unchanged');
    const text = plain((await capture(() => doctor([]))).out);
    for (const name of skipped) assert.match(text, new RegExp(`${name} \\[skipped\\]`), `${name} rendered as skipped`);
    const shown = (text.match(/\[skipped\]/g) || []).length;
    assert.equal(shown, skipped.length, 'as many [skipped] lines as skipped checks');
    const m = text.match(/(\d+) check\(s\) skipped/);
    if (m) assert.equal(Number(m[1]), shown, 'the printed count equals the lines shown');
  } finally { h.cleanup(); }
});

test('doctor: the legacy seed-signature check names the legacy seed and keeps severity skipped', async () => {
  const h = host();
  try {
    const checks = JSON.parse((await capture(() => doctor(['--json']))).out);
    const c = checks.find((x) => x.name === 'seed-signature');
    assert.equal(c.severity, 'skipped');
    assert.equal(c.pass, false);
    assert.match(c.detail, /legacy witness seed/);
    assert.match(c.detail, /v3 seed is reported under seed-v3/);
    const v3 = checks.find((x) => x.name === 'seed-v3');
    assert.match(v3.detail, /trust unsigned-development/, 'the unsigned v3 trust stays explicit');
  } finally { h.cleanup(); }
});

function globalLayout({ withLock }) {
  // npm's global layout: <prefix>/lib/node_modules/@cgsec/chaingate, and NO .package-lock.json
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'chaingate-u05-global-'));
  const nm = path.join(root, 'lib', 'node_modules');
  const pkg = path.join(nm, ...OWN_PACKAGE_NAME.split('/'));
  fs.mkdirSync(path.join(pkg, 'cli'), { recursive: true });
  fs.writeFileSync(path.join(pkg, 'package.json'), JSON.stringify({ name: OWN_PACKAGE_NAME, version: '0.1.3' }));
  fs.writeFileSync(path.join(pkg, 'cli', 'index.js'), '// synthetic');
  const sri = 'sha512-AAAA';
  if (withLock) {
    fs.writeFileSync(path.join(nm, '.package-lock.json'), JSON.stringify({ lockfileVersion: 3,
      packages: { [`node_modules/${OWN_PACKAGE_NAME}`]: { version: '0.1.3', integrity: sri } } }));
  }
  return { url: pathToFileURL(path.join(pkg, 'cli', 'index.js')).href, sri, cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}
const witness = (integrity) => ({
  getBaseline: (n, v) => (integrity ? { version: v, integrity_hash: integrity } : null),
  getHistory: () => (integrity ? [{ version: '0.1.3' }] : []),
});

test('self-witness: a normal global install (no .package-lock.json) is skipped, and says why accurately', () => {
  const g = globalLayout({ withLock: false });
  try {
    const r = checkSelfWitness(witness('sha512-AAAA'), { startFileUrl: g.url });
    assert.equal(r.status, 'unverifiable');
    assert.equal(r.reason, 'lockfile_missing', 'reason code unchanged');
    assert.match(r.detail, /normal for global installs/);
    assert.doesNotMatch(r.detail, /dev install/);
    assert.equal(classifySelfWitnessSeverity(r, true), 'skipped');
  } finally { g.cleanup(); }
});

test('self-witness: a match reports recorded integrity only and does not claim installed files were checked', () => {
  const g = globalLayout({ withLock: true });
  try {
    const r = checkSelfWitness(witness(g.sri), { startFileUrl: g.url });
    assert.equal(r.status, 'verified');
    assert.equal(r.reason, 'integrity_match', 'reason code unchanged');
    assert.match(r.detail, /recorded integrity/);
    assert.match(r.detail, /installed files are not re-hashed/);
    assert.doesNotMatch(r.detail, /seed-recorded/);
  } finally { g.cleanup(); }
});

test('init: a v3 init reports the witness database exactly once (created, or reused)', () => {
  const src = fs.readFileSync(path.join(ROOT, 'cli/commands/init.js'), 'utf8');
  // the v3 branch reports created OR reused; the legacy branch must not add "Existing witness database found"
  assert.match(src, /Using the existing witness database \(writable, separate from the seed\)/);
  const legacy = src.indexOf("console.log(fmt.ok('Existing witness database found'))");
  const guard = src.lastIndexOf('} else if (v3Installed) {', legacy);
  assert.ok(guard > 0 && guard < legacy, 'the legacy "Existing witness database found" line is skipped after a v3 install');
});

test('CLI output strings outside the frozen explanation text use plain punctuation', () => {
  // seed/v3/* (evaluation and explanation text) is pinned by the frozen goldens and is not scanned.
  // The `CACHED — UNBOUND` label is a contract label kept until a change is separately approved.
  const files = ['cli/commands/check.js', 'cli/commands/doctor.js', 'cli/commands/history.js', 'cli/commands/init.js',
    'cli/commands/status.js', 'cli/commands/update-seed.js', 'cli/format.js', 'cli/seed-bundle.js',
    'cli/self-witness.js', 'proxy/server.js'];
  const bad = [];
  for (const f of files) {
    fs.readFileSync(path.join(ROOT, f), 'utf8').split('\n').forEach((line, i) => {
      const t = line.trim();
      if (t.startsWith('//') || t.startsWith('*') || t.startsWith('/*')) return;
      const code = line.replace(/\s\/\/\s.*$/, '');
      if (/[—–…→·]/.test(code)) bad.push(`${f}:${i + 1}: ${t}`);
    });
  }
  assert.deepEqual(bad, []);
});
