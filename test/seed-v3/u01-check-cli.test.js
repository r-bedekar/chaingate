// U-01 A5/A6/A8/A10 — `chaingate check` and `chaingate why` through the real CLI, in an isolated
// HOME with a staged and activated synthetic bundle, every process under the network guard.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { stageBundle, activateBundle } from '../../cli/seed-bundle.js';
import { writeConfig } from '../../config-store.js';
import { openWitnessDB } from '../../witness/db.js';
import { explain } from '../../seed/v3/explain.js';
import { syntheticCases, buildSyntheticSeed, PROXY_POLICY } from './u01-cases.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..', '..');
const CLI = path.join(ROOT, 'cli', 'index.js');
// --import takes a URL: an absolute Windows path (D:\\...) is not one.
const GUARD = pathToFileURL(path.join(ROOT, 'test', 'helpers', 'deny-network.mjs')).href;
const GOLD = JSON.parse(fs.readFileSync(path.join(ROOT, 'test', 'fixtures', 'u01-goldens', 'synthetic.json'), 'utf8'));
const CASES = new Map(syntheticCases().map((c) => [c.id, c]));
const EXIT = { ALLOW: 0, WARN: 2, BLOCK: 3 };

const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'u01-cli-'));
const NET_LOG = path.join(WORK, 'network-attempts.log');
test.after(() => fs.rmSync(WORK, { recursive: true, force: true }));

/** A host: HOME with an active synthetic bundle and the demo policy recorded, as `init` leaves it. */
function makeHost(name, { policy = PROXY_POLICY, bundle = true } = {}) {
  const home = path.join(WORK, name);
  const base = path.join(home, '.chaingate');
  fs.mkdirSync(base, { recursive: true });
  if (bundle) {
    const { dir, dbPath } = buildSyntheticSeed();
    const staged = stageBundle({ dbPath, sha256Path: `${dbPath}.sha256` }, base, { trust: 'unsigned-development' });
    activateBundle(base, staged.dir_name);
    fs.rmSync(dir, { recursive: true, force: true });
  }
  writeConfig(path.join(base, 'config.json'), { policy });
  return { home, base, witness: path.join(base, 'witness.db') };
}

function witnessWith(host, { decisions = [], overrides = [] } = {}) {
  const db = openWitnessDB(host.witness).applySchema();
  try {
    for (const [p, v, disp] of decisions) {
      db.db.prepare('INSERT INTO gate_decisions (package_name, version, disposition, gates_fired) VALUES (?,?,?,?)')
        .run(p, v, disp, JSON.stringify([{ gate: 'legacy', result: disp, detail: 'stored long ago' }]));
    }
    for (const [p, v, reason] of overrides) db.insertOverride(p, v, reason);
  } finally { db.close(); }
}

function cleanEnv(home, extra = {}) {
  // USERPROFILE too: on Windows os.homedir() follows it, not HOME.
  const env = { PATH: process.env.PATH, HOME: home, USERPROFILE: home, NO_COLOR: '1', U01_NET_LOG: NET_LOG,
    ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}), ...extra };
  for (const k of Object.keys(env)) if (k.startsWith('CHAINGATE_')) delete env[k];
  return env;
}

function cli(host, args, extra = {}) {
  const r = spawnSync(process.execPath, ['--import', GUARD, CLI, ...args],
    { env: cleanEnv(host.home, extra), encoding: 'utf8', cwd: WORK, timeout: 60000 });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

function packumentFile(id) {
  const file = path.join(WORK, `${id.replace(/[^a-z0-9-]/gi, '_')}.json`);
  fs.writeFileSync(file, JSON.stringify(CASES.get(id).doc));
  return file;
}

const HOST = makeHost('host');
const target = (id) => `${CASES.get(id).doc.name}@${CASES.get(id).version}`;
const checkJson = (host, id, extra) => {
  const r = cli(host, ['check', target(id), '--packument', packumentFile(id), '--json'], extra);
  return { ...r, rec: r.stdout ? JSON.parse(r.stdout) : null };
};

// --- every synthetic golden through the real binary ---------------------------------------------------
test('check CLI: every PROXY_POLICY synthetic golden, exit code follows the disposition', () => {
  let n = 0;
  for (const g of GOLD.records.filter((r) => r.policy.on_unusable_input === 'BLOCK')) {
    const { status, rec } = checkJson(HOST, g.id);
    assert.equal(status, EXIT[g.decision.disposition], `${g.id}: exit`);
    assert.equal(rec.decision.disposition, g.decision.disposition, g.id);
    assert.deepEqual(rec.decision.results, g.decision.results, g.id);
    assert.deepEqual(rec.decision.not_evaluated, g.decision.not_evaluated, g.id);
    if (rec.result === 'evaluated') assert.equal(rec.candidate.placement.kind, g.decision.placement, g.id);
    assert.equal(rec.request.source.kind, 'packument-file');
    assert.equal(rec.request.source.sha256.length, 64);
    assert.equal(rec.seed.trust, 'unsigned-development');
    assert.equal(rec.seed.authenticated, false);
    assert.match(rec.seed.bundle_id, /^[0-9a-f]{16}$/);
    n++;
  }
  assert.ok(n >= 20);
});

// --- A5 ------------------------------------------------------------------------------------------------
test('A5 a CONFLICTING stored witness decision is ignored: only the fresh evaluation is reported', () => {
  const host = makeHost('conflict');
  witnessWith(host, { decisions: [['p', '1.3.0', 'ALLOW'], ['p', '1.5.0', 'BLOCK']] });
  const blocked = checkJson(host, 'pin-block-append');          // stored ALLOW, fresh BLOCK (pin)
  assert.equal(blocked.status, 3);
  assert.equal(blocked.rec.decision.disposition, 'BLOCK');
  const allowed = checkJson(host, 'allow-append');              // stored BLOCK, fresh ALLOW
  assert.equal(allowed.status, 0);
  assert.equal(allowed.rec.decision.disposition, 'ALLOW');
  for (const r of [blocked, allowed]) {
    assert.ok(!/decided_at|stored long ago|legacy/.test(r.stdout), 'nothing from the stored row appears');
  }
});

test('A5 check works with an empty witness DB and with none at all', () => {
  const empty = makeHost('empty-witness');
  witnessWith(empty);
  assert.equal(checkJson(empty, 'allow-append').status, 0);
  const none = makeHost('no-witness');
  assert.equal(fs.existsSync(none.witness), false);
  assert.equal(checkJson(none, 'allow-append').status, 0);
});

test('A5 no --packument is a usage error, exit 4, nothing on stdout', () => {
  const r = cli(HOST, ['check', 'p@1.3.0']);
  assert.equal(r.status, 4);
  assert.equal(r.stdout, '');
  assert.match(r.stderr, /--packument <file> is required/);
  assert.equal(cli(HOST, ['check', 'p@1.3.0', '--json']).status, 4);
  assert.equal(cli(HOST, ['check']).status, 4);
});

test('tool errors carry only the error member, exit 4', () => {
  const missing = cli(HOST, ['check', 'p@1.3.0', '--packument', path.join(WORK, 'nope.json'), '--json']);
  assert.equal(missing.status, 4);
  const rec = JSON.parse(missing.stdout);
  assert.deepEqual(Object.keys(rec), ['schema', 'result', 'tool', 'request', 'error']);
  assert.equal(rec.result, 'tool_error');
  assert.equal(rec.error.code, 'packument_unreadable');

  const mismatch = cli(HOST, ['check', 'other@1.3.0', '--packument', packumentFile('pin-block-append'), '--json']);
  assert.equal(mismatch.status, 4);
  assert.equal(JSON.parse(mismatch.stdout).error.code, 'packument_name_mismatch');

  const bare = makeHost('no-bundle', { bundle: false });
  const nobundle = checkJson(bare, 'allow-append');
  assert.equal(nobundle.status, 4);
  assert.equal(nobundle.rec.error.code, 'no_active_seed');
  assert.ok(!('seed' in nobundle.rec) && !('decision' in nobundle.rec));
});

// --- A10 -----------------------------------------------------------------------------------------------
test('A10 an exact-version override: evaluated BLOCK kept, effective ALLOW by override, exit 0', () => {
  const host = makeHost('override');
  witnessWith(host, { overrides: [['p', '1.3.0', 'vendored fork, reviewed']] });
  const { status, rec } = checkJson(host, 'pin-block-append');
  assert.equal(status, 0);
  assert.equal(rec.decision.disposition, 'BLOCK', 'the evaluated disposition is never rewritten');
  assert.equal(rec.effective.action, 'ALLOW');
  assert.equal(rec.effective.basis, 'override');
  assert.equal(rec.effective.override.reason, 'vendored fork, reviewed');
  assert.equal(rec.effective.override.scope, 'exact-version');
  assert.match(rec.effective.override.created_at, /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/);
  assert.ok(rec.explanation.text.some((l) => /EVALUATED disposition is BLOCK/.test(l)));
  // exact version only: the neighbouring version is not overridden
  const other = checkJson(host, 'notime-pin-block-ineligible');
  assert.equal(other.status, 3);
  assert.equal(other.rec.effective.basis, 'evaluation');
});

// --- A8 ------------------------------------------------------------------------------------------------
test('A8 why --from reproduces the saved explanation byte-identically without evaluating', () => {
  const nowhere = { home: path.join(WORK, 'empty-home') };      // no seed, no config, no witness
  fs.mkdirSync(nowhere.home, { recursive: true });
  for (const id of ['warn-trajectory', 'publisher-broke-beside-unevaluated', 'refuse-malformed-npmuser',
    'uncovered', 'cold-start-new-major']) {
    const { rec } = checkJson(HOST, id);
    const saved = path.join(WORK, `saved-${id}.json`);
    fs.writeFileSync(saved, JSON.stringify(rec));
    const j = cli(nowhere, ['why', '--from', saved, '--json']);
    assert.equal(j.status, 0, j.stderr);
    assert.equal(JSON.stringify(JSON.parse(j.stdout)), JSON.stringify(rec.explanation), `${id}: structured`);
    const t = cli(nowhere, ['why', '--from', saved]);
    assert.equal(t.stdout, `${rec.explanation.text.join('\n')}\n`, `${id}: text, byte for byte`);
    assert.deepEqual(explain(rec), rec.explanation, `${id}: explain(saved) in-process`);
  }
});

test('A8 why --packument evaluates then explains; why --cached is UNBOUND and exits 4', () => {
  const r = cli(HOST, ['why', target('warn-trajectory'), '--packument', packumentFile('warn-trajectory')]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /^p@1\.6\.0: WARN/);

  const host = makeHost('cached');
  witnessWith(host, { decisions: [['p', '1.3.0', 'ALLOW']] });
  const c = cli(host, ['why', 'p@1.3.0', '--cached']);
  assert.equal(c.status, 4);
  assert.match(c.stdout, /CACHED — UNBOUND: produced without recorded seed\/rule\/policy identities; not a current evaluation/);
  const cj = cli(host, ['why', 'p@1.3.0', '--cached', '--json']);
  assert.equal(cj.status, 4);
  assert.equal(JSON.parse(cj.stdout).label, 'CACHED-UNBOUND');
  const none = cli(host, ['why', 'p@9.9.9', '--cached']);
  assert.equal(none.status, 4, 'no row is still exit 4');

  assert.equal(cli(HOST, ['why', 'p@1.3.0']).status, 4, 'no mode: never falls back to the cached row');
  assert.equal(cli(HOST, ['why', '--from', path.join(WORK, 'nope.json')]).status, 4);
});

// --- A6 ------------------------------------------------------------------------------------------------
test('A6 no process in this file ever reached the network guard', () => {
  // runs last: node:test executes tests in order within a file
  const attempts = fs.existsSync(NET_LOG) ? fs.readFileSync(NET_LOG, 'utf8') : '';
  assert.equal(attempts, '', `network attempts recorded:\n${attempts}`);
});

test('A6 the guard is live in the check process (control)', () => {
  const probe = path.join(WORK, 'probe.mjs');
  fs.writeFileSync(probe, "process.stdout.write(process.env.U01_NETWORK_GUARD || 'none');"
    + "try { await fetch('https://registry.npmjs.org/'); process.stdout.write(' reached'); }"
    + "catch (e) { process.stdout.write(' ' + e.code); }");
  const log = path.join(WORK, 'control.log');
  const r = spawnSync(process.execPath, ['--import', GUARD, probe], { env: { PATH: process.env.PATH, U01_NET_LOG: log }, encoding: 'utf8' });
  assert.equal(r.stdout, 'deny-all U01_NETWORK_DENIED');
  assert.match(fs.readFileSync(log, 'utf8'), /fetch https:\/\/registry\.npmjs\.org\//);
});
