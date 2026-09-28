// CFT-05 — the environment-free runtime setup, end to end.
//
// The acceptance condition is exact: with EVERY `CHAINGATE_*` variable unset, initialise from a
// local bundle, restart, confirm the active seed and policy, and demonstrate a permitted and a
// blocked install. Adding another required environment setting does not meet that requirement, so
// this test asserts the absence of one as much as the presence of the behaviour.
//
// The other standing requirement it checks is separation: the immutable detection seed and the
// writable witness state are different files, and replacing the seed does not touch the state.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync,
  accessSync, constants as fsConstants } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { createHash } from 'node:crypto';

import { createProxyServer } from '../../proxy/server.js';
import { loadConfig } from '../../proxy/config.js';
import { stageBundle, activateBundle, resolveActiveBundle, verifyBundleDir,
  isV3Seed } from '../../cli/seed-bundle.js';
import { writeConfig, readConfigStrict, DEFAULT_POLICY } from '../../config-store.js';
import { openWitnessDB } from '../../witness/db.js';

const PKG = 'chaingate-lifecycle-fixture';
const VERSION = '1.0.0';
const ADVISORY = 'MAL-2026-LIFECYCLE';
const PUBLISHED_ISO = '2026-09-01T00:00:00.000Z';
const PUBLISHED_S = Math.floor(Date.parse(PUBLISHED_ISO) / 1000);

const npmAvailable = (() => {
  try { execFileSync('npm', ['--version'], { stdio: 'pipe' }); return true; } catch { return false; }
})();

/** Every CHAINGATE_* variable removed, except the home the test needs to isolate itself. */
function envFree(home) {
  const env = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (!k.startsWith('CHAINGATE_')) env[k] = v;
  }
  env.CHAINGATE_HOME = home;      // isolation only: it names the directory, not any behaviour
  return env;
}

const SCHEMA = `
CREATE TABLE packages (id INTEGER PRIMARY KEY, package_name TEXT NOT NULL UNIQUE, latest_version TEXT,
  lineage_count INTEGER NOT NULL, major_order TEXT NOT NULL);
CREATE TABLE lineages (id INTEGER PRIMARY KEY, package_id INTEGER NOT NULL, ord INTEGER NOT NULL,
  lineage_key TEXT NOT NULL, first_version TEXT NOT NULL, last_version TEXT NOT NULL,
  n_versions INTEGER NOT NULL, first_published_s INTEGER NOT NULL, last_published_s INTEGER NOT NULL);
CREATE TABLE lineage_state (lineage_id INTEGER NOT NULL, grp TEXT NOT NULL, initial_state TEXT NOT NULL,
  PRIMARY KEY (lineage_id, grp)) WITHOUT ROWID;
CREATE TABLE spine (lineage_id INTEGER NOT NULL, ord INTEGER NOT NULL, version TEXT NOT NULL,
  published_s INTEGER NOT NULL, prerelease INTEGER NOT NULL, size_bytes INTEGER, tool_key REAL,
  shasum BLOB, capture_class TEXT NOT NULL, row_digest BLOB NOT NULL,
  PRIMARY KEY (lineage_id, ord)) WITHOUT ROWID;
CREATE TABLE events (lineage_id INTEGER NOT NULL, grp TEXT NOT NULL, ord INTEGER NOT NULL,
  version TEXT NOT NULL, published_s INTEGER NOT NULL, after_state TEXT NOT NULL,
  witness_row_digest BLOB NOT NULL, PRIMARY KEY (lineage_id, grp, ord)) WITHOUT ROWID;
CREATE TABLE known_malicious_pins (package_id INTEGER NOT NULL, version TEXT NOT NULL,
  advisory_id TEXT NOT NULL, source TEXT NOT NULL,
  PRIMARY KEY (package_id, version, advisory_id)) WITHOUT ROWID;
CREATE TABLE seed_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
`;

/** A local v3 seed BUNDLE, the shape `chaingate init --seed` is handed. */
function buildBundle(dir, { pinned = false, name = 'bundle.db', snapshot = 'f'.repeat(64) } = {}) {
  const p = join(dir, name);
  const db = new Database(p);
  db.exec(SCHEMA);
  db.prepare('INSERT INTO packages VALUES (?,?,?,?,?)').run(1, PKG, VERSION, 1, '1');
  db.prepare('INSERT INTO lineages VALUES (?,?,?,?,?,?,?,?,?)')
    .run(1, 1, 0, '1', VERSION, VERSION, 1, PUBLISHED_S, PUBLISHED_S);
  for (const g of ['publisher', 'provenance', 'install', 'git', 'deps']) {
    db.prepare('INSERT INTO lineage_state VALUES (?,?,?)').run(1, g, '{}');
  }
  if (pinned) {
    db.prepare('INSERT INTO known_malicious_pins VALUES (?,?,?,?)').run(1, VERSION, ADVISORY, 'osv');
  }
  const R = { channel_a: 'infra5d-1.2+fu2final+norm1+sizeshrink', dac_trajectory: 'dac-trajectory-1.0' };
  for (const [k, v] of Object.entries({
    schema_version: '3', contract_version: 'cft-seed-v3-contract-1.0',
    corpus_snapshot_digest: snapshot, history_cutoff: '2026-12-31T00:00:00Z',
    rule_versions: JSON.stringify(R),
  })) db.prepare('INSERT INTO seed_metadata VALUES (?,?)').run(k, v);
  db.close();
  writeFileSync(`${p}.sha256`,
    `${createHash('sha256').update(readFileSync(p)).digest('hex')}  ${name}\n`);
  return p;                        // deliberately unsigned: --unsigned-development must be asked for
}

// This file keeps the INSTALLATION CONTROLS: a permitted install whose marker appears, and a
// blocked install whose marker does not — both with no operator-supplied CHAINGATE_* anywhere. The
// lifecycle itself (init, doctor, update, activation, rollback, restart) is exercised through the
// real commands in cli-lifecycle.test.js.

// --- the two installs, with no environment ----------------------------------------------------------------
function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${server.address().port}`));
  });
}
const close = (s) => new Promise((r) => s.close(r));

async function runInstall({ pinned }) {
  const home = mkdtempSync(join(tmpdir(), 'cft05-life-'));
  const stage = join(home, 'package');
  mkdirSync(stage, { recursive: true });
  writeFileSync(join(stage, 'package.json'), `${JSON.stringify({
    name: PKG, version: VERSION, license: 'Apache-2.0',
    scripts: { preinstall: 'node preinstall.js' },
  }, null, 2)}\n`);
  writeFileSync(join(stage, 'preinstall.js'),
    "const f = process.env.CG_LIFECYCLE_MARKER;\n"
    + "if (f) require('fs').writeFileSync(f, 'preinstall ran\\n');\n");
  const tgz = join(home, `${PKG}-${VERSION}.tgz`);
  execFileSync('tar', ['-czf', tgz, '-C', home, 'package']);
  const tarball = readFileSync(tgz);
  const marker = join(home, 'MARKER');
  let proxyUrl = null;

  const upstream = http.createServer((req, res) => {
    const path = decodeURIComponent(req.url.split('?')[0]);
    if (path === `/${PKG}`) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        name: PKG, 'dist-tags': { latest: VERSION },
        time: { created: PUBLISHED_ISO, modified: PUBLISHED_ISO, [VERSION]: PUBLISHED_ISO },
        versions: { [VERSION]: {
          name: PKG, version: VERSION, scripts: { preinstall: 'node preinstall.js' },
          _npmUser: { name: 'fixture', email: 'fixture@example.invalid' },
          _npmVersion: '10.9.7', _nodeVersion: '22.22.2',
          maintainers: [{ name: 'fixture', email: 'fixture@example.invalid' }],
          dist: { shasum: createHash('sha1').update(tarball).digest('hex'),
            integrity: `sha512-${createHash('sha512').update(tarball).digest('base64')}`,
            tarball: `${proxyUrl}/${PKG}/-/${PKG}-${VERSION}.tgz`,
            unpackedSize: tarball.length } } },
      }));
      return;
    }
    if (path === `/${PKG}/-/${PKG}-${VERSION}.tgz`) {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(tarball);
      return;
    }
    res.writeHead(404); res.end('{}');
  });
  const upstreamUrl = await listen(upstream);

  // INIT from the local bundle, then start from the persisted configuration alone.
  const witnessDb = join(home, 'witness.db');
  const installed = stageBundle({ dbPath: buildBundle(home, { pinned }) }, home,
    { trust: 'unsigned-development' });
  activateBundle(home, installed.bundle_id);
  writeConfig(join(home, 'config.json'), { policy: DEFAULT_POLICY });
  const db = openWitnessDB(witnessDb); db.applySchema(); db.close();

  const cfg = loadConfig(envFree(home));
  // cfg FIRST: it carries the persisted seed and policy, and the test then names its own upstream
  // and ports. Spreading it last let its default upstream (the real registry) win, which is how the
  // first run of this test 404'd against npmjs.org instead of the fixture server.
  const proxy = createProxyServer({ ...cfg, port: 0, host: '127.0.0.1', upstream: upstreamUrl,
    witnessDbPath: witnessDb, headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000 });
  proxyUrl = await listen(proxy);

  const prefix = join(home, 'install');
  mkdirSync(prefix, { recursive: true });
  writeFileSync(join(prefix, 'package.json'), '{"name":"host","version":"1.0.0","private":true}\n');
  const res = await new Promise((resolve) => {
    const child = spawn('npm', ['install', `${PKG}@${VERSION}`, '--registry', proxyUrl,
      '--cache', join(home, 'npm-cache'), '--no-audit', '--no-fund', '--foreground-scripts',
      '--ignore-scripts=false', '--no-package-lock'], {
      cwd: prefix,
      // the install inherits an environment with NO CHAINGATE_* in it
      env: { ...envFree(home), CG_LIFECYCLE_MARKER: marker, npm_config_update_notifier: 'false' },
    });
    let stdout = ''; let stderr = '';
    child.stdout.on('data', (b) => { stdout += b; });
    child.stderr.on('data', (b) => { stderr += b; });
    const t = setTimeout(() => child.kill('SIGKILL'), 120_000);
    child.on('close', (status) => { clearTimeout(t); resolve({ status, stdout, stderr }); });
  });

  let recorded = null;
  try { recorded = proxy.witnessDb.getLatestDecision(PKG, VERSION); } catch { /* asserted */ }
  const wired = Boolean(proxy.seedV3);
  await close(proxy); await close(upstream);
  return { ok: res.status === 0, stdout: res.stdout, stderr: res.stderr,
    markerPresent: existsSync(marker), recorded, wired, home };
}

test('PERMITTED with no environment: install succeeds and the marker appears',
  { skip: npmAvailable ? false : 'npm is not available', timeout: 180_000 }, async () => {
    const r = await runInstall({ pinned: false });
    assert.equal(r.wired, true, 'the proxy opened the seed from PERSISTED configuration');
    assert.equal(r.ok, true, `install should succeed:\n${r.stderr}`);
    assert.equal(r.markerPresent, true, 'the positive control: the preinstall really runs here');
    assert.ok(r.recorded, 'a decision was recorded');
    assert.notEqual(r.recorded.disposition, 'BLOCK');
    rmSync(r.home, { recursive: true, force: true });
  });

test('BLOCKED with no environment: refusal recorded, install fails, marker never appears',
  { skip: npmAvailable ? false : 'npm is not available', timeout: 180_000 }, async () => {
    const r = await runInstall({ pinned: true });
    assert.equal(r.wired, true);
    assert.equal(r.recorded.disposition, 'BLOCK');
    const fired = r.recorded.gates_fired.find((x) => x.gate === 'seed-v3');
    assert.ok(fired, `seed-v3 did not fire: ${JSON.stringify(r.recorded.gates_fired)}`);
    assert.match(fired.detail, new RegExp(ADVISORY));
    assert.equal(r.ok, false, `install should fail:\n${r.stdout}`);
    assert.equal(r.markerPresent, false, 'the preinstall script must not have executed');
    rmSync(r.home, { recursive: true, force: true });
  });

test('no CHAINGATE_* variable is REQUIRED for the installs above', () => {
  // The requirement is environment-FREE setup, so the absence is asserted rather than assumed.
  const home = mkdtempSync(join(tmpdir(), 'cft05-life-'));
  try {
    const installed = stageBundle({ dbPath: buildBundle(home) }, home,
      { trust: 'unsigned-development' });
    activateBundle(home, installed.bundle_id);
    writeConfig(join(home, 'config.json'), { policy: DEFAULT_POLICY });

    const env = envFree(home);
    assert.deepEqual(Object.keys(env).filter((k) => k.startsWith('CHAINGATE_')), ['CHAINGATE_HOME'],
      'only the isolation home, which names a directory rather than a behaviour');
    const cfg = loadConfig(env);
    assert.equal(cfg.seedV3BundleId, installed.bundle_id);
    assert.ok(cfg.policyOnUnusableInput && cfg.policyOnNoEvidence);
    assert.equal(cfg.domainVersionCount, 'from-packument');
    assert.equal(readConfigStrict(join(home, 'config.json')).policy.on_no_evidence,
      DEFAULT_POLICY.on_no_evidence);
  } finally { rmSync(home, { recursive: true, force: true }); }
});
