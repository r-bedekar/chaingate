// CFT-05 — does the proxy actually stop package code from running?
//
// The claim being tested is narrow and stated as such: for THIS package over THIS installation path
// (`npm install <name>@<version> --registry <proxy>`), a policy BLOCK prevents the version's
// `preinstall` script from executing. It is not a claim about npm in general, about other
// installation paths (a lockfile with a pinned resolved URL, a vendored tarball, a different client),
// or about packages the seed does not cover.
//
// WHY THERE IS A POSITIVE CONTROL. "The marker is absent" proves nothing on its own: the install
// could have failed for an unrelated reason, or lifecycle scripts could be disabled in this
// environment, in which case the marker would be absent whether or not anything was enforced. So the
// SAME fixture is installed twice, and the permitted half must show the marker actually appearing.
//
//   permitted: installation SUCCEEDS  and the preinstall marker APPEARS
//   blocked:   the expected policy refusal occurs, installation FAILS, and the marker NEVER appears
//
// The only difference between the two runs is one row in the seed: a recorded advisory pin for that
// exact version, which is the locked true-positive-by-construction BLOCK (CFT-05 §1).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { createHash } from 'node:crypto';

import { createProxyServer } from '../../proxy/server.js';
import { rewritePackument } from '../../gates/rewriter.js';
import R from '../../seed/v3/reader.js';

const PKG = 'chaingate-enforcement-fixture';
const VERSION = '1.0.0';
const ADVISORY = 'MAL-2026-TEST-0001';
// ONE publication time, used by the packument's `time{}` AND by the seed's lineage rows. They were
// written independently before and disagreed by a year (the seed said 2025-09-01 while the document
// said 2026-09-01), which puts the candidate before its own recorded history — the kind of mismatch
// that changes which versions count as strictly prior. Deriving both from one constant makes it
// impossible by construction.
const PUBLISHED_ISO = '2026-09-01T00:00:00.000Z';
const PUBLISHED_S = Math.floor(Date.parse(PUBLISHED_ISO) / 1000);
const HISTORY_CUTOFF_ISO = '2026-09-02T00:00:00Z';   // strictly after the release it covers

// npm must be present and able to run a lifecycle script for this test to mean anything.
const npmAvailable = (() => {
  try { execFileSync('npm', ['--version'], { stdio: 'pipe' }); return true; } catch { return false; }
})();

// --- the harmless fixture -----------------------------------------------------------------------------
// One package whose preinstall writes a marker file and exits. No network, no side effects outside
// the temp directory, and the same bytes are used for BOTH installs.
function buildFixtureTarball(dir) {
  const stage = join(dir, 'package');
  mkdirSync(stage, { recursive: true });
  writeFileSync(join(stage, 'package.json'), `${JSON.stringify({
    name: PKG,
    version: VERSION,
    description: 'harmless CFT enforcement fixture: preinstall writes a marker and exits',
    license: 'Apache-2.0',
    // A FILE, not an inline `node -e "..."`: that string is re-quoted by package.json and again by
    // `sh -c`, and reached node as an unterminated expression — the script failed for a reason that
    // had nothing to do with enforcement, which is exactly the confusion the positive control exists
    // to prevent.
    scripts: { preinstall: 'node preinstall.js' },
  }, null, 2)}\n`);
  writeFileSync(join(stage, 'preinstall.js'),
    "const f = process.env.CG_ENFORCEMENT_MARKER;\n"
    + "if (f) require('fs').writeFileSync(f, 'preinstall ran\\n');\n");
  writeFileSync(join(stage, 'index.js'), 'module.exports = 0;\n');
  const tgz = join(dir, `${PKG}-${VERSION}.tgz`);
  // deterministic-enough tar; the bytes only need to be identical between the two runs
  execFileSync('tar', ['-czf', tgz, '-C', dir, 'package']);
  return readFileSync(tgz);
}

function packumentFor(tarballUrl, tarballBytes) {
  const shasum = createHash('sha1').update(tarballBytes).digest('hex');
  const integrity = `sha512-${createHash('sha512').update(tarballBytes).digest('base64')}`;
  return {
    name: PKG,
    'dist-tags': { latest: VERSION },
    time: { created: PUBLISHED_ISO, modified: PUBLISHED_ISO, [VERSION]: PUBLISHED_ISO },
    versions: {
      [VERSION]: {
        name: PKG,
        version: VERSION,
        // npm runs the lifecycle script from the RESOLVED MANIFEST, which comes from the
        // packument — not from the package.json inside the tarball. A placeholder here is a script
        // npm actually executes, so it mirrors the fixture exactly, as a real packument does.
        scripts: { preinstall: 'node preinstall.js' },
        _npmUser: { name: 'fixture', email: 'fixture@example.invalid' },
        _npmVersion: '10.9.7',
        _nodeVersion: '22.22.2',
        maintainers: [{ name: 'fixture', email: 'fixture@example.invalid' }],
        repository: { type: 'git', url: 'git+https://github.com/example/fixture.git' },
        dist: { shasum, integrity, tarball: tarballUrl, unpackedSize: tarballBytes.length },
      },
    },
  };
}

// --- a minimal v3 seed ---------------------------------------------------------------------------------
// The schema the reader requires, one package, one lineage, and optionally the advisory pin. rc3 is
// frozen and is NOT touched: this is a purpose-built fixture seed for the enforcement path.
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
CREATE TABLE dep_names (package_id INTEGER NOT NULL, name TEXT NOT NULL,
  PRIMARY KEY (package_id, name)) WITHOUT ROWID;
CREATE TABLE known_malicious_pins (package_id INTEGER NOT NULL, version TEXT NOT NULL,
  advisory_id TEXT NOT NULL, source TEXT NOT NULL,
  PRIMARY KEY (package_id, version, advisory_id)) WITHOUT ROWID;
CREATE TABLE seed_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
`;

function buildSeed(dir, { pinned }) {
  const dbPath = join(dir, 'chaingate-seed.db');
  const db = new Database(dbPath);
  db.exec(SCHEMA);
  db.prepare('INSERT INTO packages VALUES (?,?,?,?,?)').run(1, PKG, VERSION, 1, '1');
  db.prepare('INSERT INTO lineages VALUES (?,?,?,?,?,?,?,?,?)')
    .run(1, 1, 0, '1', VERSION, VERSION, 1, PUBLISHED_S, PUBLISHED_S);
  for (const g of ['publisher', 'provenance', 'install', 'git', 'deps']) {
    db.prepare('INSERT INTO lineage_state VALUES (?,?,?)').run(1, g, '{}');
  }
  if (pinned) {
    db.prepare('INSERT INTO known_malicious_pins VALUES (?,?,?,?)')
      .run(1, VERSION, ADVISORY, 'osv');
  }
  for (const [k, v] of Object.entries({
    schema_version: '3',
    contract_version: 'cft-seed-v3-contract-1.0',
    corpus_snapshot_digest: 'f'.repeat(64),
    history_cutoff: HISTORY_CUTOFF_ISO,
    // the reader's OWN declared support, not a literal that drifts away from it
    rule_versions: JSON.stringify(Object.fromEntries(
      Object.entries(R.SUPPORTED_RULE_VERSIONS).map(([family, vs]) => [family, vs[0]]))),
  })) db.prepare('INSERT INTO seed_metadata VALUES (?,?)').run(k, v);
  db.close();
  writeFileSync(`${dbPath}.sha256`,
    `${createHash('sha256').update(readFileSync(dbPath)).digest('hex')}  chaingate-seed.db\n`);
  return dbPath;
}

// --- servers ---------------------------------------------------------------------------------------------
function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${server.address().port}`));
  });
}
const close = (s) => new Promise((resolve) => s.close(resolve));

/**
 * One isolated install of the fixture through the proxy.
 * @returns {{ok: boolean, stdout: string, stderr: string, markerPresent: boolean}}
 */
async function runInstall({ pinned }) {
  const dir = mkdtempSync(join(tmpdir(), 'cft05-enforce-'));
  const tarball = buildFixtureTarball(dir);
  const marker = join(dir, 'PREINSTALL-MARKER');
  let proxyUrl = null;

  const upstream = http.createServer((req, res) => {
    const path = decodeURIComponent(req.url.split('?')[0]);
    if (path === `/${PKG}`) {
      const body = JSON.stringify(packumentFor(`${proxyUrl}/${PKG}/-/${PKG}-${VERSION}.tgz`, tarball));
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(body);
      return;
    }
    if (path === `/${PKG}/-/${PKG}-${VERSION}.tgz`) {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(tarball);
      return;
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end('{"error":"not found"}');
  });
  const upstreamUrl = await listen(upstream);

  const seedPath = buildSeed(dir, { pinned });

  // THE INTENDED STARTUP PATH. The gate is not injected: the proxy is handed a seed path and the
  // operator's two policy choices as CONFIGURATION, opens the seed itself through the v3 reader, and
  // appends the gate to its own default module list. An injected module proves the pieces compose,
  // not that a real start-up wires them.
  const proxy = createProxyServer({
    port: 0, host: '127.0.0.1', upstream: upstreamUrl,
    witnessDbPath: join(dir, 'witness.db'), headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000,
    seedV3Path: seedPath,
    seedV3Trust: 'unsigned-development',        // the fixture seed is unsigned, and this says so
    policyOnUnusableInput: 'BLOCK',
    policyOnNoEvidence: 'ALLOW',
    // STATED, never defaulted: it decides provider_class and 0 is not "unknown". 0 reproduces the
    // seed's own corpus, which carries no domain counts at all.
    domainVersionCount: 0,
  });
  proxyUrl = await listen(proxy);

  const prefix = join(dir, 'install');
  mkdirSync(prefix, { recursive: true });
  // npm 12 blocks dependency install scripts unless the project approves them: approve exactly the
  // fixture, so the positive control still proves its preinstall runs (older npm ignores the field).
  writeFileSync(join(prefix, 'package.json'), `${JSON.stringify({ name: 'host', version: '1.0.0', private: true,
    allowScripts: { [PKG]: true } })}\n`);
  // ASYNC, deliberately. The proxy runs on THIS process's event loop, so a synchronous child
  // (spawnSync) blocks it: npm's request for the packument is accepted by the OS and then never
  // served, and both halves of the test hang rather than proving anything.
  const res = await new Promise((resolve) => {
    const child = spawn('npm', ['install', `${PKG}@${VERSION}`,
      '--registry', proxyUrl, '--cache', join(dir, 'npm-cache'), '--no-audit', '--no-fund',
      '--foreground-scripts', '--ignore-scripts=false', '--no-package-lock'], {
      cwd: prefix,
      env: { ...process.env, CG_ENFORCEMENT_MARKER: marker, npm_config_update_notifier: 'false' },
    });
    let stdout = ''; let stderr = '';
    child.stdout.on('data', (b) => { stdout += b; });
    child.stderr.on('data', (b) => { stderr += b; });
    const timer = setTimeout(() => child.kill('SIGKILL'), 120_000);
    child.on('close', (status) => { clearTimeout(timer); resolve({ status, stdout, stderr }); });
  });

  // What the system RECORDED, read back from the witness database rather than from a callback the
  // test handed in. A decision that exists only in the harness proves nothing about the runtime.
  let recorded = null;
  try { recorded = proxy.witnessDb.getLatestDecision(PKG, VERSION); } catch { /* asserted below */ }
  const wiredGate = Boolean(proxy.seedV3);

  await close(proxy);
  await close(upstream);
  return { ok: res.status === 0, status: res.status,
    stdout: res.stdout || '', stderr: res.stderr || '',
    markerPresent: existsSync(marker), recorded, wiredGate, dir };
}

// --- the two installs -------------------------------------------------------------------------------------
test('PERMITTED: the install succeeds and the preinstall marker appears (positive control)',
  { skip: npmAvailable ? false : 'npm is not available', timeout: 180_000 }, async () => {
    const r = await runInstall({ pinned: false });
    assert.equal(r.wiredGate, true, 'the proxy must have opened the v3 seed from its CONFIGURATION');
    assert.equal(r.ok, true, `install should succeed:\n${r.stderr}`);
    assert.equal(r.markerPresent, true,
      'the fixture\'s preinstall must actually run here, or the blocked half proves nothing');
    // the gate must actually have been consulted; a gate that never ran cannot have permitted anything
    assert.ok(r.recorded, 'no decision was recorded for this version');
    const permittedGate = r.recorded.gates_fired.find((x) => x.gate === 'seed-v3');
    assert.ok(permittedGate, `seed-v3 did not fire: ${JSON.stringify(r.recorded.gates_fired)}`);
    assert.match(permittedGate.detail, /cft-policy-1\.0/);
    // no advisory pins it — the ONLY difference from the blocked half
    assert.doesNotMatch(permittedGate.detail, new RegExp(ADVISORY));
    // What "permitted" means here is NOT BLOCKED: the rewriter strips a version iff its disposition
    // is BLOCK, so ALLOW and WARN both leave it installable.
    assert.notEqual(r.recorded.disposition, 'BLOCK',
      `permitted half must not block: ${JSON.stringify(r.recorded)}`);
    assert.ok(['ALLOW', 'WARN'].includes(r.recorded.disposition),
      `unexpected disposition ${r.recorded.disposition}`);
    rmSync(r.dir, { recursive: true, force: true });
  });

test('BLOCKED: the policy refusal occurs, the install fails, and the marker never appears',
  { skip: npmAvailable ? false : 'npm is not available', timeout: 180_000 }, async () => {
    const r = await runInstall({ pinned: true });

    assert.equal(r.wiredGate, true, 'the proxy must have opened the v3 seed from its CONFIGURATION');
    // 1. the expected POLICY refusal, by name — not merely "something went wrong" — and RECORDED.
    //    `gates_fired` is what the runtime persisted, so this reads the system's own record rather
    //    than a callback the harness supplied.
    assert.ok(r.recorded, 'no decision was recorded for this version');
    assert.equal(r.recorded.disposition, 'BLOCK');
    const fired = r.recorded.gates_fired;
    const seedGate = fired.find((x) => x.gate === 'seed-v3');
    assert.ok(seedGate, `seed-v3 did not fire: ${JSON.stringify(fired)}`);
    assert.equal(seedGate.result, 'BLOCK');
    assert.match(seedGate.detail, /cft-policy-1\.0/);
    assert.match(seedGate.detail, new RegExp(ADVISORY));
    assert.match(seedGate.detail, /known-malicious-pin/);

    // 2. the installation FAILS
    assert.equal(r.ok, false, `install should fail:\n${r.stdout}`);
    assert.match(`${r.stderr}${r.stdout}`, /No matching version found|notarget|ETARGET|E403|blocked/i);

    // 3. and the package's code never ran
    assert.equal(r.markerPresent, false, 'the preinstall script must not have executed');
    rmSync(r.dir, { recursive: true, force: true });
  });

test('the enforcement mechanism is the packument rewrite: the version is REMOVED, not flagged', () => {
  // Asserted rather than asserted-in-a-comment. npm never learns of a tarball to fetch, which is why
  // this is an enforcement point BEFORE package code executes — for this installation path, and this
  // package. It is not a claim about npm in general or about any other path.
  const doc = packumentFor('http://127.0.0.1:1/x.tgz', Buffer.from('x'));
  const decisions = new Map([[VERSION, { disposition: 'BLOCK',
    results: [{ gate: 'seed-v3', result: 'BLOCK', detail: `advisory ${ADVISORY}` }] }]]);
  const { packument: out, changed, summary } = rewritePackument(doc, decisions);
  assert.equal(changed, true);
  assert.equal(Object.prototype.hasOwnProperty.call(out.versions, VERSION), false,
    'the blocked version must be absent from versions{}, not merely marked');
  assert.equal(Object.prototype.hasOwnProperty.call(out.time, VERSION), false);
  assert.equal(out['dist-tags'].latest, undefined, 'a dist-tag pointing at it must be dropped');
  assert.deepEqual(summary.blocked.map((b) => b.version), [VERSION]);
  // and the original document is untouched — the rewriter is pure
  assert.ok(doc.versions[VERSION], 'the input packument must not be mutated');
});
