// CFT-05 — the intended CFT startup path, as configuration rather than injection.
//
// A test that hands `createProxyServer` a ready-made gate module proves the pieces compose. It does
// not prove that starting the proxy wires them, which is the thing an operator actually does. Here
// the proxy is given a seed PATH and the two policy choices as configuration and must do the rest
// itself: open the seed through the v3 reader, apply the declared trust mode, construct the gate,
// and append it to its own default module list.
//
// It must also REFUSE to start when it cannot. A proxy that silently runs without the detection gate
// it was configured with is the same silent degradation as serving a packument raw, moved to
// start-up where it is harder to notice.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { createHash } from 'node:crypto';

import { createProxyServer } from '../../proxy/server.js';
import { loadConfig } from '../../proxy/config.js';
import { DEFAULT_GATE_MODULES } from '../../gates/index.js';
import R from '../../seed/v3/reader.js';
import * as policyModule from '../../config-store.js';

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

let DIR;
function seedAt(name, { schemaVersion = '3' } = {}) {
  DIR = DIR || mkdtempSync(join(tmpdir(), 'cft05-startup-'));
  const p = join(DIR, name);
  const db = new Database(p);
  db.exec(SCHEMA);
  db.prepare('INSERT INTO packages VALUES (?,?,?,?,?)').run(1, 'p', '1.0.0', 1, '1');
  db.prepare('INSERT INTO lineages VALUES (?,?,?,?,?,?,?,?,?)')
    .run(1, 1, 0, '1', '1.0.0', '1.0.0', 1, 1767225600, 1767225600);
  for (const g of ['publisher', 'provenance', 'install', 'git', 'deps']) {
    db.prepare('INSERT INTO lineage_state VALUES (?,?,?)').run(1, g, '{}');
  }
  for (const [k, v] of Object.entries({
    schema_version: schemaVersion, contract_version: 'cft-seed-v3-contract-1.0',
    corpus_snapshot_digest: 'f'.repeat(64), history_cutoff: '2026-12-31T00:00:00Z',
    rule_versions: JSON.stringify(Object.fromEntries(
      Object.entries(R.SUPPORTED_RULE_VERSIONS).map(([family, vs]) => [family, vs[0]]))),
  })) db.prepare('INSERT INTO seed_metadata VALUES (?,?)').run(k, v);
  db.close();
  writeFileSync(`${p}.sha256`,
    `${createHash('sha256').update(readFileSync(p)).digest('hex')}  ${name}\n`);
  return p;
}

// Everything a v3 gate needs, stated. The proxy refuses to start without any of it.
const STATED = {
  seedV3Trust: 'unsigned-development',
  policyOnUnusableInput: 'BLOCK',
  policyOnNoEvidence: 'WARN',
  domainVersionCount: 0,
};
const start = (over) => createProxyServer({
  port: 0, host: '127.0.0.1', upstream: 'http://127.0.0.1:1',
  witnessDbPath: join(DIR || mkdtempSync(join(tmpdir(), 'cft05-startup-')), `w-${Math.random()}.db`),
  ...over,
});
const stop = (s) => new Promise((r) => s.close(r));

test('with no v3 seed configured the proxy starts exactly as before', async () => {
  const s = start({});
  try {
    assert.equal(s.seedV3, null);
  } finally { await stop(s); }
});

test('given a seed PATH the proxy opens it and wires the gate itself', async () => {
  const path = seedAt('ok.db');
  const s = start({ seedV3Path: path, ...STATED });
  try {
    assert.ok(s.seedV3, 'the proxy must have opened the seed');
    assert.equal(s.seedV3.meta.corpus_snapshot_digest, 'f'.repeat(64));
  } finally { await stop(s); }
});

test('the configured gate is ADDED to the defaults, not swapped in for them', async () => {
  // A v3 gate that replaced the pilot modules would silently drop content-hash, the only other gate
  // that can block.
  const path = seedAt('ok2.db');
  const s = start({ seedV3Path: path, ...STATED });
  try {
    assert.ok(s.seedV3);
    assert.ok(DEFAULT_GATE_MODULES.some((m) => m.name === 'content-hash'),
      'the pilot default set must still contain content-hash');
  } finally { await stop(s); }
});

test('a configured seed that cannot be OPENED stops the proxy starting', () => {
  assert.throws(() => start({ seedV3Path: '/definitely/not/a/seed.db', ...STATED }),
    /failed to open v3 seed/);
  assert.throws(() => start({ seedV3Path: '/definitely/not/a/seed.db', ...STATED }),
    /refuses to start WITHOUT the detection gate/);
});

test('a configured seed that cannot be TRUSTED stops the proxy starting', () => {
  // authenticated is the default, and the fixture seed carries no signature
  const path = seedAt('unsigned.db');
  assert.throws(() => start({ ...STATED, seedV3Path: path, seedV3Trust: 'authenticated' }),
    /failed to open v3 seed/);
  // ...and naming the development mode is what lets it through, loudly
  const s = start({ seedV3Path: path, ...STATED });
  assert.ok(s.seedV3);
  return stop(s);
});

test('a seed the reader does not implement stops the proxy starting', () => {
  const path = seedAt('v9.db', { schemaVersion: '9' });
  assert.throws(() => start({ seedV3Path: path, ...STATED }), /schema_version/);
});

test('an unrecognised trust mode is refused rather than quietly downgraded', () => {
  const path = seedAt('ok3.db');
  assert.throws(() => start({ ...STATED, seedV3Path: path, seedV3Trust: 'whatever' }),
    /authenticated.*unsigned-development/s);
});

test('an unrecognised policy value is refused when the gate is WIRED', () => {
  const path = seedAt('ok4.db');
  assert.throws(() => start({ ...STATED, seedV3Path: path, policyOnNoEvidence: 'ALOW' }),
    /failed to open v3 seed/);
});

test('UNRESOLVED POLICY IS NOT PERMISSION: a host with an active bundle refuses to start', () => {
  // Unset -> policy declines -> the gate can only answer SKIP -> SKIP does not count -> the package
  // installs. Enforcement cannot tell that apart from permission, so the configuration is refused.
  const { ConfigUnreadable, requireCompletePolicy } = policyModule;
  assert.throws(() => requireCompletePolicy({ on_unusable_input: 'BLOCK' }), ConfigUnreadable);
  assert.throws(() => requireCompletePolicy({}), ConfigUnreadable);
  assert.doesNotThrow(() => requireCompletePolicy(
    { on_unusable_input: 'BLOCK', on_no_evidence: 'WARN' }));
  // and `REFUSE_TO_DECIDE` is not an acceptable stored value at all
  assert.throws(() => policyModule.validateConfig(
    { policy: { on_unusable_input: 'REFUSE_TO_DECIDE', on_no_evidence: 'WARN' } }),
  ConfigUnreadable);
});

test('the domain version count is INTERNAL: there is no setting for it', () => {
  // It was briefly a required environment switch. That is the opposite of environment-free setup:
  // an operator cannot know how many versions of a package came from a domain, and a wrong answer
  // silently changes provider_class. It is derived per document instead.
  const cfg = loadConfig({ CHAINGATE_HOME: DIR || mkdtempSync(join(tmpdir(), 'cft05-startup-')) });
  assert.equal(cfg.domainVersionCount, 'from-packument');
  const withVar = loadConfig({ CHAINGATE_DOMAIN_VERSION_COUNT: '7',
    CHAINGATE_HOME: DIR || mkdtempSync(join(tmpdir(), 'cft05-startup-')) });
  assert.equal(withVar.domainVersionCount, 'from-packument',
    'an environment variable must not be able to set it');
});

test('configuration comes from the FILE; the environment is an override, never a requirement', () => {
  const home = mkdtempSync(join(tmpdir(), 'cft05-startup-'));
  try {
    // nothing configured at all: a legitimate pre-v3 state, not a failure
    const bare = loadConfig({ CHAINGATE_HOME: home });
    assert.equal(bare.seedV3Path, null);
    assert.equal(bare.seedV3Trust, 'authenticated', 'authenticated unless asked otherwise');
    assert.equal(bare.configSource, null);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test.after(() => { if (DIR) rmSync(DIR, { recursive: true, force: true }); });
