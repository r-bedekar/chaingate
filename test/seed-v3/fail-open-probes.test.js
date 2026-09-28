// CFT-05 — the two original fail-open probes, reproduced through the ACTUAL runner.
//
// The earlier regressions drove `createGateRunner` with synthetic modules that threw on demand.
// That proves the runner's new contract; it does not prove the REAL seed-v3 gate participates in it.
// These two probes use the real gate, over a real seed, with a real advisory pin, and break it the
// way it actually breaks in production — the seed's database handle goes away underneath it.
//
//   PROBE 1  the gate THROWS while evaluating       -> was SKIP -> did not count -> ALLOW -> installed
//   PROBE 2  the whole observation fails            -> the packument was served RAW -> installed
//
// In both cases a `known_malicious_pins` row named the exact version being installed, and in both
// cases it was discarded in silence. The assertion that matters is the same for each: the recorded
// disposition is not ALLOW, and the version does not survive the rewrite.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { createHash } from 'node:crypto';

import { createGateRunner, DEFAULT_GATE_MODULES } from '../../gates/index.js';
import { rewritePackument } from '../../gates/rewriter.js';
import { openWitnessDB } from '../../witness/db.js';
import { createWitness } from '../../witness/store.js';
import { createSeedV3Gate } from '../../seed/v3/gate.js';
import R from '../../seed/v3/reader.js';

const PKG = 'probe-fixture';
const VERSION = '1.0.0';
const ADVISORY = 'MAL-2026-PROBE';
const PUBLISHED_ISO = '2026-02-01T00:00:00.000Z';
const PUBLISHED_S = Math.floor(Date.parse(PUBLISHED_ISO) / 1000);
const POLICY = { on_unusable_input: 'BLOCK', on_no_evidence: 'WARN' };

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
function seedWithPin() {
  DIR = DIR || mkdtempSync(join(tmpdir(), 'cft05-probe-'));
  const p = join(DIR, `seed-${Math.random().toString(36).slice(2)}.db`);
  const db = new Database(p);
  db.exec(SCHEMA);
  db.prepare('INSERT INTO packages VALUES (?,?,?,?,?)').run(1, PKG, VERSION, 1, '1');
  db.prepare('INSERT INTO lineages VALUES (?,?,?,?,?,?,?,?,?)')
    .run(1, 1, 0, '1', VERSION, VERSION, 1, PUBLISHED_S, PUBLISHED_S);
  for (const g of ['publisher', 'provenance', 'install', 'git', 'deps']) {
    db.prepare('INSERT INTO lineage_state VALUES (?,?,?)').run(1, g, '{}');
  }
  db.prepare('INSERT INTO known_malicious_pins VALUES (?,?,?,?)').run(1, VERSION, ADVISORY, 'osv');
  for (const [k, v] of Object.entries({
    schema_version: '3', contract_version: 'cft-seed-v3-contract-1.0',
    corpus_snapshot_digest: 'f'.repeat(64), history_cutoff: '2026-12-31T00:00:00Z',
    rule_versions: JSON.stringify(Object.fromEntries(
      Object.entries(R.SUPPORTED_RULE_VERSIONS).map(([family, vs]) => [family, vs[0]]))),
  })) db.prepare('INSERT INTO seed_metadata VALUES (?,?)').run(k, v);
  db.close();
  writeFileSync(`${p}.sha256`,
    `${createHash('sha256').update(readFileSync(p)).digest('hex')}  ${p.split('/').pop()}\n`);
  return R.openSeed(p, { trust: R.TRUST_UNSIGNED_DEV });
}

const manifest = () => ({
  name: PKG, version: VERSION,
  _npmUser: { name: 'alice', email: 'alice@example.com' }, _npmVersion: '10.2.3',
  dist: { shasum: 'aa', tarball: `https://x/${PKG}-${VERSION}.tgz`, unpackedSize: 1000 },
});
const packument = () => ({
  name: PKG, 'dist-tags': { latest: VERSION },
  time: { [VERSION]: PUBLISHED_ISO }, versions: { [VERSION]: manifest() },
});

/** The real gate, over a real seed, wired into the real runner and witness. */
function realStack() {
  const seed = seedWithPin();
  const gate = createSeedV3Gate({ seed, config: POLICY, domainVersionCount: 0 });
  const db = openWitnessDB(join(DIR, `w-${Math.random().toString(36).slice(2)}.db`));
  db.applySchema();
  const runGates = createGateRunner({ modules: [...DEFAULT_GATE_MODULES, gate] });
  return { seed, gate, db, runGates, witness: createWitness({ db, runGates, config: {} }) };
}

test('CONTROL: the real stack blocks the pinned version while everything is healthy', () => {
  const s = realStack();
  try {
    const observed = s.witness.observePackument(PKG, packument());
    assert.equal(observed.decisions.get(VERSION).disposition, 'BLOCK');
    const { packument: out } = rewritePackument(packument(), observed.decisions);
    assert.equal(Object.prototype.hasOwnProperty.call(out.versions, VERSION), false);
  } finally { s.seed.close(); s.db.close(); }
});

test('PROBE 1: the real gate THROWS mid-evaluation and the pinned version is still not permitted', () => {
  const s = realStack();
  try {
    // Break it the way production breaks: the seed's handle goes away under the gate. Every query
    // it makes now throws from inside better-sqlite3.
    s.seed.db.close();
    // The gate catches that internally and routes it through policy rather than propagating -- so
    // the ORIGINAL probe's premise ("the module throws") is already answered one layer earlier. What
    // matters is the outcome, so that is what is asserted.
    const direct = s.gate.evaluate({
      packageName: PKG, version: VERSION, rawManifest: manifest(), publishedAt: PUBLISHED_ISO });
    assert.notEqual(direct.result, 'ALLOW', 'a gate that cannot read its seed must not permit');
    assert.equal(direct.result, 'BLOCK');

    const observed = s.witness.observePackument(PKG, packument());
    const decision = observed.decisions.get(VERSION);
    assert.ok(decision, 'the version must still be decided');
    assert.notEqual(decision.disposition, 'ALLOW',
      `a gate that could not run must not read as permission: ${JSON.stringify(decision)}`);
    assert.equal(decision.disposition, 'BLOCK', 'on_unusable_input: BLOCK was the stated choice');
    // the runner recorded WHICH gate failed and that policy answered for it
    const fired = decision.results.find((x) => x.gate === 'seed-v3');
    assert.ok(fired, `seed-v3 absent from ${JSON.stringify(decision.results)}`);
    assert.match(fired.detail, /cft-policy-1\.0/);
    // ...and the version does not survive the rewrite
    const { packument: out } = rewritePackument(packument(), observed.decisions);
    assert.equal(Object.prototype.hasOwnProperty.call(out.versions, VERSION), false,
      'the pinned version was served anyway');
  } finally { s.db.close(); }
});

test('PROBE 1b: an error the gate does NOT catch reaches the runner, which uses its declarations', () => {
  // The other half of probe 1: an unexpected error raised outside the gate's own handling. The real
  // gate's onError/onErrorResult are kept, so this measures what the RUNNER does with them rather
  // than with a synthetic stand-in.
  const s = realStack();
  try {
    const exploding = {
      name: s.gate.name,
      evaluate() { throw new Error('unexpected: something outside the gate broke'); },
      onError: s.gate.onError,
      onErrorResult: s.gate.onErrorResult,
    };
    assert.equal(exploding.onErrorResult, 'BLOCK', 'derived from on_unusable_input at wiring');
    const runGates = createGateRunner({ modules: [...DEFAULT_GATE_MODULES, exploding] });
    const decision = runGates({
      ecosystem: 'npm', packageName: PKG, version: VERSION, incoming: {}, baseline: null,
      history: Array.from({ length: 10 }, (_, i) => ({ version: `0.${i}.0` })),
    });
    assert.notEqual(decision.disposition, 'ALLOW');
    assert.equal(decision.disposition, 'BLOCK');
    const fired = decision.results.find((x) => x.gate === 'seed-v3');
    assert.match(fired.detail, /cft-policy-1\.0/);
    assert.match(fired.detail, /something outside the gate broke/);
  } finally { s.seed.close(); s.db.close(); }
});

test('PROBE 2: the whole observation fails and the packument is not served unexamined', () => {
  const s = realStack();
  try {
    // A transaction-level failure: the witness database is gone. Previously this threw out of
    // observePackument, the proxy caught it, set `observed = null`, and served the raw bytes.
    s.db.close();
    // `db.transaction()` itself throws on a closed handle, which sat OUTSIDE the store's guard, so
    // observePackument still threw for the commonest database failure and the proxy served raw.
    let observed;
    assert.doesNotThrow(() => { observed = s.witness.observePackument(PKG, packument()); },
      'observePackument must not throw: the proxy answers a throw by serving the document raw');
    assert.equal(observed.failed, true, 'the failure must be reported, not swallowed');
    const decision = observed.decisions.get(VERSION);
    assert.ok(decision, 'every version in the document must carry a decision');
    assert.notEqual(decision.disposition, 'ALLOW');
    assert.equal(decision.disposition, 'BLOCK');
    const { packument: out, changed } = rewritePackument(packument(), observed.decisions);
    assert.equal(changed, true);
    assert.equal(Object.prototype.hasOwnProperty.call(out.versions, VERSION), false);
  } finally { s.seed.close(); }
});

test('the same two probes are ALLOW when no gate declares anything — D1 is untouched', () => {
  // The pilot modules declare neither onError nor onErrorResult, so their failure still fails open.
  // This is what keeps the change scoped to the gate that can block on a recorded fact.
  const dir = DIR || mkdtempSync(join(tmpdir(), 'cft05-probe-'));
  const db = openWitnessDB(join(dir, `w-pilot-${Math.random().toString(36).slice(2)}.db`));
  db.applySchema();
  const runGates = createGateRunner({ modules: DEFAULT_GATE_MODULES });
  const witness = createWitness({ db, runGates, config: {} });
  try {
    const observed = witness.failureDecisionsFor(packument(), new Error('database is locked'));
    assert.equal(observed.decisions.get(VERSION).disposition, 'ALLOW');
  } finally { db.close(); }
});

test.after(() => { if (DIR) rmSync(DIR, { recursive: true, force: true }); });
