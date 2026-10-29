// Since 0.1.6: the runtime reads seed contract 1.3, which is 1.2 with package-scoped lineage ids:
// lineages.id = packages.id * 4096 + ord, carried by every column that names a lineage, and declared as lineage_id_rule
// "pkg4096-1". The rule is checked on the rows, never trusted from the key. Everything else (schema, identifiers, placement,
// pins by name) is 1.2's. Ported by hand from the seed side (chaingate-ops main fcde236: tools/seedgen/reader.py
// lineage_id_rule_problem, versions.py; contract text SEED-CONTRACT-1.3-SHARDS-1.0 section 1).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import R from '../../seed/v3/reader.js';
import G from '../../seed/v3/gate.js';
import A from '../../seed/v3/adapter.js';
import PK from '../../seed/v3/packument.js';
import { buildCheckRecord, inputFromPackument, recordCompatibility } from '../../cli/check-record.js';
import { validateRecord } from '../../examples/ci/chaingate-ci.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const C13 = 'cft-seed-v3-contract-1.3';
const PIPEKEY_A = 'infra5d-1.2+fu2final+norm1+sizeshrink+pipekey1';
const META_1_2 = {
  contract_version: 'cft-seed-v3-contract-1.2',
  rule_versions: JSON.stringify({ channel_a: PIPEKEY_A, dac_trajectory: 'dac-trajectory-1.0' }),
  lineage_rule_version: 'fu2-final+e1e4e5+pipekey1+stubpred1',
  stub_detector_effective_at: '2026-10-13T22:00:00+00:00',
  storage_layout: 'wr1/noeidx/p8k/pinname1/xlink1',
  tag_family_fixture: '{"sha256":"f4be8bc5ab9eaeb5a59eef8c4f206483cfc545a3aba8e90437fde21c542a7061","version":"lineage-tag-family-cases-0.2"}',
};
// changed with tag family 0.3: a 1.3 seed carries its own lineage pair (+platfam1, fixture 0.3, channel_a ...+platfam1)
const PLATFAM_A = `${PIPEKEY_A}+platfam1`;
const META_1_3 = { ...META_1_2, contract_version: C13, lineage_id_rule: 'pkg4096-1',
  lineage_rule_version: 'fu2-final+e1e4e5+pipekey1+stubpred1+platfam1',
  rule_versions: JSON.stringify({ channel_a: PLATFAM_A, dac_trajectory: 'dac-trajectory-1.0' }),
  tag_family_fixture: '{"sha256":"82f551e75df644954b7813dc6fcb804369f67e0c565b3e318ccf31d8971ffe37","version":"lineage-tag-family-cases-0.3"}' };
// the 1.2 / 1.3 layout (writer.py SCHEMA_SQL): 1.3 changes no table
const SCHEMA = `
CREATE TABLE packages (id INTEGER PRIMARY KEY, package_name TEXT NOT NULL UNIQUE, latest_version TEXT,
  lineage_count INTEGER NOT NULL, major_order TEXT NOT NULL);
CREATE TABLE lineages (id INTEGER PRIMARY KEY, package_id INTEGER NOT NULL, ord INTEGER NOT NULL,
  lineage_key TEXT NOT NULL, first_version TEXT NOT NULL, last_version TEXT NOT NULL,
  n_versions INTEGER NOT NULL, first_published_s INTEGER NOT NULL, last_published_s INTEGER NOT NULL,
  tag_family TEXT NOT NULL, UNIQUE (package_id, ord));
CREATE TABLE lineage_state (lineage_id INTEGER NOT NULL, grp TEXT NOT NULL, initial_state TEXT NOT NULL,
  PRIMARY KEY (lineage_id, grp)) WITHOUT ROWID;
CREATE TABLE spine (lineage_id INTEGER NOT NULL, ord INTEGER NOT NULL, version TEXT NOT NULL,
  published_s INTEGER NOT NULL, prerelease INTEGER NOT NULL, size_bytes INTEGER, tool_key REAL,
  shasum BLOB, capture_class TEXT NOT NULL, row_digest BLOB NOT NULL, PRIMARY KEY (lineage_id, ord)) WITHOUT ROWID;
CREATE TABLE cross_links (lineage_id INTEGER NOT NULL, ord INTEGER NOT NULL, pred_lineage_id INTEGER NOT NULL,
  pred_ord INTEGER NOT NULL, pred_version TEXT NOT NULL, pred_size_bytes INTEGER, pred_tool_key REAL,
  PRIMARY KEY (lineage_id, ord)) WITHOUT ROWID;
CREATE TABLE events (lineage_id INTEGER NOT NULL, grp TEXT NOT NULL, ord INTEGER NOT NULL,
  version TEXT NOT NULL, published_s INTEGER NOT NULL, after_state TEXT NOT NULL,
  witness_row_digest BLOB NOT NULL, PRIMARY KEY (lineage_id, grp, ord)) WITHOUT ROWID;
CREATE TABLE dep_names (package_id INTEGER NOT NULL, name TEXT NOT NULL, PRIMARY KEY (package_id, name)) WITHOUT ROWID;
CREATE TABLE known_malicious_pins (package_id INTEGER NOT NULL, version TEXT NOT NULL, advisory_id TEXT NOT NULL,
  source TEXT NOT NULL, package_name TEXT, PRIMARY KEY (package_id, version, advisory_id)) WITHOUT ROWID;
CREATE INDEX idx_pins_name ON known_malicious_pins(package_name, version);
CREATE TABLE seed_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
`;
const PUBLISHED_ISO = '2026-01-01T00:00:00.000Z';
const manifestFor = (version, over = {}) => ({
  name: 'p', version, _npmUser: { name: 'alice', email: 'alice@example.com' }, _npmVersion: '10.2.3',
  maintainers: [{ name: 'alice', email: 'alice@example.com' }], gitHead: 'abc123',
  dist: { unpackedSize: 1000, attestations: { url: 'https://x' } }, ...over,
});
const BASE = A.candidateFromRawRow(PK.observationFromManifest('1.0.0', manifestFor('1.0.0'), PUBLISHED_ISO),
  { packageName: 'p', lineageId: 1, ord: 0, domainVersionCount: 0 });
const INITIAL = {
  publisher: { identity_digest: BASE.identity_digest, tuple_digest: BASE.tuple_digest, maint_digest: BASE.maint_digest,
    tool_name: BASE.tool_name },
  provenance: { present: true }, install: { has_scripts: false, body_digest: '' },
  git: { head_present: true, repo_digest: null }, deps: {},
};
// the largest package id of the v3.2 snapshot: its lineage ids pass 2^32, so the reader must keep them exact
const PID = 2_320_024;
const lid13 = (ord) => PID * 4096 + ord;

/**
 * One package `p` with id `pid`; chains in ord order; lineage id from `lid(ord)` (1.3: pid * 4096 + ord; 1.2: ord + 1).
 * links name chains by index. `edit(db)` runs before the metadata is written.
 */
function buildSeed(chains, links = [], { meta = META_1_3, pid = PID, lid = lid13, drop = [], edit = null } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg016-c13-'));
  const dbPath = path.join(dir, 'chaingate-seed.db');
  const db = new Database(dbPath);
  db.exec(SCHEMA);
  db.prepare('INSERT INTO packages VALUES (?,?,?,?,?)').run(pid, 'p', chains.at(-1).rows.at(-1)[0], chains.length, chains.map((c) => c.key).join(','));
  chains.forEach((c, i) => {
    const id = lid(i); const n = c.rows.length;
    db.prepare('INSERT INTO lineages VALUES (?,?,?,?,?,?,?,?,?,?)').run(id, pid, i, c.key, c.rows[0][0], c.rows.at(-1)[0], n,
      c.rows[0][1], c.rows.at(-1)[1], c.family);
    for (const g of Object.keys(INITIAL)) db.prepare('INSERT INTO lineage_state VALUES (?,?,?)').run(id, g, JSON.stringify(INITIAL[g]));
    c.rows.forEach(([v, s, size = BASE.size_bytes], ord) => {
      db.prepare('INSERT INTO spine VALUES (?,?,?,?,?,?,?,?,?,?)')
        .run(id, ord, v, s, v.includes('-') ? 1 : 0, size, BASE.tool_key, null, 'LIVE', Buffer.alloc(32));
    });
  });
  for (const x of links) {
    db.prepare('INSERT INTO cross_links VALUES (?,?,?,?,?,?,?)').run(lid(x.lineage), x.ord, lid(x.pred_lineage), x.pred_ord,
      x.pred_version, x.pred_size_bytes ?? BASE.size_bytes, BASE.tool_key);
  }
  if (edit) edit(db);
  const m = { schema_version: '3', corpus_snapshot_digest: 'f'.repeat(64), history_cutoff: '2026-12-31T00:00:00Z', K: '20', ...meta };
  for (const d of drop) delete m[d];
  for (const [k, v] of Object.entries(m)) db.prepare('INSERT INTO seed_metadata VALUES (?,?)').run(k, v);
  db.close();
  fs.writeFileSync(`${dbPath}.sha256`, `${R.sha256File(dbPath)}  chaingate-seed.db\n`);
  return dbPath;
}
const DEV = { trust: R.TRUST_UNSIGNED_DEV };
const ONE = [{ key: '1', family: 'release', rows: [['1.0.0', 1767225600]] }];
const TWO = [{ key: '2', family: 'release', rows: [['2.0.0', 1767225600]] },
  { key: '2', family: 'beta', rows: [['2.1.0-beta.1', 1767225700, 500]] }];

test('C1 a 1.3 seed is read: lineage ids package_id * 4096 + ord, exact past 2^32', () => {
  assert.ok(R.SUPPORTED_SEED_CONTRACT_VERSIONS.includes(C13));
  const rep = R.verify(buildSeed(TWO), DEV);
  assert.equal(rep.ok, true, JSON.stringify(rep.checks));
  assert.equal(rep.meta.seed_contract_version, C13);
  assert.equal(rep.checks.lineage_id_rule, true);
  const seed = R.openSeed(buildSeed(TWO), DEV);
  try {
    const pv = seed.package('p');
    assert.deepEqual([...pv.lineages.keys()].sort((a, b) => a - b), [lid13(0), lid13(1)]);
    assert.ok(lid13(1) > 2 ** 32 && Number.isSafeInteger(lid13(1)));
  } finally { seed.close(); }
});

test('C2 the id rule is checked on the rows and the 1.2 identifiers still bind: each break is refused', () => {
  const refused = (p, why) => { const r = R.verify(p, DEV); assert.equal(r.ok, false, `${why}: ${JSON.stringify(r.checks)}`); return r; };
  let r = refused(buildSeed(ONE, [], { drop: ['lineage_id_rule'] }), 'no lineage_id_rule');
  assert.match(String(r.checks.lineage_id_rule), /pkg4096-1/);
  refused(buildSeed(ONE, [], { meta: { ...META_1_3, lineage_id_rule: 'pkg4096-2' } }), 'another id rule');
  r = refused(buildSeed(ONE, [], { lid: (ord) => PID * 4096 + ord + 1 }), 'an id off the rule');
  assert.match(String(r.checks.lineage_id_rule), /1 lineage\(s\) whose id is not package_id \* 4096 \+ ord/);
  refused(buildSeed(ONE, [], { lid: (ord) => ord + 1 }), 'the 1.2 ids under a 1.3 declaration');
  refused(buildSeed(ONE, [], { edit: (db) => db.prepare('UPDATE lineages SET ord = 4096, id = ? WHERE package_id = ?').run(PID * 4096 + 4096, PID) }), 'ord past the bound');
  r = refused(buildSeed(ONE, [], { meta: { ...META_1_2, lineage_id_rule: 'pkg4096-1' }, lid: (ord) => ord + 1 }), 'a 1.2 seed carrying the 1.3 key');
  assert.match(String(r.checks.lineage_id_rule), /1\.3/);
  for (const key of ['lineage_rule_version', 'stub_detector_effective_at', 'storage_layout', 'tag_family_fixture']) {
    refused(buildSeed(ONE, [], { drop: [key] }), `a 1.3 seed without ${key}`);
  }
  refused(buildSeed(ONE, [], { meta: { ...META_1_3, rule_versions: JSON.stringify({ channel_a: 'infra5d-1.2+fu2final+norm1+sizeshrink', dac_trajectory: 'dac-trajectory-1.0' }) } }),
    'a 1.3 seed without the pipeline-key rule');
  // each contract reads only under its own lineage pair: a crossed identifier is refused either way
  for (const key of ['lineage_rule_version', 'rule_versions', 'tag_family_fixture']) {
    refused(buildSeed(ONE, [], { meta: { ...META_1_3, [key]: META_1_2[key] } }), `a 1.3 seed with the 1.2 ${key}`);
    refused(buildSeed(ONE, [], { meta: { ...META_1_2, [key]: META_1_3[key] }, pid: 1, lid: (ord) => ord + 1 }), `a 1.2 seed with the 1.3 ${key}`);
  }
  assert.equal(R.verify(buildSeed(ONE, [], { meta: META_1_2, pid: 1, lid: (ord) => ord + 1 }), DEV).ok, true, 'a 1.2 seed reads as before');
});

test('C3 placement and Channel-A on a 1.3 seed are those of the 1.2 seed of the same content, cross-links included', () => {
  const pre = R.openSeed(buildSeed(TWO), DEV);
  try {
    const p = G.resolvePlacement(pre, 'p', '2.1.0', 1767225800);
    assert.deepEqual([p.kind, p.lineage_id], ['append', lid13(1)]);
    assert.equal(G.resolvePlacement(pre, 'p', '2.2.0-rc.1', 1767225800).kind, 'new-family-cold-start');
    const out = G.evaluateCandidate(pre, { config: { on_unusable_input: 'BLOCK', on_no_evidence: 'WARN' }, domainVersionCount: 0 },
      { packageName: 'p', version: '2.1.0', rawManifest: manifestFor('2.1.0'), publishedAt: '2026-01-01T00:03:20.000Z' });
    assert.equal(out.finding.channel_a.predecessor_version, '2.1.0-beta.1');
    assert.equal(out.finding.channel_a.groups.size.value, true);
  } finally { pre.close(); }
  const chains = [{ key: '2', family: 'release', rows: [['2.0.0', 1767225600], ['2.1.0', 1767225800]] },
    { key: '2', family: 'beta', rows: [['2.1.0-beta.1', 1767225700, 500]] }];
  const link = { lineage: 0, ord: 1, pred_lineage: 1, pred_ord: 0, pred_version: '2.1.0-beta.1', pred_size_bytes: 500 };
  const results = [];
  for (const [meta, pid, lid] of [[META_1_3, PID, lid13], [META_1_2, 1, (ord) => ord + 1]]) {
    const seed = R.openSeed(buildSeed(chains, [link], { meta, pid, lid }), DEV);
    try {
      const out = G.evaluateCandidate(seed, { config: { on_unusable_input: 'BLOCK', on_no_evidence: 'WARN' }, domainVersionCount: 0 },
        { packageName: 'p', version: '2.1.0', rawManifest: manifestFor('2.1.0'), publishedAt: '2026-01-01T00:03:20.000Z' });
      assert.deepEqual([out.placement.kind, out.placement.lineage_id, out.placement.ord], ['recorded', lid(0), 1]);
      results.push({ pred: out.finding.channel_a.predecessor_version, disposition: out.decision.disposition,
        rows: out.decision.results.map((x) => [x.gate, x.result]) });
    } finally { seed.close(); }
  }
  assert.equal(results[0].pred, '2.1.0-beta.1');
  assert.deepEqual(results[0], results[1], 'the same answer under 1.3 ids and 1.2 ids');
});

test('C6 a 1.3 seed places a platform build by tag family 0.3, a 1.2 seed by 0.2', () => {
  const chains = [{ key: '2', family: 'beta', rows: [['2.0.0-beta.24', 1767225600]] },
    { key: '2', family: 'beta@darwin-arm64', rows: [['2.0.0-beta.24-darwin-arm64', 1767225600]] }];
  const s13 = R.openSeed(buildSeed(chains), DEV);
  try {
    const p = G.resolvePlacement(s13, 'p', '2.0.0-beta.25-darwin-arm64', 1767225800);
    assert.deepEqual([p.kind, p.lineage_id], ['append', lid13(1)]);
    assert.equal(G.resolvePlacement(s13, 'p', '2.0.0-beta.25', 1767225800).lineage_id, lid13(0));
  } finally { s13.close(); }
  const s12 = R.openSeed(buildSeed(chains.slice(0, 1), [], { meta: META_1_2, pid: 1, lid: (ord) => ord + 1 }), DEV);
  try {
    const p = G.resolvePlacement(s12, 'p', '2.0.0-beta.25-darwin-arm64', 1767225800);
    assert.deepEqual([p.kind, p.lineage_id], ['append', 1]);
  } finally { s12.close(); }
});

test('C4 a 1.3 seed finds a pin by NAME, represented or not', () => {
  const dbPath = buildSeed(ONE, [], { edit: (db) => {
    db.prepare('INSERT INTO known_malicious_pins VALUES (?,?,?,?,?)').run(9001, '1.0.0', 'ADV-U-100', 'synthetic-fixture', 'u');
    db.prepare('INSERT INTO known_malicious_pins VALUES (?,?,?,?,?)').run(PID, '1.0.1', 'ADV-P-101', 'synthetic-fixture', 'p');
  } });
  const seed = R.openSeed(dbPath, DEV);
  try {
    for (const [name, version, adv] of [['u', '1.0.0', 'ADV-U-100'], ['p', '1.0.1', 'ADV-P-101']]) {
      const d = G.evaluateCandidate(seed, { config: { on_unusable_input: 'WARN', on_no_evidence: 'WARN' }, domainVersionCount: 0 },
        { packageName: name, version, rawManifest: manifestFor(version, { name }), publishedAt: '2026-01-01T00:03:20.000Z' }).decision;
      assert.equal(d.disposition, 'BLOCK', `${name}@${version}`);
      assert.ok(JSON.stringify(d.results.find((x) => x.gate === 'seed-v3:known-malicious-pin')).includes(adv));
    }
  } finally { seed.close(); }
});

let Ajv2020 = null; try { Ajv2020 = createRequire(import.meta.url)('ajv/dist/2020.js'); } catch { /* not installed */ }
const V3DIR = path.join(HERE, '..', '..', 'seed', 'v3');
const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));

test('C5 a check against a 1.3 seed writes chaingate.check/5 naming contract 1.3; the CI consumer and the schema accept it', () => {
  const seed = R.openSeed(buildSeed(TWO), DEV);
  try {
    const doc = { name: 'p', versions: { '2.1.0': manifestFor('2.1.0') }, time: { '2.1.0': '2026-01-01T00:03:20.000Z' } };
    const r = buildCheckRecord({ seed, policy: { on_unusable_input: 'WARN', on_no_evidence: 'WARN' },
      domainVersionCount: 'from-packument', input: inputFromPackument(doc, 'p', '2.1.0'),
      request: { package: 'p', version: '2.1.0' }, tool: { name: 'chaingate', version: 'test' } });
    assert.equal(r.schema, 'chaingate.check/5'); assert.equal(r.seed.contract_version, C13);
    assert.deepEqual(recordCompatibility(r), []);
    assert.deepEqual(validateRecord(r), []);
    assert.ok(recordCompatibility({ ...r, schema: 'chaingate.check/4' }).some((x) => /seed\.contract_version/.test(x)), '/4 never carries 1.3');
    if (Ajv2020) {
      const Ctor = Ajv2020.default || Ajv2020; const ajv = new Ctor({ strict: true, strictRequired: false, allErrors: true });
      ajv.addSchema(readJson(path.join(HERE, '..', 'fixtures', 'cft03', 'finding.schema.json')));
      const v5 = ajv.compile(readJson(path.join(V3DIR, 'chaingate-check-5.schema.json')));
      assert.ok(v5(r), JSON.stringify(v5.errors));
    }
  } finally { seed.close(); }
});
