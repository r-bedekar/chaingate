// 0.1.5 FOLLOWUPS #17 (operator go 2026-10-17): the runtime reads seed contract 1.2 (seed v3.2 #5, narrow rl2). The seed
// keeps one chain per (lineage key, prerelease tag family), "release" being a family of its own, and a `cross_links`
// relation for every predecessor that is not the previous row of its own chain (only release chains carry one). A live
// release is placed by rl2-placement-1.0. Ported BY HAND from the seed side (chaingate-ops g10-c2-pipeline-key 8110cc3:
// tools/seedgen/reader.py, checker.py `_predecessor`, writer.py digests, placement.py; contract note
// docs/design/seed-contract-1.2-rl2.md), never through sync-to-runtime.py (tools/seedgen/js is older than seed/v3).
// The fixtures are the seed side's, loaded UNCHANGED and sha-pinned:
//   rl2-lineage-cases-1.0.json          tools/seedgen/fixtures, 15 history + 13 placement cases, sha256 aa4558c6...
//   lineage-tag-family-cases-0.2.json   tools/corpus/fixtures, the tag-family definition the seed pins, sha256 f4be8bc5...
// Not here (step 2, test/gates/cft015-t16-entry-path-change.test.js P3): gates/lineage-predecessor.js, which picks the
// predecessor for the install-time gates T1.6 and size-jump-provenance; it shares seed/v3/tag-family.js with placement.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import R from '../../seed/v3/reader.js';
import G from '../../seed/v3/gate.js';
import C from '../../seed/v3/checker.js';
import L from '../../seed/v3/logical.js';
import A from '../../seed/v3/adapter.js';
import PK from '../../seed/v3/packument.js';
import { createRequire } from 'node:module';
import { buildCheckRecord, inputFromPackument, recordCompatibility, withTarball } from '../../cli/check-record.js';
import { validateRecord } from '../../examples/ci/chaingate-ci.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, '..', 'fixtures', 'rl2');
const load = (f, sha) => {
  const bytes = fs.readFileSync(path.join(FIX, f));
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), sha, `${f} is the seed side's fixture, unchanged`);
  return JSON.parse(bytes.toString('utf8'));
};
const RL2 = () => load('rl2-lineage-cases-1.0.json', 'aa4558c6bebcfa41713172eeec11630672dfa16118ba1090fecd6a56185e9eff');
const TAGS = () => load('lineage-tag-family-cases-0.2.json', 'f4be8bc5ab9eaeb5a59eef8c4f206483cfc545a3aba8e90437fde21c542a7061');

const OLD_A = 'infra5d-1.2+fu2final+norm1+sizeshrink';
const PIPEKEY_A = 'infra5d-1.2+fu2final+norm1+sizeshrink+pipekey1';
const META_1_2 = {
  contract_version: 'cft-seed-v3-contract-1.2',
  rule_versions: JSON.stringify({ channel_a: PIPEKEY_A, dac_trajectory: 'dac-trajectory-1.0' }),
  lineage_rule_version: 'fu2-final+e1e4e5+pipekey1+stubpred1',
  stub_detector_effective_at: '2026-10-13T22:00:00+00:00',
  storage_layout: 'wr1/noeidx/p8k/pinname1/xlink1',
  tag_family_fixture: '{"sha256":"f4be8bc5ab9eaeb5a59eef8c4f206483cfc545a3aba8e90437fde21c542a7061","version":"lineage-tag-family-cases-0.2"}',
};

// ---- a seed in the 1.2 layout (writer.py SCHEMA_SQL, the tables the reader and checker read)
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
const epoch = (iso) => Math.floor(Date.parse(iso) / 1000);

/**
 * chains: [{key, family, rows: [[version, published_s, size_bytes?]...]}] in lineage ord order (lineage id = index + 1);
 * links: [{lineage, ord, pred_lineage, pred_ord, pred_version, pred_size_bytes?}] by chain index; k: the spine tail.
 */
function buildSeed(chains, links = [], { meta = {}, k = 20, drop = [], tables = SCHEMA, v11 = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-rl2-'));
  const dbPath = path.join(dir, 'chaingate-seed.db');
  const db = new Database(dbPath);
  db.exec(tables);
  const last = chains.at(-1).rows.at(-1)[0];
  db.prepare('INSERT INTO packages VALUES (?,?,?,?,?)').run(1, 'p', last, chains.length, chains.map((c) => c.key).join(','));
  chains.forEach((c, i) => {
    const lid = i + 1; const n = c.rows.length;
    const lrow = [lid, 1, i, c.key, c.rows[0][0], c.rows.at(-1)[0], n, c.rows[0][1], c.rows.at(-1)[1]];
    if (v11) db.prepare('INSERT INTO lineages VALUES (?,?,?,?,?,?,?,?,?)').run(...lrow);
    else db.prepare('INSERT INTO lineages VALUES (?,?,?,?,?,?,?,?,?,?)').run(...lrow, c.family);
    for (const g of Object.keys(INITIAL)) db.prepare('INSERT INTO lineage_state VALUES (?,?,?)').run(lid, g, JSON.stringify(INITIAL[g]));
    c.rows.forEach(([v, s, size = BASE.size_bytes], ord) => {
      if (ord < n - k) return;                                    // only the K tail is kept
      db.prepare('INSERT INTO spine VALUES (?,?,?,?,?,?,?,?,?,?)')
        .run(lid, ord, v, s, v.includes('-') ? 1 : 0, size, BASE.tool_key, null, 'LIVE', Buffer.alloc(32));
    });
  });
  for (const x of links) {
    db.prepare('INSERT INTO cross_links VALUES (?,?,?,?,?,?,?)').run(x.lineage + 1, x.ord, x.pred_lineage + 1, x.pred_ord,
      x.pred_version, x.pred_size_bytes ?? BASE.size_bytes, BASE.tool_key);
  }
  const m = { schema_version: '3', corpus_snapshot_digest: 'f'.repeat(64), history_cutoff: '2026-12-31T00:00:00Z',
    K: String(k), ...META_1_2, ...meta };
  for (const d of drop) delete m[d];
  for (const [kk, v] of Object.entries(m)) db.prepare('INSERT INTO seed_metadata VALUES (?,?)').run(kk, v);
  db.close();
  fs.writeFileSync(`${dbPath}.sha256`, `${R.sha256File(dbPath)}  chaingate-seed.db\n`);
  return dbPath;
}
const DEV = { trust: R.TRUST_UNSIGNED_DEV };
const refusals = (rep) => Object.entries(rep.checks).filter(([, v]) => v !== true).map(([kk]) => kk);

// ---- tag family
test('T1 tagFamily reproduces every case of the pinned tag-family definition (lineage-tag-family-cases-0.2)', () => {
  const d = TAGS();
  assert.equal(d.cases.length, 34);
  for (const c of d.cases) assert.equal(G.tagFamily(c.version), c.family, `${c.version} (${c.note})`);
});

// ---- reader
test('R1 a 1.2 seed is accepted only with every pipeline-key identifier together', () => {
  const chains = [{ key: '1', family: 'release', rows: [['1.0.0', 1767225600]] }];
  const ok = R.verify(buildSeed(chains), DEV);
  assert.equal(ok.ok, true, JSON.stringify(ok.checks));
  assert.equal(ok.meta.seed_contract_version, 'cft-seed-v3-contract-1.2');
  assert.ok(R.SUPPORTED_SEED_CONTRACT_VERSIONS.includes('cft-seed-v3-contract-1.2'));
  // changed with tag family 0.3: the 1.3 stamp is supported too, read only from a 1.3 seed (seed-contract-1-3.test.js)
  assert.deepEqual(R.SUPPORTED_RULE_VERSIONS.channel_a, [OLD_A, PIPEKEY_A, `${PIPEKEY_A}+platfam1`]);
  for (const [key, bad] of [
    ['lineage_rule_version', 'fu2-final+e1e4e5'],
    ['stub_detector_effective_at', '2026-10-14T22:00:00+00:00'],
    ['storage_layout', 'wr1/noeidx/p8k/pinname1'],
    ['tag_family_fixture', '{"sha256":"00","version":"lineage-tag-family-cases-0.2"}'],
    ['rule_versions', JSON.stringify({ channel_a: OLD_A, dac_trajectory: 'dac-trajectory-1.0' })],
  ]) {
    const rep = R.verify(buildSeed(chains, [], { meta: { [key]: bad } }), DEV);
    assert.equal(rep.ok, false, `${key}=${bad} must be refused`);
    assert.ok(refusals(rep).length >= 1, key);
  }
  for (const key of ['lineage_rule_version', 'stub_detector_effective_at', 'storage_layout', 'tag_family_fixture']) {
    assert.equal(R.verify(buildSeed(chains, [], { drop: [key] }), DEV).ok, false, `a 1.2 seed without ${key} is refused`);
  }
});

test('R2 the pipeline-key rule and the 1.2 layout come together: 1.1 + pipekey1 is refused, and a 1.2 seed needs the rl2 tables', () => {
  const chains = [{ key: '1', family: 'release', rows: [['1.0.0', 1767225600]] }];
  const r11 = R.verify(buildSeed(chains, [], { meta: { contract_version: 'cft-seed-v3-contract-1.1' } }), DEV);
  assert.equal(r11.ok, false);
  assert.match(String(r11.checks.rule_versions), /pipekey1/);
  const noLinks = R.verify(buildSeed(chains, [], { tables: SCHEMA.replace(/CREATE TABLE cross_links[^;]+;/, '') }), DEV);
  assert.equal(noLinks.ok, false); assert.match(String(noLinks.checks.rl2_layout), /cross_links/);
  const noFam = R.verify(buildSeed(chains, [], { tables: SCHEMA.replace('\n  tag_family TEXT NOT NULL, UNIQUE', ' UNIQUE'), v11: true }), DEV);
  assert.equal(noFam.ok, false); assert.match(String(noFam.checks.rl2_layout), /tag_family/);
});

// ---- the logical digest carries cross_links (writer.py TABLES_IN_DIGEST, between spine and events)
test('D1 the logical digest covers cross_links, between spine and events; a seed without the table digests as before', () => {
  assert.deepEqual(L.TABLES_IN_DIGEST, ['packages', 'lineages', 'lineage_state', 'spine', 'cross_links', 'events', 'dep_names',
    'known_malicious_pins', 'seed_metadata']);
  assert.equal(L.ORDER.cross_links, 'lineage_id, ord');
  const chains = [{ key: '2', family: 'release', rows: [['2.0.0', 100], ['2.1.0', 300]] },
    { key: '2', family: 'beta', rows: [['2.1.0-beta.1', 200]] }];
  const link = { lineage: 0, ord: 1, pred_lineage: 1, pred_ord: 0, pred_version: '2.1.0-beta.1' };
  const a = L.logicalDigestOfDb(buildSeed(chains, [link]));
  const b = L.logicalDigestOfDb(buildSeed(chains, [{ ...link, pred_size_bytes: 7 }]));
  assert.notEqual(a, b, 'a cross-link field is inside the digest');
});

// ---- every history case: the checker reads each recorded row's predecessor from the seed form
test('H1 every history case: predecessorOf gives the rule of record\'s predecessor for every recorded row', () => {
  const d = RL2();
  assert.equal(d.history_cases.length, 15);
  for (const c of d.history_cases) {
    const at = Object.fromEntries(c.rows.map((r) => [r.version, r.published_at === null ? null : epoch(r.published_at)]));
    const chains = c.expected.lineages.map((l) => ({ key: l.lineage_key, family: l.tag_family,
      rows: l.members.map((v) => [v, at[v]]) }));
    const db = new Database(buildSeed(chains, c.expected.cross_links, { k: c.k }), { readonly: true });
    try {
      const pv = C.loadPackage(db, 'p', {});
      c.expected.lineages.forEach((l, li) => {
        const lv = pv.lineages.get(li + 1);
        assert.equal(lv.tag_family, l.tag_family, `${c.name}: chain ${li}`);
        l.members.forEach((v, ord) => {
          const got = C.predecessorOf(pv, lv, { ord });
          const want = c.expected.predecessor[v];
          if (want === null) { assert.equal(got, null, `${c.name}: ${v} is a cold start`); return; }
          const [plv, po, srow] = got;
          assert.equal(c.expected.lineages[plv.lineage_id - 1].members[po], want, `${c.name}: ${v}`);
          const linked = c.expected.cross_links.some((x) => x.lineage === li && x.ord === ord);
          // a cross-link always carries its target's spine fields, even beyond the tail; an in-chain row beyond the tail has none
          if (linked) assert.equal(srow?.version, want, `${c.name}: ${v} carries its linked predecessor's spine fields`);
          else if (srow !== null) assert.equal(srow.version, want, `${c.name}: ${v}`);
        });
      });
    } finally { db.close(); }
  }
});

// ---- every placement case: a live release
test('P1 every placement case: placeRl2 gives the reference kind, and an append extends the expected predecessor', () => {
  const d = RL2();
  assert.equal(d.placement_cases.length, 13);
  assert.equal(G.PLACEMENT_RULE_VERSION, 'rl2-placement-1.0');
  for (const c of d.placement_cases) {
    const p = G.placeRl2(c.lineages, c.candidate.version, c.candidate.published_s ?? null,
      { holdingDescription: c.candidate.holding_description === true });
    assert.equal(p.kind, c.expected.kind, `${c.name}: ${p.reason}`);
    assert.equal(p.ord, null);
    const tip = c.lineages.find((l) => l.id === p.lineage_id);
    assert.equal(tip ? tip.last_version : null, c.expected.predecessor_version, c.name);
    assert.equal(p.channel_a_usable, p.kind === 'append', c.name);
  }
});

// ---- the gate over a real 1.2 seed
test('G1 a live release after a prerelease tip appends to the prerelease chain and Channel-A compares against that tip', () => {
  const chains = [{ key: '2', family: 'release', rows: [['2.0.0', 1767225600]] },
    { key: '2', family: 'beta', rows: [['2.1.0-beta.1', 1767225700, 500]] }];
  const seed = R.openSeed(buildSeed(chains), DEV);
  try {
    const p = G.resolvePlacement(seed, 'p', '2.1.0', 1767225800);
    assert.deepEqual([p.kind, p.lineage_id], ['append', 2]);
    const pre = G.resolvePlacement(seed, 'p', '2.2.0-rc.1', 1767225800);
    assert.equal(pre.kind, 'new-family-cold-start', pre.reason);
    const own = G.resolvePlacement(seed, 'p', '2.1.0-beta.2', 1767225800);
    assert.deepEqual([own.kind, own.lineage_id], ['append', 2]);
    const rec = G.resolvePlacement(seed, 'p', '2.1.0-beta.1', 1767225700);
    assert.deepEqual([rec.kind, rec.lineage_id, rec.ord], ['recorded', 2, 0]);
    const stub = G.resolvePlacement(seed, 'p', '2.1.1', 1767225800, { holdingDescription: true });
    assert.equal(stub.kind, 'ineligible-stub');

    const out = G.evaluateCandidate(seed, { config: { on_unusable_input: 'BLOCK', on_no_evidence: 'WARN' }, domainVersionCount: 0 },
      { packageName: 'p', version: '2.1.0', rawManifest: manifestFor('2.1.0'), publishedAt: '2026-01-01T00:03:20.000Z' });
    assert.equal(out.placement.kind, 'append');
    assert.equal(out.finding.channel_a.predecessor_version, '2.1.0-beta.1');
    assert.equal(out.finding.channel_a.groups.size.value, true, 'the size is compared with the beta tip (500 -> 1000)');
    const held = G.evaluateCandidate(seed, { config: { on_unusable_input: 'BLOCK', on_no_evidence: 'WARN' }, domainVersionCount: 0 },
      { packageName: 'p', version: '2.1.1', rawManifest: manifestFor('2.1.1', { description: 'security holding package' }),
        publishedAt: '2026-01-01T00:03:20.000Z' });
    assert.equal(held.placement.kind, 'ineligible-stub', 'the holding description (a live release is always forward)');
  } finally { seed.close(); }
});

test('G2 a recorded release with a cross-link compares against the linked row of the other chain', () => {
  const chains = [{ key: '2', family: 'release', rows: [['2.0.0', 1767225600], ['2.1.0', 1767225800]] },
    { key: '2', family: 'beta', rows: [['2.1.0-beta.1', 1767225700, 500]] }];
  const link = { lineage: 0, ord: 1, pred_lineage: 1, pred_ord: 0, pred_version: '2.1.0-beta.1', pred_size_bytes: 500 };
  const seed = R.openSeed(buildSeed(chains, [link]), DEV);
  try {
    const out = G.evaluateCandidate(seed, { config: { on_unusable_input: 'BLOCK', on_no_evidence: 'WARN' }, domainVersionCount: 0 },
      { packageName: 'p', version: '2.1.0', rawManifest: manifestFor('2.1.0'), publishedAt: '2026-01-01T00:03:20.000Z' });
    assert.deepEqual([out.placement.kind, out.placement.lineage_id, out.placement.ord], ['recorded', 1, 1]);
    assert.equal(out.finding.channel_a.predecessor_version, '2.1.0-beta.1');
  } finally { seed.close(); }
});

const SCHEMA_1_1 = SCHEMA.replace('\n  tag_family TEXT NOT NULL, UNIQUE', ' UNIQUE').replace(/CREATE TABLE cross_links[^;]+;/, '');
const META_1_1 = { contract_version: 'cft-seed-v3-contract-1.1',
  rule_versions: JSON.stringify({ channel_a: OLD_A, dac_trajectory: 'dac-trajectory-1.0' }) };
const DROP_1_2 = ['lineage_rule_version', 'stub_detector_effective_at', 'storage_layout', 'tag_family_fixture'];

test('G3 a 1.1 seed reads and places exactly as before: one chain per major, a prerelease extends it', () => {
  assert.ok(!SCHEMA_1_1.includes('tag_family') && !SCHEMA_1_1.includes('cross_links'));
  const db11 = buildSeed([{ key: '2', family: 'release', rows: [['2.0.0', 1767225600]] }], [],
    { tables: SCHEMA_1_1, v11: true, meta: META_1_1, drop: DROP_1_2 });
  const seed = R.openSeed(db11, DEV);
  try {
    const p = G.resolvePlacement(seed, 'p', '2.1.0-beta.1', 1767225800);
    assert.deepEqual([p.kind, p.lineage_id], ['append', 1]);
    const pv = seed.package('p');
    assert.equal(pv.lineages.get(1).tag_family, 'release');
    assert.deepEqual([...pv.lineages.get(1).cross_links], []);
  } finally { seed.close(); }
  // a 1.2 seed that does not declare pipekey1 is refused (the reverse pairing of R2)
  const rep = R.verify(buildSeed([{ key: '2', family: 'release', rows: [['2.0.0', 1767225600]] }], [],
    { meta: { rule_versions: META_1_1.rule_versions } }), DEV);
  assert.equal(rep.ok, false); assert.match(String(rep.checks.rule_versions), /pipekey1/);
});

// ---- the check record (operator 2026-10-18): new-family-cold-start is a chaingate.check/4 value only, and a check against
// a 1.2 seed wrote /4 in 0.1.5 whether or not --tarball was given; /3 (0.1.4, published) is unchanged and never carries contract 1.2.
// Since 0.1.6 every check writes /5 (/4 under cft-policy-1.3), for any seed contract.
let Ajv2020 = null; try { Ajv2020 = createRequire(import.meta.url)('ajv/dist/2020.js'); } catch { /* not installed */ }
const V3DIR = path.join(HERE, '..', '..', 'seed', 'v3');
const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
const recordFor = (seed, version, published) => {
  const doc = { name: 'p', versions: { [version]: manifestFor(version) }, time: { [version]: published } };
  return buildCheckRecord({ seed, policy: { on_unusable_input: 'WARN', on_no_evidence: 'WARN' },
    domainVersionCount: 'from-packument', input: inputFromPackument(doc, 'p', version),
    request: { package: 'p', version }, tool: { name: 'chaingate', version: 'test' } });
};

test('K1 a check against a 1.2 seed writes chaingate.check/5 (0.1.5: /4), with or without a tarball; a new tag family is new-family-cold-start', () => {
  const chains = [{ key: '2', family: 'release', rows: [['2.0.0', 1767225600]] },
    { key: '2', family: 'beta', rows: [['2.1.0-beta.1', 1767225700, 500]] }];
  const seed = R.openSeed(buildSeed(chains), DEV);
  try {
    const cold = recordFor(seed, '2.2.0-rc.1', '2026-01-01T00:03:20.000Z');
    const app = recordFor(seed, '2.1.0', '2026-01-01T00:03:20.000Z');
    for (const r of [cold, app]) {
      assert.equal(r.schema, 'chaingate.check/5'); assert.equal(r.seed.contract_version, 'cft-seed-v3-contract-1.2');
      assert.deepEqual(recordCompatibility(r), []); assert.deepEqual(validateRecord(r), [], 'the CI consumer accepts it');
    }
    assert.equal(cold.explanation.structured.placement.kind, 'new-family-cold-start');
    assert.equal(app.explanation.structured.placement.kind, 'append');
    assert.equal(withTarball({ ...cold }, null).schema, 'chaingate.check/5');
    // the same record labelled /3 is not one: /3 carries neither contract 1.2 nor the new placement
    const as3 = { ...cold, schema: 'chaingate.check/3' };
    assert.ok(recordCompatibility(as3).some((x) => /seed\.contract_version/.test(x)));
    assert.ok(validateRecord(as3).some((x) => /candidate\.placement\.kind/.test(x) && /new-family-cold-start/.test(x)),
      'the consumer names the placement /3 lacks (a combination is checked only once the shape is valid)');
    assert.ok(validateRecord({ ...app, schema: 'chaingate.check/3' }).some((x) => /seed\.contract_version/.test(x)));
    if (Ajv2020) {
      const Ctor = Ajv2020.default || Ajv2020; const ajv = new Ctor({ strict: true, strictRequired: false, allErrors: true });
      ajv.addSchema(readJson(path.join(HERE, '..', 'fixtures', 'cft03', 'finding.schema.json')));
      const v5 = ajv.compile(readJson(path.join(V3DIR, 'chaingate-check-5.schema.json')));
      const v4 = ajv.compile(readJson(path.join(V3DIR, 'chaingate-check-4.schema.json')));
      const v3 = ajv.compile(readJson(path.join(V3DIR, 'chaingate-check-3.schema.json')));
      assert.ok(v5(cold), JSON.stringify(v5.errors)); assert.ok(v5(app), JSON.stringify(v5.errors));
      // the 0.1.5 shape is unchanged: the same record labelled /4 (it carries no retier member) is a /4 shape
      assert.ok(v4({ ...cold, schema: 'chaingate.check/4' }), JSON.stringify(v4.errors));
      assert.equal(v3({ ...cold, schema: 'chaingate.check/3' }), false, 'the /3 schema has no new-family-cold-start');
    }
  } finally { seed.close(); }
});

test('K2 a check against a 1.1 seed writes chaingate.check/5 since 0.1.6 (0.1.5 wrote /3)', () => {
  const seed = R.openSeed(buildSeed([{ key: '2', family: 'release', rows: [['2.0.0', 1767225600]] }], [],
    { tables: SCHEMA_1_1, v11: true, meta: META_1_1, drop: DROP_1_2 }), DEV);
  try {
    const r = recordFor(seed, '2.1.0', '2026-01-01T00:03:20.000Z');
    assert.equal(r.schema, 'chaingate.check/5'); assert.deepEqual(recordCompatibility(r), []); assert.deepEqual(validateRecord(r), []);
  } finally { seed.close(); }
});

// ---- known-malicious pins (the D4 lookup by name, for 1.2 as for 1.1)
test('PIN1 a 1.2 seed finds a pin by NAME: a pinned version of a package the seed does not represent BLOCKs, naming the advisory', () => {
  // seed v3.2 carries pins for packages with no `packages` row (206 rows, 42 packages, in the real 1408e015 seed); the 1.0
  // join made them invisible (D4). Package `u` has a pin and no `packages` row; `p` is represented and pinned too.
  const dbPath = buildSeed([{ key: '2', family: 'release', rows: [['2.0.0', 1767225600]] }]);
  const db = new Database(dbPath);
  db.prepare('INSERT INTO known_malicious_pins VALUES (?,?,?,?,?)').run(9001, '1.0.0', 'ADV-U-100', 'synthetic-fixture', 'u');
  db.prepare('INSERT INTO known_malicious_pins VALUES (?,?,?,?,?)').run(1, '2.0.1', 'ADV-P-201', 'synthetic-fixture', 'p');
  db.close();
  fs.writeFileSync(`${dbPath}.sha256`, `${R.sha256File(dbPath)}  chaingate-seed.db\n`);
  const seed = R.openSeed(dbPath, DEV);
  try {
    assert.equal(seed.meta.seed_contract_version, 'cft-seed-v3-contract-1.2');
    for (const config of [{ on_unusable_input: 'BLOCK', on_no_evidence: 'WARN' }, { on_unusable_input: 'WARN', on_no_evidence: 'WARN' }]) {
      for (const [name, version, adv] of [['u', '1.0.0', 'ADV-U-100'], ['p', '2.0.1', 'ADV-P-201']]) {
        const d = G.evaluateCandidate(seed, { config, domainVersionCount: 0 }, { packageName: name, version,
          rawManifest: manifestFor(version, { name }), publishedAt: '2026-01-01T00:03:20.000Z' }).decision;
        assert.equal(d.disposition, 'BLOCK', `${name}@${version} under ${config.on_unusable_input}`);
        const pin = d.results.find((x) => x.gate === 'seed-v3:known-malicious-pin');
        assert.ok(pin && JSON.stringify(pin).includes(adv), `${name}@${version} names ${adv}`);
      }
    }
  } finally { seed.close(); }
});
