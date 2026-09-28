// Hand-authored edge cases for the JS evaluator, written against synthetic seeds with controlled
// history. Agreement on 152,804 real candidates says the two implementations match; these pin the
// BOUNDARY semantics explicitly, where a real corpus may simply never land.
import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import K from '../../seed/v3/contract.js';
import C from '../../seed/v3/checker.js';

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
CREATE TABLE seed_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
`;

const GROUPS = ['publisher', 'provenance', 'install', 'git', 'deps'];
const ID_A = 'a'.repeat(64); const ID_B = 'b'.repeat(64);
const TUP_A = '1'.repeat(64); const TUP_B = '2'.repeat(64);

/** lineages: [{id, ord, n, firstS, lastS, initial:{grp:state}, events:[], spine:[]}] */
function buildSeed(lineages, pkg = 'p') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft04-edge-'));
  const dbPath = path.join(dir, 'seed.db');
  const db = new Database(dbPath);
  db.exec(SCHEMA);
  db.prepare('INSERT INTO packages VALUES (?,?,?,?,?)').run(1, pkg, null, lineages.length, '');
  for (const l of lineages) {
    db.prepare('INSERT INTO lineages VALUES (?,?,?,?,?,?,?,?,?)')
      .run(l.id, 1, l.ord, String(l.id), 'v0', 'vN', l.n, l.firstS, l.lastS);
    for (const g of GROUPS) {
      db.prepare('INSERT INTO lineage_state VALUES (?,?,?)').run(l.id, g, JSON.stringify(l.initial[g] || {}));
    }
    for (const e of l.events || []) {
      db.prepare('INSERT INTO events VALUES (?,?,?,?,?,?,?)')
        .run(l.id, e.grp, e.ord, `v${e.ord}`, e.published_s, JSON.stringify(e.after), Buffer.alloc(32));
    }
    for (const s of l.spine || []) {
      db.prepare('INSERT INTO spine VALUES (?,?,?,?,?,?,?,?,?,?)')
        .run(l.id, s.ord, `v${s.ord}`, s.published_s, 0, s.size_bytes ?? null, s.tool_key ?? null,
          null, 'LIVE', Buffer.alloc(32));
    }
  }
  db.close();
  return dbPath;
}

function evaluate(dbPath, cand, pkg = 'p') {
  const db = new Database(dbPath, { readonly: true });
  try {
    const pv = C.loadPackage(db, pkg, {});
    return C.check(pv, { tool_name: '', tool_key: 0, maint_digest: '', body_digest: '',
      publish_method: '', provider_class: 'unknown', provenance_present: false, has_scripts: false,
      head_present: false, identity_digest: null, tuple_digest: null, repo_digest: null,
      size_bytes: null, ...cand }, {});
  } finally { db.close(); }
}

const ONE = (over = {}) => [{
  id: 1, ord: 0, n: 3, firstS: 1000, lastS: 3000,
  initial: { publisher: { identity_digest: ID_A, tuple_digest: TUP_A, maint_digest: 'c'.repeat(32), tool_name: 'npm' },
    provenance: { present: true }, install: { has_scripts: false, body_digest: '' }, git: { head_present: true, repo_digest: null }, deps: {} },
  spine: [{ ord: 0, published_s: 1000, size_bytes: 1000, tool_key: 100 },
    { ord: 1, published_s: 2000, size_bytes: 1000, tool_key: 100 },
    { ord: 2, published_s: 3000, size_bytes: 1000, tool_key: 100 }],
  ...over,
}];

// --- Channel-A size: the 50 % boundary is INCLUSIVE both ways --------------------------------------
test('Channel-A size break is inclusive at exactly +/-50 %', () => {
  const db = buildSeed(ONE());
  const at = (size) => evaluate(db, { package_name: 'p', version: 'x', published_s: 4000, lineage_id: 1, ord: 2, size_bytes: size })
    .channel_a.groups.size;
  assert.strictEqual(at(1500).value, true, 'exactly +50 % must break');
  assert.strictEqual(at(500).value, true, 'exactly -50 % must break');
  assert.strictEqual(at(1499).value, false);
  assert.strictEqual(at(501).value, false);
});

test('a predecessor with no positive size is unsupported_field, not a silent pass', () => {
  const l = ONE()[0]; l.spine = [{ ord: 0, published_s: 1000, size_bytes: 0, tool_key: 100 },
    { ord: 1, published_s: 2000, size_bytes: null, tool_key: 100 }];
  const db = buildSeed([{ ...l, n: 2 }]);
  const g = evaluate(db, { package_name: 'p', version: 'x', published_s: 4000, lineage_id: 1, ord: 1, size_bytes: 9999 })
    .channel_a.groups.size;
  assert.strictEqual(g.value, null);
  assert.strictEqual(g.reason, K.UNSUPPORTED_FIELD);
});

test('a predecessor outside the K-spine is beyond_spine', () => {
  const l = ONE()[0]; l.n = 50; l.spine = [{ ord: 48, published_s: 4800, size_bytes: 1000, tool_key: 100 },
    { ord: 49, published_s: 4900, size_bytes: 1000, tool_key: 100 }];
  const db = buildSeed([l]);
  const g = evaluate(db, { package_name: 'p', version: 'x', published_s: 5000, lineage_id: 1, ord: 10, size_bytes: 1 })
    .channel_a.groups.size;
  assert.strictEqual(g.reason, K.BEYOND_SPINE);
});

// --- DAC size jump: the 5x boundary is INCLUSIVE ----------------------------------------------------
test('DAC size_jump_5x is inclusive at exactly 5x', () => {
  const db = buildSeed(ONE());
  const at = (size) => evaluate(db, { package_name: 'p', version: 'x', published_s: 4000, lineage_id: 1, ord: null, size_bytes: size })
    .dac_trajectory.predicates.size_jump_5x;
  assert.strictEqual(at(5000).value, true, 'exactly 5x must fire');
  assert.strictEqual(at(4999).value, false);
});

test('a size tie ACROSS lineages is ambiguous rather than broken by lineage id', () => {
  const base = ONE()[0];
  const other2 = (b) => ({ id: 2, ord: 1, n: 1, firstS: 2500, lastS: 2500,
    initial: b.initial, spine: [{ ord: 0, published_s: 2500, size_bytes: 10000, tool_key: 100 }] });
  const first = { ...base, spine: [{ ord: 0, published_s: 2500, size_bytes: 100, tool_key: 100 }], n: 1, firstS: 2500, lastS: 2500 };
  const db = buildSeed([first, other2(base)]);
  // Both stored rows sit at the SAME second in different lineages, and the two candidate references
  // disagree: 1000/100 = 10x fires, 1000/10000 = 0.1x does not. The tie therefore decides the answer.
  const p = evaluate(db, { package_name: 'p', version: 'x', published_s: 3000, lineage_id: 99, ord: null, size_bytes: 1000 })
    .dac_trajectory.predicates.size_jump_5x;
  assert.strictEqual(p.value, null);
  assert.strictEqual(p.reason, K.AMBIGUOUS_ORDER);
  assert.deepStrictEqual(p.evidence.reference_sizes, [100, 10000]);
});

test('a size tie whose outcome does NOT depend on the choice stays determinate', () => {
  const base = ONE()[0];
  const first = { ...base, spine: [{ ord: 0, published_s: 2500, size_bytes: 1000, tool_key: 100 }], n: 1, firstS: 2500, lastS: 2500 };
  const other = { id: 2, ord: 1, n: 1, firstS: 2500, lastS: 2500, initial: base.initial,
    spine: [{ ord: 0, published_s: 2500, size_bytes: 10, tool_key: 100 }] };
  const db = buildSeed([first, other]);
  // 5000/1000 = 5x and 5000/10 = 500x both fire, so the undecidable order changes nothing.
  const p = evaluate(db, { package_name: 'p', version: 'x', published_s: 3000, lineage_id: 99, ord: null, size_bytes: 5000 })
    .dac_trajectory.predicates.size_jump_5x;
  assert.strictEqual(p.value, true);
});

// --- publisher dedup and tri-state -----------------------------------------------------------------
test('the publisher group is ONE witness however many constituents break', () => {
  const db = buildSeed(ONE());
  // Everything else is held at the predecessor's value so ONLY the publisher constituents can break.
  const f = evaluate(db, { package_name: 'p', version: 'x', published_s: 4000, lineage_id: 1, ord: 2,
    identity_digest: ID_B, maint_digest: 'd'.repeat(32), tool_name: 'npm', tool_key: 1,
    provenance_present: true, has_scripts: false, head_present: true, size_bytes: 1000 });
  const cons = f.channel_a.publisher_constituents;
  assert.strictEqual(cons.identity.value, true);
  assert.strictEqual(cons.maintainers.value, true);
  assert.strictEqual(cons.tool_downgrade.value, true);
  assert.strictEqual(f.channel_a.groups.publisher.value, true);
  assert.strictEqual(f.channel_a.n_broke, 1, 'three broken constituents still count once');
  assert.strictEqual(f.channel_a.n_evaluable, 5);
  assert.strictEqual(f.channel_a.M, 5);
});

test('an unevaluable constituent survives a determinate publisher group', () => {
  const l = ONE()[0];
  l.initial.publisher = { identity_digest: ID_A, tuple_digest: TUP_A, maint_digest: '', tool_name: 'npm' };
  const db = buildSeed([l]);
  const f = evaluate(db, { package_name: 'p', version: 'x', published_s: 4000, lineage_id: 1, ord: 2,
    identity_digest: ID_B, tool_name: 'npm', tool_key: 100 });
  assert.strictEqual(f.channel_a.groups.publisher.value, true);
  assert.strictEqual(f.channel_a.publisher_constituents.maintainers.value, null);
  assert.strictEqual(f.channel_a.publisher_constituents.maintainers.reason, K.UNSUPPORTED_FIELD);
});

test('an indeterminate threshold retains its interval', () => {
  const db = buildSeed(ONE());
  // uncovered package: nothing evaluable, so critical(3) of 5 is indeterminate over [0, 5]
  const f = evaluate(db, { package_name: 'p', version: 'x', published_s: 4000, lineage_id: 999, ord: null });
  const crit = f.channel_a.thresholds.find((t) => t.name === 'critical');
  assert.strictEqual(crit.threshold_result, null);
  assert.strictEqual(crit.threshold_determinacy, 'indeterminate');
  assert.deepStrictEqual(crit.interval, [0, 5]);
});

// --- coverage states that must never read as "clean" ------------------------------------------------
test('cold start: ord 0 has no FU-2 predecessor', () => {
  const db = buildSeed(ONE());
  const f = evaluate(db, { package_name: 'p', version: 'x', published_s: 900, lineage_id: 1, ord: 0 });
  for (const g of Object.values(f.channel_a.groups)) {
    assert.strictEqual(g.coverage, 'NOT_EVALUATED');
    assert.strictEqual(g.reason, K.COLD_START);
  }
  assert.strictEqual(f.channel_a.n_broke, 0);
});

test('a candidate with no publication time cannot be placed in package history', () => {
  const db = buildSeed(ONE());
  const f = evaluate(db, { package_name: 'p', version: 'x', published_s: null, lineage_id: 1, ord: 2 });
  for (const p of Object.values(f.dac_trajectory.predicates)) {
    assert.strictEqual(p.reason, K.MISSING_PUBLICATION_TIME);
  }
});

test('zero_history when nothing precedes the candidate', () => {
  const l = ONE()[0]; l.n = 1; l.spine = [{ ord: 0, published_s: 1000, size_bytes: 1000, tool_key: 100 }];
  const db = buildSeed([l]);
  const f = evaluate(db, { package_name: 'p', version: 'x', published_s: 1000, lineage_id: 1, ord: 0 });
  assert.strictEqual(f.dac_trajectory.predicates.install_introduced.reason, K.ZERO_HISTORY);
});

// --- install/provenance/git direction ---------------------------------------------------------------
test('witnesses fire on the DIRECTION the contract states, not on any change', () => {
  const db = buildSeed(ONE());
  const base = { package_name: 'p', version: 'x', published_s: 4000, lineage_id: 1, ord: 2 };
  // predecessor: provenance present, no scripts, gitHead present
  const f = evaluate(db, { ...base, provenance_present: false, has_scripts: true, head_present: false });
  assert.strictEqual(f.channel_a.groups.provenance.value, true, 'provenance DROP fires');
  assert.strictEqual(f.channel_a.groups.install.value, true, 'install INTRODUCTION fires');
  assert.strictEqual(f.channel_a.groups.git.value, true, 'gitHead DISAPPEARANCE fires');
  const g = evaluate(db, { ...base, provenance_present: true, has_scripts: false, head_present: true });
  assert.strictEqual(g.channel_a.groups.provenance.value, false, 'gaining provenance is not a break');
  assert.strictEqual(g.channel_a.groups.install.value, false, 'losing scripts is not a break');
  assert.strictEqual(g.channel_a.groups.git.value, false, 'gaining gitHead is not a break');
});

test('a repository-digest change alone never adds a git witness', () => {
  const db = buildSeed(ONE());
  const f = evaluate(db, { package_name: 'p', version: 'x', published_s: 4000, lineage_id: 1, ord: 2,
    head_present: true, repo_digest: 'f'.repeat(64) });
  assert.strictEqual(f.channel_a.groups.git.value, false);
  assert.strictEqual(f.channel_a.groups.git.evidence.repo_digest_changed, true, 'recorded, but not a break');
});

// --- dependency novelty is out of scope, and says so -------------------------------------------------
test('install_body is recorded evidence and never counts toward N', () => {
  const db = buildSeed(ONE());
  const f = evaluate(db, { package_name: 'p', version: 'x', published_s: 4000, lineage_id: 1, ord: 2,
    body_digest: 'e'.repeat(32) });
  assert.strictEqual(f.channel_a.install_body.counts_toward_n, false);
  assert.strictEqual(f.channel_a.M, 5);
});

test('no finding carries a disposition', () => {
  const db = buildSeed(ONE());
  const f = evaluate(db, { package_name: 'p', version: 'x', published_s: 4000, lineage_id: 1, ord: 2 });
  const blob = JSON.stringify(f);
  assert.ok(!('disposition' in f));
  for (const w of ['"ALLOW"', '"WARN"', '"BLOCK"']) assert.ok(!blob.includes(w), `${w} must not appear`);
});
