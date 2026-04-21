import { test } from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import provenance, {
  MIN_BASELINE_STREAK,
  MACHINE_PUBLISHER_EMAIL,
  normalizeAndSortHistory,
  computeStreakSignals,
  extractPriorBaselineCarriers,
  assemblePerVersionRecord,
  assemblePackageRollup,
} from '../../patterns/provenance.js';
import { PATTERN_REGISTRY, validatePattern } from '../../patterns/index.js';

// ---------------------------------------------------------------------------
// Test helper — build a synthetic history where each entry is shorthand
// for an attested ('A'), unsigned ('U'), or unknown ('N') version at a
// monotonically increasing timestamp. Versions auto-generated as
// 1.0.N so compareSemver tiebreaks stay sensible on identical-ts cases.
// ---------------------------------------------------------------------------
function buildHistory(shorthand, { startTs = 1_000_000_000, stepMs = 1000 } = {}) {
  return shorthand.map((kind, i) => {
    const provenance_present = kind === 'A' ? 1 : kind === 'U' ? 0 : null;
    return {
      version: `1.0.${i}`,
      published_at_ms: startTs + i * stepMs,
      provenance_present,
    };
  });
}

function walk(shorthand) {
  const { rows } = normalizeAndSortHistory(buildHistory(shorthand));
  return computeStreakSignals(rows);
}

// ---------------------------------------------------------------------------
// Seed-DB helper for canonical cases. Loads all rows for a package,
// optionally filtered by a version predicate, and returns them in the
// provenance.extract() input shape. Mirrors the row mapping from
// validation/run-validation.js loadPackageHistory() so canonical
// tests exercise the same ingest path as the validation runner.
// ---------------------------------------------------------------------------
const SEED_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  'seed_export',
  'chaingate-seed.db',
);
const HAS_SEED = existsSync(SEED_PATH);

function loadSeedHistory(packageName, versionFilter = null) {
  const db = new Database(SEED_PATH, { readonly: true });
  try {
    const pkg = db
      .prepare('SELECT id FROM packages WHERE package_name = ?')
      .get(packageName);
    if (!pkg) throw new Error(`package not in seed: ${packageName}`);
    const rows = db
      .prepare(
        `SELECT version, published_at, publisher_name, publisher_email,
                provenance_present
         FROM versions WHERE package_id = ?`,
      )
      .all(pkg.id);
    const mapped = rows.map((r) => ({
      version: r.version,
      published_at_ms: r.published_at ? Date.parse(r.published_at) : null,
      publisher_name: r.publisher_name,
      publisher_email: r.publisher_email,
      provenance_present: r.provenance_present,
    }));
    return versionFilter ? mapped.filter((r) => versionFilter(r.version)) : mapped;
  } finally {
    db.close();
  }
}

function findVersion(perVersion, version) {
  const v = perVersion.find((r) => r.version === version);
  if (!v) throw new Error(`version ${version} not in perVersion output`);
  return v;
}

// ---------------------------------------------------------------------------
// Contract tests — skeleton is importable and satisfies the registry shape.
// These run unconditionally; they exercise the parts of the module that
// exist in Phase 1 (metadata + input validation).
// ---------------------------------------------------------------------------

test('provenance: module satisfies the pattern contract', () => {
  assert.doesNotThrow(() => validatePattern(provenance));
  assert.equal(provenance.name, 'provenance');
  assert.equal(provenance.version, 1);
  assert.ok(Array.isArray(provenance.requires));
  assert.ok(provenance.requires.includes('history'));
  assert.equal(typeof provenance.extract, 'function');
});

test('provenance: registered in the pattern registry', () => {
  assert.strictEqual(PATTERN_REGISTRY.provenance, provenance);
});

test('provenance: starter constants exported at expected values', () => {
  assert.equal(MIN_BASELINE_STREAK, 3);
  assert.equal(MACHINE_PUBLISHER_EMAIL, 'npm-oidc-no-reply@github.com');
});

// ---------------------------------------------------------------------------
// Input validation tests — extract() must reject malformed input before
// any Phase 2 logic gets a chance to crash on it.
// ---------------------------------------------------------------------------

test('provenance.extract: rejects non-object input', () => {
  assert.throws(() => provenance.extract(null), /non-null object/);
  assert.throws(() => provenance.extract(undefined), /non-null object/);
  assert.throws(() => provenance.extract('axios'), /non-null object/);
  assert.throws(() => provenance.extract(42), /non-null object/);
});

test('provenance.extract: rejects missing or empty packageName', () => {
  assert.throws(() => provenance.extract({ history: [] }), /packageName/);
  assert.throws(() => provenance.extract({ packageName: '', history: [] }), /packageName/);
  assert.throws(() => provenance.extract({ packageName: 123, history: [] }), /packageName/);
});

test('provenance.extract: rejects non-array history', () => {
  assert.throws(
    () => provenance.extract({ packageName: 'axios' }),
    /history must be an array/,
  );
  assert.throws(
    () => provenance.extract({ packageName: 'axios', history: 'nope' }),
    /history must be an array/,
  );
  assert.throws(
    () => provenance.extract({ packageName: 'axios', history: {} }),
    /history must be an array/,
  );
});

test('provenance.extract: empty history returns locked contract shape with zero-valued rollup', () => {
  // Flipped at Step 5 — the Phase-1 "not yet implemented" guard is
  // gone. Valid input with empty history must return the full three-
  // key output ({ perVersion, packageRollup, signals }) with
  // everything zero / null on the optional fields. No throw.
  const out = provenance.extract({ packageName: 'axios', history: [] });
  assert.deepEqual(Object.keys(out).sort(), ['packageRollup', 'perVersion', 'signals']);
  assert.deepEqual(out.perVersion, []);
  assert.equal(out.packageRollup.total_versions, 0);
  assert.strictEqual(out.packageRollup.first_attested_version, null);
  assert.strictEqual(out.packageRollup.first_baseline_reached_at, null);
  assert.equal(out.signals.skipped, 0);
  assert.equal(out.signals.has_sufficient_history, false);
  assert.equal(out.signals.min_baseline_streak, MIN_BASELINE_STREAK);
});

test('provenance.extract: deterministic on identical input (byte-identical JSON)', () => {
  const input = {
    packageName: 'axios',
    history: [
      { version: '1.0.0', published_at_ms: 100, provenance_present: 1 },
      { version: '1.0.1', published_at_ms: 200, provenance_present: 1 },
    ],
  };
  const a = provenance.extract(input);
  const b = provenance.extract(input);
  assert.equal(JSON.stringify(a), JSON.stringify(b));
});

// ---------------------------------------------------------------------------
// Step 1 — normalizeAndSortHistory
// Row validation, null coercion, and deterministic sort (published_at_ms
// ASC, compareSemver ASC). Tiebreaker finalized here: semver ASC, no id.
// ---------------------------------------------------------------------------

test('normalizeAndSortHistory: sorts by published_at_ms ASC', () => {
  const { rows } = normalizeAndSortHistory([
    { version: '1.0.1', published_at_ms: 200, provenance_present: 1 },
    { version: '1.0.0', published_at_ms: 100, provenance_present: 1 },
    { version: '1.0.2', published_at_ms: 300, provenance_present: 0 },
  ]);
  assert.deepEqual(
    rows.map((r) => r.version),
    ['1.0.0', '1.0.1', '1.0.2'],
  );
});

test('normalizeAndSortHistory: tiebreaks identical timestamps by semver ASC', () => {
  const { rows } = normalizeAndSortHistory([
    { version: '1.0.2', published_at_ms: 100, provenance_present: 1 },
    { version: '1.0.0', published_at_ms: 100, provenance_present: 1 },
    { version: '1.0.10', published_at_ms: 100, provenance_present: 1 },
    { version: '1.0.1', published_at_ms: 100, provenance_present: 1 },
  ]);
  // Semver-aware: 1.0.10 sorts after 1.0.2, not lexically before.
  assert.deepEqual(
    rows.map((r) => r.version),
    ['1.0.0', '1.0.1', '1.0.2', '1.0.10'],
  );
});

test('normalizeAndSortHistory: deterministic across re-runs on tied timestamps', () => {
  const input = [
    { version: '2.0.0', published_at_ms: 500, provenance_present: 1 },
    { version: '1.9.0', published_at_ms: 500, provenance_present: 1 },
    { version: '1.5.0', published_at_ms: 500, provenance_present: 0 },
  ];
  const a = normalizeAndSortHistory(input);
  const b = normalizeAndSortHistory(input);
  assert.equal(JSON.stringify(a), JSON.stringify(b));
});

test('normalizeAndSortHistory: coerces provenance_present to strict boolean', () => {
  const { rows } = normalizeAndSortHistory([
    { version: '1.0.0', published_at_ms: 100, provenance_present: 1 },
    { version: '1.0.1', published_at_ms: 200, provenance_present: true },
    { version: '1.0.2', published_at_ms: 300, provenance_present: 0 },
    { version: '1.0.3', published_at_ms: 400, provenance_present: false },
  ]);
  assert.equal(rows[0].provenance_present, true);
  assert.equal(rows[1].provenance_present, true);
  assert.equal(rows[2].provenance_present, false);
  assert.equal(rows[3].provenance_present, false);
});

test('normalizeAndSortHistory: preserves null provenance_present as null (UNKNOWN)', () => {
  const { rows } = normalizeAndSortHistory([
    { version: '1.0.0', published_at_ms: 100, provenance_present: null },
    { version: '1.0.1', published_at_ms: 200, provenance_present: undefined },
    { version: '1.0.2', published_at_ms: 300 },
    { version: '1.0.3', published_at_ms: 400, provenance_present: 'yes' },
  ]);
  // Every non-0/1/true/false value normalizes to null — the "UNKNOWN"
  // bucket. This is the load-bearing NULL-semantics invariant from the
  // GATE CONTRACT; downstream MUST NOT see undefined or stringly values.
  for (const r of rows) {
    assert.strictEqual(r.provenance_present, null);
  }
});

test('normalizeAndSortHistory: skips rows missing version or published_at_ms', () => {
  const { rows, skipped } = normalizeAndSortHistory([
    { version: '1.0.0', published_at_ms: 100, provenance_present: 1 },
    { version: '', published_at_ms: 200, provenance_present: 1 }, // empty version
    { version: '1.0.1', published_at_ms: '200', provenance_present: 1 }, // string ts
    { published_at_ms: 300, provenance_present: 0 }, // missing version
    { version: '1.0.2', provenance_present: 0 }, // missing ts
    null, // non-object
    { version: '1.0.3', published_at_ms: 400, provenance_present: 1 },
  ]);
  assert.deepEqual(
    rows.map((r) => r.version),
    ['1.0.0', '1.0.3'],
  );
  assert.equal(skipped.count, 5);
  assert.equal(skipped.reasons.length, 5);
  // Reasons are index-tagged and ordered by input position.
  assert.deepEqual(
    skipped.reasons.map((r) => r.index),
    [1, 2, 3, 4, 5],
  );
});

test('normalizeAndSortHistory: does not require publisher_email on every row', () => {
  // GATE CONTRACT: a row with null publisher_email can still contribute
  // to the attested/unsigned streak. Only the regression-firing row
  // needs publisher_email for disposition-layer escalators.
  const { rows, skipped } = normalizeAndSortHistory([
    { version: '1.0.0', published_at_ms: 100, provenance_present: 1, publisher_email: null },
    { version: '1.0.1', published_at_ms: 200, provenance_present: 1 },
  ]);
  assert.equal(skipped.count, 0);
  assert.equal(rows.length, 2);
  assert.strictEqual(rows[0].publisher_email, null);
  assert.strictEqual(rows[1].publisher_email, null);
});

test('normalizeAndSortHistory: lowercases and trims publisher_email', () => {
  const { rows } = normalizeAndSortHistory([
    { version: '1.0.0', published_at_ms: 100, publisher_email: '  Foo@Bar.COM  ' },
  ]);
  assert.equal(rows[0].publisher_email, 'foo@bar.com');
});

test('normalizeAndSortHistory: rejects duplicate versions, keeps first occurrence in input order', () => {
  // Two rows claim '1.0.1'. The first (with prov=1, earlier ts) wins;
  // the second is skipped with reason 'duplicate_version'. This
  // matters because otherwise the sort could interleave them
  // arbitrarily when timestamps also match, breaking determinism.
  const { rows, skipped } = normalizeAndSortHistory([
    { version: '1.0.0', published_at_ms: 100, provenance_present: 1 },
    { version: '1.0.1', published_at_ms: 200, provenance_present: 1, publisher_email: 'first@example.com' },
    { version: '1.0.2', published_at_ms: 300, provenance_present: 1 },
    { version: '1.0.1', published_at_ms: 250, provenance_present: 0, publisher_email: 'second@example.com' },
    { version: '1.0.3', published_at_ms: 400, provenance_present: 1 },
  ]);
  assert.deepEqual(
    rows.map((r) => r.version),
    ['1.0.0', '1.0.1', '1.0.2', '1.0.3'],
  );
  // First occurrence survived — provenance_present=true, not false.
  const surviving = rows.find((r) => r.version === '1.0.1');
  assert.equal(surviving.provenance_present, true);
  assert.equal(surviving.publisher_email, 'first@example.com');
  assert.equal(skipped.count, 1);
  assert.equal(skipped.reasons.length, 1);
  assert.deepEqual(skipped.reasons[0], { index: 3, reason: 'duplicate_version' });
});

test('normalizeAndSortHistory: returns empty arrays on empty input', () => {
  const { rows, skipped } = normalizeAndSortHistory([]);
  assert.deepEqual(rows, []);
  assert.equal(skipped.count, 0);
  assert.deepEqual(skipped.reasons, []);
});

// ---------------------------------------------------------------------------
// Step 2 — computeStreakSignals (direct-unit tests)
// Walker semantics exercised without sufficiency gating. Sufficiency
// short-circuit is a Step-5 concern (below-sufficiency fixture runs
// at the extract() level where has_sufficient_history is computed).
// ---------------------------------------------------------------------------

test('computeStreakSignals: empty history → empty signals', () => {
  assert.deepEqual(computeStreakSignals([]), []);
});

test('computeStreakSignals: null row preserves streak (UNKNOWN)', () => {
  // Run: A, A, N, A, U → at the final U, prior streak should still be 3
  // (the null did not reset, nor did it contribute). baseline_established
  // therefore true at U → regression fires.
  const sig = walk(['A', 'A', 'N', 'A', 'U']);
  const u = sig[4];
  assert.equal(u.prior_consecutive_attested, 3);
  assert.equal(u.baseline_established, true);
  assert.equal(u.provenance_regression, true);
});

test('computeStreakSignals: null row does NOT fire regression even on established baseline', () => {
  // A, A, A, N → at the N, baseline_established=true but
  // provenance_regression=false because provenance_present!==false.
  const sig = walk(['A', 'A', 'A', 'N']);
  const n = sig[3];
  assert.equal(n.baseline_established, true);
  assert.equal(n.provenance_regression, false);
});

test('computeStreakSignals: in_scope flips true at the K-th attested version (monotonic thereafter)', () => {
  // A, A, A, U, A, U → in_scope becomes true AT the 3rd A (index 2)
  // and stays true for every subsequent version.
  const sig = walk(['A', 'A', 'A', 'U', 'A', 'U']);
  assert.deepEqual(
    sig.map((s) => s.in_scope),
    [false, false, true, true, true, true],
  );
});

// ---------------------------------------------------------------------------
// Synthetic fixtures — un-skipped for Step 2. Each mirrors the matching
// entry in docs/PATTERNS_PROVENANCE.md Task 3.
// below-sufficiency and timestamp-tie stay skipped until Step 5 (they
// exercise the full extract() pipeline — sufficiency gate + byte-
// identical rollup respectively).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Synthetic edge-case fixtures — docs/PATTERNS_PROVENANCE.md Task 3.
// All skipped until Phase 2 implements extract(). Each stub documents
// the exact expected signal at the terminal version so the test body is
// ready to un-skip once the walker exists.
// ---------------------------------------------------------------------------

test('fixture: baseline-boundary-fire (A,A,A,U → regression fires at last)', () => {
  const sig = walk(['A', 'A', 'A', 'U']);
  const u = sig[3];
  assert.equal(u.prior_consecutive_attested, 3);
  assert.equal(u.baseline_established, true);
  assert.equal(u.provenance_regression, true);
});

test('fixture: baseline-boundary-silent (A,A,U → no regression, streak short)', () => {
  const sig = walk(['A', 'A', 'U']);
  const u = sig[2];
  assert.equal(u.prior_consecutive_attested, 2);
  assert.equal(u.baseline_established, false);
  assert.equal(u.provenance_regression, false);
  // baseline never reached → in_scope stays false throughout.
  assert.deepEqual(
    sig.map((s) => s.in_scope),
    [false, false, false],
  );
});

test('fixture: alternating-stress (A,U × 7 → streak never reaches K, all silent)', () => {
  const sig = walk(Array.from({ length: 14 }, (_, i) => (i % 2 === 0 ? 'A' : 'U')));
  // Every U has priorStreak in {0, 1} — never reaches K=3.
  for (const s of sig) {
    assert.ok(
      s.prior_consecutive_attested < MIN_BASELINE_STREAK,
      `priorStreak at ${s.version} = ${s.prior_consecutive_attested}`,
    );
    assert.equal(s.provenance_regression, false);
    assert.equal(s.in_scope, false);
  }
});

test('fixture: all-attested (A × 10 → no regression ever; in_scope after K)', () => {
  const sig = walk(Array(10).fill('A'));
  assert.ok(sig.every((s) => !s.provenance_regression));
  // in_scope flips true at index K-1 (the 3rd version).
  assert.deepEqual(
    sig.map((s) => s.in_scope),
    [false, false, true, true, true, true, true, true, true, true],
  );
});

// ---------------------------------------------------------------------------
// Step 3 — extractPriorBaselineCarriers
// ---------------------------------------------------------------------------

test('extractPriorBaselineCarriers: empty streak → empty struct', () => {
  const c = extractPriorBaselineCarriers([], 0);
  assert.deepEqual(c, { identities: [], emails: [], any_machine: false, any_human: false });
});

test('extractPriorBaselineCarriers: streakLength 0 on non-empty rows → empty struct', () => {
  const rows = [{ publisher_name: 'alice', publisher_email: 'alice@example.com' }];
  const c = extractPriorBaselineCarriers(rows, 0);
  assert.equal(c.any_machine, false);
  assert.equal(c.any_human, false);
  assert.deepEqual(c.identities, []);
});

test('extractPriorBaselineCarriers: all-machine baseline (axios@1.14.1 shape)', () => {
  const rows = [
    { publisher_name: 'github-actions[bot]', publisher_email: 'npm-oidc-no-reply@github.com' },
    { publisher_name: 'github-actions[bot]', publisher_email: 'npm-oidc-no-reply@github.com' },
    { publisher_name: 'github-actions[bot]', publisher_email: 'npm-oidc-no-reply@github.com' },
    { publisher_name: 'github-actions[bot]', publisher_email: 'npm-oidc-no-reply@github.com' },
  ];
  const c = extractPriorBaselineCarriers(rows, 4);
  assert.equal(c.any_machine, true);
  assert.equal(c.any_human, false);
  assert.deepEqual(c.emails, ['npm-oidc-no-reply@github.com']);
  assert.deepEqual(c.identities, ['github-actions[bot]']);
});

test('extractPriorBaselineCarriers: all-human baseline (axios@1.13.3 shape)', () => {
  const rows = [
    { publisher_name: 'jasonsaayman', publisher_email: 'jasonsaayman@gmail.com' },
    { publisher_name: 'jasonsaayman', publisher_email: 'jasonsaayman@gmail.com' },
    { publisher_name: 'jasonsaayman', publisher_email: 'jasonsaayman@gmail.com' },
  ];
  const c = extractPriorBaselineCarriers(rows, 3);
  assert.equal(c.any_machine, false);
  assert.equal(c.any_human, true);
  assert.deepEqual(c.emails, ['jasonsaayman@gmail.com']);
});

test('extractPriorBaselineCarriers: mixed baseline — both flags true', () => {
  const rows = [
    { publisher_name: 'ci', publisher_email: MACHINE_PUBLISHER_EMAIL },
    { publisher_name: 'jane', publisher_email: 'jane@example.com' },
    { publisher_name: 'ci', publisher_email: MACHINE_PUBLISHER_EMAIL },
  ];
  const c = extractPriorBaselineCarriers(rows, 3);
  assert.equal(c.any_machine, true);
  assert.equal(c.any_human, true);
  // Emails are de-duplicated and sorted ASCII ASC.
  assert.deepEqual(c.emails, ['jane@example.com', 'npm-oidc-no-reply@github.com']);
  assert.deepEqual(c.identities, ['ci', 'jane']);
});

test('extractPriorBaselineCarriers: only last `streakLength` rows contribute', () => {
  // Total 5 rows, streakLength=3 → only the last 3 count. The leading
  // human rows are outside the streak window and MUST be ignored.
  const rows = [
    { publisher_name: 'old', publisher_email: 'old@example.com' },
    { publisher_name: 'old', publisher_email: 'old@example.com' },
    { publisher_name: 'ci', publisher_email: MACHINE_PUBLISHER_EMAIL },
    { publisher_name: 'ci', publisher_email: MACHINE_PUBLISHER_EMAIL },
    { publisher_name: 'ci', publisher_email: MACHINE_PUBLISHER_EMAIL },
  ];
  const c = extractPriorBaselineCarriers(rows, 3);
  assert.equal(c.any_machine, true);
  assert.equal(c.any_human, false);
  assert.deepEqual(c.emails, [MACHINE_PUBLISHER_EMAIL]);
});

test('extractPriorBaselineCarriers: null email rows do not count as machine OR human', () => {
  const rows = [
    { publisher_name: 'mystery', publisher_email: null },
    { publisher_name: 'mystery', publisher_email: null },
    { publisher_name: 'mystery', publisher_email: null },
  ];
  const c = extractPriorBaselineCarriers(rows, 3);
  assert.equal(c.any_machine, false);
  assert.equal(c.any_human, false);
  assert.deepEqual(c.emails, []);
  assert.deepEqual(c.identities, ['mystery']);
});

test('extractPriorBaselineCarriers: streakLength exceeds available rows → defensive slice', () => {
  const rows = [{ publisher_name: 'a', publisher_email: 'a@b.com' }];
  const c = extractPriorBaselineCarriers(rows, 99);
  assert.equal(c.any_human, true);
  assert.deepEqual(c.identities, ['a']);
});

// ---------------------------------------------------------------------------
// Step 4 — assemblePerVersionRecord + assemblePackageRollup
// ---------------------------------------------------------------------------

test('assemblePerVersionRecord: emits every contract field, carriers=null when missing', () => {
  const row = {
    version: '1.2.3',
    published_at_ms: 12345,
    publisher_name: 'alice',
    publisher_email: 'alice@example.com',
    publisher_tool: 'npm@10.8.2',
    provenance_present: true,
  };
  const streak = {
    prior_consecutive_attested: 0,
    baseline_established: false,
    provenance_regression: false,
    in_scope: false,
  };
  const rec = assemblePerVersionRecord(row, streak, null);
  assert.equal(rec.version, '1.2.3');
  assert.equal(rec.published_at_ms, 12345);
  assert.equal(rec.provenance_present, true);
  assert.equal(rec.prior_consecutive_attested, 0);
  assert.equal(rec.baseline_established, false);
  assert.equal(rec.provenance_regression, false);
  assert.equal(rec.in_scope, false);
  assert.strictEqual(rec.prior_baseline_carriers, null);
  assert.deepEqual(rec.incoming_publisher, {
    name: 'alice',
    email: 'alice@example.com',
    tool: 'npm@10.8.2',
  });
});

test('assemblePerVersionRecord: carriers struct passed through unchanged', () => {
  const carriers = {
    identities: ['github-actions[bot]'],
    emails: ['npm-oidc-no-reply@github.com'],
    any_machine: true,
    any_human: false,
  };
  const rec = assemblePerVersionRecord(
    { version: '1', published_at_ms: 1, publisher_name: null, publisher_email: null, publisher_tool: null, provenance_present: false },
    { prior_consecutive_attested: 3, baseline_established: true, provenance_regression: true, in_scope: true },
    carriers,
  );
  assert.strictEqual(rec.prior_baseline_carriers, carriers);
});

test('assemblePackageRollup: empty history → zero-valued rollup, nulls on optional version fields', () => {
  const rollup = assemblePackageRollup([], []);
  assert.deepEqual(rollup, {
    total_versions: 0,
    attested_versions: 0,
    max_consecutive_attested: 0,
    has_baseline_at_head: false,
    regression_versions: [],
    regression_count: 0,
    machine_attested_versions: 0,
    human_attested_versions: 0,
    first_attested_version: null,
    first_baseline_reached_at: null,
  });
});

test('assemblePackageRollup: axios 1.13.0→1.15.1 shape matches design-doc rollup', () => {
  // Synthetic replay of the 11-version axios train per
  // docs/PATTERNS_PROVENANCE.md Task 2 walk table. Establishes the
  // expected rollup field values so Step 5 extract() on the real
  // seed-loaded axios slice can be asserted against the same targets.
  const history = [
    { version: '1.13.0', published_at_ms: 1_000, publisher_email: 'jasonsaayman@gmail.com', provenance_present: 1 },
    { version: '1.13.1', published_at_ms: 2_000, publisher_email: 'jasonsaayman@gmail.com', provenance_present: 1 },
    { version: '1.13.2', published_at_ms: 3_000, publisher_email: 'jasonsaayman@gmail.com', provenance_present: 1 },
    { version: '1.13.3', published_at_ms: 4_000, publisher_email: 'jasonsaayman@gmail.com', provenance_present: 0 },
    { version: '1.13.4', published_at_ms: 5_000, publisher_email: MACHINE_PUBLISHER_EMAIL, provenance_present: 1 },
    { version: '1.13.5', published_at_ms: 6_000, publisher_email: MACHINE_PUBLISHER_EMAIL, provenance_present: 1 },
    { version: '1.13.6', published_at_ms: 7_000, publisher_email: MACHINE_PUBLISHER_EMAIL, provenance_present: 1 },
    { version: '1.14.0', published_at_ms: 8_000, publisher_email: MACHINE_PUBLISHER_EMAIL, provenance_present: 1 },
    { version: '1.14.1', published_at_ms: 9_000, publisher_email: 'ifstap@proton.me', provenance_present: 0 },
    { version: '1.15.0', published_at_ms: 10_000, publisher_email: MACHINE_PUBLISHER_EMAIL, provenance_present: 1 },
    { version: '1.15.1', published_at_ms: 11_000, publisher_email: MACHINE_PUBLISHER_EMAIL, provenance_present: 1 },
  ];
  const { rows } = normalizeAndSortHistory(history);
  const streaks = computeStreakSignals(rows);
  const perVersion = rows.map((row, i) =>
    assemblePerVersionRecord(row, streaks[i], null),
  );
  const rollup = assemblePackageRollup(perVersion, rows);
  assert.equal(rollup.total_versions, 11);
  assert.equal(rollup.attested_versions, 9);
  assert.equal(rollup.max_consecutive_attested, 4); // 1.13.4 → 1.14.0 is the longest run
  assert.equal(rollup.has_baseline_at_head, false); // only 1.15.0, 1.15.1 at end = 2 < 3
  assert.deepEqual(rollup.regression_versions, ['1.13.3', '1.14.1']);
  assert.equal(rollup.regression_count, 2);
  assert.equal(rollup.machine_attested_versions, 6);
  assert.equal(rollup.human_attested_versions, 3);
  assert.equal(rollup.first_attested_version, '1.13.0');
  assert.equal(rollup.first_baseline_reached_at, '1.13.2');
});

test('assemblePackageRollup: null rows neither extend nor break consecutive-attested run', () => {
  // A, A, N, A — max_consecutive_attested should be 3 (null passes
  // through without contributing or resetting). Mirrors the NULL-
  // semantics invariant from the GATE CONTRACT.
  const history = [
    { version: '1.0.0', published_at_ms: 100, provenance_present: 1 },
    { version: '1.0.1', published_at_ms: 200, provenance_present: 1 },
    { version: '1.0.2', published_at_ms: 300, provenance_present: null },
    { version: '1.0.3', published_at_ms: 400, provenance_present: 1 },
  ];
  const { rows } = normalizeAndSortHistory(history);
  const streaks = computeStreakSignals(rows);
  const perVersion = rows.map((row, i) =>
    assemblePerVersionRecord(row, streaks[i], null),
  );
  const rollup = assemblePackageRollup(perVersion, rows);
  assert.equal(rollup.max_consecutive_attested, 3);
  assert.equal(rollup.has_baseline_at_head, true); // streak at end = 3 (A,N,A treated as a run of 3)
});

test('assemblePackageRollup: null-email attested row counts toward attested but not machine/human', () => {
  const history = [
    { version: '1.0.0', published_at_ms: 100, publisher_email: null, provenance_present: 1 },
    { version: '1.0.1', published_at_ms: 200, publisher_email: MACHINE_PUBLISHER_EMAIL, provenance_present: 1 },
    { version: '1.0.2', published_at_ms: 300, publisher_email: 'human@example.com', provenance_present: 1 },
  ];
  const { rows } = normalizeAndSortHistory(history);
  const streaks = computeStreakSignals(rows);
  const perVersion = rows.map((row, i) =>
    assemblePerVersionRecord(row, streaks[i], null),
  );
  const rollup = assemblePackageRollup(perVersion, rows);
  assert.equal(rollup.attested_versions, 3);
  assert.equal(rollup.machine_attested_versions, 1);
  assert.equal(rollup.human_attested_versions, 1); // null-email row excluded from both
});

test('fixture: long-unsigned-tail (A,A,A,U×20 → only U₁ fires)', () => {
  const sig = walk(['A', 'A', 'A', ...Array(20).fill('U')]);
  // U₁ at index 3: priorStreak=3, fires.
  assert.equal(sig[3].provenance_regression, true);
  assert.equal(sig[3].prior_consecutive_attested, 3);
  // U₂..U₂₀ at indices 4..22: priorStreak=0, silent.
  for (let i = 4; i < sig.length; i += 1) {
    assert.equal(sig[i].prior_consecutive_attested, 0);
    assert.equal(sig[i].provenance_regression, false);
  }
  // Regression count = 1 (not 20).
  assert.equal(sig.filter((s) => s.provenance_regression).length, 1);
});

test('fixture: below-sufficiency (<MIN_HISTORY_DEPTH total → short-circuit)', () => {
  // 4 versions (A,A,A,U) — well under MIN_HISTORY_DEPTH=8. The
  // walker computes regression_at_the_U locally but extract()
  // suppresses it because signals.has_sufficient_history=false.
  const history = [
    { version: '1.0.0', published_at_ms: 100, provenance_present: 1 },
    { version: '1.0.1', published_at_ms: 200, provenance_present: 1 },
    { version: '1.0.2', published_at_ms: 300, provenance_present: 1 },
    { version: '1.0.3', published_at_ms: 400, provenance_present: 0 },
  ];
  const out = provenance.extract({ packageName: 'synthetic', history });
  assert.equal(out.signals.has_sufficient_history, false);
  // Every perVersion record has in_scope=false and no regression.
  for (const v of out.perVersion) {
    assert.equal(v.in_scope, false);
    assert.equal(v.provenance_regression, false);
    assert.equal(v.baseline_established, false);
    assert.strictEqual(v.prior_baseline_carriers, null);
  }
  assert.equal(out.packageRollup.regression_count, 0);
  assert.deepEqual(out.packageRollup.regression_versions, []);
});

test('fixture: timestamp-tie (two versions, same published_at_ms → deterministic order)', () => {
  // Two rows at the same ms; compareSemver resolves ordering
  // deterministically (1.0.0 < 1.0.1). Two runs produce byte-
  // identical JSON output — the pattern-cache determinism contract.
  const history = [
    { version: '1.0.1', published_at_ms: 500, provenance_present: 1 },
    { version: '1.0.0', published_at_ms: 500, provenance_present: 1 },
    { version: '1.0.2', published_at_ms: 600, provenance_present: 1 },
    { version: '1.0.3', published_at_ms: 700, provenance_present: 1 },
    { version: '1.0.4', published_at_ms: 800, provenance_present: 1 },
    { version: '1.0.5', published_at_ms: 900, provenance_present: 1 },
    { version: '1.0.6', published_at_ms: 1000, provenance_present: 1 },
    { version: '1.0.7', published_at_ms: 1100, provenance_present: 0 },
  ];
  const a = provenance.extract({ packageName: 'tied', history });
  const b = provenance.extract({ packageName: 'tied', history });
  assert.equal(JSON.stringify(a), JSON.stringify(b));
  // And the tied pair sorts by semver ASC inside the same ms.
  assert.deepEqual(
    a.perVersion.slice(0, 2).map((v) => v.version),
    ['1.0.0', '1.0.1'],
  );
});

// ---------------------------------------------------------------------------
// Canonical cases — docs/PATTERNS_PROVENANCE.md Task 3. Four real packages
// from the seed. All skipped until Phase 2. Each stub documents the
// expected top-level signal and disposition class.
// ---------------------------------------------------------------------------

test('canonical: axios@1.14.1 — regression + escalators (a,b,d) → BLOCK-class', { skip: !HAS_SEED }, () => {
  // Loads the 11-version axios 1.13.0→1.15.1 train from the seed
  // (reconstructed 1.14.1 attack row merged by collector/export_seed.py).
  const history = loadSeedHistory('axios', (v) => /^1\.1[345]\./.test(v));
  const out = provenance.extract({ packageName: 'axios', history });
  const v = findVersion(out.perVersion, '1.14.1');
  assert.equal(v.prior_consecutive_attested, 4);
  assert.equal(v.baseline_established, true);
  assert.equal(v.provenance_regression, true);
  assert.equal(v.in_scope, true);
  // Baseline carriers immediately prior to 1.14.1 are the 4 GitHub
  // Actions CI versions (1.13.4–1.14.0) — all-machine.
  assert.ok(v.prior_baseline_carriers !== null);
  assert.equal(v.prior_baseline_carriers.any_machine, true);
  assert.equal(v.prior_baseline_carriers.any_human, false);
  assert.deepEqual(v.prior_baseline_carriers.emails, [MACHINE_PUBLISHER_EMAIL]);
  // Incoming attack publisher.
  assert.equal(v.incoming_publisher.email, 'ifstap@proton.me');
  assert.equal(v.provenance_present, false);
});

test('canonical: axios@1.13.3 — regression, zero escalators → WARN-class', { skip: !HAS_SEED }, () => {
  const history = loadSeedHistory('axios', (v) => /^1\.1[345]\./.test(v));
  const out = provenance.extract({ packageName: 'axios', history });
  const v = findVersion(out.perVersion, '1.13.3');
  assert.equal(v.prior_consecutive_attested, 3);
  assert.equal(v.baseline_established, true);
  assert.equal(v.provenance_regression, true);
  assert.equal(v.in_scope, true);
  // Baseline carriers at 1.13.3 are 1.13.0/1/2 — all personal-OIDC
  // from jasonsaayman@gmail.com. any_machine must be FALSE to
  // preserve the WARN invariant (legitimate CLI during personal-
  // OIDC baseline → WARN, not BLOCK).
  assert.ok(v.prior_baseline_carriers !== null);
  assert.equal(v.prior_baseline_carriers.any_machine, false);
  assert.equal(v.prior_baseline_carriers.any_human, true);
  assert.deepEqual(v.prior_baseline_carriers.emails, ['jasonsaayman@gmail.com']);
  assert.equal(v.incoming_publisher.email, 'jasonsaayman@gmail.com');
});

test('canonical: axios rollup matches design-doc Task-2 target', { skip: !HAS_SEED }, () => {
  const history = loadSeedHistory('axios', (v) => /^1\.1[345]\./.test(v));
  const out = provenance.extract({ packageName: 'axios', history });
  assert.equal(out.packageRollup.total_versions, 11);
  assert.equal(out.packageRollup.attested_versions, 9);
  assert.equal(out.packageRollup.max_consecutive_attested, 4);
  assert.equal(out.packageRollup.has_baseline_at_head, false);
  assert.deepEqual(out.packageRollup.regression_versions, ['1.13.3', '1.14.1']);
  assert.equal(out.packageRollup.regression_count, 2);
  assert.equal(out.packageRollup.machine_attested_versions, 6);
  assert.equal(out.packageRollup.human_attested_versions, 3);
  assert.equal(out.packageRollup.first_attested_version, '1.13.0');
  assert.equal(out.packageRollup.first_baseline_reached_at, '1.13.2');
});

test('canonical: event-stream@3.3.6 — pre-OIDC era, pattern silent', { skip: !HAS_SEED }, () => {
  // Load the full event-stream history through 3.3.6. Package had no
  // provenance adoption at attack time (2018) — every row in the
  // stream has provenance_present in {0, null}, so the streak never
  // reaches K and baseline is never established.
  const history = loadSeedHistory('event-stream');
  const out = provenance.extract({ packageName: 'event-stream', history });
  const v = findVersion(out.perVersion, '3.3.6');
  assert.equal(v.baseline_established, false);
  assert.equal(v.provenance_regression, false);
  assert.equal(v.in_scope, false);
  assert.strictEqual(v.prior_baseline_carriers, null);
  // Rollup confirms the "never attested" shape at the package level.
  assert.equal(out.packageRollup.attested_versions, 0);
  assert.equal(out.packageRollup.max_consecutive_attested, 0);
  assert.strictEqual(out.packageRollup.first_baseline_reached_at, null);
  assert.equal(out.packageRollup.regression_count, 0);
});

test('canonical: lodash@4.17.16 — no OIDC history, must NOT false-positive', { skip: !HAS_SEED }, () => {
  const history = loadSeedHistory('lodash');
  const out = provenance.extract({ packageName: 'lodash', history });
  // Every version in the lodash history must be out-of-scope and
  // non-firing — the package never adopted provenance.
  for (const v of out.perVersion) {
    assert.equal(v.baseline_established, false, `baseline at ${v.version}`);
    assert.equal(v.provenance_regression, false, `regression at ${v.version}`);
    assert.equal(v.in_scope, false, `in_scope at ${v.version}`);
    assert.strictEqual(v.prior_baseline_carriers, null);
  }
  assert.equal(out.packageRollup.regression_count, 0);
  assert.equal(out.packageRollup.max_consecutive_attested, 0);
});

test('canonical: ua-parser-js@0.7.29 — pre-OIDC adoption, pattern silent', { skip: !HAS_SEED }, () => {
  // ua-parser-js first adopted OIDC 2023-08; the 0.7.29 attack is
  // 2021-10. Filter to 0.7.x to stay within the pre-adoption window
  // — under this slice, the pattern has no attested history to form
  // a baseline on.
  const history = loadSeedHistory('ua-parser-js', (v) => /^0\.7\./.test(v));
  const out = provenance.extract({ packageName: 'ua-parser-js', history });
  const v = findVersion(out.perVersion, '0.7.29');
  assert.equal(v.baseline_established, false);
  assert.equal(v.provenance_regression, false);
  assert.equal(v.in_scope, false);
  assert.strictEqual(v.prior_baseline_carriers, null);
  assert.equal(out.packageRollup.regression_count, 0);
});
