// Phase-4 golden snapshot guard for validation/results.json aggregate
// contract. Asserts structural equality of { corpus, parameters,
// aggregates } against committed fixtures. per_attack and per_package
// arrays are deliberately NOT asserted — they shift with seed data
// (new versions, new advisories) without changing what the pattern
// actually detected. The aggregate subset is the stable contract.
//
// Two fixtures guard two modes:
//   - results-train-expected.json matches the committed
//     validation/results.json (default train mode, 94-package scope).
//   - results-test-expected.json guards the held-out split that
//     carries known-attack packages (axios, event-stream, chalk,
//     eslint-config-prettier, etc.). A train-only snapshot would miss
//     regressions that silently zero out provenance detection.
//
// Skip semantics: gracefully skip when either the seed DB is missing
// (fresh clone without re-export) or results.json hasn't been
// generated yet. Hard-failing in those cases would make fresh clones
// red until someone ran the validator manually — not a useful
// developer-workflow signal.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const SEED_PATH = path.join(REPO_ROOT, 'seed_export', 'chaingate-seed.db');
const TRAIN_RESULTS_PATH = path.join(REPO_ROOT, 'validation', 'results.json');
const TRAIN_FIXTURE = path.join(__dirname, 'fixtures', 'results-train-expected.json');
const TEST_FIXTURE = path.join(__dirname, 'fixtures', 'results-test-expected.json');

const HAS_SEED = existsSync(SEED_PATH);
const HAS_TRAIN_RESULTS = existsSync(TRAIN_RESULTS_PATH);

function readJson(p) {
  return JSON.parse(readFileSync(p, 'utf8'));
}

function pickSubset(r) {
  return {
    mode: r.mode,
    corpus: r.corpus,
    parameters: r.parameters,
    aggregates: r.aggregates,
  };
}

test(
  'snapshot: train-mode aggregates match committed fixture',
  { skip: !HAS_SEED || !HAS_TRAIN_RESULTS },
  () => {
    const actual = pickSubset(readJson(TRAIN_RESULTS_PATH));
    const expected = readJson(TRAIN_FIXTURE);
    assert.deepEqual(actual, expected);
  },
);

test(
  'snapshot: test-mode aggregates match committed fixture',
  { skip: !HAS_SEED },
  () => {
    // Test mode is not persisted to disk by default; run the validator
    // to a tempfile and diff the subset.
    const tmp = mkdtempSync(path.join(tmpdir(), 'chaingate-snapshot-'));
    const outPath = path.join(tmp, 'results-test.json');
    execFileSync(
      process.execPath,
      [path.join(REPO_ROOT, 'validation', 'run-validation.js'), '--mode=test', `--out=${outPath}`],
      { cwd: REPO_ROOT, stdio: 'pipe' },
    );
    const actual = pickSubset(readJson(outPath));
    const expected = readJson(TEST_FIXTURE);
    assert.deepEqual(actual, expected);
  },
);
