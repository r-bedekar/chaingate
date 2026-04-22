// Gated behind CHAINGATE_SLOW_TESTS=1 due to wall-time cost (~91s for 13
// train-mode validation runs: 1 baseline + 12 grid points). Regenerate both
// committed fixtures by running `node validation/calibration/run-calibration.js`
// after STARTER_PARAMETERS, train-test-split.json, or sensitivity-results.json
// changes in a way that affects the grid.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const SEED_PATH = path.join(REPO_ROOT, 'seed_export', 'chaingate-seed.db');
const SCRIPT = path.join(REPO_ROOT, 'validation', 'calibration', 'run-calibration.js');
const SWEEP = path.join(REPO_ROOT, 'validation', 'calibration', 'sweep-results.json');
const OPTIMAL = path.join(REPO_ROOT, 'validation', 'calibration', 'optimal-params.json');

const SLOW = process.env.CHAINGATE_SLOW_TESTS === '1';
const HAS_SEED = existsSync(SEED_PATH);

test(
  'snapshot: calibration sweep-results + optimal-params match committed fixtures',
  { skip: !SLOW || !HAS_SEED },
  () => {
    const sweepBefore = readFileSync(SWEEP, 'utf8');
    const optimalBefore = readFileSync(OPTIMAL, 'utf8');
    execFileSync(process.execPath, [SCRIPT], { cwd: REPO_ROOT, stdio: 'pipe' });
    const sweepAfter = readFileSync(SWEEP, 'utf8');
    const optimalAfter = readFileSync(OPTIMAL, 'utf8');
    assert.equal(
      sweepAfter,
      sweepBefore,
      'sweep-results.json changed after re-running run-calibration.js. ' +
        'Regenerate the snapshot intentionally (edit grid axes, tune ' +
        'constants, or update the split) and commit, or investigate a ' +
        'determinism regression.',
    );
    assert.equal(
      optimalAfter,
      optimalBefore,
      'optimal-params.json changed after re-running run-calibration.js. ' +
        'Regenerate the snapshot intentionally or investigate a determinism ' +
        'regression.',
    );
  },
);
