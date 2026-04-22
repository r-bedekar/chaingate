// Gated behind CHAINGATE_SLOW_TESTS=1 due to wall-time cost (~80s for 11 full
// train-mode validation runs). Regenerate snapshot whenever STARTER_PARAMETERS
// or train-test-split.json changes by running
// `node validation/calibration/run-sensitivity.js` and committing the updated
// sensitivity-results.json.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const SEED_PATH = path.join(REPO_ROOT, 'seed_export', 'chaingate-seed.db');
const SCRIPT = path.join(REPO_ROOT, 'validation', 'calibration', 'run-sensitivity.js');
const SNAPSHOT = path.join(REPO_ROOT, 'validation', 'calibration', 'sensitivity-results.json');

const SLOW = process.env.CHAINGATE_SLOW_TESTS === '1';
const HAS_SEED = existsSync(SEED_PATH);

test(
  'snapshot: sensitivity-results.json matches committed fixture',
  { skip: !SLOW || !HAS_SEED },
  () => {
    const before = readFileSync(SNAPSHOT, 'utf8');
    execFileSync(process.execPath, [SCRIPT], { cwd: REPO_ROOT, stdio: 'pipe' });
    const after = readFileSync(SNAPSHOT, 'utf8');
    assert.equal(
      after,
      before,
      'sensitivity-results.json changed after re-running run-sensitivity.js. ' +
        'Regenerate the snapshot intentionally (edit STARTER_PARAMETERS or the ' +
        'train/test split, then commit both the change and the new snapshot) ' +
        'or investigate a determinism regression.',
    );
  },
);
