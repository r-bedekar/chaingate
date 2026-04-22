// Build `train-test-split.json` deterministically.
//
// Split contract (docs/4_PLAN.md §3, split_version=2):
//   * Fixed held-out attacks: axios, event-stream locked into test
//     (Risk 11). No random attack sample in test under v2.
//   * Train-locked attacks: chalk, coa, eslint-config-prettier, rc
//     locked into train so the calibration sweep has a real recall
//     signal (Risk 14).
//   * Remaining test set: 4 clean packages (random from clean pool).
//   * Train set: everything else — train-locked attacks + remaining
//     attack-labeled + unsampled clean.
//
// Reproducibility: SQLite rows are ORDER BY package_name (stable across
// machines). Shuffle is a seeded Mulberry32 PRNG. The seed (integer)
// is embedded in the output JSON so any reviewer can regenerate the
// split byte-for-byte.
//
// Usage:
//   node validation/calibration/build-split.js
//
// Writes (at repo root): validation/calibration/train-test-split.json

import Database from 'better-sqlite3';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import {
  HELD_OUT_PACKAGES,
  TRAIN_LOCKED_PACKAGES,
  assertHeldOutsNotInTrain,
  assertHeldOutsInTest,
  assertTrainLockedInTrain,
} from './held-outs.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const SEED_DB = path.join(REPO_ROOT, 'seed_export', 'chaingate-seed.db');
const OUT_PATH = path.join(__dirname, 'train-test-split.json');

// Split format version. Bump when the stratification contract changes
// (not when constants within the same contract move). v2 introduced
// TRAIN_SET_LOCKED_ATTACKS and removed the random attack sample from
// the test bucket.
const SPLIT_VERSION = 2;

// Fixed RNG seed — recorded in the output. Changing this intentionally
// resamples the stratified picks; unchanged means identical JSON.
// v2 bump: 20260420 → 20260422 alongside the stratification change.
const RNG_SEED = 20260422;

// Stratified sample sizes for the NON-locked test bucket.
// Under v2 the attack side of test is fully populated by
// TEST_SET_HELD_OUT_ATTACKS, so no random attack sample is drawn.
const STRATA_ATTACK = 0;
const STRATA_CLEAN = 4;

function mulberry32(seedInt) {
  let a = seedInt >>> 0;
  return function rand() {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function shuffled(arr, rand) {
  const out = arr.slice();
  for (let i = out.length - 1; i > 0; i -= 1) {
    const j = Math.floor(rand() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

function loadCorpus() {
  const db = new Database(SEED_DB, { readonly: true });
  try {
    const pkgs = db
      .prepare('SELECT id, package_name FROM packages ORDER BY package_name')
      .all();

    const attackLabels = db
      .prepare(
        `SELECT package_id, COUNT(*) AS n_labels,
                SUM(CASE WHEN is_malicious = 1 THEN 1 ELSE 0 END) AS n_malicious
         FROM attack_labels
         GROUP BY package_id`,
      )
      .all();

    const attackPkgIds = new Set(
      attackLabels.filter((r) => r.n_malicious > 0).map((r) => r.package_id),
    );

    const attackLabeled = pkgs
      .filter((p) => attackPkgIds.has(p.id))
      .map((p) => p.package_name);
    const clean = pkgs
      .filter((p) => !attackPkgIds.has(p.id))
      .map((p) => p.package_name);

    return {
      total: pkgs.length,
      attackLabeled,
      clean,
    };
  } finally {
    db.close();
  }
}

function build() {
  const { total, attackLabeled, clean } = loadCorpus();

  // Confirm corpus matches the plan's assumed structure; fail loudly
  // if the seed DB has drifted (e.g. added packages) so the split
  // won't silently use a different denominator.
  for (const p of HELD_OUT_PACKAGES) {
    if (!attackLabeled.includes(p)) {
      throw new Error(
        `held-out package '${p}' not found in seed attack-labeled set; ` +
          `attack-labeled packages are: ${attackLabeled.join(', ')}`,
      );
    }
  }
  for (const p of TRAIN_LOCKED_PACKAGES) {
    if (!attackLabeled.includes(p)) {
      throw new Error(
        `train-locked package '${p}' not found in seed attack-labeled set; ` +
          `attack-labeled packages are: ${attackLabeled.join(', ')}`,
      );
    }
  }

  // Forward-compatibility: any attack-labeled package not listed in
  // TRAIN_SET_LOCKED_ATTACKS ∪ TEST_SET_HELD_OUT_ATTACKS lands in train by default.
  // To route a future attack to test, add it to one of the two lock lists.
  const lockedNames = new Set([...HELD_OUT_PACKAGES, ...TRAIN_LOCKED_PACKAGES]);
  const stratifiableAttackPool = attackLabeled.filter((n) => !lockedNames.has(n));
  const cleanPool = clean.slice();

  if (stratifiableAttackPool.length < STRATA_ATTACK) {
    throw new Error(
      `need >=${STRATA_ATTACK} attack packages to sample; have ` +
        `${stratifiableAttackPool.length} after locks`,
    );
  }
  if (cleanPool.length < STRATA_CLEAN) {
    throw new Error(
      `need >=${STRATA_CLEAN} clean packages to sample; have ${cleanPool.length}`,
    );
  }

  const rand = mulberry32(RNG_SEED);
  const attackSample = shuffled(stratifiableAttackPool, rand).slice(0, STRATA_ATTACK);
  const cleanSample = shuffled(cleanPool, rand).slice(0, STRATA_CLEAN);

  const testSet = [...HELD_OUT_PACKAGES, ...attackSample, ...cleanSample]
    .slice()
    .sort();
  const testSetSet = new Set(testSet);
  const trainSet = [...attackLabeled, ...clean]
    .filter((n) => !testSetSet.has(n))
    .sort();

  // Belt-and-braces: these match the runtime assertions in held-outs.js.
  assertHeldOutsNotInTrain(trainSet);
  assertHeldOutsInTest(testSet);
  assertTrainLockedInTrain(trainSet);

  // NOTE: no `generated_at` field — the output must be byte-stable so
  // `build-split.js` is idempotent. Commit date lives in git history.
  return {
    split_version: SPLIT_VERSION,
    corpus_size: total,
    rng: {
      algorithm: 'mulberry32',
      seed: RNG_SEED,
    },
    // v2 note: `attack_labeled_sample` retained at 0 for schema continuity.
    // Under split_version=2, attack-labeled bucket assignment is determined
    // by TRAIN_SET_LOCKED_ATTACKS ∪ TEST_SET_HELD_OUT_ATTACKS, not by the
    // sampler. The field stays in the emitted object so downstream
    // consumers that key on `strata` shape keep working.
    strata: {
      attack_labeled_sample: STRATA_ATTACK,
      clean_sample: STRATA_CLEAN,
    },
    held_out_packages: HELD_OUT_PACKAGES.slice(),
    train_locked_packages: TRAIN_LOCKED_PACKAGES.slice(),
    test_set: {
      size: testSet.length,
      packages: testSet,
      attack_labeled: testSet.filter((n) => attackLabeled.includes(n)).sort(),
      clean: testSet.filter((n) => clean.includes(n)).sort(),
    },
    train_set: {
      size: trainSet.length,
      attack_labeled: trainSet.filter((n) => attackLabeled.includes(n)).sort(),
      clean: trainSet.filter((n) => clean.includes(n)).sort(),
      packages: trainSet,
    },
  };
}

function main() {
  const split = build();
  // 2-space JSON + trailing newline — diff-friendly.
  writeFileSync(OUT_PATH, JSON.stringify(split, null, 2) + '\n');
  process.stdout.write(
    `Wrote ${OUT_PATH}\n` +
      `  corpus=${split.corpus_size}  ` +
      `test=${split.test_set.size} (${split.test_set.attack_labeled.length} attack / ${split.test_set.clean.length} clean)  ` +
      `train=${split.train_set.size} (${split.train_set.attack_labeled.length} attack / ${split.train_set.clean.length} clean)\n`,
  );
}

main();
