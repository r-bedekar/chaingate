// Phase D step 12 (docs/4_PLAN.md §2) — publisher-constant sensitivity
// sweep. Runs the train-mode validator once at baseline and twice per
// constant (down/up) with env-var overrides, reporting max|Δrecall|
// and max|ΔFP| per constant and applying the §2 drop rule.
//
// Scope: five publisher-layer constants only (W, K, MIN_VERIFIED_VERSIONS,
// CHURNING_WINDOW, SOLO_DOMINANCE). Provenance-layer constants are out
// of scope for this pass; future sensitivity work may extend
// PERTURBATION_TABLE.
//
// Recall metric: `recall_packages_point` (package-level). Reversal from
// the earlier `recall_labels_point_attributable` choice is intentional:
// under v2 the attributable denominator = 4 and sits entirely on non-
// must-pass packages, so its baseline is zero and publisher-constant
// perturbations cannot move it. Package-level recall is computed over
// N=7 attack-labeled packages in the train set, so signal exists.
//
// Granularity regime: with N=7, one package flip = 0.1429 recall delta.
// The §2 drop threshold of 0.02 is effectively discrete under this
// corpus — "any recall movement retains; zero recall movement drops."
// The fp threshold (0.005 on a denominator of 91) is similarly coarse
// at 0.011 per flip, so the drop rule functions as a boolean flip test
// rather than a smooth comparator. Kept numeric for forward
// compatibility with larger corpora.
//
// Invocation model (Gate 1 Q1 resolution, Option A): fork
// run-validation.js per perturbation with CHAINGATE_PARAM_<NAME> set in
// subprocess env. Each fork writes results.json to its own temp path;
// the canonical validation/results.json is never overwritten. Post-run
// verification reads the subprocess's results.json and asserts that
// parameters[<constant>] equals the intended value — catches env-var-
// name typos that silently fall back to default.
//
// Output: validation/calibration/sensitivity-results.json (atomic
// write via tmp + rename). Byte-stable under repeated runs given
// identical inputs — no timestamps, sorted keys where it matters.
//
// Usage:
//   node validation/calibration/run-sensitivity.js

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const VALIDATOR = path.join(REPO_ROOT, 'validation', 'run-validation.js');
const SPLIT_PATH = path.join(REPO_ROOT, 'validation', 'calibration', 'train-test-split.json');
const OUT_PATH = path.join(REPO_ROOT, 'validation', 'calibration', 'sensitivity-results.json');

// Drop rule (docs/4_PLAN.md §2, D6): retain if EITHER threshold is
// met or exceeded. Both must fall below to drop.
const DROP_THRESHOLD_RECALL = 0.02;
const DROP_THRESHOLD_FP = 0.005;

// Perturbation plan (docs/4_PLAN.md §2, D3). One row per constant.
// `envVar`       — CHAINGATE_PARAM_<NAME> naming convention.
// `starter`      — the v2 baseline value (sanity vs. results.json).
// `down` / `up`  — the two perturbed values.
// `bounds(value)` returns true if the value is admissible; used by
// validatePerturbationTable() to hard-abort before any run if the
// plan has drifted.
const PERTURBATION_TABLE = [
  {
    constant: 'W',
    envVar: 'CHAINGATE_PARAM_W',
    starter: 3,
    down: 2,
    up: 4,
    bounds: (v) => Number.isInteger(v) && v >= 1,
    boundsLabel: '≥1 integer',
    format: (v) => String(v),
  },
  {
    constant: 'K',
    envVar: 'CHAINGATE_PARAM_K',
    starter: 10,
    down: 9,
    up: 11,
    bounds: (v) => Number.isInteger(v) && v >= 1,
    boundsLabel: '≥1 integer',
    format: (v) => String(v),
  },
  {
    constant: 'MIN_VERIFIED_VERSIONS',
    envVar: 'CHAINGATE_PARAM_MIN_VERIFIED_VERSIONS',
    starter: 2,
    down: 1,
    up: 3,
    bounds: (v) => Number.isInteger(v) && v >= 1,
    boundsLabel: '≥1 integer',
    format: (v) => String(v),
  },
  {
    constant: 'CHURNING_WINDOW',
    envVar: 'CHAINGATE_PARAM_CHURNING_WINDOW',
    starter: 5,
    down: 4,
    up: 6,
    bounds: (v) => Number.isInteger(v) && v >= 1,
    boundsLabel: '≥1 integer',
    format: (v) => String(v),
  },
  {
    constant: 'SOLO_DOMINANCE',
    envVar: 'CHAINGATE_PARAM_SOLO_DOMINANCE',
    starter: 0.80,
    down: 0.75,
    up: 0.85,
    bounds: (v) => {
      if (typeof v !== 'number' || !Number.isFinite(v)) return false;
      if (v < 0.70 - 1e-9 || v > 0.90 + 1e-9) return false;
      const scaled = Math.round(v * 100);
      return scaled % 5 === 0;
    },
    boundsLabel: 'step=0.05 on [0.70, 0.90]',
    format: (v) => v.toFixed(2),
  },
];

function round4(x) {
  if (!Number.isFinite(x)) return null;
  return Math.round(x * 1e4) / 1e4;
}

function validatePerturbationTable() {
  const violations = [];
  for (const row of PERTURBATION_TABLE) {
    for (const [dir, val] of [['starter', row.starter], ['down', row.down], ['up', row.up]]) {
      if (!row.bounds(val)) {
        violations.push(`${row.constant}.${dir}=${val} violates bounds (${row.boundsLabel})`);
      }
    }
  }
  if (violations.length > 0) {
    throw new Error(
      `PERTURBATION_TABLE bounds violations:\n  ${violations.join('\n  ')}`,
    );
  }
  return PERTURBATION_TABLE.flatMap((r) => [
    { constant: r.constant, direction: 'down', value: r.down, boundsLabel: r.boundsLabel },
    { constant: r.constant, direction: 'up', value: r.up, boundsLabel: r.boundsLabel },
  ]);
}

function runValidator(envOverrides, outPath) {
  const env = { ...process.env, ...envOverrides };
  const result = spawnSync(
    process.execPath,
    [VALIDATOR, '--mode=train', `--out=${outPath}`],
    { cwd: REPO_ROOT, env, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  if (result.status !== 0) {
    const err = result.stderr ? result.stderr.toString() : '(no stderr)';
    throw new Error(
      `run-validation.js exited ${result.status} with env ${JSON.stringify(envOverrides)}:\n${err}`,
    );
  }
  const raw = readFileSync(outPath, 'utf8');
  return JSON.parse(raw);
}

function verifyParameterOverride(results, constant, intended) {
  const observed = results.parameters ? results.parameters[constant] : undefined;
  if (observed === undefined) {
    throw new Error(
      `post-run verification failed: parameters.${constant} missing from results.json ` +
        `(intended=${intended}). Env-var wiring broken.`,
    );
  }
  // Tolerate float representation drift for SOLO_DOMINANCE by comparing
  // at 4 decimals; integer constants compare exactly after that rounding
  // too. Any real env-var typo would show a default-value-sized gap.
  if (round4(observed) !== round4(intended)) {
    throw new Error(
      `post-run verification failed: parameters.${constant}=${observed} ` +
        `but sensitivity script intended ${intended}. ` +
        `Likely env-var name typo (expected ${envVarFor(constant)}) or constant not ` +
        `threaded through STARTER_PARAMETERS.`,
    );
  }
}

function envVarFor(constant) {
  const row = PERTURBATION_TABLE.find((r) => r.constant === constant);
  return row ? row.envVar : '?';
}

function atomicWriteJson(targetPath, obj) {
  const tmp = targetPath + '.tmp';
  writeFileSync(tmp, JSON.stringify(obj, null, 2) + '\n');
  renameSync(tmp, targetPath);
}

function main() {
  const planned = validatePerturbationTable();

  const workDir = mkdtempSync(path.join(tmpdir(), 'chaingate-sensitivity-'));
  try {
    const totalRuns = 1 + planned.length;
    let n = 0;

    // Baseline
    n += 1;
    const baselineOut = path.join(workDir, 'baseline.json');
    const baselineResults = runValidator({}, baselineOut);
    const baselineFp = baselineResults.aggregates.false_positive_rate_point;
    const baselineRecall = baselineResults.aggregates.recall_packages_point;
    for (const row of PERTURBATION_TABLE) {
      verifyParameterOverride(baselineResults, row.constant, row.starter);
    }
    process.stdout.write(
      `[${n}/${totalRuns}] baseline starter: fp=${baselineFp?.toFixed(4)} recall=${baselineRecall?.toFixed(4)}\n`,
    );

    // Per-constant perturbations
    const sensitivities = [];
    for (const row of PERTURBATION_TABLE) {
      const perturb = {};
      for (const direction of ['down', 'up']) {
        n += 1;
        const value = row[direction];
        const outPath = path.join(workDir, `${row.constant}-${direction}.json`);
        const results = runValidator({ [row.envVar]: row.format(value) }, outPath);
        verifyParameterOverride(results, row.constant, value);
        const fp = results.aggregates.false_positive_rate_point;
        const recall = results.aggregates.recall_packages_point;
        perturb[direction] = {
          value,
          fp: round4(fp),
          recall: round4(recall),
        };
        process.stdout.write(
          `[${n}/${totalRuns}] ${row.constant} ${direction}=${row.format(value)}: ` +
            `fp=${fp?.toFixed(4)} recall=${recall?.toFixed(4)}\n`,
        );
      }
      const deltaFp = round4(Math.max(
        Math.abs(perturb.down.fp - baselineFp),
        Math.abs(perturb.up.fp - baselineFp),
      ));
      const deltaRecall = round4(Math.max(
        Math.abs(perturb.down.recall - baselineRecall),
        Math.abs(perturb.up.recall - baselineRecall),
      ));
      const meetsRecall = deltaRecall >= DROP_THRESHOLD_RECALL;
      const meetsFp = deltaFp >= DROP_THRESHOLD_FP;
      const retained = meetsRecall || meetsFp;
      const dropReason = retained
        ? null
        : `below thresholds: |Δrecall|=${deltaRecall.toFixed(4)} < ${DROP_THRESHOLD_RECALL} ` +
          `AND |ΔFP|=${deltaFp.toFixed(4)} < ${DROP_THRESHOLD_FP}`;
      sensitivities.push({
        constant: row.constant,
        delta_fp: deltaFp,
        delta_recall: deltaRecall,
        perturbations: {
          down: perturb.down,
          up: perturb.up,
        },
        retained,
        drop_reason: dropReason,
      });
    }

    const retainedConstants = sensitivities.filter((s) => s.retained).map((s) => s.constant);
    const droppedConstants = sensitivities.filter((s) => !s.retained).map((s) => s.constant);

    // Pull split provenance from the split file so the output carries
    // its own self-describing header.
    const split = JSON.parse(readFileSync(SPLIT_PATH, 'utf8'));

    const report = {
      baseline: {
        parameters: baselineResults.parameters,
        fp_rate: round4(baselineFp),
        recall: round4(baselineRecall),
        split_version: split.split_version,
        rng_seed: split.rng.seed,
        scope_size: baselineResults.corpus.scope_size,
        attack_labeled_packages: baselineResults.corpus.attack_labeled_packages,
        clean_packages: baselineResults.corpus.clean_packages,
      },
      granularity: {
        recall_denominator: baselineResults.corpus.attack_labeled_packages,
        recall_min_nonzero_delta: round4(1 / baselineResults.corpus.attack_labeled_packages),
        fp_denominator: baselineResults.corpus.clean_packages,
        fp_min_nonzero_delta: round4(1 / baselineResults.corpus.clean_packages),
      },
      sensitivities,
      retained_constants: retainedConstants,
      dropped_constants: droppedConstants,
      perturbation_runs: planned.length,
    };

    atomicWriteJson(OUT_PATH, report);
    process.stdout.write(
      `Wrote ${OUT_PATH}\n` +
        `  retained=${retainedConstants.join(',') || '(none)'}\n` +
        `  dropped=${droppedConstants.join(',') || '(none)'}\n`,
    );
  } finally {
    rmSync(workDir, { recursive: true, force: true });
  }
}

main();
