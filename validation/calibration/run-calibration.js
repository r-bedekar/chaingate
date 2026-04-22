// Phase D step 13 (docs/4_PLAN.md §2) — publisher-constant grid-search
// calibration over the constants run-sensitivity.js (step 12) retained.
//
// Scope: 2 constants (MIN_VERIFIED_VERSIONS, SOLO_DOMINANCE). Provenance-
// layer tuning is out of scope for this pass; extend when corpus version
// warrants. W, K, CHURNING_WINDOW dropped by step 12 (ΔFP < 0.005 AND
// Δrecall < 0.02 across the ±1 sweep) stay at starter for every grid
// point and do not appear here.
//
// Grid (4 × 3 = 12):
//   MIN_VERIFIED_VERSIONS ∈ {1, 2, 3, 4}        (§2 range [1..4], full)
//   SOLO_DOMINANCE        ∈ {0.70, 0.75, 0.80}  (§2 range [0.70..0.90]
//                                                pruned at the upper edge)
//
// Grid pruning rationale (V7 finding, commit f6ebe0a): under split v2
// train, SOLO_DOMINANCE=0.85 flips both must-pass train-side attacks
// (chalk and eslint-config-prettier) from BLOCK to non-BLOCK, driving
// recall_packages_point to 0. Upper values 0.85 and 0.90 are excluded
// from the grid because no viable optimum can exist there — the
// selection rule would be structurally barred from picking them even
// if they were enumerated. Keeping them out of the grid keeps
// sweep-results.json honest: every recorded row is a legally-pickable
// candidate.
//
// Selection rule (Q3(b) reformulation of §2 under v2):
//   1. Filter: round4(fp_rate) ≤ 0.05.
//   2. If filter empty → Q1(a) empty-selection path. Emit
//      optimal-params.json with `selected: null`, plus best-achievable-fp
//      diagnostics and stage-2 deferral note. Starter constants stay.
//      This is the honest-reporting path — do NOT reframe as success.
//   3. Else → maximize recall; break ties by lower fp, then lower MVV,
//      then lower SOLO_DOMINANCE (simpler model per §2 ordering).
//   §2 originally read "max recall, then simpler model." Under v2 train,
//   recall is flat across viable points (0.2857 at all SD ≤ 0.80), so
//   §2's original tie-break would pick on MVV alone and leave FP as a
//   side effect. Q3(b) interposes FP before simpler-model, truer to
//   §2's intent ("prefer less-complex when other signals tie"). See
//   Gate 1 design note for the full rationale.
//
// Stage 2 (deferred, Q2(ii)): §2's stage-2 extension is not implemented
// this pass. Under v2, SOLO_DOMINANCE is hard-pinned at 0.80 by the V7
// recall constraint, so extending the range upward cannot surface a
// viable optimum. Re-evaluate when the corpus version ships enough
// must-pass packages to diversify the recall constraint.
//
// Invocation model: subprocess-fork, mirroring run-sensitivity.js.
// Per grid point, fork `node validation/run-validation.js --mode=train
// --out=<tempfile>` with CHAINGATE_PARAM_<NAME> in the env. Post-run
// verification reads results.json and asserts parameters[<constant>]
// equals the intended value — catches env-var-name typos that silently
// fall back to defaults.
//
// Output: validation/calibration/sweep-results.json (full grid matrix)
// and validation/calibration/optimal-params.json (selection result).
// Both written atomically via <path>.tmp + rename. Byte-stable under
// repeated runs given identical inputs — no timestamps, literal grid
// axes, deterministic enumeration order.
//
// Usage:
//   node validation/calibration/run-calibration.js

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
const SWEEP_OUT = path.join(REPO_ROOT, 'validation', 'calibration', 'sweep-results.json');
const OPTIMAL_OUT = path.join(REPO_ROOT, 'validation', 'calibration', 'optimal-params.json');

// §2 filter target.
const FP_TARGET = 0.05;

// Source of the pruning decision, recorded in sweep-results.json so a
// reader can chase the rationale back to the sensitivity artifact.
const SOURCE_SENSITIVITY_COMMIT = 'f6ebe0a';
const PRUNED_RANGE_NOTE =
  'SOLO_DOMINANCE upper values 0.85, 0.90 excluded per V7 finding (commit f6ebe0a)';

// Starter values for the two tuned axes. Used only for the baseline
// row's `params` field; the actual baseline run uses an empty env
// (no CHAINGATE_PARAM_* set) so the defaults from constants.js apply.
const STARTER_MVV = 2;
const STARTER_SD = 0.80;

const MVV_AXIS = [1, 2, 3, 4];
const SD_AXIS = [0.70, 0.75, 0.80];

// Train-side must-pass attacks (docs/4_PLAN.md §3 per-attack table).
// Emitted as per-row booleans for audit visibility; NOT consumed by
// the selection rule (recall maximization is the selection signal).
const MUST_PASS_PACKAGES = {
  chalk_detected: 'chalk',
  eslint_config_prettier_detected: 'eslint-config-prettier',
};

function round4(x) {
  if (!Number.isFinite(x)) return null;
  return Math.round(x * 1e4) / 1e4;
}

function formatSd(v) {
  return v.toFixed(2);
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
  return JSON.parse(readFileSync(outPath, 'utf8'));
}

function verifyParameterOverride(results, constant, intended) {
  const observed = results.parameters ? results.parameters[constant] : undefined;
  if (observed === undefined) {
    throw new Error(
      `post-run verification failed: parameters.${constant} missing from results.json ` +
        `(intended=${intended}). Env-var wiring broken.`,
    );
  }
  if (round4(observed) !== round4(intended)) {
    throw new Error(
      `post-run verification failed: parameters.${constant}=${observed} ` +
        `but calibration script intended ${intended}. ` +
        `Likely env-var name typo or constant not threaded through STARTER_PARAMETERS.`,
    );
  }
}

function perPackageBlockFlags(results) {
  const byName = new Map(results.per_package.map((p) => [p.package, p]));
  const flags = {};
  for (const [field, pkgName] of Object.entries(MUST_PASS_PACKAGES)) {
    const row = byName.get(pkgName);
    flags[field] = !!(row && row.disposition === 'BLOCK');
  }
  return flags;
}

function atomicWriteJson(targetPath, obj) {
  const tmp = targetPath + '.tmp';
  writeFileSync(tmp, JSON.stringify(obj, null, 2) + '\n');
  renameSync(tmp, targetPath);
}

// Sort key for the full-grid best-achievable-fp picker (empty-selection
// branch). Ordering: fp ASC (primary), recall DESC, MVV ASC, SD ASC.
// recall is secondary so that among equally-low-FP rows the one with
// higher recall surfaces (defensive — unlikely to matter under v2 but
// keeps the empty-branch choice interpretable if a grid of equal-FP
// points ever spans recall levels).
function bestAchievableFpSort(a, b) {
  if (a.fp_rate !== b.fp_rate) return a.fp_rate - b.fp_rate;
  if (a.recall !== b.recall) return b.recall - a.recall;
  if (a.params.MIN_VERIFIED_VERSIONS !== b.params.MIN_VERIFIED_VERSIONS) {
    return a.params.MIN_VERIFIED_VERSIONS - b.params.MIN_VERIFIED_VERSIONS;
  }
  return a.params.SOLO_DOMINANCE - b.params.SOLO_DOMINANCE;
}

// Sort key for the non-empty branch (Q3(b)): recall DESC, fp ASC,
// MVV ASC, SD ASC.
function selectionSort(a, b) {
  if (a.recall !== b.recall) return b.recall - a.recall;
  if (a.fp_rate !== b.fp_rate) return a.fp_rate - b.fp_rate;
  if (a.params.MIN_VERIFIED_VERSIONS !== b.params.MIN_VERIFIED_VERSIONS) {
    return a.params.MIN_VERIFIED_VERSIONS - b.params.MIN_VERIFIED_VERSIONS;
  }
  return a.params.SOLO_DOMINANCE - b.params.SOLO_DOMINANCE;
}

function main() {
  const workDir = mkdtempSync(path.join(tmpdir(), 'chaingate-calibration-'));
  try {
    // Baseline — no env overrides; starter constants apply from
    // constants.js and patterns/publisher.js.
    const baselinePath = path.join(workDir, 'baseline.json');
    const baselineResults = runValidator({}, baselinePath);
    verifyParameterOverride(baselineResults, 'MIN_VERIFIED_VERSIONS', STARTER_MVV);
    verifyParameterOverride(baselineResults, 'SOLO_DOMINANCE', STARTER_SD);
    const baselineFp = round4(baselineResults.aggregates.false_positive_rate_point);
    const baselineRecall = round4(baselineResults.aggregates.recall_packages_point);
    const baselineFlags = perPackageBlockFlags(baselineResults);
    process.stdout.write(
      `[baseline] fp=${baselineFp.toFixed(4)} recall=${baselineRecall.toFixed(4)} ` +
        `(starter MVV=${STARTER_MVV} SD=${formatSd(STARTER_SD)})\n`,
    );

    // Grid sweep
    const grid = [];
    const totalPoints = MVV_AXIS.length * SD_AXIS.length;
    let n = 0;
    for (const mvv of MVV_AXIS) {
      for (const sd of SD_AXIS) {
        n += 1;
        const env = {
          CHAINGATE_PARAM_MIN_VERIFIED_VERSIONS: String(mvv),
          CHAINGATE_PARAM_SOLO_DOMINANCE: formatSd(sd),
        };
        const outPath = path.join(workDir, `grid-${n}.json`);
        const r = runValidator(env, outPath);
        verifyParameterOverride(r, 'MIN_VERIFIED_VERSIONS', mvv);
        verifyParameterOverride(r, 'SOLO_DOMINANCE', sd);
        const fp = round4(r.aggregates.false_positive_rate_point);
        const recall = round4(r.aggregates.recall_packages_point);
        const filterPass = fp <= FP_TARGET;
        const flags = perPackageBlockFlags(r);
        grid.push({
          params: { MIN_VERIFIED_VERSIONS: mvv, SOLO_DOMINANCE: sd },
          fp_rate: fp,
          recall,
          filter_pass: filterPass,
          attack_packages_detected: r.aggregates.attack_packages_detected,
          chalk_detected: flags.chalk_detected,
          eslint_config_prettier_detected: flags.eslint_config_prettier_detected,
        });
        process.stdout.write(
          `[${n}/${totalPoints}] MVV=${mvv} SD=${formatSd(sd)}: ` +
            `fp=${fp.toFixed(4)} recall=${recall.toFixed(4)} ` +
            `[${filterPass ? 'filter-pass' : 'filter-fail'}]\n`,
        );
      }
    }

    // Pull split provenance from the split file so the output carries
    // its own self-describing header (mirrors run-sensitivity.js).
    const split = JSON.parse(readFileSync(SPLIT_PATH, 'utf8'));

    const sweep = {
      baseline: {
        params: { MIN_VERIFIED_VERSIONS: STARTER_MVV, SOLO_DOMINANCE: STARTER_SD },
        fp_rate: baselineFp,
        recall: baselineRecall,
        attack_packages_detected: baselineResults.aggregates.attack_packages_detected,
        chalk_detected: baselineFlags.chalk_detected,
        eslint_config_prettier_detected: baselineFlags.eslint_config_prettier_detected,
      },
      grid,
      grid_size: grid.length,
      split_version: split.split_version,
      rng_seed: split.rng.seed,
      scope_size: baselineResults.corpus.scope_size,
      attack_labeled_packages: baselineResults.corpus.attack_labeled_packages,
      clean_packages: baselineResults.corpus.clean_packages,
      source_sensitivity_commit: SOURCE_SENSITIVITY_COMMIT,
      pruned_range_note: PRUNED_RANGE_NOTE,
    };
    atomicWriteJson(SWEEP_OUT, sweep);

    // Selection
    const viable = grid.filter((r) => r.filter_pass);
    const stage2Limitation = {
      kind: 'stage_2_deferred',
      rationale:
        'SOLO_DOMINANCE upper edge hard-pinned by V7 recall constraint; ' +
        'stage-2 extension would not surface a viable optimum under v2 corpus. ' +
        'Implement when corpus version warrants.',
      spec_reference: 'docs/4_PLAN.md §2 Stage 2 (deferred under v2)',
    };

    let optimal;
    if (viable.length === 0) {
      const ranked = grid.slice().sort(bestAchievableFpSort);
      const best = ranked[0];
      optimal = {
        selected: null,
        reason: 'no grid point achieves §2 FP ≤ 0.05 target under v2 corpus',
        best_achievable_fp: best.fp_rate,
        best_achievable_fp_params: best.params,
        best_achievable_fp_recall: best.recall,
        calibration_limitations: [
          {
            kind: 'fp_target_unmet',
            target: FP_TARGET,
            best_in_grid: best.fp_rate,
            note: 'Starter constants retained; step 14 is a no-op under this outcome.',
          },
          stage2Limitation,
        ],
        split_version: split.split_version,
        rng_seed: split.rng.seed,
      };
    } else {
      const ranked = viable.slice().sort(selectionSort);
      const pick = ranked[0];
      optimal = {
        selected: pick.params,
        selected_fp: pick.fp_rate,
        selected_recall: pick.recall,
        selection_rule:
          'Q3(b) reformulation: filter FP ≤ 0.05, max recall, min FP, simpler model',
        calibration_limitations: [stage2Limitation],
        split_version: split.split_version,
        rng_seed: split.rng.seed,
      };
    }
    atomicWriteJson(OPTIMAL_OUT, optimal);

    process.stdout.write(
      `Selected: ${optimal.selected ? JSON.stringify(optimal.selected) : 'null'}\n` +
        `Wrote ${SWEEP_OUT}\n` +
        `Wrote ${OPTIMAL_OUT}\n`,
    );
  } finally {
    rmSync(workDir, { recursive: true, force: true });
  }
}

main();
