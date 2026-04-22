// validation/run-validation.js — Phase C step 10 baseline runner.
//
// Loads the committed train/test split + the seed SQLite DB, runs
// patterns/publisher.extract() on each in-scope package, applies
// validation/disposition.js, and writes validation/results.json.
//
// Reproducibility contract (docs/4_PLAN.md §3 Reproducibility):
//   * Given identical inputs (seed DB + split + source code), this
//     script produces byte-identical results.json. No timestamps, no
//     Set iteration leaks, no floating-point sums past 4 decimals.
//   * Packages iterate in lexicographic order. Arrays inside
//     per_attack / per_package are deterministic because they come
//     from sorted SQL.
//
// Assertion harness (docs/4_PLAN.md §5 Risk 11):
//   * mode=train  → assertHeldOutsNotInTrain(scoped packages)
//   * mode=test   → assertHeldOutsInTest(scoped packages)
//   Both run BEFORE any pattern evaluation so a split leak fails loudly
//   with a clear error instead of producing subtly wrong metrics.
//
// Usage:
//   node validation/run-validation.js                  # mode=train, default paths
//   node validation/run-validation.js --mode=test
//   node validation/run-validation.js --seed=<db> --split=<json> --out=<json>

import Database from 'better-sqlite3';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import publisher from '../patterns/publisher.js';
import { disposition, __thresholds } from './disposition.js';
import {
  MIN_HISTORY_DEPTH,
  MIN_VERIFIED_VERSIONS,
  CHURNING_WINDOW,
  SOLO_DOMINANCE,
} from '../constants.js';
import {
  assertHeldOutsNotInTrain,
  assertHeldOutsInTest,
} from './calibration/held-outs.js';
import { compareSemver, parseSemver } from '../patterns/semver.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');

const DEFAULT_SEED = path.join(REPO_ROOT, 'seed_export', 'chaingate-seed.db');
const DEFAULT_SPLIT = path.join(
  REPO_ROOT,
  'validation',
  'calibration',
  'train-test-split.json',
);
const DEFAULT_OUT = path.join(REPO_ROOT, 'validation', 'results.json');

// Starter constants per docs/4_PLAN.md §2. Recorded in results.json so
// any re-tune lands as a visible diff.
const STARTER_PARAMETERS = {
  W: 3, // is_overlap_window_W3 — baked into publisher.js (sub-step 2d)
  K: 10, // is_known_contributor_K10 — baked into publisher.js (sub-step 2e)
  MIN_HISTORY_DEPTH,
  MIN_VERIFIED_VERSIONS,
  CHURNING_WINDOW,
  SOLO_DOMINANCE,
  HIGH_PRIOR_TENURE: __thresholds.HIGH_PRIOR_TENURE,
  EXCEPTIONAL_PRIOR_TENURE: __thresholds.EXCEPTIONAL_PRIOR_TENURE,
};

function parseArgs(argv) {
  const out = { mode: 'train', seed: DEFAULT_SEED, split: DEFAULT_SPLIT, out: DEFAULT_OUT };
  for (const a of argv.slice(2)) {
    const m = /^--([^=]+)=(.*)$/.exec(a);
    if (!m) throw new Error(`unrecognized arg: ${a}`);
    const [, k, v] = m;
    if (!(k in out)) throw new Error(`unknown flag: --${k}`);
    out[k] = v;
  }
  if (out.mode !== 'train' && out.mode !== 'test') {
    throw new Error(`--mode must be 'train' or 'test', got '${out.mode}'`);
  }
  return out;
}

// Minimal semver-range matcher. Handles the forms observed in the seed:
//   ">=A <B"   (composite)
//   ">=A"
//   "<A"
//   ">A", "<=A" — also supported for completeness
// Returns true if the given version satisfies every comparator. Parses
// greedily on whitespace; anything it cannot parse throws so corpus
// drift surfaces loudly rather than silently misreporting recall.
function matchesRange(version, range) {
  if (!range || typeof range !== 'string') return false;
  const tokens = range.trim().split(/\s+/).filter(Boolean);
  for (const tok of tokens) {
    const m = /^(>=|<=|>|<|=)(.+)$/.exec(tok);
    if (!m) throw new Error(`unparseable range comparator: '${tok}' in '${range}'`);
    const [, op, v] = m;
    if (!parseSemver(v)) {
      throw new Error(`unparseable version '${v}' in range '${range}'`);
    }
    const cmp = compareSemver(version, v);
    let ok;
    switch (op) {
      case '>=': ok = cmp >= 0; break;
      case '<=': ok = cmp <= 0; break;
      case '>':  ok = cmp > 0;  break;
      case '<':  ok = cmp < 0;  break;
      case '=':  ok = cmp === 0; break;
      default:   throw new Error(`impossible op ${op}`);
    }
    if (!ok) return false;
  }
  return true;
}

function loadSplit(p) {
  const raw = readFileSync(p, 'utf8');
  return JSON.parse(raw);
}

function loadPackageHistory(db, packageId) {
  const rows = db
    .prepare(
      `SELECT id, version, published_at, publisher_name, publisher_email,
              provenance_present
       FROM versions
       WHERE package_id = ?`,
    )
    .all(packageId);
  return rows.map((r) => ({
    version_id: r.id,
    version: r.version,
    publisher_name: r.publisher_name,
    publisher_email: r.publisher_email,
    provenance_present: r.provenance_present,
    published_at_ms: r.published_at ? Date.parse(r.published_at) : null,
  }));
}

function loadAttackLabels(db, packageId) {
  return db
    .prepare(
      `SELECT id, version_id, is_malicious, affected_range,
              advisory_id, source, provenance_source, summary
       FROM attack_labels
       WHERE package_id = ? AND is_malicious = 1
         AND (
           version_id IS NOT NULL
           OR NOT EXISTS (
             SELECT 1 FROM attack_labels a2
             WHERE a2.advisory_id = attack_labels.advisory_id
               AND a2.package_id = attack_labels.package_id
               AND a2.version_id IS NOT NULL
           )
         )
       ORDER BY id`,
    )
    .all(packageId);
}

function round4(x) {
  if (!Number.isFinite(x)) return null;
  return Math.round(x * 1e4) / 1e4;
}

// Resolve the target version set for a label against the package's
// observed versions. Returns { kind, versions[] }.
//   version_pinned — label points at a specific version (version_id)
//   range_based    — label carries affected_range; enumerate matches
//   unspecified    — neither; cannot attribute to any version
function resolveLabelTargets(label, historyById) {
  if (label.version_id != null) {
    const row = historyById.get(label.version_id);
    return {
      kind: 'version_pinned',
      versions: row ? [row.version] : [],
    };
  }
  if (label.affected_range) {
    const matched = [];
    for (const h of historyById.values()) {
      if (matchesRange(h.version, label.affected_range)) matched.push(h.version);
    }
    matched.sort(compareSemver);
    return { kind: 'range_based', versions: matched };
  }
  return { kind: 'unspecified', versions: [] };
}

// Walk per-version verdicts. Each reason string carries its own
// "@ <version>" anchor emitted by disposition.js (both Pass 1
// transition-driven reasons and Pass 2 provenance-regression reasons).
// Keying the verdicts map off that anchor decouples this pairing from
// the length and order of dispositionResult.reasons[] — which stopped
// being 1:1 with extracted.transitions[] once Phase-3 two-arg
// disposition began skipping same-identity transitions in Pass 1 and
// appending provenance-version reasons in Pass 2.
//
// Control-flow reasons that have no version anchor ("no transitions
// observed", "insufficient history (...)", "no escalating signals")
// do not match the anchor regex and are skipped — they aren't
// attributable to any single version.
const REASON_ANCHOR_RE = /^(ALLOW|WARN|BLOCK):\s[^@]*@\s*(\S+)/;

function buildTransitionVerdicts(_extracted, dispositionResult) {
  const verdicts = new Map();
  for (const reason of dispositionResult.reasons) {
    if (typeof reason !== 'string') continue;
    const m = REASON_ANCHOR_RE.exec(reason);
    if (!m) continue;
    verdicts.set(m[2], { disposition: m[1], reason });
  }
  return verdicts;
}

function classifyCell(t) {
  const overlap = t.is_overlap_window_W3;
  const known = t.is_known_contributor_K10;
  if (overlap && known) return 'recurring_member';
  if (overlap && !known) return 'new_committee_member';
  if (!overlap && known) return 'returning_dormant';
  return 'cold_handoff';
}

// Per-attack row. "detected" = any target version lands on a BLOCK
// transition. For range_based labels we report the first BLOCKed
// target version encountered (sorted order), keeping the row compact.
function buildPerAttackRow(pkgName, label, targets, extracted, verdicts) {
  const row = {
    package: pkgName,
    advisory_id: label.advisory_id,
    source: label.source,
    provenance_source: label.provenance_source,
    label_kind: targets.kind,
    label_target: label.version_id != null
      ? 'version_id=' + label.version_id
      : (label.affected_range ?? null),
    candidate_versions: targets.versions,
    detected: false,
    detected_version: null,
    detected_disposition: null,
    disposition_reason: null,
    shape: extracted.shape,
    providers_seen: extracted.identity_profile.providers_seen?.slice?.() ?? [],
    domain_stability: extracted.identity_profile.domain_stability ?? null,
    cell: null,
  };

  // A label on a package where extract() has no transitions at all can
  // never be detected at this layer — record it honestly and move on.
  if (verdicts.size === 0 || targets.versions.length === 0) return row;

  for (const v of targets.versions) {
    const verdict = verdicts.get(v);
    if (!verdict) continue;
    if (verdict.disposition === 'BLOCK') {
      row.detected = true;
      row.detected_version = v;
      row.detected_disposition = verdict.disposition;
      row.disposition_reason = verdict.reason;
      const t = extracted.transitions.find((x) => x.at_version === v);
      row.cell = t ? classifyCell(t) : null;
      return row;
    }
    if (!row.detected_disposition) {
      row.detected_version = v;
      row.detected_disposition = verdict.disposition;
      row.disposition_reason = verdict.reason;
      const t = extracted.transitions.find((x) => x.at_version === v);
      row.cell = t ? classifyCell(t) : null;
    }
  }
  return row;
}

function run(options) {
  const split = loadSplit(options.split);
  const scope = options.mode === 'train' ? split.train_set : split.test_set;
  const scopePackages = scope.packages.slice().sort();
  const scopeSet = new Set(scopePackages);

  if (options.mode === 'train') assertHeldOutsNotInTrain(scopeSet);
  else assertHeldOutsInTest(scopeSet);

  const db = new Database(options.seed, { readonly: true });
  try {
    const allPkgs = db.prepare('SELECT id, package_name FROM packages').all();
    const nameToId = new Map(allPkgs.map((p) => [p.package_name, p.id]));

    // Attack-labeled sets from the split file are the ground truth for
    // per-package TP/FP bookkeeping.
    const attackLabeled = new Set(scope.attack_labeled);

    const perPackage = [];
    const perAttack = [];

    let tpPackages = 0; // attack-labeled packages with disposition=BLOCK
    let fnPackages = 0; // attack-labeled packages without BLOCK
    let fpPackages = 0; // clean packages with disposition=BLOCK
    let tnPackages = 0; // clean packages without BLOCK
    let warnClean = 0;  // clean packages at WARN (for visibility)

    for (const pkgName of scopePackages) {
      const pkgId = nameToId.get(pkgName);
      if (pkgId == null) {
        throw new Error(`split names package '${pkgName}' not present in seed DB`);
      }
      const history = loadPackageHistory(db, pkgId);
      const historyById = new Map(history.map((h) => [h.version_id, h]));

      const extracted = publisher.extract({ packageName: pkgName, history });
      const d = disposition(extracted);
      const verdicts = buildTransitionVerdicts(extracted, d);

      const isAttack = attackLabeled.has(pkgName);
      if (isAttack) {
        if (d.disposition === 'BLOCK') tpPackages += 1; else fnPackages += 1;
      } else {
        if (d.disposition === 'BLOCK') fpPackages += 1;
        else if (d.disposition === 'WARN') { warnClean += 1; tnPackages += 1; }
        else tnPackages += 1;
      }

      perPackage.push({
        package: pkgName,
        attack_labeled: isAttack,
        disposition: d.disposition,
        shape: extracted.shape,
        observed_versions_count: extracted.signals.observed_versions_count ?? history.length,
        has_sufficient_history: !!extracted.signals.has_sufficient_history,
        transitions: extracted.transitions.length,
        block_transitions: [...verdicts.values()].filter((v) => v.disposition === 'BLOCK').length,
        warn_transitions: [...verdicts.values()].filter((v) => v.disposition === 'WARN').length,
      });

      if (isAttack) {
        const labels = loadAttackLabels(db, pkgId);
        for (const label of labels) {
          const targets = resolveLabelTargets(label, historyById);
          perAttack.push(buildPerAttackRow(pkgName, label, targets, extracted, verdicts));
        }
      }
    }

    const attackPkgsInScope = scope.attack_labeled.length;
    const cleanPkgsInScope = scope.clean.length;

    // Wilson-score CI deferred to Phase E reports — baseline carries
    // point estimates only. Rounded to 4 decimals to keep byte-stable.
    const recallPoint = attackPkgsInScope > 0
      ? round4(tpPackages / attackPkgsInScope) : null;
    const fpRatePoint = cleanPkgsInScope > 0
      ? round4(fpPackages / cleanPkgsInScope) : null;
    const precisionPoint = (tpPackages + fpPackages) > 0
      ? round4(tpPackages / (tpPackages + fpPackages)) : null;

    const attackLabelsTotal = perAttack.length;
    const attackLabelsDetected = perAttack.filter((r) => r.detected).length;
    const labelRecallPoint = attackLabelsTotal > 0
      ? round4(attackLabelsDetected / attackLabelsTotal) : null;

    perPackage.sort((a, b) => (a.package < b.package ? -1 : a.package > b.package ? 1 : 0));
    perAttack.sort((a, b) => {
      if (a.package !== b.package) return a.package < b.package ? -1 : 1;
      const ka = String(a.advisory_id ?? '');
      const kb = String(b.advisory_id ?? '');
      if (ka !== kb) return ka < kb ? -1 : 1;
      return 0;
    });

    return {
      mode: options.mode,
      split_path: path.relative(REPO_ROOT, options.split),
      seed_path: path.relative(REPO_ROOT, options.seed),
      corpus: {
        scope_size: scopePackages.length,
        attack_labeled_packages: attackPkgsInScope,
        clean_packages: cleanPkgsInScope,
      },
      parameters: STARTER_PARAMETERS,
      aggregates: {
        attack_packages_detected: tpPackages,
        attack_packages_missed: fnPackages,
        clean_packages_blocked: fpPackages,
        clean_packages_warned: warnClean,
        clean_packages_allowed: cleanPkgsInScope - fpPackages - warnClean,
        recall_packages_point: recallPoint,
        false_positive_rate_point: fpRatePoint,
        precision_packages_point: precisionPoint,
        attack_labels_total: attackLabelsTotal,
        attack_labels_detected: attackLabelsDetected,
        recall_labels_point: labelRecallPoint,
      },
      per_attack: perAttack,
      per_package: perPackage,
    };
  } finally {
    db.close();
  }
}

function main() {
  const options = parseArgs(process.argv);
  const results = run(options);
  writeFileSync(options.out, JSON.stringify(results, null, 2) + '\n');
  process.stdout.write(
    `Wrote ${options.out}\n` +
      `  mode=${results.mode}  scope=${results.corpus.scope_size}  ` +
      `attack=${results.corpus.attack_labeled_packages}  clean=${results.corpus.clean_packages}\n` +
      `  TP=${results.aggregates.attack_packages_detected}  ` +
      `FN=${results.aggregates.attack_packages_missed}  ` +
      `FP=${results.aggregates.clean_packages_blocked}  ` +
      `TN=${results.aggregates.clean_packages_allowed + results.aggregates.clean_packages_warned}\n` +
      `  recall(pkg)=${results.aggregates.recall_packages_point}  ` +
      `FPR=${results.aggregates.false_positive_rate_point}  ` +
      `precision=${results.aggregates.precision_packages_point}\n`,
  );
}

main();
