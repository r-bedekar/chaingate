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

import publisher, { WINDOW_W, WINDOW_K } from '../patterns/publisher.js';
import provenance, {
  MIN_PROVENANCE_HISTORY,
  MIN_BASELINE_STREAK,
} from '../patterns/provenance.js';
import {
  disposition,
  hasProvenanceEscalator,
  __thresholds,
} from './disposition.js';
import {
  MIN_HISTORY_DEPTH,
  MIN_VERIFIED_VERSIONS,
  CHURNING_WINDOW,
  SOLO_DOMINANCE,
} from '../constants.js';
import {
  assertHeldOutsNotInTrain,
  assertHeldOutsInTest,
  assertTrainLockedInTrain,
  assertTrainLockedNotInTest,
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
  W: WINDOW_W, // patterns/publisher.js — is_overlap_window_W3 (sub-step 2d)
  K: WINDOW_K, // patterns/publisher.js — is_known_contributor_K10 (sub-step 2e)
  MIN_HISTORY_DEPTH,
  MIN_VERIFIED_VERSIONS,
  CHURNING_WINDOW,
  SOLO_DOMINANCE,
  HIGH_PRIOR_TENURE: __thresholds.HIGH_PRIOR_TENURE,
  EXCEPTIONAL_PRIOR_TENURE: __thresholds.EXCEPTIONAL_PRIOR_TENURE,
  MIN_PROVENANCE_HISTORY,
  MIN_BASELINE_STREAK,
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
              publisher_tool, provenance_present
       FROM versions
       WHERE package_id = ?`,
    )
    .all(packageId);
  return rows.map((r) => ({
    version_id: r.id,
    version: r.version,
    publisher_name: r.publisher_name,
    publisher_email: r.publisher_email,
    publisher_tool: r.publisher_tool,
    provenance_present: r.provenance_present,
    published_at_ms: r.published_at ? Date.parse(r.published_at) : null,
  }));
}

function loadAttackLabels(db, packageId) {
  return db
    .prepare(
      `SELECT id, version_id, is_malicious, affected_range,
              advisory_id, source, provenance_source, summary,
              detection_lag_days
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

// Locate the tenure block whose [first_published_at_ms,
// last_published_at_ms] contains the given timestamp. Re-implemented
// locally rather than imported from disposition.js (which has its own
// internal version) to keep run-validation.js self-contained.
function tenureBlockContaining(publishedAtMs, tenure) {
  if (typeof publishedAtMs !== 'number' || !Array.isArray(tenure)) return null;
  for (const b of tenure) {
    if (publishedAtMs >= b.first_published_at_ms && publishedAtMs <= b.last_published_at_ms) {
      return b;
    }
  }
  return null;
}

// Walk provOut.perVersion and call hasProvenanceEscalator directly on
// every in-scope regression fire. Returns a list of { version,
// escalators[], fired, perVersionSignal } — the single source of truth
// for provenance-driven aggregates (§4a, §4b, §4c). Using the
// structural escalator evaluator directly avoids the hidden format-
// string contract a reason-string grep would create.
function iterateProvenanceFires(provOut, publisherOutput) {
  const fires = [];
  if (!provOut || !Array.isArray(provOut.perVersion)) return fires;
  for (const v of provOut.perVersion) {
    if (!v || !v.in_scope) continue;
    if (!v.provenance_regression) continue;
    const esc = hasProvenanceEscalator(v, publisherOutput, provOut, null);
    fires.push({
      version: v.version,
      escalators: esc.escalators,
      fired: esc.fired,
      perVersionSignal: v,
    });
  }
  return fires;
}

// Nearest-rank quartiles over a pre-sorted ascending integer array.
// Returns null when n=0 so the aggregate emits literal `null` for
// corpora without lag data.
function computeQuartiles(sortedInts) {
  const n = sortedInts.length;
  if (n === 0) return null;
  const pick = (p) => sortedInts[Math.min(n - 1, Math.max(0, Math.ceil(p * n) - 1))];
  return {
    n,
    min: sortedInts[0],
    q1: pick(0.25),
    median: pick(0.5),
    q3: pick(0.75),
    max: sortedInts[n - 1],
  };
}

// Per-attack row. "detected" = at least one candidate version is AT or
// AFTER a BLOCK verdict within the same tenure block. Class A (exact-
// version BLOCK) and Class C (BLOCK fires at block-start, label targets
// a later version in the same block) resolve uniformly through the
// at-or-after walk.
//
// The recorded detected_version is the BLOCK anchor, not the label
// target — a reader needs to know WHERE the gate fired. For an exact-
// match Class A case the two coincide; for Class C they differ
// (event-stream labels at 3.3.6, gate fires at 3.3.5).
//
// Class B (label.kind='unspecified', candidate_versions=[]) is
// inherently undetectable at this layer — no version anchor to walk
// from. Such rows return with detected=false; they are excluded from
// recall_labels_point_attributable's denominator (see §4 aggregate
// computation in run()).
function buildPerAttackRow(pkgName, label, targets, extracted, verdicts, historyByVersion) {
  const tenure = extracted.tenure;
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
    detection_lag_days: label.detection_lag_days ?? null,
    shape: extracted.shape,
    providers_seen: extracted.identity_profile.providers_seen?.slice?.() ?? [],
    domain_stability: extracted.identity_profile.domain_stability ?? null,
    cell: null,
  };

  if (verdicts.size === 0 || targets.versions.length === 0) return row;

  // Pass 1: find any BLOCK — exact-version or at-or-after within
  // candidate's tenure block. First candidate (sorted) wins.
  let picked = null;
  for (const v of targets.versions) {
    const exact = verdicts.get(v);
    if (exact && exact.disposition === 'BLOCK') {
      picked = { anchor: v, verdict: exact };
      break;
    }
    const vRow = historyByVersion.get(v);
    if (!vRow || typeof vRow.published_at_ms !== 'number') continue;
    const vBlock = tenureBlockContaining(vRow.published_at_ms, tenure);
    if (!vBlock) continue;
    let bestAnchor = null;
    for (const [k, verdict] of verdicts) {
      if (verdict.disposition !== 'BLOCK') continue;
      if (k === v) continue;
      if (compareSemver(v, k) < 0) continue;
      const kRow = historyByVersion.get(k);
      if (!kRow || typeof kRow.published_at_ms !== 'number') continue;
      const kBlock = tenureBlockContaining(kRow.published_at_ms, tenure);
      if (kBlock !== vBlock) continue;
      if (bestAnchor === null || compareSemver(k, bestAnchor) < 0) bestAnchor = k;
    }
    if (bestAnchor !== null) {
      picked = { anchor: bestAnchor, verdict: verdicts.get(bestAnchor) };
      break;
    }
  }
  if (picked) {
    row.detected = true;
    row.detected_version = picked.anchor;
    row.detected_disposition = 'BLOCK';
    row.disposition_reason = picked.verdict.reason;
    const t = extracted.transitions.find((x) => x.at_version === picked.anchor);
    row.cell = t ? classifyCell(t) : null;
    return row;
  }

  // Pass 2: no BLOCK anywhere; record the first exact non-BLOCK verdict
  // for diagnostic visibility (not counted as detected).
  for (const v of targets.versions) {
    const verdict = verdicts.get(v);
    if (!verdict) continue;
    row.detected_version = v;
    row.detected_disposition = verdict.disposition;
    row.disposition_reason = verdict.reason;
    const t = extracted.transitions.find((x) => x.at_version === v);
    row.cell = t ? classifyCell(t) : null;
    break;
  }
  return row;
}

function run(options) {
  const split = loadSplit(options.split);
  const scope = options.mode === 'train' ? split.train_set : split.test_set;
  const scopePackages = scope.packages.slice().sort();
  const scopeSet = new Set(scopePackages);

  if (options.mode === 'train') {
    assertHeldOutsNotInTrain(scopeSet);
    assertTrainLockedInTrain(scopeSet);
  } else {
    assertHeldOutsInTest(scopeSet);
    assertTrainLockedNotInTest(scopeSet);
  }

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

    // Provenance-aware aggregate accumulators (§4a, §4b, §4c).
    let provenanceOnlyAttackDetected = 0;
    let provenanceOnlyCleanBlocked = 0;
    let publisherOnlyAttackDetected = 0;
    let provenanceOnlyAttackDetectedDecomp = 0;
    let bothAttackDetected = 0;
    const escalatorFireCounts = {
      new_domain: 0,
      privacy: 0,
      unverified: 0,
      machine_to_human: 0,
    };

    for (const pkgName of scopePackages) {
      const pkgId = nameToId.get(pkgName);
      if (pkgId == null) {
        throw new Error(`split names package '${pkgName}' not present in seed DB`);
      }
      const history = loadPackageHistory(db, pkgId);
      const historyById = new Map(history.map((h) => [h.version_id, h]));
      const historyByVersion = new Map(history.map((h) => [h.version, h]));

      const extracted = publisher.extract({ packageName: pkgName, history });
      const provOut = provenance.extract({ packageName: pkgName, history });
      const d = disposition(extracted, provOut);
      const verdicts = buildTransitionVerdicts(extracted, d);

      // Structural provenance classification, read off the fire list
      // rather than parsed out of reason strings.
      const provFires = iterateProvenanceFires(provOut, extracted);
      const provBlockAnchors = new Set(
        provFires.filter((f) => f.fired).map((f) => f.version),
      );
      const hasProvenanceBlockPkg = provBlockAnchors.size > 0;
      const hasPublisherBlockPkg = [...verdicts.entries()].some(
        ([k, v]) => v.disposition === 'BLOCK' && !provBlockAnchors.has(k),
      );

      for (const f of provFires) {
        for (const label of f.escalators) {
          if (Object.prototype.hasOwnProperty.call(escalatorFireCounts, label)) {
            escalatorFireCounts[label] += 1;
          }
        }
      }

      const isAttack = attackLabeled.has(pkgName);
      if (isAttack) {
        if (d.disposition === 'BLOCK') tpPackages += 1; else fnPackages += 1;
      } else {
        if (d.disposition === 'BLOCK') fpPackages += 1;
        else if (d.disposition === 'WARN') { warnClean += 1; tnPackages += 1; }
        else tnPackages += 1;
      }

      if (hasProvenanceBlockPkg) {
        if (isAttack) provenanceOnlyAttackDetected += 1;
        else provenanceOnlyCleanBlocked += 1;
      }
      if (isAttack && d.disposition === 'BLOCK') {
        if (hasPublisherBlockPkg && hasProvenanceBlockPkg) bothAttackDetected += 1;
        else if (hasPublisherBlockPkg) publisherOnlyAttackDetected += 1;
        else if (hasProvenanceBlockPkg) provenanceOnlyAttackDetectedDecomp += 1;
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
        provenance_regression_count: provFires.length,
        provenance_escalator_fires: provFires.filter((f) => f.fired).length,
      });

      if (isAttack) {
        const labels = loadAttackLabels(db, pkgId);
        for (const label of labels) {
          const targets = resolveLabelTargets(label, historyById);
          perAttack.push(
            buildPerAttackRow(pkgName, label, targets, extracted, verdicts, historyByVersion),
          );
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

    // Attributable denominator excludes Class B (unspecified labels
    // with zero candidate_versions) and range-based labels whose
    // range matched nothing in the observed history. Both classes
    // have no version anchor the gate could fire against; counting
    // them against recall mixes label-health signal with pattern
    // recall. recall_labels_point stays with the all-inclusive
    // denominator for continuity with commit 2.
    const attackLabelsAttributable = perAttack.filter(
      (r) => r.candidate_versions && r.candidate_versions.length > 0,
    ).length;
    const attackLabelsAttributableDetected = perAttack.filter(
      (r) => r.detected && r.candidate_versions && r.candidate_versions.length > 0,
    ).length;
    const labelRecallAttributablePoint = attackLabelsAttributable > 0
      ? round4(attackLabelsAttributableDetected / attackLabelsAttributable) : null;

    const recallProvenancePoint = attackPkgsInScope > 0
      ? round4(provenanceOnlyAttackDetected / attackPkgsInScope) : null;
    const fpRateProvenancePoint = cleanPkgsInScope > 0
      ? round4(provenanceOnlyCleanBlocked / cleanPkgsInScope) : null;

    const detectedLags = perAttack
      .filter((r) => r.detected && typeof r.detection_lag_days === 'number')
      .map((r) => r.detection_lag_days)
      .sort((a, b) => a - b);
    const detectionLagDaysQuartiles = computeQuartiles(detectedLags);

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
        split_version: split.split_version ?? 1,
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
        attack_labels_attributable: attackLabelsAttributable,
        recall_labels_point_attributable: labelRecallAttributablePoint,
        attack_packages_detected_publisher_only: publisherOnlyAttackDetected,
        attack_packages_detected_provenance_only: provenanceOnlyAttackDetectedDecomp,
        attack_packages_detected_both: bothAttackDetected,
        provenance_only_attack_detected: provenanceOnlyAttackDetected,
        provenance_only_clean_blocked: provenanceOnlyCleanBlocked,
        recall_provenance_point: recallProvenancePoint,
        false_positive_rate_provenance_point: fpRateProvenancePoint,
        escalator_fire_counts: escalatorFireCounts,
        detection_lag_days_quartiles: detectionLagDaysQuartiles,
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
