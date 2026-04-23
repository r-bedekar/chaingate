# ChainGate validation methodology

This document describes how ChainGate's v2 detection performance was
measured against its seed corpus: what was in scope, which parameters
were tuned, how confidence intervals were computed, and what the
calibration pass could and could not establish. Numbers cited here are
reproducible from artifacts committed in this repository; `validation.md`
reports the findings themselves.

## 1. Domain concepts

npm's registry vests publishing authority in accounts rather than in
source repositories. A tarball carries a maintainer identity at publish
time; it does not carry build provenance unless the publisher opts in
via npm's SLSA attestation flow. ChainGate's two detection layers —
publisher and provenance — are designed around that trust surface, and
the rest of this document assumes the four concepts below.

**Publisher identity.** The publisher of an npm version is the account
listed in `_npmUser` on the tarball and, by extension, the `maintainers`
array and the email address on each. ChainGate keys on this surface,
not on repository committers. A compromised or handed-off maintainer
account is the unit of risk; a compromised repo contributor whose patch
lands under an established maintainer is not.

**Tenure block.** A tenure block is a contiguous run of versions
published under a single publisher-identity signature — same account,
same email — bounded by any identity change. Tenure blocks are the
building block of the publisher pattern: they let the detector reason
about "this maintainer has shipped the last N versions, and now a
different account appears."

**Cold handoff.** The publisher pattern fires when an established tenure
block (a stable maintainer for at least W of the last K versions) is
interrupted by a version from a previously-unseen publisher, optionally
accompanied by a new email domain. This is the shape behind the 2025
chalk and eslint-config-prettier takeovers: long-stable solo-publisher
packages whose next release arrived under a new account, stolen
credentials in hand.

**Provenance layer.** npm's provenance surface (SLSA attestation
emitted by `npm publish --provenance`) records the build origin of a
published tarball. ChainGate's provenance layer fires on *regressions*
in attestation metadata across a publisher's tenure — a known-signed
lineage suddenly publishing unsigned, or an attested build origin
changing from a CI runner to a personal machine. It does not fire on
mere absence of attestation, which is still the default across most of
the ecosystem.

## 2. Threat model and detection goal

ChainGate targets compromised-maintainer and cold-handoff takeovers of
established packages — the class of attacks where an adversary obtains
an existing publisher's credentials (or a maintainer transfers the
project to a new account who immediately publishes malware) and ships a
malicious version that installs under the package's established name.
Out of scope: typosquatting (new packages impersonating established
ones), dependency confusion (private/public registry collisions),
runtime exploitation of legitimate code, and postinstall-script abuse
that does not change publisher identity or provenance metadata. Those
attack classes have their own signatures and their own detectors; they
are not what the v2 patterns measure.

Detection is decomposed into two layers that fire independently: a
publisher layer (tenure-block reasoning over identity changes) and a
provenance layer (regression detection across attestation metadata). A
package is flagged if either layer fires. Measuring them independently
matters because the two layers observe different parts of the adversary
surface; §5 of this document and the decomposition section of
`validation.md` break the layers apart in results reporting.

## 3. Corpus and seed

The measurement corpus is 104 npm packages drawn from a fixed seed list
(`collector/seeds/npm_top.txt`) plus reconstructed-fixture additions
for ua-parser-js. Attack labels are sourced from OSV advisories
(GHSA and MAL identifiers) and, for ua-parser-js specifically, from a
set of reconstructed-fixture rows that encode the 2021 takeover
versions. 9 packages carry attack labels (7 in the training pool, 2
in the held-out test pool — axios and event-stream — where axios and
event-stream are the locked test attacks); the remainder are
clean-labeled controls.

Reproducing the numbers in this document requires the seed database
snapshot at `seed_export/chaingate-seed.db`. That snapshot fixes the
version history, publisher identities, and attestation metadata against
which the detector runs; without it, corpus composition and label
assignments would drift as npm continues to publish. All sensitivity,
calibration, and validation runs are keyed to this snapshot.

## 4. Detection method

The publisher layer is implemented in `patterns/publisher.js` and
consumes five tunable constants: W (window length), K (context
length), MIN_VERIFIED_VERSIONS (minimum tenure depth before a
package becomes eligible), CHURNING_WINDOW (the span over which
repeated identity changes disable the pattern), and SOLO_DOMINANCE
(the minimum fraction of a window that a single publisher must hold
to count as an established tenure). The provenance layer is
implemented alongside it, consumes its own constants
(MIN_PROVENANCE_HISTORY, MIN_BASELINE_STREAK, HIGH_PRIOR_TENURE,
EXCEPTIONAL_PRIOR_TENURE), and surfaces four named escalators:
`new_domain`, `privacy`, `unverified`, and `machine_to_human`.

Dispositions for a package are one of `ALLOW`, `WARN`, or `BLOCK`.
Only `BLOCK` counts as detection for false-positive and recall
accounting; `WARN` is reported in aggregates but does not fire the
detection gate. The full disposition logic, including escalator
tiering and regression-shape classification, lives in the pattern
modules and is not reproduced here.

Commits `d7adcd7`, `f6ebe0a`, and `e71e511` mark the measurement
method's current state: the v2 split, the sensitivity analysis that
selected which constants to tune, and the calibration sweep that
characterized the publisher-layer ceiling.

## 5. Train/test split

`validation/calibration/train-test-split.json` (commit `d7adcd7`,
`split_version=2`) partitions the 104-package corpus into a
98-package training pool and a 6-package held-out test pool. Two
packages are hard-locked into the test pool regardless of random
draw (`held_out_packages`: axios, event-stream) because their
attack-label provenance is attributable at version level and they
serve as the locked test attacks. Four packages are hard-locked into
the training pool (`train_locked_packages`: chalk, coa,
eslint-config-prettier, rc) — the 2025 publisher-takeover cases
whose characteristics drove the starter constants and whose presence
in the training pool is the point of the calibration pass.

Locked packages are placed first; the remaining corpus is then
stratified by attack/clean label in the standard way, with the RNG
drawing clean-sample packages into the test pool to pad it to size.
The RNG
is `mulberry32` seeded at `20260422`. Re-running the split from the
same seed with the same corpus list produces a byte-identical output
file; drift in either input surfaces as a diff to the split.

## 6. Sensitivity analysis

The sensitivity pass (commit `f6ebe0a`, artifact
`validation/calibration/sensitivity-results.json`) perturbs each of
five publisher-layer constants (W, K, MIN_VERIFIED_VERSIONS,
CHURNING_WINDOW, SOLO_DOMINANCE) one level up and one level down from
the starter values, re-runs the full training-pool validation under
each perturbation, and records the resulting ΔFP and Δrecall against
the starter baseline. Constants outside the publisher layer
(MIN_PROVENANCE_HISTORY, MIN_BASELINE_STREAK, tenure thresholds) are
not perturbed in this pass; they are out of scope for v2 calibration
and revisiting them is future work.

A retention rule — `|Δrecall| ≥ 0.02 OR |ΔFP| ≥ 0.005` — decides
which constants carry forward into the calibration grid. The
threshold is calibrated against the corpus granularity: a recall
shift of 0.1429 (1 attack package out of 7) is the smallest non-zero
signal, and an FP shift of 0.011 (1 clean package out of 91) is
likewise the corpus minimum. A constant whose perturbation moves
neither metric above those thresholds cannot, under this corpus,
contribute information to the grid search. Under v2, W, K, and
CHURNING_WINDOW all produced zero deltas in both directions and were
dropped; MIN_VERIFIED_VERSIONS (ΔFP=0.0219) and SOLO_DOMINANCE
(ΔFP=0.044, Δrecall=0.2857) were retained.

A notable artifact of this pass: the SOLO_DOMINANCE upper
perturbation (value=0.85) collapses training recall to 0. At that
threshold, chalk and eslint-config-prettier — the two packages that
the starter constants *do* catch — stop triggering the cold-handoff
pattern. This result hard-pins the SOLO_DOMINANCE axis of the
calibration grid from above: values ≥ 0.85 are excluded by
construction, not by optimization outcome.

## 7. Calibration

Calibration (commit `e71e511`, artifacts
`validation/calibration/sweep-results.json` and
`validation/calibration/optimal-params.json`) grid-searches the two
retained constants over the following axes:

- MIN_VERIFIED_VERSIONS ∈ {1, 2, 3, 4}
- SOLO_DOMINANCE ∈ {0.70, 0.75, 0.80}

12 grid points. The upper SOLO_DOMINANCE range (0.85, 0.90) is
pruned per the V7 finding from the sensitivity pass; including it
would introduce recall-zero points into the grid whose low FP is
structurally uninformative.

The selection rule proceeds in two stages. First, candidates are
filtered by an FP ceiling (FP ≤ 0.05); filter-passing candidates are
then ranked by (recall desc, FP asc, MVV asc, SD asc). Second, if
the filter set is empty, the grid is re-scanned under an FP-first
tie-break (FP asc, recall desc, MVV asc, SD asc) to identify the
best achievable FP under v2 and report that as a characterization,
not a selection. Every grid point in the V7-pruned search space
preserves training recall at 0.2857 by construction (§6); no
explicit recall floor is needed in the selection rule. The
selected-parameter branch and the best-achievable-only branch emit
different output shapes; both are documented in `optimal-params.json`.

Under v2, the filter set is empty — no grid point achieves FP ≤
0.05 — so the selected field is `null` and the best achievable FP is
reported: 0.3407 at (MIN_VERIFIED_VERSIONS=1, SOLO_DOMINANCE=0.80),
tied with (MIN_VERIFIED_VERSIONS=2, SOLO_DOMINANCE=0.80) under the
FP-first tie-break. Since the starter value is MIN_VERIFIED_VERSIONS=2
and SOLO_DOMINANCE=0.80, the starter constants already sit at the
grid FP-minimum among recall-preserving points. The calibration pass
therefore makes no change to the committed constants.

## 8. CI reporting convention

Four aggregates carry 95% confidence intervals in `validation.md`:
test recall, test false-positive rate, test precision, and training
false-positive rate. All four use the Wilson score interval — the
"score" method, not the normal approximation, not Agresti-Coull,
not exact binomial — with z = 1.959964, clamped to [0, 1], no
continuity correction.

Formula, for x successes out of n trials with p̂ = x/n:

```
center = (p̂ + z²/(2n)) / (1 + z²/n)
half   = (z / (1 + z²/n)) · √( p̂(1-p̂)/n + z²/(4n²) )
CI     = [center − half, center + half], clamped to [0, 1]
```

**Worked example — test recall, x=2, n=2:** p̂ = 1.0, z²/n = 1.92073,
center = (1 + 0.96037) / 2.92073 ≈ 0.6712, half = (1.959964 /
2.92073) · √(0 + 3.84146/16) ≈ 0.3288, CI = [0.3424, 1.0000] (upper
clamped from the raw Wilson value 0.99997; lower is 0.34238022
rounded to 4 decimals). That lower bound reads, plainly: *we cannot
rule out a true test recall as low as 34% on a 2-of-2 observation.*
The CI width is the small-N honesty that the point estimate hides.

**Decomposition metrics reported without CIs.** Publisher-only and
provenance-only detection counts, per-attack breakdowns, per-package
dispositions, and per-escalator fire counts appear in `validation.md`
as point estimates without intervals. At those denominators —
typically single digits — Wilson CIs would span most of [0, 1] and
communicate less than the raw counts do. CIs are reserved for the
four aggregates that most directly correspond to detection targets.

**Precision denominator.** Test precision is 2/3: two true positives
over the TP+FP trials (three flagged packages, two of which were
attack-labeled). The Wilson CI is computed on that same 2/3 binomial,
not on TP/(scope) or any other framing. This wording is stated
explicitly because precision CIs are a common spot for denominator
confusion between "flagged and correct" and "overall hit rate."

## 9. Calibration limitations

Under the v2 corpus, the best achievable publisher-layer training
false-positive rate is 0.3407 — 6.8× the §2 target of 0.05. No grid
point the sensitivity pass identified as worth searching achieves the
target; no grid extension under v2 would, because the
SOLO_DOMINANCE upper edge is pinned by the chalk and
eslint-config-prettier recall constraint documented in §6. The target
is not being met.

Reframed as a measurement outcome: the calibration pass
*characterized* the publisher-layer ceiling under this corpus, and
confirmed that the starter constants are already FP-minimal among the
recall-preserving grid points. That ceiling is itself a finding. It
either tells us the §2 target needs reformulation against a different
corpus or a different denominator, or it tells us that
publisher-layer false-positive reduction has hit a structural limit
and further progress has to come from provenance-layer signals —
which are measured in this report but not yet calibrated. Both
readings are on the table. What is *not* on the table, under v2, is
a publisher-layer tuning that both preserves recall and meets the
target.

**Stage-2 calibration deferred.** The calibration spec includes a
second-stage extension of the grid (finer resolution around the
selected point, or additional axes drawn from higher-order
sensitivity). Stage 2 is not executed under v2 because the
SOLO_DOMINANCE upper edge is hard-pinned by recall; a finer grid
below that edge would characterize the same ceiling at higher
compute cost. Stage 2 becomes worth running when a larger or
restructured corpus moves the recall pin; as long as the pin is
where it is, stage 2 is a no-op.

**Small-N test set.** The held-out test pool is 4 clean packages
and 2 attack-labeled packages. Point estimates on that pool (recall
1.0, FP 0.25, precision 0.6667) are each sitting on single-digit
denominators, and their Wilson CIs — reported in `validation.md §1`
and §4 — are correspondingly wide. A 2-of-2 recall observation is
consistent with a true recall in the mid-30s; a 1-of-4 FP observation
is consistent with a true FP rate anywhere from 4.6% to 70%. The
test pool is large enough to surface a qualitative pattern, not
large enough to tighten to a point.

**Label-quality audit deferred.** A planned manual audit of the
attack-labeled rows — sampling approximately 30 labels and verifying
each against upstream advisory records — was not executed under the
initial validation pass. The numbers in this report and in
`validation.md` assume the committed labels are correct. Systematic
bias from mislabeled entries (false attack labels inflating recall
denominators, missed attack labels inflating clean counts) is not
characterized. This is explicit future work.

**Provenance-layer constants not in scope.** The sensitivity pass
perturbed only publisher-layer constants; provenance-layer thresholds
(MIN_PROVENANCE_HISTORY, MIN_BASELINE_STREAK, the two tenure
thresholds) carry the starter values without sensitivity coverage.
The provenance layer's training FP is 0.011 (1 / 91) and its
training recall is 0 — numbers reported but not calibrated. A full
provenance-layer pass is future work.

## 10. Reproducibility contract

Every number in `validation.md` is reproducible from artifacts at
HEAD given the seed-DB snapshot. The commands:

```
# Training-pool run (recovers validation/results.json)
node validation/run-validation.js --mode=train

# Held-out test run (recovers the test-mode aggregates)
node validation/run-validation.js --mode=test --out=/tmp/test.json

# Sensitivity pass (recovers sensitivity-results.json)
node validation/calibration/run-sensitivity.js

# Calibration sweep (recovers sweep-results.json + optimal-params.json)
node validation/calibration/run-calibration.js
```

Each script writes atomically (`<path>.tmp + rename`) and is
deterministic under a fixed seed DB: re-running produces a
byte-identical output. Gated snapshot tests under
`CHAINGATE_SLOW_TESTS=1` enforce this property for the sensitivity
and calibration artifacts.

Parameter overrides for the validation script are available via
environment variables of the form `CHAINGATE_PARAM_<NAME>` (e.g.,
`CHAINGATE_PARAM_SOLO_DOMINANCE=0.75`). These are the same overrides
the sensitivity and calibration harnesses use internally.

## 11. Future work

- Label-quality audit: manual sample of ~30 attack labels against
  upstream advisory sources.
- Larger held-out pool: current n=6 limits test-set CI tightness;
  scaling to n≥20 would narrow intervals meaningfully.
- Provenance-layer sensitivity + calibration: perturb
  MIN_PROVENANCE_HISTORY, MIN_BASELINE_STREAK, HIGH_PRIOR_TENURE,
  EXCEPTIONAL_PRIOR_TENURE; grid over the retained axes.
- Stage-2 calibration: revisit when a larger or differently-structured
  corpus lifts the SOLO_DOMINANCE recall pin.
- Extended attack-label anchoring: where possible, upgrade range and
  unspecified labels to version-pinned anchors so the per-label
  recall metric becomes interpretable alongside per-package recall.
