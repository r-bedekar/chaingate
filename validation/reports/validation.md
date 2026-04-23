# ChainGate v2 validation report

## 1. TL;DR

Under the v2 seed corpus (commit `e71e511`), ChainGate detected both
attack-labeled packages in the held-out test pool. Test recall
(package-level) is **1.0 (2 / 2)**, 95% Wilson CI **[0.3424, 1.0000]** —
the interval is wide because the test pool is small, and the lower
bound is the honest statement that a 2-of-2 observation does not
pin down true recall. Test false-positive rate is **0.25 (1 / 4)**,
CI **[0.0456, 0.6994]**; test precision is **0.6667 (2 / 3)**, CI
**[0.2077, 0.9385]**. On the training pool (98 packages, 7
attack-labeled), package-level recall is 0.2857 (2 / 7) — chalk
and eslint-config-prettier were BLOCKed — and the false-positive
rate is **0.3407 (31 / 91)**, CI **[0.2515, 0.4427]**. The 0.05
false-positive target is not met at the publisher layer under v2;
the calibration sweep confirmed this ceiling rather than dislodging
it. See `METHODOLOGY.md §9` for the full framing of that result.

## 2. How to read this report

Methodology, rationale, and the canonical framing of limitations
live in `validation.md`'s companion, `validation/METHODOLOGY.md`.
This document reports numbers and their uncertainty; every
methodological choice (the split design, the Wilson score interval,
the calibration selection rule, the FP-target framing) is
described there and cross-referenced from here. Numbers are drawn
from the validation and calibration artifacts committed at HEAD
`e71e511`: `validation/results.json` (training run),
`validation/calibration/sensitivity-results.json`,
`validation/calibration/sweep-results.json`,
`validation/calibration/optimal-params.json`, and a test-mode
re-run of `validation/run-validation.js` under the same commit.

## 3. Attack coverage

Attack coverage is measured at two denominators and the two
disagree. Package-level training recall is **2 / 7 = 0.2857**
(`results.json .aggregates.recall_packages_point`): chalk and
eslint-config-prettier BLOCK at the package level, and the remaining
five attack-labeled training packages do not. Label-level training
recall is **0 / 12 = 0** (`.recall_labels_point`): the BLOCKs that
trigger on chalk and eslint-config-prettier occur at versions
outside the labeled advisory ranges, so at the label granularity
every training advisory counts as a miss even though two packages
are detected. The table below is at label granularity — one row per
advisory or attack-label entry — so readers should interpret it
against the label denominator, not the package denominator. Test data
follows the same pattern: package-level recall 2/2, label-level
recall 3/4 (see table).

On the held-out test pool, both attack-labeled packages (axios,
event-stream) are BLOCKed. Label-level test recall is **3 / 4 =
0.75**: three of the four test label rows fire, with the fourth
(axios MAL-2026-2307, label_kind=unspecified) a miss-attribution
case.

| # | Package | Advisory | Bucket | Detected | Pattern | Shape | Domain stability |
|---|---|---|---|---|---|---|---|
| 1 | axios | — | test | Y | provenance_regression (committee) | committee | — |
| 2 | axios | MAL-2026-2307 | test | N | miss-attribution | committee | — |
| 3 | event-stream | — | test | Y | cold_handoff (solo) | solo | — |
| 4 | event-stream | GHSA-mh6f-8j2x-4483 | test | Y | cold_handoff (solo) | solo | — |
| 5 | chalk | MAL-2025-46969 | train | N | miss-attribution | solo | stable |
| 6 | coa | GHSA-73qr-pfmq-6rp8 | train | N | miss-attribution | committee | mixed |
| 7 | debug | GHSA-4x49-vf9v-38px | train | N | miss-attribution | committee | churning |
| 8 | debug | MAL-2025-46974 | train | N | miss-attribution | committee | churning |
| 9 | eslint-config-prettier | GHSA-f29h-pxvx-f335 | train | N | miss-attribution | solo | stable |
| 10 | eslint-config-prettier | MAL-2025-6022 | train | N | miss-attribution | solo | stable |
| 11 | node-ipc | GHSA-97m3-w2cp-4xx6 | train | N | miss-attribution | solo | stable |
| 12 | rc | GHSA-g2q5-5433-rhrf | train | N | miss-attribution | solo | stable |
| 13 | ua-parser-js | — | train | N | miss-scope | solo | stable |
| 14 | ua-parser-js | — | train | N | miss-scope | solo | stable |
| 15 | ua-parser-js | — | train | N | miss-scope | solo | stable |
| 16 | ua-parser-js | GHSA-pjwm-rvh2-c87w | train | N | miss-scope | solo | stable |

The four ua-parser-js rows are labeled from a reconstructed-fixture
source (three version-pinned rows and one OSV-advisory range row
that intersects one of the reconstructed versions); see
`METHODOLOGY.md §3` for the corpus composition note.

**Observation.** No miss in the table above is a pattern-fired-and-
missed case. Every miss traces either to architectural scope
(ua-parser-js rows, marked miss-scope: the attack shape has no v2
publisher-layer signature on the seed data) or to label attribution
(marked miss-attribution: the label is range-only, null, or
unspecified, with no seed-version anchor the pattern could fire
against). The publisher and provenance layers did not fail to fire
on any version they had the attribution for.

## 4. False positives

**Training pool (n=91 clean packages).** False-positive rate
**0.3407 (31 / 91)**, 95% Wilson CI **[0.2515, 0.4427]**
(`results.json .aggregates.false_positive_rate_point`,
`.clean_packages_blocked`, `.corpus.clean_packages`). Of the 91
clean training packages, 31 BLOCK, 44 WARN, and 16 ALLOW — the
BLOCK count is what drives the FP metric.

**Test pool (n=4 clean packages).** False-positive rate
**0.25 (1 / 4)**, CI **[0.0456, 0.6994]**. The one flagged clean
test package is `async`; the other three clean test packages (ajv,
vite, yargs) do not BLOCK. Test precision, incorporating the two
true positives and this one false positive, is **0.6667 (2 / 3)**,
CI **[0.2077, 0.9385]**.

Training and test point estimates differ (0.3407 vs. 0.25), but the
CIs overlap substantially — Wilson bounds for the training rate
cover [0.2515, 0.4427] and the test rate's CI covers [0.0456,
0.6994]. The test CI's lower bound (0.0456) falls just below the
0.05 §2 target, and its upper bound reaches 0.6994; the observation
does not rule out a true test FP rate consistent with target, though
it does not establish one either.

## 5. Decomposition

Point estimates without CIs per the `METHODOLOGY.md §8` reporting
convention; these describe *where* detection happened, not
layer-level performance estimates.

**Training pool.** 2 packages detected, all via the publisher
layer (`publisher_only=2`, `provenance_only=0`, `both=0`). The
provenance layer fires independently on 1 clean package (the
`new_domain` escalator, `escalator_fire_counts.new_domain=1`),
contributing to a provenance-layer false-positive rate of
**0.011 (1 / 91)**. Other escalators (`privacy`, `unverified`,
`machine_to_human`) did not fire on the training pool.

**Test pool.** 2 packages detected, decomposed as 1 via
publisher only (event-stream, cold-handoff on solo tenure) and
1 via provenance only (axios, committee shape, escalators
`new_domain` + `privacy` + `machine_to_human` all firing). The
two layers covered disjoint attacks on this pool — event-stream
is a classic publisher-takeover shape the publisher layer is
designed for; axios is a committee-shape package where the
publisher layer does not fire and the provenance regression
surface carried the detection. Provenance-layer test FP is
**0 (0 / 4)**.

## 6. Known limitations

- **Publisher-layer false-positive target unmet.** Training FP
  0.3407 exceeds the 0.05 target by 6.8×. The calibration sweep
  characterized this as a corpus-level ceiling under v2, not a
  tuning oversight; full framing in `METHODOLOGY.md §9`.
- **Small-N test pool.** Test-set denominators are 4 clean and 2
  attack packages; CIs are wide by construction. See
  `METHODOLOGY.md §9` for the small-N framing.
- **Label-quality audit deferred.** The planned manual sample of
  approximately 30 attack labels was not executed under the
  initial validation pass; systematic bias from mislabeled entries
  is not characterized. Named as future work in
  `METHODOLOGY.md §9` and §11.
- **Reconstructed-fixture provenance for ua-parser-js.** Three of
  the four ua-parser-js label rows come from reconstructed-fixture
  data rather than OSV advisories. This is disclosed in the §3
  table via the pattern column (miss-scope) and elaborated in
  `METHODOLOGY.md §3`.
- **Provenance-layer constants not calibrated.** The sensitivity
  and calibration passes covered only publisher-layer constants;
  provenance-layer thresholds carry starter values. See
  `METHODOLOGY.md §9` and §11.

## 7. Summary

The v2 calibration pass established a specific, defensible result:
on the held-out test pool, both locked attack packages were
detected (publisher-layer on event-stream, provenance-layer on
axios), and the starter constants already sit at the training-pool
FP-minimum among recall-preserving grid points. The publisher-layer
FP ceiling under this corpus is 0.3407, 6.8× above the 0.05 target
— a ceiling the calibration pass characterized rather than removed.
See `METHODOLOGY.md §9` for the full framing: under v2, further
publisher-layer FP reduction is constrained by the same recall pin
that makes chalk and eslint-config-prettier detectable at all, and
further progress has to come from provenance-layer tuning or a
larger, restructured corpus.
