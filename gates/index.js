// Gate runner — aggregates per-gate results into a single disposition.
//
// Contract:
//
//   const runGates = createGateRunner({ modules, getOverride, logger });
//   const decision = runGates(input);
//
//   input:
//     { ecosystem, packageName, version, incoming, baseline, history, config }
//
//   decision:
//     { disposition: 'ALLOW' | 'WARN' | 'BLOCK',
//       results:     GateResult[],
//       override:    { reason, created_at } | null }
//
//   GateResult:
//     { gate: string, result: 'ALLOW'|'SKIP'|'WARN'|'BLOCK', detail: string }
//
// Aggregation rules:
//   1. If getOverride(pkg, ver) returns a row → short-circuit:
//      disposition = ALLOW
//      results     = [{ gate:'override', result:'ALLOW', detail:`override: ${reason}` }]
//      Real modules do NOT run — overrides exist to bypass known false
//      positives, and running gates would just waste cycles and pollute logs.
//      The synthetic override entry is still persisted so `chaingate status` can
//      show override history.
//
//   2. Otherwise run all modules in insertion order. A module is:
//         { name: string, evaluate: (input) => GateResult }
//      Module exceptions are caught per-module and surfaced as
//         { gate: module.name, result: 'SKIP', detail: `gate_error: ${msg}` }
//      Fail-open: a broken gate never escalates to BLOCK.
//
//   3. Aggregation (V2 foundation, Section 7 item 1):
//        blocks = results.filter(r => r.result === 'BLOCK').length
//        warns  = results.filter(r => r.result === 'WARN').length
//        if blocks > 0    → 'BLOCK'
//        elif warns > 0   → 'WARN'
//        else             → 'ALLOW'
//      SKIP results do NOT count. N-warnings-escalate-to-BLOCK was
//      removed during the V2 dev window to prevent cry-wolf: only
//      content-hash can currently BLOCK, so any BLOCK in results is a
//      true-positive-by-construction signal. V2 may re-introduce
//      escalation once pattern-aware gates produce low-FP WARNs.

import { MIN_HISTORY_DEPTH } from '../constants.js';
import contentHash from './content-hash.js';
import publisherIdentity from './publisher-identity.js';
import depStructure from './dep-structure.js';
import provenanceContinuity from './provenance-continuity.js';
import releaseAge from './release-age.js';
import scopeBoundary from './scope-boundary.js';

const VALID_RESULTS = new Set(['ALLOW', 'SKIP', 'WARN', 'BLOCK']);

// First-seen baseline poisoning protection (V2 foundation, Section 7 item 4
// of docs/V2_DESIGN.md). The constant lives in `constants.js` because
// `patterns/publisher.js` also consumes it — one source of truth. Packages
// with fewer than MIN_HISTORY_DEPTH observed prior versions have every gate
// NOT in the exempt set short-circuited to SKIP with a poisoning-protection
// detail.
//
// Only content-hash is exempt: it compares against a recorded baseline and
// does not rely on pattern extraction from history. Any future gate added to
// the exempt set must be explicitly justified — the default for any new gate
// is "pattern-based, requires depth."
//
// Re-exported here for backward compatibility with existing callers that
// import it from this module.
// TODO: migrate callers to import directly from ../constants.js
// (test/gates/runner.test.js is the remaining importer as of V2 sub-step 2f).
export { MIN_HISTORY_DEPTH };
const HISTORY_INDEPENDENT_GATES = new Set(['content-hash']);

export const DEFAULT_GATE_MODULES = Object.freeze([
  contentHash,
  depStructure,
  publisherIdentity,
  provenanceContinuity,
  releaseAge,
  scopeBoundary,
]);

function normalizeResult(moduleName, raw) {
  if (raw == null || typeof raw !== 'object' || !VALID_RESULTS.has(raw.result)) {
    return {
      gate: moduleName,
      result: 'SKIP',
      detail: 'malformed gate output',
    };
  }
  return {
    gate: typeof raw.gate === 'string' && raw.gate ? raw.gate : moduleName,
    result: raw.result,
    detail: typeof raw.detail === 'string' ? raw.detail : '',
  };
}

function aggregate(results) {
  let blocks = 0;
  let warns = 0;
  for (const r of results) {
    if (r.result === 'BLOCK') blocks += 1;
    else if (r.result === 'WARN') warns += 1;
  }
  if (blocks > 0) return 'BLOCK';
  if (warns > 0) return 'WARN';
  return 'ALLOW';
}

export function createGateRunner({
  modules = DEFAULT_GATE_MODULES,
  getOverride = null,
  services = null,
  logger = null,
} = {}) {
  if (!Array.isArray(modules)) {
    throw new Error('createGateRunner: modules must be an array');
  }
  const log = logger ?? { info() {}, warn() {}, error() {} };
  const boundServices = services ?? {};

  return function runGates(input) {
    // Merge injected services with any caller-provided services (tests).
    const mergedServices = { ...boundServices, ...(input?.services ?? {}) };
    const gateInput = { ...input, services: mergedServices };

    if (getOverride && typeof getOverride === 'function') {
      let override = null;
      try {
        override = getOverride(input.packageName, input.version);
      } catch (err) {
        log.warn(
          `[gates] override lookup failed for ${input.packageName}@${input.version}: ${err.message}`,
        );
      }
      if (override) {
        const reason = override.reason ?? '(no reason)';
        return {
          disposition: 'ALLOW',
          results: [
            {
              gate: 'override',
              result: 'ALLOW',
              detail: `override: ${reason}`,
            },
          ],
          override: {
            reason,
            created_at: override.created_at ?? null,
          },
        };
      }
    }

    const priorCount = Array.isArray(input?.history)
      ? input.history.filter((h) => h && h.version !== input.version).length
      : 0;
    const insufficientHistory = priorCount < MIN_HISTORY_DEPTH;

    const results = [];
    for (const mod of modules) {
      const name = mod?.name ?? 'anonymous';
      if (insufficientHistory && !HISTORY_INDEPENDENT_GATES.has(name)) {
        results.push({
          gate: name,
          result: 'SKIP',
          detail: `insufficient history (${priorCount} prior version(s), need ${MIN_HISTORY_DEPTH}) — first-seen poisoning protection`,
        });
        continue;
      }
      try {
        const raw = mod.evaluate(gateInput);
        results.push(normalizeResult(name, raw));
      } catch (err) {
        log.warn(
          `[gates] ${name} threw on ${gateInput.packageName}@${gateInput.version}: ${err.message}`,
        );
        results.push({
          gate: name,
          result: 'SKIP',
          detail: `gate_error: ${err.message}`,
        });
      }
    }

    return {
      disposition: aggregate(results),
      results,
      override: null,
    };
  };
}

