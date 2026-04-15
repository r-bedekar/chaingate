// Gate runner — aggregates per-gate results into a single disposition.
//
// Contract (locked in docs/P5.md §6):
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
// Aggregation rules (docs/P5.md lines 522-544):
//   1. If getOverride(pkg, ver) returns a row → short-circuit:
//      disposition = ALLOW
//      results     = [{ gate:'override', result:'ALLOW', detail:`override: ${reason}` }]
//      Real modules do NOT run — overrides exist to bypass known false
//      positives, and running gates would just waste cycles and pollute logs.
//      The synthetic override entry is still persisted so `scw status` can
//      show override history.
//
//   2. Otherwise run all modules in insertion order. A module is:
//         { name: string, evaluate: (input) => GateResult }
//      Module exceptions are caught per-module and surfaced as
//         { gate: module.name, result: 'SKIP', detail: `gate_error: ${msg}` }
//      Fail-open: a broken gate never escalates to BLOCK.
//
//   3. Aggregation:
//        blocks = results.filter(r => r.result === 'BLOCK').length
//        warns  = results.filter(r => r.result === 'WARN').length
//        if blocks > 0                                  → 'BLOCK'
//        elif warns >= warnEscalationThreshold (def 4)  → 'BLOCK' (escalated)
//        elif warns > 0                                 → 'WARN'
//        else                                           → 'ALLOW'
//      SKIP results do NOT count toward warns.
//
//   4. P5.5 ships with DEFAULT_GATE_MODULES = []. Real modules land in
//      P5.6 (content-hash, publisher-identity, dep-structure) and P5.7
//      (provenance-continuity, release-age, scope-boundary).

import contentHash from './content-hash.js';
import publisherIdentity from './publisher-identity.js';
import depStructure from './dep-structure.js';
import provenanceContinuity from './provenance-continuity.js';
import releaseAge from './release-age.js';
import scopeBoundary from './scope-boundary.js';

const DEFAULT_WARN_ESCALATION = 4;
const VALID_RESULTS = new Set(['ALLOW', 'SKIP', 'WARN', 'BLOCK']);

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

function aggregate(results, threshold) {
  let blocks = 0;
  let warns = 0;
  for (const r of results) {
    if (r.result === 'BLOCK') blocks += 1;
    else if (r.result === 'WARN') warns += 1;
  }
  if (blocks > 0) return 'BLOCK';
  if (warns >= threshold) return 'BLOCK';
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

    const results = [];
    for (const mod of modules) {
      const name = mod?.name ?? 'anonymous';
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

    const threshold =
      Number.isFinite(gateInput?.config?.warnEscalationThreshold) && gateInput.config.warnEscalationThreshold > 0
        ? gateInput.config.warnEscalationThreshold
        : DEFAULT_WARN_ESCALATION;

    return {
      disposition: aggregate(results, threshold),
      results,
      override: null,
    };
  };
}

// Back-compat: a zero-module runner for code paths that haven't been
// updated to createGateRunner yet. P5.5 wires proxy/server.js through
// createGateRunner explicitly.
export function runGates(_input) {
  return { disposition: 'ALLOW', results: [], override: null };
}
