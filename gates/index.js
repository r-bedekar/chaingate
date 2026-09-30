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
// Only content-hash and seed-v3 are exempt: neither relies on pattern
// extraction from LOCALLY observed history. Any future gate added to the
// exempt set must be explicitly justified — the default for any new gate
// is "pattern-based, requires depth."
//
// seed-v3 justification (CFT-05). The protection exists because a first-seen
// package's locally recorded baseline can be attacker-supplied, so a gate that
// learns its expectations from that baseline can be taught anything. The
// seed-v3 gate reads NO local baseline: its history comes from the seed
// artifact, and its only BLOCK is a recorded advisory pin naming that exact
// version. It also handles thin history itself and more honestly than a SKIP
// does — an unseeded release reports NOT_EVALUATED coverage with the reason,
// which its policy layer must not read as clean. Skipping it here would have
// meant a package the proxy happens to be seeing for the first time is
// installed without the known-malware check ever being consulted.
//
// Re-exported here for backward compatibility with existing callers that
// import it from this module.
// TODO: migrate callers to import directly from ../constants.js
// (test/gates/runner.test.js is the remaining importer as of V2 sub-step 2f).
export { MIN_HISTORY_DEPTH };
const HISTORY_INDEPENDENT_GATES = new Set(['content-hash', 'seed-v3']);

export const DEFAULT_GATE_MODULES = Object.freeze([
  contentHash,
  depStructure,
  publisherIdentity,
  provenanceContinuity,
  releaseAge,
  scopeBoundary,
]);

// FAIL-OPEN, AND WHERE IT STOPS.
//
// D1's fail-open is right for a pattern gate that could not run: one broken module among several
// that still produced evidence should not block an install. It is NOT right for a gate whose BLOCK
// rests on a recorded advisory naming this exact version -- there, "the gate threw" silently became
// ALLOW and the known-malware check was simply lost.
//
// So a module may DECLARE what its own failure means, and the runner still invents nothing:
//
//   mod.onError(err) -> GateResult   the module's own statement, e.g. routed through its policy
//   mod.onErrorResult                a plain ALLOW/SKIP/WARN/BLOCK to use when onError is absent or
//                                    itself throws -- chosen by the operator when the gate is wired
//
// A module that declares neither behaves exactly as before: SKIP. Every pilot gate declares neither,
// so their behaviour is unchanged.
function declaredErrorResult(mod) {
  return VALID_RESULTS.has(mod?.onErrorResult) ? mod.onErrorResult : 'SKIP';
}

// IDENTITY (U-05 Amendment 1). Every failure below happens for a known package and version -- the runner holds both
// in its input -- and a module's `onError(err, identity)` is told them, so a gate whose BLOCK rests on a recorded
// advisory for that exact version can still find it. A module that declares nothing ignores them: unchanged.
function identityOf(input) {
  const pkg = input?.packageName;
  const version = input?.version;
  return typeof pkg === 'string' && pkg !== '' && typeof version === 'string' && version !== ''
    ? { packageName: pkg, version } : null;
}

function normalizeResult(moduleName, raw, mod = null, identity = null, { askOnError = true } = {}) {
  if (raw == null || typeof raw !== 'object' || !VALID_RESULTS.has(raw.result)) {
    // Malformed output is a failure of the module like a throw is, so a module that DECLARES what its failure means
    // is asked (once), with the identity. A module that declares no onError -- every pilot gate -- is unchanged.
    if (askOnError && typeof mod?.onError === 'function') {
      return moduleErrorResult(mod, moduleName, new Error('malformed gate output'), null, identity);
    }
    return {
      gate: moduleName,
      result: declaredErrorResult(mod),
      detail: 'malformed gate output',
    };
  }
  return {
    gate: typeof raw.gate === 'string' && raw.gate ? raw.gate : moduleName,
    result: raw.result,
    detail: typeof raw.detail === 'string' ? raw.detail : '',
  };
}

/** What one module's failure means, as the module itself declares it. */
function moduleErrorResult(mod, name, err, log, identity = null) {
  if (typeof mod?.onError === 'function') {
    try {
      return normalizeResult(name, mod.onError(err, identity), mod, identity, { askOnError: false });
    } catch (inner) {
      log?.error?.(`[gates] ${name}.onError threw: ${inner.message}`);
      return {
        gate: name,
        result: declaredErrorResult(mod),
        detail: `gate_error: ${err.message}; onError also threw: ${inner.message}`,
      };
    }
  }
  return { gate: name, result: declaredErrorResult(mod), detail: `gate_error: ${err.message}` };
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

  function runGates(input) {
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
    const identity = identityOf(input);
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
        results.push(normalizeResult(name, raw, mod, identity));
      } catch (err) {
        log.warn(
          `[gates] ${name} threw on ${gateInput.packageName}@${gateInput.version}: ${err.message}`,
        );
        results.push(moduleErrorResult(mod, name, err, log, identity));
      }
    }

    return {
      disposition: aggregate(results),
      results,
      override: null,
    };
  };

  /**
   * What a failure of the WHOLE observation means -- the runner threw, the transaction failed, a
   * version could not be parsed at all. Built from each module's own declaration, so a caller that
   * previously manufactured `ALLOW` out of an exception can ask instead of assuming. With no module
   * declaring anything this aggregates to ALLOW, which is exactly the previous behaviour.
   *
   * `identity` (U-05 Amendment 1): the caller's request-bound `{packageName, version}` when it holds both. The
   * exact-version override is checked here, because no failure path ever reached the override short-circuit above:
   * for an overridden version the modules are told so and consult no advisory, which keeps that version's outcome
   * exactly as it was. An unreadable override store counts as no override, as in runGates.
   */
  runGates.failureDecision = (err, identity = null) => {
    let id = identityOf(identity);
    if (id && getOverride && typeof getOverride === 'function') {
      let overridden = false;
      try {
        overridden = Boolean(getOverride(id.packageName, id.version));
      } catch (e) {
        log.warn(`[gates] override lookup failed for ${id.packageName}@${id.version}: ${e.message}`);
      }
      id = { ...id, overridden };
    }
    const results = modules.map((mod) => moduleErrorResult(mod, mod?.name ?? 'anonymous', err, log, id));
    return { disposition: aggregate(results), results, override: null };
  };

  return runGates;
}

