// Orchestration layer between the proxy, the witness DB, and the gate runner.
//
// Contract:
//   const witness = createWitness({ db, runGates, config });
//   const result  = witness.observePackument(packageName, packument);
//     → { decisions: Map<version, disposition>, newBaselines, versionsSeen }
//   const result  = witness.observeTarball(packageName, filename);
//     → { disposition: 'ALLOW' }   // Day 4 stub; Day 5 adds blocked-version check
//
// Day 4 guarantees:
//   - parses every version in the packument via witness/baseline.js
//   - opens ONE transaction per observePackument call
//   - per-version errors are caught so one bad entry can't abort the whole run
//   - first-seen: recordBaseline + insert ALLOW gate_decision (first-seen)
//   - second-seen: baseline is idempotent no-op; bumpLastSeen handled by db.recordBaseline
//   - state-change logging: only writes a new gate_decisions row when disposition
//     differs from the latest prior decision for (pkg, version)
//   - runGates() is called inside the transaction for every version; errors per
//     version are caught and logged as a synthetic WARN "runner_error"
//
// The store does NOT mutate the packument. Rewriting is Day 5 (gates/rewriter.js).

import { parseVersionsFromPackument } from './baseline.js';

const ECOSYSTEM = 'npm';

const FIRST_SEEN_GATE_RESULT = Object.freeze({
  gate: 'first-seen',
  result: 'ALLOW',
  detail: 'baseline recorded on first observation',
});

export function createWitness({ db, runGates, config, logger }) {
  if (!db) throw new Error('createWitness: db is required');
  if (typeof runGates !== 'function') {
    throw new Error('createWitness: runGates must be a function');
  }
  const log = logger ?? noopLogger();
  const witnessConfig = config ?? {};

  function observePackument(packageName, packument) {
    if (typeof packageName !== 'string' || !packageName) {
      throw new Error('observePackument: packageName required');
    }
    const parsedVersions = parseVersionsFromPackument(packument);
    if (parsedVersions.length === 0) {
      return { decisions: new Map(), newBaselines: 0, versionsSeen: 0 };
    }

    const txn = db.db.transaction((versions) => {
      const history = db.getHistory(packageName);
      const decisions = new Map();
      let newBaselines = 0;

      for (const incoming of versions) {
        try {
          const existing = db.getBaseline(packageName, incoming.version);
          const input = {
            ecosystem: ECOSYSTEM,
            packageName,
            version: incoming.version,
            incoming,
            baseline: existing,
            history,
            config: witnessConfig,
          };

          let result;
          try {
            result = runGates(input);
          } catch (err) {
            log.warn(
              `[witness] runGates threw for ${packageName}@${incoming.version}: ${err.message}`,
            );
            result = {
              disposition: 'ALLOW',
              results: [
                {
                  gate: 'runner_error',
                  result: 'SKIP',
                  detail: `runner threw: ${err.message}`,
                },
              ],
            };
          }
          const disposition = result?.disposition ?? 'ALLOW';
          const gateResults = Array.isArray(result?.results) ? result.results : [];

          if (!existing) {
            db.recordBaseline(packageName, incoming.version, incoming);
            newBaselines += 1;
            const firstSeen = [FIRST_SEEN_GATE_RESULT, ...gateResults];
            db.insertGateDecision(packageName, incoming.version, disposition, firstSeen);
          } else {
            // Idempotent re-observe: bumpLastSeen fires inside recordBaseline's write path.
            db.recordBaseline(packageName, incoming.version, incoming);
            const prior = db.getLatestDecision(packageName, incoming.version);
            if (!prior || prior.disposition !== disposition) {
              db.insertGateDecision(packageName, incoming.version, disposition, gateResults);
            }
          }

          decisions.set(incoming.version, { disposition, results: gateResults });
        } catch (err) {
          log.warn(
            `[witness] version ${packageName}@${incoming.version} failed: ${err.message}`,
          );
          // Fail-open for this version. Leave any partial state untouched —
          // better-sqlite3 transactions wrap this whole block, so a THROW here
          // would roll back EVERY version, not just this one. We deliberately
          // swallow to keep per-version isolation.
          decisions.set(incoming.version, { disposition: 'ALLOW', results: [] });
        }
      }

      return { decisions, newBaselines, versionsSeen: versions.length };
    });

    try {
      return txn(parsedVersions);
    } catch (err) {
      // Transaction-level failure (DB error, schema drift). Caller decides
      // whether to fail-open; we surface it as a throw so the proxy logs it
      // and the response still goes out.
      throw err;
    }
  }

  function observeTarball(_packageName, _filename) {
    // Day 4 stub. Day 5 checks gate_decisions for a BLOCK disposition on
    // (pkg, version extracted from filename) and returns { disposition:'BLOCK' }
    // so the proxy can return 403.
    return { disposition: 'ALLOW' };
  }

  function close() {
    db.close();
  }

  return {
    observePackument,
    observeTarball,
    close,
    get config() { return witnessConfig; },
  };
}

function noopLogger() {
  return {
    info: () => {},
    warn: (msg) => { console.error(msg); },
    error: (msg) => { console.error(msg); },
  };
}
