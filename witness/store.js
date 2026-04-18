// Orchestration layer between the proxy, the witness DB, and the gate runner.
//
// Contract:
//   const witness = createWitness({ db, runGates, config, logger });
//   const result  = witness.observePackument(packageName, packument);
//     → {
//         decisions: Map<version, { disposition, results }>,
//         newBaselines: number,
//         versionsSeen: number,
//       }
//     The map value is an OBJECT, not a bare disposition string.
//     `results` is the per-gate array as returned by runGates (already
//     normalized); on runner-threw fallback it is the synthetic
//     [{ gate: 'runner_error', result: 'SKIP', ... }] entry.
//
//   const result  = witness.observeTarball(packageName, filename);
//     → { disposition: 'ALLOW' }
//     Pass-through by design. Tarball-level blocking is performed in
//     proxy/server.js via db.getLatestDecision on the version extracted
//     from the filename; the store does not duplicate that lookup.
//
// Guarantees:
//   - parses every version in the packument via witness/baseline.js
//   - opens ONE better-sqlite3 transaction per observePackument call
//   - per-version errors are caught inside the txn so one bad entry cannot
//     roll back the whole batch (throwing would abort the entire txn)
//   - first-seen: recordBaseline + insert a gate_decisions row with a
//     synthetic first-seen ALLOW entry prepended to the gate results
//   - re-observe: recordBaseline is idempotent; a new gate_decisions row
//     is written ONLY when the disposition differs from the latest prior
//     decision for (pkg, version) — state-change logging, not append-on-observe
//   - runGates() is called inside the transaction for every version;
//     runner-level throws surface as a synthetic runner_error SKIP result
//     with disposition ALLOW (fail-open)
//
// The store does NOT mutate the packument. Packument rewriting lives in
// gates/rewriter.js and is driven from proxy/server.js.

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
    // Pass-through by design. Tarball-level blocking is performed in
    // proxy/server.js via db.getLatestDecision on the version extracted
    // from the filename — keeping the lookup at the proxy layer avoids
    // re-parsing the filename here and double-reading the decisions table.
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
