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
//   - (U-05 Amendment 1) every failure path passes the request-bound
//     { packageName, version } to runGates.failureDecision, so a gate can still
//     find a recorded advisory for that exact version; and a decision COMPUTED
//     before a later failure (a witness write, the transaction itself) is kept,
//     combined with what the failure declares, and marked `persisted: false` --
//     it is never reported as stored
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

  /**
   * What a failure means, as the configured gates declare it -- never a manufactured ALLOW.
   * `runGates.failureDecision` is provided by createGateRunner; a caller that injects a bare
   * function (tests do) falls back to the previous behaviour, which is what it always was.
   */
  // A failure decision is made because the gates could not run (`evaluated: false`), and is never stored on the path
  // that returns it (`persisted: false`): the proxy relies on both flags (U-05 Amendment 3, P6b and Rule K).
  function failureDecision(err, detail, identity = null) {
    if (typeof runGates.failureDecision === 'function') {
      const d = runGates.failureDecision(err, identity);
      return {
        disposition: d.disposition,
        results: [{ gate: 'observation_error', result: 'SKIP', detail }, ...d.results],
        persisted: false,
        evaluated: false,
      };
    }
    return {
      disposition: 'ALLOW',
      results: [{ gate: 'observation_error', result: 'SKIP', detail }],
      persisted: false,
      evaluated: false,
    };
  }

  /**
   * A decision already COMPUTED when a later step failed (U-05 Amendment 1, A3). The failure no longer replaces it:
   * it is combined with what the gates declare the failure means, so the result is never less severe than either --
   * a computed pin BLOCK survives a failed write, and a version the failure would have blocked is still blocked. It
   * was not stored, and says so.
   */
  function computedDespiteFailure(computed, err, what, identity) {
    const declared = typeof runGates.failureDecision === 'function'
      ? runGates.failureDecision(err, identity) : { disposition: 'ALLOW', results: [] };
    const rank = { ALLOW: 0, WARN: 1, BLOCK: 2 };
    const disposition = (rank[declared.disposition] ?? 0) > (rank[computed.disposition] ?? 0)
      ? declared.disposition : computed.disposition;
    return {
      disposition,
      results: [{ gate: 'observation_error', result: 'SKIP',
        detail: `decision computed but NOT stored (${what}: ${err.message})` },
      ...(computed.results || []), ...declared.results],
      persisted: false,
      ...(computed.evaluated === false ? { evaluated: false } : {}),
    };
  }

  function observePackument(packageName, packument) {
    if (typeof packageName !== 'string' || !packageName) {
      throw new Error('observePackument: packageName required');
    }
    const parsedVersions = parseVersionsFromPackument(packument);

    // The RAW manifest, verbatim. `parseVersionsFromPackument` projects each version object onto the
    // fields the v1/v2 gates read; a gate that consumes the registry document itself (the seed-v3
    // path reads `scripts{}`, `_nodeVersion` and `dist.attestations`) cannot recover them from that
    // projection, and must never guess at what it cannot see.
    const rawVersions = packument && typeof packument === 'object' && packument.versions
      && typeof packument.versions === 'object' ? packument.versions : {};
    const rawTimes = packument && typeof packument === 'object' && packument.time
      && typeof packument.time === 'object' ? packument.time : {};

    // A document whose manifests are ALL unreadable still contains versions, and serving it raw
    // would serve every one of them unexamined.
    if (parsedVersions.length === 0) {
      const decisions = new Map();
      for (const versionStr of Object.keys(rawVersions)) {
        const err = new Error(`packument manifest for ${versionStr} could not be parsed`);
        decisions.set(versionStr, failureDecision(err, err.message, { packageName, version: versionStr }));
      }
      if (decisions.size) log.warn(`[witness] ${packageName}: no readable manifests in packument`);
      return { decisions, newBaselines: 0, versionsSeen: 0 };
    }

    // The transaction is CONSTRUCTED here, and better-sqlite3 throws from `db.transaction()` itself
    // when the handle is closed — outside the try below, so `observePackument` still threw for the
    // commonest database failure and the proxy fell back to serving raw bytes. Everything that can
    // throw is now inside one guard.
    // Decisions computed inside the transaction, kept OUTSIDE it: a rolled-back transaction must not take them along.
    const evaluated = new Map();
    let txn;
    try {
      txn = db.db.transaction((versions) => {
      const history = db.getHistory(packageName);
      const decisions = new Map();
      let newBaselines = 0;

      for (const incoming of versions) {
        const identity = { packageName, version: incoming.version };
        let computed = null;
        try {
          const existing = db.getBaseline(packageName, incoming.version);
          const input = {
            ecosystem: ECOSYSTEM,
            packageName,
            version: incoming.version,
            incoming,
            rawManifest: Object.prototype.hasOwnProperty.call(rawVersions, incoming.version)
              ? rawVersions[incoming.version] : null,
            // The whole versions map, for gates that need PACKAGE-SCOPED context rather than one
            // manifest -- the domain version count behind provider_class is counted over exactly
            // this population.
            rawVersions,
            publishedAt: typeof rawTimes[incoming.version] === 'string'
              ? rawTimes[incoming.version] : null,
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
            // ASK, do not assume. Manufacturing ALLOW here discarded whatever a fail-closed gate
            // would have said -- including a recorded-advisory BLOCK. With no such gate configured
            // this still aggregates to ALLOW, exactly as before.
            result = failureDecision(err, `runner threw: ${err.message}`, identity);
          }
          const disposition = result?.disposition ?? 'ALLOW';
          const gateResults = Array.isArray(result?.results) ? result.results : [];
          // A failure decision made here IS stored below; it stays marked as a failure decision (Amendment 3).
          computed = { disposition, results: gateResults, ...(result?.evaluated === false ? { evaluated: false } : {}) };
          evaluated.set(incoming.version, computed);

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

          decisions.set(incoming.version, computed);
        } catch (err) {
          log.warn(
            `[witness] version ${packageName}@${incoming.version} failed: ${err.message}`,
          );
          // Swallowed to keep per-version isolation -- better-sqlite3 wraps this whole block, so a
          // THROW here would roll back EVERY version. But the swallowed version no longer becomes a
          // bare ALLOW: what the failure means is whatever the configured gates declare it means. A decision computed
          // BEFORE the failure (a witness write after evaluation) is kept, not replaced.
          decisions.set(incoming.version, computed
            ? computedDespiteFailure(computed, err, 'witness write failed', identity)
            : failureDecision(err, `version failed: ${err.message}`, identity));
        }
      }

      // A version the parser could not read at all never reached the loop above, so it had NO
      // decision -- and the rewriter keeps a version with no decision. That is a release nobody
      // looked at being served as though it had passed.
      for (const versionStr of Object.keys(rawVersions)) {
        if (decisions.has(versionStr)) continue;
        const err = new Error(`packument manifest for ${versionStr} could not be parsed`);
        log.warn(`[witness] ${packageName}@${versionStr}: unparseable manifest`);
        decisions.set(versionStr, failureDecision(err, err.message, { packageName, version: versionStr }));
      }

        return { decisions, newBaselines, versionsSeen: versions.length };
      });
      return txn(parsedVersions);
    } catch (err) {
      // Transaction-level failure (DB error, schema drift). Previously this threw, the proxy caught
      // it, and the packument was served RAW -- every BLOCK in it lost, silently. The failure is
      // still reported, but it now carries a decision for every version the document contains, so a
      // fail-closed gate's declaration survives a database error.
      log.error(`[witness] ${packageName}: observation transaction failed: ${err.message}`);
      const decisions = new Map();
      for (const versionStr of Object.keys(rawVersions)) {
        const identity = { packageName, version: versionStr };
        const computed = evaluated.get(versionStr);
        decisions.set(versionStr, computed
          ? computedDespiteFailure(computed, err, 'observation transaction failed', identity)
          : failureDecision(err, `observation failed: ${err.message}`, identity));
      }
      return { decisions, newBaselines: 0, versionsSeen: parsedVersions.length, failed: true };
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

  /**
   * The decisions to use when observation could not happen at all. The proxy previously answered
   * that case by serving the packument RAW, which discards every BLOCK the document would have
   * earned; it can now ask what the configured gates say a total failure means.
   *
   * `packageName` is the request-bound name the caller observed under (U-05 Amendment 1). Without it nothing is
   * looked up for any version, as before.
   */
  function failureDecisionsFor(packument, err, packageName = null) {
    const versions = packument && typeof packument === 'object' && packument.versions
      && typeof packument.versions === 'object' ? packument.versions : {};
    const decisions = new Map();
    const named = typeof packageName === 'string' && packageName !== '';
    for (const versionStr of Object.keys(versions)) {
      decisions.set(versionStr, failureDecision(err, `observation failed: ${err.message}`,
        named ? { packageName, version: versionStr } : null));
    }
    return { decisions, newBaselines: 0, versionsSeen: 0, failed: true };
  }

  return {
    observePackument,
    observeTarball,
    failureDecisionsFor,
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
