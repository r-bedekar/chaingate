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
import { isOverrideRow } from './db.js';

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

  /**
   * THE prior decision for (pkg, version), read with the one rule the tarball gate also uses (U-05 gap-closure r2, N3):
   * a stored override ALLOW counts only while the override exists. `live` says whether it does -- for a decision the
   * runner made BECAUSE of an override it is true by construction; for any other decision the override rows are skipped.
   */
  function effectivePrior(packageName, version, live) {
    const latest = db.getLatestDecision(packageName, version);
    if (!latest || live || !isOverrideRow(latest.gates_fired)) return latest;
    return db.getLatestNonOverrideDecision(packageName, version);
  }

  /** The underlying stored BLOCK (override rows skipped), or null -- also when it cannot be read (today's behaviour). */
  function underlyingStoredBlock(packageName, version) {
    try {
      const row = effectivePrior(packageName, version, false);
      return row && row.disposition === 'BLOCK' ? row : null;
    } catch { return null; }
  }

  function overrideEstablished(packageName, version) {
    try { return Boolean(db.getOverride(packageName, version)); } catch { return false; }
  }

  /**
   * U-05 gap-closure r2, N1 (W2): a decision made because the gates could not run never downgrades the stored BLOCK that
   * applies to this exact version. Nothing is inserted; the stored BLOCK is returned -- it IS stored -- with the failure's
   * own rows after it. (Rule K's wording, for the stored case.)
   */
  function preservedStoredBlock(packageName, version, row, failed) {
    return {
      disposition: 'BLOCK',
      results: [{ gate: 'chaingate', result: 'BLOCK',
        detail: `stored BLOCK preserved: the applicable stored decision for ${packageName}@${version} is BLOCK (decided `
          + `${row.decided_at ?? 'at an unknown time'}); a failure decision cannot make it servable` },
      ...(Array.isArray(failed?.results) ? failed.results : [])],
      evaluated: false,
    };
  }

  // Storage health (U-05 gap-closure r2, Addendum 1 §B): one outcome per observation, from the store's own database
  // steps only. `failure` if any storage step failed (failure dominates), else `ok` if the transaction committed with at
  // least one decision row inserted, else nothing. Input refusals (unreadable manifests, a runner that threw) are not
  // storage evidence.
  const health = { ok_count: 0, failure_count: 0, last_outcome: null, last_ok_at: null, last_failure_at: null,
    last_failure: null };
  function recordOutcome(failures, inserted) {
    const at = new Date().toISOString();
    if (failures.length) {
      const f = failures[0];
      health.failure_count += 1; health.last_outcome = 'failure'; health.last_failure_at = at;
      health.last_failure = { stage: f.stage, message: String(f.message).slice(0, 256), versions: failures.length };
      log.transition?.('storage', 'failing', `[witness] decision storage failing (stage ${f.stage}): ${f.message}`);
    } else if (inserted > 0) {
      const was = health.last_outcome;
      health.ok_count += 1; health.last_outcome = 'ok'; health.last_ok_at = at;
      if (was === 'failure') log.transition?.('storage', 'ok', '[witness] decision writes are committing again');
    }
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
    const storageFailures = [];
    let inserted = 0;
    let txn;
    try {
      txn = db.db.transaction((versions) => {
      const history = db.getHistory(packageName);
      const decisions = new Map();
      let newBaselines = 0;

      for (const incoming of versions) {
        const identity = { packageName, version: incoming.version };
        let computed = null;
        let stage = 'read';                       // read: before evaluation; evaluate: the gates; write: storing it
        try {
          const existing = db.getBaseline(packageName, incoming.version);
          stage = 'evaluate';
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
          stage = 'write';

          // N1 (W2): a failure-derived non-BLOCK never downgrades the underlying stored BLOCK. With an exact override
          // established the failure decision is returned as before (A1-OV); either way nothing is inserted over it.
          let returned = computed;
          let skipInsert = false;
          if (computed.evaluated === false && disposition !== 'BLOCK') {
            const kept = underlyingStoredBlock(packageName, incoming.version);
            if (kept) {
              skipInsert = true;
              if (!overrideEstablished(packageName, incoming.version)) {
                returned = preservedStoredBlock(packageName, incoming.version, kept, computed);
              }
            }
          }
          evaluated.set(incoming.version, returned);

          if (!existing) {
            db.recordBaseline(packageName, incoming.version, incoming);
            newBaselines += 1;
            if (!skipInsert) {
              const firstSeen = [FIRST_SEEN_GATE_RESULT, ...gateResults];
              db.insertGateDecision(packageName, incoming.version, disposition, firstSeen);
              inserted += 1;
            }
          } else {
            // Idempotent re-observe: bumpLastSeen fires inside recordBaseline's write path.
            db.recordBaseline(packageName, incoming.version, incoming);
            // W1: state-change logging against the EFFECTIVE prior decision -- the same rows the tarball gate applies --
            // so a new evaluation after a revoked override is recorded even when it repeats the override's ALLOW.
            const prior = skipInsert ? null
              : effectivePrior(packageName, incoming.version, isOverrideRow(gateResults));
            if (!skipInsert && (!prior || prior.disposition !== disposition)) {
              db.insertGateDecision(packageName, incoming.version, disposition, gateResults);
              inserted += 1;
            }
          }

          decisions.set(incoming.version, returned);
        } catch (err) {
          log.warn(
            `[witness] version ${packageName}@${incoming.version} failed: ${err.message}`,
          );
          if (stage !== 'evaluate') storageFailures.push({ stage, message: err.message });
          // Swallowed to keep per-version isolation -- better-sqlite3 wraps this whole block, so a
          // THROW here would roll back EVERY version. But the swallowed version no longer becomes a
          // bare ALLOW: what the failure means is whatever the configured gates declare it means. A decision computed
          // BEFORE the failure (a witness write after evaluation) is kept, not replaced.
          decisions.set(incoming.version, computed
            ? computedDespiteFailure(evaluated.get(incoming.version) ?? computed, err, 'witness write failed', identity)
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
      const out = txn(parsedVersions);
      recordOutcome(storageFailures, inserted);          // committed: the rows inserted above are durable
      return out;
    } catch (err) {
      // Transaction-level failure (DB error, schema drift). Previously this threw, the proxy caught
      // it, and the packument was served RAW -- every BLOCK in it lost, silently. The failure is
      // still reported, but it now carries a decision for every version the document contains, so a
      // fail-closed gate's declaration survives a database error.
      log.error(`[witness] ${packageName}: observation transaction failed: ${err.message}`);
      recordOutcome([{ stage: 'transaction', message: err.message }], 0);
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
    storageHealth: () => ({ ...health, last_failure: health.last_failure ? { ...health.last_failure } : null }),
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
