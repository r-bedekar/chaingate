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
//   - every failure path passes the request-bound
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
import { applicableFromRows, step, isActualEvaluation } from './decision-rule.js';
import { classSignature, pendingFacts } from './row-class.js';
import { reraise } from '../gates/retier-late.js';

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
  // that returns it (`persisted: false`): the proxy relies on both flags.
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
   * A decision already COMPUTED when a later step failed. The failure no longer replaces it:
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

  function overrideEstablished(packageName, version) {
    try { return Boolean(db.getOverride(packageName, version)); } catch { return false; }
  }

  /**
   * A decision made because the gates could not run never downgrades the stored BLOCK that applies to this exact
   * version. Nothing is inserted; the stored BLOCK is returned -- it IS stored -- with the failure's own rows after it.
   */
  /** The stored BLOCK still applies because this evaluation did not definitively clear it. */
  function applicableBlockKept(packageName, version, row, pending, computed, facts = []) {
    return {
      disposition: 'BLOCK',
      // What the kept BLOCK rests on, structured -- its confirmed fact reasons and the stored
      // BLOCK's rows -- so lines, reasons and notices name the fact rather than this synthetic row.
      held: { facts, rows: Array.isArray(row?.gates_fired) ? row.gates_fired : null },
      results: [{ gate: 'chaingate', result: 'BLOCK',
        detail: `stored BLOCK still applies: ${packageName}@${version} was BLOCKed (decided ${row.decided_at ?? 'at an unknown time'}) `
          + `and this evaluation did not definitively clear ${pending.join(', ')}` },
      ...(Array.isArray(computed?.results) ? computed.results : [])],
    };
  }

  function preservedStoredBlock(packageName, version, row, failed, facts = []) {
    return {
      disposition: 'BLOCK',
      held: { facts, rows: Array.isArray(row?.gates_fired) ? row.gates_fired : null },   // structured, as in applicableBlockKept
      results: [{ gate: 'chaingate', result: 'BLOCK',
        detail: `stored BLOCK preserved: the applicable stored decision for ${packageName}@${version} is BLOCK (decided `
          + `${row.decided_at ?? 'at an unknown time'}); a failure decision cannot make it servable` },
      ...(Array.isArray(failed?.results) ? failed.results : [])],
      evaluated: false,
    };
  }

  // Storage health: one outcome per observation, from the store's own database
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
    // Since 0.1.4: only a plain-object time map is handed to the gate for the stale-seed count; `publishedAt` above and
    // below is read exactly as before (an array-valued time{} included).
    const timesSupplied = Boolean(packument && typeof packument === 'object' && packument.time
      && typeof packument.time === 'object' && !Array.isArray(packument.time));

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
    const actual = new Set();          // versions actually evaluated, kept outside the transaction
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
            // Since 0.1.4: the packument's time map as served (undefined when it has none), for the stale-seed count.
            rawTimes: timesSupplied ? rawTimes : undefined,
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
          let disposition = result?.disposition ?? 'ALLOW';
          const gateResults = Array.isArray(result?.results) ? result.results : [];
          // Since 0.1.4: the record keeps N1h's last JUDGEMENT. A pending row (the dependency cache is cold) never
          // replaces a judged one for the same added set: the judgement changes only when a new one is made.
          const n1h = gateResults.findIndex((g) => g && g.gate === 'dependency-hooks');
          // The carried rows come from the version's HISTORY, newest first, override
          // rows skipped -- not from its newest row, which may be an override row or a row 0.1.3 wrote after a rollback.
          let decisionHistory = null;
          try { decisionHistory = db.getDecisionHistory(packageName, incoming.version); } catch { decisionHistory = null; }
          const newestFirst = (decisionHistory ?? []).filter((r) => Array.isArray(r?.gates_fired) && !isOverrideRow(r.gates_fired)).reverse();
          // Since 0.1.4: a determinate MC outcome (tarballs are immutable per version) is carried into every
          // re-evaluation; the runner never produces it. A not-checked row is not carried: it is retried at the next download.
          let mcPrev = null;
          for (const r of newestFirst) {
            mcPrev = r.gates_fired.find((g) => g && g.gate === 'install-manifest-mismatch' && (g.result === 'WARN' || g.result === 'ALLOW'));
            if (mcPrev) break;
          }
          // never into an override short-circuit: the stored override row keeps its ALLOW
          if (mcPrev && !isOverrideRow(gateResults) && !gateResults.some((g) => g && g.gate === 'install-manifest-mismatch')) {
            gateResults.push(mcPrev);
            if (mcPrev.result === 'WARN' && disposition !== 'BLOCK') disposition = 'WARN';
          }
          // 0.1.5 static checks: the newest static:* rows -- a walked outcome, or "not armed" as stated -- ride into every
          // re-evaluation too; the runner never produces them, and whether a later download walks again is decided there
          // (proxy/static-checks.js staticSettled), never here. A contributing check's row is NOTE/SKIP/ALLOW and moves nothing;
          // a named check's row (S0 and S5 since 0.1.5, then S6-S9) is a WARN and keeps the record's WARN, as MC's carried row
          // does (since 0.1.6: before, the carried WARN row sat under an ALLOW and the next download printed no warning).
          const isStatic = (g) => g && typeof g.gate === 'string' && g.gate.startsWith('static:');
          const staticPrev = newestFirst.map((r) => r.gates_fired.filter(isStatic)).find((xs) => xs.length);
          if (staticPrev && !isOverrideRow(gateResults) && !gateResults.some(isStatic)) {
            gateResults.push(...staticPrev);
            if (staticPrev.some((g) => g.result === 'WARN') && disposition !== 'BLOCK') disposition = 'WARN';
          }
          // Since 0.1.6: install-introduced as a download's walk re-read it against the tarball package.json rides into every
          // re-evaluation (the runner reads only the registry entry); then the re-tier's late guards over what was carried
          // (gates/retier-late.js), so a strict row that warned again after a download keeps warning.
          if (!isOverrideRow(gateResults)) {
            let lateChanged = false;
            const iiAt = gateResults.findIndex((g) => g && g.gate === 'install-introduced');
            const iiPrev = newestFirst.map((r) => r.gates_fired.find((g) => g && g.gate === 'install-introduced' && g.hooks_basis
              && typeof g.hooks_basis.tarball === 'string')).find(Boolean);
            if (iiPrev && iiAt >= 0 && !(gateResults[iiAt].hooks_basis && typeof gateResults[iiAt].hooks_basis.tarball === 'string')) {
              gateResults[iiAt] = iiPrev; lateChanged = true;
            }
            const rr = reraise(gateResults);
            if (rr) { gateResults[gateResults.findIndex((g) => g && g.gate === 'seed-v3')] = rr; lateChanged = true; }
            if (lateChanged && disposition !== 'BLOCK') disposition = gateResults.some((g) => g && g.result === 'WARN') ? 'WARN' : 'ALLOW';
          }
          if (n1h >= 0 && Array.isArray(gateResults[n1h].pending)) {
            // only a DETERMINATE judgement is kept: a not-evaluable SKIP is retried, not carried
            // the newest non-override row that HAS an N1h row (rows without the gate, e.g. 0.1.3's, are skipped)
            const n1hPrev = newestFirst.map((r) => r.gates_fired.find((g) => g && g.gate === 'dependency-hooks')).find(Boolean);
            const judged = n1hPrev && !Array.isArray(n1hPrev.pending) && (n1hPrev.result === 'WARN' || n1hPrev.result === 'ALLOW')
              ? n1hPrev : null;
            const sameSet = (a, b) => JSON.stringify((a ?? []).map((d) => d.name)) === JSON.stringify((b ?? []).map((d) => d.name));
            if (judged && sameSet(judged.added, gateResults[n1h].added)) {
              gateResults[n1h] = judged;
              if (judged.result === 'WARN' && disposition !== 'BLOCK') disposition = 'WARN';
            }
          }
          // A failure decision made here IS stored below; it stays marked as a failure decision.
          computed = { disposition, results: gateResults, ...(result?.evaluated === false ? { evaluated: false } : {}) };
          stage = 'write';

          // ONE applicable-BLOCK rule (witness/decision-rule.js) over the stored history
          // and this result. A read error here is a storage failure for this version (the catch below).
          const overrideBased = isOverrideRow(gateResults);
          const stored = decisionHistory ?? db.getDecisionHistory(packageName, incoming.version);
          const before = applicableFromRows(stored);
          const after = step(new Set(before.pending), gateResults);
          // A failure-derived non-BLOCK never downgrades the applicable BLOCK. With an exact override
          // established the failure decision is returned as before; either way nothing is inserted over it.
          let returned = computed;
          let skipInsert = false;
          if (computed.evaluated === false && disposition !== 'BLOCK') {
            if (before.block) {
              skipInsert = true;
              if (!overrideEstablished(packageName, incoming.version)) {
                returned = preservedStoredBlock(packageName, incoming.version, before.block, computed,
                  pendingFacts(stored, before.pending));
              }
            }
          } else if (!overrideBased && disposition !== 'BLOCK' && before.block && after.pending.size > 0) {
            // An evaluation that does not DEFINITIVELY clear every pending reason (a SKIP, an error, a missing gate,
            // an input-rule result) leaves the BLOCK applicable. Its row is still written below, once, as evidence.
            if (!overrideEstablished(packageName, incoming.version)) {
              returned = applicableBlockKept(packageName, incoming.version, before.block, [...after.pending].sort(), computed,
                pendingFacts(stored, [...after.pending]));
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
            // State-change logging against the EFFECTIVE prior decision -- the same rows the tarball gate applies --
            // so a new evaluation after a revoked override is recorded even when it repeats the override's ALLOW. A
            // result that definitively clears a pending reason is recorded even when the disposition repeats (a
            // clearance must not be lost behind an earlier non-definitive row of the same disposition).
            const prior = skipInsert ? null : (overrideBased ? (stored.at(-1) ?? null) : before.latest);
            // Since 0.1.4: also when the CLASS of the record changed (named, contributing, facts, policy
            // identity) under the same NON-BLOCK disposition -- e.g. a 1.1 coverage WARN that is a 1.2 strict-tier WARN, or
            // contributing signals under an ALLOW. BLOCK -> BLOCK keeps the pending-reason rule exactly as before: a row
            // there could add a pending reason and become the cited applicable BLOCK.
            if (!skipInsert && (!prior || prior.disposition !== disposition || after.cleared.length > 0
              || (disposition !== 'BLOCK'
                && classSignature(prior.disposition, prior.gates_fired) !== classSignature(disposition, gateResults)))) {
              db.insertGateDecision(packageName, incoming.version, disposition, gateResults);
              inserted += 1;
            }
          }

          decisions.set(incoming.version, returned);
          // This version was actually evaluated in this observation.
          if (computed.evaluated !== false && isActualEvaluation(gateResults)) actual.add(incoming.version);
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

        return { decisions, newBaselines, versionsSeen: versions.length, actual };
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
      return { decisions, newBaselines: 0, versionsSeen: parsedVersions.length, failed: true, actual };
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
   * `packageName` is the request-bound name the caller observed under. Without it nothing is
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
