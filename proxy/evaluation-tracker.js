// U-05 owner decision 10, C1: which EXACT versions this proxy process has evaluated, and the bounded evaluation work.
//
// A tarball is served only on a decision this process made for that exact (canonical name, version). This module
// remembers which versions were actually evaluated (witness/decision-rule.js isActualEvaluation) and runs at most one
// evaluation per package at a time (single flight): concurrent first requests for any version of a package wait for the
// same evaluation and none is served before it settles.
//
// It holds NO decision and NO BLOCK. Decisions live in the witness database and BLOCKs that could not be stored live in
// the unstored-BLOCK record (proxy/unstored-blocks.js), with their own caps; nothing here touches either. Eviction
// therefore only means that a version is evaluated again before it is served: it never grants permission and never
// releases a held BLOCK.
//
// Bounds (owner decision 10, F5): the tracked versions (the oldest package's entries are evicted first), the evaluations
// running at once, and the requests waiting for one. A request beyond the waiting bound is refused
// (chaingate_evaluation_busy), never served.

export const C1_DEFAULTS = Object.freeze({ maxVersions: 100_000, maxInFlight: 8, maxWaiting: 256 });

export class EvaluationBusy extends Error {
  constructor(message) { super(message); this.name = 'EvaluationBusy'; }
}

export function createEvaluationTracker(limits = {}) {
  const lim = {
    maxVersions: Number.isInteger(limits.maxVersions) && limits.maxVersions > 0 ? limits.maxVersions : C1_DEFAULTS.maxVersions,
    maxInFlight: Number.isInteger(limits.maxInFlight) && limits.maxInFlight > 0 ? limits.maxInFlight : C1_DEFAULTS.maxInFlight,
    maxWaiting: Number.isInteger(limits.maxWaiting) && limits.maxWaiting >= 0 ? limits.maxWaiting : C1_DEFAULTS.maxWaiting,
  };
  const evaluated = new Map();     // canonical name -> Set(version); Map order = least recently evaluated first
  let tracked = 0;
  let evicted = 0;
  const inflight = new Map();      // canonical name -> Promise of the running evaluation
  let running = 0;
  const waiting = [];              // resolvers of requests waiting for an evaluation slot
  let refused = 0;

  function isEvaluated(name, version) { return evaluated.get(name)?.has(version) === true; }

  /** Record the versions one evaluation of `name` actually evaluated; evict the oldest packages beyond the bound. */
  function markAll(name, versions) {
    let set = evaluated.get(name);
    if (set) evaluated.delete(name); else set = new Set();
    for (const v of versions) if (!set.has(v)) { set.add(v); tracked += 1; }
    evaluated.set(name, set);                        // now the most recent
    while (tracked > lim.maxVersions && evaluated.size > 1) {
      const [oldest, s] = evaluated.entries().next().value;
      evaluated.delete(oldest); tracked -= s.size; evicted += s.size;
    }
  }

  async function acquire() {
    if (running < lim.maxInFlight) { running += 1; return; }
    if (waiting.length >= lim.maxWaiting) {
      refused += 1;
      throw new EvaluationBusy(`${running} evaluations are running and ${waiting.length} requests are waiting `
        + `(limits ${lim.maxInFlight} and ${lim.maxWaiting})`);
    }
    await new Promise((resolve) => waiting.push(resolve));          // the slot is handed over by release()
  }
  function release() {
    const next = waiting.shift();
    if (next) next(); else running -= 1;
  }

  /** Run `fn` as THE evaluation of `name`: one at a time per package, bounded overall. */
  function run(name, fn) {
    const existing = inflight.get(name);
    if (existing) return existing;
    const p = (async () => {
      await acquire();
      try { return await fn(); } finally { release(); }
    })();
    inflight.set(name, p);
    p.then(() => inflight.delete(name), () => inflight.delete(name));
    return p;
  }

  function stats() {
    return { tracked_versions: tracked, tracked_packages: evaluated.size, evicted_versions: evicted,
      running, waiting: waiting.length, refused_busy: refused, limits: { ...lim } };
  }

  return { isEvaluated, markAll, run, stats };
}
