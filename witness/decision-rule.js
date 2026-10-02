// U-05 owner decision 10, C2: ONE rule for whether a BLOCK still applies to a package version.
//
// Every path that decides whether a version may be served uses this module and nothing else: the observation and its
// writes (witness/store.js), historical decision reads (witness/db.js getApplicableDecision), tarball enforcement
// (proxy/server.js) and the BLOCKs held only in memory (proxy/unstored-blocks.js).
//
// A BLOCK result carries a REASON. A later result removes a reason only when it is that reason's DEFINITIVE clearance:
// an actual evaluation of the evidence the BLOCK rested on. A SKIP, a missing gate, an error, a decision made by the
// input rule (unusable or unreadable input), unrecognised text, or a policy version not listed here is NEVER a
// clearance. Every reason must be cleared; a BLOCK applies while any reason is pending. Override rows are not part of
// this walk: an exact override applies only while it exists (N3), and once it is revoked the walk over the other rows
// gives the underlying decision.
//
// Classification reads the exact texts the shipped producers write (gates/content-hash.js, seed/v3/policy.js and
// seed/v3/gate.js, policy 1.0 and 1.1). There is no structured field: chaingate.check/2 carries a decision's results
// verbatim, so a new field would change the public schema. Text written by the published 0.1.0-0.1.2 runtimes is
// covered by fixtures captured from those runtimes (test/fixtures/u05-d10-historical).

import { isOverrideRow } from './db.js';

export const REASON = Object.freeze({
  CONTENT_HASH: 'content-hash',
  PIN: 'seed-v3:pin',
  INPUT: 'seed-v3:input',
  SEED_OTHER: 'seed-v3:other',
  UNCLASSIFIED: 'unclassified',
});

const POLICY_PREFIXES = Object.freeze(['cft-policy-1.0: ', 'cft-policy-1.1: ']);
// D4: under policy 1.0 "no recorded advisory pins this version" could be said of a pinned version, so only 1.1 clears a pin.
const PIN_CLEARING_PREFIXES = Object.freeze(['cft-policy-1.1: ']);
const INPUT_MARKERS = Object.freeze(['seed-v3:input', 'could not run']);
const PIN_BLOCK_MARKER = 'seed-v3:known-malicious-pin: recorded advisory';
const CONTENT_HASH_CLEARANCE = Object.freeze([/^integrity hash matches baseline/, /^shasum matches baseline/]);

const textOf = (r) => (typeof r?.detail === 'string' ? r.detail : '');
const isInputRule = (detail) => INPUT_MARKERS.some((m) => detail.includes(m));

/** The reasons of the BLOCK results in one list of gate results (each reason at most once). */
export function blockReasons(results) {
  const out = new Set();
  for (const r of Array.isArray(results) ? results : []) {
    if (!r || r.result !== 'BLOCK') continue;
    const gate = String(r.gate ?? '');
    const detail = textOf(r);
    if (gate === 'content-hash') out.add(REASON.CONTENT_HASH);
    else if (gate === 'seed-v3') {
      const pin = detail.includes(PIN_BLOCK_MARKER);
      const input = isInputRule(detail);
      if (pin) out.add(REASON.PIN);
      if (input) out.add(REASON.INPUT);
      if (!pin && !input) out.add(REASON.SEED_OTHER);
    } else if (gate !== 'override') out.add(`gate:${gate || 'unknown'}`);
  }
  return [...out];
}

/** Whether `results` contain the DEFINITIVE clearance of `reason`. Unknown reasons are never cleared. */
export function clears(reason, results) {
  const list = Array.isArray(results) ? results : [];
  switch (reason) {
    case REASON.CONTENT_HASH:
      return list.some((r) => r?.gate === 'content-hash' && r.result === 'ALLOW'
        && CONTENT_HASH_CLEARANCE.some((re) => re.test(textOf(r))));
    case REASON.PIN:
      return list.some((r) => {
        const d = textOf(r);
        return r?.gate === 'seed-v3' && (r.result === 'ALLOW' || r.result === 'WARN')
          && PIN_CLEARING_PREFIXES.some((p) => d.startsWith(p)) && !isInputRule(d)
          && !d.includes('pin lookup FAILED') && !d.includes(PIN_BLOCK_MARKER);
      });
    case REASON.INPUT:
      return list.some((r) => {
        const d = textOf(r);
        return r?.gate === 'seed-v3' && ['ALLOW', 'WARN', 'BLOCK'].includes(r.result)
          && POLICY_PREFIXES.some((p) => d.startsWith(p)) && !isInputRule(d);
      });
    default:
      return false;
  }
}

/**
 * Whether a decision's results are an actual evaluation for C1's purposes (owner decision 10, F1/F1a): no gate failed
 * (`gate_error:`), the observation did not fail, and seed-v3 did not decide by the input rule. A version whose decision is
 * not an actual evaluation is evaluated again on its next tarball request.
 */
export function isActualEvaluation(results) {
  for (const r of Array.isArray(results) ? results : []) {
    if (!r) continue;
    const d = textOf(r);
    if (r.gate === 'observation_error') return false;
    if (d.startsWith('gate_error:')) return false;
    if (r.gate === 'seed-v3' && isInputRule(d)) return false;
  }
  return true;
}

/** One step of the walk: pending reasons after a result list. Returns { pending (Set), cleared: [], added: [] }. */
export function step(pending, results) {
  const next = new Set(pending);
  const cleared = [];
  for (const reason of pending) if (clears(reason, results)) { next.delete(reason); cleared.push(reason); }
  const added = [];
  for (const reason of blockReasons(results)) if (!next.has(reason)) { next.add(reason); added.push(reason); }
  return { pending: next, cleared, added };
}

/**
 * The applicable decision from stored rows, OLDEST FIRST ({ id, disposition, gates_fired (array, or unparsed text),
 * decided_at }). `overrideLive`: an exact override exists now.
 *   block    the stored BLOCK row that still applies (the latest row that added a pending reason), or null
 *   pending  the reasons not definitively cleared, sorted
 *   latest   the latest non-override row; overrideRow the latest override row
 *   disposition  'BLOCK' while a reason is pending; 'ALLOW' for a live override; otherwise the latest row's disposition
 */
export function applicableFromRows(rows, { overrideLive = false } = {}) {
  let pending = new Set();
  const source = new Map();          // reason -> the row that last added it
  let latest = null;
  let overrideRow = null;
  for (const row of rows) {
    const results = Array.isArray(row.gates_fired) ? row.gates_fired : null;
    if (results && isOverrideRow(results)) { overrideRow = row; continue; }
    const s = step(pending, results ?? []);
    pending = s.pending;
    for (const r of s.cleared) source.delete(r);
    for (const r of s.added) source.set(r, row);
    if (row.disposition === 'BLOCK' && blockReasons(results ?? []).length === 0) {
      pending.add(REASON.UNCLASSIFIED); source.set(REASON.UNCLASSIFIED, row);
    }
    latest = row;
  }
  const reasons = [...pending].sort();
  let block = null;
  for (const r of reasons) { const row = source.get(r); if (row && (!block || row.id > block.id)) block = row; }
  if (overrideLive && overrideRow) {
    return { disposition: 'ALLOW', override: true, block: null, underlyingBlock: block, pending: reasons, latest, overrideRow };
  }
  return { disposition: block ? 'BLOCK' : (latest?.disposition ?? null), override: false, block, pending: reasons, latest, overrideRow };
}

// Reasons as a fixed-size bit set, for the in-memory record (proxy/unstored-blocks.js): a small integer is covered by the
// entry's fixed overhead in the accepted accounting model, so the model is unchanged.
const BITS = Object.freeze({ [REASON.CONTENT_HASH]: 1, [REASON.PIN]: 2, [REASON.INPUT]: 4 });
const OTHER_BIT = 8;
export function reasonBits(results) {
  let b = 0;
  const reasons = blockReasons(results);
  for (const r of reasons) b |= (BITS[r] ?? OTHER_BIT);
  return b || OTHER_BIT;
}
/** The bits of `bits` that `results` definitively clear. OTHER is never cleared. */
export function clearedBits(bits, results) {
  let c = 0;
  for (const [reason, bit] of Object.entries(BITS)) if ((bits & bit) && clears(reason, results)) c |= bit;
  return c;
}
