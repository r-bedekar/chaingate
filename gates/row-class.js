// cft-policy-1.2: the runner's ONE role table, and the validation of the seed-v3 gate's
// structured `rows` member.
//
// Contributing gates: their signal is shown beside a named row and as detail, never as a warning on its
// own. The runner records a WARN from one of them as NOTE (detail verbatim); the gate modules themselves are not edited.
// A WARN from any module NOT listed here (the seed-v3 gate, Tier 1's named modules, an unlisted module) aggregates as it
// always did. A new policy identity changes this table deliberately; a guard test pins it.
import POL from '../seed/v3/policy.js';
import RT from '../seed/v3/retier.js';

export const ROLE_POLICY = 'cft-policy-1.2';

export const CONTRIBUTING_GATES = Object.freeze(new Set([
  'publisher-identity', 'dep-structure', 'provenance-continuity', 'release-age', 'scope-boundary',
  // since 0.1.4: size-jump at >= 2x and publish-tool-change, contributing in cft-policy-1.2
  'size-jump', 'publish-tool-change',
  // since 0.1.5: identity-break, contributing. size-jump-provenance is a NAMED runner gate (policy.NAMED_RUNNER_GATES), so it
  // is not in this list.
  'identity-break',
  // since 0.1.5: entry-path-change, contributing (every component over the bar but one)
  'entry-path-change',
  // since 0.1.5: the tarball static checks start CONTRIBUTING; a check becomes named only after it has been measured, one at a time
  // (then: OUT of this list, into policy.NAMED_RUNNER_GATES and proxy/notice.js; a gate left here has its WARN turned into NOTE by
  // withRole, so it can never be named)
  // static-checks-1.2: S5 oversized-hook-target joined as a sixth static check, CONTRIBUTING first.
  // S0 and S5 are NAMED runner gates and left this list; S1-S4 stay.
  'static:S1-loader-in-hook-target', 'static:S2-obfuscated-entry', 'static:S3-secret-harvest-with-sink', 'static:S4-wallet-swap-hook',
  // S6 and S7 joined CONTRIBUTING first and are now named (S6 as INDICATOR, S7 on the static-checks-1.5 condition), so they
  // left this list for policy.NAMED_RUNNER_GATES and proxy/notice.js
]));

/** A runner row with the 1.2 role applied: a contributing gate's WARN becomes NOTE. Everything else unchanged. */
export function withRole(row) {
  if (row && row.result === 'WARN' && CONTRIBUTING_GATES.has(row.gate)) return { ...row, result: POL.NOTE };
  return row;
}

const ROW_GATES = new Set(POL.POLICY_ROW_GATES);
const ROW_RESULTS = new Set(POL.ROW_RESULTS);
export const MAX_ROWS = 32;

/** A validated copy of a GateResult's `rows`, or null when absent or malformed (never throws). */
export function validRows(rows) {
  if (!Array.isArray(rows) || rows.length === 0 || rows.length > MAX_ROWS) return null;
  const out = [];
  for (const x of rows) {
    if (!x || typeof x !== 'object' || !ROW_GATES.has(x.gate) || !ROW_RESULTS.has(x.result)) return null;
    out.push({ gate: x.gate, result: x.result });
  }
  return out;
}

/**
 * A validated copy of N1h's `added` / `pending` list -- at most 10 { name, target, spec } with string
 * members of bounded length -- or null when absent or malformed (never throws).
 */
export function validDeps(list) {
  if (!Array.isArray(list) || list.length > 10) return null;
  const ok = (s, n) => typeof s === 'string' && s.length > 0 && s.length <= n;
  const out = [];
  for (const d of list) {
    if (!d || typeof d !== 'object' || !ok(d.name, 214) || !ok(d.target, 214) || !ok(d.spec, 256)) return null;
    out.push({ name: d.name, target: d.target, spec: d.spec });
  }
  return out;
}

/** N1h's `unjudgeable` notes -- at most 10 strings of at most 120 characters, or null. */
export function validNotes(list) {
  if (!Array.isArray(list) || list.length === 0 || list.length > 10) return null;
  return list.every((x) => typeof x === 'string' && x.length > 0 && x.length <= 120) ? [...list] : null;
}

/** Since 0.1.6: install-introduced's `hooks_basis` ({ ever, gyp, tarball }), validated, or null. */
export function validHooksBasis(x) {
  if (!x || typeof x !== 'object' || typeof x.ever !== 'boolean' || typeof x.gyp !== 'boolean') return null;
  if (x.tarball !== null && !['same', 'registry-only', 'added', 'changed'].includes(x.tarball)) return null;
  return { ever: x.ever, gyp: x.gyp, tarball: x.tarball };
}

/** Since 0.1.6: the seed-v3 result's `pin` member (a pins feed pin), validated, or null. */
export function validPin(x) {
  const id = (v) => v === null || (typeof v === 'string' && /^[A-Za-z0-9._:/-]{1,80}$/.test(v));
  if (!x || typeof x !== 'object' || x.origin !== 'feed' || !['osv', 'ghsa', 'chaingate-analyst', 'other'].includes(x.source)) return null;
  if (!id(x.advisory_id) || !id(x.record_id) || (x.advisory_id === null && x.record_id === null)) return null;
  if (x.integrity !== undefined && !['matches', 'differs', 'absent'].includes(x.integrity)) return null;
  return { origin: 'feed', source: x.source, advisory_id: x.advisory_id, record_id: x.record_id,
    ...(x.integrity !== undefined ? { integrity: x.integrity } : {}) };
}

/** Since 0.1.6: the seed-v3 result's compact re-tier block (seed/v3/retier.js), validated, or null. */
export const validRetier = (x) => RT.validCompact(x);

export default { ROLE_POLICY, CONTRIBUTING_GATES, withRole, validRows, validDeps, validNotes, validRetier, validHooksBasis, validPin, MAX_ROWS };
