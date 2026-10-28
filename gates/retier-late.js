// Since 0.1.6 (cft-policy-1.3): what a download adds to the re-tier.
//
// The re-tier (seed/v3/retier.js) is decided from the registry document, before any tarball is read. Two of its guards can
// only be known after the download's walk:
//   * a tarball check fired (any static:* row that is a WARN or a NOTE), and
//   * the tarball package.json, which npm runs, adds or changes an install hook (install-introduced's `hooks_basis.tarball`).
// When either holds on a release whose strict row the re-tier showed as a NOTE, that row warns again. Nothing else moves:
// no row is lowered here, a BLOCK stays a BLOCK, and a release with no re-tiered row is returned unchanged.
//
// One pure function over a decision's gate results, used where the walk's rows are recorded (proxy/server.js) and where a
// re-evaluation carries them forward (witness/store.js), so both read the same answer.
import { NAMED_ROWS, WARN, NOTE } from '../seed/v3/policy.js';

const STRICT = new Set(NAMED_ROWS);
const POLICY_PREFIX = /^(cft-policy-\d+\.\d+): /;

/** The late guards that hold over these results: { ids, words }. */
export function lateGuards(results) {
  const list = Array.isArray(results) ? results : [];
  const ids = []; const words = [];
  const fired = list.filter((g) => g && typeof g.gate === 'string' && g.gate.startsWith('static:') && (g.result === WARN || g.result === NOTE));
  if (fired.length) {
    ids.push('tarball-check');
    words.push(`tarball check ${fired.map((g) => g.gate.slice('static:'.length)).sort().join(', ')} fired`);
  }
  const ii = list.find((g) => g && g.gate === 'install-introduced' && g.hooks_basis && typeof g.hooks_basis === 'object');
  const kind = ii ? ii.hooks_basis.tarball : null;
  if (kind === 'added' || kind === 'changed') {
    ids.push('tarball-hook');
    words.push(`the tarball package.json npm runs ${kind === 'added' ? 'adds an install hook' : 'changes an install hook'}`);
  }
  return { ids, words };
}

/**
 * The seed-v3 result with its re-tiered strict rows warning again, or null when nothing changes (no seed-v3 result, no
 * strict row shown as a NOTE, or no late guard).
 */
export function reraise(results) {
  const list = Array.isArray(results) ? results : [];
  const s = list.find((g) => g && g.gate === 'seed-v3' && Array.isArray(g.rows) && g.retier && g.retier.placement === 'recorded');
  if (!s || !s.rows.some((x) => x && STRICT.has(x.gate) && x.result === NOTE)) return null;
  const { ids, words } = lateGuards(list);
  if (!ids.length) return null;
  const strict = s.rows.filter((x) => x && STRICT.has(x.gate) && x.result === NOTE).map((x) => x.gate);
  const rows = s.rows.map((x) => (x && STRICT.has(x.gate) && x.result === NOTE ? { gate: x.gate, result: WARN } : x));
  const said = words.join('; ');
  const m = POLICY_PREFIX.exec(typeof s.detail === 'string' ? s.detail : '');
  const before = typeof s.detail === 'string' ? s.detail.slice(m ? m[0].length : 0) : '';
  return {
    ...s,
    result: s.result === 'BLOCK' ? 'BLOCK' : WARN,
    rows,
    retier: { ...s.retier, placement: 'raised', guards: [...new Set([...(s.retier.guards || []), ...ids])],
      words: `warns again after the download: ${said}`.slice(0, 400) },
    detail: `${m ? m[0] : ''}${strict.join(', ')}: warns again after the download (${said}); before the download: ${before}`,
  };
}

export default { lateGuards, reraise };
