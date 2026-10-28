// install-introduced (L1 + L1i) -- a NAMED gate in cft-policy-1.2. The counted rule, reproduced exactly as it was
// measured (0 / 2,982 benign under the 24 h window).
//
// For the candidate published at c, over the served packument (`versions` and `time`):
//   settled set = other versions published at or before c - 24 h; on a COLD START (empty) the plain set = other versions
//                 published before c; neither -> not evaluable (SKIP)
//   hooks       = preinstall / install / postinstall with Python truthiness; ever = a version in the set had one
//   L1          = the candidate has a hook, and not ever
//   L1i         = the candidate's gypfile is truthy, it has no install/preinstall hook, and not ever (the counted form:
//                 ever counts hooks only)
// A version whose time does not parse is in no set (the counted code raises on one; the registry writes ISO times). The
// detail names the set used and its size.
import { pyTruthy } from '../seed/v3/packument.js';

export const SETTLED_MS = 24 * 3_600_000;
const HOOKS = ['preinstall', 'install', 'postinstall'];
const GATE = 'install-introduced';
const result = (r, detail, basis) => ({ gate: GATE, result: r, detail, ...(basis ? { hooks_basis: basis } : {}) });

function hooksOf(manifest) {
  const s = manifest && typeof manifest === 'object' ? manifest.scripts : null;
  if (!s || typeof s !== 'object' || Array.isArray(s)) return [];
  return HOOKS.filter((k) => pyTruthy(s[k]));
}

/** The two earliest [time, version] of a list (enough to exclude the candidate itself in O(1)). */
function twoEarliest(entries) {
  let a = null; let b = null;
  for (const e of entries) {
    if (!a || e[0] < a[0]) { b = a; a = e; } else if (!b || e[0] < b[0]) b = e;
  }
  return [a, b];
}
const earliestOther = ([a, b], version) => (a && a[1] !== version ? a[0] : (b ? b[0] : Infinity));

const indexes = new WeakMap();
/** Per packument (memoised per versions object): times, hooks, and the two earliest overall and hooked. */
function indexFor(versions, times) {
  let byTimes = indexes.get(versions);
  if (byTimes && byTimes.has(times)) return byTimes.get(times);
  const time = new Map();
  const hooks = new Map();
  const all = []; const hooked = [];
  for (const [v, m] of Object.entries(versions)) {
    const h = hooksOf(m);
    hooks.set(v, h);
    const t = times && typeof times[v] === 'string' ? Date.parse(times[v]) : NaN;
    if (Number.isNaN(t)) continue;
    time.set(v, t);
    all.push([t, v]);
    if (h.length) hooked.push([t, v]);
  }
  const sorted = all.map((e) => e[0]).sort((a, b) => a - b);
  const idx = { time, hooks, all: twoEarliest(all), hooked: twoEarliest(hooked), sorted };
  if (!byTimes) { byTimes = new WeakMap(); indexes.set(versions, byTimes); }
  if (times && typeof times === 'object') byTimes.set(times, idx);
  return idx;
}

/** How many times in a sorted array are <= x (strict: < x). */
function countUpTo(sorted, x, strict) {
  let lo = 0; let hi = sorted.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (strict ? sorted[mid] < x : sorted[mid] <= x) lo = mid + 1; else hi = mid; }
  return lo;
}

export function evaluateL1(versions, times, version) {
  if (!versions || typeof versions !== 'object' || !Object.hasOwn(versions, version)) return { skip: 'the version is not in the served metadata' };
  if (!times || typeof times !== 'object') return { skip: 'no publication time for this version' };
  const idx = indexFor(versions, times);
  const c = idx.time.get(version);
  if (c === undefined) return { skip: 'no publication time for this version' };
  const firstOther = earliestOther(idx.all, version);
  const firstHooked = earliestOther(idx.hooked, version);
  let used; let ever; let n;
  if (firstOther <= c - SETTLED_MS) {
    used = 'settled 24 h'; ever = firstHooked <= c - SETTLED_MS; n = countUpTo(idx.sorted, c - SETTLED_MS, false);
  } else if (firstOther < c) {
    used = 'cold start: plain'; ever = firstHooked < c; n = countUpTo(idx.sorted, c, true);
  } else return { skip: 'no earlier version' };
  used = `${used}: ${n} version${n === 1 ? '' : 's'}`;
  const cur = idx.hooks.get(version);
  const m = versions[version];
  const gyp = Boolean(m && typeof m === 'object' && pyTruthy(m.gypfile)) && !cur.includes('install') && !cur.includes('preinstall');
  return { L1: cur.length > 0 && !ever, L1i: gyp && !ever, hooks: cur, used, ever, gyp };
}

/**
 * Since 0.1.6: the row a download's walk makes when it read the tarball package.json. npm runs the tarball's install hooks,
 * not the registry entry's, so where the two differ the row follows the tarball: hooks only the registry entry declares (pinst
 * renames postinstall in the packed copy) no longer warn, and a first hook only the tarball declares does. `prev` is the
 * decision-time row (its `hooks_basis` carries `ever` and `gyp`); `tarHooks` and `regHooks` are the two hook dicts. Returns
 * the row to store, or null when the stored row carries no basis to re-read (a row an older runtime wrote, or a SKIP).
 */
export function tarballRow(prev, tarHooks, regHooks) {
  const b = prev && prev.hooks_basis;
  if (!b || typeof b.ever !== 'boolean' || typeof b.gyp !== 'boolean' || !['ALLOW', 'WARN', 'NOTE'].includes(prev.result)) return null;
  if (b.tarball !== null && b.tarball !== undefined) return null;      // already re-read: a tarball is immutable per version
  const keysOf = (d) => Object.keys(d).filter((k) => HOOKS.includes(k)).sort();
  const t = keysOf(tarHooks); const g = keysOf(regHooks);
  const same = t.length === g.length && t.every((k) => tarHooks[k] === regHooks[k]);
  const kind = same ? 'same' : !t.length ? 'registry-only' : !g.length ? 'added' : 'changed';
  const basis = { ever: b.ever, gyp: b.gyp, tarball: kind };
  if (same) return null;                                                // nothing to re-read: the registry entry is what npm runs
  const L1 = t.length > 0 && !b.ever;
  const gypWarn = b.gyp && !b.ever && !t.includes('install') && !t.includes('preinstall');
  if (L1) return result('WARN', `the tarball package.json npm runs declares ${t.join(', ')}; no earlier version had an install hook`, basis);
  if (gypWarn) return result('WARN', 'gypfile present (an implicit node-gyp install) with no install/preinstall hook; no earlier version had an install hook', basis);
  if (prev.result === 'WARN') {
    return result('NOTE', `the registry entry declares ${g.join(', ') || 'no install hook'}; the tarball package.json npm runs declares ${t.join(', ') || 'none'}`, basis);
  }
  return { gate: GATE, result: prev.result, detail: `${prev.detail}; the tarball package.json npm runs declares ${t.join(', ') || 'no install hook'}`,
    hooks_basis: basis };
}

// each hook named with its command -- publisher text, so sanitised (control and bidi characters
// stripped) and capped at 80 characters; a non-string value is shown by its JSON type.
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g;
function commandOf(v) {
  if (typeof v !== 'string') return Array.isArray(v) ? '[list]' : (v && typeof v === 'object' ? '{object}' : `[${typeof v}]`);
  const s = v.replace(UNSAFE, '');
  return s.length > 80 ? `${s.slice(0, 80)}…` : s;
}
const named = (manifest, hooks) => hooks.map((k) => `${k} (${commandOf(manifest?.scripts?.[k])})`).join(', ');

export default {
  name: GATE,
  evaluate(input) {
    const r = evaluateL1(input?.rawVersions, input?.rawTimes, input?.version);
    if (r.skip) return result('SKIP', `not evaluable: ${r.skip}`);
    // since 0.1.6: what a download's walk needs to re-read this row against the tarball package.json (tarballRow)
    const basis = { ever: r.ever, gyp: r.gyp, tarball: null };
    if (r.L1) {
      return result('WARN', `${named(input.rawVersions[input.version], r.hooks)} present; no earlier version (${r.used}) had an install hook`, basis);
    }
    if (r.L1i) return result('WARN', `gypfile present (an implicit node-gyp install) with no install/preinstall hook; no earlier version (${r.used}) had an install hook`, basis);
    return result('ALLOW', `no install hook introduced (${r.used})`, basis);
  },
};
