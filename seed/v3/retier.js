// Since 0.1.6 (cft-policy-1.3): the RE-TIER of the seed's strict rows.
//
// The strict rows (Channel-A critical, DAC trajectory surface) warn when a release breaks against the predecessor the seed
// records, or against anything the package ever had. Some of those breaks are not new: the same state already held on the
// release this one actually follows. This module re-reads each flag that broke against that release, the BASELINE, from
// the registry document the gate already holds (versions, publish times, per-version manifests; nothing is fetched), and
// says whether any flag is new in this release.
//
// It decides nothing. policy.js turns a strict WARN into a NOTE only when this block says `recorded`: no flag is new
// against the baseline and no guard holds. A NOTE is never an ALLOW row and never touches a BLOCK.
//
// THE BASELINE. Chosen only among versions with a manifest and a publish time strictly before this one; sibling builds of
// this version are excluded first (a different flavor, published within 24 h, with the same gitHead or the same release
// core: platform packages, slim/full pairs). Then: the latest version of the same release line and the same flavor, else
// the latest of the same release line, else the latest overall. Release line: "stable:<major>" ("stable:0.<minor>" when the
// major is 0); a prerelease is "pre:<major-or-0.minor>:<first identifier>[.<second> when there are three or more]".
// Flavor: the prerelease shape with counters and hashes masked ('2.0.0-beta.5-linux-x64' -> 'beta.#.linux.x64').
//
// FAIL-SAFE. Every doubt keeps the warning: no baseline, a baseline that is only a sibling build, a publish-time tie at
// this version or at the baseline, a version without a usable publish time, a removed version between the baseline and
// this one, a manifest that cannot be read on either side, a flag this module does not know. Each is a counting flag or a
// guard, named in the block.
import A from './adapter.js';
import PK from './packument.js';

export const RETIER_VERSION = 'retier-1.0';
export const RETIER_LIMITS = Object.freeze({
  sizeBreakFraction: 0.5,               // contract.SIZE_BREAK_FRACTION, the Channel-A size group
  sizeJumpFactor: 5,                    // contract.DAC_SIZE_JUMP_FACTOR, the DAC size_jump_5x predicate
  siblingWindowMs: 24 * 3_600_000,
  recentStateMs: 7 * 24 * 3_600_000,    // a state that began less than this before the release keeps the warning
});
export const PLACED = Object.freeze({ RECORDED: 'recorded', RAISED: 'raised' });
export const GUARDS = Object.freeze({
  INSTALL_HOOK: 'install-hook',                  // the install hooks npm runs are new or changed
  PROVENANCE_DROP: 'provenance-drop',            // provenance on the baseline, none now
  DEPENDENCY: 'dependency',                      // a dependency added, or one from outside the registry
  EVIDENCE_INCOMPLETE: 'evidence-incomplete',    // the finding or the seed did not cover this release fully
  RECENT_STATE: 'recent-state',                  // the state that clears a flag began less than 7 days earlier
});

const SEMVER = /^(\d+)\.(\d+)\.(\d+)(?:-([^+]+))?(?:\+.*)?$/;
// SemVer 2.0.0, the pattern gate.js uses for a gap release: a version npm can resolve. Only such versions are ordered here,
// so a version string that reaches the block's words can carry no control or bidi character.
const STRICT_SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;
const validVersion = (v) => typeof v === 'string' && v.length <= 256 && STRICT_SEMVER.test(v);
const HOOKS = ['preinstall', 'install', 'postinstall'];
const DEP_FIELDS = ['dependencies', 'optionalDependencies', 'peerDependencies'];
const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const own = (o, k) => isObj(o) && Object.hasOwn(o, k);

/** The prerelease shape with counters and hashes masked; '' for a stable version; null when not semver. */
export function flavor(v) {
  const m = SEMVER.exec(String(v)); if (!m) return null; if (!m[4]) return '';
  return m[4].split(/[.-]/).map((t) => (/^\d+$/.test(t) ? '#' : /^g?[0-9a-f]{6,}$/i.test(t) && /\d/.test(t) ? 'H' : t)).join('.');
}
/** major.minor.patch, the first prerelease token and every numeric or hash token: the flavor's literal suffix removed. */
export function releaseCore(v) {
  const m = SEMVER.exec(String(v)); if (!m) return null; const base = `${m[1]}.${m[2]}.${m[3]}`; if (!m[4]) return base;
  const t = m[4].split(/[.-]/);
  return `${base}-${[t[0], ...t.slice(1).filter((x) => /^\d+$/.test(x) || (/^g?[0-9a-f]{6,}$/i.test(x) && /\d/.test(x)))].join('.')}`;
}
/** The release line of a version, or null when it is not semver. */
export function lineKey(v) {
  const m = /^(\d+)\.(\d+)\.(\d+)(?:-([^+]+))?(?:\+.*)?$/.exec(String(v)); if (!m) return null;
  const maj = m[1] === '0' ? `0.${m[2]}` : m[1];
  if (!m[4]) return `stable:${maj}`; const ids = m[4].split('.');
  return `pre:${maj}:${ids.length >= 3 ? `${ids[0]}.${ids[1]}` : ids[0]}`;
}
const timeOf = (times, v) => (isObj(times) && typeof times[v] === 'string' ? Date.parse(times[v]) : NaN);
function isSibling(versions, times, target, v) {
  const t = timeOf(times, target); const tv = timeOf(times, v);
  if (!Number.isFinite(t) || !Number.isFinite(tv) || Math.abs(t - tv) > RETIER_LIMITS.siblingWindowMs) return false;
  if (flavor(v) === flavor(target)) return false;
  const gh = versions[target]?.gitHead; const gv = versions[v]?.gitHead;
  if (typeof gh === 'string' && gh && gh === gv) return true;
  const c = releaseCore(target); return c !== null && c === releaseCore(v);
}

// The document index is built ONCE PER DOCUMENT, as the gate's gap index is: the store evaluates every version of a packument,
// and sorting the whole version list per candidate was quadratic (3,900 versions took 45 s). Keyed on the `time{}` object
// itself, and valid only for the `versions{}` object it was built with.
const INDEX = new WeakMap();
export function indexFor(versions, times) {
  const memo = INDEX.get(times);
  if (memo && memo.versions === versions) return memo;
  const entries = []; const info = new Map(); let untimed = 0; let invalid = 0; let firstHooked = Infinity;
  for (const v of Object.keys(versions)) {
    if (!validVersion(v)) { invalid += 1; continue; }
    const t = timeOf(times, v);
    if (!Number.isFinite(t)) { untimed += 1; continue; }
    entries.push([t, v]); info.set(v, { t, key: lineKey(v), fl: flavor(v) });
    if (t < firstHooked && nonEmpty(hooksOf(versions[v]))) firstHooked = t;
  }
  entries.sort((a, b) => (a[0] - b[0]) || (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  const removed = Object.keys(times).filter((v) => v !== 'created' && v !== 'modified' && !Object.hasOwn(versions, v))
    .map((v) => timeOf(times, v)).filter(Number.isFinite).sort((a, b) => a - b);
  const idx = { versions, entries, info, untimed, invalid, firstHooked, removed };
  INDEX.set(times, idx);
  return idx;
}
/** The first position in sorted `arr` whose time satisfies `pred` (monotone), or arr.length. */
function firstAt(arr, pred, at = (x) => x[0]) {
  let lo = 0; let hi = arr.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (pred(at(arr[mid]))) hi = mid; else lo = mid + 1; }
  return lo;
}

/**
 * The baseline for `target`, or the reasons there is no clean one. Never throws on a hostile document: a malformed entry is
 * a reason, not an exception. `walkBack()` yields the baseline's tier from the baseline backwards (newest first), sibling
 * builds excluded, as [version, time].
 * @returns {{baseline: string|null, basis: string|null, walkBack: Function, problems: string[]}}
 */
export function chooseBaseline(versions, times, target) {
  const problems = [];
  const none = (why) => ({ baseline: null, basis: null, walkBack: function* empty() {}, problems: [...problems, why] });
  if (!isObj(versions) || !isObj(times)) return none('no registry version list or publish times at hand');
  if (!validVersion(target)) return none('this version is not a valid version');
  const t = timeOf(times, target);
  if (!Number.isFinite(t)) return none('this version has no publish time');
  const idx = indexFor(versions, times);
  if (idx.invalid) return none(`${idx.invalid} version key(s) are not valid versions`);
  if (idx.untimed) problems.push(`${idx.untimed} version(s) have no usable publish time and cannot be ordered`);
  const { entries, info } = idx;
  const lo = firstAt(entries, (x) => x >= t);
  let tied = 0;
  for (let i = lo; i < entries.length && entries[i][0] === t; i += 1) if (entries[i][1] !== target) tied += 1;
  if (tied) problems.push(`${tied} version(s) share this version's publish time`);
  // a sibling is published within 24 h of the target: only those need the check
  const sib = (i) => t - entries[i][0] <= RETIER_LIMITS.siblingWindowMs && isSibling(versions, times, target, entries[i][1]);
  const key = lineKey(target); const fl = flavor(target);
  let chrono = -1; let sameLine = -1; let sameFlavor = -1;
  for (let i = lo - 1; i >= 0; i -= 1) {
    if (sib(i)) continue;
    const x = info.get(entries[i][1]);
    if (chrono < 0) chrono = i;
    if (key !== null && x.key === key) {
      if (sameLine < 0) sameLine = i;
      if (fl !== null && x.fl === fl) { sameFlavor = i; break; }
    }
  }
  if (chrono < 0) return none(lo > 0 ? 'only sibling builds of this version precede it' : 'no earlier version');
  const [at, basis, inTier] = sameFlavor >= 0 ? [sameFlavor, 'same flavor', (x) => x.key === key && x.fl === fl]
    : sameLine >= 0 ? [sameLine, 'same release line', (x) => x.key === key] : [chrono, 'previous release', () => true];
  const [tb, baseline] = entries[at];
  for (let i = at - 1; i >= 0 && entries[i][0] === tb; i -= 1) if (!sib(i)) { problems.push(`another version shares the baseline ${baseline}'s publish time`); break; }
  for (let i = at + 1; i < lo && entries[i][0] === tb; i += 1) if (!sib(i)) { problems.push(`another version shares the baseline ${baseline}'s publish time`); break; }
  const removed = firstAt(idx.removed, (x) => x >= t, (x) => x) - firstAt(idx.removed, (x) => x > tb, (x) => x);
  if (removed > 0) problems.push(`${removed} removed version(s) lie between the baseline ${baseline} and this version`);
  function* walkBack() {
    for (let i = at; i >= 0; i -= 1) if (!sib(i) && inTier(info.get(entries[i][1]))) yield entries[i];
  }
  return { baseline, basis, walkBack, problems, hookedBefore: idx.firstHooked < t };
}

const FACTS = new WeakMap();   // versions{} -> { times, pkg, by: version -> facts }

/** What the gate's adapter derives for one version (the same digests the checker compares), or null when unreadable. */
function factsOf(pkg, v, versions, times) {
  const m = versions[v];
  if (!isObj(m)) return null;
  try {
    const row = PK.observationFromManifest(v, m, typeof times[v] === 'string' ? times[v] : null);
    const c = A.candidateFromRawRow(row, { packageName: pkg, domainVersionCount: 0 });
    const u = isObj(m._npmUser) ? m._npmUser : {};
    const tp = isObj(u.trustedPublisher) ? u.trustedPublisher : null;
    return { c, hooks: hooksOf(m), manifest: m,
      trusted: tp ? JSON.stringify([tp.id ?? null, String(tp.oidcConfigId ?? '').replace(/^oidc:/, '') || null]) : null };
  } catch {
    return null;
  }
}
/** The install hooks npm runs on a registry install, as the registry entry declares them. */
function hooksOf(m) {
  const out = {};
  if (isObj(m) && isObj(m.scripts)) for (const k of HOOKS) if (PK.pyTruthy(m.scripts[k])) out[k] = m.scripts[k];
  return out;
}
const sameHooks = (a, b) => JSON.stringify(Object.entries(a).sort()) === JSON.stringify(Object.entries(b).sort());
const nonEmpty = (d) => Object.keys(d).length > 0;

/**
 * One flag of this release re-read against version `bv`: { counts, words }. A side that cannot be read counts.
 * The definitions are the checker's (seed/v3/checker.js), with the baseline in place of the seed's predecessor.
 */
function reading(flag, F, B, bv) {
  if (!F || !B) return { counts: true, words: `cannot be read: ${!F ? 'this release' : bv}'s registry entry is not usable` };
  const c = F.c; const b = B.c;
  switch (flag) {
    case 'publisher': {
      const why = [];
      if (c.identity_digest === null || b.identity_digest === null) why.push('publisher identity unknown on one side');
      else if (c.identity_digest !== b.identity_digest) why.push('publisher account differs');
      if (!b.maint_digest) why.push(`maintainer list unknown on ${bv}`);
      else if (b.maint_digest !== (c.maint_digest || '')) why.push('maintainer list differs');
      if (b.tool_name && c.tool_name && b.tool_name === c.tool_name && b.tool_key !== null && c.tool_key !== null
        && c.tool_key < b.tool_key) why.push('older publish tool');
      if (F.trusted !== B.trusted) why.push('trusted publisher configuration differs');
      return why.length ? { counts: true, words: `${why.join(', ')} against ${bv}` }
        : { counts: false, words: `same publisher, maintainers and publish configuration as ${bv}` };
    }
    case 'first_pkg_appearance_new_publisher':
      if (c.tuple_digest === null || b.tuple_digest === null) return { counts: true, words: `publisher unknown on ${c.tuple_digest === null ? 'this release' : bv}` };
      return c.tuple_digest !== b.tuple_digest ? { counts: true, words: `published by another account than ${bv}` }
        : { counts: false, words: `${bv} was published by the same account` };
    case 'provenance': case 'prov_dropped':
      if (b.provenance_present && !c.provenance_present) return { counts: true, words: `provenance on ${bv}, none now` };
      return { counts: false, words: b.provenance_present ? `provenance kept since ${bv}` : `no provenance on ${bv} either: never having it is not a drop` };
    case 'git':
      return b.head_present && !c.head_present ? { counts: true, words: `gitHead on ${bv}, none now` }
        : { counts: false, words: `no gitHead dropped against ${bv}` };
    case 'size': case 'size_jump_5x': {
      const sb = b.size_bytes; const sc = c.size_bytes;
      if (!Number.isFinite(sb) || sb <= 0 || !Number.isFinite(sc)) return { counts: true, words: `unpacked size unknown on ${!Number.isFinite(sc) ? 'this release' : bv}` };
      const ratio = sc / sb; const L = RETIER_LIMITS;
      const counts = flag === 'size' ? ratio >= 1 + L.sizeBreakFraction || ratio <= 1 - L.sizeBreakFraction : ratio >= L.sizeJumpFactor;
      return { counts, words: `unpacked size ${sc} B against ${sb} B on ${bv} (x${ratio.toFixed(2)})` };
    }
    case 'install': case 'install_introduced':
      if (!nonEmpty(F.hooks)) return { counts: false, words: 'no install hook in the registry entry' };
      return sameHooks(F.hooks, B.hooks) ? { counts: false, words: `same install hooks as ${bv}` }
        : { counts: true, words: `install hooks differ from ${bv}` };
    default:
      return { counts: true, words: `unknown flag ${JSON.stringify(String(flag).slice(0, 60))}` };
  }
}

/** A dependency spec that is not the public registry: a git host or URL, an http(s) URL, file:/link:, owner/repo shorthand,
 *  or an npm: alias to ANOTHER name. */
export function nonRegistrySpec(name, spec) {
  const s = String(spec ?? '').trim();
  if (/^(?:github|gitlab|bitbucket|gist):/i.test(s) || /^git(?:\+[a-z]+)?:/i.test(s) || /^git\+/i.test(s) || /^https?:\/\//i.test(s)
    || /^(?:file|link|portal):/i.test(s)) return true;
  if (/^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(s) && !/^\d/.test(s)) return true;
  const a = /^npm:((?:@[^/@]+\/)?[^@]+)(?:@.*)?$/.exec(s); if (a && a[1] !== name) return true;
  return false;
}
function dependencyChanges(fm, bm) {
  const added = []; const outside = [];
  for (const f of DEP_FIELDS) {
    const A0 = isObj(bm?.[f]) ? bm[f] : {}; const B0 = isObj(fm?.[f]) ? fm[f] : {};
    for (const [name, spec] of Object.entries(B0)) {
      const had = Object.hasOwn(A0, name); const nr = nonRegistrySpec(name, spec);
      if (nr && (!had || !nonRegistrySpec(name, A0[name]))) outside.push(name);
      else if (!had) added.push(name);
    }
  }
  return { added, outside };
}

/** The flags that broke in the finding: Channel-A groups (only when the placement makes Channel-A usable) and DAC predicates. */
export function brokenFlags(finding, placement) {
  const out = [];
  const usable = !placement || placement.channel_a_usable !== false;
  if (usable) for (const [k, v] of Object.entries(finding?.channel_a?.groups || {})) if (v && v.value === true) out.push({ flag: k, group: 'channel_a' });
  for (const [k, v] of Object.entries(finding?.dac_trajectory?.predicates || {})) if (v && v.value === true) out.push({ flag: k, group: 'dac' });
  return out;
}

/**
 * When the state that clears `flag` began: walk back through the baseline's tier from the baseline while the flag still
 * does not count against that version; stop at a version more than the recent-state window before this release (the state
 * is old enough). Returns the earliest version reached, its time, and whether the state is recent.
 */
function stateSince(flag, F, walkBack, factsAt, t) {
  let since = null;
  for (const [tv, v] of walkBack()) {
    if (reading(flag, F, factsAt(v), v).counts) break;
    since = v;
    if (t - tv >= RETIER_LIMITS.recentStateMs) return { since, recent: false };
  }
  return { since, recent: since !== null };
}

/**
 * The re-tier block for one evaluated candidate.
 *
 * @param {object} p
 *   p.packageName, p.version
 *   p.finding        the checker's finding
 *   p.placement      the gate's placement ({ channel_a_usable, ... }) or null
 *   p.notEvaluated   policy.notEvaluated(finding, placement): any entry is incomplete evidence
 *   p.rawVersions, p.rawTimes   the packument's versions{} and time{}
 * @returns {object|null} null when no strict flag broke (nothing to re-tier)
 */
export function retierOf({ packageName, version, finding, placement = null, notEvaluated = [], rawVersions, rawTimes }) {
  const flags = brokenFlags(finding, placement);
  if (!flags.length) return null;
  const base = { version: RETIER_VERSION };
  const raised = (why, extra = {}) => ({ ...base, placement: PLACED.RAISED, baseline: null, basis: null,
    flags: flags.map((f) => ({ ...f, counts: true, words: why })), flags_dropped: [], guards: [], words: why, ...extra });
  if (!isObj(rawVersions) || !isObj(rawTimes) || !own(rawVersions, version)) return raised('no registry version list at hand: every flag counts');
  const ch = chooseBaseline(rawVersions, rawTimes, version);
  if (ch.baseline === null || ch.problems.length) {
    return raised(`no clean baseline (${ch.problems.join('; ')}): every flag counts`, { problems: ch.problems });
  }
  const bv = ch.baseline;
  // a version's facts are its own, so they are kept per document (the store evaluates every version of it)
  let memo = FACTS.get(rawVersions);
  if (!memo || memo.times !== rawTimes || memo.pkg !== packageName) { memo = { times: rawTimes, pkg: packageName, by: new Map() }; FACTS.set(rawVersions, memo); }
  const factsAt = (v) => { if (!memo.by.has(v)) memo.by.set(v, factsOf(packageName, v, rawVersions, rawTimes)); return memo.by.get(v); };
  const F = factsAt(version); const B = factsAt(bv);
  const rows = flags.map((f) => ({ ...f, ...reading(f.flag, F, B, bv) }));

  const guards = [];
  if (F && B) {
    if (nonEmpty(F.hooks) && !sameHooks(F.hooks, B.hooks)) guards.push({ id: GUARDS.INSTALL_HOOK, words: `the install hooks npm runs differ from ${bv}'s` });
    const gyp = PK.pyTruthy(F.manifest.gypfile) && !own(F.hooks, 'install') && !own(F.hooks, 'preinstall');
    if (gyp && !ch.hookedBefore) {
      guards.push({ id: GUARDS.INSTALL_HOOK, words: 'gypfile makes npm build at install, and no version ever had an install hook' });
    }
    if (B.c.provenance_present && !F.c.provenance_present) guards.push({ id: GUARDS.PROVENANCE_DROP, words: `provenance on ${bv}, none now` });
    const dc = dependencyChanges(F.manifest, B.manifest);
    if (dc.added.length || dc.outside.length) {
      guards.push({ id: GUARDS.DEPENDENCY, words: `against ${bv}: ${dc.added.length} dependency(ies) added, ${dc.outside.length} from outside the registry` });
    }
  }
  const incomplete = [];
  if (Array.isArray(notEvaluated) && notEvaluated.length) incomplete.push(`${notEvaluated.length} observation(s) not evaluated`);
  if (placement && placement.channel_a_usable === false) incomplete.push(`placement ${placement.kind ?? 'not usable'}`);
  // Releases published after the seed tip are NOT incomplete evidence here: the baseline is read from the registry document,
  // which is exactly what corrects a comparison against an older seed tip.
  if (incomplete.length) guards.push({ id: GUARDS.EVIDENCE_INCOMPLETE, words: incomplete.join('; ') });

  const counting = rows.filter((r) => r.counts);
  if (!counting.length) {
    const t = timeOf(rawTimes, version);
    for (const r of rows) {
      const s = stateSince(r.flag, F, ch.walkBack, factsAt, t);
      r.state_since = s.since;
      if (s.recent) {
        guards.push({ id: GUARDS.RECENT_STATE, words: `the state that clears ${r.flag} began at ${s.since}, less than 7 days before this release` });
      }
    }
  }
  const placed = counting.length || guards.length ? PLACED.RAISED : PLACED.RECORDED;
  const words = placed === PLACED.RECORDED
    ? `not new against ${bv} (${ch.basis}): ${rows.map((r) => r.flag).join(', ')} already held there`
    : [counting.length ? `new against ${bv} (${ch.basis}): ${counting.map((r) => r.flag).join(', ')}` : null,
      guards.length ? `kept by ${[...new Set(guards.map((g) => g.id))].join(', ')}` : null].filter(Boolean).join('; ');
  return { ...base, placement: placed, baseline: bv, basis: ch.basis, flags: rows,
    flags_dropped: rows.filter((r) => !r.counts).map((r) => r.flag), guards, words };
}

const FLAG_NAMES = new Set(['publisher', 'provenance', 'install', 'size', 'git', 'install_introduced', 'size_jump_5x', 'prov_dropped',
  'first_pkg_appearance_new_publisher']);
const GUARD_IDS = new Set([...Object.values(GUARDS), 'tarball-check', 'tarball-hook']);
const BASES = new Set(['same flavor', 'same release line', 'previous release']);
const capText = (x, n) => (typeof x === 'string' ? (x.length > n ? `${x.slice(0, n)}...` : x) : '');

/** The block as a gate result carries it: bounded, closed vocabularies, no per-flag words. */
export function compact(b) {
  if (!isObj(b)) return null;
  return {
    version: RETIER_VERSION,
    placement: b.placement === PLACED.RECORDED ? PLACED.RECORDED : PLACED.RAISED,
    baseline: validVersion(b.baseline) ? b.baseline : null,
    basis: BASES.has(b.basis) ? b.basis : null,
    flags_dropped: (Array.isArray(b.flags_dropped) ? b.flags_dropped : []).filter((f) => FLAG_NAMES.has(f)).slice(0, 9),
    guards: [...new Set((Array.isArray(b.guards) ? b.guards : []).map((g) => g && g.id).filter((id) => GUARD_IDS.has(id)))],
    words: capText(b.words, 400),
  };
}

/** A validated copy of a stored or returned compact block, or null when absent or malformed (never throws). */
export function validCompact(x) {
  if (!isObj(x) || x.version !== RETIER_VERSION || !Object.values(PLACED).includes(x.placement)) return null;
  if (x.baseline !== null && !validVersion(x.baseline)) return null;
  if (x.basis !== null && !BASES.has(x.basis)) return null;
  if (!Array.isArray(x.flags_dropped) || x.flags_dropped.length > 9 || !x.flags_dropped.every((f) => FLAG_NAMES.has(f))) return null;
  if (!Array.isArray(x.guards) || x.guards.length > GUARD_IDS.size || !x.guards.every((g) => GUARD_IDS.has(g))) return null;
  if (typeof x.words !== 'string' || x.words.length > 403) return null;
  return { version: x.version, placement: x.placement, baseline: x.baseline, basis: x.basis, flags_dropped: [...x.flags_dropped],
    guards: [...x.guards], words: x.words };
}

export default { RETIER_VERSION, RETIER_LIMITS, PLACED, GUARDS, flavor, releaseCore, lineKey, chooseBaseline, nonRegistrySpec,
  brokenFlags, retierOf, compact, validCompact, indexFor };
