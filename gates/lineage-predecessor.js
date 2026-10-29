// 0.1.5: the LINEAGE predecessor -- a port of the seed's lineage rule
// (the seed builder's `resolve_lineage_predecessors`, final form +pipekey1, with the forward stub predicate),
// over the served packument instead of the corpus:
//
//   E5  a version whose `time` entry is missing or does not parse is in no lineage and holds no predecessor;
//   E4  a `0.0.x-security` takedown stub likewise; and, for a version first observed at or after
//       DETECTOR_STUB_EFFECTIVE_AT, a version whose description is the npm holding text or that is 0.0.1-security
//       (+stubpred1; name-hold texts are NOT excluded, as there);
//   sort the rest by (publication time, version string), stable -- the order the corpus and the seed use;
//   E2  lineage key = the leading integer of the version (all 0.x share '0'; a non-digit prefix -> '0');
//   E1  contiguous-CalVer tail: when the >= 2 most recently introduced DISTINCT majors are strictly decreasing CalVer years
//       (2000..2027), they collapse into one lineage key, so a prerelease of the next year is judged against the right base;
//   predecessor (+pipekey1): a release takes the previous version of ANY tag family in its lineage key
//   (publish order, so a prerelease can be its predecessor); a prerelease takes the previous version of ITS OWN tag family in
//   that key, and the first of a family has none.
//   tag family (+platfam1, since 0.1.6, tag family 0.3 as the live rule): a prerelease's platform tokens join its family, so
//   "2.0.0-beta.25-darwin-arm64" follows "2.0.0-beta.24-darwin-arm64", not the "2.0.0-beta.25" published beside it.
//
// As in the seed's resolver, two maps are resolved: the legacy one (only the regex excludes) and the activated one (forward
// rows by the stub predicate). A version takes its predecessor from the activated map when it was first observed at or after
// the instant, otherwise from the legacy map. The proxy has no first-observed time for another version, so it stands in that
// version's publication time; the version it analyses it observes now, so that one is always forward.
//
// Why this and not gates/predecessor.js (the highest lower RELEASE of the same SemVer major):
// measured on 24,154,424 versions, the size-jump-provenance rule fires on 0.020 % of versions
// against this predecessor (1 per 6,083 established versions) and on 0.106 % against gates/predecessor.js, with the same
// recall: a canary or nightly prerelease compared with an old stable release is noise, and this rule compares it with the
// build before it instead. The two predecessors answer different questions; the other Tier 1 gates keep theirs.
// With +pipekey1 every lineage-based rate falls again (size-jump-provenance 4,670 -> 3,634 fires); only
// prereleases change predecessor (2,149,041 of 24,248,817 versions), no release does.
//
// Cost: an index per packument (memoised per (versions, times) object), O(n log n); a lookup is O(1).
import { RELEASE_FAMILY, HOLDING_DESCRIPTION, tagFamily as seedTagFamily } from '../seed/v3/tag-family.js';

export { HOLDING_DESCRIPTION };
/** The tag family this predecessor groups by: 0.3, with the prerelease's platform tokens. */
export const tagFamily = (version) => seedTagFamily(version, { platforms: true });
export const LINEAGE_RULE_VERSION = 'infra5d-1.2+fu2final+norm1+sizeshrink+pipekey1+platfam1';
export const DETECTOR_STUB_EFFECTIVE_AT = '2026-10-13T22:00:00Z';   // collector/stub_recognition.py, the same instant
export const STUB_RE = /0\.0\.\d+-security$/;          // E4, exactly the corpus's pattern
const LEGACY_STUB_VERSION = '0.0.1-security';
const EFFECTIVE_MS = Date.parse(DETECTOR_STUB_EFFECTIVE_AT);
const MAJOR_RE = /^(\d+)/;
const CALVER_RE = /^20\d\d$/;
const CALVER_MIN = 2000; const CALVER_MAX = 2027;
export const CALVER_KEY = '__CALVER__';

export const majorOf = (version) => { const m = MAJOR_RE.exec(String(version ?? '')); return m ? m[1] : '0'; };
const isCalverYear = (major) => CALVER_RE.test(major) && Number(major) >= CALVER_MIN && Number(major) <= CALVER_MAX;
const timeOf = (times, v) => (times && typeof times[v] === 'string' ? Date.parse(times[v]) : NaN);

const excludedLegacy = (v) => STUB_RE.test(v);
/** The forward stub predicate (stub_recognition.excluded_from_lineage_forward): a superset of the legacy regex. */
const excludedForward = (v, manifest) => (manifest && typeof manifest === 'object' && manifest.description === HOLDING_DESCRIPTION)
  || v === LEGACY_STUB_VERSION || excludedLegacy(v);

/** One resolution with the caller's E4 exclusion: version -> predecessor version | null, for every version. */
function resolve(versions, times, excluded) {
  const out = new Map();
  const valid = [];
  for (const v of Object.keys(versions)) {
    out.set(v, null);
    if (excluded(v)) continue;
    const t = timeOf(times, v);
    if (Number.isNaN(t)) continue;
    valid.push({ v, t });
  }
  valid.sort((a, b) => (a.t - b.t) || (a.v < b.v ? -1 : (a.v > b.v ? 1 : 0)));
  // E1: distinct majors in order of first appearance; the CalVer tail collapses only when it has >= 2 members
  const distinct = [];
  const seen = new Set();
  for (const { v } of valid) { const m = majorOf(v); if (!seen.has(m)) { seen.add(m); distinct.push(m); } }
  const tail = [];
  for (let i = distinct.length - 1; i >= 0; i -= 1) {
    const m = distinct[i];
    if (isCalverYear(m) && (!tail.length || Number(m) < Number(tail[tail.length - 1]))) tail.push(m); else break;
  }
  const calver = new Set(tail.length >= 2 ? tail : []);
  const key = (v) => { const m = majorOf(v); return calver.has(m) ? CALVER_KEY : m; };
  const lastInLineage = new Map();
  const lastInFamily = new Map();
  for (const { v } of valid) {
    const k = key(v); const fam = tagFamily(v); const kf = `${k}\u0000${fam}`;
    const p = fam === RELEASE_FAMILY ? lastInLineage.get(k) : lastInFamily.get(kf);
    out.set(v, p ?? null);
    lastInLineage.set(k, v);
    lastInFamily.set(kf, v);
  }
  return out;
}

/** Forward when first observed (default: published) at or after the instant; never when that time is unknown. */
const forwardIn = (times, observed) => (v) => {
  const t = observed && typeof observed[v] === 'string' ? Date.parse(observed[v]) : timeOf(times, v);
  return !Number.isNaN(t) && t >= EFFECTIVE_MS;
};
const activatedMap = (versions, times, isForward) => resolve(versions, times,
  (v) => (isForward(v) ? excludedForward(v, versions[v]) : excludedLegacy(v)));

/**
 * version -> predecessor version | null, for every version of the packument, as the seed's resolver gives it: each
 * version by its own first observation (`observed[v]`, else its publication time).
 */
export function lineagePredecessors(versions, times, { observed } = {}) {
  if (!versions || typeof versions !== 'object') return new Map();
  const isForward = forwardIn(times, observed);
  const legacy = resolve(versions, times, excludedLegacy);
  const activated = activatedMap(versions, times, isForward);
  const out = new Map();
  for (const v of Object.keys(versions)) out.set(v, isForward(v) ? activated.get(v) : legacy.get(v));
  return out;
}

const indexes = new WeakMap();           // versions -> WeakMap(times -> Map) | Map: the activated map, publication stand-in
function indexFor(versions, times) {
  const timed = times && typeof times === 'object';
  const build = () => activatedMap(versions, timed ? times : null, forwardIn(timed ? times : null, null));
  let entry = indexes.get(versions);
  if (timed) {
    if (!(entry instanceof WeakMap)) { entry = new WeakMap(); indexes.set(versions, entry); }
    if (!entry.has(times)) entry.set(times, build());
    return entry.get(times);
  }
  if (!entry || entry instanceof WeakMap) { entry = build(); indexes.set(versions, entry); }
  return entry;
}

/**
 * { version, manifest } of the lineage predecessor of the version the proxy analyses now (so forward), or null (first of
 * its line or of its tag, a stub, or undated).
 */
export function lineagePredecessorOf(versions, times, version) {
  if (typeof version !== 'string' || !versions || typeof versions !== 'object') return null;
  if (excludedForward(version, versions[version])) return null;
  const p = indexFor(versions, times).get(version);
  return p ? { version: p, manifest: versions[p] } : null;
}

/** Why a version has no lineage predecessor, for a gate's not-evaluable detail. */
export const noPredecessorReason = (version) => (tagFamily(version) === RELEASE_FAMILY
  ? 'no earlier version in this release line' : 'no earlier prerelease of the same tag in this release line');

export default { lineagePredecessorOf, lineagePredecessors, noPredecessorReason, majorOf, tagFamily, STUB_RE, CALVER_KEY,
  LINEAGE_RULE_VERSION, DETECTOR_STUB_EFFECTIVE_AT, HOLDING_DESCRIPTION };
