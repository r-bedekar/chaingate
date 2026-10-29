// The supported installation path, assembled: the v3 seed as a gate module.
//
//   npm packument  ->  explicit observation row  ->  candidate  ->  finding  ->  policy  ->  one
//   GateResult, which the proxy's packument rewriter turns into enforcement.
//
// Each arrow is a layer that already has its own ground truth and its own conformance result. This
// module only composes them, and it decides nothing itself: the disposition comes from policy.js and
// the evidence from the detection contract.
//
// WHERE A LIVE RELEASE SITS IN HISTORY.
//
// This is grounded in the final lineage rule of record
// (`collector/drift_cooccurrence.resolve_lineage_predecessors`), not in a shortcut. That rule is:
//
//   E5  a version with no publication time is dropped: it can neither be a predecessor nor hold one
//   E4  a `0.0.<n>-security` takedown stub is dropped for the same reason
//       sort (published_at, version) stable
//   E2  lineage key = leading-integer major; a non-digit prefix is '0'
//   E1  contiguous-CalVer-tail: if the >=2 most recent DISTINCT majors, in publish order, are
//       strictly decreasing CalVer years, they collapse into one `__CALVER__` key
//       predecessor = the previous version in the same lineage key, in publish order
//
// "The package has one lineage, so a new release appends to it" was a SHORTCUT and is gone. It
// ignored eligibility (a stub or a version with no publication time holds no predecessor at all),
// it ignored publication ORDERING (a version published before the recorded tip is not its
// successor), and it silently treated a version the seed had compacted away as though it were new.
//
// What the seed DOES support, exactly:
//
//   recorded              the spine or events name this release      -> lineage and ordinal
//   append                one lineage carries this lineage key, and (published_s, version) sorts
//                         AFTER that lineage's recorded tip          -> that lineage, ord null
//   new-major cold start  no recorded lineage carries this key       -> first of its own lineage,
//                                                                      so no predecessor exists
//   historical-omitted    the key matches but the release sorts at or before the tip: the seed
//                         keeps a K-deep spine, so this is a version compaction dropped, not a
//                         new one
//   ineligible-stub /     E4 / E5: the release is outside lineage grouping entirely
//   ineligible-no-time
//   unresolved            several lineages share the key, or a CalVer collapse could change with
//                         this release -- E1 depends on the package's full distinct-major publish
//                         sequence, which the seed does not store
//
// SEED CONTRACT 1.2 (placement rule rl2-placement-1.0, the seed side's tools/seedgen/placement.py).
// The rule of record keys a lineage by (major, prerelease tag family): a prerelease's predecessor is the previous version
// of its own family in its key, a plain release's is the previous version of ANY family in its key. The seed keeps one
// chain per (key, family), "release" a family of its own, and every chain's tip, so for a live release:
//
//   a prerelease of family f   appends to the (key, f) chain after its tip; the first of its family is
//                              new-family-cold-start (no predecessor)
//   a plain release            appends to the chain holding the latest tip across its key's chains (that may be a
//                              prerelease chain); no chain in the key is new-major-cold-start
//   a same-second tie the predecessor depends on (the candidate against the tip, or two tips against each other) is
//   unresolved; a release before its own chain's tip is historical-omitted, inside another chain's history unresolved;
//   a candidate carrying the npm holding description is ineligible-stub (a live release is always forward of the stub
//   instant, so the forward stub predicate applies); E1 CalVer stays unresolved. A 1.0 / 1.1 seed is placed as above.
//
// Only `recorded` and `append` yield a Channel-A comparison. For every other outcome Channel-A is
// NOT evaluated and the gate says why, IN ITS OWN WORDS, rather than letting the checker report
// `uncovered_package` for a package the seed covers. The DAC trajectory is package-level -- it reads
// prior versions across the whole PackageView by publication time and never needs a lineage -- so it
// stays evaluated, and an exact-version advisory pin is a recorded fact that needs no placement at
// all. Both survive an unresolved placement.

import A from './adapter.js';
import PK from './packument.js';
import POL from './policy.js';
import { emailDomain } from './normalize.js';
import { resolvePublisherEmail } from './normalize-extra.js';
import { RELEASE_FAMILY, HOLDING_DESCRIPTION, tagFamily } from './tag-family.js';
import RT from './retier.js';

const SEED_V3_GATE = 'seed-v3';
const FROM_PACKUMENT = 'from-packument';

// The domain map is computed ONCE PER PACKUMENT and memoised on the document itself.
//
// Rebuilding it per candidate made the work quadratic: a packument with N versions visited every one
// of them for each candidate, so N candidates cost N^2 manifest visits (4 candidates, 16 visits, as
// measured). The map is a property of the DOCUMENT, not of a candidate, so it is computed once.
//
// A WeakMap keyed on the `versions{}` object is deliberate. The key IS the document, so the context
// is scoped to it exactly: a freshly fetched packument is a different object and is recomputed, and
// the entry is collected with the document. A cache keyed on the package NAME would be none of those
// things -- it would outlive the document and answer a later fetch with an earlier fetch's counts.
const DOMAIN_COUNTS = new WeakMap();

/** The package-scoped domain map for this packument, computed at most once per document. */
function domainCountsFor(rawVersions) {
  const memo = DOMAIN_COUNTS.get(rawVersions);
  if (memo) return memo;
  const counts = PK.domainVersionCounts(rawVersions);
  DOMAIN_COUNTS.set(rawVersions, counts);
  return counts;
}

/**
 * The domain version count for one candidate.
 *
 * `provider_class` is derived from it, and it is PACKAGE-SCOPED: the writer counts the versions of
 * THIS package published from the candidate's e-mail domain. Nothing global is observed or invented.
 *
 * Two honest sources, and the caller says which:
 *   a stated integer   the caller takes responsibility for the number
 *   'from-packument'   computed from the document in hand, which carries exactly that population
 *
 * Note what the second one cannot reproduce: the seed counted as of its history cutoff, a packument
 * is current, so a release published after the cutoff is counted here and was not counted there.
 */
function resolveDomainVersionCount(configured, { rawVersions, candidateEmail }) {
  if (configured !== FROM_PACKUMENT) return { count: configured, source: 'stated' };
  if (!rawVersions || typeof rawVersions !== 'object') {
    throw new Error(`domainVersionCount is '${FROM_PACKUMENT}' but no packument versions map was `
      + 'supplied: the count cannot be computed and must not be guessed');
  }
  const domain = emailDomain(candidateEmail);
  if (!domain) return { count: 0, source: 'from-packument', domain: null };
  // one map per document, then a lookup per candidate
  return { count: domainCountsFor(rawVersions).get(domain) || 0, source: 'from-packument', domain };
}

// Rules E4/E2 above, mirrored exactly: `0\.0\.\d+-security$` and `^(\d+)` with a '0' fallback.
const STUB_RE = /0\.0\.\d+-security$/;
const MAJOR_RE = /^(\d+)/;
const CALVER_KEY = '__CALVER__';
const CALVER_YEAR_MIN = 2000;
const CALVER_YEAR_MAX = 2027;

const PLACEMENT_RULE_VERSION = 'rl2-placement-1.0';
// the contracts placed by rl2 (reader.js RL2_CONTRACTS): 1.3 is 1.2 with package-scoped lineage ids
const SEED_CONTRACT_1_3 = 'cft-seed-v3-contract-1.3';
const RL2_SEED_CONTRACTS = Object.freeze(['cft-seed-v3-contract-1.2', SEED_CONTRACT_1_3]);

const majorOf = (version) => (MAJOR_RE.exec(version || '')?.[1] ?? '0');
const isStub = (version) => STUB_RE.test(version || '');
const isCalverYear = (major) => /^20\d\d$/.test(major)
  && Number(major) >= CALVER_YEAR_MIN && Number(major) <= CALVER_YEAR_MAX;

/**
 * How a release orders against a recorded one — 'after', 'before', or 'ambiguous'.
 *
 * The lineage rule sorts on (published_at, version), but the seed stores `published_s` in SECONDS
 * (`contract.TIMESTAMP_PRECISION === 'unix_seconds_utc'`), so two releases inside the same second
 * are indistinguishable in it. Treating equal stored seconds as exact timestamp equality and then
 * breaking the tie on the version string INVENTED an ordering the seed cannot support: the real
 * `published_at` carries sub-second precision and may order the two either way.
 *
 * The detection contract already takes this position everywhere else — `hasPriorVersion` and
 * `priorStates` both classify `startS === c.published_s` as AMBIGUOUS rather than prior — so this is
 * the contract's own rule, applied where placement needs it.
 */
function compareToRecorded(candidateS, recordedS) {
  if (candidateS > recordedS) return 'after';
  if (candidateS < recordedS) return 'before';
  return 'ambiguous';
}

const stubReason = (version) => `${version} is a 0.0.x-security takedown stub: it is excluded `
  + 'from lineage grouping and can hold no predecessor';

const PLACEMENTS = Object.freeze({
  RECORDED: 'recorded',
  APPEND: 'append',
  NEW_MAJOR_COLD_START: 'new-major-cold-start',
  NEW_FAMILY_COLD_START: 'new-family-cold-start',
  HISTORICAL_OMITTED: 'historical-omitted',
  INELIGIBLE_STUB: 'ineligible-stub',
  INELIGIBLE_NO_PUBLICATION_TIME: 'ineligible-no-publication-time',
  UNCOVERED_PACKAGE: 'uncovered-package',
  UNRESOLVED: 'unresolved',
});

/**
 * Where this release sits, per the lineage rule. Never throws: an unresolved placement is an OUTCOME that the
 * caller must handle, not an error that discards the evidence which does not depend on it.
 *
 * @returns {{kind, lineage_id, ord, channel_a_usable, reason}}
 */
function resolvePlacement(seed, packageName, version, publishedS, { holdingDescription = false } = {}) {
  const no = (kind, reason) => ({ kind, lineage_id: null, ord: null, channel_a_usable: false, reason });

  // Since 0.1.6, a seed cache: a package whose bucket the cache does not hold is uncovered (never "not in the seed"), and a held
  // bucket's rows are checked against the root before they answer (a mismatch throws: an unusable input).
  const unheld = seed.uncoveredReason?.(packageName) ?? null;
  if (unheld) return no(PLACEMENTS.UNCOVERED_PACKAGE, unheld);
  seed.touch?.(packageName);

  const pkg = seed.db.prepare('SELECT id FROM packages WHERE package_name = ?').get(packageName);
  if (!pkg) {
    // A takedown stub is outside lineage grouping whether or not the seed represents its package (an all-stub
    // package used to report `uncovered-package`). Placement only; the finding is unchanged.
    if (isStub(version)) return no(PLACEMENTS.INELIGIBLE_STUB, stubReason(version));
    return no(PLACEMENTS.UNCOVERED_PACKAGE, 'the seed does not cover this package');
  }

  // Already recorded? That is a fact and outranks every rule below.
  const spine = seed.db.prepare(
    'SELECT s.lineage_id AS lineage_id, s.ord AS ord FROM spine s JOIN lineages l ON l.id = s.lineage_id '
    + 'WHERE l.package_id = ? AND s.version = ? ORDER BY s.lineage_id, s.ord LIMIT 1',
  ).get(pkg.id, version);
  if (spine) {
    return { kind: PLACEMENTS.RECORDED, lineage_id: spine.lineage_id, ord: spine.ord,
      channel_a_usable: true, reason: null };
  }
  const ev = seed.db.prepare(
    'SELECT e.lineage_id AS lineage_id, e.ord AS ord FROM events e JOIN lineages l ON l.id = e.lineage_id '
    + 'WHERE l.package_id = ? AND e.version = ? ORDER BY e.lineage_id, e.ord LIMIT 1',
  ).get(pkg.id, version);
  if (ev) {
    return { kind: PLACEMENTS.RECORDED, lineage_id: ev.lineage_id, ord: ev.ord,
      channel_a_usable: true, reason: null };
  }

  if (RL2_SEED_CONTRACTS.includes(seed.meta?.seed_contract_version)) {
    const rows = seed.db.prepare('SELECT id, lineage_key, tag_family, last_version, last_published_s FROM lineages '
      + 'WHERE package_id = ? ORDER BY ord').all(pkg.id);
    // a 1.3 seed groups by tag family 0.3 (platform tokens), a 1.2 seed by 0.2: a release is placed by its seed's rule
    return placeRl2(rows, version, publishedS, { holdingDescription,
      platforms: seed.meta?.seed_contract_version === SEED_CONTRACT_1_3 });
  }

  // E4 / E5: outside lineage grouping entirely, so it holds no predecessor.
  if (isStub(version)) return no(PLACEMENTS.INELIGIBLE_STUB, stubReason(version));
  if (publishedS === null || publishedS === undefined) {
    return no(PLACEMENTS.INELIGIBLE_NO_PUBLICATION_TIME,
      'the release has no publication time: it is excluded from lineage grouping and '
      + 'cannot be ordered against any predecessor');
  }

  const lineages = seed.db.prepare(
    'SELECT id, lineage_key, first_version, last_version, n_versions, first_published_s, '
    + 'last_published_s FROM lineages WHERE package_id = ? ORDER BY ord').all(pkg.id);
  if (lineages.length === 0) {
    return no(PLACEMENTS.UNCOVERED_PACKAGE, 'the seed records no lineage for this package');
  }

  // E1 is not recomputable from the seed: the collapse depends on the package's full distinct-major
  // sequence in publish order, and the seed stores lineage keys rather than that sequence. So any
  // release that could participate in a CalVer collapse is unresolved rather than guessed.
  const major = majorOf(version);
  if (isCalverYear(major) || lineages.some((l) => l.lineage_key === CALVER_KEY)) {
    return no(PLACEMENTS.UNRESOLVED,
      `lineage key for major ${major} depends on the CalVer collapse rule, which is computed `
      + "from the package's full distinct-major publish sequence and is not stored in the seed");
  }

  const matching = lineages.filter((l) => l.lineage_key === major);
  if (matching.length === 0) {
    return no(PLACEMENTS.NEW_MAJOR_COLD_START,
      `no recorded lineage carries major ${major}: this release is the first of its own lineage `
      + 'and has no predecessor to compare against');
  }
  if (matching.length > 1) {
    return no(PLACEMENTS.UNRESOLVED,
      `${matching.length} recorded lineages carry major ${major}; which chain this release extends `
      + "comes from the producer's predecessor resolver over the whole history");
  }

  const [ln] = matching;
  const order = compareToRecorded(publishedS, ln.last_published_s);
  if (order === 'after') {
    return { kind: PLACEMENTS.APPEND, lineage_id: ln.id, ord: null, channel_a_usable: true,
      reason: null };
  }
  if (order === 'ambiguous') {
    return no(PLACEMENTS.UNRESOLVED,
      `this release and the recorded tip ${ln.last_version} of lineage ${ln.id} both stamp to `
      + `${publishedS}, and the seed stores publication time in SECONDS — their true sub-second `
      + 'order is not recoverable from it, so whether this appends to the tip or precedes it '
      + 'cannot be decided');
  }
  return no(PLACEMENTS.HISTORICAL_OMITTED,
    `(${publishedS}, ${version}) is published before the recorded tip `
    + `(${ln.last_published_s}, ${ln.last_version}) of lineage ${ln.id}: this is a version the `
    + 'seed did not retain, not a new release, and its position in the chain is not recoverable');
}

/**
 * Where a LIVE release sits in a contract-1.2 seed (rl2-placement-1.0; the seed side's placement.place, case for case).
 * `lineages`: the package's rows (id, lineage_key, tag_family, last_version, last_published_s). Never throws.
 */
function placeRl2(lineages, version, publishedS, { holdingDescription = false, platforms = false } = {}) {
  const no = (kind, reason) => ({ kind, lineage_id: null, ord: null, channel_a_usable: false, reason });
  const append = (id) => ({ kind: PLACEMENTS.APPEND, lineage_id: id, ord: null, channel_a_usable: true, reason: null });
  if (isStub(version)) return no(PLACEMENTS.INELIGIBLE_STUB, stubReason(version));
  if (holdingDescription) {
    return no(PLACEMENTS.INELIGIBLE_STUB, `${version} carries the npm holding description (the forward stub predicate): it `
      + 'is excluded from lineage grouping and holds no predecessor');
  }
  if (publishedS === null || publishedS === undefined) {
    return no(PLACEMENTS.INELIGIBLE_NO_PUBLICATION_TIME, 'the release has no publication time: it cannot be ordered');
  }
  if (!lineages.length) return no(PLACEMENTS.UNCOVERED_PACKAGE, 'the seed records no lineage for this package');
  const major = majorOf(version);
  if (isCalverYear(major) || lineages.some((l) => l.lineage_key === CALVER_KEY)) {
    return no(PLACEMENTS.UNRESOLVED, `the lineage key for major ${major} depends on the CalVer collapse rule, which the `
      + 'seed does not store');
  }
  const key = lineages.filter((l) => l.lineage_key === major);
  const fam = tagFamily(version, { platforms });
  const own = key.filter((l) => l.tag_family === fam);
  if (own.length > 1) return no(PLACEMENTS.UNRESOLVED, `${own.length} recorded chains carry (${major}, ${fam}); a 1.2 seed holds at most one`);
  const againstTip = (tip, ownChain) => {
    if (publishedS > tip.last_published_s) return append(tip.id);
    if (publishedS === tip.last_published_s) {
      return no(PLACEMENTS.UNRESOLVED, `this release and the recorded tip ${tip.last_version} of chain ${tip.id} both stamp `
        + `to the same second ${publishedS}; their true order is not recoverable`);
    }
    if (ownChain && ownChain.id === tip.id) {
      return no(PLACEMENTS.HISTORICAL_OMITTED, `the release precedes the recorded tip ${tip.last_version} of its own chain `
        + `${tip.id}: a version the seed did not retain`);
    }
    return no(PLACEMENTS.UNRESOLVED, `the release falls inside chain ${tip.id}'s history (before its tip ${tip.last_version}): `
      + 'its predecessor is a row the seed does not name for a live release');
  };
  if (fam !== RELEASE_FAMILY) {
    if (!own.length) {
      return no(PLACEMENTS.NEW_FAMILY_COLD_START, `no recorded chain carries (${major}, ${fam}): the first ${fam} prerelease `
        + 'of its key has no predecessor');
    }
    return againstTip(own[0], own[0]);
  }
  if (!key.length) {
    return no(PLACEMENTS.NEW_MAJOR_COLD_START, `no recorded chain carries major ${major}: the release is the first of its key`);
  }
  if (own.length && publishedS < own[0].last_published_s) {
    return no(PLACEMENTS.HISTORICAL_OMITTED, `(${publishedS}, ${version}) precedes the recorded tip ${own[0].last_version} `
      + `of its own chain ${own[0].id}: a version the seed did not retain`);
  }
  const latest = Math.max(...key.map((l) => l.last_published_s));
  const atLatest = key.filter((l) => l.last_published_s === latest);
  if (atLatest.length > 1) {
    return no(PLACEMENTS.UNRESOLVED, `the tips ${atLatest.map((l) => l.last_version).join(', ')} of major ${major} stamp to `
      + `the same second ${latest}; which one precedes this release is not recoverable from second-resolution storage`);
  }
  return againstTip(atLatest[0], own.length ? own[0] : null);
}

// The gap index is computed ONCE PER DOCUMENT, like the domain map above: the store evaluates every version of a
// packument, and scanning the whole time map per candidate was quadratic (N candidates x N entries). Keyed on the
// `time{}` object itself, and valid only for the `versions{}` object it was built with.
const GAP_INDEX = new WeakMap();
const STALE_LISTED = 10;   // the policy row lists at most this many (policy.js STALE_LISTED)

// SemVer 2.0.0 (semver.org's recommended pattern). A gap release must be a version npm can resolve; a key that is not
// one is not a release (and its text, which a hostile registry controls, never reaches a decision's detail).
const SEMVER_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

/**
 * major -> [[published_s, version], ...] sorted, over served, timed, non-stub, SemVer releases of this document; plus
 * `seconds`: version -> published_s for those releases.
 */
function gapIndexFor(times, versions) {
  const memo = GAP_INDEX.get(times);
  if (memo && memo.versions === versions) return memo.byMajor;
  const byMajor = new Map();
  const seconds = new Map();
  for (const [v, t] of Object.entries(times)) {
    if (typeof t !== 'string' || !Object.prototype.hasOwnProperty.call(versions, v) || isStub(v)) continue;
    if (v.length > 256 || !SEMVER_RE.test(v)) continue;
    let s;
    try { s = A.publishedSeconds(t); } catch { continue; }
    if (s === null || s === undefined) continue;
    const m = majorOf(v);
    if (!byMajor.has(m)) byMajor.set(m, []);
    byMajor.get(m).push([s, v]);
    seconds.set(v, s);
  }
  for (const arr of byMajor.values()) arr.sort((a, b) => (a[0] - b[0]) || (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  byMajor.seconds = seconds;
  GAP_INDEX.set(times, { versions, byMajor });
  return byMajor;
}

/** First index in sorted `arr` whose published second satisfies `pred` (monotone), or arr.length. */
function firstIndex(arr, pred) {
  let lo = 0; let hi = arr.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (pred(arr[mid][0])) hi = mid; else lo = mid + 1; }
  return lo;
}

/**
 * Since 0.1.4 (cft-policy-1.2): how many registry releases sit between the seed tip and an `append`
 * candidate. Channel-A compares against the tip whatever the registry published since; this only COUNTS what the
 * seed has not seen, for policy to state as a coverage row. Never throws: a malformed time on another version is not
 * counted, and must not turn this candidate's evaluation into a refusal.
 *
 * A gap release: in `rawVersions` (served; a removed release is takedown context, not staleness), a parsable string
 * time, not a stub, the candidate's major (the lineage key an `append` placement matched), and published strictly
 * after the tip and strictly before the candidate (same-second ties are not orderable, as in `resolvePlacement`).
 *
 * @returns {null | {checked: false, tip} | {checked: true, k, tip, versions}}  null for any other placement
 */
function staleSeedGap(seed, place, input, candidateS, version) {
  if (!place || place.kind !== PLACEMENTS.APPEND) return null;
  const ln = seed.db.prepare('SELECT last_version, last_published_s FROM lineages WHERE id = ?').get(place.lineage_id);
  if (!ln) return null;
  const tip = ln.last_version;
  const times = input.rawTimes;
  const versions = input.rawVersions;
  const isMap = (o) => o !== null && typeof o === 'object' && !Array.isArray(o);
  if (!isMap(times) || !isMap(versions)) return { checked: false, tip };
  const index = gapIndexFor(times, versions);
  const arr = index.get(majorOf(version)) || [];
  // strictly after the tip, strictly before the candidate. O(log n) per candidate: k comes from the two positions and
  // only the first STALE_LISTED versions are materialised (the store evaluates every version of a packument).
  const lo = firstIndex(arr, (s) => s > ln.last_published_s);
  const hi = firstIndex(arr, (s) => s >= candidateS);
  let k = Math.max(0, hi - lo);
  // The candidate is never its own gap release, even when a caller's publishedAt and time{} disagree.
  const own = index.seconds.get(version);
  const ownInside = own !== undefined && own > ln.last_published_s && own < candidateS;
  if (ownInside) k -= 1;
  const listed = arr.slice(lo, Math.min(hi, lo + STALE_LISTED + 1)).map(([, v]) => v).filter((v) => v !== version)
    .slice(0, STALE_LISTED);
  return { checked: true, k, tip, versions: listed };
}

/**
 * The checks the gate makes ONCE, at construction, before it will evaluate anything. `check` makes
 * the same checks before its single evaluation, so neither can evaluate under a configuration the
 * other would refuse. Returns the normalised policy configuration.
 */
function validateEvaluationConfig({ config = {}, domainVersionCount } = {}) {
  // Validate the operator's configuration ONCE, at construction: a typo must fail when the gate is
  // wired, not silently on the first packument that happens to exercise that branch.
  const normalised = POL.normaliseConfig(config);

  // UNRESOLVED ENFORCEMENT POLICY MUST NOT BECOME PERMISSION. `REFUSE_TO_DECIDE` yields no
  // disposition, the gate could only answer SKIP, SKIP does not count toward the aggregate, and the
  // package installs -- so declining to decide silently permitted. In an ENFORCEMENT context both
  // choices must therefore be made; `policy.decide` keeps REFUSE_TO_DECIDE for callers that read a
  // decision rather than act on one.
  const undecided = POL.OPEN_CHOICE_KEYS.filter((k) => normalised[k] === 'REFUSE_TO_DECIDE');
  if (undecided.length) {
    throw new POL.PolicyConfigInvalid(
      `a gate that enforces must not leave policy unresolved: [${undecided.join(', ')}] would `
      + 'produce no disposition, which the runner cannot distinguish from permission. Set them '
      + `(${POL.OPEN_CHOICE_KEYS.map((k) => `${k}: ${Object.keys(POL.OPEN_CHOICES[k].values)
        .filter((v) => v !== 'REFUSE_TO_DECIDE').join('|')}`).join(', ')}).`);
  }

  // `domainVersionCount` decides provider_class, and 0 is NOT "unknown" -- it means the domain has
  // no other versions, i.e. `unverified`. Defaulting it silently made this gate assert a candidate
  // fact nobody supplied.
  //
  // (An earlier comment here claimed the producer never builds domain counts and that 0 therefore
  // reproduced the corpus. That was retracted: `writer.py` DOES compute a package-scoped count, and
  // `verified-corporate` is the largest class in the seed's own publisher state. What omits the
  // count is `oracle.candidate_from_row`, the fixture candidate adapter.)
  const countFromPackument = domainVersionCount === FROM_PACKUMENT;
  if (!countFromPackument && (!Number.isInteger(domainVersionCount) || domainVersionCount < 0)) {
    throw new POL.PolicyConfigInvalid(
      `createSeedV3Gate: domainVersionCount must be a non-negative integer or '${FROM_PACKUMENT}'. `
      + 'It decides provider_class and 0 is not "unknown" -- it asserts the domain has no other '
      + `versions. '${FROM_PACKUMENT}' computes the PACKAGE-SCOPED count the writer computes, from `
      + 'the document in hand; a stated integer is the caller taking responsibility for it.');
  }
  return normalised;
}

/**
 * THE evaluation path: one candidate, derived from what the proxy holds, to a policy decision.
 *
 * The gate calls it and `chaingate check` calls it; there is no second path. Its input handling is
 * the gate's, unchanged: a missing manifest and any throw from row, placement,
 * candidate or check are policy refusals; a non-string `publishedAt` is passed as null, NOT refused.
 *
 * Call `validateEvaluationConfig` first (the gate does so at construction).
 *
 * @returns {{decision: object, finding: object|null, placement: object|null}} `finding` and
 *   `placement` are null exactly when the decision is a refusal.
 */
function evaluateCandidate(seed, { config = {}, domainVersionCount, pinOverlay = null } = {}, input = {}) {
  const pkg = input.packageName;
  const version = input.version;
  const manifest = input.rawManifest;

  // The advisory pin FIRST (cft-policy-1.1). It names this exact version and needs neither a manifest, a
  // placement nor a finding, so it is looked up before anything that can fail and carried into every decision below:
  // a refusal can no longer discard it. A lookup that throws is carried as a recorded failure, never as "no pin".
  const looked = POL.lookupPin(seed, pkg, version, pinOverlay);   // since 0.1.6: the pins feed overlay after the seed
  // since 0.1.6: a feed capture pin is compared with this version's registry integrity; the BLOCK stands either way
  const pinCtx = { pin: POL.captureIntegrity(looked.pin, manifest), pinLookupError: looked.error, pinUncovered: looked.uncovered ?? null,
    cacheStale: seed.staleness?.() ?? null };   // since 0.1.6: a seed cache's unheld bucket, and its root's age

  // A missing manifest is an UNUSABLE INPUT, which is policy's question and not this module's.
  // Answering it with a bare SKIP here bypassed policy entirely and let the aggregate permit.
  if (!manifest || typeof manifest !== 'object') {
    return { decision: POL.decide(null, {
      refusal: new Error(`no raw packument manifest supplied for ${pkg}@${version}`),
      config, packageName: pkg, version, ...pinCtx,
    }), finding: null, placement: null };
  }

  let decision;
  let finding = null;
  let place = null;
  try {
    const row = PK.observationFromManifest(version, manifest,
      typeof input.publishedAt === 'string' ? input.publishedAt : null);
    const publishedS = A.publishedSeconds(row.published_at);
    place = resolvePlacement(seed, pkg, version, publishedS,
      { holdingDescription: manifest.description === HOLDING_DESCRIPTION });
    // The candidate's own e-mail is the approver-RESOLVED one, which is what `derive` looks the
    // count up with even though the writer keys the map on the raw address.
    const dvc = resolveDomainVersionCount(domainVersionCount, {
      rawVersions: input.rawVersions,
      candidateEmail: resolvePublisherEmail(row.publisher_email ?? null, row.raw_metadata ?? null),
    });
    const candidate = A.candidateFromRawRow(row, {
      packageName: pkg, lineageId: place.lineage_id, ord: place.ord,
      domainVersionCount: dvc.count,
    });
    finding = seed.check(candidate);
    const staleSeed = staleSeedGap(seed, place, input, publishedS, version);
    // Since 0.1.6 (cft-policy-1.3): the re-tier block, from the registry document in hand. A failure here is no refusal:
    // without a block policy decides as 1.2 did, so the strict rows keep their WARN.
    let retier = null;
    try {
      retier = RT.retierOf({ packageName: pkg, version, finding, placement: place, notEvaluated: POL.notEvaluated(finding, place),
        rawVersions: input.rawVersions, rawTimes: input.rawTimes });
    } catch { retier = null; }
    // The placement travels WITH the finding. Where Channel-A cannot be compared, policy records
    // the gate's own reason rather than the checker's `uncovered_package`, and keeps what does not
    // depend on placement: the DAC trajectory and an exact-version advisory pin.
    decision = POL.decide(finding, { ...pinCtx, config, override: null, placement: place, staleSeed, retier });
  } catch (e) {
    // A refusal from any layer is an UNUSABLE INPUT, and policy decides what that means — this
    // module does not get to turn it into an ALLOW. The pin found above survives it.
    decision = POL.decide(null, {
      refusal: e, config, packageName: pkg, version, ...pinCtx,
    });
    finding = null;
    place = null;
  }
  return { decision, finding, placement: finding ? place : null };
}

/**
 * Build the gate module.
 *
 * @param {object} opts
 *   opts.seed     an open reader Seed (read-only)
 *   opts.config   the operator's policy configuration (see policy.OPEN_CHOICES)
 *   opts.onDecision  optional sink for the full decision, for reporting; the gate still returns
 *                    exactly one GateResult, because that is the shape the gate runner aggregates.
 * @returns {{name: string, evaluate: (input: object) => {gate, result, detail}}}
 */
function createSeedV3Gate({ seed, config = {}, domainVersionCount, onDecision = null, pinOverlay = null } = {}) {
  if (!seed) throw new Error('createSeedV3Gate: seed is required');
  const normalised = validateEvaluationConfig({ config, domainVersionCount });

  function evaluate(input) {
    return resultFrom(evaluateCandidate(seed, { config, domainVersionCount, pinOverlay }, input).decision,
      onDecision);
  }

  /** One GateResult from a decision. Every exit from `evaluate` goes through here, so no path can
   *  skip policy or forget to report the decision. */
  function resultFrom(decision, sink) {
    // The decision exists before the sink sees it. A sink that throws used to escape `evaluate`, and the runner then
    // answered with `onError` -- replacing a computed decision (a pin BLOCK included) with the input rule. The decision
    // stands; the sink's failure is stated beside it.
    let sinkFailure = null;
    if (sink) {
      try { sink(decision); } catch (e) { sinkFailure = e; }
    }
    // `disposition === null` is unreachable: construction refuses a gate with an unresolved policy.
    // Kept as a named refusal rather than an assumption, because silence here means permission.
    if (decision.disposition === null) {
      throw new POL.PolicyConfigInvalid(
        `policy returned no disposition ([${decision.undecided.join(', ')}] unresolved); a gate that `
        + 'enforces must never answer with silence');
    }
    // Name the policy row that DECIDED, not only what it said. `gate_decisions` is read long after
    // the fact, and "recorded advisory ... pins ..." without `seed-v3:known-malicious-pin` beside it
    // leaves a reader guessing which rule fired.
    const bearing = decision.results.filter((x) => x.result === decision.disposition);
    const why = (bearing.length ? bearing : decision.results)
      .map((x) => `${x.gate}: ${x.detail}`).join(' | ');
    // cft-policy-1.2 (since 0.1.4): contributing rows never bear the disposition, so they are shown after the
    // bearing rows -- the detail is what `why --cached` and the store keep. (When nothing bears, `why` already lists them.)
    const also = bearing.length ? decision.results.filter((x) => x.result === POL.NOTE)
      .map((x) => ` | also (contributing): ${x.gate}: ${x.detail}`).join('') : '';
    return {
      gate: SEED_V3_GATE,
      result: decision.disposition,
      // The decision's rows, structured (closed vocabulary), so a reader classifies named / contributing / coverage
      // rows without parsing the detail text.
      rows: decision.results.map((x) => ({ gate: x.gate, result: x.result })),
      // cft-policy-1.3: the re-tier, structured, when a strict row warned before it (a later download reads it)
      ...(decision.retier ? { retier: RT.compact(decision.retier) } : {}),
      // since 0.1.6: which kind of pin decided, when it came from the pins feed (the notice words it)
      ...(decision.pin ? { pin: decision.pin } : {}),
      detail: `${decision.policy_version}: ${why}${also}`
        + (decision.placement ? ` [placement: ${decision.placement}]` : '')
        + (decision.evidence_complete ? '' : ` [evidence incomplete: ${decision.not_evaluated.length}`
          + ' observation(s) NOT_EVALUATED]')
        + (sinkFailure ? ` [decision callback failed: ${sinkFailure && sinkFailure.message}; this decision stands]` : ''),
    };
  }

  /**
   * What a failure of THIS gate means. The runner calls it when `evaluate` throws, when the module
   * returns something malformed, or when the whole observation failed -- the places that used to
   * become a silent SKIP and then an ALLOW, losing a recorded-advisory BLOCK to an unrelated error.
   *
   * It is not the runner's decision and it is not this module's: an unusable input is exactly the
   * case `on_unusable_input` governs, so policy answers it.
   *
   * `identity`: the caller's request-bound `{packageName, version}` when it holds both, and
   * `overridden: true` when an exact-version override exists for them. With an identity the advisory pin for that
   * exact version is looked up in THIS gate's seed -- the one accepted at wiring -- and a pin BLOCKs, as it does on
   * every other unusable-input path. Without one nothing is looked up and nothing is invented. An overridden version
   * is not looked up either, so each failure path treats it exactly as before.
   */
  function onError(err, identity = null) {
    const error = err instanceof Error ? err : new Error(String(err));
    const pkg = identity && identity.packageName;
    const version = identity && identity.version;
    const known = typeof pkg === 'string' && pkg !== '' && typeof version === 'string' && version !== '';
    let looked = { pin: null, error: null, attempted: false };
    let note;
    if (!known) {
      note = 'advisory not consulted: package and version are not known on this path';
    } else if (identity.overridden === true) {
      note = `advisory not consulted on a failure path: an exact-version override exists for ${pkg}@${version}`;
    } else {
      looked = POL.lookupPin(seed, pkg, version, pinOverlay);
      if (looked.error) {
        note = `advisory pin lookup FAILED for ${pkg}@${version} (${looked.error.message}); the input rule decides`;
      } else if (!looked.pin) note = `no recorded advisory pins ${pkg}@${version}`;
    }
    const decision = POL.decide(null, {
      refusal: error, config, pin: looked.pin, pinLookupError: looked.error,
      packageName: known ? pkg : null, version: known ? version : null,
    });
    const pinned = looked.pin ? decision.results.find((x) => x.gate === POL.PIN_GATE) : null;
    // The failure path carries its structured rows too, so a 1.2 failure decision's facts are
    // read from rows, never from the error text.
    return { gate: SEED_V3_GATE, result: decision.disposition, rows: decision.results.map((x) => ({ gate: x.gate, result: x.result })),
      ...(decision.pin ? { pin: decision.pin } : {}),
      detail: `${decision.policy_version}: the seed-v3 path could not run (${error.message})`
        + (pinned ? ` | ${pinned.gate}: ${pinned.detail}` : '') + (note ? ` | ${note}` : '') };
  }

  // The same answer as a plain value, for the case where even onError cannot be consulted. Declared
  // when the gate is WIRED, from the operator's own configuration -- the runner never invents it.
  // `REFUSE_TO_DECIDE` is impossible here: construction refuses it.
  const onErrorResult = { BLOCK: POL.BLOCK, WARN: POL.WARN }[normalised.on_unusable_input];

  return { name: SEED_V3_GATE, evaluate, onError, onErrorResult };
}

export { SEED_V3_GATE, PLACEMENTS, resolvePlacement, placeRl2, tagFamily, PLACEMENT_RULE_VERSION, createSeedV3Gate, evaluateCandidate,
  validateEvaluationConfig, majorOf, isStub, isCalverYear, compareToRecorded,
  resolveDomainVersionCount, domainCountsFor, staleSeedGap, gapIndexFor, SEMVER_RE };
export default { SEED_V3_GATE, PLACEMENTS, resolvePlacement, placeRl2, tagFamily, PLACEMENT_RULE_VERSION, createSeedV3Gate, evaluateCandidate,
  validateEvaluationConfig, majorOf, isStub, isCalverYear, compareToRecorded,
  resolveDomainVersionCount, domainCountsFor, staleSeedGap, gapIndexFor, SEMVER_RE };
