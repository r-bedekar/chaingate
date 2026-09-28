// CFT-05 — the npm PACKUMENT adapter: registry JSON -> explicit observation rows.
//
// WHY THIS IS A SEPARATE LAYER. `adapter.js` consumes a producer EXTRACT row: a flat record whose
// fields have already been chosen, named and normalised by the collector. A packument is none of
// those things. It is the registry's own document — `versions{}` keyed by version string, a separate
// `time{}` map, `dist{}` nested inside each manifest, `_npmUser` rather than publisher_name/email,
// `scripts{}` rather than three columns, a `repository` that is a string in some packages and an
// object in others. Passing the extract-row vectors says nothing about any of that, so this layer
// has its own ground truth: the PRODUCER's own packument parser
// (`collector/sources/npm.py::_parse_single_version`, plus the `_nodeVersion` rule from
// `tools/ops/backfill/backfill_npm_publisher_fingerprint.py`) run over REAL packuments fetched from
// registry.npmjs.org. See make_packument_vectors.py.
//
// The output is an OBSERVATION ROW in the shape `adapter.candidateFromRawRow` accepts, and it obeys
// the same rule: state every observation. Explicit `null` says "observed absent"; nothing is omitted
// and nothing is defaulted. Where the packument does not permit a faithful observation at all — a
// version with no manifest, a manifest whose version disagrees with its key — this refuses by name
// rather than emitting a row that looks like evidence.

import A from './adapter.js';
import { pyStrip, emailDomain } from './normalize.js';

const PACKUMENT_ADAPTER_VERSION = 'cft-packument-adapter-1.0';

class PackumentRejected extends Error {
  constructor(reasons) {
    super(reasons.join('; ')); this.name = 'PackumentRejected'; this.reasons = reasons;
  }
}

const HOOKS = ['install', 'preinstall', 'postinstall'];
const isStr = (v) => typeof v === 'string';
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * Python's `s[:n]`, which counts CODE POINTS. `String.prototype.slice` counts UTF-16 code units, so
 * for any string carrying an astral character (an emoji, most CJK extensions, many historic scripts)
 * the two truncate at different places -- and every cap in this adapter feeds a value that is either
 * hashed or compared. A 64-cap on a gitHead of emoji kept 32 of them in Python and 32 halves of
 * surrogate pairs in JavaScript.
 */
function pyTruncate(value, limit) {
  const cps = Array.from(value);
  return cps.length <= limit ? value : cps.slice(0, limit).join('');
}

/** Python `_trim(value, limit)`: non-strings are null; str.strip(); empty -> null; then truncate. */
function trim(value, limit) {
  if (!isStr(value)) return null;
  const v = pyStrip(value);
  return v ? pyTruncate(v, limit) : null;
}

/**
 * Python's truthiness, which is NOT JavaScript's on values a registry really does store.
 *
 * `Boolean({})` and `Boolean([])` are TRUE in JavaScript and FALSE in Python. The producer writes
 * `bool(attestations)` and `any(scripts.get(k) ...)`, so an empty attestations object made this
 * adapter report `provenance_present: true` where the producer reports false — a detection WITNESS
 * firing on the opposite reading of the same document. Found by producer-generated adversarial
 * manifests, not by a real package.
 */
function pyTruthy(v) {
  if (v === undefined || v === null || v === false) return false;
  if (v === true) return true;
  if (isStr(v)) return v.length > 0;
  if (typeof v === 'number') return v !== 0;                 // Python: 0 and 0.0 are falsy
  if (Array.isArray(v)) return v.length > 0;                 // Python: [] is falsy
  if (isObj(v)) return Object.keys(v).length > 0;            // Python: {} is falsy
  return Boolean(v);
}

/** `extract_install_scripts` (Q1/Q4 lock), including the case where the two halves disagree: a
 *  truthy NON-STRING hook (a list, an object) makes has_install_scripts true while every typed
 *  column stays null. Reproduced rather than tidied up, because the producer's rows carry it. */
function installScripts(manifest) {
  const scripts = isObj(manifest) ? manifest.scripts : null;
  if (!isObj(scripts)) return { has: false, install: null, preinstall: null, postinstall: null };
  const typed = (k) => (isStr(scripts[k]) ? scripts[k] : null);
  return {
    has: HOOKS.some((k) => pyTruthy(scripts[k])),
    install: typed('install'), preinstall: typed('preinstall'), postinstall: typed('postinstall'),
  };
}

/** `_normalize_maintainers`: (name, email) pairs only, each capped at 200; empty list -> null. */
function maintainers(value) {
  if (!Array.isArray(value) || value.length === 0) return null;
  const out = [];
  for (const m of value) {
    if (!isObj(m)) continue;
    const name = isStr(m.name) ? m.name : null;
    const email = isStr(m.email) ? m.email : null;
    if (!name && !email) continue;
    const entry = {};
    if (name) entry.name = pyTruncate(name, 200);
    if (email) entry.email = pyTruncate(email, 200);
    out.push(entry);
  }
  return out.length ? out : null;
}

/** `_normalize_tool`: "npm@" + _npmVersion.strip()[:80]; absent or blank -> null. */
function publisherTool(npmVersion) {
  if (!isStr(npmVersion)) return null;
  const v = pyStrip(npmVersion);
  return v ? `npm@${pyTruncate(v, 80)}` : null;
}

/** `_extract_repo_url`: a string is used directly, an object's `url`, anything else is null. */
function repoUrl(repository) {
  if (repository === null || repository === undefined) return null;
  if (isStr(repository)) return pyTruncate(repository, 500);
  if (isObj(repository)) return isStr(repository.url) ? pyTruncate(repository.url, 500) : null;
  return null;
}

/**
 * One observation row from one packument manifest.
 *
 * @param {string} versionStr  the key in `versions{}` — the registry's identity for this release
 * @param {object} manifest    the version object, verbatim
 * @param {string|null} publishedAt  `time[versionStr]`, or null when the packument has no entry
 */
function observationFromManifest(versionStr, manifest, publishedAt) {
  const reasons = [];
  if (!isStr(versionStr) || !versionStr) reasons.push('version key is not a non-empty string');
  if (!isObj(manifest)) reasons.push(`versions[${JSON.stringify(versionStr)}] is not an object`);
  // A manifest whose own `version` disagrees with its key is not an observation this adapter can
  // make: the two identities would index different releases and nothing here can say which is right.
  if (isObj(manifest) && isStr(manifest.version) && manifest.version !== versionStr) {
    reasons.push(`versions[${JSON.stringify(versionStr)}].version is `
      + `${JSON.stringify(manifest.version)}; the key and the manifest name different releases`);
  }
  if (publishedAt !== null && publishedAt !== undefined && !isStr(publishedAt)) {
    reasons.push(`time[${JSON.stringify(versionStr)}] is not a string`);
  }
  // The producer reads `version_obj.get("_npmUser") or {}` and then calls `.get()` on the result, so
  // a non-object `_npmUser` makes its PARSER fail: no row exists for that release at all. Guarding
  // it into `{}` here would have manufactured "no publisher was recorded" out of a document the
  // producer cannot read.
  const npmUserRaw = isObj(manifest) ? manifest._npmUser : undefined;   // read once
  if (npmUserRaw !== undefined && npmUserRaw !== null && !isObj(npmUserRaw)) {
    reasons.push(`_npmUser is ${Array.isArray(npmUserRaw) ? 'an array' : typeof npmUserRaw}, `
      + 'not an object: the producer cannot read a publisher from this manifest');
  }
  if (reasons.length) throw new PackumentRejected(reasons);

  const dist = isObj(manifest.dist) ? manifest.dist : {};
  const npmUser = isObj(npmUserRaw) ? npmUserRaw : {};
  const attestations = dist.attestations;
  const scripts = installScripts(manifest);

  // EVERY field, explicitly. `null` is an observation ("the packument does not carry this"); the
  // candidate adapter refuses omission, and that refusal is the point.
  // RAW pass-through wherever the producer applies no type guard of its own. `_npmUser.name` is read
  // as `npm_user.get("name")` with no isinstance check, so a non-string reaches the row — where the
  // producer then FAILS deriving a candidate from it. Nulling it here would have replaced "a
  // publisher name was observed and is unusable" with "no publisher name was observed", which is a
  // different claim; the candidate boundary refuses it by name instead.
  const size = dist.unpackedSize;
  return {
    version: versionStr,
    published_at: publishedAt === undefined ? null : publishedAt,
    publisher_name: npmUser.name === undefined ? null : npmUser.name,
    publisher_email: npmUser.email === undefined ? null : npmUser.email,
    publisher_tool: publisherTool(manifest._npmVersion),
    // `published_with_node_version` is backfilled from raw_metadata->>'_nodeVersion' and is NULL
    // unless that value is a JSON string: no strip, no truncation.
    published_with_node_version: isStr(manifest._nodeVersion) ? manifest._nodeVersion : null,
    maintainers: maintainers(manifest.maintainers),
    // `bool(attestations)` / `"oidc" if attestations else "unknown"` — PYTHON truthiness, so an
    // empty object or empty list is ABSENT provenance, not present.
    provenance_present: pyTruthy(attestations),
    publish_method: pyTruthy(attestations) ? 'oidc' : 'unknown',
    has_install_scripts: scripts.has,
    install_script: scripts.install,
    preinstall_script: scripts.preinstall,
    postinstall_script: scripts.postinstall,
    git_head: trim(manifest.gitHead, 64),
    source_repo_url: repoUrl(manifest.repository),
    // stored RAW: `dist.get("unpackedSize")`. A float or a string is a size that cannot be used, and
    // that is not the same fact as no size having been recorded — the candidate boundary refuses it.
    package_size_bytes: size === undefined ? null : size,
    // The producer stores the whole manifest as raw_metadata, and the publisher witness unfolds a
    // staged-publish `approver` from it. Passing the manifest keeps that chokepoint working the day
    // npm exposes the field; today no packument carries one, so this resolves to _npmUser's e-mail.
    raw_metadata: manifest,
  };
}

/**
 * `domain -> number of versions OF THIS PACKAGE published from that e-mail domain`.
 *
 * This is the writer's own computation, mirrored (tools/seedgen/writer.py, "domain -> version count
 * as-of cutoff (provider classification, package-context)"):
 *
 *     dcount = defaultdict(int)
 *     for r in rows:                                   # EVERY version of this package, including
 *         d = W.email_domain(r.get("publisher_email")) # stubs and ones with no publication time
 *         if d: dcount[d] += 1
 *
 * Three details that matter and are easy to get wrong:
 *   * it is PACKAGE-SCOPED, not registry-wide -- there is no global observation here to invent;
 *   * the map is keyed on the RAW `publisher_email`, while `derive` looks it up with the
 *     approver-RESOLVED e-mail, so the two can legitimately miss each other;
 *   * every version counts, including ones lineage grouping later excludes.
 *
 * A packument carries exactly this population for the package in hand, so a live consumer can
 * compute it rather than be handed a number. What it CANNOT reproduce is the seed's "as-of cutoff"
 * population: a packument is current, so releases published after the cutoff are counted here and
 * were not counted there. Stated, because it is a real difference in the value.
 */
function domainVersionCounts(versions) {
  const counts = new Map();
  for (const manifest of Object.values(isObj(versions) ? versions : {})) {
    if (!isObj(manifest)) continue;
    // read once: one property access per manifest, so "visits" means what it says
    const raw = manifest._npmUser;
    const npmUser = isObj(raw) ? raw : {};
    const d = emailDomain(npmUser.email === undefined ? null : npmUser.email);
    if (d) counts.set(d, (counts.get(d) || 0) + 1);
  }
  return counts;
}

/**
 * Every observation row a packument supports, in the registry's own `versions{}` order.
 *
 * @returns {{package_name: string, rows: object[], refused: object[], versions_seen: number}}
 *   `refused` names each version the packument did not permit an observation for, with the reason —
 *   a version is never silently dropped, because a missing row is a release nobody looked at.
 */
function observationsFromPackument(packument) {
  if (!isObj(packument)) throw new PackumentRejected(['packument is not an object']);
  const name = packument.name;
  if (!isStr(name) || !name) throw new PackumentRejected(['packument has no name']);
  const versions = packument.versions;
  if (!isObj(versions)) throw new PackumentRejected([`${name}: packument has no versions object`]);
  const time = isObj(packument.time) ? packument.time : {};

  const rows = []; const refused = [];
  for (const [versionStr, manifest] of Object.entries(versions)) {
    try {
      rows.push(observationFromManifest(versionStr, manifest,
        Object.prototype.hasOwnProperty.call(time, versionStr) ? time[versionStr] : null));
    } catch (e) {
      if (!(e instanceof PackumentRejected)) throw e;
      refused.push({ version: versionStr, reasons: e.reasons });
    }
  }
  return { package_name: name, rows, refused, versions_seen: Object.keys(versions).length };
}

/**
 * The whole supported path for one packument: registry JSON -> observation row -> candidate ->
 * finding. Policy is applied by the caller, because this module must not decide anything.
 *
 * @param {object} packument
 * @param {object} seed    an open reader Seed
 * @param {object} opts    { lineageOf }  resolves (package, version) -> {lineage_id, ord} or null
 */
function findingsFromPackument(packument, seed, opts = {}) {
  const { lineageOf = () => null, domainVersionCount = 0 } = opts;
  const { package_name: pkg, rows, refused, versions_seen: seen } = observationsFromPackument(packument);
  const out = [];
  for (const row of rows) {
    const place = lineageOf(pkg, row.version) || { lineage_id: null, ord: null };
    let candidate;
    try {
      candidate = A.candidateFromRawRow(row, {
        packageName: pkg, lineageId: place.lineage_id, ord: place.ord, domainVersionCount,
      });
    } catch (e) {
      refused.push({ version: row.version, reasons: e.reasons || [e.message] });
      continue;
    }
    out.push({ version: row.version, row, candidate, finding: seed.check(candidate) });
  }
  return { package_name: pkg, results: out, refused, versions_seen: seen };
}

export {
  PACKUMENT_ADAPTER_VERSION, PackumentRejected, observationFromManifest, observationsFromPackument,
  findingsFromPackument, installScripts, maintainers, publisherTool, repoUrl, trim, pyTruthy,
  pyTruncate, domainVersionCounts,
};
export default {
  PACKUMENT_ADAPTER_VERSION, PackumentRejected, observationFromManifest, observationsFromPackument,
  findingsFromPackument, installScripts, maintainers, publisherTool, repoUrl, trim, pyTruthy,
  pyTruncate, domainVersionCounts,
};
