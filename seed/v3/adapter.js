// END-TO-END: a raw registry row (packument version) -> a validated candidate -> a finding.
//
// This is the path a live consumer actually walks. The fixture pack starts one step later — its
// candidate fields are already normalised — so this module is what makes the consumer usable against
// the registry rather than only against a pack.
//
// It mirrors `tools/seedgen/oracle.candidate_from_row`, which derives a candidate from the producer's
// raw row via `witness.derive`. Every field it produces is a FACT ABOUT A REAL RELEASE, so anything it
// cannot derive faithfully is refused by name rather than defaulted: a missing `has_install_scripts`
// is not `false`, it is unknown, and `false` would assert that the release has no install script.

import {
  normEmail, identityDigest, tupleDigest, maintainersDigest, installBodyDigest,
  emailDomain, providerClass,
} from './normalize.js';
import { pyStrip } from './normalize.js';
import { repoDigest, parsePublisherTool, resolvePublisherEmail } from './normalize-extra.js';
import { candidateFromMapping, CandidateRejected } from './reader.js';

// Raw fields this adapter reads. An unknown key is refused: a packument field this adapter does not
// understand may be exactly the one that carries the evidence, and silently ignoring it would produce
// a confident finding from incomplete input.
const RAW_FIELDS = [
  'version', 'published_at', 'publisher_name', 'publisher_email', 'publisher_tool',
  'published_with_node_version', 'maintainers', 'provenance_present', 'publish_method',
  'has_install_scripts', 'install_script', 'preinstall_script', 'postinstall_script',
  'git_head', 'source_repo_url', 'package_size_bytes', 'raw_metadata',
];
// ONE rule, rather than a list of special cases: state every observation. Explicit `null` is how a
// caller says "observed absent"; OMISSION is not an observation at all and is refused.
//
// The rule exists because omission does not degrade uniformly. Some fields would fall back to an
// honest "incomparable" (a missing publisher_email yields a null digest, which neither breaks nor
// clears), but others would assert something false: an omitted `git_head` became `head_present:
// false`, which is the gitHead-disappearance witness firing on an observation nobody made, and an
// omitted `maintainers` became an empty digest, which FIRES against a non-empty predecessor. Callers
// should not have to know which is which.
//
// `raw_metadata` is the one exception: it is the staged-publish approver envelope, and its absence is
// the ordinary case rather than an unobserved fact.
const REQUIRED_RAW = RAW_FIELDS.filter((f) => f !== 'raw_metadata');

/** Python truthiness, for the `x or ""` coercions the producer relies on. `{}` and `[]` are FALSE
 *  in Python and true in JavaScript. Kept local: packument.js exports the same rule for its own use
 *  and this module must not import it (packument.js imports THIS one). */
function pyTruthyValue(v) {
  if (v === undefined || v === null || v === false) return false;
  if (v === true) return true;
  if (typeof v === 'string') return v.length > 0;
  if (typeof v === 'number') return v !== 0;
  if (Array.isArray(v)) return v.length > 0;
  if (typeof v === 'object') return Object.keys(v).length > 0;
  return Boolean(v);
}

class RawRowRejected extends Error {
  constructor(reasons) { super(reasons.join('; ')); this.name = 'RawRowRejected'; this.reasons = reasons; }
}

/** Seconds since the epoch from an ISO-8601 string, a Date, or a number. null stays null. */
// Date.parse rolls impossible calendar dates forward — '2026-02-30' silently becomes 2026-03-02,
// which MOVES a candidate within package history and changes which versions count as strictly prior.
// Python's datetime.fromisoformat raises on it, so this does too: a round-trip check on the parsed
// components is the difference between rejecting a bad row and quietly re-dating a release.
const ISO_RE = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$/;

function publishedSeconds(v) {
  if (v === null || v === undefined) return null;
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new RawRowRejected([`published_at is not finite: ${v}`]);
    if (!Number.isSafeInteger(Math.floor(v))) {
      throw new RawRowRejected([`published_at ${v} is outside the exactly-representable range`]);
    }
    return Math.floor(v);
  }
  if (v instanceof Date) {
    const t = v.getTime();
    if (Number.isNaN(t)) throw new RawRowRejected(['published_at is an invalid Date']);
    return Math.floor(t / 1000);
  }
  if (typeof v !== 'string') {
    throw new RawRowRejected([`published_at has an unsupported type: ${typeof v}`]);
  }
  const m = ISO_RE.exec(v.trim());
  if (!m) {
    throw new RawRowRejected([`published_at is not an ISO-8601 timestamp: ${JSON.stringify(v)}`]);
  }
  const [, Y, Mo, D, H, Mi, S, , zone] = m;
  const y = Number(Y); const mo = Number(Mo); const d = Number(D);
  const h = Number(H); const mi = Number(Mi); const sec = Number(S);
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || sec > 60) {
    throw new RawRowRejected([`published_at has an out-of-range component: ${JSON.stringify(v)}`]);
  }
  // the round-trip is what catches 2026-02-30 and 2026-04-31
  const utc = Date.UTC(y, mo - 1, d, h, mi, Math.min(sec, 59));
  const back = new Date(utc);
  if (back.getUTCFullYear() !== y || back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d) {
    throw new RawRowRejected([
      `published_at is not a real calendar date: ${JSON.stringify(v)} `
      + `(Date.parse would silently move it to ${back.toISOString().slice(0, 10)})`]);
  }
  let offsetSec = 0;
  if (zone && zone !== 'Z') {
    const zm = /^([+-])(\d{2}):?(\d{2})$/.exec(zone);
    offsetSec = (zm[1] === '-' ? 1 : -1) * (Number(zm[2]) * 3600 + Number(zm[3]) * 60);
  }
  return Math.floor(utc / 1000) + offsetSec + (sec === 60 ? 1 : 0);
}

/**
 * Derive a candidate from a raw registry row.
 *
 * `domainVersionCount` is the number of versions of THIS package published from the candidate's
 * e-mail domain, which the producer computes package-wide before deriving. It decides only
 * `provider_class` (verified-corporate vs unverified) and a consumer that cannot compute it must say
 * so rather than pass 0 — 0 silently means "unverified".
 */
function candidateFromRawRow(row, { packageName, lineageId = null, ord = null, domainVersionCount } = {}) {
  const problems = [];
  if (row === null || typeof row !== 'object' || Array.isArray(row)) {
    throw new RawRowRejected(['raw row must be an object']);
  }
  if (typeof packageName !== 'string' || !packageName) problems.push('packageName is required');
  const unknown = Object.keys(row).filter((k) => !RAW_FIELDS.includes(k)).sort();
  if (unknown.length) {
    problems.push(`unknown raw fields (this adapter would ignore evidence it does not understand): ${unknown.join(', ')}`);
  }
  for (const k of REQUIRED_RAW) {
    if (!(k in row)) problems.push(`${k} is required: it is a fact about the release, and a default would assert one`);
  }
  if (!Number.isInteger(domainVersionCount) || domainVersionCount < 0) {
    problems.push('domainVersionCount must be a non-negative integer (it decides provider_class; '
      + '0 is not "unknown", it means the domain has no other versions)');
  }
  for (const k of ['has_install_scripts', 'provenance_present']) {
    if (k in row && typeof row[k] !== 'boolean') {
      problems.push(`${k} must be a boolean stating what was observed, got ${JSON.stringify(row[k])}`);
    }
  }
  // The publisher fields are the two the producer calls `.strip()` on with no isinstance guard, via
  // `(publisher_name or "").strip()` and `norm_email(publisher_email or "")`. A TRUTHY non-string
  // therefore makes the producer FAIL to derive a candidate, while a FALSY one it coerces to "".
  // JavaScript would have quietly normalised both to '' and produced a candidate the producer could
  // not, so the refusal is placed exactly where the producer's is.
  for (const k of ['publisher_name', 'publisher_email']) {
    const v = row[k];
    if (v !== null && v !== undefined && typeof v !== 'string' && pyTruthyValue(v)) {
      problems.push(`${k} must be a string or null; ${JSON.stringify(v)} is a value the producer `
        + 'cannot derive a candidate from');
    }
  }
  if (problems.length) throw new RawRowRejected(problems);

  const rawMeta = row.raw_metadata ?? null;
  const email = resolvePublisherEmail(row.publisher_email ?? null, rawMeta);
  const [toolName, toolKey] = parsePublisherTool(row.publisher_tool ?? null);
  const [maintDigest] = maintainersDigest(row.maintainers ?? null);
  const [, bodyDigest] = installBodyDigest(row.install_script, row.preinstall_script, row.postinstall_script);
  const head = row.git_head;

  const mapping = {
    package_name: packageName,
    version: row.version,
    published_s: publishedSeconds(row.published_at),
    lineage_id: lineageId,
    ord,
    identity_digest: identityDigest(email),
    tuple_digest: tupleDigest(row.publisher_name ?? null, email),
    maint_digest: maintDigest,
    tool_name: toolName,
    tool_key: toolKey,
    provenance_present: Boolean(row.provenance_present),
    publish_method: row.publish_method ?? '',
    has_scripts: Boolean(row.has_install_scripts),
    body_digest: bodyDigest,
    // `bool(gh) and str(gh).strip() != ""` — Python's strip, whose whitespace set is not JavaScript's:
    // a gitHead of U+0085 is absent to Python and present to trim(), and vice versa for U+FEFF.
    head_present: Boolean(head) && pyStrip(String(head)) !== '',
    repo_digest: repoDigest(row.source_repo_url ?? null),
    size_bytes: row.package_size_bytes ?? null,
    provider_class: providerClass(emailDomain(email), domainVersionCount),
  };
  // The same boundary every other entry point uses — the adapter gets no exemption from it.
  return candidateFromMapping(mapping);
}

/** raw row -> candidate -> finding, in one call, against an opened seed. */
function evaluateRawRow(seed, row, opts) {
  return seed.check(candidateFromRawRow(row, opts));
}

export {
  RAW_FIELDS, REQUIRED_RAW, RawRowRejected, publishedSeconds, candidateFromRawRow, evaluateRawRow,
  CandidateRejected, pyTruthyValue,
};

export default { RAW_FIELDS, REQUIRED_RAW, RawRowRejected, publishedSeconds,
  candidateFromRawRow, evaluateRawRow, CandidateRejected, pyTruthyValue
};