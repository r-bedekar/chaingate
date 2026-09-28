// The remaining registry-to-candidate normalisation paths: repository URL canonicalisation, the
// publisher tool key, and the staged-publish approver unfold. Mirrors collector/witness_norm.py and
// collector/drift_cooccurrence.resolve_publisher_email, and is exercised by producer-generated
// vectors rather than by reasoning about the regexes.
//
// These are separated from normalize.js only to keep each file readable; both are part of one adapter
// and index.js re-exports them together.

import { sha256Hex, domainDigest, normEmail, pyStrip, pyLower } from './normalize.js';

// --- repository URL --------------------------------------------------------------------------------
const REPO_SCHEMES = ['https://', 'http://', 'git://', 'ssh://', 'ftp://'];

/**
 * Canonicalise a declared source_repo_url to `host/owner/repo`, or null when it is not parseable.
 * An unparseable URL is NEVER a guessed key: null means incomparable, which neither breaks nor clears.
 *
 * The producer's operation is `source_repo_url.strip().lower()` — Python's strip and Python's
 * lower, which is why this does NOT use trim()/toLowerCase(). Both disagree: JS trim() removes
 * U+FEFF and keeps U+0085 where str.strip() does the opposite, so a URL carrying either produced a
 * DIFFERENT canonical key and therefore a different repo_digest; and str.lower() is contextual
 * around sigma, which a URL path segment can carry.
 */
function canonicalRepoUrl(sourceRepoUrl) {
  if (sourceRepoUrl === null || sourceRepoUrl === undefined) return null;
  if (typeof sourceRepoUrl !== 'string') return null;
  let t = pyLower(pyStrip(sourceRepoUrl));
  if (!t) return null;
  if (t.startsWith('git+')) t = t.slice(4);
  for (const scheme of REPO_SCHEMES) {
    if (t.startsWith(scheme)) { t = t.slice(scheme.length); break; }
  }
  // strip a leading 'user@' authority, but only when '@' precedes the path
  const firstSeg = t.split('/', 1)[0];
  if (firstSeg.includes('@')) t = t.slice(t.indexOf('@') + 1);
  const m = /^([^/:]+)([/:])(.*)$/.exec(t);
  if (m === null) return null;
  const host = m[1];
  let path = m[3];
  if (!host.includes('.')) return null;                 // require a dotted host
  path = path.split(/[?#]/, 1)[0];                      // drop query / fragment
  const segments = path.split('/').filter(Boolean);
  if (!segments.length) return null;
  let owner = segments[0];
  let repo = segments.length > 1 ? segments[1] : '';
  if (repo.endsWith('.git')) repo = repo.slice(0, -4);
  if (owner.endsWith('.git')) owner = owner.slice(0, -4);
  if (!owner) return null;
  return repo ? `${host}/${owner}/${repo}` : `${host}/${owner}`;
}

/** Unkeyed digest over the canonical repository URL; the git witness needs equality only. */
function repoDigest(sourceRepoUrl) {
  const canon = canonicalRepoUrl(sourceRepoUrl);
  return canon ? domainDigest('repo', canon) : null;
}

// --- publisher tool --------------------------------------------------------------------------------
// ^([^@]+)@?v?(\d+)?\.?(\d+)?\.?(\d+)?  — the trailing platform/arch token is discarded by the anchor.
const TOOL_RE = /^([^@]+)@?v?(\d+)?\.?(\d+)?\.?(\d+)?/;

/**
 * "npm@10.2.3" -> ["npm", 10*1e6 + 2*1e3 + 3]. Unparseable or empty -> ["", 0], which the publisher
 * witness reads as INCOMPARABLE: break_tool is guarded on a non-empty tool name, so an empty name
 * yields neither a break nor a clear.
 */
function parsePublisherTool(publisherTool) {
  if (!publisherTool) return ['', 0];
  const m = TOOL_RE.exec(publisherTool);
  if (m === null) return ['', 0];
  const name = m[1] || '';
  const maj = Number(m[2] || 0);
  const min = Number(m[3] || 0);
  const pat = Number(m[4] || 0);
  return [name, maj * 1e6 + min * 1e3 + pat];
}

// --- staged-publish approver unfold -----------------------------------------------------------------
const isPlain = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * Return the ORIGINAL publisher's e-mail, unfolding npm staged publish where `_npmUser` is the
 * APPROVER rather than the human publisher. Dormant against today's registry (npm exposes no
 * approver/publisher distinction), so absence returns publisher_email unchanged — but the publisher
 * witness calls this rather than reading publisher_email directly, so it is the single chokepoint.
 */
function resolvePublisherEmail(publisherEmail, rawMetadata) {
  if (isPlain(rawMetadata)) {
    const approver = rawMetadata.approver;
    if (isPlain(approver)) {
      let orig = approver.publisher_email || approver.requested_by;
      if (!orig) {
        const pub = approver.publisher;
        if (isPlain(pub)) orig = pub.email;
      }
      if (typeof orig === 'string' && orig) return orig;
    }
  }
  return publisherEmail || '';
}

/** identity/tuple digests that honour the approver unfold. */
function identityDigestOf(publisherEmail, rawMetadata = null) {
  const e = normEmail(resolvePublisherEmail(publisherEmail, rawMetadata));
  return e ? domainDigest('email', e) : null;
}

export {
  REPO_SCHEMES, canonicalRepoUrl, repoDigest, TOOL_RE, parsePublisherTool,
  resolvePublisherEmail, identityDigestOf, sha256Hex,
};

export default { REPO_SCHEMES, canonicalRepoUrl, repoDigest, TOOL_RE, parsePublisherTool,
  resolvePublisherEmail, identityDigestOf, sha256Hex
};