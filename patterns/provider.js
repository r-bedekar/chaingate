// Email domain extraction and 5-class provider classification.
//
// Sub-step 3a of the V2 publisher pattern. See patterns/publisher.js
// GATE CONTRACT addition 1 for the consumption rules (provider is a
// supplementary severity modifier, not a disposition driver) and
// docs/V2_DESIGN.md Section 11 step 2 sub-step 3 for the taxonomy
// rationale.
//
// Taxonomy (5 classes):
//   verified-corporate — non-free, non-privacy domain with >=
//                         MIN_VERIFIED_VERSIONS in this package
//   free-webmail       — domain in FREE_WEBMAIL_DOMAINS
//   privacy            — domain in PRIVACY_PROVIDER_DOMAINS
//   unverified         — non-free, non-privacy domain below the
//                         MIN_VERIFIED_VERSIONS threshold
//   unknown            — no extractable domain (bare-name identity,
//                         malformed identity)
//
// Precedence (first match wins): unknown > privacy > free-webmail >
//   verified-corporate > unverified.
// free-webmail and privacy are inherent-meaning classes; they apply
// regardless of package context. The package-context distinction only
// resolves the corporate/unverified boundary.

import {
  FREE_WEBMAIL_DOMAINS,
  PRIVACY_PROVIDER_DOMAINS,
  MIN_VERIFIED_VERSIONS,
} from '../constants.js';

// Extract the email domain from a raw email string. Returns the domain
// lowercased, or null if the input is not a string, is empty, contains
// no '@', or has nothing after the final '@'.
//
// Signature takes an email directly (not an identity string) because
// the identity key produced by patterns/identity.js is the npm account
// login when present and no longer encodes the email. The raw email is
// threaded separately through patterns/publisher.js::normalizeAndFilter
// onto each row and onto each tenure block, so domain extraction has
// the value it needs without parsing it back out of an opaque key.
export function extractDomain(email) {
  if (typeof email !== 'string' || email.length === 0) return null;
  const at = email.lastIndexOf('@');
  if (at < 0) return null;
  const domain = email.slice(at + 1).trim().toLowerCase();
  return domain.length > 0 ? domain : null;
}

// Classify a domain given the package's domain → version-count map.
// The count map must include ALL versions with that domain across the
// full package history (not just the current block's versions).
export function classifyProvider(domain, domainVersionCounts) {
  if (domain === null) return 'unknown';
  if (PRIVACY_PROVIDER_DOMAINS.has(domain)) return 'privacy';
  if (FREE_WEBMAIL_DOMAINS.has(domain)) return 'free-webmail';
  const count = domainVersionCounts.get(domain) ?? 0;
  if (count >= MIN_VERIFIED_VERSIONS) return 'verified-corporate';
  return 'unverified';
}
