// Gate 1: content-hash (BLOCK)
//
// Detects bytes-under-same-version-string replacement. Answers exactly
// one question: "has the tarball under (pkg, version) that we already
// observed been replaced?"
//
// Design priority: ZERO false positives by construction. Every BLOCK
// must be a true positive. When the incoming/baseline data is asymmetric
// or has gaps, we SKIP instead of BLOCK — a broken npm metadata response
// must never DoS legitimate installs.
//
// Spec: docs/P5.md §6 lines 395-419. This implementation is slightly
// stricter than the pseudocode: the pseudocode reads both fields with an
// OR, but that would BLOCK if one field is null on either side (a data
// gap, not an attack). We break the comparison into:
//   1. baseline null            → SKIP (first-seen)
//   2. baseline has NO hashes   → SKIP (baseline data gap)
//   3. incoming has NO hashes   → SKIP (incoming data gap)
//   4. both have integrity      → compare integrity; trust integrity match
//                                 even if shasum drifted
//   5. both have shasum only    → compare shasum
//   6. asymmetric               → SKIP (differing hash algorithms)

const HASH_DISPLAY_LEN = 16;

function truncHash(h) {
  if (typeof h !== 'string' || !h) return '(none)';
  return h.length > HASH_DISPLAY_LEN ? `${h.slice(0, HASH_DISPLAY_LEN)}…` : h;
}

function result(r, detail) {
  return { gate: 'content-hash', result: r, detail };
}

export default {
  name: 'content-hash',
  evaluate(input) {
    const baseline = input?.baseline;
    const incoming = input?.incoming;
    if (!baseline) return result('SKIP', 'first-seen: no baseline to compare');

    const bInteg = baseline.integrity_hash ?? null;
    const bSha = baseline.content_hash ?? null;
    const iInteg = incoming?.integrity_hash ?? null;
    const iSha = incoming?.content_hash ?? null;

    if (bInteg == null && bSha == null) {
      return result('SKIP', 'baseline has no hash fields — cannot verify');
    }
    if (iInteg == null && iSha == null) {
      return result('SKIP', 'incoming packument missing hash fields');
    }

    // Primary path: both sides expose integrity (sha512 RFC6920).
    if (bInteg != null && iInteg != null) {
      if (bInteg === iInteg) {
        if (bSha != null && iSha != null && bSha !== iSha) {
          return result(
            'ALLOW',
            `integrity matches baseline (sha1 re-shasum: ${truncHash(bSha)} → ${truncHash(iSha)})`,
          );
        }
        return result('ALLOW', 'integrity hash matches baseline');
      }
      return result(
        'BLOCK',
        `integrity hash differs from baseline: ${truncHash(bInteg)} → ${truncHash(iInteg)}`,
      );
    }

    // Fallback path: both sides expose only shasum (sha1).
    if (bSha != null && iSha != null) {
      if (bSha === iSha) return result('ALLOW', 'shasum matches baseline');
      return result(
        'BLOCK',
        `shasum differs from baseline: ${truncHash(bSha)} → ${truncHash(iSha)}`,
      );
    }

    // Asymmetric: baseline has one algorithm, incoming the other.
    return result('SKIP', 'cannot compare: differing hash algorithms between baseline and incoming');
  },
};
