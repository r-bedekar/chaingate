// Gate 4: provenance-continuity (WARN)
//
// Detects loss of OIDC attestation in a package that previously used it.
// This gate is a ChainGate differentiator: no mainstream supply-chain
// tool flags *regression* of Sigstore attestation. Socket/Datadog/Snyk
// all check "is provenance present NOW"; only ChainGate asks "did it
// USED to be here and isn't anymore".
//
// Attack model:
//   1. Maintainer (or attacker-controlled account) has been publishing
//      with `npm publish --provenance` for months, producing Sigstore
//      attestations stored in dist.attestations.
//   2. Attacker gains account control. The attacker's local machine
//      isn't running in the CI environment that owned the OIDC token,
//      so their release goes out WITHOUT --provenance.
//   3. Every prior version had attestation; this one doesn't. That's
//      the signal.
//
// Spec: docs/P5.md §6 lines 457-471.
//
// Zero-FP posture: SKIP whenever we can't prove there was a loss.
//   - history.length < 2 → SKIP (need at least one prior observation
//     besides the incoming one to establish a baseline)
//   - no prior version ever had provenance → SKIP (package never used
//     Trusted Publishing; this is "normal for this package")
//   - incoming has provenance → ALLOW
//   - otherwise → WARN with a count of how many prior versions did
//
// We count rather than binary-check so the detail string is
// investigation-ready: "OIDC provenance missing (4 of last 10 versions
// had it)" tells the reader exactly how abnormal this is.

function result(r, detail) {
  return { gate: 'provenance-continuity', result: r, detail };
}

function hasProvenance(v) {
  // P5.1 stores provenance_present as 0/1 (SQLite boolean coercion).
  // Packument parser writes Boolean(attestations) which normalizes to
  // true/false in JS. Accept both shapes.
  if (v == null) return false;
  const p = v.provenance_present;
  return p === 1 || p === true;
}

export default {
  name: 'provenance-continuity',
  evaluate(input) {
    const history = Array.isArray(input?.history) ? input.history : [];
    const incoming = input?.incoming ?? {};
    const currentVersion = input?.version;

    const prior = history.filter((h) => h && h.version !== currentVersion);
    if (prior.length === 0) {
      return result('SKIP', 'no prior versions to compare provenance against');
    }

    const priorWithProvenance = prior.filter(hasProvenance);
    if (priorWithProvenance.length === 0) {
      return result('SKIP', 'package has never used OIDC provenance — nothing to regress from');
    }

    if (hasProvenance(incoming)) {
      return result(
        'ALLOW',
        `OIDC provenance present (continuous with ${priorWithProvenance.length}/${prior.length} prior versions)`,
      );
    }

    return result(
      'WARN',
      `OIDC provenance missing (${priorWithProvenance.length} of last ${prior.length} versions had it, latest: ${priorWithProvenance[0].version})`,
    );
  },
};
