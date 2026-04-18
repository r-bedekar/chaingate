// Minimal in-tree semver parser + comparator. No external dependency.
//
// Scope: enough semver for deterministic ordering of npm package
// versions in pattern extraction. Handles:
//
//   major.minor.patch
//   major.minor.patch-prerelease
//   major.minor.patch-prerelease+build
//
// Not a full semver library — we do not expose ranges, satisfies(), inc(),
// or any of the things ChainGate does not need. parseSemver returns null
// on unparseable input; compareSemver falls back to string comparison in
// that case so the sort remains deterministic even on garbage data.
//
// All math is on integers. No Date, no floats.

const SEMVER_RE = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/;

export function parseSemver(v) {
  if (typeof v !== 'string') return null;
  const m = SEMVER_RE.exec(v.trim());
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    prerelease: m[4] ?? null,
  };
}

// Pre-release precedence per semver §11:
//   - Absent prerelease > present prerelease  (1.0.0 > 1.0.0-alpha)
//   - Dot-separated identifiers compared left-to-right
//   - Numeric identifiers compared numerically
//   - Non-numeric compared lexically (ASCII)
//   - Numeric < non-numeric when the slots are the same kind mismatch
//   - Longer identifier list wins if prior parts are equal
function comparePrerelease(a, b) {
  if (a === null && b === null) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  const aparts = a.split('.');
  const bparts = b.split('.');
  const len = Math.min(aparts.length, bparts.length);
  for (let i = 0; i < len; i += 1) {
    const ai = aparts[i];
    const bi = bparts[i];
    const an = /^\d+$/.test(ai);
    const bn = /^\d+$/.test(bi);
    if (an && bn) {
      const d = Number(ai) - Number(bi);
      if (d !== 0) return d < 0 ? -1 : 1;
    } else if (an) {
      return -1;
    } else if (bn) {
      return 1;
    } else {
      if (ai < bi) return -1;
      if (ai > bi) return 1;
    }
  }
  if (aparts.length !== bparts.length) return aparts.length < bparts.length ? -1 : 1;
  return 0;
}

export function compareSemver(a, b) {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) {
    // Fallback: string comparison. Deterministic on unparseable input.
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
  }
  if (pa.major !== pb.major) return pa.major < pb.major ? -1 : 1;
  if (pa.minor !== pb.minor) return pa.minor < pb.minor ? -1 : 1;
  if (pa.patch !== pb.patch) return pa.patch < pb.patch ? -1 : 1;
  return comparePrerelease(pa.prerelease, pb.prerelease);
}
