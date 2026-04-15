// Gate 5: release-age (WARN)
//
// Configurable cooldown on freshly-published versions. Motivated by
// compromise-then-detection lag: an attacker who publishes a malicious
// version has a window before advisories catch up. A cooldown delays
// adoption by that window.
//
// Spec: docs/P5.md §6 lines 473-490. This gate is commoditized by
// npm 11.10+'s native `min-release-age` config. We keep it because:
//   1. Works on Node 16-22 (min-release-age is Node 22.9+)
//   2. Combines with other gates via aggregation (the warn threshold)
//   3. Writes an explicit audit trail per version
//
// We are NOT positioning this as a differentiator.
//
// False-positive prevention (critical — without this, the gate fires
// constantly on healthy package development):
//
//   1. Prerelease exemption: 1.0.0-rc.1 / 2.0.0-beta.3 / 3.0.0-alpha /
//      4.0.0-dev.20260101 all skip this gate. Prereleases are expected
//      to be published hot and consumed quickly; a cooldown defeats
//      their purpose. This matches npm 11.10's behavior.
//
//   2. Missing published_at: SKIP (data gap, not anomaly). A malformed
//      packument should never block legit installs.
//
//   3. Non-parseable published_at: SKIP. Never throw.
//
//   4. Clock skew: if published_at is in the FUTURE (upstream clock
//      ahead, or forged), treat as age=0h (still WARN) — never SKIP
//      on the basis of "future" because that's a potential attack
//      vector (forge a future date to bypass the cooldown).
//
// Age formula: hours = (now - published_at) / 3600000, floored.

const DEFAULT_RELEASE_AGE_HOURS = 72;
const PRERELEASE_REGEX = /-[a-z0-9]/i; // semver prerelease marker after the version core

function result(r, detail) {
  return { gate: 'release-age', result: r, detail };
}

function isPrerelease(version) {
  if (typeof version !== 'string') return false;
  // A semver string with a prerelease tag has a '-' after the numeric core,
  // e.g. "1.0.0-rc.1", "2.0.0-beta.3". We split off build metadata first.
  const withoutBuild = version.split('+')[0];
  const dashIdx = withoutBuild.indexOf('-');
  if (dashIdx < 0) return false;
  // Quick sanity: characters after the dash should look like a prerelease tag.
  return PRERELEASE_REGEX.test(withoutBuild.slice(dashIdx));
}

function parsePublished(iso) {
  if (typeof iso !== 'string' || !iso) return null;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : null;
}

export default {
  name: 'release-age',
  evaluate(input) {
    const incoming = input?.incoming ?? {};
    const version = input?.version ?? incoming.version;
    const thresholdHours =
      Number.isFinite(input?.config?.releaseAgeHours) && input.config.releaseAgeHours > 0
        ? input.config.releaseAgeHours
        : DEFAULT_RELEASE_AGE_HOURS;
    const nowMs = Number.isFinite(input?.config?._nowMs)
      ? input.config._nowMs
      : Date.now();

    if (isPrerelease(version)) {
      return result('ALLOW', `prerelease exempt from release-age cooldown (${version})`);
    }

    const publishedMs = parsePublished(incoming.published_at);
    if (publishedMs == null) {
      return result('SKIP', 'published_at missing or unparseable — cannot compute age');
    }

    // Clock-skew defense: future-dated releases are treated as age=0.
    const ageMs = Math.max(0, nowMs - publishedMs);
    const ageHours = Math.floor(ageMs / (60 * 60 * 1000));

    if (ageHours >= thresholdHours) {
      return result('ALLOW', `release age ${ageHours}h ≥ threshold ${thresholdHours}h`);
    }

    return result(
      'WARN',
      `release age ${ageHours}h < threshold ${thresholdHours}h (published ${incoming.published_at})`,
    );
  },
};
