// Gate 6: scope-boundary (WARN only until V2)
//
// THE keystone ChainGate gate. Individually-soft signals compose into
// a high-confidence malicious indicator. This gate is the one that
// detects the Axios 1.14.1 attack pattern by structural composition
// alone — no CVE feed, no malicious-package database, no prior
// knowledge. Just the shape of the release.
//
// Detection logic:
//
//   Signal A (required): NEW runtime dep introduced in this version
//                        (not present in any prior observed version)
//   Signal B (required): package has install scripts
//                        (preinstall/install/postinstall)
//   Signal C (escalator): the new dep is itself freshly published
//                        (< 24h old)
//
//   A + B alone            → WARN (medium-confidence supply-chain risk)
//   A + B + C              → WARN (V2-demoted; see note below)
//
// V2 demotion note (Section 7 item 1 of docs/V2_DESIGN.md):
//   During the V2 dev window, scope-boundary must not contribute to
//   BLOCK. Point-in-time A+B+C can fire on legitimate evolution (a
//   maintainer adds a new dep that happens to be a fresh minor-version
//   bump of a sibling library). The fresh-dep signal is preserved in
//   the WARN detail so forensic investigation still sees it. V2
//   pattern-aware scope-boundary will re-introduce BLOCK once it can
//   distinguish attack-shape from legitimate-evolution-shape.
//
// Why this combination specifically:
//   A alone: happens constantly during normal development (refactors
//            add libraries).
//   B alone: happens for a small but legitimate set of packages
//            (node-gyp consumers, native addons).
//   A + B:   significantly rarer. A refactor to add a new dep AND
//            introduce/keep install scripts is specific enough to
//            warrant a WARN.
//   A + B + C: a published-within-24h dep that lands in a version
//              that also runs install scripts is, in the data we've
//              seen, almost always an attack. The spec puts FP rate
//              at "very low".
//
// Network access pattern (expert-level):
//
// scope-boundary needs to know signal C, which requires an upstream
// packument lookup per novel dep. We can't do that inside the sync
// gate runner. Instead, we read from a persistent dep_first_publish
// cache (witness/dep-cache.js). If the cache is cold:
//
//   1. We ENQUEUE a background fetch via services.enqueueDepLookup
//      (the proxy's dep-fetcher will populate the cache within seconds).
//   2. We SKIP for signal C and fall back to signal A+B = WARN.
//   3. The NEXT observation (within 24h, by which point the fetcher
//      has populated the cache) will see the warm cache and escalate
//      to BLOCK if the dep is fresh.
//
// Tradeoff: first observation of a novel-dep attack gets WARN, not
// BLOCK. Attack is still caught by dep-structure (WARN) + publisher-
// identity (WARN if email shifts) + content-hash (BLOCK on subsequent
// re-observations with drift). Second observation or later will
// escalate properly.
//
// Services injection:
//
//   input.services.lookupDepFirstPublish(name)
//     → { hit: true|false, status?, first_publish? }
//   input.services.enqueueDepLookup(name)
//     → boolean (accepted or dropped)
//
// Both optional. If services are missing, gate falls back to WARN
// on A+B with a note that we couldn't verify signal C.

const FRESH_DEP_HOURS = 24;

function result(r, detail) {
  return { gate: 'scope-boundary', result: r, detail };
}

function runtimeDepNames(v) {
  const d = v?.dependencies;
  if (d == null || typeof d !== 'object' || Array.isArray(d)) return [];
  return Object.keys(d);
}

function computeNewDeps(incoming, history, currentVersion) {
  const prior = history.filter((h) => h && h.version !== currentVersion);
  if (prior.length === 0) return { prior: [], newDeps: [] };
  const incomingDeps = runtimeDepNames(incoming);
  if (incomingDeps.length === 0) return { prior, newDeps: [] };
  const priorUnion = new Set();
  for (const h of prior) {
    for (const name of runtimeDepNames(h)) priorUnion.add(name);
  }
  const newDeps = incomingDeps.filter((n) => !priorUnion.has(n)).sort();
  return { prior, newDeps };
}

function hasInstallScripts(v) {
  // P5.1 stores has_install_scripts as 0/1 (SQLite boolean coercion).
  // Packument parser writes true/false. Accept either shape.
  return v?.has_install_scripts === 1 || v?.has_install_scripts === true;
}

function parseIso(s) {
  if (typeof s !== 'string' || !s) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : null;
}

export default {
  name: 'scope-boundary',
  evaluate(input) {
    const incoming = input?.incoming ?? {};
    const history = Array.isArray(input?.history) ? input.history : [];
    const currentVersion = input?.version;
    const currentPackageName = input?.packageName;
    const services = input?.services ?? {};
    const nowMs = Number.isFinite(input?.config?._nowMs)
      ? input.config._nowMs
      : Date.now();

    const { prior, newDeps } = computeNewDeps(incoming, history, currentVersion);

    if (prior.length === 0) {
      return result('SKIP', 'no prior versions to compare scope against');
    }
    if (newDeps.length === 0) {
      return result('ALLOW', 'no new runtime dependencies introduced');
    }
    if (!hasInstallScripts(incoming)) {
      return result(
        'ALLOW',
        `${newDeps.length} new dep(s) but no install scripts — low risk`,
      );
    }

    // A + B confirmed. Signal C: is the new dep freshly published?
    // Only check the first new dep alphabetically (deterministic),
    // but enqueue lookups for all of them so later observations warm
    // up the cache for every candidate.
    const lookup = typeof services.lookupDepFirstPublish === 'function'
      ? services.lookupDepFirstPublish
      : null;
    const enqueue = typeof services.enqueueDepLookup === 'function'
      ? services.enqueueDepLookup
      : null;

    // Prime the cache for every novel dep on every call, so subsequent
    // observations have full coverage.
    if (enqueue) {
      for (const name of newDeps) {
        if (name === currentPackageName) continue; // self-loop guard
        enqueue(name);
      }
    }

    if (!lookup) {
      return result(
        'WARN',
        `new dep(s) [${newDeps.join(', ')}] + install scripts (dep-age check unavailable)`,
      );
    }

    for (const depName of newDeps) {
      if (depName === currentPackageName) continue; // self-loop guard
      const cached = lookup(depName);
      if (!cached || !cached.hit) continue; // cold → fall through
      if (cached.status !== 'ok') continue; // vanished / error don't escalate
      const firstPublishMs = parseIso(cached.first_publish);
      if (firstPublishMs == null) continue;
      const ageHours = Math.floor((nowMs - firstPublishMs) / (60 * 60 * 1000));
      if (ageHours < FRESH_DEP_HOURS) {
        // V2-demoted: this is the A+B+C composition that was BLOCK
        // pre-V2. Kept as WARN with full detail until V2 pattern-aware
        // scope-boundary lands. See file header for rationale.
        return result(
          'WARN',
          `new dep '${depName}' published ${ageHours}h ago + install scripts in ${currentPackageName}@${currentVersion}`,
        );
      }
    }

    return result(
      'WARN',
      `new dep(s) [${newDeps.join(', ')}] + install scripts (none freshly published within ${FRESH_DEP_HOURS}h)`,
    );
  },
};
