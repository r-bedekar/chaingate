// Gate 2: dep-structure (WARN)
//
// Detects new runtime dependencies appearing in a version bump. The
// signal we care about is the first appearance of a package name in
// `dependencies{}` that was absent from every prior observed version.
// Legitimate refactors add deps, so this is WARN — aggregation with
// other gates decides whether to escalate to BLOCK.
//
// Spec: docs/P5.md §6 lines 421-437. Implementation notes:
//
//   - We intentionally compare ONLY `dependencies`, not dev/peer/optional.
//     Build-time deps don't ship to end users and are low blast-radius.
//     Scoping the check narrow keeps false positives low.
//
//   - "prior" = union of dependencies across ALL prior versions (not just
//     the latest). A dep that was added in 1.6.0 and removed in 1.7.0
//     reappearing in 1.8.0 should NOT fire — it's known to the package.
//
//   - Re-observation: the incoming version may itself be in history.
//     Filter it out before computing the prior union, else we can never
//     surface anything (every incoming dep matches "prior").
//
//   - Data gaps: if history is empty → SKIP (first-seen). If incoming has
//     no `dependencies` object or it's empty → ALLOW (no new deps is the
//     absence of the signal, not a gap).
//
//   - Detail reports the FIRST new dep alphabetically and the total count,
//     so the same input always produces the same string. We cap the
//     display at 5 names to keep the detail bounded.

const MAX_DEPS_DISPLAYED = 5;
const MAX_DEP_NAME_LEN = 80;

function truncDepName(name) {
  if (typeof name !== 'string') return '(invalid)';
  return name.length > MAX_DEP_NAME_LEN ? `${name.slice(0, MAX_DEP_NAME_LEN)}…` : name;
}

function depNamesFrom(obj) {
  if (obj == null || typeof obj !== 'object' || Array.isArray(obj)) return [];
  return Object.keys(obj);
}

function result(r, detail) {
  return { gate: 'dep-structure', result: r, detail };
}

export default {
  name: 'dep-structure',
  evaluate(input) {
    const history = Array.isArray(input?.history) ? input.history : [];
    const incoming = input?.incoming ?? {};
    const currentVersion = input?.version;

    const prior = history.filter((h) => h && h.version !== currentVersion);
    if (prior.length === 0) {
      return result('SKIP', 'no prior versions to compare dependencies against');
    }

    const incomingDeps = depNamesFrom(incoming.dependencies);
    if (incomingDeps.length === 0) {
      return result('ALLOW', 'incoming version declares no runtime dependencies');
    }

    const priorUnion = new Set();
    for (const h of prior) {
      for (const name of depNamesFrom(h.dependencies)) {
        priorUnion.add(name);
      }
    }

    const newDeps = incomingDeps.filter((name) => !priorUnion.has(name)).sort();
    if (newDeps.length === 0) {
      return result(
        'ALLOW',
        `all ${incomingDeps.length} runtime dep(s) present in prior ${prior.length} version(s)`,
      );
    }

    const shown = newDeps.slice(0, MAX_DEPS_DISPLAYED).map(truncDepName).join(', ');
    const suffix = newDeps.length > MAX_DEPS_DISPLAYED ? `, … (+${newDeps.length - MAX_DEPS_DISPLAYED} more)` : '';
    return result(
      'WARN',
      `new runtime dep(s): ${shown}${suffix} (not in prior ${prior.length} version(s))`,
    );
  },
};
