// Gate 3: publisher-identity (WARN)
//
// Detects maintainer handoff or publisher-account takeover between the
// last observed prior version and the incoming one. Account-takeover
// attacks (Shai-Hulud, eslint-scope 2018, event-stream 2018) always show
// this symptom: a different email pushes the next release.
//
// Spec: docs/P5.md §6 lines 439-455. This gate is history-driven, not
// baseline-driven — the "prior" we compare against is the latest version
// we've already observed for this package, regardless of whether the
// incoming version is itself first-seen or a re-observation.
//
// Zero-FP posture: SKIP on any data gap (no history, missing publisher
// fields, only-self in history). WARN on a real email delta. Never BLOCK
// alone — a legitimate maintainer handoff is indistinguishable from a
// takeover at this layer, so aggregation across gates decides final fate.
//
// Edge cases we handle:
//   - Re-observation: history[0] may BE the incoming version itself.
//     We filter history to versions OTHER than the incoming one before
//     picking the latest prior, otherwise we'd always compare against
//     ourselves and report ALLOW.
//   - Case-insensitive email match: in practice npm normalizes emails
//     case-insensitively. Matching ci avoids a spurious WARN when the
//     same human publishes from a client that capitalizes differently.
//   - First-seen package (history empty): SKIP with "first version of package".

const MAX_EMAIL_DISPLAY = 80;

function truncEmail(email) {
  if (typeof email !== 'string' || !email) return '(unknown)';
  return email.length > MAX_EMAIL_DISPLAY
    ? `${email.slice(0, MAX_EMAIL_DISPLAY)}…`
    : email;
}

function normEmail(email) {
  return typeof email === 'string' ? email.trim().toLowerCase() : null;
}

function result(r, detail) {
  return { gate: 'publisher-identity', result: r, detail };
}

export default {
  name: 'publisher-identity',
  evaluate(input) {
    const history = Array.isArray(input?.history) ? input.history : [];
    const incoming = input?.incoming ?? {};
    const currentVersion = input?.version;

    const prior = history.filter((h) => h && h.version !== currentVersion);
    if (prior.length === 0) {
      return result('SKIP', 'no prior versions to compare publisher against');
    }

    const latestPrior = prior[0];
    const priorEmail = normEmail(latestPrior.publisher_email);
    const incomingEmail = normEmail(incoming.publisher_email);

    if (!priorEmail) {
      return result('SKIP', 'prior version has no publisher email — cannot verify');
    }
    if (!incomingEmail) {
      return result('SKIP', 'incoming version has no publisher email — cannot verify');
    }

    if (priorEmail === incomingEmail) {
      return result('ALLOW', `publisher unchanged: ${truncEmail(latestPrior.publisher_email)}`);
    }

    return result(
      'WARN',
      `publisher changed: ${truncEmail(latestPrior.publisher_email)} → ${truncEmail(incoming.publisher_email)} (prior version: ${latestPrior.version})`,
    );
  },
};
