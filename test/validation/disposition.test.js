import { test } from 'node:test';
import assert from 'node:assert/strict';

import publisher from '../../patterns/publisher.js';
import {
  disposition,
  __thresholds,
} from '../../validation/disposition.js';

// ---------------------------------------------------------------------------
// Test fixtures re-use the publisher.extract() contract end-to-end so the
// disposition function is exercised against real pattern output — not a
// hand-built extracted object. The same buildRows / buildRowsAbsolute
// helpers as test/patterns/publisher.test.js, duplicated here to keep the
// two files independently readable.
// ---------------------------------------------------------------------------

const DAY_MS = 86_400_000;

function buildRows(spec, startMs = 1_700_000_000_000) {
  const rows = [];
  let t = startMs;
  let patch = 0;
  for (const [email, count] of spec) {
    for (let i = 0; i < count; i += 1) {
      rows.push({
        version: `1.0.${patch}`,
        publisher_email: email,
        publisher_name: email.split('@')[0],
        published_at_ms: t,
      });
      t += DAY_MS;
      patch += 1;
    }
  }
  return rows;
}

function buildRowsAbsolute(spec, startMs = 1_700_000_000_000) {
  return spec.map(([email, offsetMs], i) => ({
    version: `1.0.${i}`,
    publisher_email: email,
    publisher_name: email.split('@')[0],
    published_at_ms: startMs + offsetMs,
  }));
}

function extractDisposition(rows, packageName = 'test-pkg') {
  const extracted = publisher.extract({ packageName, history: rows });
  return { extracted, verdict: disposition(extracted) };
}

// ---------------------------------------------------------------------------
// Sufficiency axis
// ---------------------------------------------------------------------------

test('disposition: short-circuits to ALLOW when has_sufficient_history is false', () => {
  // 5 rows < MIN_HISTORY_DEPTH=8. Downstream signals still computed but
  // the gate MUST NOT consume them — every first contribution in thin
  // history would misclassify as a cold handoff.
  const rows = buildRows([
    ['dev1@acme.com', 2],
    ['dev2@acme.com', 1],
    ['dev3@acme.com', 2],
  ]);
  const { extracted, verdict } = extractDisposition(rows);

  assert.equal(extracted.signals.has_sufficient_history, false);
  assert.equal(verdict.disposition, 'ALLOW');
  assert.equal(verdict.reasons.length, 1);
  assert.match(verdict.reasons[0], /insufficient history/);
});

test('disposition: no transitions (single-identity package above threshold) → ALLOW', () => {
  const rows = buildRows([['dev@acme.com', 10]]);
  const { extracted, verdict } = extractDisposition(rows);

  assert.equal(extracted.transitions.length, 0);
  assert.equal(verdict.disposition, 'ALLOW');
  assert.equal(verdict.reasons[0], 'no transitions observed');
});

// ---------------------------------------------------------------------------
// 3c combination fixtures — the load-bearing regression set. 3c-F must
// BLOCK (axios-class attacker signature) and 3c-D must ALLOW (legitimate
// distributed team) per the user contract for this step. Other fixtures
// document the expected shape/provider/stability interactions.
// ---------------------------------------------------------------------------

test('3c-A (alternating + verified-corporate + stable): single HIGH cold handoff → WARN', () => {
  const rows = buildRows([
    ['dev1@acme.com', 5], ['dev2@acme.com', 4],
  ]);
  const { extracted, verdict } = extractDisposition(rows, '3c-A');

  assert.equal(extracted.shape, 'alternating');
  assert.equal(verdict.disposition, 'WARN');
  assert.match(verdict.reasons[0], /^WARN: cold_handoff/);
  assert.match(verdict.reasons[0], /prior_tenure=5/);
});

test('3c-B (alternating + free-webmail + stable): rotation churn → ALLOW', () => {
  const rows = buildRows([
    ['dev1@gmail.com', 1], ['dev2@yahoo.com', 1],
    ['dev1@gmail.com', 1], ['dev2@yahoo.com', 1],
    ['dev1@gmail.com', 1], ['dev2@yahoo.com', 1],
    ['dev1@gmail.com', 1], ['dev2@yahoo.com', 1],
    ['dev1@gmail.com', 1],
  ]);
  const { verdict } = extractDisposition(rows, '3c-B');
  assert.equal(verdict.disposition, 'ALLOW');
});

test('3c-C (committee + verified-corporate + mixed): rotation churn → ALLOW', () => {
  const rows = buildRows([
    ['a@alpha.com', 1], ['b@beta.com', 1], ['c@gamma.com', 1],
    ['a@alpha.com', 1], ['b@beta.com', 1], ['c@gamma.com', 1],
    ['a@alpha.com', 1], ['b@beta.com', 1], ['c@gamma.com', 1],
  ]);
  const { verdict } = extractDisposition(rows, '3c-C');
  assert.equal(verdict.disposition, 'ALLOW');
});

test('3c-D (committee + privacy + mixed, legit distributed team): must → ALLOW', () => {
  const rows = buildRows([
    ['devA@alpha.com', 1], ['devB@beta.com', 1], ['user@protonmail.me', 1],
    ['devA@alpha.com', 1], ['devB@beta.com', 1], ['devA@alpha.com', 1],
    ['user@protonmail.me', 1], ['devB@beta.com', 1], ['devA@alpha.com', 1],
    ['devB@beta.com', 1],
  ]);
  const { extracted, verdict } = extractDisposition(rows, '3c-D');
  assert.equal(extracted.identity_profile.has_privacy_provider, true);
  assert.equal(verdict.disposition, 'ALLOW');
});

test('3c-E (committee + unverified drive-by + churning): rotation churn → ALLOW', () => {
  const rows = buildRows([
    ['a@alpha.com', 1], ['a@alpha.com', 1], ['b@beta.com', 1],
    ['a@alpha.com', 1], ['b@beta.com', 1], ['a@alpha.com', 1],
    ['b@beta.com', 1], ['a@alpha.com', 1], ['newcontrib@random.xyz', 1],
  ]);
  const { extracted, verdict } = extractDisposition(rows, '3c-E');
  assert.equal(extracted.identity_profile.has_unverified_domain, true);
  assert.equal(verdict.disposition, 'ALLOW');
});

test('3c-F (solo + privacy + churning, axios-class): must → BLOCK', () => {
  const rows = buildRows([
    ['jason@gmail.com', 8], ['ifstap@protonmail.me', 1],
  ]);
  const { extracted, verdict } = extractDisposition(rows, '3c-F');
  assert.equal(extracted.shape, 'solo');
  assert.equal(verdict.disposition, 'BLOCK');
  assert.match(verdict.reasons[0], /^BLOCK: cold_handoff/);
  assert.match(verdict.reasons[0], /shape=solo/);
  assert.match(verdict.reasons[0], /prior_tenure=8/);
  // Provider annotation must fire on the new privacy domain.
  assert.match(verdict.reasons[0], /new_domain=protonmail\.me \(privacy\)/);
});

test('3c-G (unknown shape, insufficient history): short-circuits → ALLOW', () => {
  const rows = buildRowsAbsolute([
    ['a@acme.com', 0],
    ['b@gmail.com', DAY_MS],
    ['c@protonmail.me', 2 * DAY_MS],
    ['d@random.xyz', 3 * DAY_MS],
    ['e@acme.com', 4 * DAY_MS],
  ]);
  const { extracted, verdict } = extractDisposition(rows, '3c-G');
  assert.equal(extracted.signals.has_sufficient_history, false);
  assert.equal(verdict.disposition, 'ALLOW');
  assert.match(verdict.reasons[0], /insufficient history/);
});

// ---------------------------------------------------------------------------
// 2×2 cells — each cell tested against varying prior_tenure levels.
// Package disposition is the max across transitions, so cell-scoped
// claims are verified by inspecting reasons[] at the relevant index.
// ---------------------------------------------------------------------------

test('cell (T,T) recurring_member → ALLOW even on cold-handoff-rich history', () => {
  // 4th transition: B→A with from_index=3. Window [1,3] = [B,A,B]. A in
  // window → overlap=true. A count across [0..3] = 4+10 = 14 ≥ K=10 →
  // known=true. Yields (T,T). Earlier transitions are rotation churn.
  const rows = buildRows([
    ['A@a.com', 4], ['B@b.com', 1], ['A@a.com', 10], ['B@b.com', 1], ['A@a.com', 1],
  ]);
  const { extracted, verdict } = extractDisposition(rows);
  assert.equal(extracted.transitions.length, 4);
  assert.equal(extracted.transitions[3].is_overlap_window_W3, true);
  assert.equal(extracted.transitions[3].is_known_contributor_K10, true);
  assert.match(verdict.reasons[3], /^ALLOW: recurring_member/);
});

test('cell (T,F) new_committee_member → ALLOW', () => {
  // Second transition B→A has overlap=true (A in window) but A count=4 <
  // K=10 → known=false. Classifies as new_committee_member.
  const rows = buildRows([
    ['A@a.com', 4], ['B@b.com', 1], ['A@a.com', 1], ['B@b.com', 3],
  ]);
  const { extracted, verdict } = extractDisposition(rows);
  const t1 = extracted.transitions[1];
  assert.equal(t1.is_overlap_window_W3, true);
  assert.equal(t1.is_known_contributor_K10, false);
  assert.match(verdict.reasons[1], /^ALLOW: new_committee_member/);
});

test('cell (F,T) returning_dormant → ALLOW', () => {
  // A returns after 3 intervening identities push it out of the W=3
  // overlap window. A already has 10 prior contributions so known=true.
  // Prior B/C/D tenures are 1 each — first transition A→B is cold
  // handoff with prior_tenure=10. We assert the dormant-return cell
  // directly from reasons[3].
  const rows = buildRows([
    ['A@a.com', 10], ['B@b.com', 1], ['C@c.com', 1], ['D@d.com', 1], ['A@a.com', 1],
  ]);
  const { extracted, verdict } = extractDisposition(rows);
  const t3 = extracted.transitions[3];
  assert.equal(t3.is_overlap_window_W3, false);
  assert.equal(t3.is_known_contributor_K10, true);
  assert.match(verdict.reasons[3], /^ALLOW: returning_dormant/);
});

test('cell (F,F) cold_handoff with prior_tenure < HIGH → ALLOW (rotation churn)', () => {
  // prior_tenure=4 < HIGH_PRIOR_TENURE=5; MUST NOT escalate.
  assert.equal(__thresholds.HIGH_PRIOR_TENURE, 5);
  const rows = buildRows([['A@a.com', 4], ['B@b.com', 5]]);
  const { verdict } = extractDisposition(rows);
  assert.equal(verdict.disposition, 'ALLOW');
  assert.match(verdict.reasons[0], /rotation churn/);
  assert.match(verdict.reasons[0], /prior_tenure=4/);
});

test('cell (F,F) cold_handoff + solo + HIGH prior_tenure → BLOCK (event-stream class)', () => {
  // event-stream-class: long solo tenure handed off to novel identity.
  const rows = buildRows([
    ['dominictarr@example.com', 27],
    ['right9ctrl@example.com', 3],
  ]);
  const { extracted, verdict } = extractDisposition(rows, 'event-stream');
  assert.equal(extracted.shape, 'solo');
  assert.equal(verdict.disposition, 'BLOCK');
  assert.match(verdict.reasons[0], /shape=solo/);
  assert.match(verdict.reasons[0], /prior_tenure=27/);
});

test('cell (F,F) cold_handoff + committee + EXCEPTIONAL prior_tenure → BLOCK', () => {
  // 20-version tenure on a committee-shaped package. Per GATE CONTRACT
  // Addition 3: committee + (F,F) WARNs unless exceptional.
  //
  // B and C share b.com so the package has 2 unique domains and no
  // new-to-final-5 domain — stability=stable. A third (non-b.com)
  // domain in the final window would flip to churning and mask the
  // exceptional-tenure escalation with a de-escalation.
  assert.equal(__thresholds.EXCEPTIONAL_PRIOR_TENURE, 20);
  const rows = buildRows([
    ['A@a.com', 20], ['B@b.com', 5], ['C@b.com', 5],
  ]);
  const { extracted, verdict } = extractDisposition(rows);
  assert.equal(extracted.shape, 'committee');
  assert.equal(extracted.identity_profile.domain_stability, 'stable');
  assert.equal(verdict.disposition, 'BLOCK');
  assert.match(verdict.reasons[0], /shape=committee/);
  assert.match(verdict.reasons[0], /prior_tenure=20/);
});

test('cell (F,F) cold_handoff + committee + HIGH but not exceptional → WARN', () => {
  const rows = buildRows([
    ['A@a.com', 5], ['B@b.com', 5], ['C@c.com', 5],
  ]);
  const { extracted, verdict } = extractDisposition(rows);
  assert.equal(extracted.shape, 'committee');
  assert.equal(verdict.disposition, 'WARN');
});

test('cell (F,F) + unknown shape treated as solo (conservative)', () => {
  // Hand-built extracted object: forces shape='unknown' with
  // has_sufficient_history=true — a state real pattern extract() cannot
  // produce but the gate must still handle (future refactors may
  // reorganize the cascade; conservative treatment is the invariant).
  const extracted = {
    tenure: [
      {
        identity: 'old@a.com', domain: 'a.com', provider: 'verified-corporate',
        version_count: 8, first_seen_in_package_ms: 1, first_published_at_ms: 1,
        last_published_at_ms: 8, duration_ms: 7, first_version: '1.0.0', last_version: '1.0.7',
      },
      {
        identity: 'new@b.com', domain: 'b.com', provider: 'verified-corporate',
        version_count: 1, first_seen_in_package_ms: 9, first_published_at_ms: 9,
        last_published_at_ms: 9, duration_ms: 0, first_version: '1.0.8', last_version: '1.0.8',
      },
    ],
    transitions: [
      {
        from_identity: 'old@a.com', to_identity: 'new@b.com',
        from_index: 0, at_version: '1.0.8', at_published_at_ms: 9,
        prior_tenure_versions: 8, prior_tenure_duration_ms: 7, gap_ms: 1,
        is_overlap_window_W3: false, is_known_contributor_K10: false,
        prior_contribution_count: 0,
      },
    ],
    identity_profile: {
      providers_seen: ['verified-corporate'],
      has_privacy_provider: false,
      has_unverified_domain: false,
      domain_stability: 'mixed',
    },
    shape: 'unknown',
    signals: { has_sufficient_history: true, observed_versions_count: 9 },
  };
  const verdict = disposition(extracted);
  assert.equal(verdict.disposition, 'BLOCK');
  assert.match(verdict.reasons[0], /shape=unknown/);
});

// ---------------------------------------------------------------------------
// Provider + domain_stability modifiers
// ---------------------------------------------------------------------------

test('provider combo (privacy incoming + has_unverified_domain) escalates WARN → BLOCK', () => {
  // Committee with a random.xyz drive-by (unverified) sets
  // has_unverified_domain=true. A subsequent HIGH-tenure block hands off
  // to a protonmail.me identity (privacy, new domain). Per GATE CONTRACT
  // Addition 1: this combo upgrades WARN→BLOCK on the cold-handoff cell.
  //
  // Layout chosen so the privacy domain does NOT appear in the final-5
  // window (stability=mixed, not churning) — otherwise de-escalation
  // would mask the combo escalation.
  const rows = buildRows([
    ['B@random.xyz', 1],
    ['A@a.com', 8],
    ['D@protonmail.me', 1],
    ['C@a.com', 5],
  ]);
  const { extracted, verdict } = extractDisposition(rows);
  assert.equal(extracted.shape, 'committee');
  assert.equal(extracted.identity_profile.has_unverified_domain, true);
  assert.equal(extracted.identity_profile.has_privacy_provider, true);
  assert.equal(extracted.identity_profile.domain_stability, 'mixed');
  assert.equal(verdict.disposition, 'BLOCK');
  // Second transition (A→D) is the one that combos.
  assert.match(verdict.reasons[1], /^BLOCK: cold_handoff/);
  assert.match(verdict.reasons[1], /privacy\+unverified combo/);
});

test('stability=churning de-escalates BLOCK → WARN on non-solo exceptional cold handoff', () => {
  // A@a.com×20 hands off to B@b.com (exceptional prior_tenure on a
  // committee) → base disposition BLOCK. Final 5 rows include C@random.xyz
  // which is new-to-window → stability=churning. Churning de-escalates
  // BLOCK→WARN on committee/alternating (GATE CONTRACT Addition 2).
  const rows = buildRows([
    ['A@a.com', 20], ['B@b.com', 5], ['C@random.xyz', 5],
  ]);
  const { extracted, verdict } = extractDisposition(rows);
  assert.equal(extracted.shape, 'committee');
  assert.equal(extracted.identity_profile.domain_stability, 'churning');
  // Without churning this would be BLOCK; with churning de-escalation
  // fires only on first transition (A→B, exceptional), so package lands
  // at WARN.
  assert.equal(verdict.disposition, 'WARN');
  assert.match(verdict.reasons[0], /stability=churning \(de-escalated\)/);
});

test('stability=stable escalates WARN → BLOCK on non-solo HIGH cold handoff with new domain', () => {
  // Committee with only 2 domains (acme + newco) and newco first seen
  // at the A→B transition. Layout places newco block early so it falls
  // outside the final-5 window — stability=stable, not churning.
  const rows = buildRows([
    ['dev1@acme.com', 5],
    ['dev2@newco.com', 3],
    ['dev3@acme.com', 3],
    ['dev4@acme.com', 3],
  ]);
  const { extracted, verdict } = extractDisposition(rows);
  assert.equal(extracted.shape, 'committee');
  assert.equal(extracted.identity_profile.domain_stability, 'stable');
  assert.equal(verdict.disposition, 'BLOCK');
  assert.match(verdict.reasons[0], /stability=stable \(escalated\)/);
});

test('modifier precedence: provider combo escalates, then stability de-escalates (WARN wins)', () => {
  // Exact interaction: committee + (F,F) + prior_tenure=10 +
  // new privacy domain + has_unverified_domain + churning stability.
  //
  // Walk-through:
  //   base    = WARN  (committee + HIGH ≤ 10 < EXCEPTIONAL)
  //   combo   = WARN → BLOCK  (privacy incoming + has_unverified_domain)
  //   stable? = BLOCK → WARN  (churning, non-solo, de-escalate)
  //   final   = WARN
  //
  // This test locks the ORDER of modifier application. A refactor that
  // applied stability before provider, or that removed the non-solo
  // stability guard, would land this case at BLOCK and fail here —
  // exactly the regression we want to catch before calibration.
  const rows = buildRows([
    ['B@random.xyz', 1],      // unverified domain, 1 version
    ['A@a.com', 10],           // long tenure (prior_tenure=10 at next transition)
    ['D@protonmail.me', 1],    // privacy incoming, NEW domain
    ['C@c.com', 3],            // trailing block so c.com lands in final-5 → churning
  ]);
  const { extracted, verdict } = extractDisposition(rows, 'modifier-precedence');
  assert.equal(extracted.shape, 'committee');
  assert.equal(extracted.identity_profile.has_unverified_domain, true);
  assert.equal(extracted.identity_profile.has_privacy_provider, true);
  assert.equal(extracted.identity_profile.domain_stability, 'churning');

  const t1 = extracted.transitions[1]; // A → D
  assert.equal(t1.is_overlap_window_W3, false);
  assert.equal(t1.is_known_contributor_K10, false);
  assert.equal(t1.prior_tenure_versions, 10);

  assert.equal(verdict.disposition, 'WARN');
  // Both modifiers must have fired, and in this order.
  assert.match(verdict.reasons[1], /privacy\+unverified combo/);
  assert.match(verdict.reasons[1], /stability=churning \(de-escalated\)/);
  assert.match(verdict.reasons[1], /^WARN: /);
  // Sanity: the combo note must appear BEFORE the stability note in
  // the reason string — ordering is the disposition question here.
  const comboIdx = verdict.reasons[1].indexOf('privacy+unverified combo');
  const stabIdx = verdict.reasons[1].indexOf('stability=churning');
  assert.ok(comboIdx > 0 && stabIdx > comboIdx,
    `expected combo before stability in reason, got: ${verdict.reasons[1]}`);
});

test('modifiers do NOT fire on non-cold-handoff cells', () => {
  // Recurring_member transition with a protonmail incoming identity —
  // provider must NOT escalate because modifiers are scoped to the
  // cold-handoff cell only (GATE CONTRACT Addition 1).
  const rows = buildRows([
    ['A@a.com', 4], ['B@protonmail.me', 1], ['A@a.com', 10],
    ['B@protonmail.me', 1], ['A@a.com', 1],
  ]);
  const { extracted, verdict } = extractDisposition(rows);
  // Final transition (B→A) is recurring_member; A has many prior contribs.
  const last = extracted.transitions.at(-1);
  assert.equal(last.is_overlap_window_W3, true);
  assert.equal(last.is_known_contributor_K10, true);
  assert.match(verdict.reasons.at(-1), /^ALLOW: recurring_member/);
});

// ---------------------------------------------------------------------------
// Purity / determinism
// ---------------------------------------------------------------------------

test('disposition is deterministic: same extracted input → identical output', () => {
  const rows = buildRows([
    ['A@a.com', 20], ['B@b.com', 5], ['C@c.com', 5],
  ]);
  const extracted = publisher.extract({ packageName: 'det', history: rows });
  const a = disposition(extracted);
  const b = disposition(extracted);
  assert.equal(JSON.stringify(a), JSON.stringify(b));
});

test('disposition output matches contract shape', () => {
  const rows = buildRows([['A@a.com', 8], ['B@b.com', 2]]);
  const extracted = publisher.extract({ packageName: 'shape-check', history: rows });
  const out = disposition(extracted);
  assert.ok(['ALLOW', 'WARN', 'BLOCK'].includes(out.disposition));
  assert.ok(Array.isArray(out.reasons));
  assert.ok(out.reasons.every((r) => typeof r === 'string'));
});

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

test('disposition rejects null / non-object input', () => {
  assert.throws(() => disposition(null), /non-null object/);
  assert.throws(() => disposition(undefined), /non-null object/);
  assert.throws(() => disposition('nope'), /non-null object/);
});

test('disposition rejects malformed extracted objects', () => {
  assert.throws(
    () => disposition({ tenure: [], transitions: 'x', signals: {}, identity_profile: {}, shape: 's' }),
    /array tenure and transitions/,
  );
  assert.throws(
    () => disposition({ tenure: [], transitions: [], signals: null, identity_profile: {}, shape: 's' }),
    /signals must be an object/,
  );
  assert.throws(
    () => disposition({ tenure: [], transitions: [], signals: { has_sufficient_history: true }, identity_profile: null, shape: 's' }),
    /identity_profile must be an object/,
  );
  assert.throws(
    () => disposition({ tenure: [], transitions: [], signals: { has_sufficient_history: true }, identity_profile: {}, shape: 0 }),
    /shape must be a string/,
  );
});
