import { test } from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import publisher from '../../patterns/publisher.js';
import provenance from '../../patterns/provenance.js';
import {
  disposition,
  __thresholds,
} from '../../validation/disposition.js';

const SEED_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  'seed_export',
  'chaingate-seed.db',
);
const HAS_SEED = existsSync(SEED_PATH);

function loadSeedHistory(packageName, versionFilter = null) {
  const db = new Database(SEED_PATH, { readonly: true });
  try {
    const pkg = db
      .prepare('SELECT id FROM packages WHERE package_name = ?')
      .get(packageName);
    if (!pkg) throw new Error(`package not in seed: ${packageName}`);
    const rows = db
      .prepare(
        `SELECT version, published_at, publisher_name, publisher_email,
                provenance_present
         FROM versions WHERE package_id = ?`,
      )
      .all(pkg.id);
    const mapped = rows.map((r) => ({
      version: r.version,
      published_at_ms: r.published_at ? Date.parse(r.published_at) : null,
      publisher_name: r.publisher_name,
      publisher_email: r.publisher_email,
      provenance_present: r.provenance_present,
    }));
    return versionFilter ? mapped.filter((r) => versionFilter(r.version)) : mapped;
  } finally {
    db.close();
  }
}

function dispose(packageName, history) {
  const pub = publisher.extract({ packageName, history });
  const prov = provenance.extract({ packageName, history });
  return { pub, prov, verdict: disposition(pub, prov) };
}

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

test('cell (F,F) cold_handoff + committee + EXCEPTIONAL prior_tenure WITHOUT co-signal → WARN', () => {
  // 20-version tenure on a committee-shaped package. Per GATE CONTRACT
  // Addition 3: committee + (F,F) at EXCEPTIONAL tenure BLOCKs ONLY
  // with at least one co-signal (new privacy/unverified domain,
  // provenance break, or short gap). No co-signal here — b.com is a
  // verified-corporate new domain (>=MIN_VERIFIED_VERSIONS because B+C
  // total 10 releases), provenance is absent on both sides so no
  // "break" is emitted, and buildRows spaces releases at DAY_MS so
  // gap_ms == SHORT_GAP_MS (strict <). Disposition lands at WARN.
  //
  // A previous revision escalated this to BLOCK via stability=stable.
  // Removed (validation/disposition.js header axis 5) — non-solo
  // escalation is co-signal-only. Committees with long-serving leads
  // handing off to a stable-domain colleague are a legitimate pattern
  // (see date-fns 1.1.1, fs-extra 2.1.0 in the train baseline).
  assert.equal(__thresholds.EXCEPTIONAL_PRIOR_TENURE, 20);
  const rows = buildRows([
    ['A@a.com', 20], ['B@b.com', 5], ['C@b.com', 5],
  ]);
  const { extracted, verdict } = extractDisposition(rows);
  assert.equal(extracted.shape, 'committee');
  assert.equal(extracted.identity_profile.domain_stability, 'stable');
  assert.equal(verdict.disposition, 'WARN');
  assert.match(verdict.reasons[0], /shape=committee/);
  assert.match(verdict.reasons[0], /prior_tenure=20/);
  assert.match(verdict.reasons[0], /no co-signal/);
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
  // A@a.com×20 hands off to B@protonmail.me (exceptional prior_tenure
  // on a committee + new-privacy-domain co-signal) → base disposition
  // BLOCK under the co-signal rule (GATE CONTRACT Addition 3). Final 5
  // rows include C@random.xyz which is new-to-window → stability=
  // churning. Churning de-escalates BLOCK→WARN on committee/alternating
  // (GATE CONTRACT Addition 2).
  //
  // The incoming privacy domain is what lets this fixture reach BLOCK
  // in the first place — without it, committee + prior_tenure=20 alone
  // stays at WARN (no escalation without co-signal) and the
  // de-escalation path is never exercised. Using protonmail.me ensures
  // the A→B transition has co-signal=true so the BLOCK base is
  // produced, then the stability-churning guard can de-escalate it.
  const rows = buildRows([
    ['A@a.com', 20], ['B@protonmail.me', 5], ['C@random.xyz', 5],
  ]);
  const { extracted, verdict } = extractDisposition(rows);
  assert.equal(extracted.shape, 'committee');
  assert.equal(extracted.identity_profile.domain_stability, 'churning');
  assert.equal(verdict.disposition, 'WARN');
  assert.match(verdict.reasons[0], /co-signal: new privacy domain protonmail\.me/);
  assert.match(verdict.reasons[0], /stability=churning \(de-escalated\)/);
});

test('stability=stable does NOT escalate WARN → BLOCK on non-solo HIGH cold handoff without co-signal', () => {
  // Committee with only 2 domains (acme + newco) and newco first seen
  // at the A→B transition. Layout places newco block early so it falls
  // outside the final-5 window — stability=stable, not churning.
  //
  // Previous disposition revision had stability=stable escalate to
  // BLOCK here. Removed: Addition 3 reserves non-solo BLOCK for the
  // co-signal path. A stable-history committee handoff with no
  // co-signal is a legitimate long-serving committee; a 5-version
  // prior tenure is below EXCEPTIONAL regardless. Fixture produces
  // prior_tenure=5 → base path returns WARN (HIGH ≤ 5 < EXCEPTIONAL),
  // and stability cannot push it further.
  const rows = buildRows([
    ['dev1@acme.com', 5],
    ['dev2@newco.com', 3],
    ['dev3@acme.com', 3],
    ['dev4@acme.com', 3],
  ]);
  const { extracted, verdict } = extractDisposition(rows);
  assert.equal(extracted.shape, 'committee');
  assert.equal(extracted.identity_profile.domain_stability, 'stable');
  assert.equal(verdict.disposition, 'WARN');
  assert.doesNotMatch(verdict.reasons[0], /escalated/);
});

test('stability=stable + co-signal on committee EXCEPTIONAL cold handoff → BLOCK', () => {
  // Stable domain history does not by itself escalate, but an active
  // co-signal (short gap) on the same transition does: EXCEPTIONAL
  // prior tenure (>=20) + short gap (<24h) + stable → BLOCK. The
  // gap_ms co-signal is the load-bearing signal, not stability.
  //
  // Shape must be committee, so dominance must stay < SOLO_DOMINANCE
  // (0.80). Layout: dev1×22 (dominant lead) + dev2×1 (short-gap cold
  // handoff) + dev3×5 + dev4×5. 22/33 = 0.667 → committee. All four
  // share acme.com so stability=stable and no new-domain modifier
  // interferes.
  const START = 1_700_000_000_000;
  let idx = 0;
  const at = (i) => START + i * DAY_MS;
  const rows = [
    // 22 dev1 releases at 1/day cadence.
    ...Array.from({ length: 22 }, () => {
      const v = `1.0.${idx}`;
      const row = {
        version: v,
        publisher_email: 'dev1@acme.com',
        publisher_name: 'dev1',
        published_at_ms: at(idx),
      };
      idx += 1;
      return row;
    }),
    // dev2 publishes 3h after dev1's last release — short-gap co-signal.
    (() => {
      const row = {
        version: `1.0.${idx}`,
        publisher_email: 'dev2@acme.com',
        publisher_name: 'dev2',
        published_at_ms: at(idx - 1) + 3 * 3_600_000,
      };
      idx += 1;
      return row;
    })(),
    // Tail: dev3 × 5, dev4 × 5 at 1/day cadence to dilute dominance.
    ...Array.from({ length: 5 }, () => {
      const row = {
        version: `1.0.${idx}`,
        publisher_email: 'dev3@acme.com',
        publisher_name: 'dev3',
        published_at_ms: at(idx),
      };
      idx += 1;
      return row;
    }),
    ...Array.from({ length: 5 }, () => {
      const row = {
        version: `1.0.${idx}`,
        publisher_email: 'dev4@acme.com',
        publisher_name: 'dev4',
        published_at_ms: at(idx),
      };
      idx += 1;
      return row;
    }),
  ];
  const { extracted, verdict } = extractDisposition(rows);
  assert.equal(extracted.shape, 'committee');
  assert.equal(extracted.identity_profile.domain_stability, 'stable');
  const t = extracted.transitions.find((x) => x.at_version === '1.0.22');
  assert.equal(t.prior_tenure_versions, 22);
  assert.equal(t.is_overlap_window_W3, false);
  assert.equal(t.is_known_contributor_K10, false);
  assert.equal(verdict.disposition, 'BLOCK');
  const reason = verdict.reasons.find((r) => /1\.0\.22/.test(r));
  assert.match(reason, /co-signal: gap_ms=/);
});

test('solo HIGH cold handoff BLOCKs regardless of stability (carve-out unchanged)', () => {
  // Solo shape reaches BLOCK via the unconditional solo path at HIGH
  // tenure. Stability=stable (same-domain tail) still lands BLOCK —
  // the solo carve-out sits above the stability modifier. This test
  // pins the invariant after the stable-escalation removal: nothing
  // on the solo path changed.
  const rows = buildRows([
    ['solo@acme.com', 10], // long solo tenure (prior_tenure=10 ≥ HIGH=5)
    ['newbie@acme.com', 2], // same domain → stability=stable, cold_handoff
    ['solo@acme.com', 2], // tail returns to dominant maintainer
  ]);
  const { extracted, verdict } = extractDisposition(rows);
  assert.equal(extracted.shape, 'solo');
  assert.equal(extracted.identity_profile.domain_stability, 'stable');
  assert.equal(verdict.disposition, 'BLOCK');
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
// CO-SIGNAL REQUIREMENT on non-solo cold-handoff escalation.
// See patterns/publisher.js GATE CONTRACT Addition 3 and
// validation/disposition.js::hasCoSignal. Committee / alternating
// shapes at EXCEPTIONAL_PRIOR_TENURE stay at WARN unless at least one
// of (new privacy/unverified domain, provenance break, short gap) is
// present on the transition. Solo shapes are unchanged and BLOCK at
// HIGH_PRIOR_TENURE regardless.
// ---------------------------------------------------------------------------

test('co-signal: committee + (F,F) + prior_tenure=150 + no co-signal → WARN (express dougwilson case)', () => {
  // express handoff class — dougwilson (150-version committee tenure)
  // → ulisesgascon on a verified-corporate gmail-ish domain, no
  // provenance history, multi-day gap. Under the co-signal rule, a
  // celebrated committee handoff of any length alone must NOT BLOCK.
  // Layout: A's block is the load-bearing 150-version tenure; B and C
  // trail with enough volume that A's dominance stays under
  // SOLO_DOMINANCE=0.80 so the shape cascade lands on committee, not
  // solo. 150/(150+20+20) ≈ 0.789 < 0.80.
  const rows = buildRows([
    ['A@a.com', 150], ['B@b.com', 20], ['C@c.com', 20],
  ]);
  const { extracted, verdict } = extractDisposition(rows, 'express-class');
  assert.equal(extracted.shape, 'committee');
  const t0 = extracted.transitions[0];
  assert.equal(t0.prior_tenure_versions, 150);
  assert.equal(t0.is_overlap_window_W3, false);
  assert.equal(t0.is_known_contributor_K10, false);
  assert.match(verdict.reasons[0], /^WARN: /);
  assert.match(verdict.reasons[0], /no co-signal/);
});

test('co-signal: committee + (F,F) + prior_tenure=50 + new privacy domain → BLOCK', () => {
  // Co-signal (a): incoming identity on a new privacy provider domain
  // after an exceptional committee tenure. The privacy class on the
  // incoming block is the axios-shape escalation criterion.
  // 50/(50+15+15) ≈ 0.625 < SOLO_DOMINANCE → committee.
  const rows = buildRows([
    ['A@a.com', 50], ['B@protonmail.me', 15], ['C@c.com', 15],
  ]);
  const { extracted, verdict } = extractDisposition(rows, 'co-signal-privacy');
  assert.equal(extracted.shape, 'committee');
  assert.equal(extracted.transitions[0].prior_tenure_versions, 50);
  assert.equal(verdict.disposition, 'BLOCK');
  assert.match(verdict.reasons[0], /^BLOCK: cold_handoff/);
  assert.match(verdict.reasons[0], /co-signal: new privacy domain protonmail\.me/);
});

test('co-signal: committee + (F,F) + prior_tenure=50 + provenance break → BLOCK', () => {
  // Co-signal (b): prior block's last row carried provenance=true,
  // incoming block's first row does not. The "OIDC lost after
  // consistent history" case — strongest non-identity signal
  // available at this layer.
  //
  // Hand-built input: buildRows does not emit provenance_present, so
  // we construct rows directly. 50 prior + 5 incoming + 5 trailing,
  // each under a distinct login to drive committee shape.
  const rows = [];
  const start = 1_700_000_000_000;
  for (let i = 0; i < 50; i += 1) {
    rows.push({
      version: `1.0.${i}`,
      publisher_email: 'a@a.com',
      publisher_name: 'a',
      published_at_ms: start + i * DAY_MS,
      provenance_present: 1,  // baseline established
    });
  }
  for (let i = 0; i < 15; i += 1) {
    rows.push({
      version: `1.0.${50 + i}`,
      publisher_email: 'b@b.com',
      publisher_name: 'b',
      published_at_ms: start + (50 + i) * DAY_MS,
      provenance_present: 0,  // incoming block drops provenance
    });
  }
  for (let i = 0; i < 15; i += 1) {
    rows.push({
      version: `1.0.${65 + i}`,
      publisher_email: 'c@c.com',
      publisher_name: 'c',
      published_at_ms: start + (65 + i) * DAY_MS,
      provenance_present: 0,
    });
  }
  const { extracted, verdict } = extractDisposition(rows, 'co-signal-provenance');
  assert.equal(extracted.shape, 'committee');
  assert.equal(extracted.transitions[0].prior_tenure_versions, 50);
  assert.equal(extracted.tenure[0].last_provenance_present, true);
  assert.equal(extracted.tenure[1].first_provenance_present, false);
  assert.equal(verdict.disposition, 'BLOCK');
  assert.match(verdict.reasons[0], /^BLOCK: cold_handoff/);
  assert.match(verdict.reasons[0], /co-signal: provenance break/);
});

test('co-signal: committee + (F,F) + prior_tenure=50 + gap_ms=1h → BLOCK', () => {
  // Co-signal (c): incoming first release within SHORT_GAP_MS of the
  // prior block's last release. 1h gap is well under the 24h window.
  // Build via buildRowsAbsolute so we can force an exact sub-24h
  // offset between blocks.
  const HOUR_MS = 60 * 60 * 1000;
  const spec = [];
  // 50 versions under A, each 1 day apart
  for (let i = 0; i < 50; i += 1) spec.push(['a@a.com', i * DAY_MS]);
  // Incoming B starts 1 hour after A's last release
  const afterA = 49 * DAY_MS + HOUR_MS;
  for (let i = 0; i < 15; i += 1) spec.push(['b@b.com', afterA + i * DAY_MS]);
  // Trailing C to secure committee shape (dominance < 0.80)
  const afterB = afterA + 15 * DAY_MS;
  for (let i = 0; i < 15; i += 1) spec.push(['c@c.com', afterB + i * DAY_MS]);
  const rows = buildRowsAbsolute(spec);

  const { extracted, verdict } = extractDisposition(rows, 'co-signal-short-gap');
  assert.equal(extracted.shape, 'committee');
  assert.equal(extracted.transitions[0].prior_tenure_versions, 50);
  assert.equal(extracted.transitions[0].gap_ms, HOUR_MS);
  assert.equal(verdict.disposition, 'BLOCK');
  assert.match(verdict.reasons[0], /^BLOCK: cold_handoff/);
  assert.match(verdict.reasons[0], /co-signal: gap_ms=3600000/);
});

test('co-signal rule does NOT apply to solo shape (prior_tenure=5 + no co-signal → BLOCK)', () => {
  // Solo carve-out: a solo package changing hands after a HIGH tenure
  // IS the ownership event. Must BLOCK regardless of co-signal. This
  // is the event-stream / axios protection floor.
  const rows = buildRows([['solo@a.com', 10], ['new@b.com', 1]]);
  const { extracted, verdict } = extractDisposition(rows, 'solo-no-cosignal');
  assert.equal(extracted.shape, 'solo');
  assert.equal(extracted.transitions[0].prior_tenure_versions, 10);
  assert.equal(verdict.disposition, 'BLOCK');
  assert.match(verdict.reasons[0], /shape=solo/);
  // Reason must NOT contain the "no co-signal" note — solo never
  // checks co-signals.
  assert.ok(!verdict.reasons[0].includes('no co-signal'),
    `solo should not emit no-co-signal reason, got: ${verdict.reasons[0]}`);
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

// ---------------------------------------------------------------------------
// Phase 3 — disposition × provenance interaction tests. Each canonical
// seed-backed case verifies that the identity-continuity routing lands
// the expected verdict with a reason string that names the firing
// escalators / co-signals. Synthetic cases cover the non-solo cold-
// handoff co-signal extension and the legitimate emergency-CLI path.
// ---------------------------------------------------------------------------

test('phase 3: axios@1.14.1 — same identity + regression + (a,b,d) → BLOCK', { skip: !HAS_SEED }, () => {
  const history = loadSeedHistory('axios', (v) => /^1\.1[345]\./.test(v));
  const { verdict } = dispose('axios', history);
  assert.equal(verdict.disposition, 'BLOCK');
  const block = verdict.reasons.find((r) => r.startsWith('BLOCK:'));
  assert.ok(block, `expected a BLOCK reason, got ${JSON.stringify(verdict.reasons)}`);
  assert.match(block, /provenance_regression @ 1\.14\.1/);
  assert.match(block, /escalators=\[[^\]]*new_domain[^\]]*\]/);
  assert.match(block, /escalators=\[[^\]]*privacy[^\]]*\]/);
  assert.match(block, /escalators=\[[^\]]*machine_to_human[^\]]*\]/);
});

test('phase 3: axios@1.13.3 — intra-block regression, zero escalators → WARN', { skip: !HAS_SEED }, () => {
  const history = loadSeedHistory('axios', (v) => /^1\.1[345]\./.test(v));
  const { verdict } = dispose('axios', history);
  // 1.13.3 lands in a WARN reason line on the intra-block same-identity
  // row. 1.14.1 also fires a separate BLOCK reason; that's expected and
  // covered in the test above. Here we verify the 1.13.3 line shape.
  const warn = verdict.reasons.find(
    (r) => r.startsWith('WARN:') && r.includes('provenance_regression @ 1.13.3'),
  );
  assert.ok(warn, `expected a 1.13.3 WARN, got ${JSON.stringify(verdict.reasons)}`);
  assert.match(warn, /regression without escalators/);
  assert.ok(!/escalators=\[/.test(warn),
    `1.13.3 WARN must not name any escalators, got: ${warn}`);
});

test('phase 3: event-stream@3.3.6 — publisher-driven BLOCK, provenance silent', { skip: !HAS_SEED }, () => {
  const history = loadSeedHistory('event-stream');
  const { prov, verdict } = dispose('event-stream', history);
  assert.equal(verdict.disposition, 'BLOCK');
  // Provenance must be silent on event-stream — never reached baseline.
  for (const v of prov.perVersion) {
    assert.equal(v.in_scope, false);
    assert.equal(v.provenance_regression, false);
  }
  // The BLOCK reason must come from publisher (cold_handoff), not from
  // any provenance_regression string.
  const block = verdict.reasons.find((r) => r.startsWith('BLOCK:'));
  assert.ok(block);
  assert.match(block, /cold_handoff/);
  assert.match(block, /shape=solo/);
  assert.ok(!block.includes('provenance_regression'),
    `BLOCK must not cite provenance, got: ${block}`);
});

test('phase 3: ua-parser-js@0.7.29 — no transition + in_scope=false → ALLOW', { skip: !HAS_SEED }, () => {
  const history = loadSeedHistory('ua-parser-js', (v) => /^0\.7\./.test(v));
  const { pub, prov, verdict } = dispose('ua-parser-js', history);
  assert.equal(verdict.disposition, 'ALLOW');
  // Publisher sees a single identity across 0.7.x → 0 transitions.
  assert.equal(pub.transitions.length, 0);
  // Provenance is silent — never adopted OIDC in this window.
  const v = prov.perVersion.find((r) => r.version === '0.7.29');
  assert.ok(v);
  assert.equal(v.in_scope, false);
  assert.equal(verdict.reasons[0], 'no transitions observed');
});

// Synthetic helper: build rows with explicit provenance_present for
// the two co-signal-extension scenarios below. Timestamps step 1 day
// so publisher's gap_ms >= SHORT_GAP_MS and (c) short-gap co-signal
// does NOT fire — isolates the provenance_regression co-signal.
const DAY_MS_D = 86_400_000;
function buildAttestedRows(spec, startMs = 1_700_000_000_000) {
  const rows = [];
  let t = startMs;
  let patch = 0;
  for (const [email, count, attested] of spec) {
    for (let i = 0; i < count; i += 1) {
      rows.push({
        version: `1.0.${patch}`,
        published_at_ms: t,
        publisher_name: email.split('@')[0],
        publisher_email: email,
        provenance_present: attested ? 1 : 0,
      });
      t += DAY_MS_D;
      patch += 1;
    }
  }
  return rows;
}

test('phase 3: non-solo cold_handoff + regression + no other co-signals → BLOCK', () => {
  // Committee shape (U=4), EXCEPTIONAL prior_tenure on outgoing block
  // (charlie with 20 versions), incoming new identity on a
  // non-privacy/non-unverified domain, long gap. The only available
  // co-signal is provenance_regression at the incoming version T —
  // which must be sufficient to upgrade WARN→BLOCK under the STEP 4
  // extension.
  const rows = buildAttestedRows([
    ['alice@corp.com', 5, true],
    ['bob@corp.com', 5, true],
    ['charlie@corp.com', 20, true],
    ['dave@corp.com', 1, false],
  ]);
  const { pub, verdict } = dispose('non-solo-cold-handoff', rows);
  assert.notEqual(pub.shape, 'solo');
  const t = pub.transitions[pub.transitions.length - 1];
  assert.equal(t.prior_tenure_versions, 20);
  assert.equal(verdict.disposition, 'BLOCK');
  const block = verdict.reasons.find((r) => r.startsWith('BLOCK:'));
  assert.ok(block);
  assert.match(block, /co-signal: provenance regression @ 1\.0\.30/);
});

test('phase 3: legitimate committee emergency CLI — same identity, same domain, human baseline → WARN', () => {
  // alice publishes 5 attested, bob 5 attested, alice returns for one
  // unsigned release — an "emergency CLI" from the same human. Same
  // identity (intra-returning), same domain (corp.com seen before),
  // verified-corporate (non-privacy, non-unverified), baseline
  // carried entirely by humans (any_machine=false). No escalator
  // should fire. Per the interaction table: WARN.
  const rows = buildAttestedRows([
    ['alice@corp.com', 5, true],
    ['bob@corp.com', 5, true],
    ['alice@corp.com', 1, false],
  ]);
  const { verdict } = dispose('committee-emergency-cli', rows);
  assert.equal(verdict.disposition, 'WARN');
  const warn = verdict.reasons.find(
    (r) => r.startsWith('WARN:') && r.includes('provenance_regression'),
  );
  assert.ok(warn, `expected a regression WARN, got ${JSON.stringify(verdict.reasons)}`);
  assert.match(warn, /regression without escalators/);
  assert.ok(!/escalators=\[/.test(warn),
    `no escalator must fire, got: ${warn}`);
});

test('phase 3: sufficiency short-circuit — thin history → ALLOW regardless of signals', () => {
  // 5 versions < MIN_HISTORY_DEPTH=8. Even with a fabricated regression
  // pattern (AAAU), disposition must short-circuit to ALLOW. This is
  // the same-layer short-circuit as the Phase-2 sufficiency axis and
  // must fire BEFORE the interaction table is consulted.
  const rows = buildAttestedRows([
    ['alice@corp.com', 3, true],
    ['bob@corp.com', 1, false],
    ['charlie@corp.com', 1, true],
  ]);
  const { pub, verdict } = dispose('thin', rows);
  assert.equal(pub.signals.has_sufficient_history, false);
  assert.equal(verdict.disposition, 'ALLOW');
  assert.match(verdict.reasons[0], /insufficient history/);
});
