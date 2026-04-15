# ChainGate P5 — Updated Architecture & Build Plan

**Date:** April 14, 2026  
**Context:** Post-review revision capturing all decisions from the Opus review session.  
**Status:** Ready for Claude Code execution.  
**Supersedes:** ARCHITECTURE.md §6 (Phase 5 preview) and tracker/tasks.md Weeks 2-4.

---

## 1. What Changed From the Original P5 Plan

| Decision | Original Plan (April 9) | Updated Plan (April 14) | Why |
|----------|------------------------|------------------------|-----|
| User database | PostgreSQL required | SQLite default, PostgreSQL optional | No one installs PostgreSQL to try a security tool. Adoption killer. |
| Witness population | Separate collector process on user machine | Proxy writes baselines as side effect of every install | Eliminates Python dependency for end users. Zero-config. |
| Python on user machine | Required (collector) | Not required | User-facing product is pure Node.js |
| Seed data | User runs collector to build baselines | Ship pre-built SQLite with 70K versions from VPS | Day-one protection for top 209 packages |
| Upstream registry | Hardcoded registry.npmjs.org | Configurable — defaults to npmjs.org, enterprise points to Artifactory/Nexus | Enterprise deploys behind existing proxy |
| First-seen packages | No coverage | Correct — no baseline = ALLOW + record baseline for next time | Same as Go sumdb model |

---

## 2. Two Separate Environments

**Environment A: Your VPS (data factory — already built, stays PostgreSQL)**

```
Hostinger VPS
├── PostgreSQL (master witness store)
├── collector.py (Python, runs every 15 min via systemd)
├── sources/npm.py, pypi.py, osv.py (fetch from registries)
├── backfill_*.py (one-shot enrichment scripts)
└── OUTPUT: periodic SQLite seed export for shipping
```

This is P1-P4. Already done. Already running. 209 packages, 69,964 versions, 181,240 version_files, 922 attack_labels. No changes needed.

**Environment B: User's machine (enforcement layer — P5, to be built)**

```
User's machine (Node.js only)
├── ~/.chaingate/witness.db (SQLite)
│   ├── Pre-loaded with seed baselines on init
│   └── Grows as proxy observes new packages
├── proxy/server.js (HTTP server, user's .npmrc points here)
├── proxy/registry.js (forwards to upstream, any registry)
├── witness/store.js (reads/writes SQLite)
├── witness/baseline.js (compares incoming vs stored)
├── gates/*.js (6 deterministic gates)
└── cli/ (init, status, allow)
```

No Python. No PostgreSQL. No API keys. No cloud. One command to start.

---

## 3. Data Flow — End to End

```
npm install axios
       │
       ▼
.npmrc: registry=http://localhost:4873
       │
       ▼
proxy/server.js receives request
       │
       ├──► Is this a metadata request (GET /axios)?
       │         │
       │         ▼
       │    proxy/registry.js forwards to upstream
       │    (registry.npmjs.org OR Artifactory OR any configured upstream)
       │         │
       │         ▼
       │    Upstream returns full packument JSON
       │         │
       │         ▼
       │    witness/store.js — does a baseline exist for this package+version?
       │         │
       │         ├── YES: witness/baseline.js compares incoming vs stored
       │         │         │
       │         │         ▼
       │         │    gates/index.js runs all 6 gates
       │         │         │
       │         │         ├── All ALLOW → return packument to npm
       │         │         ├── Any WARN → return packument + print warnings
       │         │         └── Any BLOCK → return 403 + print block reasons
       │         │
       │         └── NO: record this as new baseline in witness.db
       │                  return packument to npm (ALLOW, first-seen)
       │
       └──► Is this a tarball request (GET /axios/-/axios-1.7.9.tgz)?
                 │
                 ▼
            Forward directly to upstream, return tarball
            (Gates run on metadata, not on tarball content.
             Content hash is verified from the metadata response.)
```

---

## 4. SQLite Schema for User-Side witness.db

Maps directly from your existing PostgreSQL schema. Same tables, adapted for SQLite:

```sql
-- Core tables (same structure as PostgreSQL, SQLite types)

CREATE TABLE packages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem  TEXT NOT NULL,                  -- 'npm' | 'pypi'
    package_name TEXT NOT NULL,
    UNIQUE (ecosystem, package_name)
);

CREATE TABLE versions (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id                  INTEGER NOT NULL REFERENCES packages(id),
    version                     TEXT NOT NULL,
    published_at                TEXT,           -- ISO 8601 timestamp
    content_hash                TEXT,
    content_hash_algo           TEXT,
    integrity_hash              TEXT,           -- npm SRI sha512-...
    git_head                    TEXT,
    dependency_count            INTEGER,
    dependencies                TEXT,           -- JSON string
    dev_dependencies            TEXT,           -- JSON string
    peer_dependencies           TEXT,           -- JSON string
    optional_dependencies       TEXT,           -- JSON string
    bundled_dependencies        TEXT,           -- JSON string
    dev_dependency_count        INTEGER,
    peer_dependency_count       INTEGER,
    optional_dependency_count   INTEGER,
    bundled_dependency_count    INTEGER,
    publisher_name              TEXT,
    publisher_email             TEXT,
    publisher_tool              TEXT,
    publisher_maintainer        TEXT,
    publisher_maintainer_email  TEXT,
    maintainers                 TEXT,           -- JSON string
    publish_method              TEXT,           -- 'oidc' | 'token' | 'unknown'
    provenance_present          INTEGER,        -- 0 or 1 (SQLite boolean)
    provenance_details          TEXT,           -- JSON string
    has_install_scripts         INTEGER,        -- 0 or 1
    package_size_bytes          INTEGER,
    source_repo_url             TEXT,
    first_observed_at           TEXT DEFAULT (datetime('now')),
    last_seen_at                TEXT,
    UNIQUE (package_id, version)
);

CREATE TABLE version_files (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id      INTEGER NOT NULL REFERENCES versions(id),
    filename        TEXT NOT NULL,
    packagetype     TEXT,
    content_hash    TEXT,
    content_hash_algo TEXT,
    size_bytes      INTEGER,
    uploaded_at     TEXT,
    url             TEXT,
    first_observed_at TEXT DEFAULT (datetime('now')),
    last_seen_at    TEXT,
    UNIQUE (version_id, filename)
);

-- New table for P5
CREATE TABLE gate_decisions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name    TEXT NOT NULL,
    version         TEXT NOT NULL,
    disposition     TEXT NOT NULL,              -- 'ALLOW' | 'WARN' | 'BLOCK'
    gates_fired     TEXT NOT NULL,              -- JSON: [{"gate":"content-hash","result":"BLOCK","detail":"..."}]
    decided_at      TEXT DEFAULT (datetime('now'))
);

-- Override table for scw allow
CREATE TABLE overrides (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name    TEXT NOT NULL,
    version         TEXT NOT NULL,
    reason          TEXT NOT NULL,
    created_at      TEXT DEFAULT (datetime('now')),
    UNIQUE (package_name, version)
);

-- Indexes
CREATE INDEX idx_versions_pkg ON versions(package_id);
CREATE INDEX idx_vfiles_ver ON version_files(version_id);
CREATE INDEX idx_decisions_pkg ON gate_decisions(package_name, version);
```

---

## 5. Seed Export Process

New script needed: `collector/export_seed.py`

Reads from your VPS PostgreSQL, writes a SQLite file:

```
VPS PostgreSQL (69,964 versions)
       │
       ▼
export_seed.py
       │
       ├── Creates witness.db (SQLite)
       ├── Copies packages table
       ├── Copies versions table (strips raw_metadata to save space)
       ├── Copies version_files table (strips raw_metadata)
       ├── Creates empty gate_decisions + overrides tables
       └── Output: chaingate-seed-YYYYMMDD.db (~50-80MB)
```

This file ships with the npm package or is downloaded on `scw init`.

---

## 6. The Six Gates — Specifications

Each gate is a pure function:

```
Input:  incoming packument + historical baseline from witness.db
Output: { gate: string, result: 'ALLOW'|'WARN'|'BLOCK', detail: string }
```

### Gate 1: content-hash (BLOCK)

```
Compare: incoming dist.shasum / dist.integrity
Against: versions.content_hash / versions.integrity_hash
         where package_id matches AND version matches

If version exists in witness.db AND hash differs → BLOCK
If version not in witness.db → ALLOW (first-seen, record baseline)
If hashes match → ALLOW

False positives: Zero. Content was literally replaced.
```

### Gate 2: dep-structure (WARN)

```
Compare: incoming dependencies object
Against: previous version's dependencies from versions table
         (ordered by published_at DESC, take the latest before this version)

If new dependency added that didn't exist in any prior version → WARN
  Detail: "New dependency: {name} (not present in prior {N} versions)"

False positives: Medium. Legitimate refactors add deps.
```

### Gate 3: publisher-identity (WARN)

```
Compare: incoming _npmUser.email
Against: most recent prior version's publisher_email

If publisher_email changed → WARN
  Detail: "Publisher changed: {old} → {new}"
If publisher_email is NULL in baseline → skip (data gap, not anomaly)

False positives: Medium. Maintainers change emails.
```

### Gate 4: provenance-continuity (WARN)

```
Compare: incoming dist.attestations presence
Against: prior version's provenance_present

If prior versions had provenance (OIDC) AND this version doesn't → WARN
  Detail: "Provenance missing (prior {N} versions had OIDC attestation)"

False positives: Low. Method changes are rare.
```

### Gate 5: release-age (WARN)

```
Check: incoming time[version] timestamp
Against: configurable threshold (default: 72 hours)

If version published less than threshold ago → WARN
  Detail: "Version published {X} hours ago (threshold: {Y}h)"

Note: Commoditized by npm native min-release-age. Include for completeness
but this is NOT the differentiator. Content-hash is.

False positives: Low. Configurable.
```

### Gate 6: scope-boundary (WARN)

```
Combined check:
  A) New dependency from gate 2 result
  B) has_install_scripts is true (from incoming scripts.preinstall/install/postinstall)
  C) New dependency's first-publish age < 24 hours (if determinable)

If A AND B → WARN
  Detail: "New dependency {name} + install scripts detected"
If A AND B AND C → escalate to BLOCK
  Detail: "New dependency {name} (published {X}h ago) + install scripts"

This is the Axios combo detector. Any one signal is ambiguous.
All three together is high-confidence malicious.
```

### Gate Runner: gates/index.js

```
Run all 6 gates. Aggregate results.

Disposition logic:
  - Any gate returns BLOCK → final disposition = BLOCK
  - 3+ gates return WARN → final disposition = BLOCK (escalation)
  - Any gate returns WARN → final disposition = WARN
  - All gates return ALLOW → final disposition = ALLOW

Check overrides table: if (package_name, version) has override → ALLOW

Log to gate_decisions table regardless of outcome.
```

---

## 7. Proxy Configuration

```javascript
// Default config (user runs `scw init`)
{
  port: 4873,
  upstream: "https://registry.npmjs.org",
  db_path: "~/.chaingate/witness.db",
  warn_escalation_threshold: 3,    // N warnings → BLOCK
  release_age_hours: 72
}

// Enterprise config (behind Artifactory)
{
  port: 4873,
  upstream: "https://artifactory.bank.sa/npm-remote/",
  db_path: "/opt/chaingate/witness.db",
  warn_escalation_threshold: 2,
  release_age_hours: 168            // 7 days
}
```

Upstream is configurable. ChainGate doesn't care what's behind it — Artifactory, Nexus, Verdaccio, direct registry, or a fully offline mirror. It intercepts the response and runs gates against local SQLite.

---

## 8. CLI Commands

### scw init

```
1. Create ~/.chaingate/ directory
2. Copy/download seed witness.db into ~/.chaingate/witness.db
3. Write proxy config to ~/.chaingate/config.json
4. Append registry=http://localhost:4873 to .npmrc
   (backs up original .npmrc first)
5. Start proxy
6. Print summary: "Ready. {N} packages, {M} versions in witness store."
```

### scw status

```
Read gate_decisions table. Print:
- Total installs verified: {N}
- Packages in witness store: {N}
- Versions tracked: {N}
- Warnings issued: {N}
- Blocks issued: {N}
- Last 5 decisions (table format)
```

### scw allow <package>@<version> --reason "..."

```
Insert into overrides table.
Print: "Override recorded. {package}@{version} will be allowed."
```

### scw stop

```
Stop proxy. Restore original .npmrc.
```

---

## 9. Proxy Write-on-Observe (Learn on First Sight)

When the proxy sees a package+version for the first time (not in witness.db):

```javascript
// In proxy response handler, after forwarding from upstream:

const existing = await store.getBaseline(packageName, version);

if (!existing) {
  // First observation — record as baseline
  await store.recordBaseline(packageName, versionData);
  // ALLOW — nothing to compare against
  return { disposition: 'ALLOW', reason: 'first-seen' };
}

// Baseline exists — run gates
const results = gates.run(versionData, existing);
```

The `store.recordBaseline()` function extracts the same fields your Python collector does (content_hash, dependencies, publisher_email, provenance, etc.) and writes them to SQLite. Same data shape, just populated from the proxy instead of from a collector process.

This means:
- Seed data gives day-one coverage for 209 popular packages
- Everything else the user installs builds a baseline on first sight
- Second install of same package triggers gate comparison
- After ~1 week of normal use, witness.db covers the user's full dependency tree

---

## 10. The Axios Test (Validation Target)

Your witness store already has real data for axios@1.14.0 and axios@1.14.1 (the March 2026 compromise). The retroactive test should show:

```
$ npm install axios@1.14.0
✓ axios@1.14.0 — ALLOW
  content-hash: match | deps: 3 (stable) | publisher: jasonsaayman
  provenance: OIDC | age: 287 days

$ npm install axios@1.14.1
🚫 axios@1.14.1 — BLOCK (4 gates fired)
  ├── content-hash:  WARN — integrity hash differs from baseline
  ├── dep-structure: WARN — new dependency: plain-crypto-js
  ├── publisher-id:  WARN — publisher changed: jasonsaayman → ifstap
  ├── provenance:    WARN — OIDC provenance missing (14 prior versions had it)
  └── 4 warnings → escalated to BLOCK

  Run: scw allow axios@1.14.1 --reason "..." to override
```

This is the demo. The LinkedIn post. The Black Hat MEA Arsenal submission. The README screenshot.

---

## 11. What Ships vs What Stays Internal

| Component | Ships (Apache 2.0) | Stays internal |
|-----------|-------------------|----------------|
| proxy/server.js | ✅ | |
| proxy/registry.js | ✅ | |
| witness/store.js | ✅ | |
| witness/baseline.js | ✅ | |
| gates/*.js (all 6 + index) | ✅ | |
| cli/*.js | ✅ | |
| chaingate-seed.db | ✅ (top 209 packages) | |
| collector/*.py | | ✅ (VPS data factory) |
| backfill_*.py | | ✅ |
| Full witness store (70K versions) | | ✅ (enterprise tier) |
| ML anomaly model (Month 3-4) | | ✅ (enterprise tier) |
| Compliance reports | | ✅ (enterprise tier) |
| SIEM connectors | | ✅ (enterprise tier) |

---

## 12. Revised 10-Day Build Plan for Claude Code

All sessions run on VPS via SSH. Claude Code reads ARCHITECTURE.md + this document.

| Day | Prompt for Claude Code | Output |
|-----|----------------------|--------|
| **1** | "Read P5_UPDATED_SUMMARY.md §4. Create witness/db.js — a SQLite wrapper using better-sqlite3. Implement: createSchema(), getBaseline(ecosystem, packageName, version), recordBaseline(ecosystem, packageName, versionData), getVersionHistory(ecosystem, packageName), insertGateDecision(), getOverride(), insertOverride(). Use the schema from §4. Test with a sample axios record." | witness/db.js working with SQLite |
| **2** | "Read P5_UPDATED_SUMMARY.md §5. Create collector/export_seed.py — reads from existing PostgreSQL chaingate DB, writes a SQLite file matching the schema in witness/db.js. Copy packages, versions (drop raw_metadata column to save space), version_files (drop raw_metadata). Create empty gate_decisions and overrides tables. Run it and check file size." | chaingate-seed.db file ready to ship |
| **3** | "Read P5_UPDATED_SUMMARY.md §3 and §7. Create proxy/server.js and proxy/registry.js. HTTP server that accepts npm registry requests. Configurable upstream (default: registry.npmjs.org). Forwards metadata and tarball requests. Test: set .npmrc to localhost:4873, run npm install axios, verify it works identically to direct." | Proxy passes through correctly |
| **4** | "Read P5_UPDATED_SUMMARY.md §9. Create witness/store.js and witness/baseline.js. store.js wraps witness/db.js for the proxy's use case: getBaseline returns historical data, recordBaseline writes new observations. baseline.js takes incoming packument + stored baseline and produces a comparison object the gates will consume. Wire into proxy: after forwarding response, check baseline, record if new." | Proxy observes and records |
| **5** | "Read P5_UPDATED_SUMMARY.md §6. Create all 6 gate files + gates/index.js. Each gate is a pure function per the spec. Gate runner aggregates results, applies escalation logic (3+ WARN → BLOCK), checks overrides. Test each gate with mock data: one test that should ALLOW, one that should trigger." | All gates implemented |
| **6** | "Wire gates into proxy. After baseline comparison, run gates/index.js. If BLOCK: return HTTP 403 with JSON body explaining which gates fired. If WARN: forward package but print warnings to stderr. If ALLOW: forward silently. Log every decision to gate_decisions table via witness/db.js." | End-to-end flow working |
| **7** | "Read P5_UPDATED_SUMMARY.md §8. Create cli/index.js (main entry), cli/init.js (create ~/.chaingate, copy seed db, write config, update .npmrc, start proxy), cli/status.js (query gate_decisions, print stats), cli/allow.js (insert override). Update package.json bin entry. Test: scw init → npm install axios → scw status." | CLI complete |
| **8** | "Create test/known-attacks/axios.test.js. Load the real axios data from the seed SQLite. Simulate the 1.14.0 → 1.14.1 delta. Verify 4 gates fire (content-hash WARN, dep-structure WARN, publisher-id WARN, provenance WARN) and final disposition is BLOCK. Also test that axios@1.7.9 (legitimate version) returns ALLOW." | Axios validation passing |
| **9** | "Create test/known-attacks/trivy.test.js — simulate hash mismatch for an already-observed version, verify content-hash BLOCK. Create test/known-attacks/shai-hulud.test.js — simulate publisher change across multiple packages, verify publisher-id WARN on each. Fix any bugs from day 8." | All 3 attack tests passing |
| **10** | "Polish: add colored terminal output for gate results (green ALLOW, yellow WARN, red BLOCK). Add error handling for proxy when upstream is unreachable (fail cleanly, don't crash). Add --help to CLI. Update README.md with actual install instructions and the Axios demo screenshot output. Run full test suite." | Shippable quality |

---

## 13. Dependencies (User-Facing, Node.js Only)

```json
{
  "dependencies": {
    "better-sqlite3": "^11.0.0",
    "http-proxy": "^1.18.0"
  },
  "devDependencies": {}
}
```

Two production dependencies. That's it. better-sqlite3 is a native module (compiles on install) but is the standard for embedded SQLite in Node.js. http-proxy handles upstream forwarding.

No Python. No PostgreSQL driver. No external API clients.

---

## 14. Key Validation Criteria for P5 Complete

- [ ] `scw init` (after npm install -g chaingate) creates witness.db with seed data and starts proxy — under 30 seconds
- [ ] `npm install axios@1.7.9` through proxy returns ALLOW with clear output
- [ ] Simulated axios@1.14.1 metadata through proxy returns BLOCK with 4 gates fired
- [ ] `scw status` shows accurate gate decision history
- [ ] `scw allow axios@1.14.1 --reason "testing"` overrides the block
- [ ] Proxy handles scoped packages (@babel/core) correctly
- [ ] Proxy survives upstream timeout without crashing
- [ ] First-seen package is ALLOWED and baseline is recorded in witness.db
- [ ] Second install of same package is verified against baseline
- [ ] All 3 known-attack tests pass

---

## 15. What This Document Does NOT Cover (Deferred)

- PyPI proxy (Month 5-6)
- Merkle tree / tamper evidence (Month 3-4)
- ML anomaly model (Month 3-4)
- Docker registry proxy (Month 3-4)
- Web dashboard (Month 5-6)
- SIEM connectors (Month 5-6)
- Compliance reports (Month 5-6)
- LDAP/AD integration (Month 5-6)
- Artifactory/Nexus plugin API (Month 5-6)
- Kubernetes Helm chart (Month 5-6)

---

## 16. Competitive Positioning (Verified April 14, 2026)

ChainGate is a **witness**, not a firewall. It does not compete with:

| Tool | What they do | What ChainGate does differently |
|------|-------------|-------------------------------|
| Socket Firewall | Analyzes code for 70+ behavioral signals. Cloud API. | Compares package metadata against its own history. Local SQLite. No cloud. |
| Datadog SCFW | Blocks known-malicious via their dataset + OSV. Open source. | Detects unknown anomalies via historical baseline. No external feeds. |
| npm min-release-age | Cooldown timer on new versions. Native in npm 11.10+. | Release-age is 1 of 6 gates, and the least important. Content-hash is the core. |
| Go sumdb | Content-hash transparency log with install-time gating. Go-only. | Same concept applied to npm (and later PyPI). Cross-ecosystem. Self-hosted. |

The five genuinely open gaps ChainGate fills (verified via web search April 14, 2026):
1. Cross-ecosystem content-hash verification against historical baseline
2. Append-only transparency log of package metadata history for npm/PyPI
3. Deterministic structural gating without external intelligence
4. Self-hosted, zero-external-dependency, air-gapped supply chain gating
5. Compliance-mapped gating for NCA ECC / SAMA CSF regulated environments
