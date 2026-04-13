# TASKS.md — ChainGate Development Tracker

Update this file as tasks are completed. Claude Code can read this to understand current progress and what's next.

## Current Phase: Month 1-2 (Foundation)

---

## Phase Plan — closing foundation gaps before proxy

These phases cut across the original Week 1-4 plan below. They exist because the gap analysis on 2026-04-13 uncovered data-layer gaps that the Week 3 gates depend on. One-screen status:

| Phase  | Scope                                                                                      | Status       | Landed     |
|--------|--------------------------------------------------------------------------------------------|--------------|------------|
| P1     | Yank / deprecation / vanish detection                                                      | done         | 2026-04-13 |
| P2.1   | versions-table extensions (maintainers, sha512, git_head, dep groups, license, publisher_tool) | done         | 2026-04-13 |
| P2.2   | `version_files` child table + PEP 740 attestation tracking                                 | in progress  | —          |
| P3     | Advisories / attack_labels (OSV + GHSA) — closes Gap #1                                    | done         | 2026-04-13 |
| P4     | Collector frequency 1h → 15m                                                               | done         | 2026-04-13 |
| P5     | Week 2-3: npm proxy + gates                                                                | pending      | —          |

Progress Log at the bottom of this file has the dated detail for every landed step. TaskList (via the Claude Code task tool) tracks intra-phase step status.

---

### Week 1: Project Setup + Data Collector

**Setup (do first — everything depends on this):**
- [x] Create PostgreSQL database: `chaingate`
- [x] Create database schema (packages, versions, gate_decisions, attack_labels tables)
- [x] Initialize git repo with .gitignore, .env, README.md, CLAUDE.md
- [x] Create project folder structure per CLAUDE.md
- [x] First commit

**Data Collector — npm:**
- [x] `collector/sources/npm.py` — fetch npm packages (100-package seed)
- [x] Parse npm registry response: extract deps, publisher, hashes, provenance, scripts, timestamps
- [x] `collector/db.py` — database helpers (upsert package, insert_if_new version, start/finish run)
- [x] `collector/collector.py` — main script: async + bounded concurrency + rate limit + retries
- [x] Test: 100 packages / 50K+ versions, 0 errors, idempotent on re-run
- [x] Install systemd timer for hourly run

**Data Collector — PyPI:**
- [x] `collector/sources/pypi.py` — fetch PyPI packages (100-package seed)
- [x] Parse PyPI JSON response: extract author, hashes, deps, upload time, size
- [x] Add PyPI source to collector.py (refactored into generic dispatch on source module)
- [x] Per-version enrichment hook (`enrich_version`) to fetch publisher_email/dependencies/source_repo_url from `/pypi/{name}/{version}/json` — closes Gap #5
- [x] Tarball inspector (`collector/sources/pypi_tarball.py`) — downloads sdist, AST-walks setup.py, detects dangerous imports/os calls/cmdclass — closes Gap #6
- [x] `db.existing_versions` + `db.update_version_fill_nulls` (COALESCE-protected fill-NULL UPDATE)
- [x] Historical backfill scripts (`backfill_pypi.py`, `backfill_pypi_tarballs.py`) — resumable id-cursor pattern
- [x] Test: 100 packages / 19.5K+ versions, 0 errors, idempotent on re-run
- [x] Install systemd timer for pypi hourly run at :15

**Data Collector — Attack Labels:**
- [x] `collector/sources/osv.py` — OSV.dev federated source (covers GHSA + PyPA + MAL-*)
- [x] Map advisories to packages in database, upsert into attack_labels table
- [x] Test: Axios NO_PROXY SSRF, event-stream, ua-parser-js malware all present

---

### Week 2: npm Proxy (basic)

- [ ] `npm init` in project root, set up package.json
- [ ] `proxy/server.js` — HTTP server that accepts npm registry requests
- [ ] `proxy/registry.js` — forward requests to registry.npmjs.org, return response
- [ ] Test: point .npmrc at localhost proxy, run `npm install axios`, verify it works
- [ ] `witness/store.js` — on every package response, extract metadata and store in database
- [ ] Test: install a package through proxy, verify metadata recorded in versions table

---

### Week 3: Gates

- [ ] `gates/content-hash.js` — compare incoming package hash vs first-observed hash in witness store. Mismatch = BLOCK.
- [ ] `gates/dep-structure.js` — compare dependency list vs previous version. New dep = WARN.
- [ ] `gates/publisher-identity.js` — compare publisher email vs previous versions. Change = WARN.
- [ ] `gates/provenance-continuity.js` — compare publish method vs previous versions. OIDC→CLI = WARN.
- [ ] `gates/release-age.js` — flag versions published less than configurable hours ago. WARN.
- [ ] `gates/scope-boundary.js` — phantom dep (new, <24hrs old) + has install scripts = WARN.
- [ ] `gates/index.js` — gate runner: execute all gates, aggregate results, determine disposition.
- [ ] Gate results logged to gate_decisions table.

**Gate tests against real attacks:**
- [ ] `test/known-attacks/axios.test.js` — use real axios@1.14.0 vs 1.14.1 metadata, verify 4 gates fire
- [ ] `test/known-attacks/trivy.test.js` — simulate hash mismatch, verify BLOCK
- [ ] `test/known-attacks/shai-hulud.test.js` — test publisher change across multiple packages

---

### Week 4: CLI + Polish

- [ ] `cli/index.js` — main `scw` command entry point
- [ ] `cli/init.js` — `scw init`: start proxy, update .npmrc to point at it
- [ ] `cli/status.js` — `scw status`: show gate stats (packages tracked, decisions made, warnings, blocks)
- [ ] `cli/allow.js` — `scw allow pkg@version --reason "..."`: override a warning, log to gate_decisions
- [ ] Terminal output: colored pass/fail for each gate on install
- [ ] `package.json` bin entry so `npm install -g chaingate` makes `scw` available
- [ ] End-to-end test: `scw init` → `npm install axios` → see gate results in terminal

---

### Month 2: Hardening

- [ ] Error handling: proxy must not crash on malformed responses
- [ ] Timeout handling: if upstream registry is slow, don't block forever
- [ ] Cache: store tarballs locally so repeat installs are fast
- [ ] SQLite support: if CHAINGATE_DB=sqlite, use local SQLite instead of PostgreSQL
- [ ] Latency check: measure added latency per install, must be <500ms
- [ ] Documentation: update README with actual install/usage instructions
- [ ] Retroactive Axios simulation: blog-ready screenshots of the tool blocking the attack

---

## NOT YET (Month 3+)

These are documented here so Claude Code knows they exist but does NOT build them:

- Merkle tree implementation (Month 3-4)
- Anomaly detection model (Month 3-4)
- Docker registry proxy (Month 3-4)
- Org-specific baselines (Month 3-4)
- Docker Compose deployment (Month 3-4)
- Web dashboard (Month 5-6)
- SIEM connectors (Month 5-6)
- Compliance reports (Month 5-6)
- LDAP/AD integration (Month 5-6)
- Artifactory/Nexus plugin (Month 5-6)
- PyPI proxy (Month 5-6)
- Helm chart (Month 5-6)
- Binary update verification (Month 7+)
- GitHub Actions verification (Month 7+)

---

## Progress Log

| Date | What was done | Notes |
|------|--------------|-------|
| 2026-04-09 | Project setup complete | DB + schema, folder structure, package.json, requirements.txt, LICENSE, first commit |
| 2026-04-13 | npm collector built + validated | 3-layer collector (db/source/orchestrator), async+retry+rate-limit; 49 pkgs / 22.4K versions in 13s, 0 errors, idempotent |
| 2026-04-13 | Systemd units drafted (npm) | `collector/deploy/systemd/*.service + .timer` + README |
| 2026-04-13 | npm timer installed + validated | Timer armed, manual trigger verified (10.03s, 49 pkgs, 0 errors, sandbox OK) |
| 2026-04-13 | PyPI collector built + validated | Generic dispatch refactor; 28 pkgs / 5.9K versions in 2.4s, 0 errors, idempotent. ctx/phpass confirmed unpublished. |
| 2026-04-13 | PyPI systemd units drafted | `chaingate-collector-pypi.{service,timer}` staggered to :15, needs sudo install |
| 2026-04-13 | Seed lists scaled to 100 | `seeds/npm_top.txt` and `seeds/pypi_top.txt` expanded to 100 packages each (attack-relevant + foundational) |
| 2026-04-13 | Gap #5 closed — PyPI per-version enrichment | `enrich_version` hook in `sources/pypi.py` fetches per-version JSON for publisher_email/dependencies/source_repo_url; wired into collector delta path |
| 2026-04-13 | Gap #6 closed — PyPI install-scripts detection | `sources/pypi_tarball.py` streams sdist (150MB cap), AST-walks setup.py for dangerous imports/os calls/cmdclass; ~30% of pypi versions flagged True |
| 2026-04-13 | DB fill-NULL UPDATE helper | `db.update_version_fill_nulls` — COALESCE-protected narrow UPDATE, append-only invariant preserved; CLAUDE.md invariant #1 amended |
| 2026-04-13 | PyPI historical backfill — publisher/deps | `backfill_pypi.py` run in tmux: 12,183 rows filled, 0 errors, 20 min. Final coverage 11,630/19,541 = 59% (remaining 7,911 NULL because PyPI authors didn't publish an email — data-source limit) |
| 2026-04-13 | PyPI historical backfill — tarballs | `backfill_pypi_tarballs.py` run in tmux: 17,641 rows filled, 0 errors, 75 min. Final `has_install_scripts` coverage: 100%; 5,866 flagged true (~30%) |
| 2026-04-13 | P1: lifecycle detection (yank / deprecation / vanish) | Schema: added `last_seen_at, deprecated_at, deprecated_reason, yanked_at, yanked_reason, vanished_at` to `versions` + new `version_events` table. Parsers: npm `deprecated`, pypi per-file `yanked`/`yanked_reason`. db helpers: `bulk_mark_seen`, `apply_lifecycle` (write-once COALESCE on `*_at`), `mark_vanished`. CLAUDE.md invariant #1 amended. Validated on test seeds: `request`/`left-pad`/`bower`/`ua-parser-js` = 299 deprecation events; `setuptools`/`pip`/`urllib3`/`numpy`/`cryptography` = 21 yank events (with real reasons). Idempotent on re-run. |
| 2026-04-13 | P2.1: versions-table extensions + fill-NULL backfill | Schema: added 16 columns to `versions` (`integrity_hash`, `git_head`, `dev/peer/optional/bundled_dependencies` + counts, `publisher_tool`, `publisher_maintainer`, `publisher_maintainer_email`, `maintainers`, `license_text`, `license_expression`). Parsers: npm `_parse_single_version` extracts all dist-group data + maintainers[] + `_npmVersion`; pypi `parse_versions` + `parse_version_detail` extract maintainer/license from `info` block. `db.update_version_fill_nulls` extended with all new fillable columns + new JSONB set. `collector._fill_existing_versions` wired into the in-loop pass so hourly runs backfill historical rows via COALESCE. New `backfill_pypi_p21.py` (resumable id-cursor, same pattern as P1 backfill) ran 19,459 rows in 32 min, 0 errors, 0 not_found. **Final coverage**: npm 50,419 rows — integrity_hash 99.99%, maintainers 99%, publisher_tool 92%, git_head 70%, dev_deps 66%, peer_deps 37%. pypi 19,541 rows — license (either field) 91%, license_text 88%, license_expression 3%, publisher_maintainer 6%, publisher_maintainer_email 9%. Remaining pypi maintainer NULLs are data-source limit (authors didn't populate the field). |
| 2026-04-13 | P2.2: `version_files` child table + parsers + collector wiring + history backfill | Schema: new `version_files` table with per-file hash/size/uploaded_at/packagetype/python_version/yanked + PEP 740 attestation columns (`attestation_present` tri-state nullable, `attestation_publisher` JSONB, `attestation_bundles` JSONB, `attestation_fetched_at`) + lifecycle (`first_observed_at`, `last_seen_at`, `vanished_at`) + `UNIQUE (version_id, filename)` + 3 indexes. Parsers: `pypi._parse_files` emits one row per sdist/wheel; `npm._synthesize_files` emits single tarball row per version. `db.insert_version_if_new` now returns `int|None` (the new id) so children can be written in the same transaction. New db helpers: `insert_version_file_if_new`, `update_file_fill_nulls` (COALESCE-protected), `bulk_mark_files_seen`, `mark_files_vanished`, `apply_file_yank`, `existing_version_ids`, `existing_file_names`. `collector._write_new_versions` inserts children inline; `_fill_existing_versions` handles new-wheel insert + fill-null + mark-seen + mark-vanished per version. `backfill_version_files.py` reconstructs files[] from each version's captured `raw_metadata` with no HTTP cost: 19,379 pypi versions + 50,068 npm versions processed in 7.2 min, **181,240 total file rows inserted** (130,817 pypi at ~6.7 files/version + 50,423 npm at 1 file/version). 162 pypi versions stayed childless (raw_metadata was truncated at original fetch; would require re-fetch to recover). |
| 2026-04-13 | P4: collector cadence 1h → 15m | Updated both timer units: npm `OnCalendar=*:00,15,30,45`, pypi `OnCalendar=*:07,22,37,52` (7-minute offset to prevent DB contention). `RandomizedDelaySec` dropped from 60→30. Installed, daemon-reloaded, both timers restarted cleanly. Next firings verified: npm 22:15, pypi 22:22. First new-cadence pypi run (22:10) fired and completed without error. Prior hourly runs preserved in `collector_runs` history. |
| 2026-04-13 | P3: OSV advisory ingest | Schema: extended `attack_labels` with `advisory_id`, `aliases`, `severity`, `summary`, `affected_range`, `url`, `raw_advisory`, `modified_at`, `first_seen_at` + partial UNIQUE `(advisory_id, package_id)`. New `collector/sources/osv.py` wraps `/v1/querybatch` + `/v1/vulns/{id}` with 2-stage fetch, `is_malicious` heuristic (MAL-* / summary / CWE-506), `parse_severity`, `_format_ranges` (collapses OSV events to semver). New `db.upsert_attack_label` — INSERT/ON CONFLICT keyed on partial unique index, refreshes mutable fields, preserves `first_seen_at`. New `collector/backfill_advisories.py` — one querybatch POST for all 209 seeds → 922 unique advisories → concurrent fetch @ 10 rps → per-vuln ingest. **Run results**: 922 advisories fetched in 112s, 0 errors, 922 rows inserted, 11 flagged malicious. Validated: axios (12 entries: NO_PROXY SSRF CRIT + MAL-2026-2307 + 10 others with correct ranges), ua-parser-js (GHSA-pjwm-rvh2-c87w malware 0.7.29-0.7.30), event-stream (GHSA-mh6f-8j2x-4483), chalk/debug/rc/coa/node-ipc/eslint-config-prettier all present. pypi=716 rows (0 malware — tight seed excludes known pypi attacks by design, ctx/phpass are unpublished). npm=206 rows including 11 malware. |
| 2026-04-13 | P2.2: PEP 740 attestation fetcher + subset validation | New `collector/sources/pypi_attestations.py` uses `/integrity/{name}/{version}/{filename}/provenance` endpoint (not the sparse `urls[].provenance` which returns None even for trusted-publishing packages). Validated live on `packaging@26.0` (wheel+sdist) and `urllib3@1.26.0` (expected 404). `backfill_attestations.py --subset` against 19 known trusted-publishing packages: 15,730 files visited in 26 min, **3,238 true hits (21%)**, 12,492 false, 0 errors. 17 of 19 seed packages have attestations — cryptography (865), charset-normalizer (747), numpy (654), pydantic (439), pandas (288), ... (iniconfig, pluggy don't yet use Trusted Publishing). Publisher signal consistent: one GitHub repo per package, workflow names like `pypi-publish.yml` / `publish.yml`. Full backfill against remaining ~115K pypi files launched in tmux. |
