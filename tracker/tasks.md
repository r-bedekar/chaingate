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
| P5     | Week 2-3: npm proxy + gates                                                                | in progress  | —          |
| P5.0   | Design lock — `docs/P5.md` replaces P5_updated.md                                          | done         | 2026-04-14 |
| P5.1   | `witness/db.js` (better-sqlite3) + schema + unit tests                                     | done         | 2026-04-14 |
| P5.2   | Seed export + Ed25519 signing + Node verifier                                              | done         | 2026-04-14 |
| P5.3   | Proxy passthrough on undici (port 6173)                                                    | done         | 2026-04-14 |
| P5.4   | Observe + first-seen pipeline (`witness/store.js`, wiring into proxy)                      | done         | 2026-04-15 |
| P5.5   | Gate runner + packument rewriter (`gates/index.js`, `gates/rewriter.js`, tarball gate)     | done         | 2026-04-15 |
| P5.6   | Gates 1-3: content-hash, publisher-identity, dep-structure                                 | done         | 2026-04-15 |

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
| 2026-04-14 | P5.0: design lock | Wrote `docs/P5.md` (~600 lines, 16 sections) replacing `P5_updated.md` as single source of truth. Locked 11 decisions: Node 22 + better-sqlite3, GH Release seed asset, Ed25519 embedded pubkey, packument rewrite (not 403) for BLOCK, downgrade `dist-tags.latest`, content-hash narrowed to same-version re-publish detection + new SKIP result, WARN threshold raised to 4, live override, synthesized Trivy fixture, empty gate_decisions on init, strict pypi/merkle deferral. 11-day build plan (P5.1→P5.10) baked in. |
| 2026-04-14 | P5.3: proxy passthrough on undici (port 6173) | Wrote `proxy/config.js` (env-var loader with defaults: port 6173, host 127.0.0.1, upstream registry.npmjs.org, headers timeout 10s, body timeout 30s, witness DB path `~/.chaingate/witness.db`). Wrote `proxy/registry.js` (`fetchPackument` / `fetchTarball` on `undici.request`, typed `UpstreamTimeoutError` + `UpstreamError`, relays `authorization` / `if-none-match` / `if-modified-since` upstream, forces scoped names to `%40scope%2Fname` form so upstream always sees canonical URL). Wrote `proxy/server.js` (`createProxyServer` factory taking overrides, `classify()` URL router that distinguishes packument vs tarball for scoped/unscoped, streams upstream body via `stream.pipeline`, returns 304/204 with drained body, typed error → 504/502/500 JSON, 405 on non-GET/HEAD, 404 on unknown route, graceful SIGINT/SIGTERM shutdown when run directly). Wrote `test/proxy/passthrough.test.js` — 18 tests using a local `node:http` fake upstream: encodePackageName unit tests (3), classify unit tests (6), end-to-end passthrough (unscoped packument 200, scoped `@babel/core` → `%40babel%2Fcore` upstream URL, binary tarball, 304 relay, 404 relay, 504 on upstream headers-timeout, `Authorization` forwarding, unknown route 404, non-GET 405). All 18 pass in 1.28s. **Smoke test**: started proxy on :6173, `cd /tmp/cg-smoke && npm --registry http://127.0.0.1:6173 install axios@1.7.9` → 23 packages installed in 2.23s, axios package.json reports 1.7.9. Full test suite now 39/39 (12 db + 9 seed_verify + 18 proxy). |
| 2026-04-14 | P5.2: seed export + Ed25519 signing | Generated Ed25519 keypair out-of-tree at `~/.chaingate-signing/` (`chmod 0400` priv, `0444` pub). Pubkey fingerprint `ed25519:09f6c9fdb8f5a2ea` committed to `collector/signing/pubkey.pem` + README; privkey never leaves VPS. Wrote `collector/export_seed.py` (~370 lines): read-only PG transaction → fresh SQLite with V1 npm-only schema from P5.md §4 → copies 104 packages + 50,442 versions (bool→0/1, deps JSON serialized, timestamps→ISO-UTC) + 50,442 version_files (drops raw_metadata/attestation_*/python_version/yanked/vanished) → writes `seed_metadata` rows (schema_version, seed_version, exported_at, source_host, row counts, fingerprint, SPKI b64) → VACUUM+PRAGMA optimize. Then sha256(db) → `.sha256`, Ed25519 sign of sha256 hex bytes → `.sig` (64 raw bytes), JSON `.manifest.json`. First real export: 105MB, sha `d2622aea…`, ~5s. Wrote `witness/seed_verify.js` (~115 lines) with embedded `CHAINGATE_SEED_PUBKEY_B64` literal + `sha256File` streaming helper + `verifySeed` that enforces hash match THEN Ed25519 sig via `node:crypto.verify(null,…)` on SPKI DER pubkey; throws typed `SeedVerificationError` with codes (`SEED_HASH_MISMATCH`, `SEED_SIG_INVALID`, `SEED_SIG_MALFORMED`, `SEED_SHA256_MALFORMED`). Wrote `test/witness/seed_verify.test.js` (9 tests): happy path w/ throwaway keypair, tamper db bytes → hash mismatch, random 64-byte sig → sig fail, tamper+rehash (keeping old sig) → sig fail (key binding), sign-with-wrong-key → sig fail, malformed sha256 → code SEED_SHA256_MALFORMED, wrong-length sig → code SEED_SIG_MALFORMED, sha256File determinism, **real 105MB bundle verified against embedded pubkey end-to-end**. Combined witness suite 21/21 pass in 567ms. `gh` CLI not installed on VPS → bundle produced but upload deferred until user installs gh or uploads manually from seed_export/. |
| 2026-04-14 | P5.1: `witness/db.js` + schema + unit tests | Wrote `witness/db.js` (WitnessDB class wrapping better-sqlite3, WAL mode, prepared statements). Schema from P5.md §4: packages, versions, version_files, gate_decisions, overrides, seed_metadata + 6 indexes. API: createSchema, getBaseline (joins version_files, decodes JSON columns), getHistory (newest-first by published_at), recordBaseline (transactional, INSERT OR IGNORE + write-once bump on last_seen_at), insertGateDecision (append-only), getOverride / insertOverride (UPSERT on conflict), getSeedMetadata / setSeedMetadata. Boolean → 0/1 coercion. JSON columns auto-encoded on write / decoded on read. Installed Node 22.22.2 via nvm (home-dir, no sudo). `npm install` → 39 packages including `better-sqlite3@11.x`, `undici@6.x`, `semver@7.x`. Unit tests: 12/12 pass in 316ms with hand-built axios@1.7.9 fixture covering round-trip, idempotency, last_seen_at bump, newest-first history, append-only decisions, CHECK constraint on disposition, override upsert, seed_metadata round-trip. |
| 2026-04-13 | P2.2: PEP 740 attestation fetcher + subset validation | New `collector/sources/pypi_attestations.py` uses `/integrity/{name}/{version}/{filename}/provenance` endpoint (not the sparse `urls[].provenance` which returns None even for trusted-publishing packages). Validated live on `packaging@26.0` (wheel+sdist) and `urllib3@1.26.0` (expected 404). `backfill_attestations.py --subset` against 19 known trusted-publishing packages: 15,730 files visited in 26 min, **3,238 true hits (21%)**, 12,492 false, 0 errors. 17 of 19 seed packages have attestations — cryptography (865), charset-normalizer (747), numpy (654), pydantic (439), pandas (288), ... (iniconfig, pluggy don't yet use Trusted Publishing). Publisher signal consistent: one GitHub repo per package, workflow names like `pypi-publish.yml` / `publish.yml`. Full backfill against remaining ~115K pypi files launched in tmux. |
| 2026-04-15 | P5.6: Gates 1-3 (content-hash, dep-structure, publisher-identity) | Wrote `gates/content-hash.js` (Gate 1, BLOCK): zero-FP-by-construction — SKIPs on any data gap (null baseline, missing baseline hashes, missing incoming hashes, asymmetric hash algorithms); compares integrity (sha512) when both sides have it, falls back to shasum (sha1); ALLOWs integrity match even with sha1 drift (annotates re-shasum); BLOCKs only on real hash delta with truncated old→new in detail. Wrote `gates/publisher-identity.js` (Gate 3, WARN): history-driven (not baseline-driven), filters incoming-version self-entry out of history to handle re-observation, case-insensitive + whitespace-trimmed email compare, SKIPs on empty history / data gaps, WARNs on real email delta with prior version pinned in detail. Wrote `gates/dep-structure.js` (Gate 2, WARN): compares incoming `dependencies` against the UNION of dependencies across ALL prior versions (so re-adopting an old dep doesn't fire), filters current version from history, SKIPs when no prior exists, alphabetizes and truncates the new-dep list at 5 names with `+N more` suffix, ignores dev/peer/optional/bundled deps by design. Updated `gates/index.js` DEFAULT_GATE_MODULES from `[]` to `[contentHash, depStructure, publisherIdentity]`. Tests: `test/gates/content-hash.test.js` 12/12, `test/gates/publisher-identity.test.js` 13/13, `test/gates/dep-structure.test.js` 15/15. Updated `test/gates/runner.test.js` DEFAULT_GATE_MODULES assertion from empty-check to name-inclusion. **Full suite 162/162** green. **Smoke A (real npm first-seen)**: started proxy on :16175 with fresh DB, fetched axios packument → 132 baselines recorded, all ALLOW, all three gates firing on each version (content-hash SKIP first-seen, dep-structure SKIP no-prior, publisher-identity SKIP no-prior). **Smoke B (tamper)**: UPDATEd `integrity_hash` on axios@1.7.9 baseline to `sha512-TAMPERED_BY_SMOKE_TEST==`, re-fetched packument — rewritten body dropped from 132 to 131 versions (1.7.9 stripped), new BLOCK decision row appended with content-hash BLOCK + dep-structure ALLOW (131 priors) + publisher-identity WARN. Tarball request for `axios-1.7.9.tgz` returned HTTP 403 with full `blocked_by_chaingate` body including gate evidence. End-to-end P5.6 flow confirmed against real npm registry. |
