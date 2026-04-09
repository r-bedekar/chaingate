# TASKS.md — ChainGate Development Tracker

Update this file as tasks are completed. Claude Code can read this to understand current progress and what's next.

## Current Phase: Month 1-2 (Foundation)

---

### Week 1: Project Setup + Data Collector

**Setup (do first — everything depends on this):**
- [ ] Create PostgreSQL database: `chaingate`
- [ ] Create database schema (packages, versions, gate_decisions, attack_labels tables)
- [ ] Initialize git repo with .gitignore, .env, README.md, CLAUDE.md
- [ ] Create project folder structure per CLAUDE.md
- [ ] First commit + push to GitHub (private repo)

**Data Collector — npm:**
- [ ] `collector/sources/npm.py` — fetch top 1000 npm packages by weekly downloads
- [ ] Parse npm registry response: extract deps, publisher, hashes, provenance, scripts, timestamps
- [ ] `collector/db.py` — database helpers (insert package, insert version, check if exists)
- [ ] `collector/collector.py` — main script that runs npm source, stores to PostgreSQL
- [ ] Test: run once manually, verify data in database
- [ ] Add to cron: hourly run

**Data Collector — PyPI:**
- [ ] `collector/sources/pypi.py` — fetch top 500 PyPI packages
- [ ] Parse PyPI JSON response: extract author, hashes, deps, upload time, size
- [ ] Add PyPI source to collector.py
- [ ] Test: run once, verify data

**Data Collector — Attack Labels:**
- [ ] `collector/sources/advisories.py` — fetch GitHub Advisory Database (supply chain tagged)
- [ ] `collector/sources/osv.py` — fetch OSV.dev malware-tagged entries
- [ ] Map advisories to packages/versions in database, insert into attack_labels table
- [ ] Test: verify Axios, Shai-Hulud entries are labeled

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
| | | |
