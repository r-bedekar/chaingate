# SUPPLY CHAIN INTEGRITY WITNESS — PROJECT BRIEF v2

**Author:** Rizwan  
**Date:** April 8, 2026  
**Updated:** April 8, 2026 (post-review revision)  
**Status:** Pre-build — Architecture finalized, ready to start  
**Classification:** CONFIDENTIAL — Do not share publicly before IP strategy decided

---

## 1. ORIGIN — THE INSIGHT

On March 31, 2026, the Axios npm package (~100M weekly downloads) was compromised by UNC1069 (North Korean state actor, also tracked as Sapphire Sleet). A stolen long-lived npm token was used to publish two malicious versions (1.14.1 and 0.30.4) that injected a phantom dependency (`plain-crypto-js`) delivering a cross-platform RAT. The attack was live for ~3 hours before removal.

Every defense existed — Socket detected it in 6 minutes, npm provenance data showed the anomaly, `ignore-scripts` would have blocked it, version pinning would have prevented it. None of these were the default. The attack succeeded because protection is opt-in, not enforced.

This is the same pattern across three major supply chain attacks in early 2026:

| Attack | Vector | Why defenses failed |
|--------|--------|-------------------|
| **Axios** (Mar 31) | Stolen npm token, phantom dependency, postinstall RAT | Provenance verification is opt-in. No registry gate rejected it. |
| **Trivy** (Mar 19) | Force-pushed 76/77 GitHub Action tags to malicious commits | Mutable tags trusted by default. No content verification. |
| **Notepad++** (Jun-Dec 2025) | Hosting provider compromised, update traffic redirected | No independent binary verification. Updater trusted server blindly. |

**The common root cause:** Enterprises blindly trust everything vendors deliver. Existing tools catch KNOWN threats (CVEs, malware signatures). Nobody catches UNKNOWN threats that exhibit structural anomalies — during the zero-day window before any intelligence database has been updated.

---

## 2. WHAT EXISTS TODAY — FULL LANDSCAPE

### Intelligence-based tools (catch KNOWN threats):

| Tool | What it does | Detection method | Zero-day window gap? |
|------|-------------|-----------------|---------------------|
| **JFrog Curation** | Blocks packages matching CVE DB, malware signatures, license policies | Known threat intelligence | YES — empty DB during zero-day window |
| **Sonatype Repository Firewall** | Quarantines suspicious components using proprietary AI + research team intelligence | AI heuristics + proprietary intelligence | PARTIAL — AI may flag, depends on model |
| **JFrog Xray** | Scans binaries for vulnerabilities post-storage | CVE database matching | YES — post-publish detection only |
| **Socket Firewall** | Install-time blocking via behavioral code analysis | Static code analysis + 70+ behavioral signals | MINIMAL — caught Axios in 6 minutes |
| **Snyk** | SCA scanning, CVE matching, fix PRs | CVE database + reachability | YES — post-advisory only |
| **npm audit** | Known advisory matching | Advisory database | YES — post-advisory only |
| **npm provenance** | Attestation of build process | OIDC + Sigstore | Not a gate — opt-in, informational only |
| **npm release-age gating** (v11.10+) | Consumer-side cooldown | Time-based | Opt-in consumer config |

### Infrastructure tools (artifact repositories):

| Tool | Role | Supply chain security? |
|------|------|----------------------|
| **JFrog Artifactory** | Enterprise artifact proxy, cache, storage for npm/Docker/PyPI/Maven | Proxy + storage. Security via Curation/Xray add-ons (intelligence-based). |
| **Sonatype Nexus Repository** | Enterprise artifact proxy, cache, storage | Proxy + storage. Security via Repository Firewall add-on (intelligence-based). |
| **Verdaccio** | Lightweight npm proxy (open source) | Proxy + cache only. No security intelligence. |

### Transparency / attestation infrastructure:

| Tool | What it does | Gap |
|------|-------------|-----|
| **Go sumdb** | Content-integrity transparency log with install-time gating | Go-only, Google-maintained |
| **Sigstore/Rekor** | Transparency log for signing events | Records WHO signed WHAT. Not a gate. Not content verification. |

### What genuinely doesn't exist:

1. **Historical baseline comparison against a package's own metadata profile** — "Is this package different from what it looked like yesterday?"
2. **Content-integrity verification across non-Go ecosystems** (Go sumdb model for npm/Docker/PyPI)
3. **Deterministic structural gating without external intelligence** — binary pass/fail based on the package's own history
4. **Publish-pattern anomaly detection** — analyzing the publish EVENT metadata, not the code
5. **Free, open-source, self-hosted supply chain gating** for air-gapped/regulated environments

---

## 3. THE PRODUCT — SUPPLY CHAIN INTEGRITY WITNESS

### One-line description:
A self-hosted intelligence layer that catches what JFrog, Sonatype, and Socket miss — zero-day supply chain attacks during the window before any intelligence database has been updated.

### Core philosophy:
JFrog and Sonatype ask: "Is this package in our database of known-bad things?"
The Witness asks: "Is this package different from what it looked like yesterday?"

### Architecture (three layers):

**Layer 1 — WITNESS (Memory)**
Append-only transparency log recording content hashes, package metadata profiles (deps, publisher, provenance, publish method) for every observed package version. Merkle tree ensures tamper-evidence. This is the system's memory — it knows what every package looked like historically.

**Layer 2 — GATES (Deterministic Rules)**
Six checks applied before every install:

| Gate | What it checks | Default action | False positive risk |
|------|---------------|----------------|-------------------|
| **Content Hash** | Does hash match first-observed state for this version? | **BLOCK** | Zero — content was literally replaced |
| **Dep Structure** | Did dependency tree change unexpectedly? | WARN | Medium — legitimate refactors happen |
| **Publisher Identity** | Did publisher email/identity change? | WARN | Medium — maintainers change emails |
| **Provenance Continuity** | Did publish method change (OIDC → CLI)? | WARN | Low — method changes are rare |
| **Release Age** | Is version less than N hours old? | WARN | Low — configurable threshold |
| **Scope Boundary** | Absolute limits (new dep from unknown publisher + postinstall scripts) | WARN | Low — specific combinations only |

**CRITICAL DEFAULT BEHAVIOR:** Only content hash mismatch triggers BLOCK. All other gates WARN by default. Developers can override with `scw allow <package>@<version> --reason "legitimate change"`. Enterprise customers can escalate warnings to blocks per policy.

**Layer 3 — ANOMALY MODEL (ML Intelligence)**
Trained on historical npm registry data + labeled attack samples (Axios, Shai-Hulud 500+ packages, CanisterWorm 135+ packages, event-stream, ua-parser-js). Isolation Forest for unsupervised anomaly detection on publish patterns. Added in Month 3-4 as an intelligence layer on top of deterministic gates.

### Disposition output:
- **ALLOW** — all checks pass, serve package normally
- **WARN** — gate anomaly detected, serve but log alert with explanation
- **QUARANTINE** — multiple signals or high anomaly score, hold for manual review
- **BLOCK** — content hash mismatch, refuse install with explanation

### Two deployment modes:

**Mode 1: Standalone proxy** (for teams without Artifactory/Nexus)
- Lightweight Verdaccio-based npm proxy
- Target: individual developers, small teams, open-source users
- Free tier

**Mode 2: Integration layer** (for enterprises with existing artifact repos)
- Plugin/webhook for JFrog Artifactory or Sonatype Nexus
- Witness provides detection intelligence; existing repo handles proxying
- No proxy maintenance burden — JFrog/Sonatype handle infrastructure
- Enterprise tier (paid)

---

## 4. ATTACK COVERAGE

**Honest estimate: 70-80% of known npm supply chain attack patterns.**

| Attack pattern | Detection method | Disposition | Confidence |
|---------------|-----------------|-------------|------------|
| **Axios** (phantom dep + publisher change + provenance break) | 4 deterministic gates fire simultaneously | BLOCK (multiple warnings escalate) | HIGH |
| **Trivy** (tag force-pushed to malicious commit) | Content hash mismatch | BLOCK | VERY HIGH |
| **Notepad++** (binary replaced via server hijack) | Content hash mismatch | BLOCK | VERY HIGH |
| **Shai-Hulud** (500+ packages via stolen tokens) | Multiple publisher changes + ML burst detection | WARN/BLOCK | HIGH |
| **CanisterWorm** (worm propagation via npm) | Structural changes + publisher changes | WARN/BLOCK | HIGH |
| **eslint-config-prettier** (account takeover) | Publisher change + structural change | WARN | HIGH |
| **Sophisticated** (same pipeline, same structure, bad code only) | **Gates pass — not detected** | ALLOW (false negative) | NOT COVERED |

**Explicit blind spot:** A compromised maintainer who publishes malicious code through the exact same CI/CD pipeline, with the same dependencies, same publisher identity, same provenance — only changing code inside existing files. This requires code-level analysis (Socket's domain). We are complementary to code analysis tools, not a replacement.

---

## 5. COMPETITIVE POSITIONING

### How we differ from every tool in the landscape:

| Dimension | JFrog Curation | Sonatype Firewall | Socket | **Witness** |
|-----------|---------------|-------------------|--------|------------|
| Detection method | Known CVE + malware DB | Proprietary AI + intel | Behavioral code analysis | **Historical baseline comparison** |
| Zero-day window | Blind until DB updated | Partial (AI may catch) | Fast (6 min for Axios) | **Immediate (structural)** |
| Requires external intelligence | Yes | Yes | Yes (threat feeds) | **No — self-contained** |
| Self-hosted / air-gapped | Yes (expensive) | Yes (expensive) | No (cloud/CLI) | **Yes (free/lightweight)** |
| Open source | No | No | CLI only | **Yes (Apache 2.0 core)** |
| KSA compliance mapping | No | No | No | **Yes (NCA ECC, SAMA CSF)** |
| Cost | $$$$$ | $$$$$ | Free CLI / $$ enterprise | **Free / $ enterprise** |

### What we say:
"JFrog and Sonatype catch known threats. Socket catches behavioral anomalies in code. We catch unknown threats that exhibit structural anomalies — during the zero-day window before any intelligence database has been updated. Different detection method. Complementary value."

### What we never say:
- ❌ "We replace JFrog/Sonatype/Socket"
- ❌ "We invented supply chain security"
- ❌ "We catch 90-95% of attacks"
- ❌ "No supply chain gates exist today"

### What we claim:
- ✅ "Catches what intelligence-based tools miss during the zero-day window"
- ✅ "Deterministic baseline verification — no threat feeds required"
- ✅ "Free, open-source, self-hosted supply chain gating"
- ✅ "Works standalone or alongside your existing Artifactory/Nexus"
- ✅ "NCA ECC and SAMA CSF compliance-mapped for KSA enterprises"

---

## 6. CONNECTION TO FILED PATENT

### Patent: "Preemptive Behavioral Validation of Non-Executable Vendor-Delivered Payloads"
**Status:** Provisional drafted, ready to file
**Scope:** Non-executable security content (CrowdStrike channel files, AV signatures, Palo Alto threat content, IDS rule packs) validated through native host-app ingestion + behavioral delta analysis

### Witness: "Supply Chain Integrity Verification of Software Distribution Payloads"
**Status:** Pre-build
**Scope:** Software packages (npm, Docker, PyPI, binaries) validated through metadata/hash comparison against historical baselines

### Shared philosophy:
"Never trust vendor-delivered content. Validate before production."

### How they differ:

| Dimension | Patent | Witness |
|-----------|--------|---------|
| Payload type | Non-executable (channel files, signatures) | Installable (packages, images, binaries) |
| Method | Native ingestion in reference instance | External metadata/hash comparison |
| Depth | Deep (kernel/hypervisor telemetry) | Lighter (registry API metadata) |
| Infrastructure cost | High (VMs per vendor) | Low (VPS + database) |
| Vibecode-able | Hard | Yes |
| Build timeline | Long-term | Months 1-6 |

### Shared elements:
- Behavioral baseline construction from historical observations
- Scope boundary rules triggering immediate escalation
- ALLOW / QUARANTINE / BLOCK disposition model
- Pre-production gating philosophy
- Customer-controlled, no vendor cooperation needed

### IP strategy:
1. File existing patent provisional (vendor security content) — establishes priority date
2. Build the Witness — proves the concept, lighter implementation
3. Consider second provisional for Witness method — before public disclosure
4. Long-term: unified platform covering both payload classes

**CRITICAL: Do not publish the Witness concept publicly (blog, GitHub, Black Hat) before deciding on provisional filing for the Witness method specifically.**

---

## 7. BUSINESS MODEL

### Open-source core (Apache 2.0):
- Standalone npm proxy with deterministic gates + CLI + audit log + Merkle tree
- Target: individual developers, small teams
- Adoption flywheel: developers use free tool → CISO asks about compliance → enterprise sale

### Enterprise tier (paid):

| Feature | Why they pay |
|---------|-------------|
| Artifactory/Nexus integration (Mode 2) | Works with existing infrastructure |
| Compliance reports (NCA ECC, SAMA CSF, SOC 2, ISO 27001) | Regulators require evidence |
| SIEM integration (Splunk, Sentinel, QRadar) | SOC workflow integration |
| LDAP/AD integration | Org-level policy management |
| Multi-ecosystem (Docker + PyPI) | Enterprise uses more than npm |
| Anomaly model (trained weights) | Intelligence beyond deterministic gates |
| SLA + priority support | "If proxy goes down, builds stop" |

### Pricing:
| Tier | Target | Price |
|------|--------|-------|
| Open Source | Individual devs, small teams | Free |
| Team | Dev teams (5-20) | $200-500/month |
| Enterprise | Banks, gov, energy | $2,000-5,000/month |
| On-prem deployment | Air-gapped | $10,000-25,000 one-time + annual support |

### Revenue projection (conservative, post-review revision):
- Month 1-6: $0 (building + open source launch)
- Month 6-12: $0-2,000 (community growth, consulting from credibility)
- Month 12-18: $2,000-5,000 (enterprise pilots, consulting engagements)
- Month 18-24: $10,000-25,000 (first enterprise conversions)

### Market advantages:
- Based in Riyadh — local presence for KSA enterprises
- NCA ECC / SAMA CSF compliance mapping — no competitor offers this
- On-prem / air-gapped deployment — JFrog/Sonatype Cloud can't serve these environments; self-managed JFrog costs significantly more
- Patent-pending deeper IP — signals seriousness to enterprise buyers
- Free and open source — JFrog Curation and Sonatype Firewall are enterprise-priced ($$$$$)
- Arabic documentation — trivial to add, massive KSA differentiator

---

## 8. TECH STACK

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| npm proxy (Mode 1) | Node.js (Verdaccio-based or custom) | npm ecosystem native |
| Artifactory/Nexus plugin (Mode 2) | Depends on platform API | Enterprise integration |
| Docker proxy | Go or Node.js | OCI spec compliance |
| PyPI proxy | Python | Native ecosystem |
| Storage (dev) | SQLite | Zero-config for individuals |
| Storage (team/enterprise) | PostgreSQL | Scalable, already on VPS |
| Merkle tree | merkle-tools (JS) or custom | Append-only log integrity |
| CLI | Node.js | `npm install -g` friendly |
| Anomaly model | Python + scikit-learn | Isolation Forest, vibecode-friendly |
| Dashboard | React | Known stack |
| Data collector | Python | Polls npm registry, stores baselines |
| Compliance reports | Python + ReportLab | PDF generation |
| Deployment | Docker Compose / Helm | Enterprise standard |

---

## 9. BUILD ROADMAP

### Month 1-2: Foundation
- npm registry proxy (Mode 1) with content hash verification
- 6 deterministic gates (hash, structure, publisher, provenance, release age, scope boundary)
- CLI tool (`scw init`, `scw status`, `scw allow`)
- SQLite/PostgreSQL audit log
- Data collector running on VPS (started Day 1)
- **Ships:** Usable by individual developers

### Month 3-4: Intelligence
- Merkle tree for append-only transparency log
- Anomaly detection model (Isolation Forest on publish patterns)
- Docker registry proxy
- Org-specific baselines
- Docker Compose deployment
- **Ships:** Open source launch + team tier

### Month 5-6: Enterprise
- Artifactory/Nexus integration (Mode 2)
- Web dashboard
- SIEM connectors (Splunk, Sentinel, QRadar)
- Compliance report generator (NCA ECC, SAMA CSF)
- PyPI proxy
- Kubernetes Helm chart
- LDAP/AD integration
- **Ships:** Enterprise pilots in KSA

### Month 7+: Platform
- Binary update verification (Notepad++ pattern)
- GitHub Actions integrity verification
- Cross-package correlation (graph-based ML)
- Attack signature matching (supervised model)
- Patent integration (unified platform narrative)
- **Ships:** Black Hat MEA demo + enterprise conversations

---

## 10. ADOPTION STRATEGY

### Pre-launch (before code ships):
1. LinkedIn "Axios Autopsy" post — validate interest before building
2. Data collector running on VPS — building training data

### Launch (Month 3-4):
3. Open source on GitHub with sharp README ("The tool that would have blocked Axios")
4. Demo GIF showing blocked install in terminal
5. Retroactive attack test results (Axios, Trivy, Shai-Hulud)
6. Hacker News "Show HN" post
7. Reddit r/netsec + r/node posts
8. Dev.to technical deep-dive

### Growth (Month 4-6):
9. OWASP Riyadh chapter presentation
10. LinkedIn thought leadership (ongoing)
11. Black Hat MEA Arsenal submission (CFP deadline August 31)

### Enterprise (Month 6+):
12. Direct outreach to CISOs via existing Saudi Energy network
13. Free enterprise pilots
14. Conference visibility (Black Hat MEA December 2026)

### Adoption targets:
- 500 GitHub stars by Month 6 (credibility threshold for enterprise buyers)
- 3-5 enterprise pilots by Month 9
- First paid enterprise customer by Month 18-24

---

## 11. RISK ASSESSMENT (POST-REVIEW)

| Risk | Severity | Mitigation |
|------|----------|------------|
| JFrog/Sonatype already occupy the proxy slot | Medium | Mode 2 integration positions as enhancement, not replacement |
| False positive fatigue kills adoption | High | WARN by default, BLOCK only on hash mismatch. Easy override. |
| Proxy maintenance is hard | High | Mode 2 eliminates this for enterprise. Mode 1 kept lightweight. |
| Enterprise sales take 18+ months | High | Revenue timeline revised. Consulting and credibility bridge the gap. |
| Socket adds baseline features | Medium | Different architecture (code analysis vs metadata comparison). Speed matters. |
| npm ships native gating | Medium | Cross-ecosystem story (npm + Docker + PyPI) differentiates. |
| Solo founder bandwidth | Medium | ZeroinSEC and English App paused. Evenings/weekends dedicated. |
| 70-80% coverage leaves 20-30% blind spot | Medium | Honestly documented. Positioned as complementary to code analysis tools. |
| Nobody adopts the open-source version | Medium | LinkedIn post validates interest before building. Axios timing helps. |

---

## 12. EXPENSES (6 MONTHS)

| Category | Amount |
|----------|--------|
| **Essential** (domain name only) | $12-15 |
| **Recommended** (domain + small VPS + branding) | $50-75 |
| **With patent filing** (existing provisional) | $210-235 |
| **Maximum** (all above + Witness provisional + better VPS) | $400-500 |

Time investment: ~250 hours over 6 months (evenings + weekends)

---

## 13. IMMEDIATE ACTIONS

### Tonight:
1. Deploy data collection script on Hostinger VPS

### This week:
2. Write LinkedIn "Axios Autopsy" post (validate interest)

### This weekend:
3. Set up project repository
4. Initialize npm proxy with basic registry forwarding
5. Implement content hash recording

### Week 2-4:
6. Implement remaining 5 gates
7. CLI tool with clear pass/fail output
8. Test against Axios/Trivy attack data retroactively

---

## 14. LEGAL / IP CHECKLIST

- [ ] File existing patent provisional (vendor security content validation)
- [ ] Consider second provisional for Witness method — before public disclosure
- [ ] Calendar non-provisional deadline (12 months from filing)
- [ ] Do NOT publish Witness concept publicly until IP strategy decided
- [ ] License: Apache 2.0 for open-source core confirmed
- [ ] Engage patent attorney within 6-8 months for non-provisional conversion

---

## 15. BLACK HAT MEA 2026

- **CFP Deadline:** August 31, 2026
- **Conference:** December 2026, Riyadh
- **Track:** Arsenal (tool demo)
- **Prerequisite:** Patent provisional(s) filed before submission
- **Demo:** Working Witness blocking simulated Axios-style attack live
- **Audience:** KSA CISOs, government security, banking security — target buyers

---

## 16. KEY DECISIONS PENDING

1. **Project name** — short, memorable, security-evocative
2. **Second provisional filing** — for Witness method specifically
3. **When to open-source** — after Month 2 (npm working) or Month 3-4 (with ML)?
4. **Standalone proxy vs Verdaccio fork** — architecture decision for Mode 1
5. **Artifactory/Nexus plugin API research** — needed for Mode 2

---

## CHANGELOG

**v2 (April 8, 2026):**
- Added JFrog Curation and Sonatype Repository Firewall to competitive landscape
- Revised coverage claim from 90-95% to 70-80%
- Changed default gate behavior: WARN by default, BLOCK only on content hash mismatch
- Added Mode 2 (Artifactory/Nexus integration layer) to architecture
- Revised enterprise revenue timeline to Month 18-24
- Repositioned from "proxy replacement" to "catches what intelligence-based tools miss"
- Added explicit blind spot acknowledgment (same-pipeline code injection)
- Added adoption strategy section
- Added full expense breakdown
- Added risk assessment incorporating reviewer feedback

---

*This document captures analysis from April 8, 2026. It is a living document — update as decisions are made and milestones are hit.*