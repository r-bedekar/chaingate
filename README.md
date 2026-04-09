# ChainGate

**Supply chain integrity gate that catches what threat intelligence misses.**

Every supply chain security tool asks: *"Is this package known to be bad?"*
ChainGate asks: *"Is this package different from what it looked like yesterday?"*

No threat feeds. No subscriptions. No cloud dependency. Self-hosted.

---

## The Problem

On March 31, 2026, axios@1.14.1 was published with a hidden RAT. 100M weekly downloads. 3-hour window. The npm registry metadata showed four red flags — new phantom dependency, publisher email changed, provenance disappeared, publish method flipped from OIDC to CLI token. None of this was surfaced to the developer at install time.

JFrog, Sonatype, Snyk — they catch **known** threats. CVEs in their database, malware in their signatures. During the zero-day window before any database is updated, they're blind.

ChainGate catches **unknown** threats that show structural anomalies — by remembering what every package looked like and telling you when something changed.

## How It Works

ChainGate sits between your developer (or CI pipeline) and the package registry. It records a baseline profile for every package version it sees — content hash, dependency structure, publisher identity, provenance status. Every subsequent install is compared against this baseline.

```
Developer → ChainGate proxy → upstream registry
                  ↓
          Compare against baseline
          Apply deterministic gates
          Score with anomaly model
                  ↓
          ✅ ALLOW  ⚠️ WARN  🚫 BLOCK
```

No AI required for the core gates. No threat intelligence feeds. Just: "this version is different from what I expect" → warn or block.

## What You See

```
$ npm install axios
✓ axios@1.14.0 — verified (hash match, 3 deps, OIDC provenance)

$ npm install axios@1.14.1
🚫 BLOCKED: axios@1.14.1
   ├── New dependency: plain-crypto-js (first published 18 hours ago)
   ├── Publisher email changed: gmail.com → protonmail.me
   ├── Provenance: NONE (previous 14 versions had OIDC attestation)
   └── Publish method: CLI token (previous versions via GitHub Actions)
   
   Run: scw allow axios@1.14.1 --reason "..." to override
```

## Gates

| Gate | What it checks | Default |
|------|---------------|---------|
| **Content Hash** | Does the hash match what was first observed for this version? | BLOCK |
| **Dep Structure** | Did the dependency tree change unexpectedly? | WARN |
| **Publisher Identity** | Did the publisher email/identity change? | WARN |
| **Provenance Continuity** | Did the publish method change (OIDC → CLI)? | WARN |
| **Release Age** | Is the version less than N hours old? | WARN |
| **Scope Boundary** | Absolute limits (phantom dep + install scripts) | WARN |

Content hash mismatch is the only hard block by default. Everything else warns. You decide what to escalate.

## Attack Coverage

| Attack | How ChainGate catches it |
|--------|------------------------|
| **Axios** (phantom dep + publisher change) | 4 gates fire simultaneously |
| **Trivy** (Git tag force-pushed) | Content hash mismatch |
| **Notepad++** (binary replaced via server hijack) | Content hash mismatch |
| **Shai-Hulud** (500+ packages via stolen tokens) | Publisher changes + anomaly model |

**Honest limitation:** If an attacker compromises the CI/CD pipeline and publishes through the same workflow with the same structure — only changing code — the metadata looks clean. For that you need code-level analysis (Socket, Snyk). ChainGate is complementary, not a replacement.

## Quick Start

```bash
npm install -g chaingate
scw init
npm install axios   # now routed through ChainGate
```

## Deployment Modes

**Mode 1: Standalone proxy** — lightweight, for individual devs and small teams.

**Mode 2: Integration layer** — plugin for JFrog Artifactory or Sonatype Nexus. Your existing repo handles proxying, ChainGate adds the intelligence.

## Ecosystem Support

| Ecosystem | Status |
|-----------|--------|
| npm | 🟢 Active |
| Docker Hub | 🟡 In progress |
| PyPI | 🟡 Planned |
| GitHub Actions | 🔵 Planned |
| Binary updates | 🔵 Planned |

## Architecture

```
┌─────────────────────────────────────────┐
│              CHAINGATE PROXY            │
│                                         │
│  ┌─────────────┐  ┌─────────────────┐  │
│  │   WITNESS    │  │      GATES      │  │
│  │   (Memory)   │  │  (Det. Rules)   │  │
│  │              │  │                 │  │
│  │ Content hash │  │ Hash verify     │  │
│  │ Pkg profiles │  │ Dep structure   │  │
│  │ Merkle tree  │  │ Publisher ID    │  │
│  │              │  │ Provenance      │  │
│  └──────┬───────┘  │ Release age     │  │
│         │          │ Scope boundary  │  │
│         │          └────────┬────────┘  │
│         │                   │           │
│         ▼                   ▼           │
│  ┌──────────────────────────────────┐   │
│  │        DECISION ENGINE           │   │
│  │   ALLOW / WARN / BLOCK           │   │
│  └──────────────────────────────────┘   │
│         │                               │
│         ▼                               │
│  ┌──────────────────────────────────┐   │
│  │    ANOMALY MODEL (optional)      │   │
│  │    Trained on historical attacks │   │
│  └──────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

## What Makes This Different

| | JFrog Curation | Sonatype Firewall | Socket | **ChainGate** |
|---|---|---|---|---|
| Detection | Known CVE + malware DB | Proprietary AI | Code analysis | **Historical baseline** |
| Zero-day window | Blind until DB updated | Partial | Fast (6 min) | **Immediate** |
| Needs external intel | Yes | Yes | Yes | **No** |
| Self-hosted | Yes (expensive) | Yes (expensive) | No | **Yes (free)** |
| Open source | No | No | CLI only | **Yes** |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. We welcome ecosystem connectors for new package registries.

## License

Apache 2.0 — see [LICENSE](LICENSE).

The open-source core includes all deterministic gates and the proxy infrastructure. The pre-trained anomaly model is available under a separate enterprise license.

---

*ChainGate catches what intelligence-based tools miss — during the zero-day window before any database has been updated.*
