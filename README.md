> **Status: Active development — not ready for production use.**  
> Core witness architecture and proxy are functional. Sequence-aware
> pattern detection (V2) is in progress. Content-hash gate is the
> only active BLOCK gate. Other metadata gates are informational
> until V2 ships. Feedback welcome.

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
          ✅ ALLOW  ⚠️ WARN  🚫 BLOCK
```

No threat intelligence feeds required. Just: "this version is different from what I expect" → warn or block.

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
   
   Run: chaingate allow axios@1.14.1 --reason "..." to override
```

*Demo shows target V2 behavior. Current V1 surfaces publisher,
dependency, and provenance signals as informational warnings
while sequence-aware pattern detection is in development.
Content-hash mismatch is the only active BLOCK gate.*

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

*Currently, only Content Hash is an active BLOCK gate. All other
gates surface informational signals. Sequence-aware pattern
detection (V2) will activate these as full gates.*

## Attack Coverage

| Attack | How ChainGate catches it |
|--------|------------------------|
| **Axios** (phantom dep + publisher change) | 4 gates fire simultaneously |
| **Trivy** (Git tag force-pushed) | Content hash mismatch |
| **Notepad++** (binary replaced via server hijack) | Content hash mismatch |
| **Shai-Hulud** (500+ packages via stolen tokens) | Publisher identity changes across packages |

**Honest limitation:** If an attacker compromises the CI/CD pipeline and publishes through the same workflow with the same structure — only changing code — the metadata looks clean. For that you need code-level analysis (Socket, Snyk). ChainGate is complementary, not a replacement.

## Quick Start

Requires **Node.js 22+**.

```bash
# npm package not yet published — install from source
git clone https://github.com/r-bedekar/chaingate.git
cd chaingate && npm install
npm link                # makes 'chaingate' command available
chaingate init          # downloads signed seed DB, starts proxy, patches .npmrc
npm install axios       # now routed through ChainGate
chaingate status        # see what was observed
chaingate why axios@1.7.9   # explain the gate decision
chaingate stop          # restore .npmrc, stop proxy
```

## Deployment Modes

**Mode 1: Standalone proxy** — lightweight, for individual devs and small teams.

**Mode 2: Integration layer** — plugin for JFrog Artifactory or Sonatype Nexus. Your existing repo handles proxying, ChainGate adds the intelligence.

## Ecosystem Support

| Ecosystem | Status |
|-----------|--------|
| npm | 🟢 Active |
| PyPI | 🔵 Planned |
| Docker Hub | 🔵 Planned |

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

## Contact

Built by Rizwan Bedekar — feedback, questions, and collaboration welcome.  
Email: rbedekar@zeroinsec.com  
GitHub: [@r-bedekar](https://github.com/r-bedekar)

---

*ChainGate catches what intelligence-based tools miss — during the zero-day window before any database has been updated.*
