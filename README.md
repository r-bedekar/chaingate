> **Status: Active development — not ready for production use.**
> The detection engine is built and validated against a 209-package
> corpus (recall 0.67 on held-out attack set, provenance false-positive
> rate 0.00 on clean packages). The proxy, CLI, and gate runner that
> sit around it are the next build-out (P5). See
> [What's built today](#whats-built-today) for what actually runs.

# ChainGate

**Supply chain integrity gate that catches what threat intelligence misses.**

Every supply chain security tool asks: *"Is this package known to be bad?"*
ChainGate asks: *"Is this package different from what it looked like yesterday?"*

No threat feeds. No subscriptions. No cloud dependency. Self-hosted. Apache 2.0.

---

## The Problem

On March 31, 2026, axios@1.14.1 was published with a hidden RAT. 100M weekly downloads. Socket flagged it in six minutes. Every intelligence-based tool — JFrog, Sonatype, Snyk — was blind until databases updated. The npm registry metadata told a different story from the start: a phantom dependency, a new publisher email on a privacy domain, provenance disappeared, publish method flipped from GitHub Actions OIDC to a CLI token.

None of this is exotic. It's all in the registry metadata every tool already downloads. It just isn't surfaced to the developer at install time.

ChainGate is the part that does the surfacing — by remembering what every package looked like before, and flagging structural changes at install time, without any threat feed.

## The Idea

ChainGate keeps a **witness log** — an append-only record of every package version it has ever observed, with its content hash, dependency tree, publisher identity, and provenance status. When a new version shows up, deterministic **gates** compare it against the history in the log.

Six gates, each reading a different axis of the registry metadata:

| Gate | What it checks |
|------|----------------|
| **Content Hash** | Does the tarball hash match what was first observed? (catches republish attacks — Trivy, Notepad++) |
| **Dep Structure** | Did a new dependency appear, especially one recently published? |
| **Publisher Identity** | Did the publisher email or domain change? |
| **Provenance Continuity** | Did attested publish break? (OIDC → CLI token) |
| **Release Age** | Is this version less than N hours old? |
| **Scope Boundary** | Phantom dependency + install scripts — hard limit |

The signals layer. An axios-class attack trips four at once. A legitimate new release trips none. The combination is what makes this work, not any single gate.

## How It Works (concept)

```
Developer / CI → ChainGate proxy → upstream registry
                        ↓
                Compare against witness log
                Apply deterministic gates
                ✅ ALLOW  ⚠️ WARN  🚫 BLOCK
```

No threat intelligence feeds. Just "is this version structurally consistent with the history of this package."

## What's Built Today

Everything below runs on a fresh clone in under five minutes.

**Detection engine.** Two pattern layers — publisher identity (tenure blocks, cold handoffs, domain classification) and per-major provenance (attestation baselines, regression detection, four-escalator logic). Both pure functions over a package's observed history.

**Witness store.** Append-only log backed by SQLite. Content hashes, dependency trees, publisher metadata, provenance status for 209 packages × 69,964 versions × 181,240 version files.

**Collector.** Pulls live npm and PyPI data, OSV advisories, PyPI attestations. Produces a signed (Ed25519) seed bundle ready for distribution.

**Validation harness.** Runs the detection engine against train/test splits on the corpus and emits metrics to `validation/results.json`. Golden snapshot tests guard the numbers.

**Current numbers on the held-out test split:**

| Metric | Value |
|--------|-------|
| Package recall | 0.67 (4 of 6 labeled attacks detected) |
| Attributable label recall | 1.0 (every attack with a version-pinned label is caught) |
| Provenance-only false-positive rate on clean packages | 0.0 |
| Canonical attacks caught | axios@1.14.1, event-stream@3.3.6, shai-hulud, ua-parser-js |

**Try it:**

```bash
git clone https://github.com/r-bedekar/chaingate.git
cd chaingate && npm install
npm test                                           # 482 tests pass
node validation/run-validation.js --mode=test      # run detection on held-out set
cat validation/results.json | jq '.aggregates'     # see the numbers
```

The Python collector stack is optional (needed only to rebuild the seed from scratch):

```bash
python3 -m venv .venv && .venv/bin/pip install -r collector/requirements.txt
.venv/bin/pytest test/collector/test_osv.py -v     # 35 tests pass
```

## What's Next

**P5 — Proxy, CLI, and gate runner.** The part that turns the detection engine into an installable tool. Ten-day build.

- Proxy that sits between `npm install` and the registry (`undici`-based packument rewriter)
- CLI: `chaingate init`, `allow`, `why`, `status`, `stop`, `update-seed`
- Gate runner wiring the six gates into the proxy request path
- End-to-end integration tests including one real `npm install` smoke test

Design is locked in [`docs/P5.md`](docs/P5.md). Zero bytes written yet — this is the current focus.

After P5: research post + calibration publication, Black Hat MEA Arsenal submission, PyPI ecosystem support, Artifactory / Nexus plugin layer.

## Attack Coverage (from the corpus)

These attacks are detected end-to-end by the current detection engine on the validation corpus. "Caught" means the validation harness reports `detected=true` with the disposition reasons shown.

| Attack | How the detection engine catches it |
|--------|-------------------------------------|
| **Axios 1.14.1** | Per-major provenance regression + three escalators: new domain (proton.me), privacy provider, machine-to-human handoff |
| **Event-stream 3.3.6** | Publisher cold-handoff BLOCK at 3.3.5 (right9ctrl ownership change), propagates to 3.3.6 via same-tenure-block detection |
| **Shai-Hulud** | Publisher identity change across 500+ packages (fixture-verified) |
| **Ua-parser-js** | New unverified domain after established baseline (fixture-verified) |

**Honest limitation.** If an attacker compromises the CI/CD pipeline and publishes through the same workflow with the same publisher and the same structure — only changing code — the metadata looks clean. Code-level analysis tools (Socket, Snyk) catch those. ChainGate is complementary, not a replacement. Honest estimated coverage: 70–80% of known supply-chain attack patterns.

## What Makes This Different

|  | JFrog Curation | Sonatype Firewall | Socket | **ChainGate** |
|---|---|---|---|---|
| Detection signal | Known CVE + malware DB | Proprietary AI | Code analysis | **Historical baseline** |
| Zero-day window | Blind until DB updated | Partial | Fast (6 min, cloud) | **Immediate, local** |
| Needs external intel | Yes | Yes | Yes | **No** |
| Self-hosted | Yes (expensive) | Yes (expensive) | No | **Yes, free** |
| Open source | No | No | CLI only | **Yes** |

## Architecture

```
┌─────────────────────────────────────────┐
│              CHAINGATE PROXY            │
│                                         │
│  ┌─────────────┐  ┌─────────────────┐   │
│  │   WITNESS   │  │      GATES      │   │
│  │             │  │                 │   │
│  │ Content hash│  │ Hash verify     │   │
│  │ Pkg profiles│  │ Dep structure   │   │
│  │ Append-only │  │ Publisher ID    │   │
│  │             │  │ Provenance      │   │
│  └──────┬──────┘  │ Release age     │   │
│         │         │ Scope boundary  │   │
│         │         └────────┬────────┘   │
│         ▼                  ▼            │
│  ┌───────────────────────────────────┐  │
│  │        DECISION ENGINE            │  │
│  │     ALLOW / WARN / BLOCK          │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

## Ecosystem Support

| Ecosystem | Status |
|-----------|--------|
| npm | 🟢 Detection engine built; proxy in progress (P5) |
| PyPI | 🔵 Collector built; detection engine planned |
| Docker Hub | 🔵 Planned |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Feedback, questions, and ecosystem-connector contributions welcome.

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Contact

Built by Rizwan Bedekar.
Email: rbedekar@zeroinsec.com
GitHub: [@r-bedekar](https://github.com/r-bedekar)

---

*ChainGate catches what intelligence-based tools miss — during the zero-day window before any database has been updated. Detection engine built. Proxy next.*
