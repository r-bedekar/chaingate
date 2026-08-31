> **Research prototype. Not production-ready.**
> Metadata deviations provide explainable warning and gating inputs but do not
> independently establish malicious intent. The runtime is built and runs
> end-to-end — local proxy, CLI, witness store, six deterministic gates, signed
> seed verification, and ALLOW / WARN / BLOCK enforcement, with 532 passing
> tests. See [What's built today](#whats-built-today) for what actually runs and
> [What's next](#whats-next) for what does not exist yet.

# ChainGate

**Supply chain integrity gate that compares a package against its own history.**

Every supply chain security tool asks: *"Is this package known to be bad?"*
ChainGate asks: *"Is this package different from what it looked like yesterday?"*

No threat feeds. No subscriptions. No cloud dependency. Self-hosted. Apache 2.0.

---

## The Problem

When axios@1.14.1 was published with a hidden RAT, the registry metadata told a
different story from the start: a phantom dependency, a new publisher email on a
privacy domain, provenance disappeared, publish method flipped from GitHub
Actions OIDC to a CLI token.

None of this is exotic. It's all in the registry metadata every tool already
downloads. It just isn't surfaced to the developer at install time.

ChainGate is the part that does the surfacing — by remembering what every package
looked like before, and flagging structural changes at install time, without any
threat feed. Content analysis answers a different question, and both matter:
metadata trajectory is complementary to content analysis, not a substitute for it.

## The Idea

ChainGate keeps a **witness log** — an append-only record of every package version
it has ever observed, with its content hash, dependency tree, publisher identity,
and provenance status. When a new version shows up, deterministic **gates** compare
it against the history in the log.

Six gates, each reading a different axis of the registry metadata:

| Gate | What it checks |
|------|----------------|
| **Content Hash** | Does the tarball hash match what was first observed? (catches republish attacks) |
| **Dep Structure** | Did a new dependency appear, especially one recently published? |
| **Publisher Identity** | Did the publisher email or domain change? |
| **Provenance Continuity** | Did attested publish break? (OIDC → CLI token) |
| **Release Age** | Is this version less than N hours old? |
| **Scope Boundary** | Phantom dependency + install scripts — hard limit |

The signals layer. An axios-class attack trips four at once. A routine release trips
none, or one with a benign explanation. The combination is what makes this work, not
any single gate.

## How It Works

```
Developer / CI → ChainGate proxy → upstream registry
                        ↓
                Compare against witness log
                Apply deterministic gates
                ✅ ALLOW  ⚠️ WARN  🚫 BLOCK
```

No threat intelligence feeds. Just "is this version structurally consistent with the
history of this package."

## What's Built Today

The full path from `npm install` to an explainable decision runs today.

**Local npm proxy.** `undici`-based packument rewriter that sits between the client
and the upstream registry, evaluating every version it resolves.

**CLI.** Eleven commands: `init`, `status`, `check`, `why`, `history`, `allow`,
`overrides`, `update-seed`, `doctor`, `stop`.

**Witness store.** Append-only log backed by SQLite — content hashes, dependency
trees, publisher metadata, provenance status.

**Six deterministic gates** wired into the proxy request path, each emitting its own
verdict and reason string.

**ALLOW / WARN / BLOCK enforcement** with a persisted decision log, per-version
overrides, and CI-friendly exit codes from `chaingate check` (0 / 2 / 3).

**Signed seed verification.** The runtime fetches a signed corpus bundle and verifies
its Ed25519 signature against a pinned public key before installing it; an
unauthorized seed cannot be installed regardless of where it appears to come from.

**Detection engine.** Two pattern layers — publisher identity (tenure blocks, cold
handoffs, domain classification) and per-major provenance (attestation baselines,
regression detection, four-escalator logic). Both pure functions over a package's
observed history.

**Validation harness.** Runs the detection engine against train/test splits on the
corpus and emits metrics to `validation/results.json`. Golden snapshot tests guard
the numbers.

**Tests.** 534 tests, 532 passing, 2 skipped.

**Pilot numbers on the held-out test split.** Small-n results from a 209-package
research corpus — a pilot measurement, not a population estimate:

| Metric | Value |
|--------|-------|
| Package recall | 0.67 (4 of 6 labeled attacks detected) |
| Attributable label recall | 1.0 (every attack with a version-pinned label is caught) |
| Provenance-only false-positive rate on clean packages | 0.0 |
| Canonical attacks caught | axios@1.14.1, event-stream@3.3.6, shai-hulud, ua-parser-js |

## Quick Start

Five minutes, no account, no feed subscription. The seed bundle is verified locally,
so this flow works without fetching a bundle over the network.

```bash
git clone https://github.com/r-bedekar/chaingate.git
cd chaingate && npm install
npm test                        # 534 tests, 532 passing, 2 skipped
```

**1. Initialize** — installs a verified seed, starts the proxy, points npm at it.
`--scope project` keeps everything inside the current directory:

```console
$ chaingate init --scope project --seed ./seed_export/chaingate-seed.db
Verifying local seed...
✓ Local seed verified and copied
✓ .npmrc updated (/path/to/project/.npmrc)
✓ Proxy running on http://127.0.0.1:6173 (pid 2366434)

Ready. 104 packages, 50521 versions in witness store.
```

Without `--seed`, `chaingate init` fetches and verifies the signed bundle from this
repository's GitHub Releases instead.

**2. Resolve a package through the proxy.** Any `npm install` does this; so does a
direct packument fetch. Every version in the packument is gated as it is resolved:

```console
$ curl -s -o /dev/null http://127.0.0.1:6173/axios
$ chaingate status --scope project
  Witness store:  104 packages, 50530 versions, 50525 files
  Seed version:   2026.04.22.1 (exported 2026-04-22T08:56:10Z)
  Proxy:          running on 127.0.0.1:6173 (pid 2366434)
  Decisions:      144 total · 12 ALLOW · 132 WARN · 0 BLOCK
```

**3. Explain a decision.** Every gate reports its own verdict and the evidence behind
it — this is the whole point of the tool:

```console
$ chaingate why axios@1.20.0 --scope project
axios@1.20.0  WARN  2026-08-31 12:07:06

  ALLOW first-seen — baseline recorded on first observation
  SKIP content-hash — first-seen: no baseline to compare
  WARN dep-structure — new runtime dep(s): https-proxy-agent (not in prior 136 version(s))
  ALLOW publisher-identity — publisher unchanged: npm-oidc-no-reply@github.com
  ALLOW provenance-continuity — OIDC provenance present (continuous with 46/136 prior versions)
  ALLOW release-age — release age 123h ≥ threshold 72h
  ALLOW scope-boundary — 1 new dep(s) but no install scripts — low risk
```

`chaingate check` gives the same decision with a CI-friendly exit code:

```console
$ chaingate check axios@1.20.0 --scope project
axios@1.20.0: WARN
$ echo $?
2
```

**4. Stop and restore.** Puts your npm configuration back the way it was:

```console
$ chaingate stop --scope project
✓ Proxy stopped
✓ .npmrc restored (/path/to/project/.npmrc)
```

Two things this walkthrough shows honestly. A seed older than the packages you resolve
produces many first-seen WARNs — the store had no baseline for those versions, and the
reason string says so; run `chaingate update-seed` for a current bundle. And
`chaingate why axios@1.14.1` returns no decision at all, because that version is no
longer present in the registry's current packument. A tool that reads only current
registry state cannot reason about a version that has been erased from it. That is
exactly why the witness log exists.

## Seed bundles

ChainGate's runtime fetches a signed corpus bundle (the "seed") from this repository's
GitHub Releases. The seed is built and signed on private collector infrastructure, then
published here for distribution. Users do not need to interact with the releases page
directly — `chaingate update-seed` handles fetching and verification automatically.
Each bundle's Ed25519 signature is verified against a pinned public key in the runtime.
See [SECURITY.md](SECURITY.md) for the full trust model.

## What's Next

**Detection-as-Code export.** Emit the gate rules and their evidence in a form
customer-owned tooling can consume and audit, rather than an opaque score.

**Structured evidence output.** One schema for a decision and the evidence behind it,
stable enough to build on.

**Customer-owned integrations.** SIEM, EDR, CI pipelines, and agent workflows
consuming that schema.

Also planned: expanded corpus and calibration, PyPI ecosystem support, and an
Artifactory / Nexus plugin layer.

## Attack Coverage (from the corpus)

These attacks are detected end-to-end by the detection engine on the validation corpus.
"Caught" means the validation harness reports `detected=true` with the disposition
reasons shown. These are corpus and fixture results, not live registry captures.

| Attack | How the detection engine catches it |
|--------|-------------------------------------|
| **Axios 1.14.1** | Per-major provenance regression + three escalators: new domain (proton.me), privacy provider, machine-to-human handoff |
| **Event-stream 3.3.6** | Publisher cold-handoff BLOCK at 3.3.5 (right9ctrl ownership change), propagates to 3.3.6 via same-tenure-block detection |
| **Shai-Hulud** | Publisher identity change across 500+ packages (fixture-verified) |
| **Ua-parser-js** | New unverified domain after established baseline (fixture-verified) |

**Honest limitation.** If an attacker compromises the CI/CD pipeline and publishes
through the same workflow with the same publisher and the same structure — only
changing code — the metadata looks clean. Code-level analysis catches those.
ChainGate is complementary, not a replacement.

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
| npm | 🟢 Proxy, CLI, gates, and witness store built |
| PyPI | 🔵 Collector built; detection engine planned |
| Docker Hub | 🔵 Planned |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Feedback, questions, and ecosystem-connector
contributions welcome.

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Contact

Built by Rizwan Bedekar.
Email: rbedekar@zeroinsec.com
GitHub: [@r-bedekar](https://github.com/r-bedekar)

---

*ChainGate surfaces structural change at install time, using a package's own history
instead of a threat feed — as explainable evidence for a human decision, not a verdict.*
