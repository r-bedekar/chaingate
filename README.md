> **Research prototype. Not production-ready.**
> Metadata deviations provide explainable warning and gating inputs but do not
> independently establish malicious intent. The runtime is built and runs
> end-to-end: local proxy, CLI, witness store, six deterministic gates, seed
> verification (legacy seeds signed; the current v3 seed unsigned and reported as such), and ALLOW / WARN / BLOCK enforcement, with a passing test
> suite. See [What's built today](#whats-built-today) for what actually runs and
> [What's next](#whats-next) for what does not exist yet.

# ChainGate

**ChainGate by CGSec.** npm package: `@cgsec/chaingate` · command: `chaingate`

**Supply chain integrity gate that compares a package against its own history.**

> **Install the scoped package.** The unscoped `chaingate` package on npm is an
> unrelated project, a cryptocurrency SDK. It is not this tool.

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

ChainGate is the part that does the surfacing, by remembering what every package
looked like before, and flagging structural changes at install time, without any
threat feed. Content analysis answers a different question, and both matter:
metadata trajectory is complementary to content analysis, not a substitute for it.

## The Idea

ChainGate keeps a **witness log**: an append-only record of every package version
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
| **Scope Boundary** | Phantom dependency plus install scripts (hard limit) |

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

**CLI.** Ten commands: `init`, `status`, `check`, `why`, `history`, `allow`,
`overrides`, `update-seed`, `doctor`, `stop`.

**Witness store.** Append-only log backed by SQLite: content hashes, dependency
trees, publisher metadata, provenance status.

**Six deterministic gates** wired into the proxy request path, each emitting its own
verdict and reason string.

**ALLOW / WARN / BLOCK enforcement** with a persisted decision log, per-version
overrides, and CI-friendly exit codes from `chaingate check` (0 / 2 / 3; 4 = tool error). `chaingate check --json`
emits a versioned `chaingate.check/1` record; `examples/ci/` has an offline CI consumer for it.

**Seed verification.** Every seed is checked against its `.sha256` sidecar before use. A seed is
**authenticated** only when its Ed25519 signature verifies against a key pinned in the runtime;
an unsigned v3 seed can be used only with `--unsigned-development`, which the tool reports as
`authenticated: false`. A present signature that cannot be checked is refused, never ignored.

**Detection engine.** Two pattern layers: publisher identity (tenure blocks, cold
handoffs, domain classification) and per-major provenance (attestation baselines,
regression detection, four-escalator logic). Both pure functions over a package's
observed history.

**Validation harness.** Runs the detection engine against train/test splits on the
corpus and emits metrics to `validation/results.json`. Golden snapshot tests guard
the numbers.

**Tests.** `npm test` runs the full suite; release candidates record their results in the release notes.

**Pilot numbers on the held-out test split.** Small-n results from a 209-package
research corpus. This is a pilot measurement, not a population estimate:

| Metric | Value |
|--------|-------|
| Package recall | 0.67 (4 of 6 labeled attacks detected) |
| Attributable label recall | 1.0 (every attack with a version-pinned label is caught) |
| Provenance-only false-positive rate on clean packages | 0.0 |
| Canonical attacks caught | axios@1.14.1, event-stream@3.3.6, shai-hulud, ua-parser-js |

## Quick Start

Five minutes, no account, no feed subscription. The seed bundle is verified locally,
so this flow works without fetching a bundle over the network.

Install from npm (Node.js 22 or 24; `package.json` declares exactly those majors). The command is
`chaingate` either way:

```bash
npm install -g @cgsec/chaingate        # global
chaingate --help

npm install @cgsec/chaingate           # or inside a project
npx chaingate --help
```

**The SQLite module has a native part.** npm builds it with `better-sqlite3`'s own install script.
npm 12 blocks dependency install scripts unless you approve them; npm 11 runs them but warns about
any not approved in `allowScripts`; an `ignore-scripts=true` configuration skips them on any version.
If the script did not run, ChainGate installs but cannot open a database: `chaingate doctor` reports
this as `native-sqlite` and prints the fix. Approve only that one package's script:

```bash
# global install (npm 11 and 12)
npm install -g @cgsec/chaingate --allow-scripts=better-sqlite3

# project install: approve in package.json before installing ...
npm pkg set allowScripts.better-sqlite3=true --json && npm install @cgsec/chaingate
# ... or install first, then approve and build it
npm install @cgsec/chaingate && npm approve-scripts better-sqlite3 && npm rebuild better-sqlite3

# with ignore-scripts=true in your npm configuration: rebuild just that package
cd "$(npm root -g)/@cgsec/chaingate" && npm rebuild better-sqlite3 --ignore-scripts=false
```

`--allow-scripts` applies to global installs only; npm rejects it for project installs, which use
`allowScripts` in your own `package.json`. The `allowScripts` entry in ChainGate's repository
`package.json` covers only ChainGate's own development install; it grants nothing in your project.
Do not enable all dependency scripts to fix this.

**Tested platforms.** Only the combinations below have been tested; anything not listed is untested,
not supported. The SQLite module installs from its official prebuilt binary on each of them (no
Python or compiler needed).

| OS | Architecture | Node.js | npm | How it was tested |
|----|--------------|---------|-----|-------------------|
| Linux (Ubuntu 24.04) | x64 | 22.22.2 | 10.9.7 | full local qualification (suite, lifecycle, parity, installed package, offline kit) |
| Linux (Ubuntu 24.04) | x64 | 22.23.2; 24.21.0 | 10.9.8, 12.1.0; 11.19.0, 12.1.0 | CI: test suite and install acceptance |
| macOS 15 | arm64 | 22.23.2; 24.20.0 | 10.9.8, 12.1.0; 11.19.0, 12.1.0 | CI: test suite and install acceptance |
| macOS 15 | x64 | 22.23.2; 24.19.0 | 10.9.8, 12.1.0; 11.17.0, 12.1.0 | CI: test suite and install acceptance |
| Windows Server 2022 (administrator account) | x64 | 22.23.2-22.23.3; 24.21.0 | 10.9.9, 12.1.0; 11.19.0, 12.1.0 | CI: test suite and install acceptance |
| Windows 10/11, standard account | x64 | | | not yet tested |

From source:

```bash
git clone https://github.com/r-bedekar/chaingate.git
cd chaingate && npm install
npm test
```

**You supply the v3 detection seed.** The v3 detection seed is a local file (about 1.9 GB for the full
corpus). **It is not downloaded automatically and no v3 seed is published yet**: pass it with
`--seed`. The current release candidate seed is **unsigned**, so it needs `--unsigned-development`,
which the tool reports as `authenticated: false`. [SEEDS.md](SEEDS.md) lists each v3 seed's exact
identifiers and how to verify a download. See [SECURITY.md](SECURITY.md) for the trust model.

A plain `chaingate init` without `--seed` does **not** install v3 detection: it downloads the older
signed legacy witness seed (about 100 MB) and says so. For v3 detection, always pass `--seed`.

**1. Initialize.** This installs the v3 bundle, starts the proxy and points npm at it:

```console
$ chaingate init --seed ./seed-v3/chaingate-seed.db --unsigned-development
✓ v3 seed bundle bf5b8bf1ec68897e active
  sha256 974c7d7ea2f24ef6…  snapshot d47e8679d6dd…  trust unsigned-development
  policy on_unusable_input=BLOCK on_no_evidence=WARN
✓ .npmrc updated
```

Opening and verifying a full seed takes tens of seconds before the proxy listens; `init` waits
while the process is alive. `--scope project` keeps everything inside the current directory.

**2. Install through the proxy.** Any `npm install` now resolves through ChainGate, and every
version in the packument is gated as it is resolved.

**3. Check a release, fresh.** `chaingate check` evaluates the release described by a packument
file against the active seed. It never reports a stored decision:

```console
$ chaingate check express@4.22.3 --packument ./express.json
express@4.22.3: ALLOW
  evaluated disposition: ALLOW under cft-policy-1.0
  placement: recorded
  ...
$ echo $?
0
```

Exit codes: 0 ALLOW, 2 WARN, 3 BLOCK, 4 tool error. `--json` gives the `chaingate.check/1` record.

**4. Explain.** `chaingate why` explains and never re-decides:

- `chaingate why <pkg>@<ver> --packument <file>` evaluates, then explains;
- `chaingate why --from <check.json>` explains a saved `check --json` result without evaluating;
- `chaingate why <pkg>@<ver> --cached` shows a legacy stored decision, labelled **CACHED — UNBOUND**
  (it carries no seed, rule or policy identity), and exits 4.

Every group and predicate that could not be evaluated is named with its reason. Missing evidence is
never shown as a clean result.

**5. Stop and restore:**

```console
$ chaingate stop
✓ Proxy stopped
✓ .npmrc restored
```

**Updating the seed.** Install another v3 bundle you have with
`chaingate update-seed --seed <bundle>/chaingate-seed.db [--unsigned-development]`, and return to
the previous one with `chaingate update-seed --rollback`. Activation never reaches into a running
proxy; restart it (`chaingate stop && chaingate init`) to load the new bundle. Plain
`chaingate update-seed`, without `--seed`, **refuses** on a host that uses a v3 bundle, because
automatic v3 download is not available.

## Seed bundles

There are two kinds of seed.

- **v3 detection seed** (what `init --seed` / `update-seed --seed` install). Built on private
  collector infrastructure from public registry metadata. **Supplied locally; not downloaded
  automatically; none published yet.** Opened read-only and verified against its `.sha256` sidecar;
  authenticated only when a signature verifies against the pinned key (see SECURITY.md).
- **Legacy witness seed** (`seed-v2.x` GitHub Releases). A plain `chaingate init` without `--seed`
  downloads this signed bundle for the legacy witness store; it does **not** install v3 detection,
  and `init` says so.

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
through the same workflow with the same publisher and the same structure, only
changing code, the metadata looks clean. Code-level analysis catches those.
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

Apache 2.0. See [LICENSE](LICENSE).

## Contact

Built by Rizwan Bedekar.
Email: rbedekar@zeroinsec.com
GitHub: [@r-bedekar](https://github.com/r-bedekar)

---

*ChainGate surfaces structural change at install time, using a package's own history
instead of a threat feed, as explainable evidence for a human decision, not a verdict.*
