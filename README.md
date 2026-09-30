> **Research prototype, not production-ready.**
> A change in a package's metadata is a reason to look, not proof of malicious intent. What exists
> today: a local proxy, a CLI, a witness store, six gates, seed verification (legacy seeds are
> signed; the current v3 seed is unsigned and reported as unsigned) and ALLOW / WARN / BLOCK
> enforcement, with a passing test suite. [What's built today](#whats-built-today) lists what runs;
> [What's next](#whats-next) lists what does not exist yet.

# ChainGate

ChainGate by CGSec. npm package `@cgsec/chaingate`, command `chaingate`.

ChainGate is a local npm proxy that compares each new package version with that package's own
release history and warns or blocks when its metadata changes in ways that often come with a
compromised release.

> **Install the scoped package.** The unscoped `chaingate` package on npm is an
> unrelated project, a cryptocurrency SDK. It is not this tool.

Most supply chain tools check a package against lists of known-bad packages. ChainGate instead
checks whether a release differs from the releases before it. It runs on your machine, needs no
threat feed or account, and is licensed Apache 2.0.

---

## The Problem

When axios@1.14.1 was published with a remote access trojan, its registry metadata already looked
different from earlier releases: a new dependency that had only just been published, a new
publisher email on a privacy-focused domain, no provenance attestation, and a publish from a CLI
token instead of GitHub Actions OIDC.

All of that is in the registry metadata that npm downloads anyway. Nothing shows it to the developer
at install time. ChainGate records what each package looked like before and reports these changes
when you install. It does not look at the code inside a package, so it complements code analysis
rather than replacing it.

## The Idea

ChainGate keeps a **witness log**, an append-only record of every package version it has seen:
content hash, dependency tree, publisher identity and provenance status. When a new version appears,
a set of **gates** compares it with that history. The same input always gives the same result.

There are six gates, each looking at a different part of the metadata:

| Gate | What it checks |
|------|----------------|
| **Content Hash** | Does the tarball hash match what was first observed? (catches republish attacks) |
| **Dep Structure** | Did a new dependency appear, especially one recently published? |
| **Publisher Identity** | Did the publisher email or domain change? |
| **Provenance Continuity** | Did a package that published with provenance stop doing so? (for example, OIDC to a CLI token) |
| **Release Age** | Is this version less than N hours old? |
| **Scope Boundary** | A new dependency together with install scripts (hard limit) |

One gate firing on its own is common and usually harmless. The axios release above triggers four
at once, while a routine release triggers none, or one with an ordinary explanation. The combination
is what matters.

## How It Works

```
npm (developer or CI)  ->  ChainGate proxy  ->  upstream registry
                               |
                               v
                   compare with the witness log
                   run the gates
                   ALLOW / WARN / BLOCK
```

## What's Built Today

The whole path, from `npm install` to a decision with its reasons, works today.

**Local npm proxy.** Sits between npm and the upstream registry, built on `undici`. It rewrites
package metadata and evaluates every version it resolves.

**CLI.** Ten commands: `init`, `status`, `check`, `why`, `history`, `allow`,
`overrides`, `update-seed`, `doctor`, `stop`.

**Witness store.** Append-only log backed by SQLite: content hashes, dependency
trees, publisher metadata, provenance status.

**Six gates** in the proxy's request path. Each reports its own result and reason.

**ALLOW / WARN / BLOCK enforcement** with a persisted decision log, per-version
overrides, and CI-friendly exit codes from `chaingate check` (0 / 2 / 3; 4 = tool error). `chaingate check --json`
emits a versioned `chaingate.check/2` record (0.1.2 and earlier wrote `chaingate.check/1`, which is still
read); `examples/ci/` has an offline CI consumer for both.

**Seed verification.** Every seed is checked against its `.sha256` file before use. A seed counts as
**authenticated** only when its Ed25519 signature verifies against a key built into the runtime. An
unsigned v3 seed can be used only with `--unsigned-development`, and the tool then reports
`authenticated: false`. A signature that is present but cannot be checked is refused.

**Detection engine.** Two layers of patterns. Publisher identity looks at how long each publisher
has held a package, handovers to a new publisher, and email domains. Provenance tracks attestation
per major version, flags when it stops, and raises severity when other signals agree. Both work only
from a package's recorded history.

**Validation.** A script runs the detection engine on train and test splits of the research corpus
and writes metrics to `validation/results.json`. Snapshot tests fail if those numbers change.

**Tests.** `npm test` runs the full suite; release candidates record their results in the release notes.

**Pilot results on the held-out test split.** These come from a small research corpus of 209
packages. Treat them as a pilot measurement, not an estimate for npm as a whole:

| Metric | Value |
|--------|-------|
| Package recall | 0.67 (4 of 6 labeled attacks detected) |
| Attributable label recall | 1.0 (every attack with a version-pinned label is caught) |
| Provenance-only false-positive rate on clean packages | 0.0 |
| Canonical attacks caught | axios@1.14.1, event-stream@3.3.6, shai-hulud, ua-parser-js |

## Quick Start

You need no account or subscription. The seed is verified locally, so these steps do not download a
seed.

Install from npm. ChainGate supports Node.js 22 and 24, the two major versions `package.json`
declares. The command is `chaingate` either way:

```bash
npm install -g @cgsec/chaingate        # global
chaingate --help

npm install @cgsec/chaingate           # or inside a project
npx chaingate --help
```

**The SQLite module has a native part.** It is installed by `better-sqlite3`'s own install script,
which downloads a prebuilt binary. npm 12 blocks dependency install scripts unless you approve them.
npm 11 runs them, but warns about any that `allowScripts` does not list. With `ignore-scripts=true` in
your npm configuration they never run. If the script did not run, ChainGate installs but cannot open
its database; `chaingate doctor` reports this as `native-sqlite` and prints the fix. Approve only
that one package's script:

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

`--allow-scripts` works for global installs only. npm rejects it for project installs, which use
`allowScripts` in your own `package.json` instead. The `allowScripts` entry in ChainGate's own
`package.json` applies only when developing ChainGate itself and grants nothing in your project. Do
not enable every dependency's scripts to fix this.

**Tested platforms.** Only the combinations below have been tested. Anything not listed is untested
and not supported. On each of them the SQLite module installed from its official prebuilt binary,
with no Python or compiler.

| OS | Architecture | Node.js | npm | How it was tested |
|----|--------------|---------|-----|-------------------|
| Linux (Ubuntu 24.04) | x64 | 22.22.2 | 10.9.7 | full local qualification (suite, lifecycle, parity, installed package, offline kit) |
| Linux (Ubuntu 24.04) | x64 | 22.23.2; 24.21.0 | 10.9.8, 12.1.0; 11.19.0, 12.1.0 | CI: test suite and install acceptance |
| macOS 15 | arm64 | 22.23.2; 24.20.0 | 10.9.8, 12.1.0; 11.19.0, 12.1.0 | CI: test suite and install acceptance |
| macOS 15 | x64 | 22.23.2; 24.19.0 | 10.9.8, 12.1.0; 11.17.0, 12.1.0 | CI: test suite and install acceptance |
| Windows Server 2022 (administrator account) | x64 | 22.23.2-22.23.3; 24.21.0 | 10.9.9, 12.1.0; 11.19.0, 12.1.0 | CI: test suite and install acceptance |
| Windows 10 Pro (standard account) | x64 | 24.21.0 | 11.19.0 | install acceptance: global and project installs |

**On Windows:**

- If PowerShell refuses to run `npm` or `chaingate` ("running scripts is disabled on this system"),
  type `npm.cmd` and `chaingate.cmd` instead. The Command Prompt uses the `.cmd` launchers
  automatically. You do not need to change the execution policy.
- Approve the SQLite script in the install command, so npm does not warn about it or skip it:
  `npm.cmd install -g @cgsec/chaingate --allow-scripts=better-sqlite3`. To approve it once for all
  your global installs: `npm.cmd config set allow-scripts=better-sqlite3 --location=user`.
- Start ChainGate with your v3 seed:
  `chaingate.cmd init --seed C:\path\to\chaingate-seed.db --unsigned-development`. Without `--seed`,
  `init` downloads the older legacy witness seed instead (see below).
- [SEEDS.md](SEEDS.md) shows how to check a seed file's SHA-256 in PowerShell.

From source:

```bash
git clone https://github.com/r-bedekar/chaingate.git
cd chaingate && npm install
npm test
```

**You supply the v3 detection seed.** It is a local file, about 1.9 GB for the full corpus. **It is
not downloaded automatically, and no v3 seed has been published yet.** Pass it with `--seed`. The
current release candidate seed is **unsigned**, so it also needs `--unsigned-development`, and the
tool reports `authenticated: false`. [SEEDS.md](SEEDS.md) lists each v3 seed's exact identifiers and
how to verify a download. [SECURITY.md](SECURITY.md) describes the trust model.

Running `chaingate init` without `--seed` does **not** set up v3 detection. It downloads the older,
signed legacy witness seed (about 100 MB) and tells you so. For v3 detection, always pass `--seed`.

**1. Initialize.** This installs the v3 seed, starts the proxy and points npm at it:

```console
$ chaingate init --seed ./seed-v3/chaingate-seed.db --unsigned-development
✓ v3 seed bundle bf5b8bf1ec68897e active
  sha256 974c7d7ea2f24ef6...  snapshot d47e8679d6dd...  trust unsigned-development
  policy on_unusable_input=BLOCK on_no_evidence=WARN
✓ .npmrc updated
```

Opening and verifying a full seed takes tens of seconds, and `init` waits for the proxy to start.
`--scope project` keeps everything inside the current directory.

**2. Install through the proxy.** Every `npm install` now goes through ChainGate, which checks each
version as npm resolves it.

**3. Check a release.** `chaingate check` evaluates a release, described by a saved packument file,
against the active seed. It always evaluates afresh and never reports a stored decision:

```console
$ chaingate check express@4.22.3 --packument ./express.json
express@4.22.3: ALLOW
  evaluated disposition: ALLOW under cft-policy-1.1
  placement: recorded
  ...
$ echo $?
0
```

Exit codes: 0 ALLOW, 2 WARN, 3 BLOCK, 4 tool error. `--json` gives the `chaingate.check/2` record.

A version named in a recorded advisory is blocked even when the release cannot be evaluated (for example a
manifest the adapter rejects), and the result names the advisory.

**4. Explain.** `chaingate why` explains a result. It never changes one:

- `chaingate why <pkg>@<ver> --packument <file>` evaluates the release, then explains the result.
- `chaingate why --from <check.json>` explains a saved `check --json` result without evaluating again.
- `chaingate why <pkg>@<ver> --cached` shows an old stored decision, labelled `CACHED — UNBOUND`
  because it records no seed, rule or policy identity, and exits with code 4.

Anything that could not be evaluated is listed with the reason. Missing evidence is never reported
as a clean result.

**5. Stop and restore:**

```console
$ chaingate stop
✓ Proxy stopped
✓ .npmrc restored
```

While ChainGate's block is in your `.npmrc`, npm sends every request to the proxy. If the proxy is
not running, for example after a restart, npm cannot install anything until you either run
`chaingate init` again, which restarts the proxy on the active seed, or run `chaingate stop`, which
restores `.npmrc`.

**Updating the seed.** Switch to another v3 seed you have with
`chaingate update-seed --seed <bundle>/chaingate-seed.db [--unsigned-development]`, and go back to the
previous one with `chaingate update-seed --rollback`. A running proxy keeps its current seed until
you restart it with `chaingate stop && chaingate init`. On a host that uses a v3 seed,
`chaingate update-seed` without `--seed` **refuses**, because v3 seeds cannot be downloaded
automatically.

## Seed bundles

There are two kinds of seed.

- **v3 detection seed**, installed by `init --seed` or `update-seed --seed`. It is built from public
  registry metadata on the maintainer's private collection servers. **You supply it locally. It is
  not downloaded automatically, and none has been published yet.** It is opened read-only and checked
  against its `.sha256` file. It counts as authenticated only when a signature verifies against the
  built-in key (see SECURITY.md).
- **Legacy witness seed**, published as `seed-v2.x` GitHub releases. `chaingate init` without `--seed`
  downloads this signed seed for the older witness store. It does **not** set up v3 detection, and
  `init` says so.

[SECURITY.md](SECURITY.md) describes the full trust model.

## What's Next

**Detection rules as code.** Export the gate rules and their evidence so that your own tools can
read and audit them, instead of receiving a single score.

**Structured evidence output.** One documented format for a decision and the evidence behind it.

**Integrations.** SIEM, EDR, CI pipelines and agent workflows that read that format.

Also planned: a larger corpus and more calibration, PyPI support, and plugins for Artifactory and
Nexus.

## Attack Coverage (from the corpus)

The detection engine detects these attacks in the validation corpus. "Detected" means the
validation script reports `detected=true` with the reasons shown. These results come from the corpus
and test fixtures, not from live registry traffic.

| Attack | How the detection engine catches it |
|--------|-------------------------------------|
| **Axios 1.14.1** | Provenance stopped within the major version, plus three supporting signals: a new email domain (proton.me), a privacy-focused provider, and a switch from automated to manual publishing |
| **Event-stream 3.3.6** | BLOCK at 3.3.5 for an abrupt handover to a new publisher (right9ctrl), carried to 3.3.6 because the same publisher released it |
| **Shai-Hulud** | Publisher identity change across 500+ packages (fixture-verified) |
| **Ua-parser-js** | New unverified domain after established baseline (fixture-verified) |

**Limitation.** If an attacker takes over the CI/CD pipeline and publishes through the same
workflow, as the same publisher, with the same structure, and changes only the code, the metadata
looks normal and ChainGate will not notice. Code analysis is needed for that case.

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
| npm | Proxy, CLI, gates and witness store built |
| PyPI | Metadata collector built; detection planned |
| Docker Hub | Planned |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Feedback, questions and contributions for other ecosystems
are welcome.

## License

Apache 2.0. See [LICENSE](LICENSE).

## Contact

Built by Rizwan Bedekar.
Email: rbedekar@zeroinsec.com
GitHub: [@r-bedekar](https://github.com/r-bedekar)

