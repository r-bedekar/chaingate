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
package metadata and evaluates every version it resolves. Installs from a lockfile (`npm ci`, and `npm install` with a
complete lockfile) ask only for tarballs, so before it serves a tarball it has not evaluated in this run, the proxy
evaluates that exact version first and applies its current decision.

**CLI.** Ten commands: `init`, `status`, `check`, `why`, `history`, `allow`,
`overrides`, `update-seed`, `doctor`, `stop`.

**Witness store.** Append-only log backed by SQLite: content hashes, dependency
trees, publisher metadata, provenance status.

**Six gates** in the proxy's request path. Each reports its own result and reason.

**ALLOW / WARN / BLOCK enforcement** with a persisted decision log, per-version
overrides, and CI-friendly exit codes from `chaingate check` (0 / 2 / 3; 4 = tool error). `chaingate check --json`
emits a versioned `chaingate.check/2` record (0.1.2 and earlier wrote `chaingate.check/1`, which is still
read); `examples/ci/` has an offline CI consumer for both.

**A failure never turns a BLOCK into permission.** A BLOCK stays in force until the check that issued it
definitively clears it (for example, the content hash matches its first-seen value again, or the seed no longer
records the advisory), or until you add an exact override with `chaingate allow`. A skipped check, an error, missing
evidence, an unreadable seed or an input the seed cannot use never clears it. This also applies to decisions written
by earlier versions; nothing in your history is rewritten.

**Exception, by your choice:** with `on_unusable_input: WARN`, a version whose stored decision cannot be read at all is
served. A BLOCK the running proxy holds in memory is still refused. Without a v3 seed (a legacy seed or
`--no-seed`), a decision that cannot be read is refused; those configurations do not provide v3 detection.

**When a BLOCK cannot be stored.** If a BLOCK decision cannot be stored, the running proxy remembers and
enforces it in memory. Restarting the proxy clears that memory, but the first request for each version after a restart
is evaluated again before anything is served, so a BLOCK the seed or the stored history supports is computed again.

**What the proxy cannot see.** ChainGate decides only requests that reach it:
- npm reuses its local cache by content hash without contacting any registry, so a version already in the cache is
  installed without a check. Give CI jobs an empty cache, and clear the cache (`npm cache clean --force`) when you
  start using ChainGate on a machine;
- a lockfile `resolved` URL on any host other than `registry.npmjs.org` or the proxy (a private registry, a mirror)
  is fetched from that host directly. With `replace-registry-host=never`, even `registry.npmjs.org` URLs are;
- an upstream other than `registry.npmjs.org` may give tarball URLs on its own host, which npm then fetches directly.

**Protected CI workflow (tested):**
1. Start the proxy with your seed (`chaingate init --seed …`).
2. Set `registry` to the proxy, and keep npm's default `replace-registry-host`.
3. Keep lockfile `resolved` URLs on `registry.npmjs.org`.
4. Run `npm ci --cache "$(mktemp -d)"`.

A pinned version then fails the install; any other version is evaluated before it is served.

This in-memory record is bounded: by default 50,000 entries and an estimated 64 MiB of retained data. You can change
these with `unstored_block_cap_entries` and `unstored_block_cap_bytes` in the configuration, or
`CHAINGATE_UNSTORED_BLOCK_CAP_ENTRIES` and `CHAINGATE_UNSTORED_BLOCK_CAP_BYTES`. The bound applies to the record, not
to the proxy's total memory, and the default values are not a measured safe limit for every machine. On the tested
Linux configuration, a record at its 64 MiB byte cap (maximum-size names and details) came with about 122 MB of heap
and 336 MB resident memory in the proxy process. Nothing is ever
evicted. When a new BLOCK does not fit, the record becomes **FULL** and stays FULL until the proxy is restarted. While
FULL, the proxy refuses (HTTP 503 `chaingate_storage_degraded`) every tarball that has no stored or remembered BLOCK and
no exact-version override, including tarballs whose stored decision is ALLOW or WARN. This happens under every
`on_unusable_input` setting, and requests whose decision cannot be made are refused too. FULL is a resource-safety
refusal, not a finding that the package is malicious. An exact override (`chaingate allow`) still lets that one version
through, but only when the override can be looked up at request time.

`chaingate status` and `chaingate doctor` show the running proxy's storage state (`witness-storage` in doctor):
- whether decisions are being stored;
- how many BLOCKs are held only in memory, with some of their names to re-request;
- whether the record is FULL.

Any BLOCK held only in memory, and FULL, are reported as degraded; doctor exits 1. The proxy's log is rate-limited, and
lines it suppresses are counted and summarised. It is not a complete record of every decision.

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
  `chaingate.cmd init --seed C:\path\to\chaingate-seed.db --unsigned-development`. On a new install,
  `init` without `--seed` downloads the older legacy witness seed instead (see below).
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

Running `chaingate init` without `--seed` does **not** set up v3 detection. On a new install (no v3
seed and no witness database yet) it downloads the older, signed legacy witness seed (about 100 MB)
and tells you so. It never downloads with `--no-seed`, or on a host that uses a v3 seed. For v3
detection, always pass `--seed`.

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

`chaingate stop` signals only the process recorded for this scope, and only after that process answers on
127.0.0.1:6173 as the ChainGate proxy with the same pid. It prints "Proxy stopped" only once the process has exited and
the port is closed, waiting up to about 8 seconds.

The stop does not succeed when:
- the process does not exit in time;
- it is not confirmed to be the proxy;
- the operating system refuses the check.

In those cases nothing is changed, the `.npmrc` block is left in place, the command says what it found, and it exits
with code 1. A pid can be reused by another process in the milliseconds between the last check and the signal; signals
cannot rule that out.

While ChainGate's block is in your `.npmrc`, npm sends every request to the proxy. If the proxy is
not running, for example after a restart, npm cannot install anything until you either run
`chaingate init` again, which restarts the proxy on the active seed, or run `chaingate stop`, which
restores `.npmrc`.

**Updating the seed.** Switch to another v3 seed you have with
`chaingate update-seed --seed <bundle>/chaingate-seed.db [--unsigned-development]`, and go back to the
previous one with `chaingate update-seed --rollback`. A running proxy keeps its current seed until
you restart it with `chaingate stop && chaingate init`. On a host that uses a v3 seed,
`chaingate update-seed` without `--seed` **refuses**, because v3 seeds cannot be downloaded
automatically. `update-seed --seed` accepts v3 seeds only; a legacy seed file is refused (see
[Seed bundles](#seed-bundles)).

**One seed command at a time.** `init`, `update-seed` and `update-seed --rollback` take a lock on the
ChainGate directory (the file `.seed-mutation.lock`) before they read or change anything about seeds.
A second seed command started meanwhile waits about 2 seconds, then stops with "another seed command
... is running" and changes nothing; run it again when the first has finished. The proxy, `status`
and `doctor` never wait for it. If a command is killed, the operating system releases the lock.
ChainGate 0.1.2 and earlier do not take this lock, so do not run seed commands from different
versions against the same directory. Seed commands are not supported on network filesystems or FAT.

**If a seed command is interrupted.** On Linux and macOS, the next seed command first finishes or
undoes an interrupted activation (`status` and `doctor` report one that is pending; they never repair
it themselves). If that record is unreadable, seed commands stop and say so: inspect
`chaingate status` and `chaingate doctor --json`, then rename the file to
`.activation-intent.json.held-<UTC timestamp>` yourself; ChainGate never deletes it. Partial copies left
by a killed command are removed by a later seed command, once the process that made them has exited
and they are more than 15 minutes old. Until then, `doctor` lists them under `seed-leftovers`.

**Space.** Installing a seed copies it first, so it needs about the seed's size free **in addition to**
what is already used, plus the small sidecar files and a 64 MiB reserve, on the filesystem that holds
the ChainGate directory. ChainGate refuses up front when there is clearly not enough. That check is
not a guarantee, because other programs can use space at the same time. A copy that fails is removed,
and the active seed stays as it was. Seed metadata files are read with fixed size limits (4 KiB for
`.sha256` and `.sig`, 64 KiB for `bundle.json` and `config.json`), and a FIFO, device or other
non-regular file in their place is refused.

## Seed bundles

There are two kinds of seed.

- **v3 detection seed**, installed by `init --seed` or `update-seed --seed`. It is built from public
  registry metadata on the maintainer's private collection servers. **You supply it locally. It is
  not downloaded automatically, and none has been published yet.** It is opened read-only and checked
  against its `.sha256` file. It counts as authenticated only when a signature verifies against the
  built-in key (see SECURITY.md).
- **Legacy witness seed**, published as `seed-v2.x` GitHub releases. On a new install, `chaingate init`
  without `--seed` downloads this signed seed for the older witness store. It does **not** set up v3
  detection, and `init` says so.

**The legacy witness seed, in detail:**

- It is never installed on a host that uses a v3 seed, and never without a valid signature.
- `--force` does not replace the witness database, and `--no-seed` never downloads. `--seed` and
  `--no-seed` together are refused.
- To refresh the legacy seed of an existing witness database, run `chaingate update-seed`, or
  `chaingate init --seed <legacy db> --force`. Stop the proxy first. The refresh happens in place, in
  one database transaction, and keeps your local decisions and overrides. Baselines the proxy
  recorded for versions the new seed does not contain are not kept, as before.
- Downloads are limited to 256 MiB for the database and 4 KiB for each signature file, with time
  limits, and the temporary download directory is removed afterwards.

**An interrupted legacy installation.** ChainGate marks a legacy seed installation as pending
(`witness.db.install-pending.json`) before it changes the witness database. While it is pending,
`chaingate doctor` reports the seed signature as unverifiable, and `init`, `allow` and the other
commands that pass ChainGate's integrity check refuse, except the one that completes the
installation. To complete it, run the same command again with the same seed: `chaingate update-seed`,
or `chaingate init --seed <legacy db> --force`.

Completing it needs the **exact** seed that was being installed and its signature files. This applies
to a local legacy bundle as much as to a published release, so **keep the original bundle until the
installation has completed**. If that seed or its signature files are no longer available, the
installation stays pending: ChainGate has no supported way to substitute another seed or to reset it.
Do not delete the witness database or the marker file to get past this, and do not try to bypass
signature verification. Other integrity failures are reported as before; completing an installation
does not skip them.

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

