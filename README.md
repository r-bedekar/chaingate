> **Research prototype, not production-ready.**
> A change in a package's metadata is a reason to look, not proof of malicious intent. What exists
> today: a local proxy, a CLI, a witness store, its rules (facts that block, named rules that warn,
> contributing signals shown as detail), signed seeds verified against a key
> built into the runtime, and ALLOW / WARN / BLOCK enforcement, with a passing test suite. [What's built today](#whats-built-today) lists what runs;
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

The new dependency, plain-crypto-js@4.2.1, also declared a `postinstall` script, so installing
axios@1.14.1 ran it. All of that is in the registry metadata that npm downloads anyway. Nothing shows
it to the developer at install time.

ChainGate records what each package looked like before. It warns on a short list of named rules: for
axios@1.14.1, that the release adds a dependency that runs install scripts. The other changes are
recorded as detail. ChainGate reads only the files npm will run, on each version's first download, and checks them
for a short list of named patterns, so it complements code analysis rather than replacing it.

## The Idea

ChainGate keeps a **witness log**, an append-only record of every package version it has seen:
content hash, dependency tree, publisher identity and provenance status. When a new version appears,
ChainGate's policy compares it with that history and with the seed. The same input always gives
the same result. Each row of the result has one of these effects:

| Kind | Rows | Effect |
|------|------|--------|
| **Facts** | an advisory in the seed naming this exact version; content that differs from the version's recorded baseline (content hash) | BLOCK |
| **Named rules** | the seed's strict tier; an install script introduced; an added dependency that runs install scripts; the tarball's install scripts differ from its registry entry; a size jump with a broken repository link; four checks of the files npm will run | WARN |
| **Contributing signals** | publisher change, new dependency, provenance dropped, release age, scope boundary, size jump, npm-version downgrade, the seed's looser rule, a publisher break, an entry point change, the other file checks | detail only |
| **Coverage choice** | the seed cannot use the release's input, or nothing in its finding was evaluated | what you set at `init`: `on_unusable_input` (default BLOCK) and `on_no_evidence` (default WARN) |

One contributing signal is common and usually harmless, and no combination of contributing rows warns:
they are shown beside a named warning and in `chaingate why`. A takeover that trips no named rule
warns only when the seed's strict tier marks the release.

## How It Works

```
npm (developer or CI)  ->  ChainGate proxy  ->  upstream registry
                               |
                               v
                   compare with the witness log and the seed
                   apply the policy
                   ALLOW / WARN / BLOCK
```

## What's Built Today

The whole path, from `npm install` to a decision with its reasons, works today.

**Local npm proxy.** Sits between npm and the upstream registry, built on `undici`. It rewrites
package metadata and evaluates every version it resolves. Installs from a lockfile (`npm ci`, and `npm install` with a
complete lockfile) ask only for tarballs, so before it serves a tarball whose exact version the running proxy has not
evaluated, the proxy fetches that package's metadata, evaluates it and applies the version's current decision. This
applies in every configuration that has a witness store. A version stays tracked as evaluated while the proxy runs, up
to 100,000 tracked versions; a version published later, one whose evaluation failed, and one dropped from that bounded
tracking are evaluated again on their next request.

If the requested version cannot be evaluated (the metadata cannot be fetched, the version is missing from it or could
not be evaluated, or the version cannot be derived from the tarball name), the existing policy for a request without a
decision applies, and the tarball is not counted as evaluated:
- with a v3 seed and `on_unusable_input: BLOCK`, it is refused (HTTP 503 `chaingate_evaluation_failed`);
- with `on_unusable_input: WARN`, or without a v3 seed, it is served without an evaluation, and the log says so.

When too many evaluations are already waiting, a request is refused with HTTP 503 `chaingate_evaluation_busy`, a
resource refusal, not a finding. A stored or remembered BLOCK is refused, and an exact override is honoured, whatever
the evaluation's outcome. While the in-memory record is FULL (below), its own rules apply instead.

**Cost of evaluating before serving.** A lockfile install through a newly started proxy fetches and evaluates each
package's metadata before serving its tarball. In our tests that added about 50 ms per package; the cost depends on each
package's size and history, the upstream and the machine. Repeat installs on the same running proxy skip it for versions
still tracked as evaluated. A new version, or one dropped from the tracking, is evaluated again. A CI job that starts a
new proxy every run pays the first-install cost every time.

**CLI.** Fourteen commands: `init`, `status`, `check`, `why`, `history`, `allow`, `overrides`, `update-seed`,
`doctor`, `stop`, `report`, `accept`, `pin`, `unpin`.

**Witness store.** Append-only log backed by SQLite: content hashes, dependency
trees, publisher metadata, provenance status.

**What decides a warning.** Each release gets a record of every check's result. Only some of those checks can make a
warning:
- **Facts BLOCK.** These are a recorded advisory naming the exact version (from the seed), and content that differs from
  the version's recorded baseline (content hash).
- **Named rules WARN.** Each one is a specific, counted reason:
  - the seed's strict tier (a release-history break of 3+ of 5 groups, or 2+ package-wide signals). Since 0.1.6 it is
    shown as a contributing note instead when nothing it found is new: every signal that broke already held on the
    release this one follows (the latest earlier release with the same prerelease shape, else of the same release line,
    else the previous release), and none of these holds: that state began less than 7 days before this release, the
    install scripts npm runs differ from that release's, provenance it had is gone, a dependency was added or comes from
    outside the registry, or part of the evidence could not be evaluated. Such a release is still read by the tarball
    checks when it is downloaded; if any of them fires, or the tarball's `package.json` adds or changes an install
    script, the warning comes back. `chaingate why` names the release it was compared with;
  - **an install script is introduced**: the release declares an install script (`preinstall`, `install` or
    `postinstall`, or a node-gyp build) when no version published at least 24 h earlier declared any (on a package's
    first day: no earlier version at all). A package's first version is not judged. A changed or additional install
    script on a package that already had one is not this rule. Since 0.1.6, once a download has read the tarball, the
    rule follows the install scripts in the tarball's `package.json`, which is what npm runs: a script only the registry
    entry declares (one renamed in the packed copy, for example) no longer counts, and one only the tarball declares
    does. The differing-install-scripts rule below still warns on either;
  - **an added dependency runs install scripts**: the release adds a registry dependency (a name no earlier release
    depended on) whose resolved version runs install scripts. Git, URL and file dependencies are not judged. A range
    resolves to the highest matching version (npm may install the `latest` tag instead when it matches), a name in both
    `dependencies` and `optionalDependencies` is judged on its `dependencies` entry, and re-pointing an existing name is
    not "added";
  - **the tarball's install scripts differ**: the tarball's `package.json` declares install scripts that differ from
    its registry entry;
  - **a size jump with a broken repository link** (0.1.5): the release's unpacked size is at least 5 times that of the
    version before it, and its link to the repository broke: `gitHead` is missing where the version before it had one,
    or the repository URL changed. npm prints "its tarball grew fivefold and its link to the repository broke". "The
    version before it" is the previous version in the release's line; for a prerelease it is the previous version of
    its own tag (a `-canary` is compared with the last canary). Since 0.1.6 a build for one platform is compared with the
    last build of its tag for the same platform (`2.0.0-beta.25-darwin-arm64` with `2.0.0-beta.24-darwin-arm64`, not with
    the `2.0.0-beta.25` published beside it). The first version of a new tag, or of a tag on a platform, has none, and the rule
    says it is not evaluable. A holding package npm publishes in place of removed malware is never used as the version
    before;
  - six of the tarball checks (below).
- **Contributing rows are detail.** These are publisher change, new dependency, provenance dropped, release age, scope
  boundary, size jump of 2x or more, npm-version downgrade, the seed's looser rule, the other tarball checks (below),
  and two checks added in 0.1.5:
  - **a publisher break**: a publisher the package has never had, together with at least two other breaks against the
    previous release (a different maintainer set, an older npm, a different repository URL, a missing `gitHead`);
  - **an entry point change**: what npm runs or links changed against the version before it (as the size-jump rule
    defines it): a lifecycle script other than the install hooks added or changed, a `bin` command added or pointed
    elsewhere, or a different `main`.

  They are listed in
  `chaingate why <pkg>@<ver>` (the recorded decision) and in `chaingate report --json`, and they never make a warning on
  their own.

Some named rules are checked when npm downloads the tarball:
- **Added dependencies** are judged from metadata npm already fetched through ChainGate, or fetched before answering:
  within 5 s, at most 8 fetches at once, cached for 10 minutes. A release that adds more than 10 is not judged, and a
  dependency that does not answer in time is "not evaluable".
  Either outcome is never an ALLOW for that rule. An install from a lockfile (`npm ci`) fetches no metadata, so each
  tarball that adds a dependency can wait up to 5 s.
- **The install-script comparison** reads the tarball while it streams to npm. It reads the archive as npm's extractor
  (node-tar) does, and compares every entry npm writes as the root `package.json`: on Linux checked against npm
  10.9.7's and 11.19.0's own extractor, on macOS and Windows emulated, with names those systems may also map to that
  file compared on their own. An archive that npm 10 and npm 11 would read differently is "not checked". The download
  that reveals a mismatch carries no notice, and npm caches it. `chaingate report` lists the mismatch at once. A later
  download that reaches ChainGate carries the notice, but npm installs a tarball it already holds from its own cache
  without asking ChainGate, so this machine may never print it.

**Tarball checks (0.1.5; every download since 0.1.6).** ChainGate also reads the files npm will run. Since 0.1.6 it
does so on every version's first download (0.1.5 read them only when the version already carried a named warning, a
publisher break, an entry point change, or the seed's coverage warning; each row still names which of these it was, or
"every download"). At most 16 downloads are read at once. A download that finds all 16 busy waits for one, up to 10
seconds (`"static_walk_wait_ms"` in `config.json`, 0 to 60,000; at most half the upstream body timeout); past that it
is served unread, recorded as "not checked: walk budget exceeded" and read at its next download. The reading adds no
latency on typical packages and at most that wait per download on heavy ones: over 500 synthetic packages at npm's
16 connections, typical tarballs (about 90 KiB) never waited and the install took 6 s; tarballs of 4.6 MB of mostly
base64 text waited 2.1 s at the median (2.8 s at most), and every one was read. The proxy's memory rose by about 70
MiB on the typical install and about 215 MiB at most on the heavy one. Each version's wait is recorded with its facts
(`walk_wait_ms`). The walk keeps the bodies of the files the registry manifest points npm at -- the install-hook targets, `main`, up to 4 `bin`
targets; at most 6 files of 1 MiB each -- and checks them. It warns when:
- an install-hook command fetches code (curl, wget, Invoke-WebRequest, certutil -urlcache, bitsadmin) and executes or
  decodes it (a pipe into a shell or interpreter, powershell -enc, base64 -d, eval, iex), or runs a network tool (curl,
  wget, nc; nslookup, dig, host or ping only with command substitution) that sends data out (command substitution, a
  data flag, a raw-IP or known exfiltration host URL), or makes a DNS lookup through node's `dns` module carrying process or
  host data (the environment, the arguments, the working directory, `__dirname`, the host name, user, home directory or network
  interfaces). In a command that runs inline node code (`node -e`, `--eval`, `-p`, `--print`), what a `console` call only
  prints is not read as a command, unless the printed text itself makes a call. npm prints "an install script downloads code to
  run or sends data to an outside host";
- a hook target is over the 1 MiB file cap (its size is read from the archive header; its body is not kept). npm prints
  "an install script runs a file too large to read";
- a hook target makes a network call (an HTTP request, fetch, a socket, a WebSocket, XMLHttpRequest or axios) and reads
  what identifies this machine (its host name, user or network interfaces, a dump of the whole environment, or the
  variables USER, USERNAME, LOGNAME, HOSTNAME or COMPUTERNAME), with no way to run code in the same file: a beacon. A
  URL written in the file is not a network call, reading other environment variables is not identification, and a value
  used only as the input of a hash (`.update(...)`) is not identification. A hook target that makes a DNS lookup through
  node's `dns` module carrying the same process or host data as above also warns, whether or not it can run code. npm
  prints "an install script sends details about this machine to the network";
- `main` or a `bin` file gained something the same file of the version this proxy served before did not have: a decode
  or obfuscation marker other than the `Function` constructor, or a network call together with a way to run code other
  than `Function`. Both versions' files must have been read and the earlier one must not be empty. Every gain,
  `Function` included, stays on the row as a fact. On the first version of a package this proxy serves there is nothing
  to compare, and the row says so; when either version's file could not be read (over the cap, or a refused archive),
  the row is "not checked", never a clean result. To compare, the proxy keeps a summary of what `main` and the `bin`
  files can do (never their content) for the newest 3 versions of each package it serves. Because it compares with
  what your proxy served, it depends on what this machine has installed. npm prints "its entry file gained a capability
  its previous version did not have";
- an install hook loads a prebuilt native module shipped in the tarball (a `.node` file with a Linux, Windows or macOS
  binary header, named in the hook command, run through `node-gyp-build`, or required by a hook target), the tarball
  ships no native source (no C, C++ or other source file, and no `binding.gyp` that lists a source), and another file is
  text hidden under a one-byte XOR (not readable text, but one single-byte key turns it into text). A module shipped
  without its source is recorded on the row on its own, never a warning. npm prints "an install script loads a
  prebuilt native module shipped without its source, next to an encoded file";
- a `binding.gyp` or `.gypi` file runs a script from the package (with node, bun, deno, sh, bash, python, perl or ruby)
  in a command expansion (`<!(...)`) and discards the script's output. npm builds a `binding.gyp` at the package root
  while installing, even with no install script. npm prints "its native build file runs a package script during
  install and hides the output".

These last two read every file in the archive (the first 2 MiB of each; the XOR test reads the first 1 MiB), not only
the kept files. They do not read a file with a zero byte in its first 8,000 bytes for hidden text, a key longer than one
byte, or a module loaded some other way (by `main`, a `bin` file or a dependency). An archive of more than 20,000 files
is "not checked" for them.

The other tarball checks are contributing notes, shown in `chaingate why` and `chaingate report --json`, never a
warning on their own:
- a hook target under 8 KiB carries a network call and a way to run code (a loader);
- an entry file carries 20 or more `_0x` identifiers and a decode marker (eval, Function, atob, a long
  String.fromCharCode run, hex escapes over 15 % of the file, or 1,000 or more numeric hex literals);
- a file carries a credential source (.npmrc, ssh keys, cloud credentials, token variables, a process.env dump) and a
  known exfiltration host (a raw IP or a POST to another host is recorded, never enough on its own);
- an entry file overrides `XMLHttpRequest.prototype.send`, `window.fetch` or `window.ethereum.request` and carries two
  or more cryptocurrency-address regexes.

The download that reveals a tarball warning has already been served, so `chaingate report` lists it at once and the
next download that reaches ChainGate carries the npm notice. A row names the markers that matched, the file and its
size -- never the file's content. A file that is binary, over the cap, absent, or named only by the tarball's own
`package.json` is "not checked" and says so; a check that found no eligible file to read says "no eligible file in the
tarball". A tarball is examined once: the outcome rides every later record of that version. A version 0.1.5 recorded
as "not armed" is read at its next download.

**Holding a download until it is checked (optional).** With the `static_withhold` setting on
(`"static_withhold": true` in ChainGate's `config.json`), the proxy holds a download it reads in memory, up to 8 MiB,
while the tarball checks read it. If one of the six tarball warnings fires, npm receives HTTP 403
`withheld_by_static_check`, naming the check and `chaingate why <pkg>@<ver>`, and the package is not installed. The
recorded decision stays WARN: withholding is a choice about serving, not a different verdict. A download over 8 MiB is
served and recorded as it is without the switch. The switch is off by default.

**Recorded facts (0.1.5).** Beside the rows, the proxy records facts that change no verdict, no warning and no notice.
They are there to be read and counted first; using any of them to decide is a later change. For each version it serves,
once, after its first download's rows are final:
- whether it is the `latest` dist-tag, and which tags point at it;
- for each named sign on it, whether the version this proxy served before already had it ("not new since <version>");
- whether its publisher is a known owner: a listed maintainer, an earlier publisher, or the publisher of most earlier
  versions;
- where a size change against the version served before came from: documentation, source maps, declaration files, a
  second module format, or other files.

For each download they read, the tarball checks also record:
- each long base64 or hex run in a file: its length, how many different characters it uses, and what its decoded first
  bytes are (WebAssembly, PNG, gzip or a web font);
- for a hook target over the 1 MiB cap, which the walk reads through once without keeping it: the share of the file in
  base64 runs and what the first run decodes to;
- dynamic-code and raw-IP matches, with those under `test/`, `__tests__/`, `fixtures/`, `vendor/` or `node_modules/`
  paths counted apart;
- a hook command or file that writes under an AI coding agent's configuration folder (such as `~/.claude`, `~/.cursor`
  or `~/.codex`);
- a tarball with no network, file, process, environment, execution or encoding use at all;
- after the download, whether the registry's provenance record names the same source repository as the package metadata
  (the record's signature is not checked), or whether the version served before had provenance and this one has none.
  This one costs a request to the registry, so it is made only for a version that already carries one of the 0.1.5
  reasons above.

`chaingate why <pkg>@<ver>` prints them under "Recorded facts" and "Static check facts", `chaingate report --json`
carries them, and the report text names a version with a notable fact.

A "not evaluable" added-dependency or "not checked" install-script comparison is kept in the record
(`chaingate why <pkg>@<ver>`). npm does not print it. The report counts a release as checked when another named rule
(an introduced install script, or the seed's strict tier) gave a result, and as not checked only when no named rule did.

`chaingate check` (the CI command) evaluates the seed. The rules on introduced install scripts, added dependencies and
differing install scripts are reported by the proxy, not by `check`.

Since 0.1.5, `chaingate check <pkg>@<ver> --packument <file> --tarball <file>` also reads that local archive offline --
the install-script comparison and the tarball checks above, the keep list from the packument's manifest -- and reports
their rows in the record's `tarball` member (0.1.5 wrote `chaingate.check/4`, which is `/3` plus that one optional
member; since 0.1.6 every check writes `chaingate.check/5`, below). Offline
there is no earlier version to compare, so the entry-file comparison says it is not applicable. Those rows never change
the decision or the exit code in 0.1.5: a CI job that wants to gate on them reads `tarball.disposition`.

In 0.1.5 a check against seed v3.2 or later also wrote `chaingate.check/4`, with or without `--tarball`: `/4` carries its
placement `new-family-cold-start`, the first prerelease of a new tag (for example the first `-rc`), which has no earlier
version of its own tag to compare against. Since 0.1.6 every check writes `chaingate.check/5`: `/4` under the 0.1.6
policy, whose decision carries a `retier` member when a strict-tier row warned before it was compared with the
release this one follows (that release, how it was chosen, the signals that are not new, the guards that held, and
`recorded` or `raised`).

**What you see.** For a named warning, a refusal that rests on a fact (a recorded advisory or a content change), or a
version your pin withholds, ChainGate sends npm a notice on the tarball response, and npm prints it. Other refusals (an
evaluation that failed or is busy, a full record) carry only the HTTP error. `chaingate why <pkg>@<ver>`, the command the
notice names, shows the proxy's recorded decision for that version (labelled UNBOUND, exit code 4):

```console
npm notice chaingate: WARNING q@1.5.0: release-history break vs the seed (2+ package-wide signals). Details: chaingate why q@1.5.0
npm notice chaingate: BLOCKED p@1.3.0: a recorded advisory names this version. Details: chaingate why p@1.3.0
```

npm prints a notice only on a response it does not cache (npm 10 and 11). So a named-WARN tarball is
sent `no-store`. Two consequences follow:
- An offline or `--prefer-offline` install cannot take that tarball from npm's cache.
- `chaingate accept` makes the version cacheable again (below).

A dist-tag that ChainGate moves off a blocked version is not printed by npm, because the metadata stays cacheable. The
report shows it instead.

**The report.** `chaingate report` says what the proxy served and refused in your last install:
- each named warning: what moved, the baseline, what already happened, the last version without the signal, and what
  to do;
- each refusal, and each dist-tag moved off a blocked version;
- how many packages no named rule checked, and why.

`--all` shows every install the running proxy holds; `--json` gives the record. Without a running proxy it reads
ChainGate's disk record of the last 24 h (`--since 7d` to change), which keeps only named warnings and the refusals and
dist-tag moves that rest on a fact (a pin refusal, for example, is not on disk).
- Exit codes: 0 = nothing named, refused or moved; 2 = named warnings; 3 = a refusal or a moved dist-tag; 4 = a tool
  error, or an incomplete record with nothing else to report.
- The report covers only what reached ChainGate: npm's own cache is invisible to it.

**Your actions:**
- `chaingate accept <pkg>@<ver>` accepts a named warning for that exact version.
  - ChainGate stops sending the notice while the version's record shows only the signals you accepted. A later or
    different signal warns again.
  - It never overrides a BLOCK: a later advisory for that version still blocks it.
  - `--revoke` undoes it and `--list` shows them.
- `chaingate pin <pkg>@<K>` keeps `<pkg>` on K within K's major (for 0.x, within 0.y). Every newer version in that range,
  prereleases included, is withheld until `chaingate unpin <pkg>`.
  - A running proxy (0.1.4 or later) that reads the same ChainGate directory (the same `--scope` or
    `CHAINGATE_HOME`) applies it at once, and the command says whether it did. npm may keep using metadata it
    cached for up to about 5 minutes, and `npm install --prefer-online` refreshes it.
  - A withheld version requested from a lockfile is refused with a notice naming your pin.
- `chaingate allow <pkg>@<ver> --reason "..."` keeps its meaning: an exact-version override for a false-positive BLOCK.
  A pin wins over an override on a version it withholds, and both commands say so.

These actions, and each `chaingate why`, are recorded locally with the version's classes at that moment, for a later
reading of which warnings anyone acted on; no command displays it in 0.1.4 or 0.1.5. Nothing leaves the machine.

**Local endpoints.** `/_chaingate/self` and `/_chaingate/report` answer only local, non-browser requests: a loopback
client and a loopback `Host`, no `Origin` header, and `Sec-Fetch-Site` absent or `none`. This keeps a web page from
reading your installed package names through DNS rebinding.

**ALLOW / WARN / BLOCK enforcement** with a persisted decision log, per-version
overrides, and CI-friendly exit codes from `chaingate check` (0 / 2 / 3; 4 = tool error). `chaingate check --json`
emits a versioned `chaingate.check/5` record (0.1.5 wrote `/3` or `/4`, 0.1.4 `/3`, 0.1.3 `/2` and 0.1.2 and earlier
`/1`; all are still read); `examples/ci/` has an offline CI consumer for them.

**A failure never turns a BLOCK into permission.** A BLOCK stays in force until the check that issued it
definitively clears it (for example, the content hash matches its first-seen value again, or the seed no longer
records the advisory), or until you add an exact override with `chaingate allow`. A skipped check, an error, missing
evidence, an unreadable seed or an input the seed cannot use never clears it. This also applies to decisions written
by earlier versions; nothing in your history is rewritten.

**Exception, by your choice:** with `on_unusable_input: WARN`, a version whose stored decision cannot be read at all is
served. A BLOCK the running proxy holds in memory is still refused. Without a v3 seed (a legacy seed or
`--no-seed`), a decision that cannot be read is refused; those configurations do not provide v3 detection.

**When a BLOCK cannot be stored.** If a BLOCK decision cannot be stored, the running proxy remembers and
enforces it in memory. Restarting the proxy clears that memory. After a restart, a version is evaluated again before
its tarball is served (with the failure policy above), and a BLOCK that this evaluation reproduces from the seed or the
stored history is refused again. A BLOCK it cannot reproduce is lost at the restart, for example a content-hash BLOCK
whose stored baseline is no longer available.

**What the proxy cannot see.** ChainGate decides only requests that reach it:
- npm reuses its local cache by content hash without contacting any registry, so a version already in the cache is
  installed without a check. Give CI jobs an empty cache, and clear the cache (`npm cache clean --force`) when you
  start using ChainGate on a machine;
- a lockfile `resolved` URL on any host other than `registry.npmjs.org` or the proxy (a private registry, a mirror)
  is fetched from that host directly. With `replace-registry-host=never`, even `registry.npmjs.org` URLs are;
- an upstream other than `registry.npmjs.org` may give tarball URLs on its own host, which npm then fetches directly.

**Protected CI workflow (tested):**
1. Start the proxy with your seed (`chaingate init --seed <folder>/chaingate-seed-v3.db.gz`).
2. Set `registry` to the proxy, and keep npm's default `replace-registry-host`.
3. Keep lockfile `resolved` URLs on `registry.npmjs.org`.
4. Run `npm ci --cache "$(mktemp -d)"`.

A pinned version then fails the install; any other version is evaluated before it is served.

This in-memory record is bounded: by default 50,000 entries and an estimated 64 MiB of retained data. You can change
these with `unstored_block_cap_entries` and `unstored_block_cap_bytes` in the configuration, or
`CHAINGATE_UNSTORED_BLOCK_CAP_ENTRIES` and `CHAINGATE_UNSTORED_BLOCK_CAP_BYTES`. The bound applies to the record, not
to the proxy's total memory, and the default values are not a safe limit for every machine. Nothing is ever
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
per major version and flags when it stops. Both are contributing signals: they are shown
beside a named warning and never warn on their own. Both work only from a package's recorded history.

**Tests.** `npm test` runs the full suite.

## Quick Start

You need no account or subscription. You download the detection seed yourself once (below), and
ChainGate verifies it locally.

Install from npm. ChainGate supports Node.js 22 (22.19.0 or later) and 24, the versions `package.json`
declares. The command is `chaingate` either way:

```bash
npm install -g @cgsec/chaingate        # global
chaingate --help

npm install @cgsec/chaingate           # or inside a project
npx chaingate --help
```

**Upgrading.** After installing a new version, restart the proxy (`chaingate stop`, then `chaingate init`). Until then
the proxy that is running keeps the old version's rules, and `chaingate doctor` reports the version mismatch as
TAMPER. The first install that touches each package afterwards records a current decision for every version of it
that npm's metadata still lists, except a BLOCK that is reached again, which keeps its stored row (rows are only
appended).

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
# (npm 11.19.0 also names it npm install-scripts approve better-sqlite3; checked on 11.19.0, absent from 10.9.7)

# with ignore-scripts=true in your npm configuration: rebuild just that package
cd "$(npm root -g)/@cgsec/chaingate" && npm rebuild better-sqlite3 --ignore-scripts=false
```

`--allow-scripts` works for global installs only. npm rejects it for project installs, which use
`allowScripts` in your own `package.json` instead. The `allowScripts` entry in ChainGate's own
`package.json` applies only when developing ChainGate itself and grants nothing in your project. Do
not enable every dependency's scripts to fix this.

**Supported platforms.** ChainGate is tested on Linux x64 (Ubuntu 24.04), macOS 15 on arm64 and x64, and Windows
Server 2022 and Windows 10 on x64, with Node.js 22 and 24 and npm 10, 11 and 12. Anything else is untested and not
supported. The SQLite module installs from its official prebuilt binary, with no Python or compiler.

Not tested on Windows:
- **A real full disk.** Free-space handling there was exercised only by a simulated free-space figure and injected
  write errors.
- **An activation file that is a symbolic link.** A standard account cannot create one; a junction was tested.

**On Windows:**

- If PowerShell refuses to run `npm` or `chaingate` ("running scripts is disabled on this system"),
  type `npm.cmd` and `chaingate.cmd` instead. The Command Prompt uses the `.cmd` launchers
  automatically. You do not need to change the execution policy.
- Approve the SQLite script in the install command, so npm does not warn about it or skip it:
  `npm.cmd install -g @cgsec/chaingate --allow-scripts=better-sqlite3`. To approve it once for all
  your global installs: `npm.cmd config set allow-scripts=better-sqlite3 --location=user`.
- Start ChainGate with your v3 seed:
  `chaingate.cmd init --seed C:\path\to\chaingate-seed-v3.db.gz`. On a new install,
  `init` without `--seed` downloads the older legacy witness seed instead (see below).
- [SEEDS.md](SEEDS.md) shows how to check a seed file's SHA-256 in PowerShell.

From source:

```bash
git clone https://github.com/cgsec-labs/chaingate.git
cd chaingate && npm install
npm test
```

**You download the full v3 detection seed file yourself.** It is published as the signed GitHub release
[seed-v3.3-full](https://github.com/cgsec-labs/chaingate/releases/tag/seed-v3.3-full). Download its
`chaingate-seed-v3.db.gz`, `chaingate-seed-v3.db.sha256` and `chaingate-seed-v3.db.sig` assets into one folder
(about 1 GB to download, about 2.4 GB once installed) and pass the `.gz` file with `--seed`. **ChainGate does not
download the full file for you**; with the seed cache on (the default), it fetches the same seed in buckets instead (see
[The seed cache](#the-seed-cache-016)). seed-v3.3-full needs ChainGate 0.1.6 or later: earlier versions refuse it and
keep the seed they have.

Since 0.1.5, `--seed` also takes the compressed database, `chaingate-seed-v3.db.gz`, not only an uncompressed
`chaingate-seed-v3.db`. ChainGate decompresses it into its own staging copy (at most 8 GiB, with free space checked
for the decompressed size first). The `.sha256` and `.sig` files describe the decompressed database, and ChainGate
checks the `.sha256` file and verifies the signature against the key built into the runtime over the decompressed
database, exactly as for an uncompressed download. Seeds larger than GitHub's 2 GiB per-file limit, from seed v3.2 on,
are published only as `.gz`.
The release page lists the seed's exact identifiers and how to verify the download yourself.
[SECURITY.md](SECURITY.md) describes the trust model. An unsigned seed still needs `--unsigned-development`, and the tool then reports
`authenticated: false`.

Since 0.1.6, `chaingate init` without `--seed` sets up v3 detection through the seed cache (see
[The seed cache](#the-seed-cache-016)) unless `"seed_cache": false`. When the cache is off or its host has none to give
yet, init does what it did before: on a new install (no v3 seed and no witness database yet) it downloads the older,
signed legacy witness seed (about 100 MB) and tells you so. It never downloads with `--no-seed`, or on a host that uses a
v3 seed. For a full v3 seed file, pass `--seed`.

**1. Initialize.** This installs the v3 seed, starts the proxy and points npm at it:

```console
$ chaingate init --seed ./seed-v3.3/chaingate-seed-v3.db.gz
Verifying v3 seed signature...
✓ v3 seed signature verified
✓ v3 seed bundle <bundle id> active
  sha256 daaa783e8d85df9d...  snapshot <snapshot>...  trust authenticated (authenticated)
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
  placement: recorded
  ...
$ echo $?
0
```

Exit codes: 0 ALLOW, 2 WARN, 3 BLOCK, 4 tool error. `--json` gives the `chaingate.check/5` record (above). `check` evaluates the seed: the rules on introduced install
scripts, added dependencies and differing install scripts are reported by the proxy (above).

A version named in a recorded advisory is blocked even when the release cannot be evaluated (for example a
manifest the adapter rejects), and the result names the advisory.

**4. Explain.** `chaingate why` explains a result. It never changes one:

- `chaingate why <pkg>@<ver> --packument <file>` evaluates the release, then explains the result.
- `chaingate why --from <check.json>` explains a saved `check --json` result without evaluating again.
- `chaingate why <pkg>@<ver> --cached` shows an old stored decision, labelled cached and unbound
  (`CACHED-UNBOUND` in `--json`) because it records no seed, rule or policy identity, and exits with code 4.
- `chaingate why <pkg>@<ver>` with no mode (the form ChainGate's npm notices print) is the same as `--cached`: the
  proxy's recorded decision, including the rows for introduced install scripts, added dependencies, differing install
  scripts and the tarball checks, which `--packument` (seed only, like `check`) does not evaluate.

Anything that could not be evaluated is listed with the reason. Missing evidence is never reported
as a clean result. `why` also records, locally, that it was asked about that version (best-effort; it never changes
its output or exit code).

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

**The proxy port.** `chaingate init`, `chaingate stop` and `chaingate status` always use port 6173 on 127.0.0.1:
`init` starts the proxy there and points `.npmrc` at it, and `stop` and `status` look for it there.
`chaingate doctor`, `chaingate report` and `chaingate pin` reach the proxy at `CHAINGATE_PORT` when it is set, and at
6173 otherwise. A proxy you start yourself listens on `CHAINGATE_PORT` when it is set.

While ChainGate's block is in your `.npmrc`, npm sends every request to the proxy. If the proxy is
not running, for example after a restart, npm cannot install anything until you either run
`chaingate init` again, which restarts the proxy on the active seed, or run `chaingate stop`, which
restores `.npmrc`.

**Updating the seed.** Switch to another v3 seed you have with
`chaingate update-seed --seed <folder>/chaingate-seed-v3.db.gz` (add `--unsigned-development` only for an
unsigned seed), and go back to the
previous one with `chaingate update-seed --rollback`. A running proxy keeps its current seed until
you restart it with `chaingate stop && chaingate init`. On a host that uses a v3 seed,
`chaingate update-seed` without `--seed` **refuses**, because a full v3 seed file is not downloaded
automatically (the seed cache keeps itself current; see [The seed cache](#the-seed-cache-016)). `update-seed --seed` accepts v3 seeds only; a legacy seed file is refused (see
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
  npm registry metadata and published as signed GitHub
  releases (`seed-v3.*`), starting with `seed-v3.1-full`; the current one is `seed-v3.3-full`.
  **You download the full file yourself; it is not downloaded automatically** (with the seed cache on, ChainGate
  fetches the same seed in buckets instead). It is opened read-only and checked
  against its `.sha256` file. It counts as authenticated only when its signature verifies against the
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

## The advisory feed (0.1.6)

The seed names known malicious versions as of the day it was built. The advisory feed adds the ones recorded since then: a
signed list of package versions, cut hourly, read after the seed's own list. A version the feed names is a BLOCK, as a
seed entry is; `chaingate allow` lifts it for that version. (`chaingate pin` is unrelated: it keeps you on a version you
chose.) The notice says "a recorded advisory names this version", or "a ChainGate analyst record names this version" when
the entry comes from ChainGate's own review of a captured tarball rather than a public advisory. For such an entry,
`chaingate why` also says whether the registry's integrity for the version matches the tarball that was reviewed. The
version is blocked either way; a difference is a warning beside the BLOCK and one line in the proxy log.

**It makes an outbound connection, on by default.** The proxy fetches the feed from
`https://raw.githubusercontent.com/cgsec-labs/chaingate-pins/main/pins/` when it starts and then every hour, while a
v3 seed is in use, and `chaingate init` says that it is on. Each fetch is a few plain GET requests to that host: no
account, no registry token, and nothing about your packages or this machine. `"advisory_feed": false` in ChainGate's
`config.json` turns it off (`chaingate init` keeps that setting), `"advisory_feed_url": "<https URL>"` fetches a copy
from another host, and a host with no seed never fetches. `chaingate update-advisories`
fetches it now; `chaingate update-advisories --file <dir>` reads a copy from a local directory.

**What it accepts.** A cut is used only when it verifies:

- its signature is by a feed key that a key list signed with the seed key names, valid at the cut's own time;
- it is later than the cut ChainGate already has, and it names the cut before it. A newer cut is taken only when the
  chain of cuts between the two is complete, each one checked; a missing or wrong cut refuses it.
- A cut is held until you take it with `chaingate update-advisories --accept-cut <sha256>` when it is more than 7 days
  newer than the one held, adds more than 2,000 versions, or removes more than 100 versions or a quarter of those held
  (whichever is fewer; an empty cut always). A version moved from one advisory to another counts as neither. For a cut
  that removes versions, the message lists up to 20 of them that this proxy blocked in the last 30 days.
  `chaingate status` shows the command with its digest.

Whatever happens, the last accepted cut keeps serving. `chaingate status` shows the cut and its age; `chaingate doctor`
gives a notice when it is older than 48 hours, stale past 7 days, held, or when the last fetch was refused or failed.

## The seed cache (0.1.6)

The seed is also published in pieces: 16,384 buckets of packages (a package's bucket is fixed by its name, so a bucket holds
the records of about 22 package names) under a signed index. With the seed cache, ChainGate fetches only the buckets it
needs instead of the whole seed file, and the index is refreshed every hour.

**It is on by default, with an outbound connection to `https://shards.cgsec.dev/`.** `chaingate init`, run without
`--seed`, fetches the index and the buckets of the packages in the current directory's `package-lock.json` (or
`npm-shrinkwrap.json`). When a package the proxy decides falls in a bucket the cache does not hold yet, the proxy fetches
that bucket first and waits for it at most 5 seconds. If it has not arrived by then, that decision says the seed did not
check the package, which warns (as for a package the seed does not cover; `on_no_evidence` decides), and the bucket keeps
downloading for the next one. `chaingate check` fetches the bucket of the package it checks the same way, with the same
5-second bound. A bucket the host no longer has (a newer index replaced it) is asked for once more after the
index is fetched again; if it is still missing, the decision is the same as for a bucket that has not arrived. The index
is fetched again at start and every hour; a request with nothing new is answered "not modified". Each request is a plain GET with no account, no registry token and no identifiers.
`"seed_cache": false` in `config.json` turns it off; ChainGate then reads a full seed you install with
`chaingate init --seed`. `init --seed`, `update-seed --seed` and `update-seed --rollback` set it for you and say so, so
the full seed they install or activate is the one ChainGate reads; remove the setting to use the seed cache again. `"seed_cache_url": "<https URL>"` fetches from another host.

**What the host learns.** Each bucket request names one bucket, which narrows a package to about 22 names that share
it. The host, like any web server, also sees the address of the machine that asks. A full seed file reveals nothing about
your packages; use it if this matters to you.

**What it accepts.** The index is used only when its signature is by a key that a key list signed with the seed key
names, valid at the time ChainGate fetches it, and only when it is later than the index the cache holds. A bucket is
checked before anything in it is read: its size and sha256 against the index, then its records against the digest the
index names. A bucket that fails is not used, and the rest of the cache keeps serving. A bucket already held is checked
again the first time it is used after the proxy starts. An index more than 7 days old is stated on every decision, and
`chaingate doctor` gives a notice past 48 hours. A cache holding at least one bucket takes the place of an installed full
seed; until then the full seed serves. `chaingate status` shows the index, the seed it was cut from, its age and how many buckets are held.

**Licences.** The buckets are cut from a published seed release (the one `chaingate status` names) and carry its terms:
the seed is licensed CC BY 4.0, and the data in it keeps its own licence: GitHub Advisory Database records (GHSA
identifiers) CC BY 4.0, OpenSSF malicious-packages records (MAL identifiers) Apache-2.0 (see [SEEDS.md](SEEDS.md)). The
host serves that release's third-party notices at `https://shards.cgsec.dev/THIRD_PARTY_NOTICES.txt`; the signed index
names the file and its sha256, and `chaingate status` and `chaingate doctor` show its address. ChainGate never fetches or
reads the file to decide anything.

## What's Next

**A GitHub Action (0.1.7).** A ready-made action that runs `chaingate check` in a CI job, on the same seed cache and
advisory feed as a workstation.

**Detection rules as code.** Export the gate rules and their evidence so that your own tools can
read and audit them, instead of receiving a single score.

**Structured evidence output.** One documented format for a decision and the evidence behind it.

**Integrations.** SIEM, EDR, CI pipelines and agent workflows that read that format.

Also planned: more calibration, PyPI support, and plugins for Artifactory and Nexus.

## Limitations

A release warns only on a named rule. A takeover that changes the publisher, the provenance, the dependencies or the
code, but trips no named rule, gets no warning unless the seed's strict tier marks the release. The files npm will run
are read on every download, but only for the named patterns above, so a takeover through the same CI/CD workflow, as
the same publisher, that changes only the code in some other way looks normal. Code analysis is needed for those cases.

## Architecture

```
┌───────────────────────────────────────────────┐
│                CHAINGATE PROXY                │
│                                               │
│  ┌──────────────┐   ┌──────────────────────┐  │
│  │   WITNESS    │   │  SEED (v3)           │  │
│  │ content hash │   │  advisories, history │  │
│  │ pkg profiles │   │  strict / loose tier │  │
│  │ append-only  │   └──────────┬───────────┘  │
│  └──────┬───────┘              │              │
│         ▼                      ▼              │
│  ┌─────────────────────────────────────────┐  │
│  │      POLICY                             │  │
│  │  FACTS (advisory, content hash) → BLOCK │  │
│  │  NAMED RULES (strict tier, install      │  │
│  │    scripts, deps, files)        → WARN  │  │
│  │  CONTRIBUTING (publisher, deps, prove-  │  │
│  │    nance, age, scope, size, npm) → note │  │
│  └─────────────────────────────────────────┘  │
└───────────────────────────────────────────────┘
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

