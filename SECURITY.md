# Security and Trust Model

## Reporting vulnerabilities

Please report security issues privately to the maintainer via
the email listed in the repository's contact information. Do
not open public issues for vulnerabilities.

## Trust model

ChainGate's runtime trusts a single Ed25519 public key, embedded
as a literal in `witness/seed_verify.js`. The corresponding
private key signs the seeds published to this repository's releases:
the legacy witness seed bundles (`seed-v2.x`) and the v3 detection
seeds (`seed-v3.*`, starting with `seed-v3.1-full`). The runtime rejects any seed bundle
whose signature does not verify against this pinned key,
regardless of where the bundle is hosted or how it is delivered.

### Pinned public key

```
ed25519:09f6c9fdb8f5a2ea
```

The full base64-encoded public key is visible in
`witness/seed_verify.js`. Users concerned about supply-chain
risk should verify each release independently against this
fingerprint.

### Current key custody

The private key that signs all ChainGate seeds (legacy witness seeds
`seed-v2.x` and v3 detection seeds `seed-v3.*`, starting with
`seed-v3.1-full`) resides on a single build host as a file with
restricted permissions (mode 0400, in an owner-only directory).
Signing is a manual maintainer step: the seed tooling refuses to sign
unless the release's qualification record is accepted, checks this
before it reads the key, and never reads the key otherwise. The public
key's fingerprint is `ed25519:09f6c9fdb8f5a2ea`; its only use is seed
signing. The public key is embedded in the runtime
(`witness/seed_verify.js`), so rotating it requires a new runtime
release; there is no online revocation, and a compromised key would be
answered by a runtime release pinning a new key and re-signed seeds,
while older runtimes keep trusting the old key. Users can verify a
seed themselves with the PEM and the openssl command in the release
notes and SEEDS.md; the runtime verifies the signature automatically
before import. That host is the trust root for seed signing,
and it is a single point of failure. The plan is to move seed signing
to keyless signing with Sigstore and GitHub Actions OIDC before wider
use. That migration has
**not** happened yet.

**Recorded deferral (2026-09-28).** An earlier version of this
document targeted that migration "before npm publication of the
`chaingate` package". For the **research-preview** npm release of
`@cgsec/chaingate`, the maintainer has explicitly **deferred** the
seed-signing migration. That release publishes **no new seed**. The
deferral authorizes no seed signing and no seed publication, and it
makes **no claim of npm package provenance** (see "npm package
provenance" below). The unscoped `chaingate` package on npm is an
unrelated project.

**Update (2026-10-13).** The v3 detection seed `seed-v3.1-full` was
signed with the pinned key and published as a GitHub pre-release. The
keyless-signing migration above has still not happened.

Until the migration is complete, users in regulated environments
or with elevated trust requirements may:

- Pin a specific legacy seed version rather than auto-updating.
- Verify a legacy seed themselves: check that `chaingate-seed.db`
  hashes to the value in `chaingate-seed.db.sha256`, and that
  `chaingate-seed.db.sig` is a valid Ed25519 signature over the
  contents of that `.sha256` file under the pinned key.
- Treat `chaingate-seed.db.manifest.json` as **informational only**:
  the signature does not cover it, and the CLI does not fetch it.

### The advisory feed (0.1.6)

The advisory feed is a signed list of known malicious package versions, read after the seed's own
list (README, "The advisory feed"). The runtime embeds no feed key. The seed key signs a key list
(`keys.json`, with its signature in `keys.json.sig`) that names each feed key, its key id in the form
above, and a validity window of at most 90 days. A cut's signature is Ed25519 over the sha256 hex of
the cut file, as for the seed, by the feed key the cut's header names, valid at the cut's own time.
Each cut names the one before it, and the runtime takes a newer cut only when every cut between it
and the one it holds is present and verifies.

A stolen feed key could publish a cut that adds wrong BLOCKs (`chaingate allow` lifts one) or that
leaves out versions the feed named before. A cut adding more than 2,000 versions, or removing more
than 100 or a quarter of those held, is held for a manual step that names the versions it would
lift. The seed's own entries are not affected by the feed. A cut cannot be replayed or rolled back
past the cut a host holds, and every dated cut stays public, so a change is visible. The fetch is an
outbound connection, on by default, to raw.githubusercontent.com (or the configured
`advisory_feed_url` host, https only), at proxy start and hourly. It sends no identifiers, but that
host sees the address of each client that fetches, as GitHub does for a seed download. It is off
with `"advisory_feed": false`.

### The seed cache (0.1.6)

The seed cache reads the seed as buckets under a signed index (README, "The seed cache"). The runtime embeds no key for
it: the key list that names the advisory feed's key also names the seed cache's, signed with the seed key, each key valid
for at most 90 days. The index is Ed25519-signed over the sha256 hex of its bytes and is accepted only at the reader's own
clock, never at a time the index states. The copy of the key list served beside the index must equal the advisory feed's,
byte for byte, when the feed is on. A bucket is used only after its size, its sha256 and the digest of its records match
what the index names; it is imported whole or not at all. A bucket changed in the cache file after import is refused the
first time it is read after a start; the others keep serving.

A stolen seed cache key could publish an index that leaves packages out or changes their history, until the key list
drops the key (at most 90 days). An index older than the one held is refused. The fetch is an outbound connection, on by
default, to shards.cgsec.dev (or the configured `seed_cache_url` host, https only), at `init`, at proxy start, hourly, and
for each bucket a decision needs (in the proxy or `chaingate check`). A bucket request tells that host which of 16,384 buckets a machine needs, which narrows a
package to about 22 names. It is off with `"seed_cache": false`.

### v3 detection seeds and trust modes

The full v3 detection seed file is **supplied locally** (`chaingate init --seed <file>`,
`chaingate update-seed --seed <file>`). It is **not downloaded automatically**; since 0.1.6 the seed cache (above)
fetches the same seed in signed buckets instead, unless it is off.
The first published v3 seed is `seed-v3.1-full`, a signed GitHub
pre-release (see SEEDS.md). Before use, the runtime checks the
seed's schema and contract versions, its required bindings and its
SHA-256 against the `.sha256` sidecar, and opens it read-only.

There are exactly two trust modes, and no silent downgrade:

- `authenticated` (the default) requires a signature that verifies
  against the pinned key.
- `unsigned-development` must be requested by name
  (`--unsigned-development`). It tolerates a missing signature and says
  so: the proxy and `chaingate check --json` report
  `authenticated: false`. **The SHA-256 check then proves only that the
  file matches its own sidecar. It does not prove who produced it.** Use
  it only with a seed file you obtained from a source you trust.

In both modes, a signature that is present but cannot be checked is
refused rather than ignored. The published `seed-v3.1-full` seed is
signed with the pinned key and installs in `authenticated` mode. The
earlier v3.0-rc3 test seed, never published as a release, is unsigned.

### Verification properties

ChainGate verifies legacy seeds at two different points. Each check
proves something different.

For **legacy witness seeds**, at install time (invoked from
`chaingate init` and `chaingate update-seed`), the CLI does the full
bundle check: it streams the
freshly-fetched `chaingate-seed.db`, computes its SHA-256, and
compares the result to the published `.sha256` file. It then
verifies that the `.sha256` contents are signed by the pinned
Ed25519 key. This combination defends against transit corruption
of the bundle bytes and against registry tampering of any of the
three artifacts in isolation. A failure at install time aborts
the install before any state is written.

Post-install (invoked from `chaingate doctor` and the integrity
gate that runs before mutating commands), the CLI verifies only
the persisted `.sha256/.sig` pair against the pinned key. It does
not re-hash the live `witness.db`. This is deliberate: `witness.db`
is a mutable runtime database. Schema migrations apply when the
runtime version moves ahead of an older bundle; gate decisions
get appended in normal use; both legitimately change the file's
bytes. A post-install check that compared the live hash to the
install-time hash would fire false-positive on every healthy
installation. What the post-install check does prove, and the
property that matters at this layer, is that this install was
seeded from a bundle signed by the project's pinned key.
The persisted pair shows that the installed seed came from a signed bundle; it does not
authenticate the current, mutable `witness.db`.

While an interrupted legacy installation is pending (`witness.db.install-pending.json`), the persisted
pair on disk may be the old pair, a partial pair or the new pair. ChainGate never leaves an old digest
beside a new signature, but none of those states describes what is installed. So `chaingate doctor`
reports the seed signature as unverifiable, and the integrity gate refuses every mutating command
except the one that completes the installation. For that command it waives only this refusal: the
other integrity checks, and the verification of the incoming seed, still apply.

The commands added in 0.1.4 that change what is served or what is reported -- `chaingate accept`, `chaingate pin` and
`chaingate unpin` -- pass the same integrity gate as every other mutating command. `chaingate why` records, best-effort
and without the gate, only that it was asked about a version (a local action record); that record is never an input to
any decision, notice or refusal.

Defending the local `witness.db` against an attacker who already has filesystem
write access is outside what the signatures can protect. At that
level, the protection is the filesystem permissions on
`~/.chaingate/`.

### What `chaingate doctor` checks about ChainGate itself

The `self-witness` check compares two recorded values: the tarball integrity that npm recorded when
it installed `@cgsec/chaingate` (in `node_modules/.package-lock.json`), and the integrity the witness
store holds for that version. It shows whether the package npm installed is the one the witness
recorded. It has limits:

- It does not hash the installed files, so changes made to them after installation are not detected.
- It cannot run for a normal global install (`npm install -g`), because npm writes no
  `.package-lock.json` for global installs. Doctor reports it as skipped. The same applies to
  `npm link` and to other package managers.
- It needs a witness baseline for the installed version. That baseline comes from a legacy witness
  seed or from the proxy recording the registry's metadata. With a v3 seed only, the baseline is not
  authenticated.

## Build and signing

Seed bundles are built on the maintainer's private collection
servers from public package registry metadata (npm, PyPI) and the
OSV vulnerability database.

- **Legacy witness seeds** (`seed-v2.x`) are signed with the
  Ed25519 key described above and published as releases on this
  repository.
- **v3 detection seeds**, starting with `seed-v3.1-full`, are signed
  with the same key and published as releases on this repository.
  Authenticated mode is the default. `unsigned-development` is only
  for unsigned engineering and test seeds such as v3.0-rc3, which was
  never published as a release.

Release notes for each bundle attribute the build to a specific
commit on the private infrastructure repository. Reproducibility
of the bundle from public sources alone is not currently a goal;
this may be revisited as part of the trust-model migration.

## Seed release resolution (legacy witness seeds only)

This section applies only to the legacy witness seed. **Automatic
download of v3 detection seeds is not available:** on a host whose
detection runs from a v3 bundle, plain `chaingate update-seed` (without
`--seed`) refuses and changes nothing.

The chaingate CLI resolves the most recent legacy seed release dynamically
via the GitHub REST API rather than relying on a fixed download URL.
On `chaingate update-seed`:

1. The CLI calls `https://api.github.com/repos/cgsec-labs/chaingate/releases`
2. Filters releases whose tag matches `^seed-v\d+(\.\d+)*$`
3. Selects the most recently published matching release
4. Fetches three assets from that release: `chaingate-seed.db`,
   `chaingate-seed.db.sha256` and `chaingate-seed.db.sig`. (A
   release also carries `chaingate-seed.db.manifest.json`; the CLI
   does not fetch it and the signature does not cover it.)
5. Verifies SHA-256 and Ed25519 signature locally before installing

Each download is bounded on the bytes actually received, whatever the server's headers say: at most
256 MiB for the database and 4 KiB for each signature file, with connection, idle and total time
limits. The temporary download directory is removed on every exit path. This limit applies only to
legacy seed downloads, not to v3 seeds or to a local file given with `--seed`.

This design decouples seed releases from any future CLI version
releases on the same repository: a future `v1.0.0` CLI release
won't shadow a recent `seed-v3` for users running `update-seed`.
The `releases/latest/download/...` URL pattern is intentionally
NOT used.

The CLI uses unauthenticated GitHub API calls (60 requests per
hour, per IP). Resolution requires one API call per `update-seed`;
asset downloads are direct HTTP fetches that do not count against
the API rate limit.

## npm package provenance

Releases of `@cgsec/chaingate` published from a maintainer machine
carry **no npm provenance statement**. npm provenance
(https://docs.npmjs.com/generating-provenance-statements/) links a
package version to the source commit and build that produced it,
and requires publishing from a supported CI provider (for example
GitHub Actions) with `--provenance`. Until releases are published
that way, compare a release with its tagged source commit to verify
it; each release names the exact commit it was built from.

## Upstream registry connections

The proxy trusts its configured upstream registry for content. The
measures below remove one connection-reuse condition. They do not
make an untrusted registry trustworthy.

- **Pinned HTTP client.** All upstream requests use an Agent from the
  pinned `undici` (an exact 8.x version since 0.1.6; an exact 6.x
  version from 0.1.1 to 0.1.5). These are packuments
  (including the metadata request the proxy makes to evaluate a version
  before serving a tarball it has not evaluated in this run),
  tarballs, background dependency lookups and the raw upstream
  fallback the proxy uses when an unexpected internal error occurs
  before any decision exists under `on_unusable_input: WARN` or with
  pilot gates only (under `on_unusable_input: BLOCK`, or while the
  record of unstored BLOCKs is full, the proxy refuses such requests
  instead). The Agent is set explicitly because on Node 22 importing
  `node:http` installs Node's own bundled undici as the process-wide
  default. Without that, the pinned version would never handle
  upstream traffic. The process-wide default itself is left
  unchanged.
- **Upstream close during a slow download.** With undici 6, a
  registry that closed the connection while the proxy was still
  waiting to pass a download on to a slow or departed npm client could
  stop the proxy process with an internal assertion (upstream undici
  issue 5360). undici 8.4.1 and later end such a response normally;
  0.1.6 moved to undici 8 for this fix, which is why it needs Node.js
  22.19.0 or later on Node 22. Redirects (at most 2 for packuments and
  tarballs, none for attestation bundles) are followed by undici's
  redirect interceptor, which drops `authorization` and cookies when a
  redirect leaves the origin, as undici 6 did.
- **No upstream connection reuse.** Keep-alive is disabled
  (`pipelining: 0`). Every upstream request uses its own connection,
  sends `connection: close`, and the connection is closed after the
  response.

  This is our mitigation for behaviour we reproduced locally. It is
  not an upstream advisory update. An upstream that writes an
  unsolicited response onto an idle keep-alive socket can have it
  delivered for the next request (GHSA-35p6-xmwp-9g52). undici 6.28.1
  fixed the case of a socket's first reuse. In loopback tests the
  later-reuse case still reproduced on 6.28.1 at the same rate as on
  6.25.0. The cost is one new connection (and TLS handshake) per
  upstream request.

### Node's bundled HTTP client (separate limitation)

`chaingate init` and `update-seed` download legacy witness seeds with
Node's built-in `fetch()`. That uses the undici bundled with Node
(6.24.1 in Node 22.22.2), not the pinned package, so a package update
cannot patch it. It follows the Node version installed. Downloaded
legacy seeds are still checked against their SHA-256 and Ed25519
signature before use (see above).

## Seed downloads

v3 detection seeds are never downloaded automatically. When one is made available for download, its
exact identifiers (file SHA-256, logical digest, corpus snapshot) are recorded in
[SEEDS.md](SEEDS.md) in a signed commit, with a signed git tag carrying the file digest.
[SEEDS.md](SEEDS.md) explains how to verify both the git signature and the file. That verification
authenticates the digest through the maintainer's git signing key. A signed seed such as `seed-v3.1-full` is also
verified at runtime against the pinned key. The git record does not make an unsigned seed signature-verified at
runtime: the tool still reports `authenticated: false`.

## Platform support

The README's "Supported platforms" paragraph names the platforms ChainGate is tested on; anything else is untested. On
Windows that includes a standard (non-administrator) account on Windows 10 with Node 24.

On Windows (from 0.1.2), the active and previous seed bundles are recorded in one file,
`seeds\activation.json`, which is replaced in a single rename: Windows cannot rename a symbolic link
over an existing one, even for an administrator, and creating one may need Developer Mode. The
record is validated strictly on every read; if it is malformed or names a bundle that is missing or
outside the seeds directory, ChainGate refuses to run detection instead of guessing. Linux and macOS
keep symbolic links. Running ChainGate as Administrator, or enabling Developer Mode, is not a
supported workaround. Mixing ChainGate versions on one Windows home directory is not supported.

## Disclosure

This document describes the current state. The trust model will
change as ChainGate moves beyond a research preview. Significant
changes will be made in the runtime and announced in release notes.
