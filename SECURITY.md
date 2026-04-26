# Security and Trust Model

## Reporting vulnerabilities

Please report security issues privately to the maintainer via
the email listed in the repository's contact information. Do
not open public issues for vulnerabilities.

## Trust model

ChainGate's runtime trusts a single Ed25519 public key, embedded
as a literal in `witness/seed_verify.js`. The corresponding
private key signs every seed bundle published to this
repository's releases. The runtime rejects any seed bundle
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

The signing private key currently resides on a single build host
as a file with restricted permissions (mode 0400, single-user
readable). This host is the operational trust root for seed
signing. We acknowledge this is a single point of failure and
intend to migrate to keyless signing via Sigstore and GitHub
Actions OIDC before broader adoption (target: before npm
publication of the `chaingate` package).

Until that migration is complete, users in regulated environments
or with elevated trust requirements may:

- Pin a specific seed version rather than auto-updating
- Audit the released `chaingate-seed.db.manifest.json` against
  the published Ed25519 fingerprint manually
- Verify the seed's SHA-256 against the published `.sha256` file

### Verification properties

ChainGate performs cryptographic verification at two distinct
moments, and it is worth being precise about what each one does
and does not prove.

At install time — invoked from `chaingate init` and `chaingate
update-seed` — the CLI does the full bundle check: it streams the
freshly-fetched `chaingate-seed.db`, computes its SHA-256, and
compares the result to the published `.sha256` file. It then
verifies that the `.sha256` contents are signed by the pinned
Ed25519 key. This combination defends against transit corruption
of the bundle bytes and against registry tampering of any of the
three artifacts in isolation. A failure at install time aborts
the install before any state is written.

Post-install — invoked from `chaingate doctor` and the integrity
gate that runs before mutating commands — the CLI verifies only
the persisted `.sha256/.sig` pair against the pinned key. It does
not re-hash the live `witness.db`. This is deliberate: `witness.db`
is a mutable runtime database. Schema migrations apply when the
runtime version moves ahead of an older bundle; gate decisions
get appended in normal use; both legitimately change the file's
bytes. A post-install check that compared the live hash to the
install-time hash would fire false-positive on every healthy
installation. What the post-install check does prove — and the
property that matters at this layer — is that this install was
seeded from a bundle signed by the project's pinned key.
Defending the local `witness.db` against an attacker who already has filesystem
write access is outside the cryptographic threat model; the
relevant defense at that layer is filesystem permissions on
`~/.chaingate/`.

## Build and signing

Seed bundles are produced by a private collector infrastructure
that ingests metadata from public package registries (npm, PyPI)
and the OSV vulnerability database. Each bundle is signed with
the Ed25519 key described above and published as a release on
this repository.

Release notes for each bundle attribute the build to a specific
commit on the private infrastructure repository. Reproducibility
of the bundle from public sources alone is not currently a goal;
this may be revisited as part of the trust-model migration.

## Seed release resolution

The chaingate CLI resolves the most recent seed release dynamically
via the GitHub REST API rather than relying on a fixed download URL.
On `chaingate update-seed`:

1. The CLI calls `https://api.github.com/repos/r-bedekar/chaingate/releases`
2. Filters releases whose tag matches `^seed-v\d+(\.\d+)*$`
3. Selects the most recently published matching release
4. Fetches the four assets (`chaingate-seed.db`, `.sha256`, `.sig`,
   `.manifest.json`) from that release
5. Verifies SHA-256 and Ed25519 signature locally before installing

This design decouples seed releases from any future CLI version
releases on the same repository: a future `v1.0.0` CLI release
won't shadow a recent `seed-v3` for users running `update-seed`.
The `releases/latest/download/...` URL pattern is intentionally
NOT used.

The CLI uses unauthenticated GitHub API calls (60 requests per
hour, per IP). Resolution requires one API call per `update-seed`;
asset downloads are direct HTTP fetches that do not count against
the API rate limit.

## Disclosure

This document represents the current state. The trust model is
expected to evolve as ChainGate moves from pre-launch to broader
adoption. Material changes to this document will be reflected in
the runtime and announced in release notes.
