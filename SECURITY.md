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
