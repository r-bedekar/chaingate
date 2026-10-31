# ChainGate v3 detection seeds

This file records the exact identity of each v3 detection seed that is offered for download, and
how to check a download. It lives in the signed git history, so the digests below can be verified
through the maintainer's git signing key, independently of the release page that hosts the files.

A full v3 seed file is never downloaded automatically: you pass it to `chaingate init --seed`. Since 0.1.6 the seed cache,
on by default, fetches the current seed in buckets instead (README, "The seed cache"); installing a full seed with
`init --seed` or `update-seed --seed` turns the seed cache off, so the file you install is the one ChainGate reads.

## seed-v3.3-full: signed v3 detection seed (current)

**Status:** published as the GitHub release
[seed-v3.3-full](https://github.com/cgsec-labs/chaingate/releases/tag/seed-v3.3-full), for
`@cgsec/chaingate` 0.1.6 or later. 0.1.5 and earlier cannot read it: they refuse it and keep the seed they have.

- **Signed.** The seed is signed with the ChainGate seed key `ed25519:09f6c9fdb8f5a2ea`, the key built into the
  runtime (`witness/seed_verify.js`). The runtime checks the signature before it imports anything, and the seed
  installs in `authenticated` mode.
- **Git record.** The signed annotated tag `seed-v3.3-full` points at the signed marker commit
  `15d15026845fdca79656f3deee7800fc2207d12a`, whose `SEED-RELEASE.md` records the seed, key, record and asset digests.
- **Compressed only.** The database is larger than a single GitHub release asset can be, so it is published as
  `chaingate-seed-v3.db.gz`. The `.sha256` and `.sig` files are over the decompressed database.
- **Seed cache.** The seed cache's host (`https://shards.cgsec.dev/`) serves this seed in buckets under a signed index
  that names it, with its `THIRD_PARTY_NOTICES.txt`.

| Field | Value |
|---|---|
| file | `chaingate-seed-v3.db` (decompressed), 2,430,681,088 bytes; `chaingate-seed-v3.db.gz`, 992,716,347 bytes |
| file SHA-256 | `daaa783e8d85df9d7d75168112d1835a0f31272d154c5086830a966c4e41e9ab` (decompressed) |
| data cutoff | 2026-10-29T23:14:59Z; advisories reviewed up to 2026-10-30T00:22:00Z |
| content | 367,612 npm packages and 1,023,772 lineages; 2,942 pinned package versions |
| signing key | `ed25519:09f6c9fdb8f5a2ea` |

### Verify the download

Use the seed key from the seed-v3.1-full section below. The signature is Ed25519 over the decompressed database's
SHA-256 written as 64 lower-case hex characters, with no newline. With OpenSSL 3:

```
H=$(gzip -dc chaingate-seed-v3.db.gz | sha256sum | cut -d' ' -f1)
[ "$H" = "$(cut -c1-64 chaingate-seed-v3.db.sha256)" ] && echo "digest OK"
printf '%s' "$H" > msg.txt
openssl pkeyutl -verify -pubin -inkey chaingate-seed-key.pem -rawin -in msg.txt -sigfile chaingate-seed-v3.db.sig
```

The expected output is `digest OK`, then `Signature Verified Successfully`.

### Asset digests (sha256)

```
dd6bcfa5e4af8ddf9d81cc9dbfdefc07e6beac5bfbace33160686465d6338701  chaingate-seed-v3.db.gz
8038d94e47455d28d00f19e7bce0d65f149c3e3b68a97a777d988a4413814714  chaingate-seed-v3.db.sha256
92f836cf40aed7ef19e2a13d06b2af482099c7ea68b81ae2bddc15989d49d51b  chaingate-seed-v3.db.manifest.json
e654ea4618c988530c0fa56e6279c32fb279cf062fd13bf4f19ce5b30cedebdd  chaingate-seed-v3.db.sig
de3adde65d00e6d15169cbe697d42ca9cf9bb08b4f9a161fcdd8e74f63448245  chaingate-seed-v3.db.manifest.sig
fae56cc0a488688ab3ee36a59c162974f10af55aa81e19d786556831a019f548  THIRD_PARTY_NOTICES.txt
```

### Use it

Download `chaingate-seed-v3.db.gz`, `chaingate-seed-v3.db.sha256` and `chaingate-seed-v3.db.sig` into one folder, then:

```bash
chaingate update-seed --seed <folder>/chaingate-seed-v3.db.gz     # an existing install
chaingate init --seed <folder>/chaingate-seed-v3.db.gz            # a new install
```

Upgrade the runtime to 0.1.6 before you switch to this seed. To go back to 0.1.5, first return to seed-v3.2-full with
`chaingate update-seed --rollback`. Do not add `--unsigned-development`: this seed is signed and never needs it.

## seed-v3.2-full: signed v3 detection seed (previous)

**Status:** published as the GitHub release
[seed-v3.2-full](https://github.com/cgsec-labs/chaingate/releases/tag/seed-v3.2-full), for
`@cgsec/chaingate` 0.1.5 or later. 0.1.4 and earlier cannot read it.

- **Signed.** The seed is signed with the ChainGate seed key `ed25519:09f6c9fdb8f5a2ea`, the key built into the
  runtime (`witness/seed_verify.js`). The runtime checks the signature before it imports anything, and the seed
  installs in `authenticated` mode.
- **Git record.** The signed annotated tag `seed-v3.2-full` points at the signed marker commit
  `d508535b6d788d610fd28c00a627b2fcefee612f`, whose `SEED-RELEASE.md` records the seed, key, record and asset digests.
  The marker names the 0.1.5 release candidate the seed was first qualified on (tarball sha256
  `d97036f41e4c68843cc64e76de24c8a010280ef60da999ca5a9b08e56796c5d8`), which was not published. The seed was then
  qualified again, unchanged, on the published 0.1.5 (tarball sha256
  `a8c362ca4a142c7c1b7741b9cbd8ce11259a516c1d1b90397a10b5160ece6d7e`).
- **Compressed only.** The database is larger than a single GitHub release asset can be, so it is published as
  `chaingate-seed-v3.db.gz`. The `.sha256` and `.sig` files are over the decompressed database.

| Field | Value |
|---|---|
| file | `chaingate-seed-v3.db` (decompressed), 2,359,566,336 bytes; `chaingate-seed-v3.db.gz`, 983,721,048 bytes |
| file SHA-256 | `1408e015a7026ea292624e25fb709b4fb6085de2a9a2549cd403caecdc1b0bf7` (decompressed) |
| data cutoff | 2026-10-18T19:15:48Z; advisories reviewed up to 2026-10-19T10:32:00Z |
| content | 367,611 npm packages and 1,018,655 lineages; 2,913 pinned package versions |
| signing key | `ed25519:09f6c9fdb8f5a2ea` |

### Verify the download

Use the seed key from the seed-v3.1-full section below. The signature is Ed25519 over the decompressed database's
SHA-256 written as 64 lower-case hex characters, with no newline. With OpenSSL 3:

```
H=$(gzip -dc chaingate-seed-v3.db.gz | sha256sum | cut -d' ' -f1)
[ "$H" = "$(cut -c1-64 chaingate-seed-v3.db.sha256)" ] && echo "digest OK"
printf '%s' "$H" > msg.txt
openssl pkeyutl -verify -pubin -inkey chaingate-seed-key.pem -rawin -in msg.txt -sigfile chaingate-seed-v3.db.sig
```

The expected output is `digest OK`, then `Signature Verified Successfully`.

### Asset digests (sha256)

```
685ee0fed454f5f4523c9a3c6f82b670f5661a58743254cb2032721471e66e1e  chaingate-seed-v3.db.gz
eff6b8a39584b41d6b7bee6ab1b8b09be0a0c35c90868fc18c93d6281d30d131  chaingate-seed-v3.db.sha256
87caaabf1d806a202fe66fd25468f01a548ebbfc26b07a001e1f4e2a73ef386c  chaingate-seed-v3.db.manifest.json
fbd5550f2e86c13a50f83af43159e161906a837fbb52e8a449cd4c7b7dc67ec4  chaingate-seed-v3.db.sig
506a51ed20580d5f1d7d93a2e6f3d9c333bb12dca02dbbc3426d153dc4c095a8  chaingate-seed-v3.db.manifest.sig
7e6f7d4583345ec8fc1820c80640fb8d9c37737b45fd0359033e298c2bd8f4b0  THIRD_PARTY_NOTICES.txt
```

### Use it

Download `chaingate-seed-v3.db.gz`, `chaingate-seed-v3.db.sha256` and `chaingate-seed-v3.db.sig` into one folder, then:

```bash
chaingate update-seed --seed <folder>/chaingate-seed-v3.db.gz     # an existing install
chaingate init --seed <folder>/chaingate-seed-v3.db.gz            # a new install
```

Upgrade the runtime to 0.1.5 before you switch to this seed. To go back to 0.1.4, first return to seed-v3.1-full with
`chaingate update-seed --rollback`. Do not add `--unsigned-development`: this seed is signed and never needs it.

## seed-v3.1-full: signed v3 detection seed (older)

**Status:** published as the GitHub pre-release
[seed-v3.1-full](https://github.com/cgsec-labs/chaingate/releases/tag/seed-v3.1-full), for
`@cgsec/chaingate` 0.1.4. 0.1.5 also reads it.

- **Signed.** The seed is signed with the ChainGate seed key `ed25519:09f6c9fdb8f5a2ea`, the key built into the
  runtime (`witness/seed_verify.js`). The runtime checks the signature before it imports anything, and the seed
  installs in `authenticated` mode.
- **Git record.** The signed annotated tag `seed-v3.1-full` points at the signed marker commit
  `a283b65a93760c9392a97e6a76182521f86de9b0`, whose `SEED-RELEASE.md` records the seed, key, runtime, record and asset
  digests.

| Field | Value |
|---|---|
| file | `chaingate-seed-v3.db`, 1,960,910,848 bytes |
| file SHA-256 | `a4c4e364de00653bea01c9f0a5ca5655a6ba2e2488e9a96a7da045f75bc89790` |
| data cutoff | 2026-10-12T12:18:13Z |
| content | 367,580 npm packages and 736,659 lineages; 810 pinned package versions |
| signing key | `ed25519:09f6c9fdb8f5a2ea` |

### Verify the download

The seed key, save it as `chaingate-seed-key.pem`:

```
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAP2W40LmbxTrDqDKaOpbfWD/xrbSPW4hz6RqQxZFte5E=
-----END PUBLIC KEY-----
```

The signature is Ed25519 over the database's SHA-256 written as 64 lower-case hex characters, with no newline. With
OpenSSL 3:

```
H=$(sha256sum chaingate-seed-v3.db | cut -d' ' -f1)
[ "$H" = "$(cut -c1-64 chaingate-seed-v3.db.sha256)" ] && echo "digest OK"
printf '%s' "$H" > msg.txt
openssl pkeyutl -verify -pubin -inkey chaingate-seed-key.pem -rawin -in msg.txt -sigfile chaingate-seed-v3.db.sig
```

The expected output is `digest OK`, then `Signature Verified Successfully`.

### Asset digests (sha256)

```
a4c4e364de00653bea01c9f0a5ca5655a6ba2e2488e9a96a7da045f75bc89790  chaingate-seed-v3.db
bcf624c23dd4a5a9f0a86bff83cafef9d530956b742ea2ea301991ceefc527ec  chaingate-seed-v3.db.sha256
c5a06109926cd623cc8cfdc25a6986ce865a33c7ccc5119d98b989bb0d095b6f  chaingate-seed-v3.db.manifest.json
b2cf178c981033e66b0573b8aad57243efe2f395efadea4ba84d7fb613821ac3  chaingate-seed-v3.db.sig
b2715a4041ebc3c4e6ed1d04cc62f8d085c6093cad65a3dc6db2eda6e747e755  chaingate-seed-v3.db.manifest.sig
14e5830c6b1693c5608196fb648adc1b6da93b23f480a5d8e9e2e4c98155c66c  THIRD_PARTY_NOTICES.txt
80e3ce8965b49a27c8689a9e51990941c5003d6bb282236bb07c9df202d3906f  chaingate-seed-v3.db.gz
```

### Use it

Download `chaingate-seed-v3.db`, `chaingate-seed-v3.db.sha256` and `chaingate-seed-v3.db.sig` into one folder, then:

```bash
chaingate update-seed --seed <folder>/chaingate-seed-v3.db     # an existing install
chaingate init --seed <folder>/chaingate-seed-v3.db            # a new install
```

With ChainGate 0.1.5 or later you can download `chaingate-seed-v3.db.gz` instead of the database, with the same
`.sha256` and `.sig`, and pass `<folder>/chaingate-seed-v3.db.gz` to `--seed`. The `.sha256` and the signature are
checked over the decompressed database.

Do not add `--unsigned-development`. This seed is signed and never needs it; that option is only for unsigned
engineering and test seeds.

To request a correction or a removal (for example a withdrawn advisory or a wrong pairing), open an issue at
https://github.com/cgsec-labs/chaingate/issues. Corrected seeds are cut with the regular classification refresh, every one
to two weeks.

The seed is licensed CC BY 4.0; third-party data keeps its own terms (see `THIRD_PARTY_NOTICES.txt` on the release).

## Data sources and attribution

The seed is derived data: package metadata and advisory identifiers. It contains no package code.

- **Package metadata** comes from the public npm registry, replicated through its public APIs.
- **Publisher and maintainer identities** are present only as unkeyed SHA-256 digests.
  - **They are pseudonymous, not anonymous.** Anyone who knows an address can recompute its digest.
- **Advisory identifiers** were obtained from the OSV API (`api.osv.dev`), not from npm's security
  endpoints:
  - **GitHub Advisory Database** (GHSA identifiers): licensed CC BY 4.0,
    https://github.com/github/advisory-database/blob/main/LICENSE.md.
  - **OpenSSF malicious-packages** (MAL identifiers): licensed Apache-2.0,
    https://github.com/ossf/malicious-packages/blob/main/LICENSE.
  - The seed records identifiers, versions and the resulting pins. It does not reproduce the
    advisory text.
- **Seven pins without a source or identifier** (`@immobiliarelabs/backstage-plugin-gitlab`, seven
  versions):
  - they are ChainGate analyst labels added on 2026-06-26 from a public incident report;
  - OSV has since published `MAL-2026-6526` for the same seven versions;
  - a seed built before that still shows them without a source.
