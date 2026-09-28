# ChainGate v3 detection seeds

This file records the exact identity of each v3 detection seed that is offered for download, and
how to check a download. It lives in the signed git history, so the digests below can be verified
through the maintainer's git signing key, independently of the release page that hosts the files.

A v3 seed is never downloaded automatically: you pass it to `chaingate init --seed`.

## seed-v3.0-rc3: unsigned v3 research prerelease, not release-qualified

**Status:** prepared. The files are downloadable only if the GitHub prerelease `seed-v3.0-rc3` is
published. If that release does not exist, this seed is not available.

- **Not release-qualified.** It passed the bootstrap gate profile only; the release profile has not
  run.
- **Unsigned.** It carries no seed signature. Use it only with `--unsigned-development`; the tool
  reports `authenticated: false`.
- **Git signature, not a seed signature.** The git commit and tag that record these digests are
  signed with the maintainer's git signing key. That authenticates this record, not the seed itself.

| Field | Value |
|---|---|
| file | `chaingate-seed.db`, 1,943,855,104 bytes |
| file SHA-256 | `974c7d7ea2f24ef627074517ea49b2f089d5e8108bc22b60401e6b1b612376dc` |
| `chaingate-seed.db.sha256` (contents: the file SHA-256 and a newline, no filename) | SHA-256 `eef7045b9c23272d7ad41d544ae4ac442ec5bbadce1751238b9e01b3069d4bb2` |
| `chaingate-seed.db.manifest.json` | SHA-256 `e140e806f7b6a71dbb8ba7fc53fc52bfa04294d04bbf3fce585818bbdb7fd957` |
| seed logical digest | `b3f9b1ab0b0ac2d12da011b10fceaa46562548fbd8e4c6dfeaefffb6d54c9521` |
| corpus snapshot digest | `d47e8679d6dd4c5f295f5c9201db08b99b28c391a3a1981e77cce3202875941e` |
| corpus snapshot | 2026-09-19T23:50:26+03:00; 368,879 packages; 23,752,890 versions |
| gate profile | `bootstrap` |

### 1. Verify this record (the git signature)

The maintainer's git signing key:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIADj46VirEcIgq2xi6UiH66C7vx1UPiiZynIoNoIh28l
```

- **Fingerprint:** `SHA256:zbLchuE+udpzKR52Oiv2129cKjL9smHZ8d+Ul2k+LdQ`.
- **Principal:** `rbedekar@zeroinsec.com`.
- **Confirm the key through a second channel:** GitHub lists it as the signing key of
  `@r-bedekar`, at `https://api.github.com/users/r-bedekar/ssh_signing_keys`. Compare the full key.

**Online steps**, done once:

```bash
git clone https://github.com/r-bedekar/chaingate.git
cd chaingate
git fetch --tags
```

**Offline steps:**

```bash
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIADj46VirEcIgq2xi6UiH66C7vx1UPiiZynIoNoIh28l\n' > signer.pub
ssh-keygen -lf signer.pub               # must show SHA256:zbLchuE+udpzKR52Oiv2129cKjL9smHZ8d+Ul2k+LdQ
printf 'rbedekar@zeroinsec.com namespaces="git" %s\n' "$(cat signer.pub)" > allowed_signers
git -c gpg.ssh.allowedSignersFile=allowed_signers verify-tag seed-v3.0-rc3
git -c gpg.ssh.allowedSignersFile=allowed_signers verify-commit seed-v3.0-rc3^{commit}
git cat-file -p seed-v3.0-rc3           # the tag message carries the file SHA-256
```

**Expected output:**
- **Signature check:** both `verify` commands print
  `Good "git" signature for rbedekar@zeroinsec.com with ED25519 key SHA256:zbLchuE+udpzKR52Oiv2129cKjL9smHZ8d+Ul2k+LdQ`
  and exit 0.
- **A different key:** the check fails with `No principal matched`.
- **The record:** read this file at that commit (`git show seed-v3.0-rc3:SEEDS.md`) and use the file
  SHA-256 above as the trusted digest.

On Windows, run the same commands in Git Bash. They need Git 2.34 or later and OpenSSH's `ssh-keygen`.

### 2. Verify the downloaded file

Compare with the **trusted digest from step 1**, not only with the `.sha256` file from the same
release page.

**Linux:**

```bash
expected=974c7d7ea2f24ef627074517ea49b2f089d5e8108bc22b60401e6b1b612376dc
[ "$(tr -d '[:space:]' < chaingate-seed.db.sha256)" = "$expected" ] && echo ".sha256 file matches"
echo "$expected  chaingate-seed.db" | sha256sum -c -
```

**macOS:** the same, with `shasum -a 256 -c -` in place of `sha256sum -c -`.

**Windows (PowerShell):**

```powershell
$expected = '974c7d7ea2f24ef627074517ea49b2f089d5e8108bc22b60401e6b1b612376dc'
(Get-Content .\chaingate-seed.db.sha256 -Raw).Trim() -eq $expected
(Get-FileHash .\chaingate-seed.db -Algorithm SHA256).Hash.ToLower() -eq $expected
```

Both lines must print `True`. For `cmd`, run `certutil -hashfile chaingate-seed.db SHA256` and
compare the output with the trusted digest, ignoring case.

### 3. Use it

```bash
chaingate init --seed ./chaingate-seed.db --unsigned-development
```

### Data sources and attribution

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
  - the frozen seed is unchanged and still shows them without a source.
