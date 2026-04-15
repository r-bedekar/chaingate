# ChainGate seed signing

The Ed25519 **public key** that verifies ChainGate seed bundles is committed
here as `pubkey.pem`. It is the exact same key embedded literally as
`CHAINGATE_SEED_PUBKEY_B64` in `witness/seed_verify.js`.

| Field        | Value                                                                |
|--------------|----------------------------------------------------------------------|
| Algorithm    | Ed25519                                                              |
| Fingerprint  | `ed25519:09f6c9fdb8f5a2ea` (first 16 hex of SHA-256 of 32-byte raw) |
| SPKI b64     | `MCowBQYDK2VwAyEAP2W40LmbxTrDqDKaOpbfWD/xrbSPW4hz6RqQxZFte5E=`       |
| Created      | 2026-04-14                                                           |

## Custody

- The **private** key lives outside this repository at
  `~/.chaingate-signing/privkey.pem` on the ChainGate VPS. `chmod 0400`.
- It is **never** copied off the VPS, never synced to cloud storage, never
  checked into git. `.gitignore` carries a belt-and-suspenders entry for
  `collector/signing/privkey.pem` and `*.key`.
- `collector/export_seed.py` reads this key directly on the VPS. CI never
  sees it.

## Rotation

Rotation is a v1.1 concern (documented in `docs/P5.md` Appendix A). The
procedure requires:
1. Generating a new Ed25519 keypair.
2. Updating the literal in `witness/seed_verify.js`.
3. Cutting a new `chaingate` npm release with that updated verifier.
4. Re-signing the next seed bundle with the new private key.
5. Old seed bundles become unverifiable on new CLI versions.

## Verifying the pubkey matches the embedded literal

```bash
# The b64 on the SPKI line must match CHAINGATE_SEED_PUBKEY_B64:
grep -v '^-' collector/signing/pubkey.pem | tr -d '\n'
```
