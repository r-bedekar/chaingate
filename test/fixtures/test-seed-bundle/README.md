# test-seed-bundle

Minimal signed seed bundle used by `test/integration/update-seed.test.js`.

## Files committed
- `chaingate-seed.db` — SQLite DB built from the vendored bundle SCHEMA
  (`test/fixtures/bundle-schema.sql`) with one fixture package, one version,
  and the standard `seed_metadata` rows.
- `chaingate-seed.db.sha256` — hex-encoded SHA-256 of the `.db`.
- `chaingate-seed.db.sig` — raw 64-byte Ed25519 signature over the SHA-256
  hex bytes (matches `collector/export_seed.py` signing convention).

## Identity
- `seed_version = "2026.test.1"`
- `exported_at  = "2026-04-26T00:00:00Z"`
- Signed by a **throwaway** Ed25519 keypair generated at build time and
  discarded. Not the production signing key. Never store the privkey here
  or anywhere else — the bundle is regenerable.

## Why the fixture sig isn't actually verified
The integration test mocks `verifySeed` so it does not check this signature
against the throwaway pubkey. Production-key signature verification is
covered by `test/witness/seed_verify.test.js`. This fixture's job is to
exercise the schema/swap/migration/preservation logic downstream of
verification.

## Regenerate
```
node test/fixtures/test-seed-bundle/build.js
```

This rewrites all three `.db`, `.sha256`, `.sig` files. The SHA-256 and
signature change every regeneration (different ephemeral key, different
DB header timestamps); commit the new files alongside the change that
prompted regeneration.

## Drifted variant

A sibling fixture lives at `../test-seed-bundle-drifted/`. It simulates
a pre-Option-C bundle (e.g., seed-v2.1) that predates the
`dep_first_publish` table — the bundle SCHEMA exec'd at build time has
that CREATE TABLE removed in-memory before the SQLite DB is built.

Used by the schema-gap recovery integration test to prove that
`applySchema` running post-swap in `update-seed.js` correctly fills in
the missing table.

Both fixtures share this `build.js`. Regenerate the drifted variant:
```
node test/fixtures/test-seed-bundle/build.js --drift
```

Identity differences from the happy-path fixture: `seed_version =
"2026.test.1.drifted"`, `dep_first_publish` table absent in the `.db`,
otherwise structurally identical (one package, one version,
seed_metadata, throwaway-key signature).
