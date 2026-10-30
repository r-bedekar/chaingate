Signed toy shards fixture v3 (seed shards 1.0, contract 1.3, lineage pair +platfam1, read layout g10-rl1; the root signs
seed_version, notices_sha256 and notices_path). FIXTURE KEYS ONLY, generated per run; only public keys here.
good/: root.json (canonical), root.json.gz, root.json.sig (raw Ed25519 by the shards key over the ASCII sha256 hex
of root.json), buckets/NNNNN.db.gz (8 buckets, bucket_bits 3: a production reader refuses anything but 14),
keys.json + keys.json.sig (pins-keys-1.0 form, role shards, signed by the fixture seed key), fixture-seed-pub.pem,
THIRD_PARTY_NOTICES.txt (the file the root's notices_path names; its sha256 is notices_sha256; display only),
expected.json (the reader's time, bucket of each name, the pins, the full seed logical digest, the lineage pair, the
bucket holding rl1 rows (pkg-a's) and the held buckets with none).
Root: canonical bytes; keys.json verifies under the seed key; a shards key valid at the time whose key_id the root
names and matches its spki; the signature verifies. Bucket: gz_bytes bound, gz_sha256, decompress under
raw_bytes_max as one gzip stream, stage, logical digest and bucket rule, then import whole.
cases/: cases.json lists each case: the files of good/ it replaces (in cases/<name>/), the reader's time, and the
reason a reader must refuse. All 8 buckets imported under good/ give seed_logical_digest.
