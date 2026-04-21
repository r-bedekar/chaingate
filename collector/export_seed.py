"""Export signed SQLite seed bundle from ChainGate Postgres.

Reads the VPS witness store (Postgres) read-only, writes a fresh SQLite DB
matching the V1 npm-only schema from docs/P5.md §4, signs it with the
embedded Ed25519 signing key, and emits a 4-file bundle:

    chaingate-seed.db              # SQLite database
    chaingate-seed.db.sha256       # hex sha256 of the .db
    chaingate-seed.db.sig          # raw 64-byte Ed25519 signature over the sha256 hex bytes
    chaingate-seed.db.manifest.json

Usage:
    python -m collector.export_seed \
        --out-dir seed_export \
        --seed-version 2026.04.14.1 \
        --key ~/.chaingate-signing/privkey.pem
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dotenv import load_dotenv

SCHEMA_SQL = """
CREATE TABLE packages (
    id           INTEGER PRIMARY KEY,
    ecosystem    TEXT NOT NULL CHECK (ecosystem = 'npm'),
    package_name TEXT NOT NULL,
    UNIQUE (ecosystem, package_name)
);

CREATE TABLE versions (
    id                          INTEGER PRIMARY KEY,
    package_id                  INTEGER NOT NULL REFERENCES packages(id),
    version                     TEXT NOT NULL,
    published_at                TEXT,
    content_hash                TEXT,
    content_hash_algo           TEXT,
    integrity_hash              TEXT,
    git_head                    TEXT,
    package_size_bytes          INTEGER,
    dependency_count            INTEGER,
    dependencies                TEXT,
    dev_dependencies            TEXT,
    peer_dependencies           TEXT,
    optional_dependencies       TEXT,
    bundled_dependencies        TEXT,
    dev_dependency_count        INTEGER,
    peer_dependency_count       INTEGER,
    optional_dependency_count   INTEGER,
    bundled_dependency_count    INTEGER,
    publisher_name              TEXT,
    publisher_email             TEXT,
    publisher_tool              TEXT,
    maintainers                 TEXT,
    publish_method              TEXT,
    provenance_present          INTEGER,
    provenance_details          TEXT,
    has_install_scripts         INTEGER,
    source_repo_url             TEXT,
    license                     TEXT,
    first_observed_at           TEXT,
    last_seen_at                TEXT,
    provenance_source           TEXT NOT NULL DEFAULT 'collected'
                                 CHECK (provenance_source IN ('collected', 'reconstructed')),
    UNIQUE (package_id, version)
);

CREATE TABLE version_files (
    id                INTEGER PRIMARY KEY,
    version_id        INTEGER NOT NULL REFERENCES versions(id),
    filename          TEXT NOT NULL,
    packagetype       TEXT,
    content_hash      TEXT,
    content_hash_algo TEXT,
    size_bytes        INTEGER,
    uploaded_at       TEXT,
    url               TEXT,
    first_observed_at TEXT,
    last_seen_at      TEXT,
    UNIQUE (version_id, filename)
);

CREATE TABLE gate_decisions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name TEXT NOT NULL,
    version      TEXT NOT NULL,
    disposition  TEXT NOT NULL CHECK (disposition IN ('ALLOW','WARN','BLOCK')),
    gates_fired  TEXT NOT NULL,
    decided_at   TEXT DEFAULT (datetime('now'))
);

CREATE TABLE overrides (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name TEXT NOT NULL,
    version      TEXT NOT NULL,
    reason       TEXT NOT NULL,
    created_at   TEXT DEFAULT (datetime('now')),
    UNIQUE (package_name, version)
);

CREATE TABLE seed_metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE attack_labels (
    id                     INTEGER PRIMARY KEY,
    package_id             INTEGER NOT NULL REFERENCES packages(id),
    version_id             INTEGER REFERENCES versions(id),
    is_malicious           INTEGER NOT NULL CHECK (is_malicious IN (0, 1)),
    attack_name            TEXT,
    source                 TEXT,
    advisory_id            TEXT,
    aliases                TEXT,
    severity               TEXT,
    summary                TEXT,
    affected_range         TEXT,
    url                    TEXT,
    modified_at            TEXT,
    advisory_published_at  TEXT,
    detection_lag_days     INTEGER,
    provenance_source      TEXT NOT NULL DEFAULT 'collected'
                            CHECK (provenance_source IN ('collected', 'reconstructed'))
);

CREATE INDEX idx_versions_pkg      ON versions(package_id);
CREATE INDEX idx_versions_pub_at   ON versions(package_id, published_at DESC);
CREATE INDEX idx_vfiles_ver        ON version_files(version_id);
CREATE INDEX idx_decisions_pkg_ver ON gate_decisions(package_name, version);
CREATE INDEX idx_decisions_at      ON gate_decisions(decided_at DESC);
CREATE UNIQUE INDEX idx_overrides  ON overrides(package_name, version);
CREATE INDEX idx_attack_labels_pkg ON attack_labels(package_id);
CREATE INDEX idx_attack_labels_ver ON attack_labels(version_id);
CREATE INDEX idx_attack_labels_mal ON attack_labels(is_malicious) WHERE is_malicious = 1;
CREATE UNIQUE INDEX idx_attack_labels_adv_pkg
    ON attack_labels(advisory_id, package_id)
    WHERE advisory_id IS NOT NULL;
CREATE INDEX idx_versions_reconstructed
    ON versions(provenance_source)
    WHERE provenance_source = 'reconstructed';
CREATE INDEX idx_attack_labels_reconstructed
    ON attack_labels(provenance_source)
    WHERE provenance_source = 'reconstructed';
"""

RECONSTRUCTED_FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent
    / "validation"
    / "fixtures"
    / "reconstructed-attacks.json"
)

REQUIRED_FIXTURE_FIELDS = (
    "package_name", "version", "published_at_ms",
    "publisher_name", "publisher_email",
    "integrity_hash", "has_install_scripts",
    "provenance_present", "dependencies",
)

VERSION_SELECT = """
SELECT v.id, v.package_id, v.version,
       v.published_at, v.content_hash, v.content_hash_algo, v.integrity_hash,
       v.git_head, v.package_size_bytes,
       v.dependency_count, v.dependencies,
       v.dev_dependencies, v.peer_dependencies, v.optional_dependencies, v.bundled_dependencies,
       v.dev_dependency_count, v.peer_dependency_count,
       v.optional_dependency_count, v.bundled_dependency_count,
       v.publisher_name, v.publisher_email, v.publisher_tool, v.maintainers,
       v.publish_method, v.provenance_present, v.provenance_details,
       v.has_install_scripts, v.source_repo_url,
       v.first_observed_at, v.last_seen_at
FROM versions v
JOIN packages p ON p.id = v.package_id
WHERE p.ecosystem = 'npm'
ORDER BY v.id
"""

VERSION_INSERT = """
INSERT INTO versions (
    id, package_id, version,
    published_at, content_hash, content_hash_algo, integrity_hash,
    git_head, package_size_bytes,
    dependency_count, dependencies,
    dev_dependencies, peer_dependencies, optional_dependencies, bundled_dependencies,
    dev_dependency_count, peer_dependency_count,
    optional_dependency_count, bundled_dependency_count,
    publisher_name, publisher_email, publisher_tool, maintainers,
    publish_method, provenance_present, provenance_details,
    has_install_scripts, source_repo_url, license,
    first_observed_at, last_seen_at
) VALUES (?, ?, ?,  ?, ?, ?, ?,  ?, ?,  ?, ?,  ?, ?, ?, ?,  ?, ?, ?, ?,
          ?, ?, ?, ?,  ?, ?, ?,  ?, ?, ?,  ?, ?)
"""

FILE_SELECT = """
SELECT f.id, f.version_id, f.filename, f.packagetype,
       f.content_hash, f.content_hash_algo, f.size_bytes,
       f.uploaded_at, f.url, f.first_observed_at, f.last_seen_at
FROM version_files f
JOIN versions v ON v.id = f.version_id
JOIN packages p ON p.id = v.package_id
WHERE p.ecosystem = 'npm'
ORDER BY f.id
"""

FILE_INSERT = """
INSERT INTO version_files (
    id, version_id, filename, packagetype,
    content_hash, content_hash_algo, size_bytes,
    uploaded_at, url, first_observed_at, last_seen_at
) VALUES (?, ?, ?, ?,  ?, ?, ?,  ?, ?, ?, ?)
"""

# Strip list: labeled_at, first_seen_at (collector-local, leak +03:00
# offset), raw_advisory (2.7 MB of OSV-duplicative JSON).
ATTACK_LABEL_SELECT = """
SELECT a.id, a.package_id, a.version_id, a.is_malicious,
       a.attack_name, a.source,
       a.advisory_id, a.aliases, a.severity, a.summary,
       a.affected_range, a.url, a.modified_at,
       a.advisory_published_at, a.detection_lag_days
FROM attack_labels a
JOIN packages p ON p.id = a.package_id
WHERE p.ecosystem = 'npm'
ORDER BY a.id
"""

ATTACK_LABEL_INSERT = """
INSERT INTO attack_labels (
    id, package_id, version_id, is_malicious,
    attack_name, source,
    advisory_id, aliases, severity, summary,
    affected_range, url, modified_at,
    advisory_published_at, detection_lag_days
) VALUES (?, ?, ?, ?,  ?, ?,  ?, ?, ?, ?,  ?, ?, ?,  ?, ?)
"""

BATCH = 2000


def _utc_iso(dt) -> str | None:
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _ms_to_iso(ms) -> str | None:
    if ms is None:
        return None
    return (
        datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _json_or_none(v) -> str | None:
    if v is None:
        return None
    return json.dumps(v, separators=(",", ":"), sort_keys=True)


def _bool_to_int(v) -> int | None:
    if v is None:
        return None
    return 1 if v else 0


def _load_privkey(path: Path) -> Ed25519PrivateKey:
    with path.open("rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit(f"{path} is not an Ed25519 private key")
    return key


def _pubkey_fingerprint(priv: Ed25519PrivateKey) -> tuple[str, str]:
    pub = priv.public_key()
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    spki = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(raw).hexdigest()[:16]
    return fingerprint, base64.b64encode(spki).decode("ascii")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _copy_packages(pg_cur, sqlite_cur) -> int:
    pg_cur.execute(
        "SELECT id, ecosystem, package_name FROM packages WHERE ecosystem = 'npm' ORDER BY id"
    )
    rows = pg_cur.fetchall()
    sqlite_cur.executemany(
        "INSERT INTO packages (id, ecosystem, package_name) VALUES (?, ?, ?)",
        rows,
    )
    return len(rows)


def _copy_versions(pg_cur, sqlite_cur) -> int:
    pg_cur.execute(VERSION_SELECT)
    total = 0
    while True:
        batch = pg_cur.fetchmany(BATCH)
        if not batch:
            break
        mapped = []
        for r in batch:
            (
                vid, pkg_id, version,
                published_at, content_hash, content_hash_algo, integrity_hash,
                git_head, package_size_bytes,
                dep_count, deps,
                dev_deps, peer_deps, opt_deps, bundled_deps,
                dev_count, peer_count, opt_count, bundled_count,
                publisher_name, publisher_email, publisher_tool, maintainers,
                publish_method, provenance_present, provenance_details,
                has_install_scripts, source_repo_url,
                first_observed_at, last_seen_at,
            ) = r
            mapped.append((
                vid, pkg_id, version,
                _utc_iso(published_at), content_hash, content_hash_algo, integrity_hash,
                git_head, package_size_bytes,
                dep_count, _json_or_none(deps),
                _json_or_none(dev_deps), _json_or_none(peer_deps),
                _json_or_none(opt_deps), _json_or_none(bundled_deps),
                dev_count, peer_count, opt_count, bundled_count,
                publisher_name, publisher_email, publisher_tool, _json_or_none(maintainers),
                publish_method, _bool_to_int(provenance_present), _json_or_none(provenance_details),
                _bool_to_int(has_install_scripts), source_repo_url,
                None,  # license: not extracted from PG in V1; filled from raw_metadata in v1.1
                _utc_iso(first_observed_at), _utc_iso(last_seen_at),
            ))
        sqlite_cur.executemany(VERSION_INSERT, mapped)
        total += len(mapped)
    return total


def _copy_files(pg_cur, sqlite_cur) -> int:
    pg_cur.execute(FILE_SELECT)
    total = 0
    while True:
        batch = pg_cur.fetchmany(BATCH)
        if not batch:
            break
        mapped = [
            (
                fid, vid, filename, packagetype,
                content_hash, content_hash_algo, size_bytes,
                _utc_iso(uploaded_at), url,
                _utc_iso(first_observed_at), _utc_iso(last_seen_at),
            )
            for (fid, vid, filename, packagetype,
                 content_hash, content_hash_algo, size_bytes,
                 uploaded_at, url, first_observed_at, last_seen_at) in batch
        ]
        sqlite_cur.executemany(FILE_INSERT, mapped)
        total += len(mapped)
    return total


def _copy_attack_labels(pg_cur, sqlite_cur) -> int:
    pg_cur.execute(ATTACK_LABEL_SELECT)
    total = 0
    while True:
        batch = pg_cur.fetchmany(BATCH)
        if not batch:
            break
        mapped = [
            (
                lid, package_id, version_id, _bool_to_int(is_malicious),
                attack_name, source,
                advisory_id, _json_or_none(aliases), severity, summary,
                affected_range, url, _utc_iso(modified_at),
                _utc_iso(advisory_published_at), detection_lag_days,
            )
            for (lid, package_id, version_id, is_malicious,
                 attack_name, source,
                 advisory_id, aliases, severity, summary,
                 affected_range, url, modified_at,
                 advisory_published_at, detection_lag_days) in batch
        ]
        sqlite_cur.executemany(ATTACK_LABEL_INSERT, mapped)
        total += len(mapped)
    return total


def _merge_reconstructed_attacks(
    sqlite_cur, fixture_path: Path
) -> tuple[int, int, int]:
    """Merge reconstructed attack records into the already-populated seed.

    Each fixture record becomes: (a) a packages row if the name is new,
    (b) a versions row with provenance_source='reconstructed', and
    (c) an attack_labels row with is_malicious=1 and
    provenance_source='reconstructed'. Version-id collisions against
    collector-fetched data raise — unpublished fixtures must not shadow
    live observations.

    Returns (packages_inserted, versions_inserted, labels_inserted).
    """
    if not fixture_path.exists():
        raise SystemExit(f"reconstructed fixture not found: {fixture_path}")

    doc = json.loads(fixture_path.read_text())
    records = doc.get("records")
    if not isinstance(records, list) or not records:
        raise SystemExit(f"fixture {fixture_path}: records[] missing or empty")

    sqlite_cur.execute("SELECT COALESCE(MAX(id), 0) FROM packages")
    next_pkg_id = sqlite_cur.fetchone()[0] + 1
    sqlite_cur.execute("SELECT COALESCE(MAX(id), 0) FROM versions")
    next_ver_id = sqlite_cur.fetchone()[0] + 1
    sqlite_cur.execute("SELECT COALESCE(MAX(id), 0) FROM attack_labels")
    next_label_id = sqlite_cur.fetchone()[0] + 1

    pkg_inserted = 0
    ver_inserted = 0
    label_inserted = 0

    for idx, rec in enumerate(records):
        tag = f"{rec.get('package_name', '?')}@{rec.get('version', '?')}"
        if rec.get("reconstructed") is not True:
            raise SystemExit(f"record[{idx}] {tag}: reconstructed must be true")
        fields = rec.get("fields") or {}
        missing = [f for f in REQUIRED_FIXTURE_FIELDS if f not in fields]
        if missing:
            raise SystemExit(
                f"record[{idx}] {tag}: missing required fields {missing}"
            )

        package_name = rec["package_name"]
        version = rec["version"]

        sqlite_cur.execute(
            "SELECT id FROM packages WHERE ecosystem = 'npm' AND package_name = ?",
            (package_name,),
        )
        row = sqlite_cur.fetchone()
        if row is None:
            sqlite_cur.execute(
                "INSERT INTO packages (id, ecosystem, package_name) VALUES (?, 'npm', ?)",
                (next_pkg_id, package_name),
            )
            package_id = next_pkg_id
            next_pkg_id += 1
            pkg_inserted += 1
        else:
            package_id = row[0]

        sqlite_cur.execute(
            "SELECT id FROM versions WHERE package_id = ? AND version = ?",
            (package_id, version),
        )
        if sqlite_cur.fetchone() is not None:
            raise SystemExit(
                f"record[{idx}] {tag}: version already present in seed — "
                "reconstructed fixture must not collide with collector-fetched data"
            )

        def _v(name):
            return fields[name]["value"]

        deps = _v("dependencies") or {}
        sqlite_cur.execute(
            """
            INSERT INTO versions (
                id, package_id, version,
                published_at, integrity_hash,
                dependency_count, dependencies,
                publisher_name, publisher_email,
                provenance_present, has_install_scripts,
                provenance_source
            ) VALUES (?, ?, ?,  ?, ?,  ?, ?,  ?, ?,  ?, ?,  'reconstructed')
            """,
            (
                next_ver_id, package_id, version,
                _ms_to_iso(_v("published_at_ms")), _v("integrity_hash"),
                len(deps), _json_or_none(deps),
                _v("publisher_name"), _v("publisher_email"),
                _bool_to_int(_v("provenance_present")),
                _bool_to_int(_v("has_install_scripts")),
            ),
        )
        version_id = next_ver_id
        next_ver_id += 1
        ver_inserted += 1

        sqlite_cur.execute(
            """
            INSERT INTO attack_labels (
                id, package_id, version_id, is_malicious,
                source, summary,
                provenance_source
            ) VALUES (?, ?, ?, 1,  'reconstructed-fixture', ?,  'reconstructed')
            """,
            (next_label_id, package_id, version_id, rec.get("reconstruction_notes")),
        )
        next_label_id += 1
        label_inserted += 1

    return pkg_inserted, ver_inserted, label_inserted


def export(
    *,
    out_dir: Path,
    seed_version: str,
    privkey_path: Path,
    db_url: str,
    fixture_path: Path = RECONSTRUCTED_FIXTURE_PATH,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    db_path = out_dir / "chaingate-seed.db"
    if db_path.exists():
        db_path.unlink()

    priv = _load_privkey(privkey_path)
    fingerprint, spki_b64 = _pubkey_fingerprint(priv)

    print(f"[export] opening sqlite: {db_path}")
    sqlite_conn = sqlite3.connect(str(db_path))
    sqlite_conn.execute("PRAGMA foreign_keys = ON")
    sqlite_conn.executescript(SCHEMA_SQL)
    sqlite_cur = sqlite_conn.cursor()

    print(f"[export] connecting to postgres (read-only transaction)")
    pg_conn = psycopg2.connect(db_url)
    pg_conn.set_session(readonly=True, autocommit=False)
    pg_cur = pg_conn.cursor()

    try:
        print("[export] copying packages …")
        n_pkgs = _copy_packages(pg_cur, sqlite_cur)
        print(f"[export]   {n_pkgs} packages")

        print("[export] copying versions …")
        n_vers = _copy_versions(pg_cur, sqlite_cur)
        print(f"[export]   {n_vers} versions")

        print("[export] copying version_files …")
        n_files = _copy_files(pg_cur, sqlite_cur)
        print(f"[export]   {n_files} files")

        print("[export] copying attack_labels …")
        n_labels = _copy_attack_labels(pg_cur, sqlite_cur)
        print(f"[export]   {n_labels} attack labels")

        print(f"[export] merging reconstructed attacks from {fixture_path} …")
        n_rec_pkgs, n_rec_vers, n_rec_labels = _merge_reconstructed_attacks(
            sqlite_cur, fixture_path
        )
        print(
            f"[export]   +{n_rec_pkgs} packages, +{n_rec_vers} versions, "
            f"+{n_rec_labels} attack labels (provenance_source='reconstructed')"
        )

        exported_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

        meta_rows = [
            ("schema_version", "2"),
            ("seed_version", seed_version),
            ("exported_at", exported_at),
            ("source_platform", f"{platform.system()}-{platform.machine()}"),
            ("row_count_packages", str(n_pkgs + n_rec_pkgs)),
            ("row_count_versions_collected", str(n_vers)),
            ("row_count_versions_reconstructed", str(n_rec_vers)),
            ("row_count_versions", str(n_vers + n_rec_vers)),
            ("row_count_version_files", str(n_files)),
            ("row_count_attack_labels_collected", str(n_labels)),
            ("row_count_attack_labels_reconstructed", str(n_rec_labels)),
            ("row_count_attack_labels", str(n_labels + n_rec_labels)),
            ("signing_key_fingerprint", f"ed25519:{fingerprint}"),
            ("signing_pubkey_spki_b64", spki_b64),
        ]
        sqlite_cur.executemany(
            "INSERT INTO seed_metadata (key, value) VALUES (?, ?)",
            meta_rows,
        )

        sqlite_conn.commit()
        print("[export] VACUUM + PRAGMA optimize")
        sqlite_conn.execute("VACUUM")
        sqlite_conn.execute("PRAGMA optimize")
        sqlite_conn.close()
    finally:
        pg_conn.rollback()
        pg_conn.close()

    db_sha = _sha256_file(db_path)
    sha_path = db_path.with_suffix(db_path.suffix + ".sha256")
    sha_path.write_text(db_sha + "\n")
    print(f"[export] sha256: {db_sha}")

    sig_bytes = priv.sign(db_sha.encode("ascii"))  # sign the hex string, 64-byte raw sig
    sig_path = db_path.with_suffix(db_path.suffix + ".sig")
    sig_path.write_bytes(sig_bytes)
    print(f"[export] signature: {len(sig_bytes)} bytes → {sig_path.name}")

    manifest = {
        "seed_version": seed_version,
        "exported_at": exported_at,
        "schema_version": 2,
        "row_counts": {
            "packages": n_pkgs + n_rec_pkgs,
            "versions": {
                "collected": n_vers,
                "reconstructed": n_rec_vers,
                "total": n_vers + n_rec_vers,
            },
            "version_files": n_files,
            "attack_labels": {
                "collected": n_labels,
                "reconstructed": n_rec_labels,
                "total": n_labels + n_rec_labels,
            },
        },
        "sha256": db_sha,
        "signing_key_fingerprint": f"ed25519:{fingerprint}",
        "signing_pubkey_spki_b64": spki_b64,
        "artifacts": {
            "db": db_path.name,
            "sha256": sha_path.name,
            "sig": sig_path.name,
        },
    }
    manifest_path = db_path.with_suffix(db_path.suffix + ".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"[export] wrote manifest → {manifest_path.name}")

    return manifest


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Export + sign chaingate seed bundle")
    parser.add_argument("--out-dir", type=Path, default=Path("seed_export"))
    parser.add_argument("--seed-version", required=True, help="e.g. 2026.04.14.1")
    parser.add_argument(
        "--key",
        type=Path,
        default=Path.home() / ".chaingate-signing" / "privkey.pem",
    )
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres DSN (defaults to DATABASE_URL)",
    )
    parser.add_argument(
        "--fixture",
        type=Path,
        default=RECONSTRUCTED_FIXTURE_PATH,
        help="Path to reconstructed-attacks.json (required; merged into seed)",
    )
    args = parser.parse_args(argv)

    if not args.database_url:
        parser.error("DATABASE_URL not set and --database-url not provided")
    if not args.key.exists():
        parser.error(f"signing key not found: {args.key}")
    if not args.fixture.exists():
        parser.error(f"reconstructed fixture not found: {args.fixture}")

    manifest = export(
        out_dir=args.out_dir.resolve(),
        seed_version=args.seed_version,
        privkey_path=args.key,
        db_url=args.database_url,
        fixture_path=args.fixture,
    )
    print(f"\n✓ seed bundle ready → {args.out_dir}/")
    print(f"  {manifest['row_counts']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
