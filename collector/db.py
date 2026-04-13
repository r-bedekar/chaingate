"""Database helpers for the collector.

Thin wrapper over psycopg2. All functions take an explicit connection so the
caller controls transaction boundaries. No ORM, no connection pool — the
collector is single-process and the bottleneck is HTTP, not Postgres.
"""
from __future__ import annotations

import json
import os
from contextlib import contextmanager
from typing import Any, Iterator

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]


@contextmanager
def connect() -> Iterator[psycopg2.extensions.connection]:
    conn = psycopg2.connect(DATABASE_URL)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def upsert_package(conn, ecosystem: str, package_name: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO packages (ecosystem, package_name)
            VALUES (%s, %s)
            ON CONFLICT (ecosystem, package_name) DO UPDATE
              SET package_name = EXCLUDED.package_name
            RETURNING id
            """,
            (ecosystem, package_name),
        )
        return cur.fetchone()[0]


def insert_version_if_new(
    conn, package_id: int, version_data: dict[str, Any]
) -> int | None:
    """Insert a version row. Returns the new row id, or None if it was
    already present (ON CONFLICT DO NOTHING)."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO versions (
                package_id, version, published_at, content_hash, content_hash_algo,
                integrity_hash, git_head,
                dependency_count, dependencies,
                dev_dependencies, peer_dependencies, optional_dependencies, bundled_dependencies,
                dev_dependency_count, peer_dependency_count, optional_dependency_count, bundled_dependency_count,
                publisher_name, publisher_email, publisher_tool,
                publisher_maintainer, publisher_maintainer_email,
                maintainers,
                publish_method, provenance_present, provenance_details,
                has_install_scripts, package_size_bytes, source_repo_url,
                license_text, license_expression,
                raw_metadata
            ) VALUES (
                %(package_id)s, %(version)s, %(published_at)s, %(content_hash)s, %(content_hash_algo)s,
                %(integrity_hash)s, %(git_head)s,
                %(dependency_count)s, %(dependencies)s,
                %(dev_dependencies)s, %(peer_dependencies)s, %(optional_dependencies)s, %(bundled_dependencies)s,
                %(dev_dependency_count)s, %(peer_dependency_count)s, %(optional_dependency_count)s, %(bundled_dependency_count)s,
                %(publisher_name)s, %(publisher_email)s, %(publisher_tool)s,
                %(publisher_maintainer)s, %(publisher_maintainer_email)s,
                %(maintainers)s,
                %(publish_method)s, %(provenance_present)s, %(provenance_details)s,
                %(has_install_scripts)s, %(package_size_bytes)s, %(source_repo_url)s,
                %(license_text)s, %(license_expression)s,
                %(raw_metadata)s
            )
            ON CONFLICT (package_id, version) DO NOTHING
            RETURNING id
            """,
            {
                "package_id": package_id,
                "version": version_data["version"],
                "published_at": version_data.get("published_at"),
                "content_hash": version_data.get("content_hash"),
                "content_hash_algo": version_data.get("content_hash_algo"),
                "integrity_hash": version_data.get("integrity_hash"),
                "git_head": version_data.get("git_head"),
                "dependency_count": version_data.get("dependency_count"),
                "dependencies": _json_or_none(version_data.get("dependencies")),
                "dev_dependencies": _json_or_none(version_data.get("dev_dependencies")),
                "peer_dependencies": _json_or_none(version_data.get("peer_dependencies")),
                "optional_dependencies": _json_or_none(version_data.get("optional_dependencies")),
                "bundled_dependencies": _json_or_none(version_data.get("bundled_dependencies")),
                "dev_dependency_count": version_data.get("dev_dependency_count"),
                "peer_dependency_count": version_data.get("peer_dependency_count"),
                "optional_dependency_count": version_data.get("optional_dependency_count"),
                "bundled_dependency_count": version_data.get("bundled_dependency_count"),
                "publisher_name": version_data.get("publisher_name"),
                "publisher_email": version_data.get("publisher_email"),
                "publisher_tool": version_data.get("publisher_tool"),
                "publisher_maintainer": version_data.get("publisher_maintainer"),
                "publisher_maintainer_email": version_data.get("publisher_maintainer_email"),
                "maintainers": _json_or_none(version_data.get("maintainers")),
                "publish_method": version_data.get("publish_method"),
                "provenance_present": version_data.get("provenance_present"),
                "provenance_details": _json_or_none(version_data.get("provenance_details")),
                "has_install_scripts": version_data.get("has_install_scripts"),
                "package_size_bytes": version_data.get("package_size_bytes"),
                "source_repo_url": version_data.get("source_repo_url"),
                "license_text": version_data.get("license_text"),
                "license_expression": version_data.get("license_expression"),
                "raw_metadata": _json_or_none(version_data.get("raw_metadata")),
            },
        )
        row = cur.fetchone()
        return row[0] if row else None


def existing_versions(conn, package_id: int) -> set[str]:
    """Return the set of version strings already present for a package."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT version FROM versions WHERE package_id = %s",
            (package_id,),
        )
        return {row[0] for row in cur.fetchall()}


def existing_version_ids(conn, package_id: int) -> dict[str, int]:
    """Return a map of version_string -> version_id for all rows of a
    package. Used by the child-file write path to resolve parent ids."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT version, id FROM versions WHERE package_id = %s",
            (package_id,),
        )
        return {row[0]: row[1] for row in cur.fetchall()}


# Columns the enrichment pass is allowed to fill. Kept explicit so adding a
# new enrichable field is a deliberate code change, not an accidental one.
_FILLABLE_COLUMNS = {
    "publisher_name",
    "publisher_email",
    "publisher_tool",
    "publisher_maintainer",
    "publisher_maintainer_email",
    "maintainers",
    "dependency_count",
    "dependencies",
    "dev_dependencies",
    "peer_dependencies",
    "optional_dependencies",
    "bundled_dependencies",
    "dev_dependency_count",
    "peer_dependency_count",
    "optional_dependency_count",
    "bundled_dependency_count",
    "integrity_hash",
    "git_head",
    "source_repo_url",
    "has_install_scripts",
    "license_text",
    "license_expression",
}

_JSONB_COLUMNS = {
    "dependencies",
    "dev_dependencies",
    "peer_dependencies",
    "optional_dependencies",
    "bundled_dependencies",
    "maintainers",
}


def update_version_fill_nulls(
    conn,
    package_id: int,
    version: str,
    fields: dict[str, Any],
) -> bool:
    """Fill NULL columns on an existing version row.

    Non-NULL values are protected via `SET col = COALESCE(col, %s)` so a
    second enrichment pass can never overwrite an already-populated value.
    This is the sole sanctioned UPDATE path on the versions table — see
    CLAUDE.md Collector Design invariant #1.

    Returns True if the row existed (regardless of whether any column
    actually changed — COALESCE makes repeated calls harmless).
    """
    usable = {k: v for k, v in fields.items() if k in _FILLABLE_COLUMNS and v is not None}
    if not usable:
        return False

    set_clauses = []
    params: list[Any] = []
    for col, value in usable.items():
        set_clauses.append(f"{col} = COALESCE({col}, %s)")
        if col in _JSONB_COLUMNS:
            params.append(_json_or_none(value))
        else:
            params.append(value)
    params.extend([package_id, version])

    sql = (
        "UPDATE versions SET "
        + ", ".join(set_clauses)
        + " WHERE package_id = %s AND version = %s"
    )
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.rowcount > 0


def bulk_mark_seen(conn, package_id: int, versions: list[str]) -> None:
    """Bump last_seen_at for all observed versions of a package.

    Harmless monotonic UPDATE — permitted by CLAUDE.md invariant #1 as a
    lifecycle-observation write. Repeated calls just advance the timestamp.
    """
    if not versions:
        return
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE versions
               SET last_seen_at = NOW()
             WHERE package_id = %s AND version = ANY(%s)
            """,
            (package_id, versions),
        )


def mark_vanished(
    conn, package_id: int, versions: list[str], run_id: int | None
) -> list[str]:
    """Mark versions no longer present in the registry as vanished.

    Write-once: only rows with vanished_at IS NULL are updated. For each
    transition, append a `version_events` row so the history is preserved
    even if the package later reappears.

    Returns the list of version strings that actually transitioned (i.e.
    were not already vanished). Empty list is the common case.
    """
    if not versions:
        return []
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE versions
               SET vanished_at = NOW()
             WHERE package_id = %s
               AND version = ANY(%s)
               AND vanished_at IS NULL
         RETURNING id, version
            """,
            (package_id, versions),
        )
        transitioned = cur.fetchall()
        if not transitioned:
            return []
        psycopg2.extras.execute_batch(
            cur,
            """
            INSERT INTO version_events (version_id, event_type, run_id, detail)
            VALUES (%s, 'vanished', %s, %s)
            """,
            [(vid, run_id, json.dumps({"version": v})) for vid, v in transitioned],
        )
    return [v for _, v in transitioned]


def apply_lifecycle(
    conn,
    package_id: int,
    version: str,
    deprecated_reason: str | None,
    yanked: bool,
    yanked_reason: str | None,
    run_id: int | None,
) -> list[str]:
    """Apply deprecation / yank lifecycle signals to an existing version row.

    Write-once semantics: `deprecated_at` / `yanked_at` are only set when
    currently NULL, so repeated observations are idempotent. Each first
    transition also writes a row to `version_events`.

    Both fields are optional — npm callers pass only deprecation, pypi
    callers pass only yank. Returns the list of event types emitted.
    """
    events: list[str] = []
    with conn.cursor() as cur:
        if deprecated_reason is not None:
            cur.execute(
                """
                UPDATE versions
                   SET deprecated_at = COALESCE(deprecated_at, NOW()),
                       deprecated_reason = COALESCE(deprecated_reason, %s)
                 WHERE package_id = %s AND version = %s
                   AND deprecated_at IS NULL
             RETURNING id
                """,
                (deprecated_reason, package_id, version),
            )
            row = cur.fetchone()
            if row:
                cur.execute(
                    """
                    INSERT INTO version_events (version_id, event_type, run_id, detail)
                    VALUES (%s, 'deprecated', %s, %s)
                    """,
                    (row[0], run_id, json.dumps({"reason": deprecated_reason})),
                )
                events.append("deprecated")

        if yanked:
            cur.execute(
                """
                UPDATE versions
                   SET yanked_at = COALESCE(yanked_at, NOW()),
                       yanked_reason = COALESCE(yanked_reason, %s)
                 WHERE package_id = %s AND version = %s
                   AND yanked_at IS NULL
             RETURNING id
                """,
                (yanked_reason, package_id, version),
            )
            row = cur.fetchone()
            if row:
                cur.execute(
                    """
                    INSERT INTO version_events (version_id, event_type, run_id, detail)
                    VALUES (%s, 'yanked', %s, %s)
                    """,
                    (row[0], run_id, json.dumps({"reason": yanked_reason})),
                )
                events.append("yanked")

    return events


_FILE_FILLABLE_COLUMNS = {
    "packagetype",
    "python_version",
    "content_hash",
    "content_hash_algo",
    "size_bytes",
    "uploaded_at",
    "url",
    "attestation_present",
    "attestation_publisher",
    "attestation_bundles",
    "attestation_fetched_at",
}

_FILE_JSONB_COLUMNS = {
    "attestation_publisher",
    "attestation_bundles",
    "raw_metadata",
}


def existing_file_names(conn, version_id: int) -> set[str]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT filename FROM version_files WHERE version_id = %s",
            (version_id,),
        )
        return {row[0] for row in cur.fetchall()}


def insert_version_file_if_new(
    conn, version_id: int, file_data: dict[str, Any]
) -> bool:
    """Insert a version_files row. Returns True if inserted."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO version_files (
                version_id, filename, packagetype, python_version,
                content_hash, content_hash_algo, size_bytes, uploaded_at, url,
                yanked, yanked_reason, raw_metadata
            ) VALUES (
                %(version_id)s, %(filename)s, %(packagetype)s, %(python_version)s,
                %(content_hash)s, %(content_hash_algo)s, %(size_bytes)s, %(uploaded_at)s, %(url)s,
                %(yanked)s, %(yanked_reason)s, %(raw_metadata)s
            )
            ON CONFLICT (version_id, filename) DO NOTHING
            RETURNING id
            """,
            {
                "version_id": version_id,
                "filename": file_data["filename"],
                "packagetype": file_data.get("packagetype"),
                "python_version": file_data.get("python_version"),
                "content_hash": file_data.get("content_hash"),
                "content_hash_algo": file_data.get("content_hash_algo"),
                "size_bytes": file_data.get("size_bytes"),
                "uploaded_at": file_data.get("uploaded_at"),
                "url": file_data.get("url"),
                "yanked": bool(file_data.get("yanked")),
                "yanked_reason": file_data.get("yanked_reason"),
                "raw_metadata": _json_or_none(file_data.get("raw_metadata")),
            },
        )
        return cur.fetchone() is not None


def update_file_fill_nulls(
    conn, version_id: int, filename: str, fields: dict[str, Any]
) -> bool:
    """Fill-NULL UPDATE for a version_files row. COALESCE-protected so a
    second pass can never overwrite a non-NULL column. Sole sanctioned
    UPDATE path on version_files (attestation fetch uses this too)."""
    usable = {
        k: v for k, v in fields.items() if k in _FILE_FILLABLE_COLUMNS and v is not None
    }
    if not usable:
        return False

    set_clauses = []
    params: list[Any] = []
    for col, value in usable.items():
        set_clauses.append(f"{col} = COALESCE({col}, %s)")
        if col in _FILE_JSONB_COLUMNS:
            params.append(_json_or_none(value))
        else:
            params.append(value)
    params.extend([version_id, filename])

    sql = (
        "UPDATE version_files SET "
        + ", ".join(set_clauses)
        + " WHERE version_id = %s AND filename = %s"
    )
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.rowcount > 0


def bulk_mark_files_seen(conn, version_id: int, filenames: list[str]) -> None:
    """Monotonic last_seen_at bump for all observed files of a version."""
    if not filenames:
        return
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE version_files
               SET last_seen_at = NOW()
             WHERE version_id = %s AND filename = ANY(%s)
            """,
            (version_id, filenames),
        )


def mark_files_vanished(conn, version_id: int, filenames: list[str]) -> list[str]:
    """Write-once vanished_at for files no longer present upstream."""
    if not filenames:
        return []
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE version_files
               SET vanished_at = NOW()
             WHERE version_id = %s
               AND filename = ANY(%s)
               AND vanished_at IS NULL
         RETURNING filename
            """,
            (version_id, filenames),
        )
        return [row[0] for row in cur.fetchall()]


def apply_file_yank(
    conn, version_id: int, filename: str, yanked_reason: str | None
) -> bool:
    """Write-once per-file yank transition. Append-only: once yanked=TRUE,
    never flips back."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE version_files
               SET yanked = TRUE,
                   yanked_reason = COALESCE(yanked_reason, %s)
             WHERE version_id = %s AND filename = %s AND yanked = FALSE
         RETURNING id
            """,
            (yanked_reason, version_id, filename),
        )
        return cur.fetchone() is not None


def upsert_attack_label(
    conn,
    *,
    advisory_id: str,
    package_id: int,
    version_id: int | None,
    is_malicious: bool,
    attack_name: str | None,
    source: str,
    severity: str | None,
    summary: str | None,
    affected_range: str | None,
    aliases: list[str] | None,
    url: str | None,
    modified_at: Any,
    raw_advisory: dict[str, Any] | None,
) -> bool:
    """Upsert an advisory-driven attack_labels row.

    Keyed on (advisory_id, package_id) via the partial unique index. On
    conflict we refresh the mutable fields (severity/summary/range/raw)
    because OSV advisories can be revised upstream. `first_seen_at` is
    preserved because it's only set on INSERT.

    version_id is NULL by default — most advisories describe *ranges* of
    versions, not a single pinned release, so we keep the mapping at the
    package level and let consumers interpret `affected_range`.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO attack_labels (
                package_id, version_id, is_malicious, attack_name, source,
                labeled_at, advisory_id, aliases, severity, summary,
                affected_range, url, raw_advisory, modified_at, first_seen_at
            ) VALUES (
                %s, %s, %s, %s, %s,
                NOW(), %s, %s, %s, %s,
                %s, %s, %s, %s, NOW()
            )
            ON CONFLICT (advisory_id, package_id) WHERE advisory_id IS NOT NULL
            DO UPDATE SET
                is_malicious = EXCLUDED.is_malicious,
                severity = EXCLUDED.severity,
                summary = EXCLUDED.summary,
                affected_range = EXCLUDED.affected_range,
                url = EXCLUDED.url,
                raw_advisory = EXCLUDED.raw_advisory,
                modified_at = EXCLUDED.modified_at,
                aliases = EXCLUDED.aliases
             RETURNING (xmax = 0) AS inserted
            """,
            (
                package_id, version_id, is_malicious, attack_name, source,
                advisory_id, _json_or_none(aliases), severity, summary,
                affected_range, url, _json_or_none(raw_advisory), modified_at,
            ),
        )
        row = cur.fetchone()
        return bool(row[0]) if row else False


def start_run(conn, source: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO collector_runs (source, status) VALUES (%s, 'running') RETURNING id",
            (source,),
        )
        return cur.fetchone()[0]


def finish_run(
    conn,
    run_id: int,
    packages_attempted: int,
    versions_inserted: int,
    errors: int,
    status: str,
    notes: str | None = None,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE collector_runs
               SET finished_at = NOW(),
                   packages_attempted = %s,
                   versions_inserted = %s,
                   errors = %s,
                   status = %s,
                   notes = %s
             WHERE id = %s
            """,
            (packages_attempted, versions_inserted, errors, status, notes, run_id),
        )


def _json_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return json.dumps(value, default=str)
