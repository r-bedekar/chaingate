"""P2.2 historical backfill — populate version_files from raw_metadata.

Every `versions` row already captured the full per-file list under
`raw_metadata.files` (pypi) or `raw_metadata.dist` (npm) at fetch time.
We reconstruct the normalized `files` list without any HTTP calls and
insert child rows into `version_files`.

Resumable via id cursor on `versions.id`. Rows with no files list (old
vanished yanked releases that were captured post-delete) stay childless.

Records one `collector_runs` row with source='version_files_backfill'.

Usage:
    .venv/bin/python -m collector.backfill_version_files [ecosystem]

    ecosystem: 'pypi' | 'npm' | 'all'   (default: all)
"""
from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any

from collector import db
from collector.sources import npm, pypi

BATCH_SIZE = 500
PROGRESS_EVERY = 1000

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":%(message)s}',
)
log = logging.getLogger("backfill_version_files")


def _event(level: int, event: str, **fields: Any) -> None:
    log.log(level, json.dumps({"event": event, **fields}))


def _total_remaining(ecosystem: str | None) -> int:
    """Count versions that have no child file rows yet."""
    where = "AND p.ecosystem = %s" if ecosystem else ""
    params = (ecosystem,) if ecosystem else ()
    with db.connect() as conn, conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT COUNT(*)
              FROM versions v
              JOIN packages p ON p.id = v.package_id
              LEFT JOIN version_files vf ON vf.version_id = v.id
             WHERE vf.id IS NULL
               {where}
            """,
            params,
        )
        return cur.fetchone()[0]


def _fetch_batch(
    cursor_id: int, batch_size: int, ecosystem: str | None
) -> list[tuple[int, str, str, dict[str, Any]]]:
    where = "AND p.ecosystem = %s" if ecosystem else ""
    params: tuple = (cursor_id, batch_size) if not ecosystem else (
        cursor_id,
        ecosystem,
        batch_size,
    )
    sql = f"""
        SELECT v.id, p.ecosystem, v.version, v.published_at, v.raw_metadata
          FROM versions v
          JOIN packages p ON p.id = v.package_id
          LEFT JOIN version_files vf ON vf.version_id = v.id
         WHERE vf.id IS NULL
           AND v.id > %s
           {where}
         ORDER BY v.id
         LIMIT %s
    """
    with db.connect() as conn, conn.cursor() as cur:
        if ecosystem:
            cur.execute(sql, (cursor_id, ecosystem, batch_size))
        else:
            cur.execute(sql, (cursor_id, batch_size))
        return cur.fetchall()


def _reconstruct_files(
    ecosystem: str,
    version_str: str,
    published_at: Any,
    raw_metadata: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    if not isinstance(raw_metadata, dict):
        return []
    if ecosystem == "pypi":
        files = raw_metadata.get("files")
        if not isinstance(files, list):
            return []
        return pypi._parse_files(files)  # noqa: SLF001
    if ecosystem == "npm":
        dist = raw_metadata.get("dist")
        if not isinstance(dist, dict):
            return []
        pub_iso = published_at.isoformat() if hasattr(published_at, "isoformat") else published_at
        return npm._synthesize_files(  # noqa: SLF001
            version_str, raw_metadata, dist, pub_iso
        )
    return []


def _write_files(version_id: int, files: list[dict[str, Any]]) -> int:
    if not files:
        return 0
    inserted = 0
    with db.connect() as conn:
        for f in files:
            if db.insert_version_file_if_new(conn, version_id, f):
                inserted += 1
    return inserted


def run(ecosystem_filter: str | None) -> int:
    started = time.monotonic()
    remaining = _total_remaining(ecosystem_filter)
    _event(logging.INFO, "backfill_start", remaining=remaining, ecosystem=ecosystem_filter)

    with db.connect() as conn:
        run_id = db.start_run(conn, "vf_backfill")

    cursor_id = 0
    versions_visited = 0
    files_inserted = 0
    no_files = 0

    while True:
        batch = _fetch_batch(cursor_id, BATCH_SIZE, ecosystem_filter)
        if not batch:
            break
        for row_id, ecosystem, version_str, published_at, raw_metadata in batch:
            files = _reconstruct_files(ecosystem, version_str, published_at, raw_metadata)
            if not files:
                no_files += 1
            else:
                files_inserted += _write_files(row_id, files)
            versions_visited += 1
            if versions_visited % PROGRESS_EVERY == 0:
                _event(
                    logging.INFO,
                    "progress",
                    versions=versions_visited,
                    files=files_inserted,
                    no_files=no_files,
                )
        cursor_id = batch[-1][0]

    elapsed = round(time.monotonic() - started, 2)
    with db.connect() as conn:
        db.finish_run(
            conn,
            run_id=run_id,
            packages_attempted=0,
            versions_inserted=files_inserted,
            errors=0,
            status="success",
            notes=f"versions_visited={versions_visited} no_files={no_files}",
        )

    _event(
        logging.INFO,
        "backfill_end",
        elapsed_s=elapsed,
        versions=versions_visited,
        files=files_inserted,
        no_files=no_files,
    )
    return 0


if __name__ == "__main__":
    ecosystem = sys.argv[1] if len(sys.argv) > 1 else "all"
    if ecosystem == "all":
        ecosystem = None
    elif ecosystem not in ("npm", "pypi"):
        print(f"unknown ecosystem: {ecosystem}", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(run(ecosystem))
