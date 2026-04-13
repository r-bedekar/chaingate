"""P2.2 attestation backfill — PEP 740 provenance for pypi files.

For every pypi file in `version_files` with `attestation_present IS NULL`,
calls `/integrity/{name}/{version}/{filename}/provenance`. Writes one of:
  - attestation_present=True, publisher{...}, bundles[...], fetched_at=now  (200 OK)
  - attestation_present=False, fetched_at=now                               (404)

Both outcomes set `attestation_fetched_at` so the cursor walk is write-once
— a subsequent run filters this row out of the WHERE clause.

Most pypi files (~95%) still upload via API token and will 404. The
fetch cost is cheap (~5 KB response for 404) but we rate-limit at 10 rps
to stay polite.

Usage:
    .venv/bin/python -m collector.backfill_attestations [--subset]

    --subset : only process the 19 packages we know use Trusted Publishing,
               for fast validation before a full run.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
from datetime import datetime, timezone
from typing import Any

import httpx
from aiolimiter import AsyncLimiter

from collector import db
from collector.sources import pypi_attestations

CONCURRENCY = 10
RATE_LIMIT_PER_SECOND = 10
BATCH_SIZE = 500
PROGRESS_EVERY = 500

SUBSET_PACKAGES = [
    "packaging", "urllib3", "certifi", "typing-extensions", "requests",
    "charset-normalizer", "idna", "cryptography", "numpy", "pydantic",
    "pluggy", "click", "attrs", "anyio", "pandas", "pytest",
    "markupsafe", "iniconfig", "platformdirs",
]

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":%(message)s}',
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
log = logging.getLogger("backfill_attestations")


def _event(level: int, event: str, **fields: Any) -> None:
    log.log(level, json.dumps({"event": event, **fields}))


def _total_remaining(subset: bool) -> int:
    subset_clause = "AND p.package_name = ANY(%s)" if subset else ""
    params = (SUBSET_PACKAGES,) if subset else ()
    with db.connect() as conn, conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT COUNT(*)
              FROM version_files vf
              JOIN versions v ON v.id = vf.version_id
              JOIN packages p ON p.id = v.package_id
             WHERE p.ecosystem = 'pypi'
               AND vf.attestation_present IS NULL
               {subset_clause}
            """,
            params,
        )
        return cur.fetchone()[0]


def _fetch_batch(
    cursor_id: int, batch_size: int, subset: bool
) -> list[tuple[int, int, str, str, str]]:
    subset_clause = "AND p.package_name = ANY(%s)" if subset else ""
    with db.connect() as conn, conn.cursor() as cur:
        if subset:
            cur.execute(
                f"""
                SELECT vf.id, vf.version_id, p.package_name, v.version, vf.filename
                  FROM version_files vf
                  JOIN versions v ON v.id = vf.version_id
                  JOIN packages p ON p.id = v.package_id
                 WHERE p.ecosystem = 'pypi'
                   AND vf.attestation_present IS NULL
                   AND vf.id > %s
                   {subset_clause}
                 ORDER BY vf.id
                 LIMIT %s
                """,
                (cursor_id, SUBSET_PACKAGES, batch_size),
            )
        else:
            cur.execute(
                f"""
                SELECT vf.id, vf.version_id, p.package_name, v.version, vf.filename
                  FROM version_files vf
                  JOIN versions v ON v.id = vf.version_id
                  JOIN packages p ON p.id = v.package_id
                 WHERE p.ecosystem = 'pypi'
                   AND vf.attestation_present IS NULL
                   AND vf.id > %s
                 ORDER BY vf.id
                 LIMIT %s
                """,
                (cursor_id, batch_size),
            )
        return cur.fetchall()


def _apply_fills(version_id: int, filename: str, fills: dict[str, Any]) -> None:
    with db.connect() as conn:
        db.update_file_fill_nulls(conn, version_id, filename, fills)


async def _process_row(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    limiter: AsyncLimiter,
    version_id: int,
    package_name: str,
    version: str,
    filename: str,
    counters: dict[str, int],
) -> None:
    async with semaphore:
        async with limiter:
            try:
                raw = await pypi_attestations.fetch_provenance(
                    client, package_name, version, filename
                )
            except pypi_attestations.AttestationNotFound:
                counters["no_attestation"] += 1
                fills = {
                    "attestation_present": False,
                    "attestation_fetched_at": datetime.now(timezone.utc),
                }
                await asyncio.to_thread(_apply_fills, version_id, filename, fills)
                return
            except Exception as e:
                counters["errors"] += 1
                _event(
                    logging.WARNING,
                    "fetch_failed",
                    package=package_name,
                    version=version,
                    filename=filename,
                    error=type(e).__name__,
                    message=str(e),
                )
                return

        parsed = pypi_attestations.parse_provenance(raw)
        parsed["attestation_fetched_at"] = datetime.now(timezone.utc)
        try:
            await asyncio.to_thread(_apply_fills, version_id, filename, parsed)
            counters["has_attestation"] += 1
            _event(
                logging.INFO,
                "attestation_found",
                package=package_name,
                version=version,
                filename=filename,
                publisher=parsed.get("attestation_publisher"),
            )
        except Exception as e:
            counters["errors"] += 1
            _event(
                logging.ERROR,
                "update_failed",
                package=package_name,
                version=version,
                filename=filename,
                error=type(e).__name__,
                message=str(e),
            )


async def run(subset: bool) -> int:
    started = time.monotonic()
    remaining = _total_remaining(subset)
    _event(
        logging.INFO, "backfill_start", remaining=remaining, subset=subset
    )

    with db.connect() as conn:
        run_id = db.start_run(conn, "att_backfill")

    counters = {"has_attestation": 0, "no_attestation": 0, "errors": 0}
    semaphore = asyncio.Semaphore(CONCURRENCY)
    limiter = AsyncLimiter(RATE_LIMIT_PER_SECOND, 1)
    cursor_id = 0
    total_visited = 0

    async with httpx.AsyncClient(
        headers={"User-Agent": "chaingate-attestations/0.1"}
    ) as client:
        while True:
            batch = _fetch_batch(cursor_id, BATCH_SIZE, subset)
            if not batch:
                break
            tasks = []
            for row_id, version_id, package_name, version, filename in batch:
                tasks.append(
                    _process_row(
                        client, semaphore, limiter,
                        version_id, package_name, version, filename, counters,
                    )
                )
            await asyncio.gather(*tasks)
            total_visited += len(batch)
            if total_visited % PROGRESS_EVERY == 0 or total_visited == len(batch):
                _event(
                    logging.INFO,
                    "progress",
                    visited=total_visited,
                    **counters,
                )
            cursor_id = batch[-1][0]

    elapsed = round(time.monotonic() - started, 2)
    status = "success" if counters["errors"] == 0 else "partial"

    with db.connect() as conn:
        db.finish_run(
            conn,
            run_id=run_id,
            packages_attempted=0,
            versions_inserted=counters["has_attestation"],
            errors=counters["errors"],
            status=status,
            notes=f"no_att={counters['no_attestation']} visited={total_visited}",
        )

    _event(
        logging.INFO,
        "backfill_end",
        status=status,
        elapsed_s=elapsed,
        visited=total_visited,
        **counters,
    )
    return 0 if status == "success" else 1


if __name__ == "__main__":
    subset = "--subset" in sys.argv
    raise SystemExit(asyncio.run(run(subset)))
