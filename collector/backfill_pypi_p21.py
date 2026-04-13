"""P2.1 PyPI historical backfill — license + maintainer fields.

Fills `license_text`, `license_expression`, `publisher_maintainer`, and
`publisher_maintainer_email` on rows that the earlier backfill passes couldn't
populate because those columns didn't exist yet. Reuses
`pypi.parse_version_detail` and `db.update_version_fill_nulls`; COALESCE
protection means rows the P1 pass already filled for publisher_email are
safe — the new columns get set, the old ones are left alone.

Filter: rows where BOTH `license_expression` and `license_text` are NULL.
A row that already has either side filled (by the hourly collector running
with the new parser) is skipped. The cursor walks v.id monotonically so each
row is visited exactly once per run.

Usage:
    .venv/bin/python -m collector.backfill_pypi_p21
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import httpx
from aiolimiter import AsyncLimiter

from collector import db
from collector.sources import pypi

CONCURRENCY = 10
RATE_LIMIT_PER_SECOND = 10
BATCH_SIZE = 500
PROGRESS_EVERY = 200

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":%(message)s}',
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
log = logging.getLogger("backfill_pypi_p21")


def _event(level: int, event: str, **fields: Any) -> None:
    log.log(level, json.dumps({"event": event, **fields}))


def _total_remaining() -> int:
    with db.connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*)
                  FROM versions v JOIN packages p ON p.id = v.package_id
                 WHERE p.ecosystem = 'pypi'
                   AND v.license_expression IS NULL
                   AND v.license_text IS NULL
                """
            )
            return cur.fetchone()[0]


def _fetch_batch(cursor_id: int, batch_size: int) -> list[tuple[int, int, str, str]]:
    with db.connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT v.id, v.package_id, p.package_name, v.version
                  FROM versions v JOIN packages p ON p.id = v.package_id
                 WHERE p.ecosystem = 'pypi'
                   AND v.license_expression IS NULL
                   AND v.license_text IS NULL
                   AND v.id > %s
                 ORDER BY v.id
                 LIMIT %s
                """,
                (cursor_id, batch_size),
            )
            return cur.fetchall()


def _apply_fills(package_id: int, version: str, fills: dict[str, Any]) -> None:
    with db.connect() as conn:
        db.update_version_fill_nulls(conn, package_id, version, fills)


async def _process_row(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    limiter: AsyncLimiter,
    package_id: int,
    package_name: str,
    version: str,
    counters: dict[str, int],
) -> None:
    async with semaphore:
        async with limiter:
            try:
                raw = await pypi.fetch_version(client, package_name, version)
            except pypi.PackageNotFoundError:
                counters["not_found"] += 1
                _event(
                    logging.WARNING,
                    "row_not_found",
                    package=package_name,
                    version=version,
                )
                return
            except Exception as e:
                counters["errors"] += 1
                _event(
                    logging.ERROR,
                    "row_fetch_failed",
                    package=package_name,
                    version=version,
                    error=type(e).__name__,
                    message=str(e),
                )
                return

        try:
            fills = pypi.parse_version_detail(raw)
        except Exception as e:
            counters["errors"] += 1
            _event(
                logging.ERROR,
                "row_parse_failed",
                package=package_name,
                version=version,
                error=type(e).__name__,
                message=str(e),
            )
            return

        try:
            await asyncio.to_thread(_apply_fills, package_id, version, fills)
            counters["visited"] += 1
        except Exception as e:
            counters["errors"] += 1
            _event(
                logging.ERROR,
                "row_update_failed",
                package=package_name,
                version=version,
                error=type(e).__name__,
                message=str(e),
            )
            return

        if counters["visited"] % PROGRESS_EVERY == 0:
            _event(
                logging.INFO,
                "progress",
                visited=counters["visited"],
                not_found=counters["not_found"],
                errors=counters["errors"],
            )


async def run() -> int:
    started = time.monotonic()
    remaining = _total_remaining()
    _event(logging.INFO, "backfill_start", remaining=remaining)

    with db.connect() as conn:
        run_id = db.start_run(conn, "pypi_backfill_p21")

    counters = {"visited": 0, "not_found": 0, "errors": 0}
    semaphore = asyncio.Semaphore(CONCURRENCY)
    limiter = AsyncLimiter(RATE_LIMIT_PER_SECOND, 1)
    cursor_id = 0
    packages_seen: set[int] = set()

    async with httpx.AsyncClient(
        headers={"User-Agent": "chaingate-backfill/0.1"}
    ) as client:
        while True:
            batch = _fetch_batch(cursor_id, BATCH_SIZE)
            if not batch:
                break
            tasks = []
            for row_id, package_id, package_name, version in batch:
                packages_seen.add(package_id)
                tasks.append(
                    _process_row(
                        client,
                        semaphore,
                        limiter,
                        package_id,
                        package_name,
                        version,
                        counters,
                    )
                )
            await asyncio.gather(*tasks)
            cursor_id = batch[-1][0]

    elapsed = round(time.monotonic() - started, 2)
    status = "success" if counters["errors"] == 0 else "partial"

    with db.connect() as conn:
        db.finish_run(
            conn,
            run_id=run_id,
            packages_attempted=len(packages_seen),
            versions_inserted=counters["visited"],
            errors=counters["errors"],
            status=status,
            notes=f"not_found={counters['not_found']}",
        )

    _event(
        logging.INFO,
        "backfill_end",
        status=status,
        elapsed_s=elapsed,
        **counters,
    )
    return 0 if status == "success" else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
