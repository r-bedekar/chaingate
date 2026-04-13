"""Main collector orchestrator.

Loads a seed list, fetches each package concurrently with bounded concurrency
and a global rate limit, writes normalized versions to Postgres, and records
a single row in collector_runs.

Usage:
    python -m collector.collector <source> [seed_file]

Supported sources: npm, pypi
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
from aiolimiter import AsyncLimiter

from collector import db
from collector.sources import npm, pypi

CONCURRENCY = 10
RATE_LIMIT_PER_SECOND = 10
RUN_TIMEOUT_SECONDS = 600

SEEDS_DIR = Path(__file__).parent / "seeds"

SOURCES: dict[str, tuple[ModuleType, str]] = {
    "npm": (npm, "npm_top.txt"),
    "pypi": (pypi, "pypi_top.txt"),
}

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":%(message)s}',
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
log = logging.getLogger("collector")


def _log_event(level: int, event: str, **fields: Any) -> None:
    log.log(level, json.dumps({"event": event, **fields}))


async def _process_package(
    source_mod: ModuleType,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    limiter: AsyncLimiter,
    package_name: str,
    counters: dict[str, int],
    run_id: int,
) -> None:
    async with semaphore:
        async with limiter:
            try:
                raw = await source_mod.fetch_package(client, package_name)
            except source_mod.PackageNotFoundError:
                _log_event(logging.WARNING, "package_not_found", package=package_name)
                counters["errors"] += 1
                return
            except Exception as e:
                _log_event(
                    logging.ERROR,
                    "fetch_failed",
                    package=package_name,
                    error=type(e).__name__,
                    message=str(e),
                )
                counters["errors"] += 1
                return

        try:
            versions = source_mod.parse_versions(raw)
        except Exception as e:
            _log_event(
                logging.ERROR,
                "parse_failed",
                package=package_name,
                error=type(e).__name__,
                message=str(e),
            )
            counters["errors"] += 1
            return

        try:
            package_id, existing = await asyncio.to_thread(
                _package_state, source_mod.ECOSYSTEM, package_name
            )
        except Exception as e:
            _log_event(
                logging.ERROR,
                "db_state_failed",
                package=package_name,
                error=type(e).__name__,
                message=str(e),
            )
            counters["errors"] += 1
            return

        new_versions = [v for v in versions if v["version"] not in existing]

        enrich_errors = 0
        enrich_hook = getattr(source_mod, "enrich_version", None)
        if enrich_hook and new_versions:
            for v in new_versions:
                if not _needs_enrichment(v):
                    continue
                async with limiter:
                    try:
                        fills = await enrich_hook(client, package_name, v["version"])
                    except source_mod.PackageNotFoundError:
                        # Version exists in the bulk listing but per-version
                        # endpoint 404s — rare, happens to very old yanked
                        # releases. Log and leave the row with NULL fills.
                        enrich_errors += 1
                        _log_event(
                            logging.WARNING,
                            "enrich_not_found",
                            package=package_name,
                            version=v["version"],
                        )
                        continue
                    except Exception as e:
                        enrich_errors += 1
                        _log_event(
                            logging.WARNING,
                            "enrich_failed",
                            package=package_name,
                            version=v["version"],
                            error=type(e).__name__,
                            message=str(e),
                        )
                        continue
                for k, val in fills.items():
                    if val is not None and v.get(k) is None:
                        v[k] = val

        try:
            inserted = await asyncio.to_thread(
                _write_new_versions, package_id, new_versions
            )
        except Exception as e:
            _log_event(
                logging.ERROR,
                "db_write_failed",
                package=package_name,
                error=type(e).__name__,
                message=str(e),
            )
            counters["errors"] += 1
            return

        # Fill-NULL pass for existing versions: if the parser produced fields
        # the existing row has NULL, fill them now from the just-fetched
        # bulk data. This is how the npm-side new columns (maintainers,
        # integrity_hash, git_head, dep-group counts, publisher_tool) back-
        # fill onto historical rows — no extra HTTP cost, the data is already
        # in hand. COALESCE protects pre-existing non-NULL values.
        existing_list = [v for v in versions if v["version"] in existing]
        if existing_list:
            try:
                await asyncio.to_thread(
                    _fill_existing_versions, package_id, existing_list
                )
            except Exception as e:
                _log_event(
                    logging.ERROR,
                    "fill_existing_failed",
                    package=package_name,
                    error=type(e).__name__,
                    message=str(e),
                )
                counters["errors"] += 1
                return

        present_strs = [v["version"] for v in versions]
        vanished_strs = sorted(existing - set(present_strs))
        try:
            lifecycle_summary = await asyncio.to_thread(
                _apply_observations,
                package_id,
                versions,
                present_strs,
                vanished_strs,
                run_id,
            )
        except Exception as e:
            _log_event(
                logging.ERROR,
                "lifecycle_failed",
                package=package_name,
                error=type(e).__name__,
                message=str(e),
            )
            counters["errors"] += 1
            return

        counters["versions_inserted"] += inserted
        counters["packages_attempted"] += 1
        counters["deprecated_events"] += lifecycle_summary["deprecated"]
        counters["yanked_events"] += lifecycle_summary["yanked"]
        counters["vanished_events"] += lifecycle_summary["vanished"]
        _log_event(
            logging.INFO,
            "package_done",
            package=package_name,
            versions_total=len(versions),
            versions_new=len(new_versions),
            versions_inserted=inserted,
            enrich_errors=enrich_errors,
            deprecated=lifecycle_summary["deprecated"],
            yanked=lifecycle_summary["yanked"],
            vanished=lifecycle_summary["vanished"],
        )


# Fields an enrichment pass is expected to populate. If any are still NULL
# on a newly-parsed version, we call the source's enrich_version hook.
# `has_install_scripts` is here because for PyPI the bulk `/pypi/{name}/json`
# can never populate it — tarball inspection is the only way — so every new
# PyPI version needs to flow through enrichment even when the bulk pass did
# set publisher/deps (true for the latest version of every package).
_ENRICHABLE = ("publisher_email", "dependencies", "has_install_scripts")


def _needs_enrichment(version_data: dict[str, Any]) -> bool:
    return any(version_data.get(k) is None for k in _ENRICHABLE)


def _package_state(ecosystem: str, package_name: str) -> tuple[int, set[str]]:
    with db.connect() as conn:
        package_id = db.upsert_package(conn, ecosystem, package_name)
        existing = db.existing_versions(conn, package_id)
    return package_id, existing


def _write_new_versions(package_id: int, versions: list[dict[str, Any]]) -> int:
    """Insert new version rows and their child version_files. Returns
    count of version rows actually inserted. Each inserted version's
    `files` list is written as child rows in the same transaction.
    """
    inserted = 0
    with db.connect() as conn:
        for v in versions:
            version_id = db.insert_version_if_new(conn, package_id, v)
            if version_id is None:
                continue
            inserted += 1
            for f in v.get("files") or []:
                db.insert_version_file_if_new(conn, version_id, f)
    return inserted


def _fill_existing_versions(
    package_id: int, versions: list[dict[str, Any]]
) -> None:
    """Apply fill-NULL updates to versions that are already in the DB,
    plus insert/fill-null for their version_files children. COALESCE
    protection means this is safe to call on every run — existing
    non-NULL values are never overwritten. Also handles new-file insert
    (new wheels appearing on an existing release) and file-vanish."""
    with db.connect() as conn:
        id_map = db.existing_version_ids(conn, package_id)
        for v in versions:
            db.update_version_fill_nulls(conn, package_id, v["version"], v)
            version_id = id_map.get(v["version"])
            if version_id is None:
                continue
            existing_files = db.existing_file_names(conn, version_id)
            present_files: list[str] = []
            for f in v.get("files") or []:
                filename = f.get("filename")
                if not filename:
                    continue
                present_files.append(filename)
                if filename in existing_files:
                    db.update_file_fill_nulls(conn, version_id, filename, f)
                else:
                    db.insert_version_file_if_new(conn, version_id, f)
            if present_files:
                db.bulk_mark_files_seen(conn, version_id, present_files)
            gone = sorted(existing_files - set(present_files))
            if gone:
                db.mark_files_vanished(conn, version_id, gone)


def _apply_observations(
    package_id: int,
    versions: list[dict[str, Any]],
    present_strs: list[str],
    vanished_strs: list[str],
    run_id: int,
) -> dict[str, int]:
    """Bump last_seen_at, apply deprecation/yank transitions, and flag
    vanished versions for one package. Single connection, single txn."""
    deprecated = yanked = vanished = 0
    with db.connect() as conn:
        db.bulk_mark_seen(conn, package_id, present_strs)
        for v in versions:
            if not (v.get("deprecated") or v.get("yanked")):
                continue
            events = db.apply_lifecycle(
                conn,
                package_id=package_id,
                version=v["version"],
                deprecated_reason=v.get("deprecated"),
                yanked=bool(v.get("yanked")),
                yanked_reason=v.get("yanked_reason"),
                run_id=run_id,
            )
            if "deprecated" in events:
                deprecated += 1
            if "yanked" in events:
                yanked += 1
        if vanished_strs:
            transitioned = db.mark_vanished(conn, package_id, vanished_strs, run_id)
            vanished = len(transitioned)
    return {"deprecated": deprecated, "yanked": yanked, "vanished": vanished}


async def run_source(source_mod: ModuleType, seed_file: Path) -> int:
    ecosystem = source_mod.ECOSYSTEM
    package_names = _load_seeds(seed_file)
    _log_event(logging.INFO, "run_start", source=ecosystem, seed_count=len(package_names))

    with db.connect() as conn:
        run_id = db.start_run(conn, ecosystem)

    counters = {
        "packages_attempted": 0,
        "versions_inserted": 0,
        "errors": 0,
        "deprecated_events": 0,
        "yanked_events": 0,
        "vanished_events": 0,
    }
    semaphore = asyncio.Semaphore(CONCURRENCY)
    limiter = AsyncLimiter(RATE_LIMIT_PER_SECOND, 1)
    started = time.monotonic()

    async with httpx.AsyncClient(headers={"User-Agent": "chaingate-collector/0.1"}) as client:
        tasks = [
            _process_package(source_mod, client, semaphore, limiter, name, counters, run_id)
            for name in package_names
        ]
        try:
            await asyncio.wait_for(asyncio.gather(*tasks), timeout=RUN_TIMEOUT_SECONDS)
            status = "success" if counters["errors"] == 0 else "partial"
        except asyncio.TimeoutError:
            status = "failed"
            _log_event(logging.ERROR, "run_timeout", elapsed_s=time.monotonic() - started)

    with db.connect() as conn:
        db.finish_run(
            conn,
            run_id=run_id,
            packages_attempted=counters["packages_attempted"],
            versions_inserted=counters["versions_inserted"],
            errors=counters["errors"],
            status=status,
        )

    _log_event(
        logging.INFO,
        "run_end",
        source=ecosystem,
        status=status,
        elapsed_s=round(time.monotonic() - started, 2),
        **counters,
    )
    return 0 if status == "success" else 1


def _load_seeds(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def main() -> int:
    if len(sys.argv) < 2:
        print(
            f"usage: python -m collector.collector <source> [seed_file]\n"
            f"sources: {', '.join(SOURCES)}",
            file=sys.stderr,
        )
        return 2

    source_name = sys.argv[1]
    if source_name not in SOURCES:
        print(f"unsupported source: {source_name}", file=sys.stderr)
        print(f"supported: {', '.join(SOURCES)}", file=sys.stderr)
        return 2

    source_mod, default_seed = SOURCES[source_name]
    seed_file = Path(sys.argv[2]) if len(sys.argv) > 2 else SEEDS_DIR / default_seed
    if not seed_file.exists():
        print(f"seed file not found: {seed_file}", file=sys.stderr)
        return 2

    return asyncio.run(run_source(source_mod, seed_file))


if __name__ == "__main__":
    sys.exit(main())
