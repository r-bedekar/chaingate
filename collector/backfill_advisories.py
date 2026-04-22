"""P3 advisory backfill — ingest OSV advisories for all seed packages.

Two-stage fetch mirrors the OSV API:

1. querybatch every (name, ecosystem) pair in `packages` — one POST
   returns up to ~1000 sparse hits. We collect the unique advisory ids.

2. GET /v1/vulns/{id} for each unique id (rate-limited). We cache by id so
   multi-package advisories (typosquats + originals) are fetched once.

For every (vuln × affected-entry matching a seed package) we upsert one
row into attack_labels, keyed on (advisory_id, package_id). OSV ranges
are flattened to a semver-ish string and stored in `affected_range`;
version_id stays NULL because most advisories cover a range, not a pin.

Records one `collector_runs` row with source='osv_backfill'.

Usage:
    .venv/bin/python -m collector.backfill_advisories
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
from datetime import datetime
from typing import Any

import httpx
from aiolimiter import AsyncLimiter

from collector import db
from collector.sources import osv

CONCURRENCY = 10
RATE_LIMIT_PER_SECOND = 10
BATCH_QUERY_SIZE = 500  # OSV querybatch accepts up to 1000; stay safe

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":%(message)s}',
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
log = logging.getLogger("backfill_advisories")


def _event(level: int, event: str, **fields: Any) -> None:
    log.log(level, json.dumps({"event": event, **fields}))


def _load_packages() -> list[tuple[int, str, str]]:
    """Return [(package_id, ecosystem, package_name), ...] for every seed."""
    with db.connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, ecosystem, package_name FROM packages ORDER BY id"
        )
        return cur.fetchall()


def _parse_modified(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


async def _query_all(
    client: httpx.AsyncClient,
    packages: list[tuple[int, str, str]],
) -> dict[str, list[tuple[int, str, str]]]:
    """POST all queries in chunks. Returns vuln_id -> [(pkg_id, eco, name), ...]
    so we know which seed packages each advisory references."""
    id_to_pkgs: dict[str, list[tuple[int, str, str]]] = {}
    for start in range(0, len(packages), BATCH_QUERY_SIZE):
        chunk = packages[start : start + BATCH_QUERY_SIZE]
        queries = [
            {
                "package": {
                    "name": name,
                    "ecosystem": osv.ECOSYSTEM_MAP.get(eco, eco),
                }
            }
            for _, eco, name in chunk
        ]
        results = await osv.query_batch(client, queries)
        for (pkg_id, eco, name), result in zip(chunk, results):
            vulns = (result or {}).get("vulns") or []
            for v in vulns:
                vid = v.get("id")
                if not isinstance(vid, str):
                    continue
                id_to_pkgs.setdefault(vid, []).append((pkg_id, eco, name))
        _event(
            logging.INFO,
            "querybatch_chunk",
            chunk_start=start,
            chunk_size=len(chunk),
            unique_ids=len(id_to_pkgs),
        )
    return id_to_pkgs


async def _fetch_one(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    limiter: AsyncLimiter,
    vuln_id: str,
    cache: dict[str, dict[str, Any]],
    counters: dict[str, int],
) -> None:
    async with semaphore:
        async with limiter:
            try:
                cache[vuln_id] = await osv.fetch_vuln(client, vuln_id)
                counters["fetched"] += 1
            except Exception as e:
                counters["fetch_errors"] += 1
                _event(
                    logging.WARNING,
                    "fetch_failed",
                    vuln_id=vuln_id,
                    error=type(e).__name__,
                    message=str(e),
                )


def _ingest_vuln(
    vuln: dict[str, Any],
    pkgs: list[tuple[int, str, str]],
    counters: dict[str, int],
) -> None:
    vid = vuln.get("id")
    if not isinstance(vid, str):
        return
    is_mal = osv.is_malicious(vuln)
    severity = osv.parse_severity(vuln)
    summary = vuln.get("summary")
    if isinstance(summary, str):
        summary = summary[:2000]
    else:
        summary = None
    aliases = vuln.get("aliases") if isinstance(vuln.get("aliases"), list) else None
    modified = _parse_modified(vuln.get("modified"))
    refs = vuln.get("references") or []
    primary_url: str | None = None
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, dict) and isinstance(ref.get("url"), str):
                primary_url = ref["url"][:1000]
                break

    attack_name = "malware" if is_mal else "advisory"

    with db.connect() as conn:
        for package_id, eco, name in pkgs:
            affected_entries = osv.parse_affected_for_package(vuln, name, eco)
            if not affected_entries:
                counters["unmatched_affected"] += 1
                continue
            first = affected_entries[0]
            inserted = db.upsert_attack_label(
                conn,
                advisory_id=vid,
                package_id=package_id,
                version_id=None,
                is_malicious=is_mal,
                attack_name=attack_name,
                source="osv",
                severity=severity,
                summary=summary,
                affected_range=first.get("affected_range"),
                aliases=aliases,
                url=primary_url,
                modified_at=modified,
                raw_advisory=vuln,
            )
            if inserted:
                counters["inserted"] += 1
            else:
                counters["updated"] += 1
            if is_mal:
                counters["malicious_rows"] += 1

            # Version-pinned resolution: for malicious advisories only,
            # intersect the advisory's affected set with our observed
            # versions and emit one pinned row per hit. The package-level
            # row above stays — both views serve different consumers
            # (range-based enumeration vs. direct version→lag lookup).
            #
            # Resolution strategy, in order:
            #   1. explicit affected_versions[] (direct set intersection)
            #   2. affected_range via osv.matches_range()
            # First entry of `affected_entries` is used for consistency
            # with the package-level row above (same `first` dict).
            if is_mal:
                existing = db.existing_version_ids(conn, package_id)
                explicit = first.get("affected_versions") or []
                range_str = first.get("affected_range")
                explicit_set = set(explicit)
                hits: list[int] = []
                for ver_str, ver_id in existing.items():
                    if ver_str in explicit_set:
                        hits.append(ver_id)
                    elif range_str and osv.matches_range(ver_str, range_str):
                        hits.append(ver_id)
                if not hits:
                    counters["version_pinned_skipped_no_match"] += 1
                for ver_id in hits:
                    pinned_inserted = db.insert_version_pinned_attack_label(
                        conn,
                        advisory_id=vid,
                        package_id=package_id,
                        version_id=ver_id,
                        is_malicious=is_mal,
                        attack_name=attack_name,
                        source="osv-version-resolved",
                        severity=severity,
                        summary=summary,
                        affected_range=first.get("affected_range"),
                        aliases=aliases,
                        url=primary_url,
                        modified_at=modified,
                        raw_advisory=vuln,
                    )
                    if pinned_inserted:
                        counters["version_pinned_inserted"] += 1
                    else:
                        counters["version_pinned_updated"] += 1


async def run() -> int:
    started = time.monotonic()
    packages = _load_packages()
    _event(logging.INFO, "backfill_start", packages=len(packages))

    with db.connect() as conn:
        run_id = db.start_run(conn, "osv_backfill")

    counters = {
        "fetched": 0,
        "fetch_errors": 0,
        "inserted": 0,
        "updated": 0,
        "unmatched_affected": 0,
        "malicious_rows": 0,
        "version_pinned_inserted": 0,
        "version_pinned_updated": 0,
        "version_pinned_skipped_no_match": 0,
    }

    cache: dict[str, dict[str, Any]] = {}
    semaphore = asyncio.Semaphore(CONCURRENCY)
    limiter = AsyncLimiter(RATE_LIMIT_PER_SECOND, 1)

    async with httpx.AsyncClient(
        headers={"User-Agent": "chaingate-advisories/0.1"}
    ) as client:
        id_to_pkgs = await _query_all(client, packages)
        _event(
            logging.INFO,
            "querybatch_done",
            unique_advisories=len(id_to_pkgs),
        )

        tasks = [
            _fetch_one(client, semaphore, limiter, vid, cache, counters)
            for vid in id_to_pkgs
        ]
        await asyncio.gather(*tasks)

    for vid, pkgs in id_to_pkgs.items():
        vuln = cache.get(vid)
        if not vuln:
            continue
        _ingest_vuln(vuln, pkgs, counters)

    elapsed = round(time.monotonic() - started, 2)
    status = "success" if counters["fetch_errors"] == 0 else "partial"

    with db.connect() as conn:
        db.finish_run(
            conn,
            run_id=run_id,
            packages_attempted=len(packages),
            versions_inserted=counters["inserted"] + counters["updated"],
            errors=counters["fetch_errors"],
            status=status,
            notes=(
                f"advisories={len(id_to_pkgs)} "
                f"inserted={counters['inserted']} updated={counters['updated']} "
                f"malicious={counters['malicious_rows']}"
            ),
        )

    _event(
        logging.INFO,
        "backfill_end",
        status=status,
        elapsed_s=elapsed,
        advisories=len(id_to_pkgs),
        **counters,
    )
    return 0 if status == "success" else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
