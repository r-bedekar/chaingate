"""Backfill advisory_published_at + detection_lag_days on attack_labels.

Reads raw_advisory JSONB on every attack_labels row, extracts the OSV
'published' timestamp, and computes detection_lag_days (advisory publish
date minus version publish date) where a version_id is pinned.

Negative lag rows are a data anomaly — logged at WARN for investigation.
Malformed or missing 'published' fields are left NULL rather than guessed.

Idempotent: reruns overwrite the two enrichment columns based on the
current raw_advisory contents. Does not touch any other field.

Usage:
    .venv/bin/python -m collector.backfill_advisory_timeline
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime
from statistics import median, quantiles
from typing import Any

from collector import db

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":%(message)s}',
)
log = logging.getLogger("backfill_advisory_timeline")


def _event(level: int, event: str, **fields: Any) -> None:
    log.log(level, json.dumps({"event": event, **fields}))


def _parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _extract_published(raw: Any) -> datetime | None:
    if not isinstance(raw, dict):
        return None
    return _parse_ts(raw.get("published"))


def run() -> int:
    populated = 0
    null_published = 0
    lag_populated = 0
    negative_lag: list[tuple[int, str, str, int]] = []  # (label_id, adv, pkg, lag)
    lag_values: list[int] = []

    with db.connect() as conn:
        db.apply_schema_migrations(conn)

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT a.id, a.advisory_id, a.version_id,
                       a.raw_advisory, v.published_at, p.package_name
                FROM attack_labels a
                JOIN packages p ON p.id = a.package_id
                LEFT JOIN versions v ON v.id = a.version_id
                """
            )
            rows = cur.fetchall()

        _event(logging.INFO, "backfill_start", rows=len(rows))

        with conn.cursor() as cur:
            for label_id, adv_id, version_id, raw, ver_published, pkg_name in rows:
                adv_published = _extract_published(raw)
                if adv_published is None:
                    null_published += 1
                    cur.execute(
                        "UPDATE attack_labels "
                        "SET advisory_published_at = NULL, detection_lag_days = NULL "
                        "WHERE id = %s",
                        (label_id,),
                    )
                    continue

                lag_days: int | None = None
                if version_id is not None and ver_published is not None:
                    delta = adv_published - ver_published
                    lag_days = delta.days
                    lag_populated += 1
                    lag_values.append(lag_days)
                    if lag_days < 0:
                        negative_lag.append(
                            (label_id, adv_id or "?", pkg_name, lag_days)
                        )

                cur.execute(
                    "UPDATE attack_labels "
                    "SET advisory_published_at = %s, detection_lag_days = %s "
                    "WHERE id = %s",
                    (adv_published, lag_days, label_id),
                )
                populated += 1

    distribution: dict[str, Any] = {}
    if lag_values:
        lag_sorted = sorted(lag_values)
        distribution = {
            "n": len(lag_sorted),
            "min": lag_sorted[0],
            "max": lag_sorted[-1],
            "median": median(lag_sorted),
        }
        if len(lag_sorted) >= 4:
            q = quantiles(lag_sorted, n=4)
            distribution["p25"] = q[0]
            distribution["p75"] = q[2]

    _event(
        logging.INFO,
        "backfill_summary",
        rows_total=len(rows) if rows else 0,
        advisory_published_at_populated=populated,
        null_published=null_published,
        detection_lag_days_populated=lag_populated,
        lag_distribution=distribution,
        negative_lag_count=len(negative_lag),
    )

    for label_id, adv_id, pkg_name, lag in negative_lag:
        _event(
            logging.WARNING,
            "negative_lag",
            label_id=label_id,
            advisory_id=adv_id,
            package_name=pkg_name,
            detection_lag_days=lag,
        )

    return 0


if __name__ == "__main__":
    sys.exit(run())
