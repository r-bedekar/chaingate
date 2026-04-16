"""PyPI source.

Fetches full package metadata from pypi.org/pypi/{name}/json and parses each
release into the normalized shape that db.insert_version_if_new expects.

PyPI quirks worth knowing:

1. The /pypi/{name}/json endpoint returns top-level `info` only for the LATEST
   version. Older versions in `releases` come with file-level data (hashes,
   upload time, size) but NO per-version author/requires_dist/etc. To get
   those we make one additional `GET /pypi/{name}/{version}/json` per *new*
   version in the hourly run — `enrich_version` handles that. Historical rows
   already in the DB with NULL enrichable fields are filled by the one-time
   `collector.backfill_pypi` script. Both paths use `db.update_version_fill_nulls`
   which protects non-NULL values at the SQL layer (see invariant #1).

2. Each version has ONE OR MORE files (one sdist plus possibly many wheels).
   Our schema has a single `content_hash` column, so we record the sdist's
   sha256 if present, else the first wheel's. Every file's hash is preserved
   in `raw_metadata` so a future gate can inspect per-wheel divergence.

3. PyPI has no `has_install_scripts` field in the JSON API. Detection requires
   downloading the sdist and inspecting setup.py / pyproject.toml — handled
   by `collector.sources.pypi_tarball`, invoked from `enrich_version` for
   each new version.

4. PEP 740 sigstore attestations for PyPI exist but are not yet exposed in
   the JSON API. `provenance_present` is False for all PyPI rows today.
"""
from __future__ import annotations

import json
from typing import Any

import httpx
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

REGISTRY_URL = "https://pypi.org/pypi"
ECOSYSTEM = "pypi"

RAW_METADATA_MAX_BYTES = 500_000


class PackageNotFoundError(Exception):
    pass


class RegistryError(Exception):
    """Non-retryable registry error."""


class RetryableRegistryError(Exception):
    """Retryable registry error (5xx)."""


async def fetch_package(client: httpx.AsyncClient, package_name: str) -> dict[str, Any]:
    return await _fetch_json(client, f"{REGISTRY_URL}/{package_name}/json", package_name)


async def fetch_version(
    client: httpx.AsyncClient, package_name: str, version: str
) -> dict[str, Any]:
    """Fetch per-version JSON to get author/email/requires_dist.

    Older releases on `/pypi/{name}/json` come without these fields; this
    endpoint always returns them for any version that still exists on PyPI.
    """
    url = f"{REGISTRY_URL}/{package_name}/{version}/json"
    return await _fetch_json(client, url, f"{package_name}@{version}")


async def _fetch_json(
    client: httpx.AsyncClient, url: str, label: str
) -> dict[str, Any]:
    async for attempt in AsyncRetrying(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=16),
        retry=retry_if_exception_type((httpx.TransportError, RetryableRegistryError)),
        reraise=True,
    ):
        with attempt:
            resp = await client.get(url, timeout=30.0)
            if resp.status_code == 404:
                raise PackageNotFoundError(label)
            if 500 <= resp.status_code < 600:
                raise RetryableRegistryError(f"{label}: HTTP {resp.status_code}")
            if resp.status_code != 200:
                raise RegistryError(f"{label}: unexpected HTTP {resp.status_code}")
            return resp.json()
    raise RuntimeError("unreachable")


def parse_version_detail(raw: dict[str, Any]) -> dict[str, Any]:
    """Extract enrichable fields from a per-version PyPI JSON response."""
    info = raw.get("info") or {}
    deps: list[str] = info.get("requires_dist") or []
    return {
        "publisher_name": _trim(info.get("author"), 300),
        "publisher_email": _trim(info.get("author_email"), 300),
        "publisher_maintainer": _trim(info.get("maintainer"), 300),
        "publisher_maintainer_email": _trim(info.get("maintainer_email"), 300),
        "dependency_count": len(deps) if info.get("requires_dist") is not None else None,
        "dependencies": {"requires_dist": deps} if info.get("requires_dist") is not None else None,
        "source_repo_url": _extract_home_page(info),
        "license_text": _trim_text(info.get("license"), 5000),
        "license_expression": _trim(info.get("license_expression"), 300),
    }


async def enrich_version(
    client: httpx.AsyncClient,
    package_name: str,
    version: str,
) -> dict[str, Any]:
    """Return the dict of fillable fields for one version. Exceptions from
    the per-version JSON fetch bubble up (caller decides fail-open behavior);
    tarball inspection failures are swallowed into `has_install_scripts=None`
    because a missing install-scripts signal shouldn't block the write.
    """
    from collector.sources import pypi_tarball

    raw = await fetch_version(client, package_name, version)
    fills = parse_version_detail(raw)

    files = raw.get("urls") or []
    try:
        scripts = await pypi_tarball.inspect_version(
            client, package_name, version, files
        )
    except Exception:
        scripts = None
    if scripts is not None:
        fills["has_install_scripts"] = scripts

    return fills


def parse_versions(raw: dict[str, Any]) -> list[dict[str, Any]]:
    info = raw.get("info") or {}
    releases = raw.get("releases") or {}
    latest_version = info.get("version")

    # Latest-version-only fields
    latest_deps: list[str] = info.get("requires_dist") or []
    latest_author: str | None = _trim(info.get("author"), 300)
    latest_author_email: str | None = _trim(info.get("author_email"), 300)
    latest_maintainer: str | None = _trim(info.get("maintainer"), 300)
    latest_maintainer_email: str | None = _trim(info.get("maintainer_email"), 300)
    latest_home_page: str | None = _extract_home_page(info)
    latest_license_text: str | None = _trim_text(info.get("license"), 5000)
    latest_license_expr: str | None = _trim(info.get("license_expression"), 300)

    result: list[dict[str, Any]] = []
    for version_str, files in releases.items():
        if not isinstance(files, list):
            continue
        primary = _select_primary_file(files)
        is_latest = version_str == latest_version
        yanked, yanked_reason = _rollup_yanked(files)
        file_rows = _parse_files(files)

        result.append(
            {
                "version": version_str,
                "files": file_rows,
                "published_at": (primary or {}).get("upload_time_iso_8601")
                or (primary or {}).get("upload_time"),
                "content_hash": _dig(primary, "digests", "sha256"),
                "content_hash_algo": "sha256" if _dig(primary, "digests", "sha256") else None,
                "dependency_count": len(latest_deps) if is_latest else None,
                "dependencies": {"requires_dist": latest_deps} if is_latest else None,
                "publisher_name": latest_author if is_latest else None,
                "publisher_email": latest_author_email if is_latest else None,
                "publisher_maintainer": latest_maintainer if is_latest else None,
                "publisher_maintainer_email": latest_maintainer_email if is_latest else None,
                "license_text": latest_license_text if is_latest else None,
                "license_expression": latest_license_expr if is_latest else None,
                "publish_method": "unknown",
                "provenance_present": False,
                "provenance_details": None,
                "has_install_scripts": None,
                "package_size_bytes": (primary or {}).get("size"),
                "source_repo_url": latest_home_page if is_latest else None,
                "raw_metadata": _build_raw_metadata(version_str, files, is_latest, info),
                "deprecated": None,  # PyPI has no deprecation concept
                "yanked": yanked,
                "yanked_reason": yanked_reason,
            }
        )

    return result


def _parse_files(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize a release's file list for version_files insertion.

    Each PyPI release has one sdist plus 0..N wheels. We keep one row per
    file so wheel-replacement and wheel-yank attacks stay visible. Hash
    preference is sha256 (PyPI's canonical); md5 is ignored.
    """
    rows: list[dict[str, Any]] = []
    for f in files:
        if not isinstance(f, dict):
            continue
        filename = f.get("filename")
        if not isinstance(filename, str) or not filename:
            continue
        digests = f.get("digests") or {}
        sha256 = digests.get("sha256") if isinstance(digests, dict) else None
        yanked_flag = bool(f.get("yanked"))
        yanked_reason = f.get("yanked_reason")
        if not (isinstance(yanked_reason, str) and yanked_reason.strip()):
            yanked_reason = None
        rows.append(
            {
                "filename": filename[:500],
                "packagetype": _trim(f.get("packagetype"), 32),
                "python_version": _trim(f.get("python_version"), 32),
                "content_hash": sha256,
                "content_hash_algo": "sha256" if sha256 else None,
                "size_bytes": f.get("size"),
                "uploaded_at": f.get("upload_time_iso_8601") or f.get("upload_time"),
                "url": _trim(f.get("url"), 1000),
                "yanked": yanked_flag,
                "yanked_reason": yanked_reason[:2000] if yanked_reason else None,
                "raw_metadata": f,
            }
        )
    return rows


def _rollup_yanked(files: list[dict[str, Any]]) -> tuple[bool, str | None]:
    """PyPI yank is per-file but always applied across all files of a release
    in practice. We consider the version yanked if any file is yanked, and
    surface the first non-empty reason we find."""
    any_yanked = False
    reason: str | None = None
    for f in files:
        if f.get("yanked"):
            any_yanked = True
            if reason is None:
                r = f.get("yanked_reason")
                if isinstance(r, str) and r.strip():
                    reason = r.strip()[:2000]
    return any_yanked, reason


def _select_primary_file(files: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not files:
        return None
    for f in files:
        if f.get("packagetype") == "sdist":
            return f
    return files[0]


def _dig(d: dict[str, Any] | None, *keys: str) -> Any:
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def _trim(value: Any, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return None
    return value[:limit]


def _trim_text(value: Any, limit: int) -> str | None:
    """Same as _trim but for longer text columns — license can be multi-line."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return None
    return value[:limit]


def _extract_home_page(info: dict[str, Any]) -> str | None:
    hp = _trim(info.get("home_page"), 500)
    if hp:
        return hp
    project_urls = info.get("project_urls")
    if isinstance(project_urls, dict):
        for key in ("Source", "Homepage", "Repository", "Source Code"):
            v = _trim(project_urls.get(key), 500)
            if v:
                return v
    return None


def _build_raw_metadata(
    version_str: str,
    files: list[dict[str, Any]],
    is_latest: bool,
    info: dict[str, Any],
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "version": version_str,
        "files": files,
    }
    if is_latest:
        payload["info_snapshot"] = info
    encoded = json.dumps(payload, default=str)
    if len(encoded) <= RAW_METADATA_MAX_BYTES:
        return payload
    # Drop the heaviest fields if we overflowed
    if is_latest and "info_snapshot" in payload:
        snap = dict(info)
        for heavy in ("description", "description_content_type", "readme"):
            snap.pop(heavy, None)
        payload["info_snapshot"] = snap
        encoded = json.dumps(payload, default=str)
        if len(encoded) <= RAW_METADATA_MAX_BYTES:
            return payload
    return {"_truncated": True, "version": version_str, "file_count": len(files)}
