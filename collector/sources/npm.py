"""npm registry source.

Fetches full package metadata from registry.npmjs.org and parses each version
into the normalized shape that db.insert_version_if_new expects.
"""
from __future__ import annotations

from typing import Any

import httpx
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

REGISTRY_URL = "https://registry.npmjs.org"
ECOSYSTEM = "npm"

# Cap raw_metadata to avoid blowing up the DB on oddly large per-version objects.
RAW_METADATA_MAX_BYTES = 500_000


class PackageNotFoundError(Exception):
    pass


class RegistryError(Exception):
    """Non-retryable registry error (4xx other than 404, unexpected shape)."""


class RetryableRegistryError(Exception):
    """Retryable registry error (5xx). Separated so tenacity retries only these."""


async def fetch_package(client: httpx.AsyncClient, package_name: str) -> dict[str, Any]:
    """GET the full package metadata. Retries on 5xx and network errors, not 4xx."""
    async for attempt in AsyncRetrying(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=16),
        retry=retry_if_exception_type((httpx.TransportError, RetryableRegistryError)),
        reraise=True,
    ):
        with attempt:
            resp = await client.get(f"{REGISTRY_URL}/{package_name}", timeout=30.0)
            if resp.status_code == 404:
                raise PackageNotFoundError(package_name)
            if 500 <= resp.status_code < 600:
                raise RetryableRegistryError(f"{package_name}: HTTP {resp.status_code}")
            if resp.status_code != 200:
                raise RegistryError(f"{package_name}: unexpected HTTP {resp.status_code}")
            return resp.json()
    raise RuntimeError("unreachable")  # tenacity either returns or raises


def parse_versions(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a full npm registry response into a list of normalized version dicts."""
    versions = raw.get("versions", {})
    time_map = raw.get("time", {})
    result: list[dict[str, Any]] = []

    for version_str, version_obj in versions.items():
        parsed = _parse_single_version(version_str, version_obj, time_map.get(version_str))
        result.append(parsed)

    return result


def _parse_single_version(
    version_str: str, version_obj: dict[str, Any], published_at: str | None
) -> dict[str, Any]:
    dist = version_obj.get("dist") or {}
    dependencies = version_obj.get("dependencies") or {}
    dev_deps = version_obj.get("devDependencies") or {}
    peer_deps = version_obj.get("peerDependencies") or {}
    optional_deps = version_obj.get("optionalDependencies") or {}
    # npm spec uses `bundleDependencies`; in practice registries store either.
    bundled_deps = (
        version_obj.get("bundledDependencies")
        or version_obj.get("bundleDependencies")
        or None
    )
    scripts = version_obj.get("scripts") or {}
    npm_user = version_obj.get("_npmUser") or {}
    maintainers = version_obj.get("maintainers") or None
    attestations = dist.get("attestations")
    deprecated = version_obj.get("deprecated")
    npm_client_version = version_obj.get("_npmVersion")

    raw_metadata = _truncate_raw(version_obj)

    return {
        "version": version_str,
        "published_at": published_at,
        "files": _synthesize_files(version_str, version_obj, dist, published_at),
        "content_hash": dist.get("shasum"),
        "content_hash_algo": "sha1" if dist.get("shasum") else None,
        "integrity_hash": dist.get("integrity"),
        "git_head": _trim(version_obj.get("gitHead"), 64),
        "dependency_count": len(dependencies),
        "dependencies": dependencies,
        "dev_dependencies": dev_deps or None,
        "peer_dependencies": peer_deps or None,
        "optional_dependencies": optional_deps or None,
        "bundled_dependencies": _normalize_bundled(bundled_deps),
        "dev_dependency_count": len(dev_deps),
        "peer_dependency_count": len(peer_deps),
        "optional_dependency_count": len(optional_deps),
        "bundled_dependency_count": _bundled_count(bundled_deps),
        "publisher_name": npm_user.get("name"),
        "publisher_email": npm_user.get("email"),
        "publisher_tool": _normalize_tool(npm_client_version),
        "maintainers": _normalize_maintainers(maintainers),
        "publish_method": "oidc" if attestations else "unknown",
        "provenance_present": bool(attestations),
        "provenance_details": attestations,
        "has_install_scripts": any(
            scripts.get(k) for k in ("preinstall", "install", "postinstall")
        ),
        "package_size_bytes": dist.get("unpackedSize"),
        "source_repo_url": _extract_repo_url(version_obj.get("repository")),
        "raw_metadata": raw_metadata,
        "deprecated": _deprecated_reason(deprecated),
        "yanked": False,
        "yanked_reason": None,
    }


def _synthesize_files(
    version_str: str,
    version_obj: dict[str, Any],
    dist: dict[str, Any],
    published_at: str | None,
) -> list[dict[str, Any]]:
    """npm publishes one tarball per version — unlike PyPI where a release
    can have sdist+N wheels. We still create one `version_files` row per
    version so the schema stays uniform. Filename is derived from the
    tarball URL basename when present."""
    tarball = dist.get("tarball")
    if not isinstance(tarball, str):
        return []
    filename = tarball.rsplit("/", 1)[-1] if "/" in tarball else tarball
    return [
        {
            "filename": filename[:500],
            "packagetype": "tarball",
            "python_version": None,
            "content_hash": dist.get("shasum"),
            "content_hash_algo": "sha1" if dist.get("shasum") else None,
            "size_bytes": dist.get("unpackedSize"),
            "uploaded_at": published_at,
            "url": tarball[:1000],
            "yanked": False,
            "yanked_reason": None,
            "raw_metadata": {
                "dist": dist,
                "_npmVersion": version_obj.get("_npmVersion"),
                "_nodeVersion": version_obj.get("_nodeVersion"),
                "_hasShrinkwrap": version_obj.get("_hasShrinkwrap"),
            },
        }
    ]


def _trim(value: Any, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value[:limit] if value else None


def _normalize_bundled(value: Any) -> Any:
    """`bundleDependencies` may be a list of package names OR a bool OR a dict.
    Store as-is if list/dict, drop if bool."""
    if isinstance(value, (list, dict)) and value:
        return value
    return None


def _bundled_count(value: Any) -> int:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return len(value)
    return 0


def _normalize_maintainers(value: Any) -> list[dict[str, str]] | None:
    """Keep only (name, email) pairs. Drop whatever else the registry sticks in."""
    if not isinstance(value, list) or not value:
        return None
    out: list[dict[str, str]] = []
    for m in value:
        if not isinstance(m, dict):
            continue
        name = m.get("name") if isinstance(m.get("name"), str) else None
        email = m.get("email") if isinstance(m.get("email"), str) else None
        if name or email:
            entry: dict[str, str] = {}
            if name:
                entry["name"] = name[:200]
            if email:
                entry["email"] = email[:200]
            out.append(entry)
    return out or None


def _normalize_tool(npm_version: Any) -> str | None:
    if isinstance(npm_version, str) and npm_version.strip():
        return f"npm@{npm_version.strip()[:80]}"
    return None


def _deprecated_reason(value: Any) -> str | None:
    """npm stores deprecation as a string reason. Presence = deprecated.
    Some old packages set `deprecated: true` as a boolean — normalize that."""
    if value is None or value is False:
        return None
    if value is True:
        return "(deprecated, no reason provided)"
    if isinstance(value, str):
        stripped = value.strip()
        return stripped[:2000] if stripped else None
    return None


def _extract_repo_url(repo: Any) -> str | None:
    if repo is None:
        return None
    if isinstance(repo, str):
        return repo[:500]
    if isinstance(repo, dict):
        url = repo.get("url")
        return url[:500] if isinstance(url, str) else None
    return None


def _truncate_raw(version_obj: dict[str, Any]) -> dict[str, Any]:
    """Defensive cap — if a single per-version object exceeds the limit, drop the
    heaviest fields. Popular packages sometimes inline huge README text here."""
    import json

    encoded = json.dumps(version_obj, default=str)
    if len(encoded) <= RAW_METADATA_MAX_BYTES:
        return version_obj
    trimmed = dict(version_obj)
    for heavy_key in ("readme", "description", "_attachments"):
        trimmed.pop(heavy_key, None)
    encoded = json.dumps(trimmed, default=str)
    if len(encoded) <= RAW_METADATA_MAX_BYTES:
        return trimmed
    return {"_truncated": True, "version": version_obj.get("version")}
