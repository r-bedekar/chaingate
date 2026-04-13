"""PEP 740 attestation fetcher for PyPI.

PyPI publishes sigstore-backed provenance for files uploaded via Trusted
Publishing (OIDC from GitHub Actions, GitLab CI, Google, ActiveState). The
flag is exposed at:

    GET https://pypi.org/integrity/{name}/{version}/{filename}/provenance

Response shape (observed 2026-04-13):

    {
      "version": 1,
      "attestation_bundles": [
        {
          "publisher": {
            "kind": "GitHub",
            "repository": "pypa/packaging",
            "workflow": "release.yml",
            "environment": "pypi"
          },
          "attestations": [ {...sigstore bundle bytes...} ]
        }
      ]
    }

Files without Trusted Publishing return HTTP 404 (the common case — most
uploads still use API tokens). We swallow 404 into attestation_present=False
and leave the other fields NULL.

Note: the `urls[].provenance` field on the main /pypi JSON is *not*
reliable — it's None even for packages like pydantic-core/uv/ruff that
are known to publish via OIDC. Always use the /integrity/ endpoint.
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

INTEGRITY_URL = "https://pypi.org/integrity"


class AttestationNotFound(Exception):
    """404 — file has no Trusted Publishing attestation."""


class RetryableAttestationError(Exception):
    """5xx — transient, retry."""


async def fetch_provenance(
    client: httpx.AsyncClient,
    package_name: str,
    version: str,
    filename: str,
) -> dict[str, Any]:
    """GET the provenance payload for one file. Raises AttestationNotFound
    on 404. Retries on 5xx up to 3 times."""
    url = f"{INTEGRITY_URL}/{package_name}/{version}/{filename}/provenance"
    async for attempt in AsyncRetrying(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=16),
        retry=retry_if_exception_type(
            (httpx.TransportError, RetryableAttestationError)
        ),
        reraise=True,
    ):
        with attempt:
            resp = await client.get(url, timeout=30.0)
            if resp.status_code == 404:
                raise AttestationNotFound(f"{package_name}/{version}/{filename}")
            if 500 <= resp.status_code < 600:
                raise RetryableAttestationError(
                    f"{filename}: HTTP {resp.status_code}"
                )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"{filename}: unexpected HTTP {resp.status_code}"
                )
            return resp.json()
    raise RuntimeError("unreachable")


def parse_provenance(raw: dict[str, Any]) -> dict[str, Any]:
    """Extract the bits we store into version_files columns.

    Returns: {
        attestation_present: True,
        attestation_publisher: {environment, kind, repository, workflow},
        attestation_bundles: [...]  # raw bundles for forensics
    }
    """
    bundles = raw.get("attestation_bundles")
    if not isinstance(bundles, list) or not bundles:
        return {"attestation_present": False}

    # First bundle wins for the publisher summary. Multi-bundle is possible
    # in theory but not observed in practice — keep all bundles in the raw
    # column for forensics.
    first = bundles[0] if isinstance(bundles[0], dict) else {}
    pub = first.get("publisher") if isinstance(first.get("publisher"), dict) else {}

    return {
        "attestation_present": True,
        "attestation_publisher": {
            "kind": _s(pub.get("kind")),
            "repository": _s(pub.get("repository")),
            "workflow": _s(pub.get("workflow")),
            "environment": _s(pub.get("environment")),
        },
        "attestation_bundles": bundles,
    }


def _s(v: Any) -> str | None:
    if isinstance(v, str) and v.strip():
        return v.strip()[:500]
    return None
