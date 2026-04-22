"""OSV.dev source for advisory ingest.

OSV federates GitHub Advisory Database, PyPA, RustSec, and many others.
One API covers npm, PyPI, Go, Maven, Packagist, RubyGems, crates.io, etc.

Two-stage fetch:

1. POST /v1/querybatch  — cheap; accepts up to 1000 package lookups per
   request, returns a sparse {id, modified} per hit. We use this to find
   WHICH advisories apply to our seed packages.

2. GET /v1/vulns/{id}   — one call per advisory. Returns the full OSV
   record with affected[].ranges[], severity, summary, database_specific.
   We cache these by id so multi-package advisories are fetched once.

Malware detection: OSV flags malicious-package advisories in two ways
we care about:
  - id starts with `MAL-` (Malicious Packages ecosystem)
  - summary contains "Malware in X" or "Embedded Malicious Code" (GHSA
    ghsa-malware category, which is the npm supply-chain attack set)

See https://google.github.io/osv.dev/api/.
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

API_BASE = "https://api.osv.dev/v1"

# OSV ecosystem names are capitalized for PyPI, lowercase for npm.
ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "PyPI",
}


class OSVError(Exception):
    pass


class RetryableOSVError(Exception):
    pass


async def query_batch(
    client: httpx.AsyncClient, queries: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """POST /v1/querybatch — returns one result entry per query in order.
    Each result is `{vulns: [{id, modified}, ...]}` (sparse)."""
    async for attempt in AsyncRetrying(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=16),
        retry=retry_if_exception_type((httpx.TransportError, RetryableOSVError)),
        reraise=True,
    ):
        with attempt:
            resp = await client.post(
                f"{API_BASE}/querybatch",
                json={"queries": queries},
                timeout=60.0,
            )
            if 500 <= resp.status_code < 600:
                raise RetryableOSVError(f"querybatch HTTP {resp.status_code}")
            if resp.status_code != 200:
                raise OSVError(f"querybatch HTTP {resp.status_code}")
            return resp.json().get("results", [])
    raise RuntimeError("unreachable")


async def fetch_vuln(client: httpx.AsyncClient, vuln_id: str) -> dict[str, Any]:
    """GET /v1/vulns/{id} — full advisory record."""
    async for attempt in AsyncRetrying(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=16),
        retry=retry_if_exception_type((httpx.TransportError, RetryableOSVError)),
        reraise=True,
    ):
        with attempt:
            resp = await client.get(f"{API_BASE}/vulns/{vuln_id}", timeout=30.0)
            if resp.status_code == 404:
                raise OSVError(f"vuln {vuln_id} not found")
            if 500 <= resp.status_code < 600:
                raise RetryableOSVError(f"vuln {vuln_id} HTTP {resp.status_code}")
            if resp.status_code != 200:
                raise OSVError(f"vuln {vuln_id} HTTP {resp.status_code}")
            return resp.json()
    raise RuntimeError("unreachable")


def parse_affected_for_package(
    vuln: dict[str, Any], package_name: str, ecosystem: str
) -> list[dict[str, Any]]:
    """Extract one label-dict per (vuln × affected-entry) matching package.

    Each OSV advisory can name multiple affected packages (same advisory
    covers both the original package and the typosquat, for example).
    We filter to the one(s) matching our package+ecosystem and flatten the
    ranges/versions fields into a single string we store in attack_labels.
    """
    eco_name = ECOSYSTEM_MAP.get(ecosystem, ecosystem)
    out: list[dict[str, Any]] = []
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("name") != package_name:
            continue
        if pkg.get("ecosystem") != eco_name:
            continue
        out.append(
            {
                "affected_range": _format_ranges(aff.get("ranges") or []),
                "affected_versions": aff.get("versions") or [],
            }
        )
    return out


def is_malicious(vuln: dict[str, Any]) -> bool:
    """Heuristic: an OSV entry represents a supply-chain/malware attack if:
      - id starts with MAL-   (OSV Malicious Packages ecosystem), OR
      - summary contains 'Malware' / 'malicious code' / 'typosquat', OR
      - database_specific.cwe_ids contains CWE-506 (Embedded Malicious Code).
    """
    vid = (vuln.get("id") or "").upper()
    if vid.startswith("MAL-"):
        return True
    summary = (vuln.get("summary") or "").lower()
    for marker in ("malware", "malicious code", "typosquat", "embedded malicious"):
        if marker in summary:
            return True
    ds = vuln.get("database_specific") or {}
    cwes = ds.get("cwe_ids") or []
    if isinstance(cwes, list) and "CWE-506" in cwes:
        return True
    return False


def parse_severity(vuln: dict[str, Any]) -> str | None:
    """OSV exposes severity in two places — `severity[]` (CVSS vectors)
    and `database_specific.severity` (string CRITICAL/HIGH/...). Prefer
    the latter because that's what consumers display, fall back to CVSS."""
    ds = vuln.get("database_specific") or {}
    s = ds.get("severity")
    if isinstance(s, str) and s:
        return s.upper()[:16]
    sev_list = vuln.get("severity")
    if isinstance(sev_list, list) and sev_list:
        item = sev_list[0]
        if isinstance(item, dict):
            t = item.get("type")
            if isinstance(t, str):
                return t.upper()[:16]
    return None


def _format_ranges(ranges: list[dict[str, Any]]) -> str | None:
    """Collapse OSV `ranges` (events introduced/fixed/last_affected) into
    a readable semver expression. Multi-range advisories are joined with
    ' || ' matching npm-style semver syntax."""
    parts: list[str] = []
    for r in ranges:
        events = r.get("events") or []
        introduced = None
        fixed = None
        last_affected = None
        for e in events:
            if not isinstance(e, dict):
                continue
            if "introduced" in e:
                introduced = e["introduced"]
            if "fixed" in e:
                fixed = e["fixed"]
            if "last_affected" in e:
                last_affected = e["last_affected"]
        if introduced == "0":
            intro_str = ""
        elif introduced is not None:
            intro_str = f">={introduced}"
        else:
            intro_str = ""
        if fixed is not None:
            end_str = f"<{fixed}"
        elif last_affected is not None:
            end_str = f"<={last_affected}"
        else:
            end_str = ""
        expr = " ".join(s for s in (intro_str, end_str) if s)
        if expr:
            parts.append(expr)
    return " || ".join(parts) if parts else None


# LIMITATION: this is a numeric-tuple comparator. It is correct for
# canonical npm MAJOR.MINOR.PATCH and adequate for PyPI when versions
# are plain X.Y.Z. Prerelease suffixes (everything after the first
# '-') and build metadata (after '+') are STRIPPED before comparison,
# not preserved — so "1.0.0-rc.1" is canonicalized to "1.0.0" and
# compares equal to the final "1.0.0" release rather than sorting
# before it. This does NOT implement PEP 440 prerelease/post ordering
# (1.0rc1 < 1.0 < 1.0.post1 is not preserved). Acceptable today
# because 0 malicious advisories intersect PyPI seed versions;
# revisit when PyPI malware or prerelease-sensitive malware lands in
# the corpus.
#
# Used exclusively by matches_range against expressions produced by
# _format_ranges above. Operator set is intentionally closed: >=, <=,
# >, <, =, and bare version (= exact).

_OPERATORS: tuple[str, ...] = (">=", "<=", ">", "<", "=")


def _parse_version(s: str) -> tuple[int, ...]:
    """Canonicalize a version string to a comparable tuple.

    Strips anything after the first '-' (npm prerelease tag) or '+'
    (build metadata), splits the remainder on '.', coerces each
    segment to int. Non-numeric segments become -1 so they sort
    before numeric releases.

    Empty string → empty tuple (sorts before all non-empty).
    """
    if not s:
        return ()
    core = s.split("-", 1)[0].split("+", 1)[0]
    parts: list[int] = []
    for seg in core.split("."):
        if seg.isdigit():
            parts.append(int(seg))
        else:
            parts.append(-1)
    return tuple(parts)


def _cmp_versions(a: str, b: str) -> int:
    """-1/0/+1 tuple-compare of two version strings, padded with
    zeros so '1.0' and '1.0.0' compare equal."""
    ta, tb = _parse_version(a), _parse_version(b)
    n = max(len(ta), len(tb))
    pa = ta + (0,) * (n - len(ta))
    pb = tb + (0,) * (n - len(tb))
    if pa < pb:
        return -1
    if pa > pb:
        return 1
    return 0


def matches_range(version_str: str, range_str: str | None) -> bool:
    """Evaluate a _format_ranges()-produced expression against a version.

    Grammar (exclusively what _format_ranges emits):
      expr        := conjunction ('||' conjunction)*
      conjunction := comparator (WS comparator)*
      comparator  := ('>='|'<='|'>'|'<'|'='|'') VERSION

    Semantics: any conjunction True ⇒ True. Within a conjunction all
    comparators must hold. Empty/None range_str returns False — the
    caller should skip labels that carry no range.
    """
    if not range_str or not version_str:
        return False
    for conj in range_str.split("||"):
        conj = conj.strip()
        if not conj:
            continue
        tokens = conj.split()
        if not tokens:
            continue
        if _conjunction_matches(version_str, tokens):
            return True
    return False


def _conjunction_matches(version_str: str, tokens: list[str]) -> bool:
    for token in tokens:
        op, rhs = _split_comparator(token)
        if rhs == "":
            return False  # defensive: malformed token
        c = _cmp_versions(version_str, rhs)
        if op == ">=" and not (c >= 0):
            return False
        elif op == "<=" and not (c <= 0):
            return False
        elif op == ">" and not (c > 0):
            return False
        elif op == "<" and not (c < 0):
            return False
        elif op == "=" and c != 0:
            return False
    return True


def _split_comparator(token: str) -> tuple[str, str]:
    """Return (operator, version) for a single comparator token.
    Bare version (no operator prefix) is treated as exact '='."""
    for op in _OPERATORS:
        if token.startswith(op):
            return op, token[len(op):].strip()
    return "=", token.strip()
