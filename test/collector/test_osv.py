"""Unit tests for collector.sources.osv range-matching surface.

Covers the pure functions _parse_version, _cmp_versions,
_split_comparator, matches_range, and a round-trip through
_format_ranges + matches_range. No Postgres, no network.
"""
from __future__ import annotations

import pytest

from collector.sources.osv import (
    _cmp_versions,
    _format_ranges,
    _parse_version,
    _split_comparator,
    matches_range,
)


# -- _parse_version ---------------------------------------------------------

@pytest.mark.parametrize("inp,expected", [
    ("", ()),
    ("1.2.3", (1, 2, 3)),
    ("1.0", (1, 0)),
    ("1.2.3-rc.1", (1, 2, 3)),
    ("1.2.3+build.5", (1, 2, 3)),
    ("1.2.3-rc.1+build.5", (1, 2, 3)),
    ("1.2.a", (1, 2, -1)),
])
def test_parse_version(inp, expected):
    assert _parse_version(inp) == expected


# -- _cmp_versions ----------------------------------------------------------

@pytest.mark.parametrize("a,b,expected", [
    ("1.0", "1.0.0", 0),
    ("1.0.0", "1.0.1", -1),
    ("2.0.0", "1.99.99", 1),
    ("1.0.0-rc.1", "1.0.0", 0),
])
def test_cmp_versions(a, b, expected):
    assert _cmp_versions(a, b) == expected


# -- _split_comparator ------------------------------------------------------

@pytest.mark.parametrize("token,expected", [
    (">=1.2.3", (">=", "1.2.3")),
    ("<=1.2.3", ("<=", "1.2.3")),
    (">1.2.3", (">", "1.2.3")),
    ("<1.2.3", ("<", "1.2.3")),
    ("=1.2.3", ("=", "1.2.3")),
    ("1.2.3", ("=", "1.2.3")),
])
def test_split_comparator(token, expected):
    assert _split_comparator(token) == expected


# -- matches_range ----------------------------------------------------------

@pytest.mark.parametrize("version,rng,expected", [
    ("1.14.0", "<1.14.1", True),
    ("1.14.1", "<1.14.1", False),
    ("10.1.6", ">=10.1.6 <10.1.8", True),
    ("10.1.7", ">=10.1.6 <10.1.8", True),
    ("10.1.8", ">=10.1.6 <10.1.8", False),
    ("10.1.5", ">=10.1.6 <10.1.8", False),
    ("1.2.0", ">=1.0.0 <1.1.0 || >=1.2.0 <1.3.0", True),
    ("1.1.5", ">=1.0.0 <1.1.0 || >=1.2.0 <1.3.0", False),
    ("1.0.0-rc.1", "=1.0.0", True),
    ("1.0.0-rc.1", "<1.0.0", False),
    ("1.0", "<1.0.1", True),
    ("2.0.0", ">=1.5.0", True),
    ("1.2.3", "", False),
    ("1.2.3", None, False),
    ("", ">=1.0.0", False),
    ("1.2.3", "1.2.3", True),
])
def test_matches_range(version, rng, expected):
    assert matches_range(version, rng) is expected


# -- round-trip: _format_ranges output feeds matches_range ------------------

def test_roundtrip_node_ipc_shape():
    ranges = [
        {"events": [{"introduced": "10.1.6"}, {"fixed": "10.1.8"}]},
    ]
    rng = _format_ranges(ranges)
    assert rng == ">=10.1.6 <10.1.8"
    assert matches_range("10.1.6", rng) is True
    assert matches_range("10.1.7", rng) is True
    assert matches_range("10.1.5", rng) is False
    assert matches_range("10.1.8", rng) is False


def test_roundtrip_axios_shape():
    ranges = [
        {"events": [{"introduced": "0"}, {"fixed": "1.14.1"}]},
    ]
    rng = _format_ranges(ranges)
    assert rng == "<1.14.1"
    assert matches_range("0.0.1", rng) is True
    assert matches_range("1.14.0", rng) is True
    assert matches_range("1.14.1", rng) is False
