import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from app.scope import ScopeError, in_scope, normalize_pattern

INC = ["*.example.com", "example.com", "api.example.net"]
EXC = ["status.example.com", "*.legacy.example.com"]


@pytest.mark.parametrize("host,expected", [
    ("app.example.com", True),
    ("APP.Example.com.", True),          # normalized
    ("example.com", True),               # apex listed explicitly
    ("deep.a.example.com", True),
    ("api.example.net", True),
    ("www.example.net", False),          # exact rule only
    ("example.net", False),
    ("status.example.com", False),       # exclude wins
    ("x.legacy.example.com", False),     # wildcard exclude
    ("notexample.com", False),           # suffix must be a label boundary
    ("example.com.evil.test", False),
    ("", False),
    ("https://app.example.com", False),  # URLs are not hosts
])
def test_in_scope(host, expected):
    assert in_scope(host, INC, EXC) is expected


def test_wildcard_does_not_cover_apex():
    assert in_scope("example.org", ["*.example.org"], []) is False


def test_empty_rules_mean_nothing_is_in_scope():
    assert in_scope("app.example.com", [], []) is False


@pytest.mark.parametrize("bad", ["*example.com", "a.*.example.com", "http://x.example.com", "nodot"])
def test_rejects_bad_patterns(bad):
    with pytest.raises(ScopeError):
        normalize_pattern(bad)
