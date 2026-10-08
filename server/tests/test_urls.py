import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.urls import clean

INC, EXC = ["*.example.com"], ["status.example.com"]


def test_clean_filters_scope_static_and_duplicates():
    out = clean([
        "https://app.example.com/item?id=1",
        "https://app.example.com/item?id=2",          # same shape as above
        "https://app.example.com/item?id=2&sort=x",   # new parameter set
        "https://app.example.com/logo.png",           # static
        "https://app.example.com/static/app.js?v=3",  # JS is kept
        "https://status.example.com/",                # excluded
        "https://evil.test/?u=app.example.com",       # foreign host
        "javascript:alert(1)",
        "ftp://app.example.com/file",
    ], INC, EXC)
    assert [u for _, u, _ in out] == [
        "https://app.example.com/item?id=1",
        "https://app.example.com/item?id=2&sort=x",
        "https://app.example.com/static/app.js?v=3",
    ]
    assert [js for *_, js in out] == [False, False, True]


def test_fragment_is_dropped():
    assert clean(["https://a.example.com/p#top"], INC, [])[0][1] == "https://a.example.com/p"
