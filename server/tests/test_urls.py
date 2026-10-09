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


def test_static_files_under_interesting_paths_are_kept_and_media_elsewhere_dropped():
    out = [u for _, u, _ in clean([
        "https://a.example.com/assets/public/images/uploads/%F0%9F%98%BC-%23zatschi-1.jpg",  # upload: kept
        "https://a.example.com/assets/logo.png",                                           # media: dropped
        "https://a.example.com/backup/site.css",                                           # under backup: kept
        "https://a.example.com/assets/site.zip",                                           # archive: kept anywhere
        "https://a.example.com/static/main.js.map",                                        # sourcemap: kept
        "https://a.example.com/fonts/a.woff2",
    ], INC, [])]
    assert out == ["https://a.example.com/assets/public/images/uploads/%F0%9F%98%BC-%23zatschi-1.jpg",
                   "https://a.example.com/backup/site.css", "https://a.example.com/assets/site.zip",
                   "https://a.example.com/static/main.js.map"]


def test_hash_routes_are_kept_as_their_own_entries():
    out = [u for _, u, _ in clean(["https://a.example.com/#/score-board", "https://a.example.com/#/admin",
                                   "https://a.example.com/#!/legacy", "https://a.example.com/#/admin",
                                   "https://a.example.com/#section"], INC, [])]
    assert out == ["https://a.example.com/#/score-board", "https://a.example.com/#/admin",
                   "https://a.example.com/#!/legacy", "https://a.example.com/"]
