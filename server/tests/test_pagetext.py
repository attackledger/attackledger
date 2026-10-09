"""Reading views and recon parsers: text survives the cut, listings and well-known files parse."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import pagetext

STYLE = "<style>" + "ul li { margin: 0; padding: 0; }\n" * 400 + "</style>"
LISTING = (f"<!DOCTYPE html><html><head><title>listing directory /ftp</title>{STYLE}"
           "<script>function x(){return 1}</script></head><body><h1>~ / ftp</h1><ul id='files'>"
           "<li><a href='.'>..</a></li><li><a href='ftp'>ftp</a></li>"
           "<li><a href='ftp/acquisitions.md' title='acquisitions.md'><span class='name'>acquisitions.md</span>"
           "<span class='size'>909</span></a></li>"
           "<li><a href='ftp/package.json.bak'><span>package.json.bak</span></a></li>"
           "<li><a href='ftp/quarantine'><span>quarantine</span></a></li></ul></body></html>")


def test_markup_styles_and_scripts_are_stripped_before_the_cut():
    assert len(LISTING) > 12_000 and LISTING.index("acquisitions.md") > 4000      # the old view never got there
    shown, kind = pagetext.view(LISTING, "http://h.test/ftp", "text/html; charset=utf-8")
    assert kind == "html-text" and len(shown) < 1000
    assert "acquisitions.md" in shown and "package.json.bak" in shown and "Directory listing, 3 entries" in shown
    assert "margin" not in shown and "function" not in shown
    assert "Links: . ftp ftp/acquisitions.md" in shown


def test_directory_listing_entries_resolve_and_skip_parent_and_self():
    assert pagetext.directory_listing(LISTING, "http://h.test/ftp") == [
        "http://h.test/ftp/acquisitions.md", "http://h.test/ftp/package.json.bak", "http://h.test/ftp/quarantine"]
    apache = ("<html><head><title>Index of /backup</title></head><body><h1>Index of /backup</h1>"
              "<a href='?C=N;O=D'>Name</a><a href='/'>Parent Directory</a><a href='db.sql.gz'>db.sql.gz</a>"
              "<a href='https://other.test/x'>x</a></body></html>")
    assert pagetext.directory_listing(apache, "http://h.test/backup/") == ["http://h.test/backup/db.sql.gz"]
    assert pagetext.directory_listing("<html><title>Shop</title><a href='a'>a</a></html>", "http://h.test/") is None


def test_robots_and_security_txt_parse_and_an_spa_index_is_neither():
    assert pagetext.robots("User-agent: *\nDisallow: /ftp\nDisallow: /admin/*\nAllow: /pub # ok\n"
                           "Sitemap: https://h.test/s.xml") == {
        "disallow": ["/ftp", "/admin/*"], "allow": ["/pub"], "sitemaps": ["https://h.test/s.xml"]}
    spa = "<!doctype html><html><head><title>App</title></head><body><app-root></app-root></body></html>"
    assert pagetext.robots(spa) is None and pagetext.security_txt(spa) is None
    assert pagetext.robots("hello world") is None
    st = pagetext.security_txt("# comment\nContact: mailto:sec@h.test\nAcknowledgements: /#/score-board\n")
    assert st == {"contact": ["mailto:sec@h.test"], "acknowledgements": ["/#/score-board"]}
    assert pagetext.security_txt("Expires: 2030-01-01") is None              # no Contact: not one


def test_large_bundles_are_summarised_and_small_or_plain_bodies_are_raw():
    bundle = ("var r=[{path:`score-board`,component:A},{path:`administration`,component:B}];"
              "RouterModule.forRoot(r,{useHash:!0});fetch('/rest/user/whoami');x='/10';" + "a=1;" * 3000)
    shown, kind = pagetext.view(bundle, "http://h.test/main.js", "application/javascript")
    assert kind == "js-summary" and len(shown) < 1000
    assert "/administration, /score-board" in shown and "hash routing" in shown and "/rest/user/whoami" in shown
    assert "/10" not in shown
    assert pagetext.view("var a=1;", "http://h.test/a.js", "application/javascript") == ("var a=1;", "raw")
    assert pagetext.view('{"a": 1}', "http://h.test/api", "application/json") == ('{"a": 1}', "raw")
    assert pagetext.view("<p>short</p>", "http://h.test/", "text/html") == ("<p>short</p>", "raw")
