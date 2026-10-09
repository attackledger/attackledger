"""Ranking recon endpoints for an agent: junk out, shapes collapsed, signal first."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import surface

B = "http://juice.lab.test:3000"


def ep(path, source="katana", js=False):
    return {"url": B + path, "source": source, "js": js}


def test_junk_from_bundles_is_recognised():
    junk = ["/%60+_%28i%5B11%5D%7C%7Cf%5Bg.toLowerCase%28%29%5D%29+%60", "/%7B%7Bhref%7D%7D", "/10", "/0/0",
            "/bQ", "/pQ6q2dQ7s4aQ9W6rT=m", "/application/vnd.ms-word.do", "/%5C/index%5C.html"]
    real = ["/", "/api/Users", "/rest/user/whoami", "/ftp/eastere.gg%2500.md", "/odata/$metadata",
            "/assets/public/images/uploads/%F0%9F%98%BC-%23zatschi-1.jpg", "/#/score-board", "/v1"]
    assert [p for p in junk if not surface.is_junk(B + p)] == []
    assert [p for p in real if surface.is_junk(B + p)] == []


def test_shapes_collapse_identifiers_values_and_trailing_slashes():
    assert surface.shape(B + "/api/Products/42") == "/api/Products/{id}"
    assert surface.shape(B + "/api/Challenges/?key=abc&x=1") == "/api/Challenges?key&x"
    assert surface.shape(B + "/api/Challenges") == surface.shape(B + "/api/Challenges/")
    assert surface.shape(B + "/u/3f2b1c7e-8d9a-4b6c-9e1f-0a2b3c4d5e6f") == "/u/{id}"
    assert surface.shape(B + "/#/address/edit/:addressId") == "/#/address/edit/{id}"


def test_ranking_puts_signal_first_not_the_alphabet():
    eps = [ep(p) for p in ("/%60x%60", "/10", "/16", "/about", "/accounting", "/api/Users", "/api/Products/1",
                           "/api/Products/2", "/metrics", "/rest/admin/application-configuration")]
    eps += [ep("/ftp", "ferox-200"), ep("/support", "ferox-403"), ep("/main.js", js=True),
            ep("/#/score-board", "js"), ep("/#/administration", "js")]
    leads = [{"kind": "nuclei", "source_url": B + "/metrics", "detail": {}},
             {"kind": "param-class", "source_url": B + "/api/Users", "detail": {"lane": "authz", "urls": []}}]
    r = surface.rank_endpoints(eps, leads, lane_role="authz", limit=5)
    urls = [e["url"].removeprefix(B) for e in r["endpoints"]]
    assert urls[0] == "/api/Users"                                     # API + lead + routed to this lane
    # /ftp (sensitive name, seen by content discovery) outranks /support (a 403 only).
    assert set(urls) == {"/api/Users", "/rest/admin/application-configuration", "/metrics", "/api/Products/1",
                         "/ftp"}
    products = next(e for e in r["endpoints"] if e["shape"] == "/api/Products/{id}")
    assert products["count"] == 2                                      # two URLs, one entry
    assert r["junk_dropped"] == 3 and r["total"] == len(eps) and r["omitted"] == r["shapes"] - 5
    # Client routes are listed on their own and never compete with server paths.
    assert r["routes"] == [B + "/#/administration", B + "/#/score-board"]


def test_breadth_keeps_one_prefix_from_crowding_out_the_rest():
    eps = [ep(f"/api/Thing{n}") for n in range(30)] + [ep("/ftp", "ferox-200"), ep("/encryptionkeys")]
    picked = [e["url"].removeprefix(B) for e in surface.rank_endpoints(eps, limit=20)["endpoints"]]
    assert "/encryptionkeys" in picked and "/ftp" in picked


def test_status_and_file_signals():
    assert surface.score(B + "/admin", "ferox-401")[1] == ["KEYWORD", "STATUS"]
    assert "FILE" in surface.score(B + "/ftp/package.json.bak", "listing")[1]
    assert surface.status_of("katana,ferox-500") == 500 and surface.status_of("js") is None
