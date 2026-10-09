import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.triage import rank, score_host


def p(status, title="", tech=(), port=443):
    return {"status_code": status, "title": title, "tech": list(tech), "port": port}


def test_admin_login_behind_auth_scores_high():
    r = score_host("admin.example.com", [p(401, "Admin Login", ["Nginx:1.25", "PHP"])])
    assert r["signals"] == ["AUTH", "TITLE", "APPTECH", "KEYWORD"]
    assert r["score"] == 11 and r["golden"]


def test_waf_403_is_not_auth():
    r = score_host("www.example.com", [p(403, "Attention Required! | Cloudflare", ["Cloudflare"])])
    assert "AUTH" not in r["signals"] and "WAF" in r["signals"]
    assert "APPTECH" not in r["signals"]          # CDN/edge tech is noise
    assert not r["golden"]


def test_odd_port_and_plain_200():
    r = score_host("static.example.com", [p(200, "Welcome", [], 8443)])
    assert r["signals"] == ["ODDPORT", "200"] and r["score"] == 2


def test_rank_orders_by_score_then_host():
    rows = rank({
        "b.example.com": [p(200)],
        "a.example.com": [p(200)],
        "api.example.com": [p(401, "Swagger UI")],
        "dead.example.com": [],
    })
    assert [r["host"] for r in rows] == ["api.example.com", "a.example.com", "b.example.com"]


def test_a_single_page_app_with_an_api_reaches_golden():
    spa = [p(200, "OWASP Juice Shop", [], 3000)]
    before = score_host("juice.lab.test", spa)
    assert before["signals"] == ["ODDPORT", "KEYWORD", "200"] and not before["golden"]
    after = score_host("juice.lab.test", spa, api_shapes=12)
    assert after["signals"][-1] == "API" and after["score"] == 5 and after["golden"]


def test_one_or_two_api_paths_do_not_count_and_api_alone_is_not_golden():
    assert "API" not in score_host("www.example.com", [p(200)], api_shapes=2)["signals"]
    r = score_host("www.example.com", [p(200)], api_shapes=40)
    assert r["score"] == 3 and not r["golden"]                     # 200 + API: still below 4


def test_rank_passes_api_shapes_per_host():
    rows = rank({"a.example.com": [p(200, port=8080)], "b.example.com": [p(200, port=8080)]},
                api_shapes={"b.example.com": 3})
    assert [r["host"] for r in rows] == ["b.example.com", "a.example.com"] and rows[0]["golden"]


def test_api_shapes_collapse_identifiers_and_ignore_junk():
    from app.surface import api_shapes
    assert api_shapes(["https://a/api/Products/1", "https://a/api/Products/2", "https://a/api/Users",
                       "https://a/rest/x?y=1", "https://a/api/%60junk%60", "https://a/about"]) == \
        {"/api/Products/{id}", "/api/Users", "/rest/x"}
