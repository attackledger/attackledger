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
