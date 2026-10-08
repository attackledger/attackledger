import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import passive


def test_parameters_route_to_the_lane_that_tests_them():
    rows = passive.route({"https://a.example.com/p?url=x&id=1&x=2": ["url", "id", "x"],
                          "https://a.example.com/q?next=/": ["next"]})
    by = {(r["class"], r["param"]): r for r in rows}
    assert by[("ssrf", "url")]["lane"] == "injection"
    assert by[("idor", "id")]["lane"] == "authz" and by[("sqli", "id")]["lane"] == "injection"
    assert by[("redirect", "next")]["lane"] == "authflow"
    assert not any(r["param"] == "x" for r in rows)


def test_params_of_and_dorks():
    assert passive.params_of("https://a.example.com/s?q=1&page=2") == ["page", "q"]
    d = passive.dorks_for("example.com")
    assert len(d) == len(passive.DORKS) and d[0]["url"].startswith("https://www.google.com/search?q=site%3Aexample.com")
