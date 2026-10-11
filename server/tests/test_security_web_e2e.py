"""Server-side regressions for what the browser end-to-end tests found
(docs/security-review/WEB_E2E.md). The browser tests (e2e/, tools/test_e2e.sh) cover the same
cases in Chromium and Firefox; these run with the rest of the server suite."""
import sys
from pathlib import Path
from urllib.parse import unquote

import pytest
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import stack  # noqa: E402,F401
from test_ledger import client  # noqa: E402,F401  (fixture)

from app.models import Observation  # noqa: E402


# ---- WE-1: a report download for a name outside Latin-1 ------------------------------------------

@pytest.mark.parametrize("name", ["Müşteri portalı", "عربي", "東京 pentest", "Café ‮exe.txt"])
@pytest.mark.parametrize("path", ["report", "report.html"])
def test_we1_a_report_downloads_whatever_script_its_name_is_in(client, name, path):
    eng = client.post("/engagements", json={"name": name}).json()["id"]
    r = client.get(f"/engagements/{eng}/{path}?download=true")
    assert r.status_code == 200, r.text
    disposition = r.headers["content-disposition"]
    disposition.encode("ascii")                         # the header itself is plain ASCII
    assert disposition.startswith('attachment; filename="attackledger-')
    utf8 = disposition.split("filename*=UTF-8''", 1)[1]
    ext = "json" if path == "report" else "html"
    # The name the web app gives the same download (Report.tsx reportFilename): letters kept.
    slug = "".join(ch if ch.isalnum() else "-" for ch in name.lower()).strip("-")
    assert unquote(utf8) == f"attackledger-{slug}-{eng}.{ext}"
    plain = disposition.split('filename="', 1)[1].split('"', 1)[0]
    assert plain.isascii() and plain.endswith(f"-{eng}.{ext}")


def test_we1_an_ascii_name_downloads_as_before(client):
    eng = client.post("/engagements", json={"name": "Client web app"}).json()["id"]
    r = client.get(f"/engagements/{eng}/report?download=true")
    assert r.headers["content-disposition"] == (
        f"attachment; filename=\"attackledger-client-web-app-{eng}.json\"; "
        f"filename*=UTF-8''attackledger-client-web-app-{eng}.json")


# ---- WE-2: a probe URL that is not an http(s) URL of the probed host -------------------------------

def test_we2_a_probe_url_must_be_an_http_url_of_the_host_it_probed(stack):
    e = stack.engagement(name="probe")
    stack.queue(e, "probe", ["a.example.com"])
    job = stack.claim()
    bad = ["javascript:alert(document.domain)//", "JavaScript://a.example.com/%0aalert(1)",
           "data:text/html,<script>alert(1)</script>", "https://b.example.com/", "//a.example.com/", 42]
    out = job.results(observations=[{"host": "a.example.com", "data": {"url": u, "title": "x", "live": True}} for u in bad]
                      + [{"host": "a.example.com", "data": {"url": "https://a.example.com:8443/", "live": True}},
                         {"host": "a.example.com", "data": {"url": None, "live": False}}])
    assert out["observations"] == 2 and out["refused"] == len(bad)
    with stack.Session() as s:
        assert [o.data.get("url") for o in s.scalars(select(Observation).order_by(Observation.id))] == [
            "https://a.example.com:8443/", None]
