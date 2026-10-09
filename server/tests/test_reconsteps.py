"""Well-known files and content discovery on single-page apps (app/reconsteps.py), run through
the worker's own helpers against a fake site: no network."""
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from harness import stack  # noqa: F401

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "server"))
import app.reconsteps  # noqa: E402,F401 - this tree's app package, before the worker adds /srv to the path
spec = importlib.util.spec_from_file_location("worker_reconsteps", ROOT / "worker" / "worker.py")
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)

from app import db, egress, reconsteps, targets  # noqa: E402
from app.models import Endpoint, Engagement, Job, JobStatus, Lead  # noqa: E402

BASE = "http://shop.example.com:3000"
INDEX = b"<!doctype html><html><head><title>Shop</title></head><body><app-root></app-root></body></html>"
LISTING = (b"<html><head><title>listing directory /ftp</title><style>" + b"a{color:red}" * 500 +
           b"</style></head><body><a href='ftp/acquisitions.md'>acquisitions.md</a>"
           b"<a href='ftp/eastere.gg'>eastere.gg</a></body></html>")


@pytest.fixture()
def session():
    eng_ = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    db.Base.metadata.create_all(eng_)
    s = sessionmaker(bind=eng_, expire_on_commit=False)()
    yield s
    s.close()


class Site:
    """GET-only fake target: path -> (status, body); anything else is the catch-all."""

    def __init__(self, pages, catch_all=(200, INDEX)):
        self.pages, self.catch_all, self.requested = pages, catch_all, []

    def fetcher(self, eng, gw=None, tool_name="fetch"):
        worker.require_identification(eng)          # the same refusal as the real fetcher

        def get(url):
            path = url.removeprefix(BASE) or "/"
            self.requested.append(path)
            status, body = self.pages.get(path, self.catch_all)
            return (body, "") if status == 200 else (None, f"HTTP {status}")
        return get


def run_for(stack, kind, monkeypatch, site, ferox_lines=(), header="X-Bug-Bounty: r1"):
    """A job claimed from the API (D-042) and run with a fake site; what the API stored."""
    e = stack.engagement(name=f"t-{kind}", exclude=("out.example.com",), rps=20, header=header,
                         modules=("content",))
    stack.queue(e, kind, [BASE])
    job = stack.claim()
    monkeypatch.setattr(worker, "fetcher", site.fetcher)
    monkeypatch.setattr(reconsteps.time, "sleep", lambda s: None)
    r = worker.Run(job, egress.Egress(job.id, "s3cret-value-0123456789"))
    commands = []

    def tool_lines(name, cmd, stdin):
        commands.append((name, cmd, stdin))
        yield from (json.dumps(x) for x in ferox_lines)
    r.tool_lines = tool_lines
    count = worker.RUNNERS[kind](r, [BASE])
    r.flush()
    with stack.Session() as s:
        eps = {x.url.removeprefix(BASE): x.source for x in s.scalars(select(Endpoint))}
        leads = {l.kind: l for l in s.scalars(select(Lead))}
    r.job.log_text = stack.job(job.id).log
    return count, commands, eps, leads, r


def ferox(path, status, length, words=10, lines=3):
    return {"type": "response", "url": BASE + path, "status": status, "content_length": length,
            "word_count": words, "line_count": lines}


def test_the_worker_uses_these_runners():
    assert worker.RUNNERS["content"].func is reconsteps.run_content
    assert worker.RUNNERS["wellknown"].func is reconsteps.run_wellknown
    worker.check_registry()


def test_catch_all_decisions():
    fp = lambda status, length=0, words=0, lines=0: {"status": status, "length": length, "words": words,  # noqa: E731
                                                     "lines": lines, "title": "App"}
    assert reconsteps.catch_all_filter([fp("404"), fp("404")]) == {}
    assert reconsteps.catch_all_filter([fp("200", 10), fp("404")]) == {}
    assert reconsteps.catch_all_filter([fp("403"), fp("403")]) == {"skip": "every path answers 403"}
    assert reconsteps.catch_all_filter([fp("200", 9393, 50), fp("200", 9393, 50)]) == {"size": 9393, "title": "App"}
    # A page that echoes the path changes size but not its word count.
    assert reconsteps.catch_all_filter([fp("200", 100, 7, 2), fp("200", 104, 7, 2)]) == {"words": 7, "title": "App"}
    assert "skip" in reconsteps.catch_all_filter([fp("200", 100, 7, 2), fp("200", 140, 9, 3)])


def test_content_discovery_runs_on_an_spa_and_drops_the_catch_all_page(stack, monkeypatch):
    site = Site({"/ftp": (200, LISTING)})
    lines = [ferox("/zzz", 200, len(INDEX)),            # the catch-all, had feroxbuster let it through
             ferox("/ftp", 200, len(LISTING)), ferox("/api-docs", 301, 0), ferox("/support", 403, 50)]
    count, commands, eps, leads, r = run_for(stack, "content", monkeypatch, site, lines)
    (_, cmd, stdin), = commands
    assert cmd[cmd.index("--filter-size") + 1] == str(len(INDEX)) and stdin == [BASE]
    assert "X-Bug-Bounty: r1" in cmd and "--dont-scan" in cmd           # the worker's own ferox flags
    assert eps == {"/ftp": "ferox-200,listing", "/api-docs": "ferox-301", "/support": "ferox-403",
                   "/ftp/acquisitions.md": "listing", "/ftp/eastere.gg": "listing"}
    assert leads["listing"].title == "Directory listing at /ftp: 2 entries: acquisitions.md, eastere.gg"
    assert leads["listing"].detail["entries"] == ["acquisitions.md", "eastere.gg"]
    # Two baseline paths and one listing check, through the worker's fetcher; the files are not fetched.
    assert len(site.requested) == 3 and site.requested[2] == "/ftp"
    assert "filtering it out by size" in r.job.log_text


def test_a_host_that_answers_every_path_with_an_error_is_still_skipped(stack, monkeypatch):
    count, commands, eps, leads, r = run_for(stack, "content", monkeypatch, Site({}, catch_all=(403, b"")))
    assert count == 0 and commands == [] and eps == {} and "every path answers 403" in r.job.log_text


def test_wellknown_records_robots_security_txt_and_listings(stack, monkeypatch):
    site = Site({
        "/robots.txt": (200, b"User-agent: *\nDisallow: /ftp\nDisallow: /logout\nDisallow: /private/*\n"
                             b"Sitemap: https://out.example.com/s.xml\n"),
        "/.well-known/security.txt": (200, b"Contact: mailto:sec@example.com\nAcknowledgements: /#/score-board\n"
                                           b"Csaf: http://localhost:3000/csaf.json\n"),
        "/ftp": (200, LISTING)})
    count, commands, eps, leads, r = run_for(stack, "wellknown", monkeypatch, site)
    assert commands == []                                                 # no external tool
    assert site.requested == ["/robots.txt", "/.well-known/security.txt", "/ftp"]   # /logout never requested
    assert eps == {"/robots.txt": "robots", "/ftp": "listing,robots", "/.well-known/security.txt": "security.txt",
                   "/#/score-board": "security.txt", "/ftp/acquisitions.md": "listing",
                   "/ftp/eastere.gg": "listing"}                         # no /logout, no other host
    assert leads["robots"].title == "robots.txt: 3 disallowed paths: /ftp, /logout, /private/*"
    assert leads["security-txt"].title == "security.txt at /.well-known/security.txt: contact mailto:sec@example.com"
    assert leads["listing"].source_url == BASE + "/ftp"
    assert count == 3 + len(eps)


def test_wellknown_on_an_spa_takes_the_index_page_for_nothing(stack, monkeypatch):
    site = Site({})
    count, commands, eps, leads, r = run_for(stack, "wellknown", monkeypatch, site)
    assert count == 0 and eps == {} and leads == {}
    assert site.requested == ["/robots.txt", "/.well-known/security.txt", "/security.txt"]


def test_wellknown_needs_identification(stack, monkeypatch):
    site = Site({})
    e = stack.engagement(name="t-noident", header=None)
    j = stack.queue(e, "wellknown", [BASE])
    assert stack.claim() is None                     # the API's gate, when the job is claimed
    assert "research header" in stack.job(j).log
    spec = {"id": 1, "kind": "wellknown", "token": "t", "gateway_secret": "s3cret-value-0123456789",
            "targets": [BASE], "engagement": {"id": e, "scope_include": ["*.example.com"], "scope_exclude": [],
                                              "rate_limit_rps": 5, "research_header": None,
                                              "research_user_agent": None, "crawl_depth": 3, "enabled_modules": []}}
    from app import workerclient
    r = worker.Run(workerclient.JobChannel(stack.client, spec))
    monkeypatch.setattr(worker, "fetcher", site.fetcher)
    with pytest.raises(RuntimeError, match="research header"):  # and the worker's own refusal
        worker.RUNNERS["wellknown"](r, [BASE])
    assert site.requested == []


def test_recorded_files_and_routes_are_never_parameter_targets(session):
    e = Engagement(name="t", scope_include=["*.example.com"], authorized_by="op",
                   authorized_at=datetime.now(timezone.utc))
    session.add(e)
    session.commit()
    job = Job(engagement_id=e.id, kind="crawl", targets=[], status=JobStatus.done)
    session.add(job)
    session.commit()
    for i, u in enumerate([BASE + "/#/search?q=x", BASE + "/uploads/a.jpg?v=1", BASE + "/api/items"]):
        session.add(Endpoint(engagement_id=e.id, job_id=job.id, host="shop.example.com", url=u,
                             url_sha256=f"{i:064d}", source="t"))
    session.commit()
    assert targets.dynamic_endpoints(session, e) == [BASE + "/api/items"]
