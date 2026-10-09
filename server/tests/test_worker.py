import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "server"))
spec = importlib.util.spec_from_file_location("worker", ROOT / "worker" / "worker.py")
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


def eng(header=None, ua=None, rps=5, ports=False, depth=3):
    return SimpleNamespace(research_header=header, research_user_agent=ua, rate_limit_rps=rps,
                           enabled_modules=["ports"] if ports else [], crawl_depth=depth)


def cmd(kind, e):
    return worker.commands(kind, e)[0][1]


def test_probe_adds_identification_headers_and_never_follows_redirects():
    c = cmd("probe", eng("X-Bug-Bounty: r1", "Mozilla/5.0 (r1)"))
    assert c[c.index("-H") + 1] == "X-Bug-Bounty: r1"
    assert "User-Agent: Mozilla/5.0 (r1)" in c
    assert "-follow-redirects" not in c and "-fr" not in c


@pytest.mark.parametrize("kind", ["probe", "crawl"])
def test_target_traffic_refuses_without_identification(kind):
    with pytest.raises(RuntimeError, match="research header"):
        worker.commands(kind, eng())


def test_crawl_stays_on_host_skips_destructive_paths_and_identifies():
    c = cmd("crawl", eng("X-Bug-Bounty: r1", depth=2))
    assert c[c.index("-fs") + 1] == "fqdn"
    assert "logout" in c[c.index("-cos") + 1] and "/delete" in c[c.index("-cos") + 1]
    assert c[c.index("-d") + 1] == "2" and "X-Bug-Bounty: r1" in c


def test_port_scan_needs_engagement_permission_and_skips_smtp():
    with pytest.raises(RuntimeError, match="not allowed"):
        worker.commands("ports", eng())
    c = cmd("ports", eng(ports=True, rps=3))
    assert c[c.index("-exclude-ports") + 1] == "25" and c[c.index("-scan-type") + 1] == "c"
    assert c[c.index("-rate") + 1] == "3"       # the engagement limit, never a multiple of it
    assert c[c.index("-c") + 1] == "3"


def test_passive_kinds_need_no_identification():
    names = [n for n, _ in worker.commands("subdomains", eng())]
    assert names == ["subfinder", "assetfinder"]
    assert [n for n, _ in worker.commands("archive", eng())] == ["gau", "wayback"]
    passes = worker.commands("resolve", eng(rps=3))
    assert [n for n, _ in passes] == ["dnsx", "dnsx-cname"]
    assert "-cname" not in passes[0][1] and "-cname" in passes[1][1] and passes[0][1][-1] == "3"


def test_parse_probe_strips_port_from_host():
    host, data = worker.parse_probe({"input": "app.example.com:8443", "url": "https://app.example.com:8443",
                                     "port": "8443", "status_code": 200, "tech": ["nginx"]})
    assert host == "app.example.com" and data["live"] and data["port"] == "8443"


def test_resolvers_are_passed_to_dns_tools(monkeypatch):
    monkeypatch.setattr(worker, "RESOLVERS", "127.0.0.11")
    assert cmd("resolve", eng())[cmd("resolve", eng()).index("-r") + 1] == "127.0.0.11"
    c = cmd("ports", eng(ports=True))
    assert c[c.index("-r") + 1] == "127.0.0.11"


def test_js_fetcher_requires_identification():
    with pytest.raises(RuntimeError, match="research header"):
        worker.fetcher(eng())


def test_js_fetcher_refuses_redirects():
    handler = worker._NoRedirect()
    assert handler.redirect_request(None, None, 302, "Found", {}, "https://evil.test/") is None


@pytest.mark.parametrize("rps", [1, 5, 50])
def test_no_step_exceeds_the_engagement_rate_limit(rps):
    e = eng("X-Bug-Bounty: r1", ports=True, rps=rps)
    for kind in ("resolve", "ports", "probe", "crawl"):
        for _, c in worker.commands(kind, e):
            flag = "-rate" if "-rate" in c else "-rl"
            assert int(c[c.index(flag) + 1]) <= rps, (kind, c)


# ---- batching, time limit and partial runs -----------------------------------

from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import db
from app.models import Engagement, Job, JobStatus


@pytest.fixture()
def session():
    eng_ = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    db.Base.metadata.create_all(eng_)
    s = sessionmaker(bind=eng_, expire_on_commit=False)()
    yield s
    s.close()


def make_job(s, targets, kind="resolve"):
    e = Engagement(name="t", scope_include=["*.example.com"], scope_exclude=[],
                   authorized_by="op", authorized_at=datetime.now(timezone.utc))
    s.add(e)
    s.commit()
    j = Job(engagement_id=e.id, kind=kind, targets=targets, status=JobStatus.running)
    s.add(j)
    s.commit()
    return j


def test_watchdog_stops_a_silent_tool(session, monkeypatch):
    monkeypatch.setattr(worker, "JOB_TIMEOUT", 1)
    r = worker.Run(session, make_job(session, ["a.example.com"]))
    t0 = __import__("time").monotonic()
    with pytest.raises(worker.Cancelled, match="timed out"):
        list(r.tool_lines("sleep", ["sleep", "30"], []))
    assert __import__("time").monotonic() - t0 < 5


def test_time_limit_marks_remaining_targets(session, monkeypatch):
    targets = [f"h{i}.example.com" for i in range(7)]
    job = make_job(session, targets)
    calls = []

    def fake_runner(r, chunk):
        calls.append(chunk)
        if len(calls) == 3:
            raise worker.Cancelled("timed out")
        return len(chunk)

    monkeypatch.setattr(worker, "CHUNK_SIZE", 3)
    monkeypatch.setitem(worker.RUNNERS, "resolve", fake_runner)
    r = worker.run(session, job)
    assert r.stopped == "timed out"
    assert job.targets_done == 6 and job.result_count == 6
    assert job.remaining_targets == ["h6.example.com"]   # the interrupted batch is not counted


def test_complete_run_has_no_remaining_targets(session, monkeypatch):
    job = make_job(session, ["a.example.com", "b.example.com"])
    monkeypatch.setitem(worker.RUNNERS, "resolve", lambda r, chunk: len(chunk))
    r = worker.run(session, job)
    assert r.stopped is None and job.targets_done == 2 and job.remaining_targets is None


def test_worker_runners_match_the_module_registry():
    worker.check_registry()   # raises SystemExit on any mismatch


def test_worker_rechecks_gates_at_run_time(session):
    job = make_job(session, ["a.example.com"], kind="ports")   # port scanning not enabled
    with pytest.raises(RuntimeError, match="off for this engagement"):
        worker.run(session, job)


def test_target_limit_lists_the_overflow_as_remaining(session, monkeypatch):
    urls_ = [f"https://app.example.com/js/{i:03d}.js" for i in range(260)]
    job = make_job(session, urls_, kind="jsanalyze")
    job.engagement.research_header = "X-Bug-Bounty: r1"
    session.commit()
    seen = []
    monkeypatch.setitem(worker.RUNNERS, "jsanalyze", lambda r, chunk: seen.extend(chunk) or len(chunk))
    r = worker.run(session, job)
    assert r.stopped == "target limit"
    assert len(seen) == 250 and job.targets_done == 250
    assert job.remaining_targets == urls_[250:]          # nothing dropped silently


def test_deferred_job_resolves_targets_at_run_time(session, monkeypatch):
    job = make_job(session, [], kind="resolve")
    job.deferred = True
    from app.models import Asset
    session.add(Asset(engagement_id=job.engagement_id, host="app.example.com", in_scope=True))
    session.commit()
    seen = []
    monkeypatch.setitem(worker.RUNNERS, "resolve", lambda r, chunk: seen.extend(chunk) or len(chunk))
    worker.run(session, job)
    assert job.targets == ["app.example.com"] and seen == ["app.example.com"]


def test_deferred_job_with_nothing_to_do_is_skipped(session):
    job = make_job(session, [], kind="crawl")
    job.deferred = True
    job.engagement.research_header = "X-Bug-Bounty: r1"
    session.commit()
    r = worker.run(session, job)
    assert r.skipped and "nothing to run" in job.log and "Find live web servers" in job.log
    assert job.result == {"skipped_reason": "no live web servers from 'Find live web servers'"}
    assert worker.final_status(r) == JobStatus.skipped and job.output_sha256 is None


def test_deferred_root_step_without_a_wildcard_is_skipped(session):
    job = make_job(session, [], kind="archive")
    job.deferred = True
    job.engagement.scope_include = ["shop.example.com"]
    session.commit()
    r = worker.run(session, job)
    assert worker.final_status(r) == JobStatus.skipped and "wildcard" in job.result["skipped_reason"]


def test_final_status_of_a_run(session, monkeypatch):
    job = make_job(session, ["a.example.com"])
    monkeypatch.setitem(worker.RUNNERS, "resolve", lambda r, chunk: 0)
    r = worker.run(session, job)
    assert worker.final_status(r) == JobStatus.done and job.result is None   # ran, found nothing
    r.stopped = "timed out"
    assert worker.final_status(r) == JobStatus.partial


def test_noerror_without_records_is_not_resolved(session, monkeypatch):
    job = make_job(session, ["real.example.com", "ghost.example.com"])
    r = worker.Run(session, job)
    lines = {
        "dnsx": ['{"host":"real.example.com","a":["192.0.2.1"],"status_code":"NOERROR"}',
                 '{"host":"ghost.example.com","status_code":"NOERROR"}'],
        "dnsx-cname": ['{"host":"ghost.example.com","cname":["x.example.net"]}'],
    }
    monkeypatch.setattr(worker.Run, "tool_lines", lambda self, name, cmd, inp: iter(lines[name]))
    out = worker.resolve_hosts(r, ["real.example.com", "ghost.example.com"])
    assert list(out) == ["real.example.com"]


@pytest.fixture()
def nuclei_exclude(tmp_path, monkeypatch):
    f = tmp_path / "exclude.txt"
    f.write_text("/opt/nuclei-templates/http/x.yaml\n")
    monkeypatch.setattr(worker, "NUCLEI_EXCLUDE_FILE", str(f))
    return f


def test_nuclei_refuses_without_exclusion_list(monkeypatch):
    monkeypatch.setattr(worker, "NUCLEI_EXCLUDE_FILE", "/nonexistent")
    with pytest.raises(RuntimeError, match="exclusion list"):
        worker.nuclei_cmd(eng("X-Bug-Bounty: r1"))


def test_nuclei_command_is_safe_by_construction(nuclei_exclude):
    c = worker.nuclei_cmd(eng("X-Bug-Bounty: r1", rps=3), worker._tpl("exposures"))
    assert "-ni" in c and "-dr" in c                     # no OOB callbacks, no redirects
    assert c[c.index("-et") + 1] == str(nuclei_exclude)  # every template not provably read-only
    for t in ("dos", "fuzz", "intrusive", "instrusive", "default-login", "credential-stuffing", "token-spray"):
        assert t in c[c.index("-etags") + 1].split(",")
    assert "X-Bug-Bounty: r1" in c
    assert c[c.index("-severity") + 1] == "medium,high,critical"
    paths = [c[i + 1] for i, x in enumerate(c) if x == "-t"]
    for p in paths:
        for banned in ("default-logins", "credential-stuffing", "token-spray", "fuzzing"):
            assert f"/{banned}/" not in p


@pytest.mark.parametrize("rps,tick_ms", [(2, 1050), (3, 525), (5, 263), (20, 56), (100, 11)])
def test_nuclei_pacing_is_one_request_per_tick(nuclei_exclude, rps, tick_ms):
    c = worker.nuclei_cmd(eng("X-Bug-Bounty: r1", rps=rps))
    assert c[c.index("-rl") + 1] == "1" and c[c.index("-rld") + 1] == f"{tick_ms}ms"
    assert c[c.index("-retries") + 1] == "0"
    # A window holds at most one request per tick inside it plus one refilled just before it.
    ticks_in_window = -(-1000 // tick_ms)
    assert ticks_in_window + 1 <= rps


def test_nuclei_refuses_limits_it_cannot_keep(nuclei_exclude):
    with pytest.raises(RuntimeError, match="at least 2"):
        worker.nuclei_cmd(eng("X-Bug-Bounty: r1", rps=1))
    from app import jobgates
    e = SimpleNamespace(authorized_at=1, scope_include=["*.x.test"], enabled_modules=["nuclei"], rate_limit_rps=1,
                        research_header="X-Bug-Bounty: r1", research_user_agent=None)
    with pytest.raises(jobgates.GateError, match="at least 2"):
        jobgates.check_engagement(e, "nuclei")


def test_nuclei_templates_are_reverified_before_the_first_scan(tmp_path, monkeypatch):
    root = tmp_path / "t" / "http"
    root.mkdir(parents=True)
    (root / "post.yaml").write_text("id: p\ninfo: {name: p}\nhttp:\n  - method: POST\n    path: ['{{BaseURL}}/']\n")
    (root / "get.yaml").write_text("id: g\ninfo: {name: g}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/']\n")
    listed = tmp_path / "exclude.txt"
    listed.write_text(str(tmp_path / "t" / "http" / "other.yaml") + "\n")   # misses post.yaml
    monkeypatch.setattr(worker, "NUCLEI_TEMPLATES", str(tmp_path / "t"))
    monkeypatch.setattr(worker, "NUCLEI_EXCLUDE_FILE", str(listed))
    worker._verified.clear()
    with pytest.raises(RuntimeError, match="not provably read-only"):
        worker.verify_nuclei_templates()
    listed.write_text(str(root / "post.yaml") + "\n")
    assert worker.verify_nuclei_templates() == {"safe": 1, "excluded": 1}
    worker._verified.clear()


def test_run_nuclei_verifies_templates_before_any_request(monkeypatch):
    def refuse():
        raise RuntimeError("not provably read-only")
    monkeypatch.setattr(worker, "verify_nuclei_templates", refuse)
    sent = []
    r = SimpleNamespace(tool_lines=lambda *a: sent.append(a) or iter(()), log=lambda line: None)
    with pytest.raises(RuntimeError, match="not provably read-only"):
        worker.run_nuclei(r, ["http://a.x.test/"])
    assert sent == []


def test_nuclei_passes_never_share_a_second(monkeypatch, nuclei_exclude):
    sleeps, passes = [], []
    monkeypatch.setattr(worker.time, "sleep", sleeps.append)
    u = "http://a.x.test/"
    r = SimpleNamespace(eng=eng("X-Bug-Bounty: r1", rps=20), in_scope=lambda h: True, log=lambda line: None,
                        nuclei_plan={"reps": {u}, "golden": {u}, "tags": {u: {"nginx"}}},
                        tool_lines=lambda name, cmd, inputs: passes.append(name) or iter(()))
    worker.run_nuclei(r, [u])
    worker.run_nuclei(r, [u])        # the next target batch
    assert passes == ["nuclei-takeovers", "nuclei-generic", "nuclei-stack", "nuclei-golden"] * 2
    assert sleeps == [worker.NUCLEI_PASS_GAP] * 7 and worker.NUCLEI_PASS_GAP > 1


def test_nuclei_refuses_without_identification():
    with pytest.raises(RuntimeError, match="research header"):
        worker.nuclei_cmd(eng())


def test_nuclei_template_paths_exist_in_the_pinned_layout():
    # The original pipeline used http/cve/ (no such directory); the templates use http/cves/.
    assert worker._tpl("cves")[0].endswith("/http/cves/")


def test_ferox_stays_within_the_rate_limit_and_skips_destructive_paths(monkeypatch, tmp_path):
    c = worker.ferox_cmd(eng("X-Bug-Bounty: r1", "AL (r1)", rps=4))
    assert c[c.index("--scan-limit") + 1] == "1" and c[c.index("--depth") + 1] == "1"   # one scan per process
    # Two unthrottled start requests per scan, so ferox gets the limit minus two.
    assert c[c.index("--rate-limit") + 1] == "2" and "--dont-filter" in c
    assert "--dont-extract-links" in c and "-r" not in c and "--redirects" not in c
    assert "logout" in c[c.index("--dont-scan") + 1]
    assert c[c.index("-H") + 1] == "X-Bug-Bounty: r1" and c[c.index("-a") + 1] == "AL (r1)"


def test_ferox_refuses_limits_it_cannot_keep():
    with pytest.raises(RuntimeError, match="at least 3"):
        worker.ferox_cmd(eng("X-Bug-Bounty: r1", rps=2))
    from app import jobgates, modules
    e = SimpleNamespace(authorized_at=1, scope_include=["*.x.test"], enabled_modules=["content"], rate_limit_rps=2,
                        research_header="X-Bug-Bounty: r1", research_user_agent=None)
    with pytest.raises(jobgates.GateError, match="at least 3"):
        jobgates.check_engagement(e, "content")
    e.rate_limit_rps = 3
    assert jobgates.check_engagement(e, "content") is modules.get("content")


def test_ferox_refuses_without_identification():
    with pytest.raises(RuntimeError, match="research header"):
        worker.ferox_cmd(eng())


def test_content_baseline_skips_catch_all_hosts():
    assert worker.baseline_status(lambda u: "403", "https://a.example.com/") == ("403", "403")
    codes = iter(["404", "404"])
    assert worker.baseline_status(lambda u: next(codes), "https://a.example.com/") == ("404", "404")


def test_arjun_command_identifies_and_rate_limits():
    c = worker.arjun_cmd(eng("X-Bug-Bounty: r1", "AL (r1)", rps=3), "https://a.example.com/p.php", "/tmp/o.json")
    assert c[c.index("--rate-limit") + 1] == "3" and c[c.index("-t") + 1] == "1"
    assert c[c.index("-d") + 1] == "0.333"
    assert c[c.index("--headers") + 1] == "X-Bug-Bounty: r1\nUser-Agent: AL (r1)"
    with pytest.raises(RuntimeError, match="research header"):
        worker.arjun_cmd(eng(), "https://a.example.com/", "/tmp/o.json")
