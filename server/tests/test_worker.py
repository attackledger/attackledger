from types import SimpleNamespace

import pytest

from harness import load_worker, stack  # noqa: F401

worker = load_worker()


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
    probes = []

    class Gw:
        def probe(self, host, port):
            probes.append((host, port))
            return (200, "open") if port in (80, 443) else (502, "closed")
    logs = []
    r = SimpleNamespace(eng=eng(rps=3), gw=Gw(), in_scope=lambda h: h.endswith(".example.com"),
                        digest=__import__("hashlib").sha256(), log=logs.append, check_stop=lambda: None,
                        fetch_failures=0, observed={}, observe=lambda h, d: r.observed.update({h: d}))
    with pytest.raises(RuntimeError, match="not allowed"):
        worker.run_ports(r, ["a.example.com"])
    r.eng = eng(ports=True, rps=3)
    assert worker.run_ports(r, ["a.example.com", "out.other.test"]) == 1
    assert {h for h, _ in probes} == {"a.example.com"}           # out of scope: never probed
    assert len(probes) == 99 and 25 not in {p for _, p in probes}  # nmap's top 100 without SMTP
    assert r.observed == {"a.example.com": {"open_ports": [80, 443]}}


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


def test_every_tool_is_pointed_at_the_gateway(monkeypatch):
    from app import egress
    gw = egress.Egress(7, "s3cret-value-0123456789")
    monkeypatch.setattr(egress.Egress, "resolver", lambda self: "10.0.0.9:53")
    proxy = lambda t: f"http://job-7.{t}:s3cret-value-0123456789@gateway.invalid:8080"  # noqa: E731
    flags = lambda path: worker.gateway_flags([path], gw, SimpleNamespace(resolver_file=lambda: "/tmp/r.txt"))  # noqa: E731
    assert flags(worker.tool("subfinder")) == ["-proxy", proxy("subfinder")]
    assert flags(worker.tool("dnsx")) == ["-r", "10.0.0.9:53"]
    assert flags(worker.tool("httpx")) == ["-proxy", proxy("httpx"), "-r", "10.0.0.9:53"]
    assert flags(worker.tool("katana")) == ["-proxy", proxy("katana"), "-r", "10.0.0.9:53"]
    assert flags(worker.tool("gau")) == ["--proxy", proxy("gau")]
    assert flags(worker.tool("feroxbuster")) == ["--proxy", proxy("feroxbuster")]
    assert flags(worker.tool("nuclei")) == ["-p", proxy("nuclei"), "-pi", "-r", "/tmp/r.txt"]
    # Tools without a proxy flag get it from the environment, and nothing else from the worker.
    monkeypatch.setenv("DATABASE_URL", "postgresql://secret")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
    env = gw.env("assetfinder")
    assert env["HTTPS_PROXY"] == env["https_proxy"] == env["HTTP_PROXY"] == proxy("assetfinder")
    assert env["SSL_CERT_FILE"] == gw.ca_file and env["NO_PROXY"] == ""
    assert "DATABASE_URL" not in env and "ANTHROPIC_API_KEY" not in env
    assert gw.mask("x " + proxy("gau")) == "x " + proxy("gau").replace("s3cret-value-0123456789", "********")


def test_tool_runs_get_the_gateway_and_never_log_the_secret_or_the_tokens(stack):
    job = claim(stack, ["a.example.com"])
    r = worker.Run(job)
    out = list(r.tool_lines("env", ["/usr/bin/env"], []))
    assert f"HTTPS_PROXY={r.gw.proxy_url('env')}" in out
    # The tool gets the gateway secret (its proxy credential) and nothing else of the worker's.
    assert not any(job.token in line or "worker-token" in line or line.startswith("DATABASE_URL") for line in out)
    r.log(f"proxy {r.gw.proxy_url('x')}")
    log = stack.job(job.id).log
    assert job.gateway_secret not in log and "********" in log


def test_jobs_that_send_traffic_need_the_gateway(stack, monkeypatch):
    monkeypatch.delenv("ATTACKLEDGER_GATEWAY")
    job = claim(stack, ["a.example.com"])
    monkeypatch.setitem(worker.RUNNERS, "resolve", lambda r, chunk: pytest.fail("ran without a gateway"))
    with pytest.raises(RuntimeError, match="no gateway"):
        worker.run(job)
    assert stack.job(job.id).gateway_secret_sha256         # the API made a credential, and kept only its hash
    assert worker.execute(job)["status"] == "failed" and "no gateway" in stack.job(job.id).log
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY", "gateway.invalid:8080")
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_CA", "/nonexistent/ca.pem")
    job2 = claim(stack, ["b.example.com"], eng_id=stack.job(job.id).engagement_id)
    with pytest.raises(RuntimeError, match="CA certificate"):
        worker.run(job2)


def test_js_fetcher_requires_identification_and_the_gateway():
    with pytest.raises(RuntimeError, match="research header"):
        worker.fetcher(eng())
    with pytest.raises(RuntimeError, match="no gateway"):
        worker.fetcher(eng("X-Bug-Bounty: r1"))


def test_js_fetcher_refuses_redirects():
    handler = worker._NoRedirect()
    assert handler.redirect_request(None, None, 302, "Found", {}, "https://evil.test/") is None


@pytest.mark.parametrize("rps", [1, 5, 50])
def test_no_step_exceeds_the_engagement_rate_limit(rps):
    e = eng("X-Bug-Bounty: r1", ports=True, rps=rps)
    for kind in ("resolve", "probe", "crawl"):
        for _, c in worker.commands(kind, e):
            flag = "-rate" if "-rate" in c else "-rl"
            assert int(c[c.index(flag) + 1]) <= rps, (kind, c)


# ---- batching, time limit and partial runs (through the API, D-042) -----------

import itertools  # noqa: E402

from app.models import JobStatus  # noqa: E402

_names = itertools.count()


def claim(stack, targets, kind="resolve", eng_id=None, **eng):
    """Queue a job on a fresh engagement (or eng_id) and claim it as the worker does."""
    if eng_id is None:
        eng_id = stack.engagement(name=f"t{next(_names)}", **eng)
    stack.queue(eng_id, kind, targets)
    return stack.claim()


def finish(stack, job, **kw):
    """Run the job through worker.execute, which reports the outcome; the API's view of it."""
    out = worker.execute(job, **kw)
    return out, stack.job(job.id)


def test_watchdog_stops_a_silent_tool(stack, monkeypatch):
    monkeypatch.setattr(worker, "JOB_TIMEOUT", 1)
    r = worker.Run(claim(stack, ["a.example.com"]))
    t0 = __import__("time").monotonic()
    with pytest.raises(worker.Cancelled, match="timed out"):
        list(r.tool_lines("sleep", ["sleep", "30"], []))
    assert __import__("time").monotonic() - t0 < 5


def test_time_limit_marks_remaining_targets(stack, monkeypatch):
    targets = [f"h{i}.example.com" for i in range(7)]
    job = claim(stack, targets)
    calls = []

    def fake_runner(r, chunk):
        calls.append(chunk)
        if len(calls) == 3:
            raise worker.Cancelled("timed out")
        return len(chunk)

    monkeypatch.setattr(worker, "CHUNK_SIZE", 3)
    monkeypatch.setitem(worker.RUNNERS, "resolve", fake_runner)
    out, j = finish(stack, job)
    assert out["status"] == "partial"
    assert j.targets_done == 6 and j.result_count == 6
    assert j.remaining_targets == ["h6.example.com"]   # the interrupted batch is not counted
    assert "stopped (timed out) after 6 of 7 targets; 1 not run" in j.log


def test_complete_run_has_no_remaining_targets(stack, monkeypatch):
    job = claim(stack, ["a.example.com", "b.example.com"])
    monkeypatch.setitem(worker.RUNNERS, "resolve", lambda r, chunk: len(chunk))
    out, j = finish(stack, job)
    assert out["status"] == "done" and j.targets_done == 2 and j.remaining_targets is None


def test_worker_runners_match_the_module_registry():
    worker.check_registry()   # raises SystemExit on any mismatch


def test_gates_are_checked_again_when_the_job_is_claimed(stack):
    e = stack.engagement()
    j = stack.queue(e, "ports", ["a.example.com"])          # port scanning not enabled
    assert stack.claim() is None                              # nothing reaches the worker
    job = stack.job(j)
    assert job.status == JobStatus.failed and "off for this engagement" in job.log
    assert job.worker_token_sha256 is None and job.gateway_secret_sha256 is None


def test_target_limit_lists_the_overflow_as_remaining(stack, monkeypatch):
    urls_ = [f"https://app.example.com/js/{i:03d}.js" for i in range(260)]
    job = claim(stack, urls_, kind="jsanalyze")
    assert len(job.spec["targets"]) == 250 and job.spec["over_limit"] == 10
    seen = []
    monkeypatch.setitem(worker.RUNNERS, "jsanalyze", lambda r, chunk: seen.extend(chunk) or len(chunk))
    out, j = finish(stack, job)
    assert out["status"] == "partial"
    assert len(seen) == 250 and j.targets_done == 250
    assert j.remaining_targets == urls_[250:]          # nothing dropped silently


def test_deferred_job_resolves_targets_when_claimed(stack, monkeypatch):
    e = stack.engagement()
    stack.lane(e, "app.example.com")
    stack.queue(e, "resolve", [], deferred=True)
    job = stack.claim()
    assert job.spec["targets"] == ["app.example.com"] and stack.job(job.id).targets == ["app.example.com"]


def test_deferred_job_with_nothing_to_do_is_skipped(stack):
    e = stack.engagement()
    j = stack.queue(e, "crawl", [], deferred=True)
    assert stack.claim() is None
    job = stack.job(j)
    assert job.status == JobStatus.skipped and "nothing to run" in job.log and "Find live web servers" in job.log
    assert job.result == {"skipped_reason": "no live web servers from 'Find live web servers'"}
    assert job.output_sha256 is None


def test_deferred_root_step_without_a_wildcard_is_skipped(stack):
    e = stack.engagement(include=("shop.example.com",))
    j = stack.queue(e, "archive", [], deferred=True)
    assert stack.claim() is None
    assert stack.job(j).status == JobStatus.skipped and "wildcard" in stack.job(j).result["skipped_reason"]


def test_final_status_of_a_run(stack, monkeypatch):
    job = claim(stack, ["a.example.com"])
    monkeypatch.setitem(worker.RUNNERS, "resolve", lambda r, chunk: 0)
    out, j = finish(stack, job)
    assert out["status"] == "done" and j.result is None   # ran, found nothing
    job = claim(stack, ["b.example.com"], eng_id=j.engagement_id)

    def failing(r, chunk):
        r.failed_tools.append("dnsx")
        return 0
    monkeypatch.setitem(worker.RUNNERS, "resolve", failing)
    out, j = finish(stack, job)
    assert out["status"] == "failed" and "dnsx failed and nothing was found" in j.log


def test_noerror_without_records_is_not_resolved(stack, monkeypatch):
    r = worker.Run(claim(stack, ["real.example.com", "ghost.example.com"]))
    lines = {
        "dnsx": ['{"host":"real.example.com","a":["192.0.2.1"],"status_code":"NOERROR"}',
                 '{"host":"ghost.example.com","status_code":"NOERROR"}'],
        "dnsx-cname": ['{"host":"ghost.example.com","cname":["x.example.net"]}'],
    }
    monkeypatch.setattr(worker.Run, "tool_lines", lambda self, name, cmd, inp: iter(lines[name]))
    out = worker.resolve_hosts(r, ["real.example.com", "ghost.example.com"])
    assert list(out) == ["real.example.com"]


def test_results_reach_the_api_in_one_call_per_batch(stack, monkeypatch):
    targets = [f"h{i}.example.com" for i in range(5)]
    job = claim(stack, targets)
    calls = []
    real = job.results
    monkeypatch.setattr(job, "results", lambda **kw: calls.append(kw) or real(**kw))

    def runner(r, chunk):
        for h in chunk:
            r.observe(h, {"a": ["192.0.2.1"], "aaaa": [], "cname": []})
        return len(chunk)
    monkeypatch.setattr(worker, "CHUNK_SIZE", 2)
    monkeypatch.setitem(worker.RUNNERS, "resolve", runner)
    out, j = finish(stack, job)
    assert out["status"] == "done" and [len(c["observations"]) for c in calls] == [2, 2, 1]
    from app.models import Asset, Observation
    with stack.Session() as s:
        assert sorted(o.host for o in s.query(Observation).filter_by(job_id=job.id)) == targets
        assert {a.host for a in s.query(Asset).filter_by(engagement_id=j.engagement_id)} == set(targets)


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
                        totals={"leads_added": 0}, flush=lambda: None,
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


def test_cancelling_stops_a_silent_tool_at_the_next_heartbeat(stack, monkeypatch):
    monkeypatch.setattr(worker, "HEARTBEAT_SECONDS", 0.1)
    job = claim(stack, ["a.example.com"])
    r = worker.Run(job)
    assert stack.api.post(f"/jobs/{job.id}/cancel").status_code == 200
    t0 = __import__("time").monotonic()
    with r.heartbeats(), pytest.raises(worker.Cancelled, match="cancelled"):
        list(r.tool_lines("sleep", ["sleep", "30"], []))
    assert __import__("time").monotonic() - t0 < 5
    out, j = job.finish(stopped="cancelled"), stack.job(job.id)
    assert out == {"status": "cancelled"} and j.remaining_targets == ["a.example.com"]
