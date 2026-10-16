"""Getting ready for a live agent run: the pre-flight checks (app.agentcheck), the gateway's
test-only trust for a stub Claude API, and the measurements of tools/agent_live.py.

Nothing here reaches the network: the SDK's calls are captured by a transport that answers
itself, and the gateway runs against the local fake upstream of test_gateway.Stack."""
import base64
import http.client
import datetime as dt
import importlib.util
import json
import ssl
import sys
from pathlib import Path

import pytest

from app import agentcheck, agentloop, gateway
from test_gateway import Stack  # noqa: F401

ROOT = Path(__file__).resolve().parents[2]
REAL_LOOKING = "sk-ant-api03-" + "Q" * 95


@pytest.fixture()
def worker_env(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("not read by the check, only looked for")
    return {"ATTACKLEDGER_AGENT_MODEL": "claude-haiku-5-5", "ATTACKLEDGER_AGENT_MAX_USD": "0.50",
            "ATTACKLEDGER_GATEWAY_CA": str(ca)}


def failed(out) -> set:
    return {c["name"] for c in out["checks"] if not c["ok"]}


# ---- what the SDK sends, through the gateway's own checks ------------------------------------

@pytest.mark.parametrize("model", list(agentloop.MODELS))
def test_preflight_checks_the_call_the_sdk_really_builds_for_every_model(worker_env, model):
    w = agentcheck.worker_checks(env={**worker_env, "ATTACKLEDGER_AGENT_MODEL": model}, live=True)
    assert failed(w) == set(), w["checks"]
    [wire] = w["wires"]
    assert wire["method"] == "POST" and wire["url"].startswith("https://api.anthropic.com/v1/messages")
    body = json.loads(base64.b64decode(wire["body_b64"]))
    headers = dict(wire["headers"])
    # betas travel as a header, never in the body (the GW-1 filter would refuse them there).
    assert "betas" not in body and body["model"] == model and body["max_tokens"] == agentloop.MIN_OUTPUT_TOKENS
    assert ("anthropic-beta" in headers) == agentloop.MODELS[model]["fallback"]
    assert headers["x-api-key"] == agentcheck.PLACEHOLDER_KEY
    g = agentcheck.gateway_checks(w, env={"ANTHROPIC_API_KEY": REAL_LOOKING}, live=True)
    assert failed(g) == set(), g["checks"]
    assert "Q" * 20 not in json.dumps(g)          # the key's value is never in the output
    assert any(c["name"] == f"call {model}" and "pass the GW-1 check" in c["detail"] for c in g["checks"])


def test_preflight_names_the_cheapest_model_and_the_budget(worker_env):
    w = agentcheck.worker_checks(env={**worker_env, "ATTACKLEDGER_AGENT_MODEL": ""})
    assert w["model"] == "claude-opus-5-5" and w["cheapest"] == "claude-haiku-5-5"
    assert w["ceilings"]["max_cost_usd"] == 0.5
    no_budget = {k: v for k, v in worker_env.items() if k != "ATTACKLEDGER_AGENT_MAX_USD"}
    assert failed(agentcheck.worker_checks(env=no_budget)) == {"budget"}
    assert failed(agentcheck.worker_checks(env={**worker_env, "ATTACKLEDGER_AGENT_MAX_USD": "-1"})) == {"budget"}
    assert failed(agentcheck.worker_checks(env={**worker_env, "ATTACKLEDGER_AGENT_MODEL": "gpt-x"})) >= {"model"}


def test_preflight_fails_without_a_key_and_never_prints_one(worker_env):
    w = agentcheck.worker_checks(env=worker_env, live=True)
    g = agentcheck.gateway_checks(w, env={}, live=True)
    assert {"key", "call claude-haiku-5-5"} <= failed(g)
    assert "missing" in g["checks"][0]["detail"] and "ANTHROPIC_API_KEY" in json.dumps(g)
    for key, shown in [("short", "under 40"), ("x" * 60, "40 to 99"), (REAL_LOOKING, "100 or more")]:
        text = agentcheck.key_class(key)
        assert shown in text and key not in text


def test_preflight_live_refuses_a_stub_setup(worker_env):
    """What the dry run uses (a stub host, a test CA) passes the dry-run checks only."""
    stub = {**worker_env, "ANTHROPIC_BASE_URL": "https://claude-stub.test"}
    assert failed(agentcheck.worker_checks(env=stub, live=True)) == {"sdk"}
    w = agentcheck.worker_checks(env=stub)
    assert failed(w) == set()
    gw_env = {"ANTHROPIC_API_KEY": "dry-run-stub-key", "ATTACKLEDGER_GATEWAY_SERVICE_HOSTS": "claude-stub.test",
              gateway.TEST_SERVICE_CA_ENV: "/stub-ca/ca.pem"}
    assert failed(agentcheck.gateway_checks(w, env=gw_env)) == set()
    assert failed(agentcheck.gateway_checks(w, env=gw_env, live=True)) == {"key", "test-ca"}
    # The stub host is refused by a gateway that was not told about it.
    assert failed(agentcheck.gateway_checks(w, env={"ANTHROPIC_API_KEY": "k"})) == {"call claude-haiku-5-5"}


def test_preflight_fails_when_the_gateway_would_refuse_the_body(worker_env, monkeypatch):
    real = agentloop.request_params

    def with_mcp(model, messages, tools=None):
        return {**real(model, messages, tools), "mcp_servers": [{"type": "url", "url": "https://x.invalid/",
                                                                 "name": "x"}]}
    monkeypatch.setattr(agentloop, "request_params", with_mcp)
    w = agentcheck.worker_checks(env=worker_env, live=True)
    g = agentcheck.gateway_checks(w, env={"ANTHROPIC_API_KEY": REAL_LOOKING}, live=True)
    assert failed(g) == {"call claude-haiku-5-5"}
    assert "mcp_servers is not what an agent run sends" in next(c["detail"] for c in g["checks"] if not c["ok"])


def test_preflight_cli_exit_status(worker_env, monkeypatch, capsys):
    for k, v in worker_env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    assert agentcheck.main(["worker", "--live"]) == 0
    worker = capsys.readouterr().out
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(sys, "stdin", __import__("io").StringIO(worker))
    assert agentcheck.main(["gateway", "--live"]) == 1
    assert agentcheck.main(["nothing"]) == 2


# ---- the gateway's test-only trust for a stub Claude API -------------------------------------

@pytest.fixture()
def stack(tmp_path):
    s = Stack(tmp_path)
    yield s
    s.close()


def service_call(stack, host: str, job=6):
    ctx = ssl.create_default_context(cafile=stack.ca_file)
    c = http.client.HTTPSConnection("127.0.0.1", stack.port, context=ctx, timeout=10)
    c.set_tunnel(host, 443, headers={"Proxy-Authorization": stack.auth(job=job, tool="claude")})
    body = json.dumps({"model": "m", "max_tokens": 1, "messages": []}).encode()
    try:
        c.request("POST", "/v1/messages", body=body, headers={"content-type": "application/json"})
        r = c.getresponse()
        return r.status
    finally:
        c.close()


def test_a_test_ca_is_used_for_an_added_stub_host_only_never_for_the_claude_api(stack):
    stack.api.add(6, kind="agent", traffic="agent")
    stack.gw.policy = gateway.Policy(service_hosts=gateway.SERVICE_HOSTS | {"claude-stub.test"}, service_key="k")
    stub_ctx = ssl.create_default_context()
    stack.gw.test_service_ctx = stub_ctx
    assert service_call(stack, "claude-stub.test") == 200
    assert stack.connects[-1]["ssl"] is stub_ctx and stack.connects[-1]["sni"] == "claude-stub.test"
    assert service_call(stack, "api.anthropic.com") == 200
    assert stack.connects[-1]["ssl"] is stack.gw.verify_ctx       # the real API: the public roots only
    stack.gw.test_service_ctx = None
    assert service_call(stack, "claude-stub.test") == 200
    assert stack.connects[-1]["ssl"] is stack.gw.verify_ctx


def test_the_test_ca_is_refused_with_a_real_key(tmp_path):
    ca = gateway.CA(str(tmp_path / "priv"), str(tmp_path / "pub"))
    path = str(tmp_path / "pub" / "ca.pem")
    with pytest.raises(SystemExit, match="refused"):
        gateway.test_service_context(path, REAL_LOOKING)
    ctx = gateway.test_service_context(path, "dry-run-stub-key")
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert len(ctx.get_ca_certs()) == 1 and ca.cert_pem          # that CA alone, not the public roots


def test_no_compose_file_passes_the_dry_run_settings():
    """The stub's settings reach a container only through the dry run's own override: compose
    passes a container only the variables its file lists, so .env cannot set them."""
    for name in ("docker-compose.yml", "deploy/compose.prod.yml"):
        text = (ROOT / name).read_text()
        assert gateway.TEST_SERVICE_CA_ENV not in text and "ANTHROPIC_BASE_URL" not in text, name
    dry = (ROOT / "tools/agent_dryrun/compose.dryrun.yml").read_text()
    assert gateway.TEST_SERVICE_CA_ENV in dry and "internal: true" in dry


# ---- tools/agent_live.py: what the benchmark section says --------------------------------------

def load_live():
    spec = importlib.util.spec_from_file_location("agent_live", ROOT / "tools" / "agent_live.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def lab_line(path, research="agent-live-run", ua="AttackLedger agent live run", t=1000.5, status=200):
    return f'80 "GET {path} HTTP/1.1" {status} ua="{ua}" research="{research}" t={t}'


def run_data(live, lab, rows):
    job = {"id": 9, "status": "done", "started_at": "2026-10-12T08:00:00Z", "finished_at": "2026-10-12T08:00:30Z",
           "result": {"status": "finished", "model": "claude-haiku-5-5", "turns": 4, "requests": 2,
                      "items_marked": 1, "leads_added": 1, "summary": "s", "detail": "",
                      "limits": {"max_turns": 15, "max_requests": 20, "max_cost_usd": 0.5},
                      "usage": {"input": 10, "output": 20, "cache_read": 30, "cache_write": 40},
                      "cost_usd_estimate": 0.0012}}
    lane = {"evidence": [{"source": "agent", "item_idx": 1, "created_at": "2026-10-12T08:00:10Z"},
                         {"source": "agent", "item_idx": 1, "created_at": "2026-10-12T08:00:11Z"},
                         {"source": "manual", "item_idx": 2, "created_at": "2026-10-12T08:00:12Z"},
                         {"source": "agent", "item_idx": 2, "created_at": "2026-10-11T08:00:00Z"}]}
    parsed = [live.LAB_LINE.match(x).groupdict() for x in lab]
    return live.measure(job, {"rows": rows}, parsed, lane, 0.0, 31.0, live.HEADER)


def row(url, kind="target", method="GET", verdict="allowed", reason=""):
    return {"kind": kind, "method": method, "url": url, "verdict": verdict, "reason": reason}


def test_the_measurements_count_hosts_methods_header_evidence_and_refusals():
    live = load_live()
    claude = row("https://api.anthropic.com/v1/messages?beta=true", kind="service", method="POST")
    rows = [claude, claude, row("http://shop.lab.test/"), row("http://shop.lab.test/x")]
    m = run_data(live, [lab_line("/"), lab_line("/x")], rows)
    assert m["claude_api_calls"] == 2 and m["claude_api_hosts"] == ["api.anthropic.com"]
    assert m["target_by_method"] == {"GET": 2} and m["only_lab_host"] and m["header_on_every_request"]
    assert m["evidence_entries"] == 2 and m["items_evidenced"] == 1 and m["refused_rows"] == []
    m["budget"], m["budget_usd"] = "$0.50, 15 turns, 2,000,000 tokens", 0.5      # from the job log (run())
    text = live.section(m, dry=False, today="2026-10-13", project="attackledger", prices="2026-10-09",
                        label="first")
    assert text.startswith("\n## Live agent run (2026-10-13, first)")
    assert "| Research header on every request | yes |" in text and "cache write 40" in text
    assert "| Cost (estimate) | $0.0012 of a $0.5 budget |" in text and "applied by the worker: $0.50, 15 turns" in text

    # A request without the header, one the lab saw that the gateway did not log, another host.
    m = run_data(live, [lab_line("/"), lab_line("/x", research="")], rows)
    assert not m["header_on_every_request"]
    m = run_data(live, [lab_line("/"), lab_line("/x"), lab_line("/y")], rows)
    assert not m["header_on_every_request"]
    m = run_data(live, [lab_line("/")], rows[:3] + [row("http://other.lab.test/", verdict="refused",
                                                        reason="not the lane's host")])
    assert not m["only_lab_host"] and m["refused_rows"][0]["reason"] == "not the lane's host"
    assert m["header_on_every_request"]          # the refused one never reached the lab
    assert "| Research header on every request | yes |" in live.section(m, dry=True, today="d", project="p",
                                                                         prices="x")

    # nginx answers 400 to a path above the root before it reads the headers and logs "-" for both
    # (the first live run, /..%2f..%2fetc%2fpasswd): counted as not observable, not as missing.
    rows2 = rows[:3] + [row("http://shop.lab.test/..%2f..%2fetc%2fpasswd")]
    m = run_data(live, [lab_line("/"), lab_line("/..%2f..%2fetc%2fpasswd", research="-", ua="-", status=400)], rows2)
    assert m["header_on_every_request"] and m["lab_headers_unread"] == 1 and m["lab_with_header"] == 1
    text = live.section(m, dry=False, today="d", project="p", prices="x")
    assert "| Research header on every request | yes (on the 1 whose headers the lab read; 1 not observable) |" in text
    assert "1 answered 400 by the lab's nginx before it read the headers" in text
    # Only that shape: a 400 with the header, or any other status without it, is still judged.
    m = run_data(live, [lab_line("/"), lab_line("/x", research="-", ua="-")], rows)
    assert not m["header_on_every_request"] and m["lab_headers_unread"] == 0
    m = run_data(live, [lab_line("/"), lab_line("/x", research="-", status=400)], rows)
    assert not m["header_on_every_request"]


def test_runs_in_parallel_share_the_labs_log_without_a_false_alarm():
    """Four lanes run at once on one lab: the access log of a run's time holds all their requests.
    Each run's own rows are found by method, path and time; the others' are explained by the gateway's
    rows of the other jobs, and a row nobody's gateway rows explain still fails the run."""
    live = load_live()

    def at(t):
        return f"2026-10-16T10:00:{int(t) % 60:02d}.{int(t * 1000) % 1000:03d}+00:00"
    base = dt.datetime.fromisoformat(at(0)).timestamp()

    def gw(url, t, method="GET"):
        return {**row(url, method=method), "at": at(t), "duration_ms": 50}

    def line(path, t, **kw):
        return lab_line(path, t=base + t, **kw)
    mine = [gw("http://shop.lab.test/a", 1), gw("http://shop.lab.test/b", 3)]
    theirs = [gw("http://shop.lab.test/a", 1.2), gw("http://shop.lab.test/c", 2)]
    lab = [line("/a", 1.05), line("/a", 1.25), line("/c", 2.05), line("/b", 3.05),
           line("/..%2f..%2fetc", 2.5, research="-", ua="-", status=400)]
    theirs.append(gw("http://shop.lab.test/..%2f..%2fetc", 2.45))
    job = {"id": 9, "status": "done", "result": {}}
    parsed = [live.LAB_LINE.match(x).groupdict() for x in lab]
    m = live.measure(job, {"rows": mine}, parsed, {}, 0.0, 31.0, live.HEADER, others=theirs)
    assert m["header_on_every_request"] and m["lab_requests"] == 2 and m["lab_requests_in_window"] == 5
    assert m["lab_unmatched"] == 0 and m["lab_not_from_the_gateway"] == 0
    text = live.section({**m, "usage": {}, "summary": "", "detail": "", "turns": 1, "model": "m", "limits": {}},
                        dry=True, today="d", project="p", prices="x")
    assert "of 5 in the run's time, the others from runs in parallel" in text
    # Without the other runs' rows, their requests are ones the gateway did not log: a failed run.
    m = live.measure(job, {"rows": mine}, parsed, {}, 0.0, 31.0, live.HEADER, others=[])
    assert not m["header_on_every_request"] and m["lab_not_from_the_gateway"] == 3
    # One of this job's requests the lab never saw.
    m = live.measure(job, {"rows": mine + [gw("http://shop.lab.test/d", 4)]}, parsed, {}, 0.0, 31.0, live.HEADER,
                     others=theirs)
    assert not m["header_on_every_request"] and m["lab_unmatched"] == 1


def test_the_lab_logs_the_header_the_live_run_sends():
    live = load_live()
    conf = (ROOT / "lab" / "nginx.conf").read_text()
    name = live.HEADER.split(":")[0].lower().replace("-", "_")
    assert f'research="$http_{name}"' in conf and 'ua="$http_user_agent"' in conf
    assert live.LAB_LINE.match(lab_line("/a?b=1"))["path"] == "/a?b=1"


def test_the_stubs_fixed_run_uses_the_agents_tools_as_their_schemas_say():
    """The dry run's stub (tools/agent_dryrun/claude_stub.py) must stay in step with the tools,
    or the dry run would test refusals instead of the path."""
    from app import agenttools
    spec = importlib.util.spec_from_file_location("claude_stub", ROOT / "tools" / "agent_dryrun" / "claude_stub.py")
    stub = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stub)
    schemas = {t["name"]: t["input_schema"] for t in agenttools.TOOLS}
    ctx = {"host": "shop.lab.test", "items": [{"idx": 1, "state": "done"}, {"idx": 2, "state": "open"}]}
    messages = [{"role": "user", "content": agentloop.first_message(ctx)}]
    assert stub.lane_context(messages) == ctx
    names = []
    for turn in range(7):
        uses = [b for b in stub.play(turn, ctx, messages) if b["type"] == "tool_use"]
        assert len(uses) == 1
        names.append(uses[0]["name"])
        assert set(uses[0]["input"]) == set(schemas[uses[0]["name"]]["required"]), uses[0]
        if uses[0]["name"] in ("add_evidence", "mark_item"):
            assert uses[0]["input"]["item_idx"] == 2           # the first open item
    assert names == ["http_request", "http_request", "add_evidence", "record_lead", "mark_item", "finish", "finish"]


# ---- the lab's sign-in and the lanes that need it (athn, sess, athz) ----------------------------

LAB_CONF = ROOT / "lab" / "nginx.conf"


def test_the_lab_log_names_the_signed_in_user_and_the_run_counts_it():
    live = load_live()
    conf = LAB_CONF.read_text()
    assert 'user="$lab_user"' in conf and "map $cookie_lab_session $lab_user" in conf
    line = '80 "GET /account/ HTTP/1.1" 200 ua="u" research="agent-live-run" t=1000.5 user="alice"'
    assert live.LAB_LINE.match(line)["user"] == "alice"
    assert live.LAB_LINE.match(lab_line("/"))["user"] is None          # a line from before the sign-in
    rows = [row("http://shop.lab.test/"), row("http://shop.lab.test/account/"), row("http://shop.lab.test/account/")]
    m = run_data(live, [lab_line("/") + ' user=""', line, line.replace("alice", "carol")], rows)
    assert m["lab_signed_in"] == {"alice": 1, "carol": 1} and m["header_on_every_request"]
    live.LANE_ROLE = "athz"
    text = live.section(m, dry=False, today="d", project="p", prices="x")
    assert "; signed in as alice 1, carol 1 |" in text
    assert "test accounts `user` (customer, alice), `admin` (admin, carol)" in text
    live.LANE_ROLE = "errh"
    m = run_data(live, [lab_line("/"), lab_line("/x")], rows[:2])
    assert m["lab_signed_in"] == {} and "signed in as" not in live.section(m, dry=False, today="d", project="p",
                                                                           prices="x")


def test_the_lanes_that_need_a_signed_in_user_are_wstg_lanes_with_the_labs_accounts():
    from app import packs
    live = load_live()
    assert set(live.ACCOUNT_ROLES) == {"athn", "sess", "athz", "cryp", "clnt", "apit"}
    assert set(live.ACCOUNT_ROLES) <= set(live.ROLES)
    wstg = {lane.key for lane in packs.all_packs()[live.PACK].lanes}
    # Every WSTG lane can be run on the lab: each has something planted for it.
    assert set(live.ROLES) == wstg and len(live.ROLES) == len(set(live.ROLES))
    conf = LAB_CONF.read_text()
    # Each fictional account signs in with what the lab's sign-in reads, and two roles exist to compare.
    for label, role, username, password in live.LAB_ACCOUNTS:
        assert f"username={username}(?:&|$))(?=.*(?:^|&)password={password}(?:&|$))" in conf, username
        assert f"{username} {role};" in conf, username
    assert {r for _, r, _, _ in live.LAB_ACCOUNTS} == {"customer", "admin"}
    assert live.SESSION_COOKIE == "lab_session" and 'Set-Cookie "lab_session=$lab_issue; Path=/"' in conf


def test_the_labs_signed_in_pages_answer_only_with_a_session():
    """Every location that serves a signed-in page or API checks the session first, and the sign-in's
    own answer listens on the loopback only."""
    import re
    conf = LAB_CONF.read_text()
    blocks = re.findall(r"location (?:= |~ )?(\S+) \{\n(.*?)\n  \}", conf, re.S)
    signed = {p: b for p, b in blocks if p.startswith(("/account/", "/api/v1/me", "/api/v1/orders", "/api/v1/admin",
                                                        "^/account/"))}
    assert len(signed) >= 9
    for path, body in signed.items():
        if path != "/account/logout":          # sign-out answers anyone, as it always did
            assert 'if ($lab_user = "") { return 401' in body, path
    assert "listen 127.0.0.1:8081;" in conf and "proxy_pass http://127.0.0.1:8081;" in conf
    assert re.search(r"location = /_signin \{\n\s+internal;", conf)
    # The planted issues are written down where the lab is, for the benchmark to say what is there.
    for planted in ("ATHN-01", "ATHN-06", "ATHN-07", "ATHN-09", "SESS-02", "SESS-04", "SESS-05", "SESS-06",
                    "SESS-07", "ATHZ-04", "ATHZ-02/03"):
        assert f"#     - {planted}" in conf, planted


def test_the_sign_in_cookie_is_read_from_the_answer_and_never_printed(capsys):
    live = load_live()
    ok = ("Connecting to 127.0.0.1 (127.0.0.1:80)\n  HTTP/1.1 200 OK\n  Server: nginx\n"
          "  Set-Cookie: lab_session=0123abcd; Path=/\n  \nsaving to '/dev/null'\n")
    assert live.session_cookie(ok) == "lab_session=0123abcd"
    assert live.session_cookie("  HTTP/1.1 401 Unauthorized\nwget: server returned error") is None
    assert live.session_cookie("  Set-Cookie: other=1; Path=/\n") is None

    class Runs:
        def __init__(self, out):
            self.out, self.argv = out, None

        def run(self, *argv, check=True, **kw):
            self.argv = argv
            return __import__("subprocess").CompletedProcess(argv, 0, stdout="", stderr=self.out)
    stack = Runs(ok)
    assert live.sign_in(stack, "alice", "pw") == "lab_session=0123abcd"
    assert stack.argv[:3] == ("exec", "-T", "lab") and "username=alice&password=pw" in stack.argv
    assert live.HEADER in stack.argv                     # the sign-in carries the research header too
    with pytest.raises(live.Failed, match="HTTP 401") as e:
        live.sign_in(Runs("  HTTP/1.1 401 Unauthorized\n"), "alice", "bad")
    assert "bad" not in str(e.value)
    assert "0123abcd" not in capsys.readouterr().out


class FakeApi:
    """The API routes tools/agent_live.py's prepare step uses, in memory, and the lab's sign-in."""

    def __init__(self, live):
        self.live, self.engs, self.accounts, self.lanes, self.calls, self.n = live, {}, {}, {}, [], 0
        self.signed_in = []

    def _id(self):
        self.n += 1
        return self.n

    def run(self, *argv, check=True, **kw):
        user = next(a for a in argv if a.startswith("username=")).split("&")[0].split("=")[1]
        self.signed_in.append(user)
        out = f"  HTTP/1.1 200 OK\n  Set-Cookie: lab_session=secret-of-{user}; Path=/\n"
        return __import__("subprocess").CompletedProcess(argv, 0, stdout="", stderr=out)

    def api(self, method, path, body=None):
        import re
        self.calls.append((method, path, body))
        parts = path.strip("/").split("/")
        if path == "/engagements":
            if method == "GET":
                return [{"id": i, "name": e["name"]} for i, e in self.engs.items()]
            i = self._id()
            self.engs[i] = {"name": body["name"], "scope": {}, "lanes": {}}
            self.accounts[i] = []
            return {"id": i, "name": body["name"]}
        if re.fullmatch(r"/engagements/\d+/scope", path):
            e = self.engs[int(parts[1])]
            if method == "PUT":
                e["scope"].update(body)
            return {"include": e["scope"].get("include"), "exclude": e["scope"].get("exclude", []),
                    "authorized_at": e.get("authorized_at"), "research_header": e["scope"].get("research_header"),
                    "content_deleted": None, "redact_evidence": True}
        if re.fullmatch(r"/engagements/\d+/attest", path):
            self.engs[int(parts[1])]["authorized_at"] = "2026-10-14T00:00:00Z"
            return {}
        if re.fullmatch(r"/engagements/\d+/coverage", path):
            e = self.engs[int(parts[1])]
            return {"assets": [{"host": self.live.LAB_HOST, "asset_id": int(parts[1]),
                                "roles": {r: {"lane_id": lid} for r, lid in e["lanes"].items()}}]}
        if path == "/lanes" and method == "POST":
            i = self._id()
            self.lanes[i] = {"id": i, "items": [{"state": "open"}], "status": "open", "executor": "manual"}
            self.engs[body["asset_id"]]["lanes"][body["role"]] = i
            return self.lanes[i]
        if re.fullmatch(r"/lanes/\d+", path):
            return self.lanes[int(parts[1])]
        if re.fullmatch(r"/lanes/\d+/agent-runs", path):
            return []
        if re.fullmatch(r"/engagements/\d+/test-accounts", path):
            accounts = self.accounts[int(parts[1])]
            if method == "POST":
                accounts.append({"id": self._id(), "label": body["label"], "role": body["role"],
                                 "hosts": body["hosts"], "kind": body["kind"], "value": body["value"]})
            return [{k: v for k, v in a.items() if k != "value"} for a in accounts]
        if re.fullmatch(r"/engagements/\d+/test-accounts/\d+", path):
            a = next(x for x in self.accounts[int(parts[1])] if x["id"] == int(parts[3]))
            a.update(body)
            return {k: v for k, v in a.items() if k != "value"}
        raise AssertionError(f"unexpected {method} {path}")


def test_prepare_signs_in_the_labs_accounts_for_the_lanes_that_need_them(capsys):
    live = load_live()
    api = FakeApi(live)
    api.api("GET", "/engagements")
    # A signed-out lane: its own engagement, no test accounts.
    live.LANE_ROLE = "inpv"
    e, lane, how = live.find_lane(api, prepare=True)
    assert how == "created" and e["name"] == live.ENG_NAME and api.accounts[e["id"]] == [] and api.signed_in == []
    # A lane that needs a signed-in user: another engagement, with both accounts for the lab host only,
    # each from a sign-in, as cookies.
    live.LANE_ROLE = "athz"
    e2, lane2, how = live.find_lane(api, prepare=True)
    assert how == "created" and e2["name"] == live.ACCOUNTS_ENG_NAME and e2["id"] != e["id"]
    assert api.signed_in == ["alice", "carol"]
    got = {a["label"]: a for a in api.accounts[e2["id"]]}
    assert set(got) == {"user", "admin"}
    assert got["user"]["value"] == "lab_session=secret-of-alice" and got["admin"]["value"] == "lab_session=secret-of-carol"
    assert all(a["hosts"] == [live.LAB_HOST] and a["kind"] == "cookie" for a in got.values())
    assert got["user"]["role"] == "customer (alice)" and got["admin"]["role"] == "admin (carol)"
    # The next account lane reuses that engagement and signs in no one again; a signed-out lane never
    # takes the engagement that has accounts.
    live.LANE_ROLE = "sess"
    e3, _, how = live.find_lane(api, prepare=True)
    assert e3["id"] == e2["id"] and api.signed_in == ["alice", "carol"]
    live.LANE_ROLE = "conf"
    e4, _, _ = live.find_lane(api, prepare=True)
    assert e4["id"] == e["id"]
    # An account deleted on the engagement is signed in again; with --no-prepare it is not, and the
    # engagement is not used.
    api.accounts[e2["id"]] = [a for a in api.accounts[e2["id"]] if a["label"] != "admin"]
    live.LANE_ROLE = "athn"
    with pytest.raises(live.Failed, match="and its test accounts"):
        live.find_lane(api, prepare=False)
    e5, _, how = live.find_lane(api, prepare=True)
    assert e5["id"] == e2["id"] and how == "reused" and api.signed_in == ["alice", "carol", "carol"]
    out = capsys.readouterr().out
    assert "secret-of" not in out and "Signed in to the lab as alice and added the session as test account user" in out
    assert not [c for c in api.calls if c[2] and "secret-of" in json.dumps(c[2]) and "test-accounts" not in c[1]]


def test_the_stub_sends_its_first_request_as_a_usable_test_account():
    spec = importlib.util.spec_from_file_location("claude_stub", ROOT / "tools" / "agent_dryrun" / "claude_stub.py")
    stub = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stub)
    ctx = {"host": "shop.lab.test", "items": [{"idx": 1, "state": "open"}],
           "test_accounts": [{"label": "other", "role": "x", "usable_on_this_host": False},
                             {"label": "user", "role": "customer (alice)", "usable_on_this_host": True}]}
    [use] = [b for b in stub.play(0, ctx, []) if b["type"] == "tool_use"]
    assert use["input"]["as_account"] == "user"
    [use] = [b for b in stub.play(1, ctx, []) if b["type"] == "tool_use"]
    assert use["input"]["as_account"] == ""
    [use] = [b for b in stub.play(0, {"host": "shop.lab.test", "items": []}, []) if b["type"] == "tool_use"]
    assert use["input"]["as_account"] == ""


# ---- the lanes planted last (idnt, cryp, busl, clnt, apit) -------------------------------------

def lab_blocks() -> dict:
    """Each location's body by its path (lab/nginx.conf, the shop's server and the loopback's): the
    first one for a path (`location = /`, the home page, before the catch-all `location /`). A body
    is cut at its first line that starts "  }", which is enough for what these tests read."""
    import re
    out: dict = {}
    for path, body in re.findall(r"location (?:= |~ )?(\S+) \{\n(.*?)\n  \}", LAB_CONF.read_text(), re.S):
        out.setdefault(path, body)
    return out


def test_the_lab_says_what_is_planted_for_each_new_lane_and_serves_it():
    """The comment block at the top of lab/nginx.conf is what the benchmark says there is to find:
    each issue is listed under its lane, and each path it names is served."""
    conf = LAB_CONF.read_text()
    head = conf.split("\nserver {")[0]
    for lane in ("idnt", "cryp", "busl", "clnt", "apit"):
        assert f"({lane})" in head, lane
    for planted in ("IDNT-04", "IDNT-04/05", "IDNT-02", "CRYP-01/03", "CRYP-04", "BUSL-01/05", "BUSL-02/03",
                    "CLNT-01", "CLNT-11", "CLNT-07", "CLNT-09", "APIT-01"):
        assert f"#     - {planted}:" in head, planted
    blocks = lab_blocks()
    for path in ("/forgot-password", "/register", "/_register", "/static/register.js", "/api/v1/username-available",
                 "/invoice", "/account/export", "/cart", "/static/cart.js", "/api/v1/cart/check",
                 "/api/v1/checkout/quote", "/track", "/static/track.js", "/support", "/static/support.js",
                 "/api/v1/me", "/graphql"):
        assert path in blocks, path
    # Reachable from pages an agent starts on: the home page, the sign-in page, the account page, app.js.
    for page, links in (("/", ("/cart", "/track", "/support")), ("/login", ("/forgot-password", "/register")),
                        ("/account/", ("/invoice?ref=$lab_invoice_ref", "/account/export")),
                        ("/static/app.js", ('"/graphql"',))):
        for link in links:
            assert link in blocks[page], (page, link)
    # The lanes that run signed out find theirs signed out: none of those locations reads the session.
    for path in ("/forgot-password", "/register", "/api/v1/username-available", "/cart", "/api/v1/cart/check",
                 "/api/v1/checkout/quote"):
        assert "$lab_user" not in blocks[path] and "$cookie_lab_session" not in blocks[path], path


def test_the_new_lanes_planted_issues_are_what_the_comments_say():
    import base64
    import hashlib
    import re
    live = load_live()
    conf = LAB_CONF.read_text()
    blocks = lab_blocks()
    # IDNT-04/05: the known usernames are matched exactly and case-sensitively (a map's plain strings
    # ignore case, so "Carol" would be taken); the reset and the check answer differently for them.
    assert '"~^alice$" alice;' in conf and '"~^carol$" carol;' in conf
    assert "return 404" in blocks["/forgot-password"] and "$lab_masked_email" in blocks["/forgot-password"]
    assert '{"available":false}' in blocks["/api/v1/username-available"]
    # IDNT-02: the form sends the role, and the loopback's answer names the role it was sent.
    assert '<input type="hidden" name="role" value="customer">' in blocks["/register"]
    assert "rewrite ^ /_register last;" in blocks["/register"]
    assert re.search(r"location = /_register \{\n\s+internal;", conf)
    assert "proxy_set_header X-Lab-Register-Role $lab_register_role;" in blocks["/_register"]
    assert "with the role $http_x_lab_register_role." in conf.split("listen 127.0.0.1:8081;")[1]
    # CRYP-04: each account's invoice reference is base64 of "order=<its order>", and the map opens it.
    for user, order in (("alice", 1001), ("carol", 1002)):
        ref = base64.b64encode(f"order={order}".encode()).decode()
        assert f'{user} "{ref}";' in conf and f'"~^{ref.rstrip("=")}(==|%3D%3D)?$" {order};' in conf
        assert f"if ($lab_invoice = {order})" in blocks["/invoice"]
    # CRYP-04: the export's hash is the unsalted MD5 of each fictional password.
    for _, _, username, password in live.LAB_ACCOUNTS:
        assert f'{username} "{hashlib.md5(password.encode()).hexdigest()}";' in conf, username
    assert '"password_hash_algorithm":"md5"' in blocks["/account/export"]
    # BUSL: any whole number is a valid quantity; the quote's price is the request's.
    assert '"~^(-?)0*([0-9]{1,9})$" $1$2;' in conf and '"valid":true' in blocks["/api/v1/cart/check"]
    assert '"unit_price":"$lab_price","total":"$lab_price EUR"' in blocks["/api/v1/checkout/quote"]
    assert "price=89.90" in blocks["/cart"]
    # CLNT: the hash into innerHTML, a message listener without an origin check, reflected CORS.
    assert "location.hash" in blocks["/static/track.js"] and ".innerHTML =" in blocks["/static/track.js"]
    support = blocks["/static/support.js"]
    assert 'addEventListener("message"' in support and "origin" not in support and ".innerHTML = e.data" in support
    me = blocks["/api/v1/me"]
    assert "add_header Access-Control-Allow-Origin $http_origin always;" in me
    assert "add_header Access-Control-Allow-Credentials true always;" in me
    served = "\n".join(line for line in conf.splitlines() if not line.lstrip().startswith("#"))
    assert "x-frame-options" not in served.lower() and "frame-ancestors" not in served
    # APIT-01: introspection before the sign-in check; another customer's data after it.
    gql = blocks["/graphql"]
    assert gql.index("$lab_gql = introspection") < gql.index('$lab_user = ""') < gql.index("$lab_gql_customer")
    assert '"~__schema|__type[^a-z]" introspection;' in conf and "Did you mean customer, viewer or orders?" in gql
    assert '"~customer.*carol"' in conf and '"email":"carol@example.test"' in conf


def test_every_role_takes_the_engagement_its_lane_needs():
    """A signed-in lane takes the engagement with the lab's accounts, a signed-out one the other."""
    live = load_live()
    api = FakeApi(live)
    engs = {}
    for role in live.ROLES:
        live.LANE_ROLE = role
        e, lane, _ = live.find_lane(api, prepare=True)
        engs[role] = e["name"]
        assert lane["id"] in api.lanes
    live.LANE_ROLE = "errh"
    assert {r for r, n in engs.items() if n == live.ACCOUNTS_ENG_NAME} == set(live.ACCOUNT_ROLES)
    assert {r for r, n in engs.items() if n == live.ENG_NAME} == set(live.ROLES) - set(live.ACCOUNT_ROLES)
    assert api.signed_in == ["alice", "carol"]            # once, for the first signed-in lane


def test_the_labs_form_targets_take_post_only():
    """A read must never look like a write: GET /account/password answering "saved" was reported by a
    live run as a changed password. The form targets refuse every other method (405, Allow: POST)
    after the sign-in check, and only a POST is "saved". Sign-out by GET stays (SESS-06, planted)."""
    import re
    conf = LAB_CONF.read_text()
    [body] = re.findall(r"location ~ \^/account/\(email\|password\)\$ \{\n(.*?)\n  \}", conf, re.S)
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    assert lines == ['if ($lab_user = "") { return 401 \'sign in first\'; }',
                     "if ($request_method != POST) { add_header Allow POST always; "
                     "return 405 'method not allowed: this form takes POST'; }",
                     "return 200 'saved';"]
    # Nothing else answers like a saved write; the registration answers only to its POST.
    served = "\n".join(line for line in conf.splitlines() if not line.lstrip().startswith("#"))
    assert served.count("'saved'") == 1 and "if ($request_method = POST) { rewrite ^ /_register last; }" in served


def test_juice_shop_lab_writes_and_own_accounts_options():
    """--lab-writes and --own-accounts (D-062): an engagement of their own, two accounts per lane,
    the methods checked, and the section says who approved the writes."""
    live = load_live()
    try:
        live.use_target("juiceshop")
        live.LANE_ROLE, live.LAB_WRITES, live.OWN_ACCOUNTS = "athz", ("POST", "DELETE"), True
        assert live.eng_name() == "Agent live run (Juice Shop, own test accounts, lab writes)"
        assert not live.eng_name().startswith(live.ENG_NAME) and live.uses_accounts()
        assert live.account_labels() == ["athz1", "athz2"]
        live.OWN_ACCOUNTS = False
        assert live.eng_name() == "Agent live run (Juice Shop, lab writes)" and not live.uses_accounts()
        m = run_data(live, [], [])
        m["lab_writes"] = {"rule": 4, "methods": ["POST", "DELETE"], "max_writes": 200, "sent": 3,
                           "sent_by_method": {"POST": 2, "DELETE": 1}, "not_by_rule": 0,
                           "separation_of_duties_met": False}
        text = live.section(m, dry=False, today="d", project="p", prices="x")
        assert "| Writes (D-062) | lab write rule #4 (POST, DELETE, up to 200): 3 sent (DELETE 1, POST 2)" in text
        assert "separation of duties **not met**" in text
        for bad in (["--lab-writes", "GET"], ["--own-accounts"]):
            with pytest.raises(SystemExit):
                live.main(["run", *bad] + (["--target", "juiceshop"] if bad[0] != "--own-accounts" else []))
    finally:
        live.use_target("shop")
        live.LANE_ROLE, live.LAB_WRITES, live.OWN_ACCOUNTS = "errh", (), False
