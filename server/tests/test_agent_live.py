"""Getting ready for a live agent run: the pre-flight checks (app.agentcheck), the gateway's
test-only trust for a stub Claude API, and the measurements of tools/agent_live.py.

Nothing here reaches the network: the SDK's calls are captured by a transport that answers
itself, and the gateway runs against the local fake upstream of test_gateway.Stack."""
import base64
import http.client
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


def lab_line(path, research="agent-live-run", ua="AttackLedger agent live run", t=1000.5):
    return f'80 "GET {path} HTTP/1.1" 200 ua="{ua}" research="{research}" t={t}'


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
