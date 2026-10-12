"""Pre-flight checks for a live agent run (tools/agent_preflight.sh, tools/agent_live.py).

Nothing here sends anything anywhere. The Claude API calls are built by the real SDK, as the
worker builds them, and captured by a transport that answers them itself; the gateway's policy
is then run over the captured calls in the gateway's own process, with its own environment.

  python -m app.agentcheck worker  [--live]          in the worker: model, ceilings, SDK base URL,
                                                     and the captured calls (JSON on stdout)
  python -m app.agentcheck gateway [--live] [--lab HOST] < worker.json
                                                     in the gateway: the key (set or missing, a
                                                     length class, never the value), the service
                                                     route and the GW-1 body check for each call,
                                                     the key header swap, the lab's port

--live: the checks for a run against the real Claude API, which a dry run against a stub
(tools/agent_dryrun) does not pass: the SDK must call api.anthropic.com and the gateway must not
trust a test CA.

Each prints {"checks": [{"name", "ok", "detail"}], ...}; the exit status is 1 if any check failed.
"""
import base64
import json
import os
import socket
import sys
from urllib.parse import urlsplit

from . import agentloop

# The key the worker's SDK sends; the gateway replaces it (worker.GATEWAY_HOLDS_THE_KEY).
PLACEHOLDER_KEY = "added-by-the-attackledger-gateway"
CLAUDE_API = "api.anthropic.com"


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"name": name, "ok": bool(ok), "detail": detail}


def sample_messages() -> list:
    """A first message and one tool round trip, with every block kind a run sends back."""
    ctx = {"lane": {"id": 1, "role": "errh", "name": "Error handling"}, "host": "shop.lab.test",
           "items": [{"idx": 1, "key": "WSTG-ERRH-01", "text": "Test for improper error handling", "state": "open"}]}
    return [
        {"role": "user", "content": agentloop.first_message(ctx)},
        {"role": "assistant", "content": [
            {"type": "thinking", "thinking": "Start with the home page.", "signature": "c2ln"},
            {"type": "text", "text": "Fetching the home page."},
            {"type": "tool_use", "id": "toolu_1", "name": "http_request",
             "input": {"method": "GET", "url": "http://shop.lab.test/", "headers": []}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1",
                                      "content": '{"status": 200, "body": "<html>ok</html>"}'}]},
    ]


def canned_message(model: str) -> dict:
    return {"id": "msg_preflight", "type": "message", "role": "assistant", "model": model,
            "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 1}}


def capture(models=None, base_url: str | None = None) -> list[dict]:
    """What the SDK sends for each model's call, as agentloop makes it (request_params, with
    max_tokens set by the budget): method, URL, headers and body. The transport answers itself."""
    import anthropic
    try:
        import httpx2 as httpx        # the HTTP client of anthropic 1.x
    except ImportError:  # pragma: no cover - older SDKs use httpx
        import httpx
    out = []
    for model in models or list(agentloop.MODELS):
        seen = []

        def handler(request: httpx.Request, model=model, seen=seen) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, json=canned_message(model))
        client = anthropic.Anthropic(api_key=PLACEHOLDER_KEY, base_url=base_url, max_retries=0,
                                     http_client=anthropic.DefaultHttpxClient(
                                         transport=httpx.MockTransport(handler), trust_env=False))
        params = agentloop.request_params(model, sample_messages())
        params["max_tokens"] = agentloop.MIN_OUTPUT_TOKENS
        client.beta.messages.create(**params)
        req = seen[0]
        out.append({"model": model, "method": req.method, "url": str(req.url),
                    "headers": [[k, v] for k, v in req.headers.items()],
                    "body_b64": base64.b64encode(req.content).decode()})
    return out


def worker_checks(env=os.environ, live: bool = False) -> dict:
    checks, wires = [], []
    try:
        model = agentloop.configured_model(env)
        cheapest = min(agentloop.MODELS, key=lambda m: agentloop.MODELS[m]["price"]["output"])
        checks.append(_check("model", True, f"{model}" + (" (the cheapest configured)" if model == cheapest
                                                          else f" (the cheapest is {cheapest})")))
    except ValueError as e:
        model, cheapest = None, None
        checks.append(_check("model", False, str(e)))
    cap = None
    try:
        cap = agentloop.ceilings(env)
        explicit = (env.get("ATTACKLEDGER_AGENT_MAX_USD") or "").strip()
        checks.append(_check("budget", bool(explicit),
                             f"ATTACKLEDGER_AGENT_MAX_USD={cap['max_cost_usd']:.2f}, "
                             f"MAX_TURNS={cap['max_turns']}, MAX_TOKENS={cap['max_tokens_total']:,}"
                             + ("" if explicit else "; set ATTACKLEDGER_AGENT_MAX_USD in .env for a measured run")))
    except ValueError as e:
        checks.append(_check("budget", False, str(e)))
    base = (env.get("ANTHROPIC_BASE_URL") or "").strip() or None
    try:
        wires = capture([model] if model else None, base_url=base)
        hosts = sorted({urlsplit(w["url"]).hostname for w in wires})
        ok = not live or hosts == [CLAUDE_API]
        checks.append(_check("sdk", ok, f"the SDK builds {len(wires)} call(s) to {', '.join(hosts)}"
                             + ("" if ok else f"; a live run must call {CLAUDE_API} (unset ANTHROPIC_BASE_URL)")))
    except Exception as e:  # noqa: BLE001 - a broken SDK call is what this is here to find
        checks.append(_check("sdk", False, f"the SDK could not build the call: {type(e).__name__}: {str(e)[:300]}"))
    gw_ca = env.get("ATTACKLEDGER_GATEWAY_CA") or ""
    checks.append(_check("gateway-ca", bool(gw_ca) and os.path.exists(gw_ca),
                         f"{gw_ca or 'ATTACKLEDGER_GATEWAY_CA unset'}"))
    return {"checks": checks, "wires": wires, "model": model, "cheapest": cheapest, "ceilings": cap}


def key_class(key: str | None) -> str:
    """Whether the key is set, and its shape, never its value."""
    k = (key or "").strip()
    if not k:
        return "missing"
    size = "under 40" if len(k) < 40 else ("40 to 99" if len(k) < 100 else "100 or more")
    return f"set ({size} characters, {'starts like' if k.startswith('sk-ant-') else 'does not start like'} " \
           f"an Anthropic key)"


def gateway_checks(worker: dict, env=os.environ, live: bool = False, lab: str | None = None) -> dict:
    from . import gateway
    key = env.get("ANTHROPIC_API_KEY")
    k = (key or "").strip()
    checks = [_check("key", bool(k) and (k.startswith("sk-ant-") or not live), key_class(key))]
    test_ca = (env.get(gateway.TEST_SERVICE_CA_ENV) or "").strip()
    checks.append(_check("test-ca", not (live and test_ca),
                         ("a test CA is trusted for stub hosts (dry run only)" if test_ca else "none (as in production)")
                         + ("; a live run needs it unset" if live and test_ca else "")))
    # Built as gateway.main builds it, from the same environment.
    policy = gateway.Policy(_hosts(env, "ATTACKLEDGER_GATEWAY_PASSIVE_HOSTS", gateway.PASSIVE_HOSTS),
                            _hosts(env, "ATTACKLEDGER_GATEWAY_SERVICE_HOSTS", gateway.SERVICE_HOSTS),
                            service_key=key)
    rules = gateway.Rules(job_id=0, engagement_id=0, kind="agent", traffic="agent", include=("shop.lab.test",),
                          exclude=(), rate_limit_rps=1, research_header="X-Bug-Bounty: preflight",
                          research_user_agent=None)
    wires = worker.get("wires") or []
    if not wires:
        checks.append(_check("calls", False, "the worker built no call to check"))
    for w in wires:
        name = f"call {w['model']}"
        try:
            u = urlsplit(w["url"])
            host, port = u.hostname or "", u.port or 443
            path = u.path + (f"?{u.query}" if u.query else "")
            if u.scheme != "https":
                raise gateway.Refused(403, f"the SDK calls {u.scheme}://, not https://")
            kind = policy.classify(rules, host, port, "https")
            if kind != "service":
                raise gateway.Refused(403, f"{host} is not a Claude API host for the gateway ({kind})")
            heads = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in w["headers"]]
            policy.check(rules, kind, w["method"], path, heads)
            body = base64.b64decode(w["body_b64"])
            policy.check_service_body(body)
            sent = policy.headers(rules, kind, heads, host)
            keys = [v for n, v in sent if n.lower() == b"x-api-key"]
            if len(keys) != 1 or keys[0] == PLACEHOLDER_KEY.encode() or any(n.lower() == b"authorization"
                                                                            for n, _ in sent):
                raise gateway.Refused(500, "the gateway would not send exactly its own key")
            beta = dict((k.lower(), v) for k, v in w["headers"]).get("anthropic-beta", "")
            doc = json.loads(body)
            checks.append(_check(name, True, f"{w['method']} {host}{u.path}: forwarded; body keys "
                                 f"{', '.join(sorted(doc))} pass the GW-1 check"
                                 + (f"; anthropic-beta {beta}" if beta else "")))
        except gateway.Refused as e:
            checks.append(_check(name, False, f"the gateway would refuse it: {e.reason}"))
        except Exception as e:  # noqa: BLE001
            checks.append(_check(name, False, f"{type(e).__name__}: {str(e)[:300]}"))
    if lab:
        try:
            socket.create_connection((lab, 80), 3).close()
            checks.append(_check("lab", True, f"{lab} accepts connections on port 80 (no request sent)"))
        except OSError as e:
            checks.append(_check("lab", False, f"{lab} does not answer: {e}; start it with "
                                               f"docker compose --profile lab up -d lab"))
    return {"checks": checks}


def _hosts(env, name: str, base) -> frozenset:
    extra = {h.strip().lower() for h in (env.get(name) or "").split(",") if h.strip()}
    return frozenset(base) | extra


def main(argv: list[str]) -> int:
    live = "--live" in argv
    lab = argv[argv.index("--lab") + 1] if "--lab" in argv else None
    if argv[:1] == ["worker"]:
        out = worker_checks(live=live)
    elif argv[:1] == ["gateway"]:
        out = gateway_checks(json.load(sys.stdin), live=live, lab=lab)
    else:
        print(__doc__, file=sys.stderr)
        return 2
    print(json.dumps(out))
    return 0 if all(c["ok"] for c in out["checks"]) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
