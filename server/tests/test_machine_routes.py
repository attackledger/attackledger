"""The machine routes answer on the control network only (TM-1, docs/THREAT_MODEL.md).

The gateway calls /gateway/* and relays the worker's /worker/* to the API on the control
network, which only the gateway shares with it. nginx refuses both prefixes on the public front
end (test_web_headers.py); the API refuses them as well when a call reaches it on any other of
its addresses, by the local address of the connection (authz.machine_channel). The tests send
each call to a chosen local address: Starlette's test client puts the URL's host in ASGI's
"server", where uvicorn puts the socket's own address."""
import re
from pathlib import Path

import pytest
import yaml

from harness import WORKER_TOKEN, stack  # noqa: F401

from app import authz, workerclient

ROOT = Path(__file__).resolve().parents[2]
CONTROL = "10.77.0.2"         # the API's address on the control network, in these tests
ELSEWHERE = "10.66.0.3"       # its address on the default network (nginx, a published port)
GATEWAY_TOKEN = "gateway-token-for-tests-00000000000"


class _Compose(yaml.SafeLoader):
    """Compose's merge tags (!reset, !override) as plain values."""


for _tag in ("!reset", "!override"):
    _Compose.add_constructor(_tag, lambda loader, node: (
        loader.construct_sequence(node) if isinstance(node, yaml.SequenceNode)
        else loader.construct_mapping(node) if isinstance(node, yaml.MappingNode) else loader.construct_scalar(node)))


def _load(path: Path) -> dict:
    return yaml.load(path.read_text(), Loader=_Compose)


MACHINE = sorted({p for (_m, p), (perm, _k) in authz.RULES.items() if perm in authz.MACHINE})


@pytest.fixture(autouse=True)
def _fresh_cache():
    authz._control_cache.clear()
    yield
    authz._control_cache.clear()


def at(address: str, path: str) -> str:
    return f"http://{address}:8000{path}"


def send(stack, address, method, path, token=None, body=None):
    r = stack.api.request(method, at(address, path), json=body,
                          headers={"authorization": f"Bearer {token}"} if token else {})
    return r.status_code, r.json() if r.content else None


def test_every_machine_route_is_under_the_two_prefixes_nginx_refuses():
    assert MACHINE and all(p.startswith(("/gateway/", "/worker/")) for p in MACHINE)
    # and no route a person uses is under them
    assert not [p for (_m, p), (perm, _k) in authz.RULES.items()
                if perm not in authz.MACHINE and p.startswith(("/gateway", "/worker"))]


def test_off_the_control_network_a_machine_route_is_a_path_that_does_not_exist(stack, monkeypatch):
    monkeypatch.setenv("ATTACKLEDGER_CONTROL_LISTEN", CONTROL)
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_TOKEN", GATEWAY_TOKEN)
    missing = send(stack, ELSEWHERE, "GET", "/no-such-route")
    assert missing == (404, {"detail": "Not Found"})
    e = stack.engagement()
    job = stack.queue(e, "resolve", ["a.example.com"])
    calls = [("GET", "/worker/ping", WORKER_TOKEN), ("POST", "/worker/claim", WORKER_TOKEN),
             ("GET", "/gateway/dns-scopes", GATEWAY_TOKEN), ("POST", "/gateway/log", GATEWAY_TOKEN),
             ("POST", f"/worker/jobs/{job}/heartbeat", "a-job-token"),
             # without a token, or a wrong one: the same answer, never a 401 or a 503
             ("POST", "/worker/claim", None), ("GET", "/gateway/dns-scopes", "wrong")]
    for method, path, token in calls:
        assert send(stack, ELSEWHERE, method, path, token, {}) == missing, (method, path)
    assert stack.job(job).status.value == "queued"            # nothing was claimed
    # The same calls on the control address are answered as before.
    assert send(stack, CONTROL, "GET", "/worker/ping", WORKER_TOKEN) == (200, {"ok": True})
    assert send(stack, CONTROL, "POST", "/worker/claim", None, {})[0] == 401
    assert send(stack, CONTROL, "GET", "/gateway/dns-scopes", GATEWAY_TOKEN)[0] == 200
    assert send(stack, CONTROL, "GET", "/gateway/dns-scopes", "wrong")[0] == 401


def test_the_whole_job_channel_works_on_the_control_address(stack, monkeypatch):
    """The worker's client, as the gateway's relay forwards it, on the control address."""
    monkeypatch.setenv("ATTACKLEDGER_CONTROL_LISTEN", f"{CONTROL}, ")
    base = stack.api.base_url
    stack.api.base_url = at(CONTROL, "")
    try:
        e = stack.engagement()
        stack.queue(e, "resolve", ["a.example.com"])
        job = stack.claim()
        job.heartbeat()
        job.progress(["a.example.com"])
        assert job.finish(output_sha256="0" * 64, result_count=0) == {"status": "done"}
    finally:
        stack.api.base_url = base
    assert stack.job(job.id).status.value == "done"
    stack.queue(e, "resolve", ["b.example.com"])
    with pytest.raises(workerclient.ApiError) as off:     # the same client on another address
        stack.claim()
    assert off.value.status == 404


def test_routes_for_people_answer_on_every_address(stack, monkeypatch):
    monkeypatch.setenv("ATTACKLEDGER_CONTROL_LISTEN", CONTROL)
    assert send(stack, ELSEWHERE, "GET", "/health")[0] == 200
    assert send(stack, ELSEWHERE, "GET", "/engagements")[0] == 200       # open mode in tests: local operator


def test_a_name_that_does_not_resolve_closes_the_machine_routes(stack, monkeypatch, capsys):
    monkeypatch.setenv("ATTACKLEDGER_CONTROL_LISTEN", "api-control.invalid")
    assert send(stack, CONTROL, "GET", "/worker/ping", WORKER_TOKEN) == (404, {"detail": "Not Found"})
    assert "does not resolve" in capsys.readouterr().err


def test_the_caller_cannot_choose_the_address_with_forwarding_headers(stack, monkeypatch):
    monkeypatch.setenv("ATTACKLEDGER_CONTROL_LISTEN", CONTROL)
    spoof = {"x-forwarded-for": CONTROL, "x-real-ip": CONTROL, "forwarded": f"for={CONTROL};host={CONTROL}",
             "host": f"{CONTROL}:8000", "x-forwarded-host": CONTROL, "authorization": f"Bearer {WORKER_TOKEN}"}
    r = stack.api.request("GET", at(ELSEWHERE, "/worker/ping"), headers=spoof)
    assert (r.status_code, r.json()) == (404, {"detail": "Not Found"})


def test_addresses_are_compared_in_one_spelling(monkeypatch):
    monkeypatch.setenv("ATTACKLEDGER_CONTROL_LISTEN", "localhost")
    assert "127.0.0.1" in authz.control_addresses()
    assert authz._address("::ffff:10.77.0.2") == "10.77.0.2" and authz._address("not an address") is None
    monkeypatch.delenv("ATTACKLEDGER_CONTROL_LISTEN")
    assert authz.control_addresses() is None


def test_the_compose_stack_reaches_the_api_on_its_control_alias():
    """The API is told its control alias, the gateway calls it by that alias (not "api", which
    Docker may answer with the API's default-network address), and the alias is the API's on
    the control network, which the web app is not on."""
    compose = _load(ROOT / "docker-compose.yml")
    api, gateway, web = (compose["services"][n] for n in ("api", "gateway", "web"))
    alias = api["environment"]["ATTACKLEDGER_CONTROL_LISTEN"]
    assert alias in api["networks"]["control"]["aliases"]
    assert re.fullmatch(rf"http://{re.escape(alias)}:8000", gateway["environment"]["ATTACKLEDGER_API_URL"])
    assert "control" in gateway["networks"] and "control" not in (web.get("networks") or ["default"])
    prod = _load(ROOT / "deploy" / "compose.prod.yml")["services"]
    assert "ATTACKLEDGER_CONTROL_LISTEN" not in (prod["api"].get("environment") or {})    # inherited, not reset
    assert "ATTACKLEDGER_API_URL" not in (prod["gateway"].get("environment") or {})
    # The browser tests' runner posts a worker's results as the gateway's relay would: on the control network.
    e2e = _load(ROOT / "e2e" / "compose.e2e.yml")["services"]
    assert "control" in e2e["runner"]["networks"]
    assert f'"http://{alias}:8000"' in (ROOT / "e2e" / "tests" / "lib.ts").read_text()
