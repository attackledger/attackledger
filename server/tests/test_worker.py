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
                           allow_port_scan=ports, crawl_depth=depth)


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
    assert c[c.index("-rate") + 1] == "30"


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
