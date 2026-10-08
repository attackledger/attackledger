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


def eng(header=None, ua=None, rps=5):
    return SimpleNamespace(research_header=header, research_user_agent=ua, rate_limit_rps=rps)


def test_probe_adds_identification_headers():
    cmd = worker.command("probe", eng("X-Bug-Bounty: r1", "Mozilla/5.0 (r1)"))
    assert cmd[cmd.index("-H") + 1] == "X-Bug-Bounty: r1"
    assert "User-Agent: Mozilla/5.0 (r1)" in cmd
    assert "-follow-redirects" not in cmd and "-fr" not in cmd


def test_probe_refuses_without_identification():
    with pytest.raises(RuntimeError):
        worker.command("probe", eng())


def test_passive_kinds_do_not_need_identification():
    assert worker.command("subdomains", eng())[0].endswith("/subfinder")
    assert worker.command("resolve", eng(rps=3))[-1] == "3"


def test_parse_probe_uses_input_host():
    host, data = worker.parse("probe", {"input": "app.example.com", "url": "https://app.example.com",
                                        "status_code": 200, "tech": ["nginx"]})
    assert host == "app.example.com" and data["live"] and data["status_code"] == 200
