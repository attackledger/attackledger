"""OWASP Juice Shop as a second practice target (D-060): how it is wired into the compose files,
how tools/agent_live.py runs an agent on it, and how tools/juiceshop_score.py scores a run.

Nothing here starts a container or reaches the network: the compose files are read as YAML, the
API and the containers are fakes, and the scoring reads a snapshot made in the test."""
import importlib.util
import json
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from test_agent_live import FakeApi, lab_line, load_live
from test_supply_chain import FILES, _services

ROOT = Path(__file__).resolve().parents[2]
FRONT_CONF = ROOT / "lab" / "juiceshop.conf"
CATALOGUE = ROOT / "tools" / "juiceshop" / "challenges-v20.2.0.json"


def _networks(svc: dict) -> dict:
    nets = svc.get("networks") or ["default"]
    return {n: {} for n in nets} if isinstance(nets, list) else {n: (v or {}) for n, v in nets.items()}


def load_score():
    spec = importlib.util.spec_from_file_location("juiceshop_score", ROOT / "tools" / "juiceshop_score.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def catalogue() -> list[dict]:
    return json.loads(CATALOGUE.read_text())["challenges"]


# ---- the compose files -------------------------------------------------------------------------

@pytest.mark.parametrize("files", FILES)
def test_juice_shop_is_reachable_only_through_its_front_on_the_lab_network(files):
    services = _services(files)
    juice, front = services["juiceshop"], services["juiceshop-front"]
    # Optional, never published, pinned to a released version by its index digest.
    for svc in (juice, front):
        assert svc.get("profiles") == ["lab"]
        assert not svc.get("ports") and not svc.get("expose")
        assert svc.get("network_mode") is None
    assert re.fullmatch(r"bkimminich/juice-shop:v20\.2\.0@sha256:[0-9a-f]{64}", juice["image"])
    # Juice Shop is on its own network, which only its front shares; the gateway reaches the front only,
    # as juice.lab.test on the lab network.
    assert set(_networks(juice)) == {"juiceshop"}
    assert set(_networks(front)) == {"lab", "juiceshop"}
    assert _networks(front)["lab"].get("aliases") == ["juice.lab.test"]
    on_juice = {n for n, s in services.items() if "juiceshop" in _networks(s)}
    assert on_juice == {"juiceshop", "juiceshop-front"}
    assert "juiceshop" not in _networks(services["gateway"])
    nets: dict = {}
    for f in files:
        for name, conf in (yaml.safe_load((ROOT / f).read_text().replace("!override", "").replace("!reset", ""))
                           .get("networks") or {}).items():
            nets.setdefault(name, {}).update(conf or {})
    assert nets["juiceshop"]["internal"] is True
    assert nets["juiceshop"]["driver_opts"]["com.docker.network.bridge.inhibit_ipv4"] == "true"
    # Hardened like the rest, but for the read-only root filesystem (test_supply_chain.READ_WRITE_SERVICES).
    assert juice["user"].split(":")[0] == "65532" and juice.get("read_only") is False
    assert "/nodejs/bin/node" in juice["healthcheck"]["test"] and "connect(3000" in " ".join(juice["healthcheck"]["test"])
    assert front["depends_on"]["juiceshop"]["condition"] == "service_healthy"
    assert "./lab/juiceshop.conf:/etc/nginx/conf.d/default.conf:ro" in front["volumes"]


def test_the_lab_proxy_for_browsers_still_forwards_to_the_shop_only():
    conf = (ROOT / "deploy" / "lab-proxy.conf").read_text()
    assert "juice" not in conf


def test_the_front_logs_like_the_shop_and_passes_requests_as_sent():
    live = load_live()
    conf = FRONT_CONF.read_text()
    [fmt] = re.findall(r"log_format withheaders '([^']*)';", conf)
    shop_fmt = re.findall(r"log_format withheaders '([^']*)';", (ROOT / "lab" / "nginx.conf").read_text())[0]
    assert fmt == shop_fmt.replace('user="$lab_user"', 'user=""')
    # A line as the front writes it is what agent_live.py counts, and it is never "signed in".
    line = (f'80 "GET /rest/products/search?q=x HTTP/1.1" 200 ua="{live.USER_AGENT}" research="agent-live-run" '
            f't=1000.5 user=""')
    m = live.LAB_LINE.match(line)
    assert m and m["path"] == "/rest/products/search?q=x" and m["user"] == ""
    assert "access_log /var/log/nginx/access.log withheaders;" in conf and "listen 80;" in conf
    served = "\n".join(x for x in conf.splitlines() if not x.lstrip().startswith("#"))
    assert "set $juice http://juiceshop:3000;" in served and "proxy_pass $juice;" in served
    assert "X-Forwarded" not in served and "X-Real-IP" not in served


# ---- tools/agent_live.py --target juiceshop ----------------------------------------------------

def test_the_shop_stays_the_default_target():
    live = load_live()
    assert (live.TARGET, live.LAB_HOST, live.ENG_NAME, live.LAB_SERVICES, live.LAB_LOG_SERVICE) == (
        "shop", "shop.lab.test", "Agent live run (lab)", ("lab",), "lab")
    live.use_target("juiceshop")
    assert (live.LAB_HOST, live.ENG_NAME, live.LAB_SERVICES, live.LAB_LOG_SERVICE) == (
        "juice.lab.test", "Agent live run (Juice Shop)", ("juiceshop", "juiceshop-front"), "juiceshop-front")
    live.use_target("shop")
    assert live.LAB_HOST == "shop.lab.test" and live.LAB_LOG_SERVICE == "lab"


def test_every_juice_shop_lane_runs_signed_out_on_its_own_engagement():
    live = load_live()
    live.use_target("juiceshop")
    api = FakeApi(live)
    engs = set()
    for role in live.ROLES:
        live.LANE_ROLE = role
        assert not live.uses_accounts()
        e, lane, how = live.find_lane(api, prepare=True)
        engs.add(e["id"])
    live.LANE_ROLE = "errh"
    [eid] = engs
    eng = api.engs[eid]
    assert eng["name"] == "Agent live run (Juice Shop)" and set(eng["lanes"]) == set(live.ROLES)
    assert eng["scope"]["include"] == ["juice.lab.test"] and eng["scope"]["exclude"] == []
    assert eng["scope"]["research_header"] == live.HEADER and eng["authorized_at"]
    assert api.signed_in == [] and api.accounts[eid] == []
    attest = [c for c in api.calls if c[1].endswith("/attest")]
    assert attest[0][2]["operator"] == "agent_live.py (juiceshop)"
    # The shop's engagement is not taken for Juice Shop, nor Juice Shop's for the shop.
    live.use_target("shop")
    e, _, how = live.find_lane(api, prepare=True)
    assert how == "created" and e["id"] != eid and api.engs[e["id"]]["scope"]["include"] == ["shop.lab.test"]


class Containers:
    """docker compose for the Juice Shop helpers: exec in the front answers what Juice Shop would."""

    def __init__(self, challenges, version="20.2.0"):
        self.challenges, self.version, self.calls = challenges, version, []

    def run(self, *argv, check=True, **kw):
        self.calls.append(argv)
        if argv[:3] == ("exec", "-T", "juiceshop-front"):
            url = argv[-1]
            if url.endswith("/api/Challenges"):
                out = json.dumps({"status": "success", "data": self.challenges})
            elif url.endswith("/rest/admin/application-version"):
                out = json.dumps({"version": self.version})
            else:
                out = ""
            return subprocess.CompletedProcess(argv, 0, stdout=out, stderr="")
        if "--force-recreate" in argv:
            for c in self.challenges:
                c["solved"] = False
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        raise AssertionError(argv)


def live_challenges(solved=()):
    return [{**c, "id": i, "description": "d", "solved": c["key"] in solved} for i, c in enumerate(catalogue(), 1)]


def test_juice_shop_is_read_inside_the_stack_and_a_run_starts_on_a_fresh_shop(capsys):
    live = load_live()
    live.use_target("juiceshop")
    stack = Containers(live_challenges())
    name, ok, detail = live.juice_check(stack)
    assert ok and "Juice Shop 20.2.0: 116 challenges, none solved" in detail
    # Straight to Juice Shop on its own network, from the front's container: not through the gateway, and
    # not through the front's access log.
    assert all(c[:3] == ("exec", "-T", "juiceshop-front") and c[-1].startswith("http://juiceshop:3000/")
               for c in stack.calls)
    stack = Containers(live_challenges(solved={"scoreBoardChallenge"}))
    assert live.juice_check(stack)[1] is False
    rows = live.fresh_juice_shop(stack)
    assert not any(r["solved"] for r in rows) and any("--force-recreate" in c for c in stack.calls)
    assert "recreating it for a fresh shop" in capsys.readouterr().out
    assert set(rows[0]) == {"key", "name", "category", "difficulty", "solved", "disabledEnv"}


def test_the_run_section_names_juice_shop():
    live = load_live()
    live.use_target("juiceshop")
    from test_agent_live import row, run_data
    m = run_data(live, [lab_line("/")], [row("http://juice.lab.test/")])
    assert m["only_lab_host"] and m["target_hosts"] == ["juice.lab.test"]
    text = live.section(m, dry=False, today="2026-10-16", project="p", prices="x", label="errh lane")
    assert text.startswith("\n## Live agent run (2026-10-16, Juice Shop, errh lane)")
    assert "`errh` on `juice.lab.test`, scope `juice.lab.test` only" in text


def test_the_snapshot_holds_the_runs_leads_and_evidence_only(tmp_path):
    live = load_live()
    live.use_target("juiceshop")
    before = [{k: c[k] for k in ("key", "name", "category", "difficulty", "disabledEnv")} | {"solved": False}
              for c in catalogue()]
    stack = Containers(live_challenges(solved={"directoryListingChallenge"}))

    class Api:
        def api(self, method, path, body=None):
            assert (method, path) == ("GET", "/engagements/3/leads?kind=agent")
            return [{"id": 1, "title": "Confidential file /ftp/acquisitions.md", "severity": "medium",
                     "source_url": "http://juice.lab.test/ftp/acquisitions.md",
                     "detail": {"text": "readable", "lane": "conf", "lane_id": 7}},
                    {"id": 2, "title": "Other lane", "severity": "", "source_url": "",
                     "detail": {"text": "/metrics", "lane": "info", "lane_id": 8}}]
    stack.api = Api().api
    lane = {"id": 7, "role": "conf", "items": [{"idx": 1, "key": "CONF-04", "text": "t", "state": "done",
                                                "na_reason": None}],
            "evidence": [{"id": 5, "source": "agent", "item_idx": 1, "kind": "http", "uri": "http://juice.lab.test/ftp",
                          "summary": "Directory listing on /ftp", "created_at": "2026-10-16T10:00:05Z"},
                         {"id": 6, "source": "agent", "item_idx": 1, "kind": "http", "uri": "http://juice.lab.test/metrics",
                          "summary": "an earlier run", "created_at": "2026-10-16T09:00:00Z"}]}
    args = type("A", (), {"dry_run": False, "snapshot": str(tmp_path / "snap.json"), "no_append": True})()
    text = live.juice_snapshot(stack, args, {"id": 11, "started_at": "2026-10-16T10:00:00Z"}, {"id": 3}, lane,
                               {"agent_status": "finished", "summary": "s"}, before, "2026-10-16")
    snap = json.loads((tmp_path / "snap.json").read_text())
    assert [x["id"] for x in snap["leads"]] == [1] and [x["id"] for x in snap["evidence"]] == [5]
    assert snap["juice_shop_version"] == "20.2.0" and snap["lane"] == {"id": 7, "role": "conf"}
    assert "| Identified (counted) | 1 |" in text and "| Solved during the run (Juice Shop's flags) | 1 |" in text
    assert "Confidential Document (Sensitive Data Exposure, identified)" in text


# ---- tools/juiceshop_score.py ------------------------------------------------------------------

def test_the_indicator_table_fits_the_pinned_juice_shop():
    sc = load_score()
    rows = sc.load_map()
    assert sc.check_map(rows, catalogue()) == []
    assert {r["confidence"] for r in rows} == {"firm", "uncertain"}
    # A firm indicator names something specific: never a bare class of issue.
    for r in rows:
        if r["confidence"] == "firm":
            assert not re.fullmatch(r"\\b?(xss|sqli|sql injection|idor|csrf|ssrf)\\b?", r["pattern"], re.I), r
    # The catalogue is the pinned image's: 116 challenges, 18 of them disabled in Docker.
    assert len(catalogue()) == 116
    assert sum("Docker" in c["disabledEnv"] for c in catalogue()) == 18
    assert json.loads(CATALOGUE.read_text())["version"] == "20.2.0"
    compose = (ROOT / "docker-compose.yml").read_text()
    assert "bkimminich/juice-shop:v20.2.0@" in compose


def test_the_table_fails_loudly_on_another_juice_shop(tmp_path):
    sc = load_score()
    renamed = [dict(c, name="Something Else") if c["key"] == "scoreBoardChallenge" else c for c in catalogue()]
    assert any("scoreBoardChallenge is called 'Something Else'" in p for p in sc.check_map(sc.load_map(), renamed))
    bad = tmp_path / "map.tsv"
    bad.write_text("scoreBoardChallenge\tScore Board\tsure\tscore\twhy\n")
    with pytest.raises(sc.Failed, match="not firm or uncertain"):
        sc.load_map(bad)


def snapshot(leads=(), evidence=(), solved_before=(), solved_after=()):
    def lst(solved):
        return [{"key": c["key"], "name": c["name"], "category": c["category"], "difficulty": c["difficulty"],
                 "disabledEnv": c["disabledEnv"], "solved": c["key"] in solved} for c in catalogue()]
    return {"job_id": 4, "lane": {"id": 2, "role": "info"}, "juice_shop_version": "20.2.0",
            "leads": list(leads), "evidence": list(evidence), "items": [{"idx": 1, "state": "done"}],
            "challenges_before": lst(solved_before), "challenges_after": lst(set(solved_before) | set(solved_after))}


def lead(i, title, detail="", url=""):
    return {"id": i, "title": title, "detail": {"text": detail}, "source_url": url}


def test_scoring_counts_firm_matches_lists_uncertain_ones_and_reads_solved_flags():
    sc = load_score()
    snap = snapshot(
        leads=[lead(1, "Prometheus metrics exposed", "GET /metrics answers 200 with process data"),
               lead(2, "Possible SQL injection in the product search", "q=' gives SQLITE_ERROR",
                    "http://juice.lab.test/rest/products/search?q=%27"),
               lead(3, "Error page", "No stack trace was shown on /no-such-page")],
        evidence=[{"id": 9, "item_idx": 1, "uri": "http://juice.lab.test/ftp/acquisitions.md",
                   "summary": "The confidential document is readable"}],
        solved_before=["privacyPolicyChallenge"],
        solved_after=["directoryListingChallenge", "errorHandlingChallenge"])
    s = sc.score(snap, sc.load_map())
    ident = {r["key"]: r for r in s["identified"]}
    unc = {r["key"] for r in s["uncertain"]}
    assert {"exposedMetricsChallenge", "directoryListingChallenge"} <= set(ident)
    # SQLITE_ERROR is an error answered with its internals (firm for Error Handling), and SQL injection in
    # the search fits two challenges: uncertain, listed, not counted.
    assert "errorHandlingChallenge" in ident
    assert {"unionSqlInjectionChallenge", "dbSchemaChallenge"} <= unc
    assert not unc & set(ident)
    # The negated sentence is only uncertain on its own; the lead quotes the text it was found in.
    neg = [h for h in ident["errorHandlingChallenge"]["hits"] if h["where"] == "lead 3"]
    assert neg and neg[0]["negated"] and neg[0]["confidence"] == "uncertain"
    assert ident["exposedMetricsChallenge"]["hits"][0]["text"].startswith("Prometheus metrics exposed")
    # Solved: Juice Shop's flags, during the run only.
    assert {c["key"] for c in s["solved_during_run"]} == {"directoryListingChallenge", "errorHandlingChallenge"}
    assert s["solved_before_run"] == ["privacyPolicyChallenge"]
    assert all(c["identified"] for c in s["solved_during_run"])
    # Totals per category add up to the catalogue.
    assert sum(c["challenges"] for c in s["categories"].values()) == 116
    assert sum(c["enabled"] for c in s["categories"].values()) == 116 - 18
    assert s["categories"]["Observability Failures"]["identified"] == 1
    assert sum(c["identified"] for c in s["categories"].values()) == len(s["identified"])
    md = sc.markdown(s)
    assert "A read-only agent can identify far more than it can solve." in md
    assert f"| **Total** | 116 (98) | {len(s['identified'])} | {len(s['uncertain'])} | 2 |" in md
    assert "| Solved before the run (not counted) | 1 |" in md


def test_a_negated_mention_alone_is_never_counted():
    sc = load_score()
    s = sc.score(snapshot(leads=[lead(1, "Checked /metrics", "There is no /metrics endpoint: 404.")]), sc.load_map())
    assert s["identified"] == [] and [r["key"] for r in s["uncertain"]] == ["exposedMetricsChallenge"]


def test_a_review_confirms_or_rejects_matches(tmp_path, capsys):
    sc = load_score()
    snap = snapshot(leads=[lead(1, "SQL injection in the sign-in", "POST /rest/user/login would need approval"),
                           lead(2, "Score board route in main.js", "#/score-board")])
    s = sc.score(snap, sc.load_map(), {"loginAdminChallenge": "confirmed", "scoreBoardChallenge": "rejected",
                                       "ssrfChallenge": "confirmed"})
    assert [r["key"] for r in s["identified"]] == ["loginAdminChallenge"]
    assert s["identified"][0]["review"] == "confirmed"
    assert [r["key"] for r in s["rejected"]] == ["scoreBoardChallenge"]
    assert s["review_not_matched"] == ["ssrfChallenge"]
    with pytest.raises(sc.Failed, match="confirmed or rejected"):
        sc.score(snap, sc.load_map(), {"loginAdminChallenge": "yes"})
    # The command line: Markdown by default, JSON on request, and a plain stop on a bad file.
    f = tmp_path / "snap.json"
    f.write_text(json.dumps(snap))
    assert sc.main([str(f)]) == 0 and "### Juice Shop scoring (job 4, lane `info`" in capsys.readouterr().out
    assert sc.main([str(f), "--json"]) == 0 and json.loads(capsys.readouterr().out)["challenges"] == 116
    f.write_text("{}")
    assert sc.main([str(f)]) == 1 and "no challenge list" in capsys.readouterr().err
