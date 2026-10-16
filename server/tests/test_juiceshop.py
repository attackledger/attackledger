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
    assert {r["kind"] for r in rows} == {"issue", "obtained", "group:search-sqli", "group:login-sqli"}
    # A firm indicator names something specific: never a bare class of issue.
    for r in rows:
        if r["confidence"] == "firm":
            assert not re.fullmatch(r"\\b?(xss|sqli|sql injection|idor|csrf|ssrf)\\b?", r["pattern"], re.I), r
            for word in ("xss", "sql injection", "idor", "csrf", "open redirect", "dom xss", "directory listing"):
                assert not r["rx"].fullmatch(word), (r["key"], word)
    # Every challenge this lab can reach has an indicator, and all but two have a firm one (reading the
    # privacy policy and closing notifications at once are not findings).
    reach = sc.load_reach()
    reachable = {k for k, r in reach.items() if r["reach"] == "yes"}
    assert reachable <= {r["key"] for r in rows}
    assert reachable - {r["key"] for r in rows if r["confidence"] == "firm"} == {
        "privacyPolicyChallenge", "closeNotificationsChallenge"}
    # 20.2.0 checks ngy-cookie for the front-end typosquatting, not the package older versions used.
    assert [r["pattern"] for r in rows if r["key"] == "typosquattingAngularChallenge"] == ["ngy-cookie"]
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
    bad.write_text("scoreBoardChallenge\tScore Board\tsure\tissue\tscore\twhy\n")
    with pytest.raises(sc.Failed, match="not firm or uncertain"):
        sc.load_map(bad)
    bad.write_text("scoreBoardChallenge\tScore Board\tfirm\tscore\twhy\n")
    with pytest.raises(sc.Failed, match="not 6"):
        sc.load_map(bad)
    bad.write_text("scoreBoardChallenge\tScore Board\tfirm\tfile\tscore\twhy\n")
    with pytest.raises(sc.Failed, match="kind 'file'"):
        sc.load_map(bad)
    # The reachability table too: every challenge once, disabled in Docker exactly when Juice Shop says so.
    reach = sc.load_reach()
    assert sc.check_reach(reach, catalogue()) == []
    assert any("scoreBoardChallenge" in p for p in sc.check_reach(reach, renamed))
    flipped = dict(reach, rceChallenge=dict(reach["rceChallenge"], reach="yes"))
    assert any("rceChallenge is not no-docker here" in p for p in sc.check_reach(flipped, catalogue()))
    missing = {k: v for k, v in reach.items() if k != "csafChallenge"}
    assert any("csafChallenge (Security Advisory) has no row" in p for p in sc.check_reach(missing, catalogue()))
    bad.write_text("csafChallenge\tSecurity Advisory\tyes\tread\twrite\tno\t-\t-\n")
    with pytest.raises(sc.Failed, match="and a source"):
        sc.load_reach(bad)
    bad.write_text("csafChallenge\tSecurity Advisory\tmaybe\tread\twrite\tno\tsrc\t-\n")
    with pytest.raises(sc.Failed, match="reach 'maybe'"):
        sc.load_reach(bad)


def test_the_reachable_set_is_written_down_with_what_each_challenge_needs():
    sc = load_score()
    reach = sc.load_reach()
    s = sc.reachable_summary(reach)
    # 98 enabled in Docker; 83 possible offline in this lab.
    assert s["total"] == 83
    assert s["not_reachable"] == {"no-docker": 18, "no-llm": 4, "no-chain": 2, "no-internet": 7, "no-front": 2}
    assert s["needs"] == {"read": 53, "write": 20, "account": 10}
    assert s["solve"] == {"read": 33, "write": 37, "account": 13}
    assert s["browser_only"] == 4
    assert {k for k, r in reach.items() if r["browser"] == "yes"} == {
        "localXssChallenge", "xssBonusChallenge", "svgInjectionChallenge", "closeNotificationsChallenge"}
    # The chatbot needs the LLM, two Web3 challenges a Sepolia node; the other Web3-tagged ones need no network.
    assert {k for k, r in reach.items() if r["reach"] == "no-llm"} == {
        "chatbotPromptInjectionChallenge", "chatbotGreedyInjectionChallenge", "aiDebuggingChallenge",
        "systemPromptExtractionChallenge"}
    assert {k for k, r in reach.items() if r["reach"] == "no-chain"} == {"nftMintChallenge", "web3WalletChallenge"}
    assert all(reach[k]["reach"] == "yes" for k in ("web3SandboxChallenge", "tokenSaleChallenge", "nftUnlockChallenge"))
    # What the lab's front refuses (D-060): the continue codes and the challenge list's descriptions.
    conf = (ROOT / "lab" / "juiceshop.conf").read_text()
    assert "rest/continue-code" in conf and "api/challenges" in conf
    assert {k for k, r in reach.items() if r["reach"] == "no-front"} == {"continueCodeChallenge",
                                                                          "premiumPaywallChallenge"}
    # Every row of a reachable challenge cites the file or route of Juice Shop 20.2.0 that decides it.
    for k, r in reach.items():
        if r["reach"] == "yes":
            assert re.search(r"\b[\w./-]+\.(ts|html|tf|yml|json)\b|GET /|POST /|PUT /|PATCH /|DELETE /", r["source"]), k
        if r["needs"] == "read":
            assert re.search(r"(routes|frontend|lib|server|models|infrastructure)[\w./-]*\.(ts|html|tf)|GET /|/ftp|"
                             r"/assets|/\.well-known|/encryptionkeys|/infrastructure|/support", r["source"]), k
    # The new table is in git despite *.tsv in .gitignore.
    ignore = (ROOT / ".gitignore").read_text().splitlines()
    assert "!tools/juiceshop/reachable.tsv" in ignore and "!tools/juiceshop/challenge_map.tsv" in ignore


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
    assert f"| **Total** | 116 (98, 83) | {len(s['identified'])} | {len(s['uncertain'])} | 2 |" in md
    assert "| Reachable in this lab | 83 of 98 enabled: 53 read, 20 write, 10 account; 4 solved only in a browser" in md
    assert f"| Identified of the reachable | {len(s['identified'])} of 83 (" in md
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


# ---- the sentence rules, with the agents' own sentences (tools/benchmark/juiceshop-2026-10-16-opus-*.json) ----

def keys_of(s, field):
    return {r["key"] for r in s[field]}


def score_leads(*texts):
    sc = load_score()
    return sc.score(snapshot(leads=[lead(i, t) for i, t in enumerate(texts, 1)]), sc.load_map())


def test_a_negated_protection_names_the_issue_a_negated_issue_does_not():
    # A protection said to be absent: the issue is there (job 103, leads 148 and evidence 1247).
    s = score_leads("GET http://juice.lab.test/metrics returns 200 with full Prometheus metrics (process CPU/memory, "
                    "open FDs, event-loop lag, HTTP status counters, app startup timings) with no authentication.")
    assert keys_of(s, "identified") == {"exposedMetricsChallenge"}
    s = score_leads("GET /metrics returned a Prometheus metrics endpoint (process CPU/memory, event-loop, HTTP "
                    "counters) with no authentication.")
    assert keys_of(s, "identified") == {"exposedMetricsChallenge"}
    s = score_leads("GET /rest/user/change-password?new=x&repeat=x changed the password without the current password.")
    assert keys_of(s, "identified") == {"changePasswordBenderChallenge"}
    # Normative: "should not be web-accessible" says they are (job 103, evidence 1253).
    s = score_leads("GET /ftp/coupons_2013.md.bak%2500.md returned the backup file contents, which should not be "
                    "web-accessible.")
    assert {"forgottenBackupChallenge", "nullByteChallenge"} <= keys_of(s, "identified")
    # The issue itself said to be absent: listed, never counted.
    for text, key in (
            ("No stack trace was shown on /no-such-page.", "errorHandlingChallenge"),
            ("There is no /metrics endpoint: 404.", "exposedMetricsChallenge"),
            # job 104, evidence 1273
            ("Requested a path containing an XSS payload (GET /abc\"><script>alert(1)</script>); the server returned "
             "the static Angular index.html (HTTP 200) with no reflection of the input. Unknown paths hit the SPA "
             "catch-all, so no server-side reflected XSS was observed.", "reflectedXssChallenge"),
            # job 105, evidence 1263
            ("Tested for cross-site script inclusion: /rest/user/whoami returns application/json {\"user\":{}} as a "
             "JSON object (not an assignable array or JSONP callback) and all responses carry X-Content-Type-Options: "
             "nosniff. No JSONP/callback parameter support was observed in the referenced endpoints, so the JSON "
             "responses cannot be included as script and read cross-site.", "emailLeakChallenge")):
        s = score_leads(text)
        assert key not in keys_of(s, "identified"), text
        [row] = [r for r in s["uncertain"] if r["key"] == key]
        assert row["hits"][0]["reason"] == "absent" and row["hits"][0]["negated"]
    # A negation inside the target's quoted message is not the agent's (job 104, lead 153).
    s = score_leads('GET /rest/products/search?q=test\'))/**/UNION/**/SELECT/**/1-- returns HTTP 500 with verbose error '
                    '"SQLITE_ERROR: SELECTs to the left and right of UNION do not have the same number of result '
                    'columns".')
    assert {"errorHandlingChallenge", "unionSqlInjectionChallenge"} <= keys_of(s, "identified")


def test_a_sentence_that_only_supposes_the_issue_never_counts():
    # The DOM XSS of job 105 was a false positive: CSP missing "should an injection sink be reachable" (lead 152),
    # and a check "left open" for a browser (evidence 1265).
    s = score_leads("Absence of CSP removes a key mitigation against DOM XSS / HTML injection / JS execution should "
                    "an injection sink be reachable in the Angular SPA.",
                    "Confirming DOM-XSS execution requires rendering the SPA in a browser, which cannot be done with "
                    "read-only HTTP; left open for a browser-driven check (Juice Shop search/track-result routes are "
                    "known DOM-XSS sinks).")
    assert "localXssChallenge" not in keys_of(s, "identified") and "localXssChallenge" in keys_of(s, "uncertain")
    # Each form, on a sentence that would otherwise be firm.
    firm = "The search field #/search?q= is a DOM XSS sink through bypassSecurityTrustHtml"
    assert keys_of(score_leads(firm + "."), "identified") == {"localXssChallenge"}
    for text in (firm + " that would execute a payload.", firm + " that could execute a payload.",
                 "Should a sink be reachable, " + firm + ".", firm + " if a sink exists.",
                 firm + "; left open.", "Confirming that " + firm + " requires a browser.",
                 firm + " which might execute a payload.", "Possible: " + firm + ".",
                 firm + ", which cannot be confirmed with read-only requests."):
        s = score_leads(text)
        assert keys_of(s, "identified") == set(), text
        assert s["uncertain"][0]["hits"][0]["reason"] == "speculative", text


def test_a_file_only_listed_or_refused_counts_only_where_finding_it_is_the_challenge():
    sc = load_score()
    # Job 102, lead 146: a listing of /ftp. The confidential document is served as listed (seeing it is the
    # challenge); the backups and the easter egg sit behind the .md/.pdf filter.
    listing = ("GET http://juice.lab.test/ftp returns an HTML directory listing of 11 entries, including backup and "
               "secrets files: package.json.bak, package-lock.json.bak, coupons_2013.md.bak, incident-support.kdbx "
               "(KeePass DB), announcement_encrypted.md, encrypt.pyc, suspicious_errors.yml, acquisitions.md, "
               "eastere.gg, and a quarantine folder.")
    s = score_leads(listing)
    assert keys_of(s, "identified") == {"directoryListingChallenge"}
    behind = {"forgottenBackupChallenge", "forgottenDevBackupChallenge", "easterEggLevelOneChallenge",
              "misplacedSignatureFileChallenge"}
    assert behind | {"loginSupportChallenge"} <= keys_of(s, "uncertain")
    assert {r["hits"][0]["reason"] for r in s["uncertain"] if r["key"] in behind} == {"not obtained"}
    # Job 103, evidence 1242 and 1243: one file refused, one obtained through the null byte.
    s = sc.score(snapshot(evidence=[
        {"id": 1242, "item_idx": 3, "uri": "http://juice.lab.test/ftp/package.json.bak",
         "summary": "[agent] GET http://juice.lab.test/ftp/package.json.bak -> 403. Direct GET /ftp/package.json.bak "
                    "is blocked (403 \"Only .md and .pdf files are allowed!\"), but GET /ftp/coupons_2013.md.bak%2500.md "
                    "(poison null byte) bypassed the extension filter and returned the raw .bak file contents (131 "
                    "bytes, application/octet-stream), showing unsafe file-extension handling that exposes backup "
                    "files."},
        {"id": 1240, "item_idx": 2, "uri": "http://juice.lab.test/ftp/package.json.bak",
         "summary": "[agent] GET http://juice.lab.test/ftp/package.json.bak -> 403. Requesting /ftp/package.json.bak "
                    "returned a 403 with a full Express stack trace disclosing framework version (Express ^4.22.1)."}]),
        sc.load_map())
    assert {"forgottenBackupChallenge", "nullByteChallenge", "errorHandlingChallenge"} == keys_of(s, "identified")
    assert "forgottenDevBackupChallenge" in keys_of(s, "uncertain")
    # Obtained by a request answered 200.
    s = sc.score(snapshot(evidence=[{"id": 1, "item_idx": 1, "uri": "http://juice.lab.test/ftp/eastere.gg%2500.md",
                                     "summary": "[agent] GET http://juice.lab.test/ftp/eastere.gg%2500.md -> 200. Read."}]),
                 sc.load_map())
    assert keys_of(s, "identified") == {"easterEggLevelOneChallenge", "nullByteChallenge"}


def test_sql_injection_in_the_search_counts_once_unless_data_was_extracted():
    # Job 104, lead 153: a real SQL injection error on a UNION, nothing extracted.
    s = score_leads("SQL injection in /rest/products/search q parameter (SQLite)")
    assert keys_of(s, "identified") == {"unionSqlInjectionChallenge"}
    [db] = [r for r in s["uncertain"] if r["key"] == "dbSchemaChallenge"]
    assert db["hits"][0]["reason"] == "counted once, for User Credentials"
    # The schema extracted: Database Schema counts on its own.
    s = score_leads("SQL injection in /rest/products/search: a UNION over sqlite_master returned CREATE TABLE `Users` "
                    "and the other table definitions.")
    assert {"unionSqlInjectionChallenge", "dbSchemaChallenge"} <= keys_of(s, "identified")
    # The same for the sign-in: once, for Login Admin, unless a user is named.
    s = score_leads("SQL injection in POST /rest/user/login with ' OR 1=1--.")
    assert keys_of(s, "identified") == {"loginAdminChallenge"}
    assert {"loginBenderChallenge", "loginJimChallenge"} <= keys_of(s, "uncertain")
    s = score_leads("Signed in as bender@juice-sh.op'-- through SQL injection in the login.")
    assert "loginBenderChallenge" in keys_of(s, "identified")


def test_the_allowlist_bypass_is_named_by_its_url_or_its_name():
    # Jobs 104 and 105 (leads 154 and 145); Juice Shop marked Allowlist Bypass solved.
    for text in ("Open redirect via /redirect?to= allowlist bypass",
                 "GET /redirect?to=https://evil.example.com/?x=https://github.com/juice-shop/juice-shop returns 302."):
        assert keys_of(score_leads(text), "identified") == {"redirectChallenge"}, text
    s = score_leads("GET /redirect?to=http://evil.example.com returns 406.")
    assert keys_of(s, "identified") == set() and "redirectChallenge" in keys_of(s, "uncertain")


OPUS_RUNS = {  # job: lane, identified with the old table and rules (commit f57949b), identified now
    "info": (102, 10, {"web3SandboxChallenge", "scoreBoardChallenge", "securityPolicyChallenge",
                       "directoryListingChallenge"}),
    "conf": (103, 6, {"nullByteChallenge", "exposedMetricsChallenge", "errorHandlingChallenge",
                      "forgottenBackupChallenge"}),
    "inpv": (104, 1, {"unionSqlInjectionChallenge", "errorHandlingChallenge", "redirectChallenge"}),
    "clnt": (105, 2, {"web3SandboxChallenge", "redirectChallenge"}),
}


def test_the_first_four_opus_runs_score_as_reviewed(capsys):
    """The reviewed truth of jobs 102-105: the DOM XSS of job 105 out; Exposed Metrics (job 103) and Allowlist
    Bypass (jobs 104, 105) in; the SQL injection in the search (job 104) counted for one challenge only."""
    sc = load_score()
    rows, reach = sc.load_map(), sc.load_reach()
    files = [ROOT / "tools" / "benchmark" / f"juiceshop-2026-10-16-opus-{lane}.json" for lane in OPUS_RUNS]
    scores = [sc.score(json.loads(f.read_text()), rows, reach=reach) for f in files]
    for s, (lane, (job, _, expected)) in zip(scores, OPUS_RUNS.items()):
        assert s["job_id"] == job and s["lane"]["role"] == lane
        assert keys_of(s, "identified") == expected, lane
        assert s["reachable"]["identified"] == len(expected)
    clnt = scores[3]
    assert "localXssChallenge" in keys_of(clnt, "uncertain")
    inpv = scores[2]
    assert len({"unionSqlInjectionChallenge", "dbSchemaChallenge"} & keys_of(inpv, "identified")) == 1
    u = sc.union(scores, reach)
    assert u["jobs"] == [102, 103, 104, 105]
    assert set(u["identified"]) == set().union(*(e for _, _, e in OPUS_RUNS.values()))
    assert u["reachable"]["identified"] == 10 and u["reachable"]["identified_by_needs"] == {
        "read": 10, "write": 0, "account": 0}
    # The four ran on one shop at once, so each snapshot holds the same six solved flags; every one of them
    # is identified by the union.
    assert set(u["solved_during_runs"]) == {"errorHandlingChallenge", "forgottenBackupChallenge",
                                            "securityPolicyChallenge", "redirectChallenge",
                                            "exposedMetricsChallenge", "nullByteChallenge"}
    assert u["solved_not_identified"] == []
    # The command line takes several snapshots and adds their union.
    assert sc.main([str(f) for f in files]) == 0
    out = capsys.readouterr().out
    assert out.count("### Juice Shop scoring (job") == 4
    assert "### Juice Shop scoring, union of jobs 102, 103, 104, 105" in out
    assert "| Identified of the reachable | 10 of 83 (12%): read 10/53, write 0/20, account 0/10 |" in out
    assert sc.main([str(f) for f in files] + ["--json"]) == 0
    assert json.loads(capsys.readouterr().out)["union"]["reachable"]["identified"] == 10
