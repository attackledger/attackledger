"""Regressions for the security review of evidence integrity, encryption, imports and the web
front end (docs/security-review/EVIDENCE.md). Each test names the finding it covers.

The verifier findings share one threat: someone edits a report after the server made it and
recomputes the body hash (which anyone can), keeping every signature as it was. Whatever a
signature covers cannot change; the verifier must not let what it does not cover contradict it.
"""
import copy
import json
from datetime import datetime, timedelta, timezone

from app import redact
from app.gatewayapi import LogIn, gateway_log
from app.models import GatewayRequest
from test_agent import HOST, api  # noqa: F401  (fixture)
from test_auditlog import rechain, signed_report
from test_encryption import delete, engagement
from test_import import verify
from test_keytrust import env  # noqa: F401  (fixture)
from test_people import client  # noqa: F401  (fixture)
from test_people import sign_in as people_sign_in
from test_receipt_void import receipted_recon_lane


def rehash(r: dict) -> dict:
    """The body hash recomputed, as anyone editing a report can."""
    r["integrity"]["body_sha256"] = verify.sha(verify.canonical({k: v for k, v in r.items() if k != "integrity"}))
    return r


def run(tmp_path, report: dict, capsys, name="r.json", text=None) -> tuple[int, str]:
    path = tmp_path / name
    path.write_text(text if text is not None else json.dumps(report), encoding="utf-8")
    capsys.readouterr()
    code = verify.main(["verify_report.py", str(path)])
    return code, capsys.readouterr().out


def signed_lane(report: dict) -> dict:
    return next(l for l in report["lanes"] if l["receipt"] and l["receipt"].get("signature"))


# ---- EV-1: a voided receipt reported as receipted (D-052) ---------------------------------

def test_ev1_a_voided_receipt_cannot_be_reported_as_receipted(client, tmp_path, capsys):
    ids, e, L = receipted_recon_lane(client)
    people_sign_in(client, "tess@lab.test")
    client.patch(f"/lanes/{L}/items/1", json={"state": "open"})      # voids the receipt
    client.patch(f"/lanes/{L}/items/1", json={"state": "done"})      # the manifest matches it again
    people_sign_in(client, "owner@lab.test")
    report = client.get(f"/engagements/{e}/report").json()
    assert next(x for x in report["lanes"] if x["lane_id"] == L)["status"] == "stale"
    assert run(tmp_path, report, capsys)[0] == 0

    # The lane's status is not signed: flip it back, with the summary's count, and rehash.
    forged = copy.deepcopy(report)
    next(x for x in forged["lanes"] if x["lane_id"] == L)["status"] = "closed"
    forged["summary"]["lanes_receipted"] += 1
    rehash(forged)
    assert verify.check_receipts(forged)[0] == []           # the manifest matches the receipt
    assert verify.check_signatures(forged)[0] == []
    problems = verify.check_audit_log(forged)[0]
    assert any("reported as receipted, but the change history records that this receipt was voided" in p
               for p in problems), problems
    code, out = run(tmp_path, forged, capsys)
    assert code == 1 and "FAIL  Change history" in out

    # A new signature on the same manifest is a new receipt: the old void does not touch it.
    people_sign_in(client, "rita@lab.test")
    assert client.post(f"/lanes/{L}/close", json={"reviewed": True}).json()["status"] == "closed"
    people_sign_in(client, "owner@lab.test")
    again = client.get(f"/engagements/{e}/report").json()
    assert verify.check_audit_log(again)[0] == []
    assert run(tmp_path, again, capsys)[0] == 0


# ---- EV-2: the receipt's issue time is not the signed one -----------------------------------

def test_ev2_the_receipt_issue_time_must_match_the_signed_payload(env, tmp_path, capsys):
    c, _ = env
    report, payload, ids = signed_report(c)
    assert verify.check_signatures(report)[0] == []
    rc = signed_lane(report)["receipt"]
    gap = datetime.fromisoformat(rc["issued_at"]) - datetime.fromisoformat(payload["issued_at"])
    assert timedelta(0) <= gap < timedelta(minutes=1)                # genuine: just after the payload

    # Before the fix: moving the unsigned issue time to before the audit log covered the
    # engagement turned the role check into a note, so a signer without the reviewer role passed.
    demoted = copy.deepcopy(report)
    members = next(x for x in demoted["audit_log"]["entries"] if x["action"] == "members.updated")
    for m in members["change"]["after"]:
        if m["user_id"] == ids["rita"]:
            m["roles"] = ["tester"]
    rechain(demoted)
    assert any("did not hold the reviewer role" in p for p in verify.check_audit_log(demoted)[0])
    moved = copy.deepcopy(demoted)
    signed_lane(moved)["receipt"]["issued_at"] = (datetime.fromisoformat(rc["issued_at"])
                                                  - timedelta(days=30)).isoformat()
    rehash(moved)
    found, notes = verify.check_audit_log(moved)
    assert found == [] and any("before the audit log covered" in n for n in notes)   # the check alone is blind
    assert any("issue time is not the time its signed payload was issued" in p
               for p in verify.check_signatures(moved)[0])
    assert run(tmp_path, moved, capsys)[0] == 1

    for shift in (timedelta(hours=-2), timedelta(minutes=16), timedelta(days=1)):
        later = copy.deepcopy(report)
        signed_lane(later)["receipt"]["issued_at"] = (datetime.fromisoformat(rc["issued_at"]) + shift).isoformat()
        rehash(later)
        assert any("issue time" in p for p in verify.check_signatures(later)[0]), shift
    # Within the server's window (ten minutes to sign, then the timestamp authority): still valid.
    near = copy.deepcopy(report)
    signed_lane(near)["receipt"]["issued_at"] = (datetime.fromisoformat(payload["issued_at"])
                                                 + timedelta(minutes=11)).isoformat()
    assert verify.check_signatures(near)[0] == []


# ---- EV-3: the signed engagement is not the report's -----------------------------------------

def test_ev3_a_receipt_signed_for_another_engagement_fails(env, tmp_path, capsys):
    c, _ = env
    report, payload, _ = signed_report(c)
    assert payload["engagement"] == {"id": report["engagement"]["id"], "name": report["engagement"]["name"]}
    moved = copy.deepcopy(report)
    moved["engagement"]["id"] += 1000
    rehash(moved)
    assert any("the signature names another engagement" in p for p in verify.check_signatures(moved)[0])
    assert run(tmp_path, moved, capsys)[0] == 1

    # A rename after signing is allowed (the server allows it); the verifier says so.
    renamed = copy.deepcopy(report)
    renamed["engagement"]["name"] = "Another client"
    rehash(renamed)
    problems, notes = verify.check_signatures(renamed)
    assert problems == [] and any(f'signed when the engagement was named "{payload["engagement"]["name"]}"' in n
                                  for n in notes)


# ---- EV-4: the counts printed at the top are not checked ------------------------------------

def test_ev4_the_summary_counts_must_be_the_reports_own(env, tmp_path, capsys):
    c, _ = env
    report, _, _ = signed_report(c)
    assert verify.check_receipts(report)[0] == [] and verify.check_chain(report) == []
    more = copy.deepcopy(report)
    more["summary"]["lanes_receipted"] = 12
    rehash(more)
    assert any("the summary says 12 lanes are receipted, but 1 in-scope lanes are" in p
               for p in verify.check_receipts(more)[0])
    code, out = run(tmp_path, more, capsys)
    assert code == 1 and "12 receipted lanes" in out and "FAIL  Lane receipts" in out
    entries = copy.deepcopy(report)
    entries["summary"]["evidence_entries"] = 40
    rehash(entries)
    assert any("the summary counts 40 evidence entries" in p for p in verify.check_chain(entries))
    assert run(tmp_path, entries, capsys)[0] == 1


# ---- EV-5: an HTML report verifies only its embedded JSON --------------------------------

def test_ev5_html_reports_say_that_only_the_embedded_json_is_checked(env, tmp_path, capsys):
    c, _ = env
    report, _, _ = signed_report(c)
    page = c.get(f"/engagements/{report['engagement']['id']}/report.html").text
    # The page's own text is not covered: edited, it still verifies, so the verifier says so.
    edited = page.replace("AttackLedger coverage report", "Penetration test: no findings", 1)
    code, out = run(tmp_path, {}, capsys, name="r.html", text=edited)
    assert code == 0 and "NOTE  this is an HTML report: the checks cover the JSON report embedded in it" in out
    code, out = run(tmp_path, report, capsys)
    assert code == 0 and "this is an HTML report" not in out


# ---- EV-6: deleted content left the traffic log's URLs --------------------------------------

def test_ev6_deleting_content_removes_the_traffic_log_urls(api):
    e, _ = engagement(api)
    s = api.Session()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    s.add(GatewayRequest(at=now, engagement_id=e, tool="agent", kind="target", method="GET",
                         url=f"https://{HOST}/account/orders?customer=4711", host=HOST, port=443, status=200,
                         verdict="allowed"))
    s.commit()
    assert api.get(f"/engagements/{e}/gateway-log").json()["rows"][0]["url"].endswith("customer=4711")
    assert any("traffic log" in x for x in api.get(f"/engagements/{e}/content").json()["removes"])
    res = delete(api, e)
    assert res["removed"]["gateway_urls"] == 1
    log = api.get(f"/engagements/{e}/gateway-log").json()
    assert log["total"] == 1 and log["rows"][0]["url"] == ""
    assert (log["rows"][0]["method"], log["rows"][0]["status"], log["rows"][0]["verdict"]) == ("GET", 200, "allowed")
    # A batch the gateway sends after the deletion keeps no URL either.
    gateway_log(LogIn(rows=[{"at": datetime.now(timezone.utc), "engagement_id": e, "tool": "agent", "kind": "target",
                             "method": "GET", "url": f"https://{HOST}/late?customer=4711", "host": HOST,
                             "verdict": "allowed"}]), session=s)
    assert all(r["url"] == "" for r in api.get(f"/engagements/{e}/gateway-log").json()["rows"])
    s.close()


# ---- EV-7: cloud API key headers were stored as captured -----------------------------------

def test_ev7_cloud_api_key_headers_are_redacted():
    raw = (b"GET /orders HTTP/1.1\r\nHost: api.lab.test\r\n"
           b"Ocp-Apim-Subscription-Key: 0123456789abcdef0123456789abcdef\r\n"
           b"x-functions-key: QmFzZTY0RnVuY3Rpb25LZXk1234==\r\n\r\n")
    rep = redact.Report()
    out = redact.http_message(raw, rep)
    assert b"0123456789abcdef" not in out and b"QmFzZTY0RnVuY3Rpb25LZXk" not in out and rep.count == 2
    assert out.startswith(b"GET /orders HTTP/1.1\r\nHost: api.lab.test\r\nOcp-Apim-Subscription-Key: [redacted:")
    for text in ('{"subscriptionKey": "s3cr3t-value-1"}', "https://api.lab.test/x?subscription-key=s3cr3t-value-1",
                 "X-Master-Key: s3cr3t-value-1"):
        assert "s3cr3t-value-1" not in redact.text(text, redact.Report()), text
