"""Regressions for the open items of the evidence security review (docs/security-review/EVIDENCE.md,
O-1 to O-3), closed by manifest version 2 and receipt payload v4 (D-054).

- O-1: a receipt's manifest names each item's id and text, so the item ids of two items marked
  done cannot be swapped in a signed report. Receipts made with manifest version 1 still verify,
  with a NOTE that this is not covered.
- O-2: a v4 payload signs the heads of the audit log and the key log, and how many audit entries
  of the engagement and its signer led up to it. A report that leaves one of them out, or stops
  before the signed head, fails; --require-history also fails a report without the logs, or with
  a receipt that does not commit to them.
- O-3: after an HTML report verifies, the verifier prints what its embedded JSON says.

The threat is the one of test_security_evidence.py: someone edits a report and recomputes the
body hash, keeping every signature as it was.
"""
import contextlib
import copy
import io
import json

from app import auditlog, gates, keylog, seal
from app.models import Engagement, Lane, Receipt
from test_auditlog import setup
from test_keytrust import env, register, sign_in, signed_close  # noqa: F401  (env is a fixture)
from test_signing import verifier

VOID = "lane.receipt_voided"


def rehash(r: dict) -> dict:
    r["integrity"]["body_sha256"] = verifier.sha(verifier.canonical({k: v for k, v in r.items() if k != "integrity"}))
    return r


def reseal(r: dict) -> dict:
    """Rehash and seal again with this server's own seal key (D-055): a report as the server
    would have exported it, or as whoever holds the server's key could make one."""
    r = rehash(r)
    r["integrity"].pop("seal", None)
    return seal.seal(r)


def run(tmp_path, report, *flags, name="r.json", text=None) -> tuple[int, str]:
    path = tmp_path / name
    path.write_text(text if text is not None else json.dumps(report), encoding="utf-8")
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = verifier.main(["verify_report.py", str(path), *flags])
    return code, out.getvalue()


def two_items(c, signed=True):
    """Rita attaches evidence to items 1 and 2 of a recon lane (the rest N/A) and closes it,
    signed or with her name only. Returns (engagement, lane, ids, key or None)."""
    e, lane, ids = setup(c)
    sign_in(c, "rita@lab.test")
    for idx, text in ((1, "scope confirmed"), (2, "passive sources listed")):
        assert c.post(f"/lanes/{lane}/attach", json={"item_idx": idx, "kind": "note", "text": text}).status_code == 201
        assert c.patch(f"/lanes/{lane}/items/{idx}", json={"state": "done"}).status_code == 200
    k = None
    if signed:
        k = register(c)
        signed_close(c, lane, k)
    else:
        assert c.post(f"/lanes/{lane}/close", json={"reviewed": True}).json()["status"] == "closed"
    return e, lane, ids, k


def report_of(c, e) -> dict:
    sign_in(c, "owner@lab.test")
    return c.get(f"/engagements/{e}/report").json()


def swap_item_ids(r: dict, lane_id: int) -> dict:
    """The item ids of items 1 and 2 swapped: each one's evidence now seems to support the other."""
    items = next(l for l in r["lanes"] if l["lane_id"] == lane_id)["items"]
    a, b = (next(i for i in items if i["idx"] == n) for n in (1, 2))
    a["item_id"], b["item_id"] = b["item_id"], a["item_id"]
    return rehash(r)


def payload_of(r: dict, lane_id: int) -> dict:
    return json.loads(next(l for l in r["lanes"] if l["lane_id"] == lane_id)["receipt"]["signature"]["payload"])


# ---- O-1: the manifest binds evidence to its item ---------------------------------------------

def test_o1_new_receipts_are_over_a_manifest_that_names_each_item(env):
    c, Session = env
    e, L, _, _ = two_items(c)
    with Session() as s:
        lane = s.get(Lane, L)
        m = gates.manifest(lane)
        assert m["v"] == 2
        assert [(i["id"], i["text"]) for i in m["items"]] == [(i.id, i.text) for i in lane.items]
        assert lane.receipts[-1].manifest_sha256 == gates.manifest_hash(lane) != gates.manifest_hash(lane, 1)
        assert gates.lane_status(lane) == gates.LaneStatus.closed
    assert payload_of(report_of(c, e), L)["manifest_sha256"] == gates.manifest_hash(lane)


def test_o1_swapped_item_ids_fail_under_manifest_v2(env, tmp_path):
    c, _ = env
    e, L, _, _ = two_items(c)
    report = report_of(c, e)
    assert run(tmp_path, report)[0] == 0
    forged = swap_item_ids(copy.deepcopy(report), L)
    problems, _ = verifier.check_receipts(forged)
    # Both items still have evidence, so only the manifest can tell.
    assert problems == ["shop.lab.test / Recon: receipt does not match its items and evidence"], problems
    assert verifier.check_signatures(forged)[0] == []
    code, out = run(tmp_path, forged)
    assert code == 1 and "FAIL  Lane receipts" in out


def test_o1_manifest_v1_receipts_still_close_and_verify_with_a_note(env, tmp_path):
    c, Session = env
    e, L, _, _ = two_items(c, signed=False)
    with Session() as s:                 # a receipt issued before manifest version 2
        lane = s.get(Lane, L)
        rc = s.get(Receipt, lane.receipts[-1].id)
        rc.manifest_sha256 = gates.manifest_hash(lane, 1)
        s.commit()
        assert gates.lane_status(s.get(Lane, L)) == gates.LaneStatus.closed
    report = report_of(c, e)
    note = ("shop.lab.test / Recon: the receipt's manifest is version 1, which does not name each item's id and "
            "text, so which item each piece of evidence supports is not covered by it")
    code, out = run(tmp_path, report)
    assert code == 0 and f"NOTE  {note}" in out
    # What version 1 leaves open, and the note says: the same swap goes unnoticed.
    assert verifier.check_receipts(swap_item_ids(copy.deepcopy(report), L)) == ([], [note])


# ---- O-2: the signed history, and --require-history ----------------------------------------

def test_o2_payload_v4_signs_the_history_heads_and_the_server_checks_them(env):
    c, Session = env
    e, L, ids, k = two_items(c, signed=False)
    sign_in(c, "owner@lab.test")
    a = c.post(f"/engagements/{e}/assets", json={"host": "api.lab.test"}).json()["id"]
    lane = c.post("/lanes", json={"asset_id": a, "role": "recon"}).json()
    for it in lane["items"]:
        c.patch(f"/lanes/{lane['id']}/items/{it['idx']}", json={"state": "na", "na_reason": "lab"})
    sign_in(c, "rita@lab.test")
    k = register(c)
    text = c.get(f"/lanes/{lane['id']}/receipt-payload", params={"key": k.fingerprint}).json()["payload"]
    p = json.loads(text)
    with Session() as s:
        assert p["history"]["audit"] == auditlog.commitment(s, e, ids["rita"])
        assert p["history"]["key_log"] == keylog.head_at(s, s.get(Engagement, e).organization_id)
    # The key log: Rita's key (#1), then the instance's seal key, registered as the payload is issued (D-055).
    assert p["history"]["audit"]["entries"] >= 3 and p["history"]["key_log"]["seq"] == 2

    def close(payload):
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return c.post(f"/lanes/{lane['id']}/close", json={"reviewed": True, "payload": body, "signature": k.sign(body),
                                                          "key_fingerprint": k.fingerprint})
    for change in ({"entries": p["history"]["audit"]["entries"] - 1}, {"sha256": "0" * 64}, {"seq": "1"},
                   {"seq": 2 ** 70}, {"seq": -1}, {"head": "f" * 64}):
        bad = copy.deepcopy(p)
        bad["history"]["audit"].update(change)
        r = close(bad)
        assert r.status_code == 422 and "change history heads" in r.json()["detail"], (change, r.text)
    bad = copy.deepcopy(p)
    bad["history"]["key_log"]["seq"] = 7
    assert close(bad).status_code == 422
    bad = copy.deepcopy(p)
    del bad["history"]
    r = close(bad)
    assert r.status_code == 422 and "missing fields" in r.json()["detail"]
    assert close(p).status_code == 200


def test_o2_an_audit_entry_the_signature_covers_cannot_be_left_out(env, tmp_path):
    c, _ = env
    e, L, _, _ = two_items(c)
    report = report_of(c, e)
    head = payload_of(report, L)["history"]["audit"]
    assert verifier.check_audit_log(report)[0] == []

    # Left out: an entry of the engagement before the signature. The role check alone cannot see it.
    dropped = copy.deepcopy(report)
    dropped["audit_log"]["entries"] = [x for x in dropped["audit_log"]["entries"] if x["action"] != "engagement.created"]
    problems = verifier.check_audit_log(rehash(dropped))[0]
    assert problems == [f"shop.lab.test / Recon: the change history leaves out entries the signature covers: it names "
                        f"{head['entries']} entries of this engagement and its signer up to audit log entry "
                        f"#{head['seq']}, and the report has {head['entries'] - 1} such entries"], problems
    assert run(tmp_path, dropped)[0] == 1

    # Truncated: the links stop before the head the signature names.
    cut = copy.deepcopy(report)
    log = cut["audit_log"]
    log["links"] = [ln for ln in log["links"] if ln["seq"] < head["seq"]]
    log["entries"] = [x for x in log["entries"] if x["seq"] < head["seq"]]
    log["head"] = {"seq": log["links"][-1]["seq"], "entry_hash": log["links"][-1]["entry_hash"]}
    assert any("does not reach the audit log head the signature names" in p
               for p in verifier.check_audit_log(rehash(cut))[0])

    # The key log, the same way.
    cut = copy.deepcopy(report)
    signed = payload_of(report, L)["history"]["key_log"]["seq"]
    assert cut["key_log"]["links"][-1]["seq"] == signed
    cut["key_log"]["links"][-1]["entry_hash"] = "e" * 64
    cut["key_log"]["head"]["entry_hash"] = "e" * 64
    assert any(f"the key log entry #{signed} the signature names is not the one in this report" in p
               for p in verifier.check_key_log(rehash(cut))[0])


def test_o2_require_history(env, tmp_path):
    c, _ = env
    e, L, ids, k = two_items(c)
    report = report_of(c, e)
    code, out = run(tmp_path, report, "--require-history")
    assert code == 0, out
    assert "NOTE  the change history is complete, as far as receipt signatures show, up to audit log entry #" in out

    # A report made before the logs was made before seals too (D-055): no seal either.
    for section, message in (("audit_log", "this report has no change history, which --require-history requires"),
                             ("key_log", "this report has no key history, which --require-history requires")):
        gone = rehash({k_: v for k_, v in copy.deepcopy(report).items() if k_ != section})
        del gone["integrity"]["seal"]
        assert run(tmp_path, gone)[0] == 0                      # D-037: a NOTE only, without the option
        code, out = run(tmp_path, gone, "--require-history")
        assert code == 1 and message in out, out

    # A receipt signed before v4 commits to no history: it still verifies, but not strictly. The report
    # is sealed again, as the server seals an export that holds an old receipt.
    v3 = copy.deepcopy(report)
    sig = next(l for l in v3["lanes"] if l["lane_id"] == L)["receipt"]["signature"]
    p = json.loads(sig["payload"])
    del p["history"]
    p["format"] = "attackledger-receipt-v3"
    sig["payload"] = json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    sig["value"] = k.sign(sig["payload"])
    v3 = reseal(v3)
    assert run(tmp_path, v3)[0] == 0
    code, out = run(tmp_path, v3, "--require-history")
    assert code == 1 and "its signed payload is not format v4, so nothing binds its change history" in out

    # A v4 payload must name the heads.
    p["format"] = "attackledger-receipt-v4"
    sig["payload"] = json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    sig["value"] = k.sign(sig["payload"])
    assert any("does not name the change history heads" in x for x in verifier.check_signatures(rehash(v3))[0])

    # A receipt with a name only, and the first report format.
    e2 = name_only_engagement(c, ids["rita"])
    plain = report_of(c, e2)
    assert run(tmp_path, plain)[0] == 0
    code, out = run(tmp_path, plain, "--require-history")
    assert code == 1 and "the receipt is not signed, so nothing binds its change history" in out
    old = rehash({**copy.deepcopy(report), "format": "attackledger-report/1"})
    code, out = run(tmp_path, old, "--require-history")
    assert code == 1 and "this report format carries no change history" in out


def name_only_engagement(c, rita: int) -> int:
    """Another engagement in the same database, its lane closed with a name only."""
    sign_in(c, "owner@lab.test")
    e = c.post("/engagements", json={"name": "Plain"}).json()["id"]
    c.put(f"/engagements/{e}/members", json={"members": [{"user_id": rita, "roles": ["tester", "reviewer"]}]})
    a = c.post(f"/engagements/{e}/assets", json={"host": "shop.lab.test"}).json()["id"]
    lane = c.post("/lanes", json={"asset_id": a, "role": "recon"}).json()
    sign_in(c, "rita@lab.test")
    for it in lane["items"]:
        c.patch(f"/lanes/{lane['id']}/items/{it['idx']}", json={"state": "na", "na_reason": "lab"})
    assert c.post(f"/lanes/{lane['id']}/close", json={"reviewed": True}).json()["status"] == "closed"
    return e


def void_then_sign_another(c, later: bool):
    """Lane A signed, then changed and changed back (void, D-052, the manifest matches again);
    lane B signed after the void (later) or before it."""
    e, A, ids = setup(c)
    sign_in(c, "owner@lab.test")
    asset = c.post(f"/engagements/{e}/assets", json={"host": "api.lab.test"}).json()["id"]
    B = c.post("/lanes", json={"asset_id": asset, "role": "recon"}).json()
    for it in B["items"]:
        c.patch(f"/lanes/{B['id']}/items/{it['idx']}", json={"state": "na", "na_reason": "lab"})
    sign_in(c, "rita@lab.test")
    k = register(c)
    signed_close(c, A, k)
    if not later:
        signed_close(c, B["id"], k)
    c.patch(f"/lanes/{A}/items/1", json={"state": "open"})
    c.patch(f"/lanes/{A}/items/1", json={"state": "na", "na_reason": "lab"})
    if later:
        signed_close(c, B["id"], k)
    return report_of(c, e), A


def hide_the_void(report: dict, A: int) -> dict:
    """EV-1 with the void entry dropped as well: the lane reported as receipted."""
    r = copy.deepcopy(report)
    next(l for l in r["lanes"] if l["lane_id"] == A)["status"] = "closed"
    r["summary"]["lanes_receipted"] += 1
    r["audit_log"]["entries"] = [x for x in r["audit_log"]["entries"] if x["action"] != VOID]
    return rehash(r)


def test_o2_a_void_left_out_is_caught_by_any_later_signature(env, tmp_path):
    c, _ = env
    report, A = void_then_sign_another(c, later=True)
    assert next(l for l in report["lanes"] if l["lane_id"] == A)["status"] == "stale"
    assert run(tmp_path, report)[0] == 0
    forged = hide_the_void(report, A)
    problems = verifier.check_audit_log(forged)[0]
    assert any("api.lab.test / Recon: the change history leaves out entries the signature covers" in p
               for p in problems), problems
    assert run(tmp_path, forged)[0] == 1


def test_o2_a_void_after_the_newest_signature_is_caught_by_the_seal(env, tmp_path):
    """The gap strict mode had (D-054): nothing a reviewer signed after the void commits to it.
    The seal made at export does (D-055): the hidden void breaks it in every mode, and a report
    without a seal fails strict mode."""
    c, _ = env
    report, A = void_then_sign_another(c, later=False)
    assert run(tmp_path, report, "--require-history")[0] == 0
    forged = hide_the_void(report, A)                       # the seal kept as it was
    assert verifier.check_audit_log(forged, True)[0] == []  # the receipts' signatures cannot see it
    for flags in ((), ("--require-history",)):
        code, out = run(tmp_path, forged, *flags)
        assert code == 1 and "FAIL  Report seal" in out, out
        assert "the report is not the one that was sealed: its body was changed after the seal was made" in out
    unsealed = copy.deepcopy(forged)
    del unsealed["integrity"]["seal"]
    code, out = run(tmp_path, unsealed, "--require-history")
    assert code == 1 and "this report is not sealed, which --require-history requires" in out, out
    code, out = run(tmp_path, unsealed)                     # an old report: a NOTE only, without the option
    assert code == 0 and "NOTE  this report is not sealed (made before report seals)" in out, out
    # What the seal cannot prove, and VERIFIER.md says: whoever holds the server's key can seal
    # another report. The strict NOTE then names the sealed head, not "would not be detected".
    code, out = run(tmp_path, reseal(copy.deepcopy(forged)), "--require-history")
    assert code == 0, out
    assert "as far as the report's seal shows, up to entry #" in out and "would not be detected" not in out


# ---- O-3: what a verified HTML report says ------------------------------------------------------

def test_o3_a_verified_html_report_is_followed_by_its_facts(env, tmp_path):
    c, _ = env
    e, L, _, _ = two_items(c)
    sign_in(c, "owner@lab.test")
    page = c.get(f"/engagements/{e}/report.html").text
    code, out = run(tmp_path, None, name="r.html", text=page)
    assert code == 0, out
    facts = out.split(verifier.FACTS_TITLE, 1)[1]
    assert "  Engagement: Audit (id " in facts
    assert "  Scope: in scope " in facts and "  Hosts: 1 in scope, 0 out of scope" in facts
    assert "  Lanes: 1 receipted, 0 with a void receipt, 0 open" in facts
    assert "  Receipted: shop.lab.test / Recon: 2 done, " in facts and "signed by Rita Reviewer (rita@lab.test)" in facts
    assert "  Evidence: 2 entries, chain head " in facts
    # Not for a JSON report (it is the JSON), and not when verification fails.
    assert verifier.FACTS_TITLE not in run(tmp_path, c.get(f"/engagements/{e}/report").json())[1]
    start = page.index('id="attackledger-report">') + len('id="attackledger-report">')
    end = page.index("</script>", start)
    edited = json.loads(page[start:end])
    edited["engagement"]["name"] = "Another client"          # body hash not recomputed
    code, out = run(tmp_path, None, name="r.html", text=page[:start] + json.dumps(edited) + page[end:])
    assert code == 1 and "FAIL  Report body hash" in out and verifier.FACTS_TITLE not in out
