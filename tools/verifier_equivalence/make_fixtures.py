#!/usr/bin/env python3
"""Make the report fixtures for the verifier equivalence tests.

The fixtures are genuine reports from the server itself (signed in the test suite's
browser-key stand-in, timestamped by throwaway OpenSSL timestamp authorities with RSA and
EC chains; evidence chain records v1 and v2 in one chain; reports made after an owner and
the retention policy deleted an engagement's content), and mutated copies, each made to
break one check. tools/verifier_equivalence/run.sh then runs verify_report.py and the
browser module on every one of them and compares the output.

It needs the server's dependencies and the openssl command, so it runs in the API image:

    docker run --rm --user 1000:1000 -e HOME=/tmp -v "$PWD":/w -w /w/server \\
      --entrypoint python attackledger-api:latest /w/tools/verifier_equivalence/make_fixtures.py

Everything is fictional: *.lab.test hosts and people. Writes tools/verifier_equivalence/fixtures/.
"""
import base64
import copy
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUT = HERE / "fixtures"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ.pop("ATTACKLEDGER_API_TOKEN", None)
os.environ["ATTACKLEDGER_DEV_KEY"] = "1"          # the public development master key (vault.py)
WORK = Path(tempfile.mkdtemp(prefix="al-fixtures-"))
os.environ["ATTACKLEDGER_BLOBS"] = str(WORK / "blobs")
sys.path[:0] = [str(ROOT / "server"), str(ROOT / "server" / "tests")]

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from datetime import date, datetime, timedelta, timezone  # noqa: E402

from app import auth, db, people, timestamps  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Engagement, Lane  # noqa: E402
from test_agent import load_worker  # noqa: E402
from test_encryption import v1_row  # noqa: E402
from test_signing import BrowserKey  # noqa: E402
from test_timestamps import TSA  # noqa: E402

PW = "fixture password 1"         # a throwaway database's password, for this script only


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def fresh_client() -> TestClient:
    """A client on a new database, with its own blob and key store."""
    auth._failures.clear()
    os.environ["ATTACKLEDGER_BLOBS"] = tempfile.mkdtemp(prefix="blobs-", dir=WORK)
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    db.Base.metadata.create_all(eng)
    Session = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

    def _session():
        s = Session()
        try:
            yield s
        finally:
            s.close()
    app.dependency_overrides[db.get_session] = _session
    people.SessionLocal = Session
    c = TestClient(app)
    c.Session = Session
    return c


def ok(r, code=(200, 201)):
    assert r.status_code in (code if isinstance(code, tuple) else (code,)), (r.status_code, r.text)
    return r.json()


def sign_in(c, email):
    c.cookies.clear()
    ok(c.post("/auth/login", json={"email": email, "password": PW}))


def register(c, alg):
    k = BrowserKey(alg)
    body = ok(c.post("/auth/keys", json={"algorithm": alg, "public_key": k.spki}), 201)
    k.fingerprint, k.id = body["fingerprint"], body["id"]
    return k


def signed_close(c, lane_id, k):
    payload = ok(c.get(f"/lanes/{lane_id}/receipt-payload", params={"key": k.fingerprint}))["payload"]
    ok(c.post(f"/lanes/{lane_id}/close", json={"reviewed": True, "payload": payload, "signature": k.sign(payload),
                                               "key_fingerprint": k.fingerprint}))


def lane_with_items(c, asset, role, done: dict, na_reason="lab"):
    """A lane whose items in done (idx -> evidence text) carry evidence, the rest N/A."""
    return lane_items(c, ok(c.post("/lanes", json={"asset_id": asset, "role": role}), 201), done, na_reason)


def lane_items(c, lane, done: dict, na_reason="lab"):
    for it in lane["items"]:
        if it["idx"] in done:
            ok(c.post(f"/lanes/{lane['id']}/attach", json={"item_idx": it["idx"], "kind": "note", "text": done[it["idx"]]}), 201)
            ok(c.patch(f"/lanes/{lane['id']}/items/{it['idx']}", json={"state": "done"}))
        else:
            ok(c.patch(f"/lanes/{lane['id']}/items/{it['idx']}", json={"state": "na", "na_reason": na_reason}))
    return lane["id"]


def use_tsa(tsa):
    if tsa is None:
        os.environ.pop("ATTACKLEDGER_TSA_URL", None)
    else:
        os.environ["ATTACKLEDGER_TSA_URL"] = "http://tsa.lab.test/"
        timestamps.POST = tsa.post


def people_engagement(c, name):
    ok(c.post("/people", json={"email": "owner@lab.test", "name": "Olive Owner", "password": PW, "is_owner": True}), 201)
    sign_in(c, "owner@lab.test")
    ids = {}
    for email, who in (("riza@lab.test", "Rıza Çelik"), ("ray@lab.test", "Ray Tester")):
        ids[email] = ok(c.post("/people", json={"email": email, "name": who, "password": PW}), 201)["id"]
    e = ok(c.post("/engagements", json={"name": name}), 201)["id"]
    ok(c.put(f"/engagements/{e}/members", json={"members": [{"user_id": i, "roles": ["tester", "reviewer"]}
                                                            for i in ids.values()]}))
    assets = {h: ok(c.post(f"/engagements/{e}/assets", json={"host": h}), 201)["id"]
              for h in ("shop.lab.test", "api.lab.test")}
    ok(c.put(f"/engagements/{e}/scope", json={"include": ["shop.lab.test", "api.lab.test"], "rate_limit_rps": 5,
                                               "research_header": "X-Lab: equivalence"}))
    return e, assets


def report(c, e) -> bytes:
    r = c.get(f"/engagements/{e}/report")
    assert r.status_code == 200, r.text
    return r.content


def make_signed(ec_tsa):
    """Two signers (ECDSA P-256 and Ed25519), an EC timestamp chain (P-256 root, P-384 below),
    a v1 entry written before chain record v2 among v2 ones, non-ASCII names and text, one
    lane left open. Returns the report, and the reports after the owner deleted the content."""
    use_tsa(ec_tsa)
    with fresh_client() as c:
        name = "Equivalence: signed"
        e, assets = people_engagement(c, name)
        lane = ok(c.post("/lanes", json={"asset_id": assets["shop.lab.test"], "role": "recon"}), 201)
        with c.Session() as s:
            v1_row(s, s.get(Lane, lane["id"]), "written before chain record v2", sha("old"))
        a = lane_items(c, lane, {1: "kapsam doğrulandı — ✓ 😀"}, na_reason="laboratuvar ortamı — yok")
        b = lane_with_items(c, assets["api.lab.test"], "recon", {1: "api scope confirmed", 2: "passive sources listed"})
        lane_with_items(c, assets["shop.lab.test"], "mapper", {})        # left open
        sign_in(c, "riza@lab.test")
        signed_close(c, a, register(c, "ECDSA-P256"))
        sign_in(c, "ray@lab.test")
        signed_close(c, b, register(c, "Ed25519"))
        before = report(c, e)
        sign_in(c, "owner@lab.test")
        ok(c.post(f"/engagements/{e}/content/delete", json={"confirm_name": name}))
        return before, report(c, e)


def make_retention():
    """The retention date passed and the worker deleted the content (actor: the retention policy)."""
    use_tsa(None)
    with fresh_client() as c:
        e, assets = people_engagement(c, "Equivalence: retention")
        a = lane_with_items(c, assets["shop.lab.test"], "recon", {1: "scope confirmed", 2: "sources listed"})
        sign_in(c, "riza@lab.test")
        signed_close(c, a, register(c, "Ed25519"))
        sign_in(c, "owner@lab.test")
        tomorrow = (datetime.now(timezone.utc).date() + timedelta(days=1)).isoformat()
        ok(c.patch(f"/engagements/{e}", json={"retain_until": tomorrow}))
        with c.Session() as s:
            s.get(Engagement, e).retain_until = date.today() - timedelta(days=1)
            s.commit()
            assert load_worker().retention_pass(s) == [e]
        return report(c, e)


def make_rsa(rsa_tsa):
    """An RSA timestamp chain; a key revoked after it signed; an owner's unsigned close."""
    use_tsa(rsa_tsa)
    with fresh_client() as c:
        e, assets = people_engagement(c, "Equivalence: RSA timestamps")
        a = lane_with_items(c, assets["shop.lab.test"], "recon", {1: "scope confirmed"})
        b = lane_with_items(c, assets["api.lab.test"], "recon", {})
        sign_in(c, "riza@lab.test")
        k = register(c, "Ed25519")
        signed_close(c, a, k)
        ok(c.post(f"/auth/keys/{k.id}/revoke"))
        sign_in(c, "owner@lab.test")
        ok(c.post(f"/lanes/{b}/close", json={"reviewed": True}))
        return report(c, e)


def make_unsigned():
    use_tsa(None)
    with fresh_client() as c:
        e, assets = people_engagement(c, "Equivalence: unsigned")
        a = lane_with_items(c, assets["shop.lab.test"], "recon", {1: "scope confirmed"})
        sign_in(c, "riza@lab.test")
        ok(c.post(f"/lanes/{a}/close", json={"reviewed": True}))
        return report(c, e)


def make_void():
    """A signed receipt voided by a change, then the lane changed back (D-052): the manifest matches
    the receipt again, the lane stays void, and the change history records the void."""
    use_tsa(None)
    with fresh_client() as c:
        e, assets = people_engagement(c, "Equivalence: void")
        a = lane_with_items(c, assets["shop.lab.test"], "recon", {1: "scope confirmed"})
        sign_in(c, "riza@lab.test")
        signed_close(c, a, register(c, "Ed25519"))
        sign_in(c, "ray@lab.test")
        ok(c.patch(f"/lanes/{a}/items/1", json={"state": "open"}))
        ok(c.patch(f"/lanes/{a}/items/1", json={"state": "done"}))
        return report(c, e)


def void_mutations(void: dict) -> dict:
    out = {}

    def as_receipted(r):    # the void hidden: the lane's status (not signed) and the count with it
        next(l for l in r["lanes"] if l["status"] == "stale")["status"] = "closed"
        r["summary"]["lanes_receipted"] += 1
    r = copy.deepcopy(void)
    as_receipted(r)
    out["void-reported-as-receipted"] = rehash(r)
    r = copy.deepcopy(void)
    void_kept_issue_time_moved(r)
    out["void-receipted-issue-time-moved"] = rehash(r)
    return out


def void_kept_issue_time_moved(r: dict) -> None:
    """The void hidden without leaving its entry out (security recheck EV-1): the lane reported
    as receipted, and the receipt's issue time (not signed) moved by a second, inside the window
    the signature check allows, so it no longer equals the one the void entry names."""
    lane = next(l for l in r["lanes"] if l["status"] == "stale")
    lane["status"] = "closed"
    r["summary"]["lanes_receipted"] += 1
    rc = lane["receipt"]
    rc["issued_at"] = (datetime.fromisoformat(rc["issued_at"]) + timedelta(seconds=1)).isoformat()


def html_report(c, e) -> bytes:
    r = c.get(f"/engagements/{e}/report.html")
    assert r.status_code == 200, r.text
    return r.content


def lane_of(r: dict, host: str, role: str = "recon") -> dict:
    return next(l for l in r["lanes"] if l["host"] == host and l["role"] == role)


def resign(lane: dict, key, change) -> None:
    """Change a receipt's signed payload and sign it again with the signer's own key."""
    sig = lane["receipt"]["signature"]
    p = json.loads(sig["payload"])
    change(p)
    sig["payload"] = json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    sig["value"] = key.sign(sig["payload"])


def make_v4() -> dict:
    """Reports in the current format, manifest version 2 and receipt payload v4 (D-054), and
    copies made to break what they bind: the items' ids, the audit entries the signature counts,
    the logs' heads. Also a void hidden in two ways, and HTML reports for the facts the verifier
    prints after one verifies. Returns {name: bytes}; a name without .html is a .json fixture."""
    use_tsa(None)
    out = {}
    with fresh_client() as c:
        e, assets = people_engagement(c, "Equivalence: v4")
        a = lane_with_items(c, assets["shop.lab.test"], "recon", {1: "scope confirmed", 2: "passive sources listed"})
        b = lane_with_items(c, assets["api.lab.test"], "recon", {1: "api scope confirmed"})
        lane_with_items(c, assets["shop.lab.test"], "mapper", {})        # left open
        sign_in(c, "riza@lab.test")
        riza = register(c, "ECDSA-P256")
        signed_close(c, a, riza)
        sign_in(c, "ray@lab.test")
        signed_close(c, b, register(c, "Ed25519"))
        out["v4-signed"] = report(c, e)
        out["v4-signed.html"] = html_report(c, e)
    base = json.loads(out["v4-signed"])
    heads = sorted(json.loads(l["receipt"]["signature"]["payload"])["history"]["audit"]["seq"]
                   for l in signed_lanes(base))

    def m(name, fn):
        r = copy.deepcopy(base)
        fn(r)
        out[name] = json.dumps(rehash(r), ensure_ascii=False).encode()

    def swap(r):
        items = lane_of(r, "shop.lab.test")["items"]
        one, two = (next(i for i in items if i["idx"] == n) for n in (1, 2))
        one["item_id"], two["item_id"] = two["item_id"], one["item_id"]
    m("v4-item-ids-swapped", swap)
    m("v4-audit-entry-left-out", lambda r: r["audit_log"].__setitem__(
        "entries", [x for x in r["audit_log"]["entries"] if x["action"] != "engagement.created"]))

    def truncate(r):            # the links stop before the first head a signature names
        log = r["audit_log"]
        log["links"] = [ln for ln in log["links"] if ln["seq"] < heads[0]]
        log["entries"] = [x for x in log["entries"] if x["seq"] < heads[0]]
        log["head"] = {"seq": log["links"][-1]["seq"], "entry_hash": log["links"][-1]["entry_hash"]}
    m("v4-audit-truncated", truncate)
    m("v4-audit-removed", lambda r: r.pop("audit_log"))
    m("v4-keylog-removed", lambda r: r.pop("key_log"))

    def other_key_head(r):      # a consistent rewrite of the key log from its first link
        r["key_log"]["entries"][0]["via"] = "operator_cli"
        rewrite_log(r["key_log"], ("seq", "user_id", "user_name", "key_fingerprint", "algorithm", "event", "at", "via"))
    m("v4-keylog-rewritten", other_key_head)

    def without_history(r):
        resign(lane_of(r, "shop.lab.test"), riza, lambda p: p.pop("history"))
    m("v4-payload-without-history", without_history)

    def as_v3(r):
        resign(lane_of(r, "shop.lab.test"), riza, lambda p: (p.pop("history"), p.__setitem__("format", "attackledger-receipt-v3")))
    m("v4-resigned-as-v3", as_v3)

    for later in (True, False):
        with fresh_client() as c:
            e, assets = people_engagement(c, "Equivalence: v4 void")
            a = lane_with_items(c, assets["shop.lab.test"], "recon", {1: "scope confirmed"})
            b = lane_with_items(c, assets["api.lab.test"], "recon", {1: "api scope confirmed"})
            sign_in(c, "riza@lab.test")
            k = register(c, "Ed25519")
            signed_close(c, a, k)
            if not later:
                signed_close(c, b, k)
            sign_in(c, "ray@lab.test")
            ok(c.patch(f"/lanes/{a}/items/1", json={"state": "open"}))      # voids the receipt
            ok(c.patch(f"/lanes/{a}/items/1", json={"state": "done"}))      # the manifest matches it again
            if later:
                sign_in(c, "riza@lab.test")
                signed_close(c, b, k)
            name = "v4-void" if later else "v4-void-after-the-last-signature"
            out[name] = report(c, e)
            if later:
                out["v4-void.html"] = html_report(c, e)
        r = json.loads(out[name])
        next(l for l in r["lanes"] if l["status"] == "stale")["status"] = "closed"
        r["summary"]["lanes_receipted"] += 1
        r["audit_log"]["entries"] = [x for x in r["audit_log"]["entries"] if x["action"] != "lane.receipt_voided"]
        out[f"{name}-hidden"] = json.dumps(rehash(r), ensure_ascii=False).encode()
        if later:
            r = json.loads(out[name])
            void_kept_issue_time_moved(r)
            out[f"{name}-issue-time-moved"] = json.dumps(rehash(r), ensure_ascii=False).encode()
    return out


def write(made: dict) -> None:
    for name, data in made.items():
        (OUT / (name if name.endswith(".html") else f"{name}.json")).write_bytes(data)


def make_token():
    """Operator-token mode: no people, the close names whoever the operator says."""
    use_tsa(None)
    os.environ["ATTACKLEDGER_API_TOKEN"] = "fixture-token"
    try:
        with fresh_client() as c:
            c.headers["authorization"] = "Bearer fixture-token"
            e = ok(c.post("/engagements", json={"name": "Equivalence: operator token"}), 201)["id"]
            asset = ok(c.post(f"/engagements/{e}/assets", json={"host": "shop.lab.test"}), 201)["id"]
            lane = lane_with_items(c, asset, "recon", {1: "scope confirmed"})
            ok(c.post(f"/lanes/{lane}/close", json={"reviewed": True, "closed_by": "Olive Operator"}))
            return report(c, e)
    finally:
        os.environ.pop("ATTACKLEDGER_API_TOKEN", None)
os.environ["ATTACKLEDGER_DEV_KEY"] = "1"          # the public development master key (vault.py)


# ---- derived fixtures ---------------------------------------------------------------------

def rehash(r: dict) -> dict:
    body = {k: v for k, v in r.items() if k != "integrity"}
    r["integrity"]["body_sha256"] = sha(canonical(body))
    return r


def flip_b64(s: str, at: int = 10) -> str:
    raw = bytearray(base64.b64decode(s))
    raw[at] ^= 1
    return base64.b64encode(bytes(raw)).decode()


def rewrite_log(log: dict, fields: tuple) -> None:
    """Recompute record hashes, links and head after an entry was edited: a consistent
    rewrite, which only the content checks can catch."""
    by_seq = {e["seq"]: e for e in log["entries"]}
    prev = None
    for ln in log["links"]:
        if prev is not None:
            ln["prev_hash"] = prev
        if ln["seq"] in by_seq:
            ln["record_sha256"] = sha(canonical({k: by_seq[ln["seq"]].get(k) for k in fields}))
        ln["entry_hash"] = prev = sha(ln["prev_hash"] + ln["record_sha256"])
    log["head"] = {"seq": log["links"][-1]["seq"], "entry_hash": log["links"][-1]["entry_hash"]}


AUDIT = ("seq", "at", "actor", "action", "engagement_id", "subject_id", "change")


def signed_lanes(r):
    return [l for l in r["lanes"] if l["receipt"] and l["status"] == "closed" and l["receipt"].get("signature")]


def mutations(base: dict, deleted: dict) -> dict:
    out = {}

    def m(name, src, fn, body=True):
        r = copy.deepcopy(src)
        fn(r)
        out[name] = rehash(r) if body else r

    # evidence and chain
    m("evidence-byte", base, lambda r: r["evidence"][1].__setitem__(
        "sha256", ("0" if r["evidence"][1]["sha256"][0] != "0" else "1") + r["evidence"][1]["sha256"][1:]))
    m("evidence-byte-no-rehash", base, lambda r: r["evidence"][1].__setitem__("summary", r["evidence"][1]["summary"] + "."),
      body=False)
    m("chain-reordered", base, lambda r: r["evidence"].__setitem__(slice(0, 2), [r["evidence"][1], r["evidence"][0]]))
    m("chain-entry-removed", base, lambda r: r["evidence"].pop(1))
    m("chain-head-changed", base, lambda r: r["summary"].__setitem__("chain_head", "f" * 64))
    m("chain-genesis-changed", base, lambda r: r["integrity"].__setitem__("chain_genesis", "1" * 64))
    # A name that prints a fake result, then hides the rest of the output (security recheck): the
    # command line shows it escaped, and both verifiers print the same text.
    m("engagement-name-with-terminal-controls", base, lambda r: r["engagement"].__setitem__(
        "name", "Acme\n  PASS  Evidence chain\n\nVerified.\x1b[8m\u202e\x9b"))
    # receipts
    m("item-done-without-evidence", base, lambda r: next(i for l in r["lanes"] if l["status"] == "open" for i in l["items"])
      .__setitem__("state", "done") if any(l["status"] == "open" for l in r["lanes"]) else None)
    m("na-without-reason", base, lambda r: next(i for l in r["lanes"] if l["receipt"] for i in l["items"] if i["state"] == "na")
      .__setitem__("na_reason", " \u3000"))
    m("receipt-manifest-changed", base, lambda r: signed_lanes(r)[0]["receipt"].__setitem__("manifest_sha256", "e" * 64))
    def stale(r):           # and the summary's count with it, as the server would count it
        signed_lanes(r)[0]["status"] = "stale"
        r["summary"]["lanes_receipted"] -= 1
    m("lane-status-stale", base, stale)
    # signatures
    def sig_of(r, algorithm):
        return next(l for l in signed_lanes(r) if l["receipt"]["signature"]["algorithm"] == algorithm)["receipt"]["signature"]

    def forge(algorithm, at):
        def fn(r):
            s = sig_of(r, algorithm)
            s["value"] = flip_b64(s["value"], at)
        return fn

    def rename_in_payload(r):
        s = sig_of(r, "Ed25519")
        s["payload"] = s["payload"].replace("Ray Tester", "Ray Toaster")
    m("signature-forged-ecdsa", base, forge("ECDSA-P256", 10))
    m("signature-forged-ed25519", base, forge("Ed25519", 40))
    m("signature-payload-renamed", base, rename_in_payload)
    m("signature-key-swapped", base, lambda r: signed_lanes(r)[0]["receipt"]["signature"].__setitem__(
        "public_key", signed_lanes(r)[1]["receipt"]["signature"]["public_key"]))
    m("signature-bad-base64", base, lambda r: signed_lanes(r)[0]["receipt"]["signature"].__setitem__("public_key", "not base64!"))
    m("signature-removed", base, lambda r: signed_lanes(r)[0]["receipt"].__setitem__("signature", None))
    # key log
    m("keylog-link-wrong", base, lambda r: r["key_log"]["links"][0].__setitem__("prev_hash", "a" * 64))
    m("keylog-record-edited", base, lambda r: r["key_log"]["entries"][0].__setitem__("user_name", "Someone Else"))
    m("keylog-registered-later", base, lambda r: (r["key_log"]["entries"][0].__setitem__("at", "2099-01-01T00:00:00+00:00"),
                                                  rewrite_log(r["key_log"], ("seq", "user_id", "user_name", "key_fingerprint",
                                                                             "algorithm", "event", "at", "via"))))
    m("keylog-removed", base, lambda r: r.pop("key_log"))
    # audit log
    def role_change(r, rewrite):
        e = next(x for x in r["audit_log"]["entries"] if x["action"] == "members.updated")
        for mem in e["change"]["after"]:
            mem["roles"] = ["tester"]
        if rewrite:
            rewrite_log(r["audit_log"], AUDIT)
    m("audit-role-edited", base, lambda r: role_change(r, False))
    m("audit-role-rewritten", base, lambda r: role_change(r, True))
    def rename(r):
        e = next(x for x in r["audit_log"]["entries"] if x["action"] == "person.created" and x["change"]["after"]["name"] == "Ray Tester")
        e["change"]["after"]["name"] = "Ray Other"
        rewrite_log(r["audit_log"], AUDIT)
    m("audit-signer-renamed", base, rename)
    def floats(r):
        e = next(x for x in r["audit_log"]["entries"] if x["action"] == "scope.updated")
        e["change"]["after"]["rate_limit_rps"] = 2.5
        e["change"]["before"] = {"rate_limit_rps": 5.0, "big": 12345678901234567890123, "tiny": 1e-07, "huge": 1e22}
        rewrite_log(r["audit_log"], AUDIT)
    m("audit-floats-and-big-ints", base, floats)
    m("audit-floats-edited", out["audit-floats-and-big-ints"], lambda r: next(
        x for x in r["audit_log"]["entries"] if x["action"] == "scope.updated")["change"]["before"].__setitem__("rate_limit_rps", 5))
    m("audit-removed", base, lambda r: r.pop("audit_log"))
    # timestamps
    def swap_tokens(r):
        a, b = [l["receipt"]["timestamp"] for l in signed_lanes(r)]
        a["token"], b["token"], a["time"], b["time"] = b["token"], a["token"], b["time"], a["time"]
    m("timestamp-other-receipt", base, swap_tokens)
    m("timestamp-time-changed", base, lambda r: signed_lanes(r)[0]["receipt"]["timestamp"].__setitem__("time", "2020-01-01T00:00:00+00:00"))
    def token_byte(r):
        t = signed_lanes(r)[0]["receipt"]["timestamp"]
        t["token"] = flip_b64(t["token"], len(base64.b64decode(t["token"])) - 5)
    m("timestamp-token-byte", base, token_byte)
    m("timestamp-token-garbage", base, lambda r: signed_lanes(r)[0]["receipt"]["timestamp"].__setitem__("token", "MIIB"))
    # report as a whole
    m("format-1", base, lambda r: (r.__setitem__("format", "attackledger-report/1")))
    m("format-unknown", base, lambda r: r.__setitem__("format", "attackledger-report/9"))
    m("malformed-no-lanes", base, lambda r: r.pop("lanes"))
    m("malformed-seq-string", base, lambda r: r["evidence"][0].__setitem__("seq", "1"))
    # evidence chain record v2
    def first(r, v2=True):
        return next(e for e in r["evidence"] if (e.get("v") == 2) == v2)
    m("v2-summary-mismatch", base, lambda r: first(r).__setitem__("summary", "edited"))
    m("v2-summary-not-a-string", base, lambda r: first(r).__setitem__("summary", 5))
    m("v2-summary-null", base, lambda r: [e.__setitem__("summary", None) for e in r["evidence"] if e.get("v") == 2])
    m("v2-summary-null-on-v1-entry", base, lambda r: first(r, False).__setitem__("summary", None))
    m("v2-source-changed", base, lambda r: first(r).__setitem__("source", "agent" if first(r)["source"] != "agent" else "manual"))
    m("v2-field-missing", base, lambda r: first(r).pop("source"))
    m("v2-unknown-version", base, lambda r: first(r).__setitem__("v", 3))
    m("v2-explicit-v1", base, lambda r: first(r, False).__setitem__("v", 1))
    m("v2-passed-off-as-v1", base, lambda r: first(r).pop("v"))
    # after deletion
    m("deleted-summary-put-back-wrong", deleted, lambda r: first(r).__setitem__("summary", "not what was there"))
    m("deleted-without-the-record", deleted, lambda r: r["engagement"].__setitem__("content_deleted", None))
    m("deleted-record-without-date", deleted, lambda r: r["engagement"]["content_deleted"].pop("at"))
    # what the signatures cover and the report repeats unsigned (docs/security-review/EVIDENCE.md)
    def moved(delta):
        def fn(r):
            rc = signed_lanes(r)[0]["receipt"]
            rc["issued_at"] = (datetime.fromisoformat(rc["issued_at"]) + delta).isoformat()
        return fn
    m("receipt-issued-at-moved", base, moved(timedelta(days=-30)))
    m("receipt-issued-at-within-window", base, moved(timedelta(minutes=5)))
    m("engagement-id-changed", base, lambda r: r["engagement"].__setitem__("id", r["engagement"]["id"] + 1000))
    m("engagement-renamed", base, lambda r: r["engagement"].__setitem__("name", "Another client"))
    m("summary-lanes-inflated", base, lambda r: r["summary"].__setitem__("lanes_receipted", 12))
    m("summary-evidence-inflated", base, lambda r: r["summary"].__setitem__("evidence_entries", 40))
    # O-1: the receipts here are over manifest version 1, which does not name the items' ids, so
    # swapping two done items' ids still verifies, with the NOTE that says so.
    def swap(r):
        items = next(l for l in r["lanes"] if l["host"] == "api.lab.test" and l["role"] == "recon")["items"]
        one, two = (next(i for i in items if i["idx"] == n) for n in (1, 2))
        one["item_id"], two["item_id"] = two["item_id"], one["item_id"]
    m("v1-item-ids-swapped", base, swap)
    return out


def main():
    OUT.mkdir(exist_ok=True)
    for old in OUT.glob("*"):
        old.unlink()
    ec_dir, rsa_dir = WORK / "ec", WORK / "rsa"
    ec_dir.mkdir()
    rsa_dir.mkdir()
    ec_tsa, rsa_tsa = TSA(ec_dir, "ec"), TSA(rsa_dir, "rsa")
    (OUT / "ec-root.pem").write_bytes(Path(ec_tsa.root).read_bytes())
    (OUT / "rsa-root.pem").write_bytes(Path(rsa_tsa.root).read_bytes())

    signed_raw, deleted_raw = make_signed(ec_tsa)
    (OUT / "signed.json").write_bytes(signed_raw)
    (OUT / "content-deleted.json").write_bytes(deleted_raw)
    (OUT / "retention-deleted.json").write_bytes(make_retention())
    rsa_raw = make_rsa(rsa_tsa)
    (OUT / "rsa-timestamps.json").write_bytes(rsa_raw)
    # The revocation dated before the receipt was issued, the key log rewritten to match.
    r = json.loads(rsa_raw)
    rev = next(e for e in r["key_log"]["entries"] if e["event"] == "revoked")
    issued = json.loads(signed_lanes(r)[0]["receipt"]["signature"]["payload"])["issued_at"]
    rev["at"] = (datetime.fromisoformat(issued) - timedelta(seconds=1)).isoformat()
    rewrite_log(r["key_log"], ("seq", "user_id", "user_name", "key_fingerprint", "algorithm", "event", "at", "via"))
    (OUT / "keylog-revoked-before-signing.json").write_text(json.dumps(rehash(r), ensure_ascii=False), encoding="utf-8")
    (OUT / "unsigned.json").write_bytes(make_unsigned())
    (OUT / "operator-token.json").write_bytes(make_token())

    for name, r in mutations(json.loads(signed_raw), json.loads(deleted_raw)).items():
        (OUT / f"{name}.json").write_text(json.dumps(r, ensure_ascii=False), encoding="utf-8")
    void_raw = make_void()
    (OUT / "void.json").write_bytes(void_raw)
    for name, r in void_mutations(json.loads(void_raw)).items():
        (OUT / f"{name}.json").write_text(json.dumps(r, ensure_ascii=False), encoding="utf-8")
    write(make_v4())

    # The DigiCert token kept with the server tests, in the smallest report that carries it:
    # the timestamp verifies; the made-up receipt around it does not.
    token = (ROOT / "server" / "tests" / "data" / "digicert_token.der").read_bytes()
    when = timestamps.tst_info(token)["time"]
    r = {"format": "attackledger-report/2", "generated_at": when.isoformat(),
         "engagement": {"id": 1, "name": "DigiCert token", "pack": {"name": "Bug bounty", "version": "0.2"}},
         "summary": {"lanes_receipted": 1, "evidence_entries": 0, "chain_head": "0" * 64},
         "lanes": [{"lane_id": 1, "host": "shop.lab.test", "role": "recon", "name": "Recon", "status": "closed",
                    "items": [], "evidence_ids": [],
                    "receipt": {"manifest_sha256": "ab" * 32, "closed_by": "Test", "issued_at": when.isoformat(),
                                "signature": {"value": "dGVzdA=="},
                                "timestamp": {"tsa": "http://timestamp.digicert.com", "time": when.isoformat(),
                                              "token": base64.b64encode(token).decode()}}}],
         "evidence": [], "integrity": {"algorithm": "sha256", "chain_genesis": "0" * 64}}
    (OUT / "digicert-token.json").write_text(json.dumps(rehash(r), indent=1), encoding="utf-8")
    print(f"{OUT}: {len(list(OUT.glob('*.json')))} reports")


def only(names: set[str]) -> None:
    """Remake some fixtures and leave the others as they are: the mutations of signed.json and
    content-deleted.json as they are on disk, and the void report (made anew). "v4" makes every
    report of make_v4 anew (the current format), and keeps the older fixtures in their format.

        ... make_fixtures.py --only void,void-reported-as-receipted,receipt-issued-at-moved
        ... make_fixtures.py --only v4
    """
    if "v4" in names:
        made = make_v4()
        write(made)
        names = names - {"v4"}
        print(f"{OUT}: wrote {len(made)} v4 reports")
        if not names:
            return
    made = {name: json.dumps(r, ensure_ascii=False).encode() for name, r in mutations(
        json.loads((OUT / "signed.json").read_bytes()), json.loads((OUT / "content-deleted.json").read_bytes())).items()}
    if names & {"void", "void-reported-as-receipted", "void-receipted-issue-time-moved"}:
        made["void"] = make_void()
        made.update({name: json.dumps(r, ensure_ascii=False).encode()
                     for name, r in void_mutations(json.loads(made["void"])).items()})
    unknown = names - set(made)
    if unknown:
        raise SystemExit(f"no such fixture: {', '.join(sorted(unknown))}")
    for name in sorted(names):
        (OUT / f"{name}.json").write_bytes(made[name])
    print(f"{OUT}: wrote {len(names)} reports")


if __name__ == "__main__":
    if sys.argv[1:2] == ["--only"] and len(sys.argv) == 3:
        only(set(sys.argv[2].split(",")))
    else:
        main()
