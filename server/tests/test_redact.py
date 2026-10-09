"""Redaction of sensitive values before raw evidence is stored (redact.py, D-038).

Unit tests for every rule, including what must stay as it is, then end to end: an agent's
HTTP exchange, notes and files attached by people, recon output, and the setting that
turns it off. The end-to-end tests read every file in the blob store and check that no
secret byte reached it."""
import base64
import hashlib
import json
import time

import pytest
from sqlalchemy import select

from app import blobs, ledger, redact, vault
from app.models import Endpoint, Engagement, Evidence, Job, JobStatus, Lead, Observation
from test_agent import HOST, FakeTransport, api, api_lane, get, load_worker, make_lane, session, toolbox  # noqa: F401

JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


def red(s: str, personal: bool = False) -> tuple[str, redact.Report]:
    rep = redact.Report()
    return redact.text(s, rep, personal=personal), rep


def m(value: str) -> str:
    return redact.marker(value)


# ---- the marker ---------------------------------------------------------------

def test_marker_is_a_short_hash_that_correlates_without_the_value():
    assert m("s3cret") == f"[redacted:sha256:{hashlib.sha256(b's3cret').hexdigest()[:12]}]"
    out, rep = red("a?token=s3cret b?api_key=s3cret")
    assert out == f"a?token={m('s3cret')} b?api_key={m('s3cret')}"       # same value, same marker
    assert "s3cret" not in json.dumps(rep.as_dict()) and rep.count == 2


def test_report_counts_kinds_never_values_and_the_summary_note():
    _, rep = red("Cookie: a=1; b=2\nAuthorization: Basic dXNlcjpwYXNz\nGET /?access_token=xyz")
    assert rep.as_dict() == {"redacted": 4, "kinds": ["Cookie", "Authorization", "access_token"], "not_redacted": []}
    assert rep.suffix() == " [4 values redacted: Cookie, Authorization, access_token]"
    assert redact.Report().suffix() == ""
    assert redact.Report(off=True).suffix() == " [not redacted: redaction is off for this engagement]"
    many = redact.Report()
    for k in "abcdefgh":
        many.add(k)
    assert many.suffix() == " [8 values redacted: a, b, c, d, e, f and 2 more]"


def test_a_value_already_redacted_is_not_redacted_again():
    once, _ = red("Authorization: Bearer " + JWT)
    twice, rep = red(once)
    assert twice == once and rep.count == 0


# ---- headers --------------------------------------------------------------------

def hv(name, value):
    rep = redact.Report()
    return redact.header_value(name, value, rep), rep


def test_authorization_keeps_the_scheme():
    assert hv("Authorization", f"Bearer {JWT}")[0] == f"Bearer {m(JWT)}"
    assert hv("authorization", "Basic dXNlcjpwYXNz")[0] == f"Basic {m('dXNlcjpwYXNz')}"
    assert hv("Proxy-Authorization", "Basic Zm9vOmJhcg==")[0] == f"Basic {m('Zm9vOmJhcg==')}"
    assert hv("Authorization", "rawtoken123")[0] == m("rawtoken123")


def test_cookie_values_go_names_and_attributes_stay():
    assert hv("Cookie", "sid=abc123; theme=dark")[0] == f"sid={m('abc123')}; theme={m('dark')}"
    out, rep = hv("Set-Cookie", "session=xyz789; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT; HttpOnly; Secure")
    assert out == f"session={m('xyz789')}; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT; HttpOnly; Secure"
    assert rep.as_dict()["kinds"] == ["Set-Cookie"]
    joined, rep = hv("set-cookie", "a=1; Path=/, b=2; Max-Age=60")      # two cookies folded into one header
    assert joined == f"a={m('1')}; Path=/, b={m('2')}; Max-Age=60" and rep.count == 2


@pytest.mark.parametrize("name", ["X-Api-Key", "X-Auth-Token", "X-CSRF-Token", "X-XSRF-TOKEN", "X-Access-Token",
                                  "X-Amz-Security-Token", "Api-Key", "X-Session-Id", "X-Client-Secret",
                                  "X-Password", "x-apikey", "Refresh-Token"])
def test_secret_headers_are_replaced_whole(name):
    out, rep = hv(name, "v4lue-9")
    assert out == m("v4lue-9") and rep.as_dict()["kinds"] == [name]


@pytest.mark.parametrize("name,value", [
    ("Content-Type", "application/json"), ("Host", "shop.lab.test"), ("Sec-WebSocket-Key", "dGhlIHNhbXBsZQ=="),
    ("Access-Control-Allow-Headers", "Authorization, X-Api-Key, X-CSRF-Token"),
    ("Access-Control-Allow-Credentials", "true"), ("Vary", "Cookie"), ("X-Request-Id", "42"),
    ("Keynote", "v1"), ("Content-Security-Policy", "default-src 'self'"),
])
def test_ordinary_headers_stay(name, value):
    assert hv(name, value)[0] == value


def test_identification_header_is_kept_even_if_its_name_looks_secret():
    rep = redact.Report()
    sent = {"X-Research-Token": "lab-researcher", "User-Agent": "lab (r1)", "X-Api-Key": "k-123"}
    out = redact.headers(sent, rep, keep={"X-Research-Token": "lab-researcher", "User-Agent": "x"})
    assert out == {"X-Research-Token": "lab-researcher", "User-Agent": "lab (r1)", "X-Api-Key": m("k-123")}
    assert redact.headers([("Set-Cookie", "a=b"), ("Server", "x")], rep) == [["Set-Cookie", f"a={m('b')}"], ["Server", "x"]]


def test_header_lines_in_text():
    raw = "GET / HTTP/1.1\r\nHost: shop\r\nCookie: sid=abc\r\nX-Auth-Token: t0k\r\nSession: tested on Monday\r\n\r\n"
    out, _ = red(raw)
    assert out == f"GET / HTTP/1.1\r\nHost: shop\r\nCookie: sid={m('abc')}\r\nX-Auth-Token: {m('t0k')}\r\nSession: tested on Monday\r\n\r\n"
    assert red("api_key: AbC123xyz\nToken: none found")[0] == f"api_key: {m('AbC123xyz')}\nToken: none found"


# ---- query strings and form bodies --------------------------------------------------

@pytest.mark.parametrize("name", ["token", "access_token", "id_token", "refresh_token", "api_key", "apikey", "apiKey",
                                  "key", "secret", "client_secret", "password", "passwd", "pwd", "session", "sid",
                                  "code", "signature", "sig", "SESSIONID", "X-Amz-Signature", "user[password]",
                                  "csrf_token", "auth"])
def test_secret_parameters(name):
    out, rep = red(f"https://shop.lab.test/cb?page=2&{name}=V4lue_9&lang=en")
    assert out == f"https://shop.lab.test/cb?page=2&{name}={m('V4lue_9')}&lang=en"
    assert rep.as_dict()["kinds"] == [name]


@pytest.mark.parametrize("name", ["keynote", "monkey", "id", "page", "state", "zip_code", "description", "author",
                                  "passage", "redirect_uri", "q", "keyword"])
def test_ordinary_parameters_stay(name):
    s = f"https://shop.lab.test/?{name}=hello&x=1"
    out, rep = red(s)
    assert out == s and rep.count == 0


def test_form_bodies_quoted_values_and_comparisons():
    assert red("user=alice&password=hunter2&remember=1")[0] == f"user=alice&password={m('hunter2')}&remember=1"
    assert red('token="abc" secret=\'d e\'')[0] == f'token="{m("abc")}" secret=\'{m("d e")}\''
    assert red("if (token==null) x = token;")[0] == "if (token==null) x = token;"
    assert red("token=&key=")[0] == "token=&key="           # empty values: nothing to hide


# ---- JSON -------------------------------------------------------------------------

def test_json_keys_at_any_depth_keep_the_document_byte_for_byte():
    doc = ('{"user": {"name": "alice", "password":"hunter2", "prefs": {"refresh_token": "r-1", "theme": "dark"}},\n'
           ' "apiKey": 12345, "tokens": ["a1", "b2"], "code": 400, "keynote": "k", "ok": true}')
    out, rep = red(doc)
    assert out == ('{"user": {"name": "alice", "password":"' + m("hunter2") + '", "prefs": {"refresh_token": "'
                   + m("r-1") + '", "theme": "dark"}},\n "apiKey": "' + m("12345") + '", "tokens": ["' + m("a1")
                   + '", "' + m("b2") + '"], "code": 400, "keynote": "k", "ok": true}')
    assert json.loads(out)["user"]["name"] == "alice"       # still valid JSON
    assert rep.count == 5


def test_har_style_header_objects():
    har = '{"headers": [{"name": "Cookie", "value": "sid=abc"}, {"name": "Accept", "value": "*/*"}, ' \
          '{"name": "Authorization", "value": "Bearer zzz111"}]}'
    out, _ = red(har)
    assert f'"value": "sid={m("abc")}"' in out and '"value": "*/*"' in out and f'"Bearer {m("zzz111")}"' in out


# ---- credential formats ---------------------------------------------------------------

def test_jwt_anywhere_in_text():
    out, rep = red(f"the page embeds {JWT} in a script")
    assert out == f"the page embeds {m(JWT)} in a script" and rep.as_dict()["kinds"] == ["JWT"]
    assert red("eyJhbGciOi is not a token")[1].count == 0


def test_private_keys_aws_ids_and_vendor_tokens():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabcd\n-----END RSA PRIVATE KEY-----"
    assert red(f"key:\n{pem}\nend")[0] == f"key:\n{m(pem)}\nend"
    cut = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nThe rest was cut."
    assert red(cut)[0] == m(cut.rsplit("\n", 1)[0]) + "\nThe rest was cut."
    assert red("id AKIAIOSFODNN7EXAMPL3 here")[0] == f"id {m('AKIAIOSFODNN7EXAMPL3')} here"
    gh = "ghp_" + "a" * 36
    sk = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
    out, rep = red(f"{gh} {sk}")
    assert out == f"{m(gh)} {m(sk)}" and set(rep.kinds) == {"GitHub token", "Stripe secret or restricted live key"}


def test_publishable_keys_are_public_and_stay():
    for s in ("pk_live_" + "a" * 24, "AIza" + "b" * 35):
        assert red(s)[0] == s


def test_bearer_tokens_and_passwords_in_urls():
    assert red("send Bearer abcdefghijklmnop1234 now")[0] == f"send Bearer {m('abcdefghijklmnop1234')} now"
    assert red("Bearer token-based-authentication is used")[1].count == 0
    scheme = "postgres" + "://"        # split so secret scanners do not take the fixture for a real URL
    assert red(scheme + "app:pa55@db.internal:5432/x")[0] == f"{scheme}app:{m('pa55')}@db.internal:5432/x"
    assert red("https://shop.lab.test:8443/a@b")[1].count == 0


# ---- personal data ------------------------------------------------------------------

def test_emails_and_card_numbers_only_when_asked():
    s = "contact alice@example.com, card 4111111111111111 or 4111 1111 1111 1111, amex 3782-822463-10005"
    out, rep = red(s, personal=True)
    assert out == (f"contact {m('alice@example.com')}, card {m('4111111111111111')} or {m('4111 1111 1111 1111')}, "
                   f"amex {m('3782-822463-10005')}")
    assert rep.as_dict()["kinds"] == ["email address", "card number"]
    assert red(s)[0] == s                                   # summaries and notes: secrets only


# 1696800000006 (a time in milliseconds) and 1234567890123456785 pass the Luhn check: the first digit keeps them.
@pytest.mark.parametrize("s", ["4111111111111112", "1696800000006", "id 1234567890123456785", "3.14159265358979323",
                               "v1.2.3@4.5", "core-js@3.2.1"])
def test_not_card_numbers_or_emails(s):
    assert red(s, personal=True)[0] == s


def test_luhn():
    assert redact.luhn("4111111111111111") and redact.luhn("378282246310005")
    assert not redact.luhn("4111111111111112")


# ---- bytes ----------------------------------------------------------------------------

def test_bytes_are_kept_exactly_around_what_is_redacted():
    text = b"Latin-1 caf\xe9 and plain words around it, " * 3
    raw = text + b"token=abc \x80 end"                     # not valid UTF-8: kept byte for byte
    rep = redact.Report()
    out = redact.data(raw, rep)
    assert out == text + b"token=" + m("abc").encode() + b" \x80 end" and rep.count == 1
    clean = "Ünïcode text, nothing to hide.\n".encode() * 100
    assert redact.data(clean, rep) is clean


def test_binary_content_is_stored_as_is_and_noted():
    rep = redact.Report()
    png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR token=abc"
    assert redact.data(png, rep) == png and rep.not_redacted == ["binary content"]
    rep = redact.Report()
    mostly_text = b"\x00" + b"token=abc " * 50              # one NUL byte: not a text format
    assert redact.data(mostly_text, rep) == mostly_text and rep.count == 0
    rep = redact.Report()
    assert redact.data(b"token=abc", rep, filename="shot.PNG") == b"token=abc"
    assert rep.suffix() == " [not redacted: binary content]"


def test_redaction_is_linear_on_large_recon_output():
    line = ("https://shop.lab.test/p/{n}?page={n}&utm_source=x&access_token=tok{n}&q=a+b "
            '{{"id": {n}, "name": "item", "email": "u{n}@example.com", "secret": "s{n}"}} plain words here\n')

    def timed(n_lines):
        s = "".join(line.format(n=n) for n in range(n_lines))
        t = time.perf_counter()
        out = redact.text(s, redact.Report(), personal=True)
        return time.perf_counter() - t, len(s), out
    small, _, _ = timed(5_000)
    big, size, out = timed(20_000)                          # about 4 MB
    assert size > 3_000_000 and "tok19999" not in out and "u19999@example.com" not in out
    assert big < 15 and big / small < 8                     # 4x the input, not 16x the time
    for evil in ("=" * 500_000, '"' * 500_000, "eyJ" * 200_000, "4" * 500_000, "a@" * 300_000,
                 "-----BEGIN PRIVATE KEY-----" * 20_000, '"token": [' * 50_000):
        t = time.perf_counter()
        redact.text(evil, redact.Report(), personal=True)
        assert time.perf_counter() - t < 5, evil[:20]


# ---- end to end: the agent's HTTP exchange -----------------------------------------------

def all_blob_bytes() -> bytes:
    """Every stored blob as plaintext: encrypted ones are opened with their engagement's key,
    so a secret cannot hide from this check behind the encryption."""
    out = []
    for p in blobs.root().rglob("*"):
        if not p.is_file() or p.name in ("key.json", "deleted.json"):
            continue
        rel = p.relative_to(blobs.root()).parts
        if rel[0] == "e":
            data = vault.open_blob(int(rel[1]), p.name, p.read_bytes())
            assert data is not None, p
            out.append(data)
        else:
            out.append(p.read_bytes())
    return b"".join(out)


SESSION_SECRET = "Zx9SessionValue771"
BEARER_SECRET = "agentBearerToken12345"


def test_agent_exchange_stores_no_secret_value(session):
    lane, job = make_lane(session)
    body = json.dumps({"access_token": "AccessTok3n999", "user": "alice@example.com", "items": [1, 2]}).encode()
    t = FakeTransport(body=body, headers=[("Content-Type", "application/json"),
                                          ("Set-Cookie", f"sid={SESSION_SECRET}; Path=/; HttpOnly")])
    tb = toolbox(session, lane, job, transport=t)
    res, err = get(tb, f"https://{HOST}/api/me?session={SESSION_SECRET}",
                   [{"name": "Authorization", "value": f"Bearer {BEARER_SECRET}"}])
    assert not err
    sent = t.calls[0]
    assert sent["headers"]["Authorization"] == f"Bearer {BEARER_SECRET}"          # sent as asked...
    assert sent["headers"]["X-Bug-Bounty"] == "lab-researcher"
    stored = all_blob_bytes()                                                     # ...never stored
    for secret in (SESSION_SECRET, BEARER_SECRET, "AccessTok3n999", "alice@example.com"):
        assert secret.encode() not in stored
        assert secret not in json.dumps(res)                                      # nor shown to the model
    raw = blobs.get(tb.exchanges["x1"]["sha256"], engagement_id=tb.eng.id)
    meta = json.loads(raw.split(b"\n\n", 1)[0])
    assert meta["request"]["headers"]["X-Bug-Bounty"] == "lab-researcher"         # identification stays
    assert meta["request"]["headers"]["Authorization"] == f"Bearer {m(BEARER_SECRET)}"
    assert dict(meta["response"]["headers"])["Set-Cookie"] == f"sid={m(SESSION_SECRET)}; Path=/; HttpOnly"
    assert meta["redaction"]["redacted"] == 5 and "redacted" in res
    assert json.loads(raw.split(b"\n\n", 1)[1])["items"] == [1, 2]

    tb.call("add_evidence", {"item_idx": 1, "exchange_ids": ["x1"], "summary": "Profile endpoint answers."})
    session.commit()
    ev = session.scalars(select(Evidence)).one()
    assert vault.summary_of(ev).endswith("Profile endpoint answers. [5 values redacted: session, Authorization, "
                               "Set-Cookie, access_token, email address]")
    assert SESSION_SECRET not in vault.summary_of(ev) and SESSION_SECRET not in ev.uri
    assert ev.redaction == {"redacted": 5, "kinds": ["session", "Authorization", "Set-Cookie", "access_token",
                                                     "email address"], "not_redacted": []}
    assert ev.sha256 == hashlib.sha256(raw).hexdigest()                           # the hash is of the stored bytes
    rec = {**ledger.evidence_record(ev, HOST, "recon"), "prev_hash": ev.prev_hash, "chain_hash": ev.chain_hash}
    assert ledger.verify_chain([rec]) == []


def test_agent_note_and_lead_are_redacted_and_binary_bodies_noted(session):
    lane, job = make_lane(session)
    tb = toolbox(session, lane, job, transport=FakeTransport(body=b"\x89PNG\r\n\x1a\n\x00\x00token=abc"))
    get(tb, f"https://{HOST}/logo.png")
    tb.call("add_evidence", {"item_idx": 1, "exchange_ids": ["x1"], "summary": "Logo."})
    tb.call("add_evidence", {"item_idx": 2, "exchange_ids": [], "summary": f"Saw {JWT} in the page."})
    tb.call("record_lead", {"title": "JWT exposed", "detail": f"value {JWT}", "severity": "", "url": ""})
    session.commit()
    logo, note = session.scalars(select(Evidence).order_by(Evidence.seq)).all()
    assert vault.summary_of(logo).endswith("Logo. [not redacted: binary response body]")
    assert vault.summary_of(note) == f"[agent] Saw {m(JWT)} in the page. [1 value redacted: JWT]"
    assert blobs.get(note.sha256, engagement_id=note.engagement_id) == f"Saw {m(JWT)} in the page.".encode()
    assert JWT not in session.scalars(select(Lead)).one().detail["text"]


def test_agent_with_redaction_off_stores_as_captured(session):
    lane, job = make_lane(session)
    lane.asset.engagement.redact_evidence = False
    session.commit()
    tb = toolbox(session, lane, job, transport=FakeTransport(headers=[("Set-Cookie", f"sid={SESSION_SECRET}")]))
    get(tb, f"https://{HOST}/")
    tb.call("add_evidence", {"item_idx": 1, "exchange_ids": ["x1"], "summary": "Home."})
    session.commit()
    assert SESSION_SECRET.encode() in all_blob_bytes()
    ev = session.scalars(select(Evidence)).one()
    assert vault.summary_of(ev).endswith("Home. [not redacted: redaction is off for this engagement]")
    assert ev.redaction["not_redacted"] == ["redaction is off for this engagement"]


# ---- end to end: people attach notes and files ---------------------------------------------

def test_attached_note_with_a_jwt_is_masked(api):
    e, lane = api_lane(api)
    r = api.post(f"/lanes/{lane}/attach", json={"item_idx": 1, "kind": "note",
                                                 "text": f"Login returns {JWT} in the body."})
    ev = r.json()["evidence"][-1]
    assert ev["summary"] == f"Login returns {m(JWT)} in the body. [1 value redacted: JWT]"
    assert ev["redaction"] == {"redacted": 1, "kinds": ["JWT"], "not_redacted": []}
    assert JWT.encode() not in all_blob_bytes() and api.get(f"/blobs/{ev['sha256']}").text == f"Login returns {m(JWT)} in the body."
    # A note with nothing to hide is stored exactly, without a note in its summary.
    ev = api.post(f"/lanes/{lane}/attach", json={"item_idx": 1, "kind": "note", "text": "robots.txt lists /backup/"}).json()["evidence"][-1]
    assert ev["summary"] == "robots.txt lists /backup/" and blobs.get(ev["sha256"], engagement_id=e) == b"robots.txt lists /backup/"


def test_attached_files_text_redacted_binary_noted(api):
    e, lane = api_lane(api)
    har = json.dumps({"log": {"entries": [{"request": {"headers": [{"name": "Cookie", "value": f"sid={SESSION_SECRET}"}]}}]}})
    r = api.post(f"/lanes/{lane}/attach", json={"item_idx": 1, "kind": "file", "filename": "capture.har",
                                                 "content_b64": base64.b64encode(har.encode()).decode(),
                                                 "summary": "Browser capture of the login."})
    ev = r.json()["evidence"][-1]
    assert ev["summary"] == "Browser capture of the login. [1 value redacted: Cookie]"
    assert SESSION_SECRET.encode() not in all_blob_bytes()
    png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    r = api.post(f"/lanes/{lane}/attach", json={"item_idx": 2, "kind": "file", "filename": "shot.png",
                                                 "content_b64": base64.b64encode(png).decode(), "summary": "Admin panel."})
    ev = r.json()["evidence"][-1]
    assert blobs.get(ev["sha256"], engagement_id=e) == png and ev["summary"] == "Admin panel. [not redacted: binary content]"
    assert ev["redaction"]["not_redacted"] == ["binary content"]


def test_raw_evidence_route_redacts_summary_and_uri(api):
    _, lane = api_lane(api)
    digest = hashlib.sha256(b"x").hexdigest()
    api.post(f"/lanes/{lane}/evidence", json={"kind": "response", "sha256": digest, "summary": "callback seen",
                                              "uri": "https://shop.lab.test/cb?code=OAuthC0de1"})
    api.post(f"/lanes/{lane}/evidence", json={"kind": "response", "sha256": digest, "summary": "plain"})
    first, second = api.get(f"/lanes/{lane}").json()["evidence"]
    assert first["uri"] == f"https://shop.lab.test/cb?code={m('OAuthC0de1')}"
    assert first["summary"] == "callback seen [1 value redacted: code]" and first["redaction"]["redacted"] == 1
    assert second["summary"] == "plain" and second["redaction"] is None


def test_owner_turns_redaction_off_and_it_shows(api):
    e, lane = api_lane(api)
    assert api.get(f"/engagements/{e}/scope").json()["redact_evidence"] is True          # on by default
    assert api.patch(f"/engagements/{e}", json={"redact_evidence": False}).json()["redact_evidence"] is False
    assert api.get(f"/engagements/{e}/scope").json()["redact_evidence"] is False
    ev = api.post(f"/lanes/{lane}/attach", json={"item_idx": 1, "kind": "note",
                                                  "text": f"token={SESSION_SECRET}"}).json()["evidence"][-1]
    assert blobs.get(ev["sha256"], engagement_id=e) == f"token={SESSION_SECRET}".encode()
    assert ev["summary"] == f"token={SESSION_SECRET} [not redacted: redaction is off for this engagement]"
    report = api.get(f"/engagements/{e}/report").json()
    assert report["engagement"]["redact_evidence"] is False
    assert "Off: raw evidence is stored as captured" in api.get(f"/engagements/{e}/report.html").text


# ---- end to end: recon output ------------------------------------------------------------

def recon_run(session, kind="archive", redact_on=True):
    worker = load_worker()
    e = Engagement(name=f"recon-{kind}-{redact_on}", scope_include=["*.lab.test"], scope_exclude=[],
                   authorized_by="op", redact_evidence=redact_on)
    session.add(e)
    session.commit()
    job = Job(engagement_id=e.id, kind=kind, targets=["lab.test"], status=JobStatus.running)
    session.add(job)
    session.commit()
    return worker, worker.Run(session, job)


def test_recon_urls_leads_and_observations_are_redacted(session):
    worker, r = recon_run(session)
    r.lead_fps = set()
    seen = {f"https://shop.lab.test/reset?token={SESSION_SECRET}&lang=en": {"wayback"},
            "https://shop.lab.test/search?q=keynote": {"gau"}}
    assert worker.store_endpoints(r, seen) == 2
    worker.add_lead(r, "shop.lab.test", f"https://shop.lab.test/x?api_key={SESSION_SECRET}", "nuclei", "Exposed key",
                    detail={"extracted": [f"Authorization: Bearer {BEARER_SECRET}"]})
    r.observe("shop.lab.test", {"location": f"https://shop.lab.test/sso?id_token={JWT}", "status_code": 302})
    session.commit()
    stored = json.dumps([[x.url for x in session.scalars(select(Endpoint))],
                         [[l.source_url, l.detail] for l in session.scalars(select(Lead))],
                         [o.data for o in session.scalars(select(Observation))]])
    for secret in (SESSION_SECRET, BEARER_SECRET, JWT):
        assert secret not in stored
    urls_ = sorted(x.url for x in session.scalars(select(Endpoint)))
    assert urls_ == [f"https://shop.lab.test/reset?token={m(SESSION_SECRET)}&lang=en",
                     "https://shop.lab.test/search?q=keynote"]
    assert r.redacted.count == 4
    # The same URL seen again is the same endpoint: the marker is stable.
    assert worker.store_endpoints(r, {f"https://shop.lab.test/reset?token={SESSION_SECRET}&lang=en": {"gau"}}) == 0


def test_recon_with_redaction_off_stores_urls_as_seen(session):
    worker, r = recon_run(session, redact_on=False)
    worker.store_endpoints(r, {f"https://shop.lab.test/reset?token={SESSION_SECRET}": {"wayback"}})
    session.commit()
    assert session.scalars(select(Endpoint)).one().url.endswith(SESSION_SECRET)
