"""tools/caido_pull.py: pulling HTTP history out of a tester's own Caido (D-029, D-035).

There is no Caido here. A fake Caido GraphQL server on localhost answers the tool's two
queries the way Caido's public schema (v0.58.3) says the real one does: paged with cursors,
filtered by HTTPQL, raw bytes as base64, and errors with Caido's AUTHORIZATION extension.
It also answers wrongly on purpose (a changed schema, a 401, a redirect) to test the
refusals. The tool's output is then imported through the server's Caido adapter, and in one
test uploaded over real HTTP to the API served by uvicorn on localhost. The token used here
is made up for these tests."""
import base64
import importlib.util
import json
import re
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from sqlalchemy import func, select

from app import auth, importers, redact
from app.models import AuditEntry, ImportBatch, InboxEntry, UserSession
from test_import import db, stored_bytes, team, upload  # noqa: F401  (helpers)
from test_people import PW, client, sign_in  # noqa: F401  (fixture and helpers)

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "caido_pull.py"
spec = importlib.util.spec_from_file_location("caido_pull", TOOL)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

TOKEN = "lab-caido-access-0f3c9a1e7b2d4c6e8a0b"     # made up; stands for a tester's Caido token
AL_TOKEN = "lab-attackledger-operator-5d1e9b"
COOKIE = "lab-caido-cookie-11"
BEARER = "lab-app-bearer-token-0123456789abcdef"
QUERY_SECRET = "lab-caido-query-token-12"
SET_COOKIE = "lab-caido-set-cookie-13"
EMAIL = "tess@example.com"
PASSWORD = "lab-caido-password-14"
SECRETS = [COOKIE, BEARER, QUERY_SECRET, SET_COOKIE, EMAIL, PASSWORD]
T0 = 1791540000000      # 2026-10-09T10:00:00Z, in epoch milliseconds


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def node(i, host="shop.example.com", path="/", query="", method="GET", req=None, resp="default", source="INTERCEPT",
         at=None):
    raw = req if req is not None else f"{method} {path}{'?' + query if query else ''} HTTP/1.1\r\nHost: {host}\r\n\r\n"
    n = {"id": str(i), "host": host, "port": 443, "method": method, "path": path, "query": query, "isTls": True,
         "createdAt": T0 + i * 1000 if at is None else at, "source": source, "alteration": "NONE", "edited": False,
         "length": len(raw), "raw": b64(raw) if raw else ""}
    if resp == "default":
        resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"
    n["response"] = None if resp is None else {
        "id": f"r{i}", "statusCode": int(resp.split()[1]) if resp else 200, "roundtripTime": 12, "length": len(resp),
        "createdAt": T0 + i * 1000 + 120, "alteration": "NONE", "edited": False, "raw": b64(resp) if resp else None}
    return n


SEARCH_REQ = (f"GET /rest/products/search?q=apple&session_token={QUERY_SECRET} HTTP/1.1\r\nHost: shop.example.com\r\n"
              f"Cookie: sid={COOKIE}; theme=dark\r\nAuthorization: Bearer {BEARER}\r\n\r\n")
BODY = json.dumps({"user": {"email": EMAIL, "name": "Tess"}})
SEARCH_RESP = (f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: sid={SET_COOKIE}; Path=/; HttpOnly\r\n"
               f"Content-Length: {len(BODY)}\r\n\r\n{BODY}")
LOGIN_BODY = json.dumps({"email": "tess@lab.test", "password": PASSWORD})
LOGIN_REQ = (f"POST /rest/user/login HTTP/1.1\r\nHost: shop.example.com\r\nContent-Type: application/json\r\n"
             f"Content-Length: {len(LOGIN_BODY)}\r\n\r\n{LOGIN_BODY}")


def history():
    return [node(1, path="/rest/products/search", query=f"q=apple&session_token={QUERY_SECRET}", req=SEARCH_REQ,
                 resp=SEARCH_RESP, source="REPLAY"),
            node(2, path="/rest/user/login", method="POST", req=LOGIN_REQ,
                 resp="HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{}"),
            node(3, host="tracker.example.net", path="/collect"),
            node(4, path="/rest/admin/application-version", req="", resp=""),     # Caido kept no raw bytes
            node(5, path="/socket", resp=None)]                                    # no response at all


class FakeCaido:
    """A Caido GraphQL endpoint on 127.0.0.1. `mode` makes it answer wrongly on purpose."""

    def __init__(self, nodes, mode=None, location=None):
        self.nodes, self.mode, self.location, self.seen = nodes, mode, location, []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                fake.seen.append({"path": self.path, "headers": dict(self.headers), "body": body.decode()})
                status, doc, extra = fake.answer(self.path, self.headers, body)
                out = json.dumps(doc).encode() if not isinstance(doc, bytes) else doc
                self.send_response(status)
                for k, v in extra.items():
                    self.send_header(k, v)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            do_GET = do_POST

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    @property
    def queries(self):
        return [json.loads(s["body"]) for s in self.seen if s["body"]]

    def answer(self, path, headers, body):
        if self.mode == "redirect":
            return 307, {}, {"Location": self.location}
        if self.mode == "http401":
            return 401, {"error": "unauthorized"}, {}
        if self.mode == "not-json":
            return 200, b"<html>a login page</html>", {}
        if path != "/graphql":
            return 404, {}, {}
        q = json.loads(body)
        if headers.get("Authorization") != f"Bearer {TOKEN}":
            return 200, {"data": None, "errors": [{"message": "Invalid token", "extensions": {
                "CAIDO": {"code": "AUTHORIZATION", "reason": "INVALID_TOKEN"}}}]}, {}
        if "runtime" in q["query"]:
            return 200, {"data": {"runtime": {"version": "0.58.3"}}}, {}
        if self.mode == "schema":
            return 200, {"data": None, "errors": [{"message": 'Cannot query field "isTls" on type "Request".'}]}, {}
        if self.mode == "httpql":
            return 200, {"data": None, "errors": [{"message": "Invalid HTTPQL: unexpected token at 4"}]}, {}
        v = q["variables"]
        code = v["filter"]["code"]
        rows = self.nodes
        host = re.search(r'req\.host\.eq:"([^"]+)"', code)
        if host:
            rows = [n for n in rows if n["host"] == host.group(1)]
        for op, when in re.findall(r'req\.created_at\.(gt|lt):"([^"]+)"', code):
            from datetime import datetime
            ms = int(datetime.fromisoformat(when).timestamp() * 1000)
            rows = [n for n in rows if (n["createdAt"] > ms if op == "gt" else n["createdAt"] < ms)]
        rows = sorted(rows, key=lambda n: n["createdAt"])
        start = int(v["after"]) + 1 if v.get("after") else 0
        page = rows[start:start + v["first"]]
        edges = [{"cursor": str(start + i), "node": n} for i, n in enumerate(page)]
        more = start + len(page) < len(rows)
        conn = {"edges": edges, "pageInfo": {"hasNextPage": more, "endCursor": edges[-1]["cursor"] if edges else None}}
        if self.mode == "shape":
            conn = {"nodes": [e["node"] for e in edges], "pageInfo": conn["pageInfo"]}
        if self.mode == "bad-node":
            for e in edges:
                e["node"] = dict(e["node"], isTls="yes")
        if self.mode == "bad-base64":
            for e in edges:
                e["node"] = dict(e["node"], raw="not base64!")
        return 200, {"data": {"requests": conn}}, {}


@pytest.fixture
def caido():
    servers = []

    def make(nodes=None, **kw):
        s = FakeCaido(history() if nodes is None else nodes, **kw)
        servers.append(s)
        return s
    yield make
    for s in servers:
        s.close()


@pytest.fixture(autouse=True)
def fresh_secrets(monkeypatch):
    monkeypatch.setattr(tool, "SECRETS", tool.Secrets())
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY",
                 "no_proxy", "ATTACKLEDGER_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CAIDO_TOKEN", TOKEN)


def run(capsys, *argv):
    code = tool.main([str(a) for a in argv])
    out = capsys.readouterr()
    return code, out.out + out.err


def pull(capsys, fake, out, *extra, host="shop.example.com"):
    return run(capsys, "--caido", fake.url, "--filter", f'req.host.eq:"{host}"', "--out", out, *extra)


# ---- pulling --------------------------------------------------------------------------------

def test_pages_through_the_history_and_writes_the_export_layout(caido, capsys, tmp_path):
    fake = caido([node(i) for i in range(1, 26)])
    code, said = pull(capsys, fake, tmp_path / "h.json", "--page-size", "10")
    assert code == 0, said
    rows = json.loads((tmp_path / "h.json").read_text())
    assert [r["id"] for r in rows] == [str(i) for i in range(1, 26)]
    pages = [q for q in fake.queries if "requests" in q["query"]]
    assert [p["variables"]["after"] for p in pages] == [None, "9", "19"]
    assert all(p["variables"]["first"] == 10 for p in pages)
    assert pages[0]["variables"]["order"] == {"by": "CREATED_AT", "ordering": "ASC"}
    r = rows[0]
    assert {k: r[k] for k in ("host", "port", "is_tls", "method", "path", "query", "created_at", "source",
                              "alteration", "edited")} == {
        "host": "shop.example.com", "port": 443, "is_tls": True, "method": "GET", "path": "/", "query": "",
        "created_at": T0 + 1000, "source": "intercept", "alteration": "none", "edited": False}
    assert r["response"]["status_code"] == 200 and base64.b64decode(r["response"]["raw"]).endswith(b"ok")
    assert "wrote 25 request(s)" in said and "0.58.3" in said
    assert (tmp_path / "h.json").stat().st_mode & 0o077 == 0          # captured traffic: owner only


def test_the_query_is_the_one_pinned_to_caidos_schema(caido, capsys, tmp_path):
    fake = caido()
    assert pull(capsys, fake, tmp_path / "h.json")[0] == 0
    q = [q for q in fake.queries if "requests" in q["query"]][0]["query"]
    assert q == tool.REQUESTS_QUERY
    # Every field it asks for is in Caido's published schema (types Request and Response).
    for field in ("id", "host", "port", "method", "path", "query", "isTls", "createdAt", "source", "alteration",
                  "edited", "length", "raw", "response", "statusCode", "roundtripTime", "hasNextPage", "endCursor"):
        assert re.search(rf"\b{field}\b", q)


def test_filter_and_time_window_reach_caido_as_httpql(caido, capsys, tmp_path):
    fake = caido()
    code, said = pull(capsys, fake, tmp_path / "h.json", "--since", "2026-10-09T10:00:01Z",
                      "--until", "2026-10-09T12:00:05+02:00")
    assert code == 0, said
    q = [q for q in fake.queries if "requests" in q["query"]][0]
    assert q["variables"]["filter"] == {"code": '(req.host.eq:"shop.example.com") AND '
                                                'req.created_at.gt:"2026-10-09T10:00:01+00:00" AND '
                                                'req.created_at.lt:"2026-10-09T10:00:05+00:00"'}
    rows = json.loads((tmp_path / "h.json").read_text())
    assert [r["id"] for r in rows] == ["2", "4"]        # 1 is too early, 3 is another host, 5 too late
    assert run(capsys, "--caido", fake.url, "--filter", "x", "--since", "yesterday", "--out",
               tmp_path / "n.json")[1].count("--since is not a date") == 1


def test_missing_raw_bytes_and_missing_responses_are_kept(caido, capsys, tmp_path):
    code, said = pull(capsys, caido(), tmp_path / "h.json")
    assert code == 0, said
    rows = {r["id"]: r for r in json.loads((tmp_path / "h.json").read_text())}
    assert "raw" not in rows["4"] and "raw" not in rows["4"]["response"]
    assert rows["5"]["response"] is None
    assert "1 request(s) had no raw bytes" in said
    _, parsed = importers.parse((tmp_path / "h.json").read_bytes())
    e = {x.tool_id: x for x in parsed.entries}
    assert (e["4"].request, e["4"].response, e["4"].status) == (None, None, 200)
    assert e["5"].status is None and e["5"].request.startswith(b"GET /socket")


def test_one_file_holds_at_most_one_imports_worth_and_says_how_to_continue(caido, capsys, tmp_path, monkeypatch):
    fake = caido([node(i) for i in range(1, 26)])
    code, said = pull(capsys, fake, tmp_path / "h.json", "--max-rows", "7", "--page-size", "5")
    assert code == 0, said
    assert len(json.loads((tmp_path / "h.json").read_text())) == 7
    assert "--since 2026-10-09T10:00:07Z" in said            # the 8th row is at 10:00:08
    assert (tool.MAX_ENTRIES, tool.MAX_FILE_BYTES) == (importers.MAX_ENTRIES, importers.MAX_FILE_BYTES)
    # The size limit counts bytes as the file is written: a file cut by size fits the import.
    monkeypatch.setattr(tool, "MAX_FILE_BYTES", 3_000)
    code, said = pull(capsys, fake, tmp_path / "s.json", "--overwrite")
    written = (tmp_path / "s.json").stat().st_size
    assert code == 0 and "more requests match" in said and 2_500 < written <= 3_000, written
    monkeypatch.setattr(tool, "MAX_FILE_BYTES", 100)
    code, said = pull(capsys, fake, tmp_path / "t.json")
    assert code == 1 and "alone is larger" in said and not (tmp_path / "t.json").exists()
    assert tool.SESSION_COOKIE == auth.COOKIE


def test_an_existing_file_is_not_overwritten_unless_asked(caido, capsys, tmp_path):
    out = tmp_path / "h.json"
    out.write_text("keep")
    fake = caido()
    code, said = pull(capsys, fake, out)
    assert code == 1 and "exists" in said and out.read_text() == "keep" and fake.seen == []
    assert pull(capsys, fake, out, "--overwrite")[0] == 0 and out.read_text() != "keep"


# ---- refusals -------------------------------------------------------------------------------

def test_a_refused_token_stops_the_pull_and_writes_nothing(caido, capsys, tmp_path, monkeypatch):
    fake = caido()
    monkeypatch.setenv("CAIDO_TOKEN", "lab-expired-token-999")
    code, said = pull(capsys, fake, tmp_path / "h.json")
    assert code == 1 and "INVALID_TOKEN" in said and "expired" in said
    assert not (tmp_path / "h.json").exists() and "lab-expired-token-999" not in said
    code, said = pull(capsys, caido(mode="http401"), tmp_path / "h.json")
    assert code == 1 and "HTTP 401" in said and TOKEN not in said and not (tmp_path / "h.json").exists()


@pytest.mark.parametrize("mode,expect", [
    ("shape", "requests.edges is missing"),
    ("bad-node", "requests.edges[0].node.isTls is str"),
    ("bad-base64", "requests.edges[0].node.raw is not valid base64"),
    ("schema", "did not accept this tool's query: Cannot query field \"isTls\""),
    ("not-json", "did not answer with GraphQL"),
    ("httpql", "Caido refused the query: Invalid HTTPQL"),
])
def test_an_unexpected_answer_stops_with_a_clear_message(caido, capsys, tmp_path, mode, expect):
    code, said = pull(capsys, caido(mode=mode), tmp_path / "h.json")
    assert code == 1 and expect in said, said
    if mode in ("shape", "bad-node", "bad-base64", "schema"):
        assert "v0.58.3" in said
    assert not (tmp_path / "h.json").exists() and TOKEN not in said


def test_runtime_version_of_another_shape_is_refused(caido, capsys, tmp_path, monkeypatch):
    fake = caido()
    monkeypatch.setattr(fake, "answer", lambda *_a: (200, {"data": {"runtime": {"release": "1.0"}}}, {}))
    code, said = pull(capsys, fake, tmp_path / "h.json")
    assert code == 1 and "runtime { version }" in said


@pytest.mark.parametrize("argv", [["--token", TOKEN], [f"--token={TOKEN}"], ["--caido-token", TOKEN],
                                  [f"--token-f={TOKEN}"], ["--password", TOKEN]])
def test_a_token_on_the_command_line_is_refused_and_not_echoed(caido, capsys, tmp_path, argv):
    fake = caido()
    with pytest.raises(SystemExit) as e:
        tool.main(["--caido", fake.url, "--filter", "x", "--out", str(tmp_path / "h.json"), *argv])
    said = capsys.readouterr()
    assert e.value.code == 2 and TOKEN not in said.out + said.err
    assert "unknown option" in said.err and fake.seen == []


def test_the_token_comes_from_a_file_or_the_named_variable(caido, capsys, tmp_path, monkeypatch):
    monkeypatch.delenv("CAIDO_TOKEN")
    fake = caido()
    code, said = pull(capsys, fake, tmp_path / "a.json")
    assert code == 1 and "no Caido token" in said and fake.seen == []
    f = tmp_path / "token"
    f.write_text(TOKEN + "\n")
    f.chmod(0o644)
    code, said = pull(capsys, fake, tmp_path / "b.json", "--token-file", f)
    assert code == 0 and "can be read by other users" in said
    f.chmod(0o600)
    assert "can be read" not in pull(capsys, fake, tmp_path / "c.json", "--token-file", f)[1]
    monkeypatch.setenv("MY_CAIDO", TOKEN)
    assert pull(capsys, fake, tmp_path / "d.json", "--token-env", "MY_CAIDO")[0] == 0
    f.write_text("two words\n")
    code, said = pull(capsys, fake, tmp_path / "e.json", "--token-file", f)
    assert code == 1 and "spaces, line breaks" in said and "two words" not in said


def test_a_personal_access_token_is_refused_before_anything_is_sent(caido, capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("CAIDO_TOKEN", "caido_lab0123456789")
    fake = caido()
    code, said = pull(capsys, fake, tmp_path / "h.json")
    assert code == 1 and "personal access token" in said and fake.seen == []
    assert "caido_lab0123456789" not in said


def test_no_proxy_from_the_environment_and_no_redirects(caido, capsys, tmp_path, monkeypatch):
    elsewhere = caido()
    proxy = caido()
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, proxy.url)
    fake = caido(mode="redirect", location=elsewhere.url + "/graphql")
    code, said = pull(capsys, fake, tmp_path / "h.json")
    assert code == 1 and "redirect" in said
    assert len(fake.seen) == 1 and elsewhere.seen == [] and proxy.seen == []
    assert pull(capsys, caido(), tmp_path / "h.json")[0] == 0 and proxy.seen == []


def test_plain_http_to_another_machine_is_refused_before_connecting(capsys, tmp_path, monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("the tool opened a connection")
    monkeypatch.setattr(socket, "create_connection", refuse)
    for url in ("http://192.0.2.10:8080", "http://caido.example.com"):
        code, said = run(capsys, "--caido", url, "--filter", "x", "--out", tmp_path / "h.json")
        assert code == 1 and "plain HTTP to another machine" in said
    code, said = run(capsys, "--caido", "http://127.0.0.1:8080", "--filter", "x", "--out", tmp_path / "h.json",
                     "--upload", "http://attackledger.example.com", "--engagement", "1")
    assert code == 1 and "AttackLedger address uses plain HTTP" in said
    assert tool.base_url("http://[::1]:8080/", "Caido", False) == "http://[::1]:8080"
    assert tool.base_url("https://caido.example.com", "Caido", False) == "https://caido.example.com"
    with pytest.raises(tool.PullError):
        tool.base_url("http://user:pw@127.0.0.1:8080", "Caido", False)


# ---- the token never leaves -----------------------------------------------------------------

def test_the_token_is_never_in_output_logs_or_the_file(caido, capsys, tmp_path, caplog):
    caplog.set_level("DEBUG")
    fake = caido()
    for extra in ([], ["--redact-locally"]):
        out = tmp_path / f"h{len(extra)}.json"
        code, said = pull(capsys, fake, out, *extra)
        assert code == 0, said
        assert TOKEN not in said and TOKEN not in caplog.text
        assert TOKEN.encode() not in out.read_bytes()
        assert TOKEN.encode() not in b"".join(p.read_bytes() for p in tmp_path.iterdir() if p.is_file())
    # Caido received it in the Authorization header only, and nowhere in a query.
    assert {s["headers"]["Authorization"] for s in fake.seen} == {f"Bearer {TOKEN}"}
    assert all(TOKEN not in s["body"] and TOKEN not in s["path"] for s in fake.seen)
    # An error that quotes the token back (a server echoing the header) is scrubbed.
    fake.mode = "httpql"
    fake.answer = lambda *_a: (200, {"errors": [{"message": f"bad header Bearer {TOKEN}"}]}, {})
    code, said = pull(capsys, fake, tmp_path / "x.json")
    assert code == 1 and TOKEN not in said and "[Caido token]" in said


# ---- local redaction ------------------------------------------------------------------------

def test_redact_locally_keeps_secrets_off_the_disk(caido, capsys, tmp_path):
    code, said = pull(capsys, caido(), tmp_path / "h.json", "--redact-locally")
    assert code == 0, said
    data = (tmp_path / "h.json").read_bytes()
    decoded = data + b"".join(base64.b64decode(m) for m in re.findall(rb'"raw": "([A-Za-z0-9+/=]+)"', data))
    for s in SECRETS:
        assert s.encode() not in decoded, s
        assert redact.marker(s).encode() in decoded, s
    assert "AttackLedger's redaction rules (server/app/redact.py)" in said
    rows = {r["id"]: r for r in json.loads(data)}
    assert rows["1"]["query"] == f"q=apple&session_token={redact.marker(QUERY_SECRET)}"
    resp = base64.b64decode(rows["1"]["response"]["raw"])
    head, body = resp.split(b"\r\n\r\n", 1)
    assert f"Content-Length: {len(body)}".encode() in head                 # rewritten for the stored body
    req = base64.b64decode(rows["1"]["raw"])
    assert f"Cookie: sid={redact.marker(COOKIE)}; theme={redact.marker('dark')}".encode() in req   # names kept
    assert f"Authorization: Bearer {redact.marker(BEARER)}".encode() in req                         # scheme kept


def test_without_the_repository_the_vendored_header_rules_apply(caido, capsys, tmp_path, monkeypatch):
    monkeypatch.setattr(tool, "_load_repo_redact", lambda: None)
    code, said = pull(capsys, caido(), tmp_path / "h.json", "--redact-locally")
    assert code == 0 and "header and parameter rules only" in said
    rows = {r["id"]: r for r in json.loads((tmp_path / "h.json").read_text())}
    req, resp = (base64.b64decode(rows["1"]["raw"]), base64.b64decode(rows["1"]["response"]["raw"]))
    for s in (COOKIE, BEARER, QUERY_SECRET):
        assert s.encode() not in req and redact.marker(s).encode() in req
    assert SET_COOKIE.encode() not in resp and QUERY_SECRET not in rows["1"]["query"]
    assert EMAIL.encode() in resp          # bodies are left to the server, as the message says


HEADERS = [("Cookie", "sid=abc; theme=dark; x="), ("Set-Cookie", "a=1; Path=/, b=2; Expires=Wed, 21 Oct 2026 07:28:00 GMT"),
           ("Authorization", "Bearer lab-tok-1"), ("Authorization", "Basic bGFiOmxhYg=="),
           ("Proxy-Authorization", "Digest x"), ("Authorization", "lab-no-scheme"), ("X-Api-Key", "lab-k"),
           ("X-Auth-Token", "lab-t"), ("X-CSRF-Token", "c"), ("X-Session-Id", "s"), ("Content-Type", "text/html"),
           ("Accept", "*/*"), ("Referer", "https://shop.example.com/?q=1&access_token=lab-r"),
           ("Cookie", redact.marker("already")), ("Authorization", "Bearer " + redact.marker("already")),
           ("Db_Password", "p"), ("signature", "s"), ("Host", "shop.example.com")]


def test_the_vendored_rules_match_the_servers():
    assert tool.Vendored.SECRET_NAMES == redact.SECRET_NAMES
    assert tool.Vendored.SECRET_PARTS == redact.SECRET_PARTS
    assert tool.Vendored.MARKER_PREFIX == redact.MARKER_PREFIX
    assert tool.Vendored.MARKER_RE.pattern == redact.MARKER_RE.pattern
    assert tool.Vendored._KV.pattern == redact._KV.pattern
    assert tool.Vendored._COOKIE_PAIR.pattern == redact._COOKIE_PAIR.pattern
    assert tool.Vendored._SETCOOKIE_SPLIT.pattern == redact._SETCOOKIE_SPLIT.pattern
    assert tool.Vendored._SCHEME.pattern == redact._SCHEME.pattern
    names = ["api_key", "apiKey", "X-Api-Key", "token", "csrftoken", "code", "sid", "Session", "user", "q",
             "password", "pass", "passport", "id", "x-amz-signature", "private_key", "", "-"]
    assert [tool.Vendored.secret_name(n) for n in names] == [redact.secret_name(n) for n in names]
    for name, value in HEADERS:
        a, b = redact.Report(), tool.Vendored.Report()
        assert tool.Vendored.header_line(f"{name}: {value}", b) == redact._header_line(f"{name}: {value}", a), name
        assert a.kinds == b.kinds
    raw = ("GET /a?session_token=lab-q&x=1 HTTP/1.1\r\n" + "".join(f"{n}: {v}\r\n" for n, v in HEADERS) +
           "\r\n").encode()
    assert tool.Vendored.http_message(raw, tool.Vendored.Report()) == redact.http_message(raw, redact.Report())


# ---- round trip -----------------------------------------------------------------------------

def test_the_output_imports_cleanly_and_matches_server_side_redaction(caido, capsys, tmp_path, client):
    fake = caido()
    assert pull(capsys, fake, tmp_path / "plain.json", host="shop.example.com")[0] == 0
    assert pull(capsys, fake, tmp_path / "red.json", "--redact-locally")[0] == 0
    adapter, parsed = importers.parse((tmp_path / "plain.json").read_bytes())
    assert adapter.id == "caido" and parsed.unreadable == [] and len(parsed.entries) == 4
    search = [x for x in parsed.entries if x.tool_id == "1"][0]
    assert search.url == f"https://shop.example.com/rest/products/search?q=apple&session_token={QUERY_SECRET}"
    assert (search.method, search.status, search.label, search.time) == ("GET", 200, "replay",
                                                                         "2026-10-09T10:00:01.000+00:00")
    assert search.request == SEARCH_REQ.encode() and search.response == SEARCH_RESP.encode()

    _, e, _ = team(client)
    sign_in(client, "tess@lab.test")
    r = upload(client, e, (tmp_path / "plain.json").read_bytes(), name="plain.json")
    assert r.status_code == 201, r.text
    assert (r.json()["format"], r.json()["accepted"], r.json()["unreadable"]) == ("caido", 4, 0)
    # The file redacted on the tester's machine stores the same bytes the server would store:
    # every one of its rows is a duplicate of the rows the server redacted itself.
    r = upload(client, e, (tmp_path / "red.json").read_bytes(), name="red.json").json()
    assert (r["accepted"], r["duplicates"]) == (0, 4), r
    everything = stored_bytes(client)
    for s in SECRETS + [TOKEN]:
        assert s.encode() not in everything


@pytest.fixture
def live_api(client):
    """The API on a real localhost port, served by uvicorn from the test's database."""
    import uvicorn
    from app.main import app
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, lifespan="off", log_level="warning", access_log=False))
    t = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    t.start()
    for _ in range(200):
        if server.started:
            break
        threading.Event().wait(0.02)
    yield f"http://127.0.0.1:{sock.getsockname()[1]}"
    server.should_exit = True
    t.join(5)


def test_pull_and_upload_over_http_as_the_tester(caido, capsys, tmp_path, client, live_api, monkeypatch):
    _, e, _ = team(client)
    sessions = db(client).scalar(select(func.count()).select_from(UserSession))
    monkeypatch.setattr(tool.getpass, "getpass", lambda _prompt: PW)
    fake = caido()
    code, said = pull(capsys, fake, tmp_path / "h.json", "--redact-locally", "--upload", live_api,
                      "--engagement", "import", "--al-email", "tess@lab.test", host="shop.example.com")
    assert code == 0, said
    assert f"engagement {e}: batch" in said and "4 in the inbox, 0 out of scope" in said
    assert PW not in said and TOKEN not in said
    s = db(client)
    batch = s.scalars(select(ImportBatch)).one()
    assert (batch.tool, batch.accepted, batch.filename) == ("caido", 4, "h.json")
    assert s.scalar(select(func.count()).select_from(UserSession)) == sessions     # signed out again
    assert TOKEN.encode() not in stored_bytes(client)
    audit = json.dumps([{k: str(v) for k, v in vars(a).items() if not k.startswith("_")}
                        for a in s.scalars(select(AuditEntry))])
    assert TOKEN not in audit and PW not in audit and "Tess" in audit
    # The same file again is refused unless asked; a wrong password is refused.
    code, said = run(capsys, "--caido", fake.url, "--filter", 'req.host.eq:"shop.example.com"', "--out",
                     tmp_path / "h.json", "--overwrite", "--redact-locally", "--upload", live_api, "--engagement", e,
                     "--al-email", "tess@lab.test")
    assert code == 1 and "--reimport" in said
    monkeypatch.setattr(tool.getpass, "getpass", lambda _prompt: "lab-wrong-password")
    code, said = run(capsys, "--caido", fake.url, "--filter", 'req.host.eq:"shop.example.com"', "--out",
                     tmp_path / "h2.json", "--upload", live_api, "--engagement", e, "--al-email", "tess@lab.test")
    assert code == 1 and "did not sign you in (HTTP 401)" in said and "lab-wrong-password" not in said
    monkeypatch.setattr(tool.getpass, "getpass", lambda _prompt: PW)
    # A name nobody can read is not guessed at.
    code, said = run(capsys, "--caido", fake.url, "--filter", 'req.host.eq:"shop.example.com"', "--out",
                     tmp_path / "h4.json", "--upload", live_api, "--engagement", "Other", "--al-email", "tess@lab.test")
    assert code == 1 and 'no engagement you can read is named "Other"' in said
    # A viewer may not import.
    code, said = run(capsys, "--caido", fake.url, "--filter", 'req.host.eq:"shop.example.com"', "--out",
                     tmp_path / "h3.json", "--upload", live_api, "--engagement", e, "--al-email", "vic@lab.test")
    assert code == 1 and "HTTP 403" in said and "tester role" in said
    assert s.scalar(select(func.count()).select_from(InboxEntry)) == 4


def test_upload_with_the_operator_token(caido, capsys, tmp_path, client, live_api, monkeypatch):
    _, e, _ = team(client)
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", AL_TOKEN)
    monkeypatch.setenv("ATTACKLEDGER_TOKEN", "lab-not-the-token")
    code, said = pull(capsys, caido(), tmp_path / "a.json", "--upload", live_api, "--engagement", e)
    assert code == 1 and "HTTP 401" in said and "lab-not-the-token" not in said
    f = tmp_path / "al-token"
    f.write_text(AL_TOKEN)
    f.chmod(0o600)
    code, said = pull(capsys, caido(), tmp_path / "b.json", "--upload", live_api, "--engagement", e,
                      "--al-token-file", f)
    assert code == 0 and "4 in the inbox" in said and AL_TOKEN not in said


def test_it_runs_with_the_standard_library_only(caido, tmp_path):
    """No site-packages (-S), isolated (-I): what a tester's laptop has."""
    fake, proxy = caido(), caido()
    env = {"CAIDO_TOKEN": TOKEN, "PATH": "/usr/bin:/bin", "HTTP_PROXY": proxy.url, "http_proxy": proxy.url}
    p = subprocess.run([sys.executable, "-I", "-S", str(TOOL), "--caido", fake.url, "--filter",
                        'req.host.eq:"shop.example.com"', "--out", str(tmp_path / "h.json"), "--redact-locally"],
                       capture_output=True, text=True, env=env, timeout=60)
    assert p.returncode == 0, p.stderr
    assert "wrote 4 request(s)" in p.stderr and TOKEN not in p.stdout + p.stderr
    assert len(json.loads((tmp_path / "h.json").read_text())) == 4
    assert proxy.seen == [] and len(fake.seen) == 2        # the version, then one page
