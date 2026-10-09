"""The nuclei template classifier: only provably read-only templates may run (D-020, D-024)."""
import textwrap

import pytest
import yaml

from app import nucleisafe

GET_ONLY = """
id: get-only
info: {name: x, severity: medium, tags: exposure}
http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{RootURL}}/metrics?x=1"
    matchers:
      - type: word
        words: [DB_PASSWORD]
"""


def reasons(src: str) -> list[str]:
    src = textwrap.dedent(src)
    return nucleisafe.classify(yaml.safe_load(src), src)


def with_request(**req) -> str:
    doc = {"id": "t", "info": {"name": "t", "severity": "high"},
           "http": [{"path": ["{{BaseURL}}/x"], "matchers": [{"type": "status", "status": [200]}], **req}]}
    return yaml.safe_dump(doc)


def raw(*requests: str, **extra) -> str:
    doc = {"id": "t", "info": {"name": "t", "severity": "high"},
           "http": [{"raw": [textwrap.dedent(r) for r in requests],
                     "matchers": [{"type": "status", "status": [200]}], **extra}]}
    return yaml.safe_dump(doc)


def test_get_only_template_passes():
    assert reasons(GET_ONLY) == []


@pytest.mark.parametrize("method", ["HEAD", "OPTIONS"])
def test_other_read_methods_pass(method):
    assert reasons(with_request(method=method)) == []


def test_missing_method_is_nucleis_default_get():
    assert reasons(with_request()) == []


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "TRACE", "DEBUG", "PURGE", "{{verb}}", "get", None, ["GET"]])
def test_write_or_unknown_methods_are_excluded(method):
    assert any(r.startswith("method") for r in reasons(with_request(method=method)))


def test_raw_get_passes_and_annotations_are_ignored():
    assert reasons(raw("""\
        @timeout: 10s
        GET /api/version HTTP/1.1
        Host: {{Hostname}}
        Accept: */*
        """)) == []


@pytest.mark.parametrize("line", ["POST / HTTP/1.1", "DELETE /api/users/1 HTTP/1.1", "PUT /x HTTP/1.1",
                                  "DEBUG /Foobar-debug.aspx HTTP/1.1", "{{verb}} / HTTP/1.1"])
def test_raw_non_get_is_excluded(line):
    assert any(r.startswith("raw ") for r in reasons(raw(f"{line}\nHost: {{{{Hostname}}}}\n")))


def test_one_write_among_reads_excludes_the_template():
    out = reasons(raw("GET /a HTTP/1.1\nHost: {{Hostname}}\n", "DELETE /a HTTP/1.1\nHost: {{Hostname}}\n"))
    assert "raw DELETE request" in out


def test_nacos_create_user_tagged_instrusive_is_excluded_by_content():
    # Upstream tags it "instrusive" (typo), so a tag exclusion of "intrusive" misses it.
    src = """
    id: nacos-create-user
    info: {name: nacos, severity: high, tags: "misconfig,nacos,unauth,bypass,instrusive,vuln"}
    variables: {token: "eyJ..."}
    http:
      - raw:
          - |
            POST /nacos/v1/auth/users/?username={{randstr_1}}&password={{randstr_2}}&accessToken={{token}} HTTP/1.1
            Host: {{Hostname}}

          - |
            GET /nacos/v1/auth/users?pageNo=1&accessToken={{token}} HTTP/1.1
            Host: {{Hostname}}

          - |
            DELETE /nacos/v1/auth/users/?username={{randstr_1}}&accessToken={{token}} HTTP/1.1
            Host: {{Hostname}}

        matchers:
          - type: dsl
            dsl: ["status_code_1 == 200"]
    """
    out = reasons(src)
    assert "raw POST request" in out and "raw DELETE request" in out


def test_raw_destination_tricks_are_excluded():
    assert "raw @Host annotation" in reasons(raw("@Host: https://elsewhere.test\nGET / HTTP/1.1\nHost: {{Hostname}}\n"))
    assert "raw Host header is not the target" in reasons(raw("GET / HTTP/1.1\nHost: 127.0.0.1\n"))
    assert "raw Host header is not the target" in reasons(raw("GET / HTTP/1.1\nAccept: */*\n"))
    assert "raw request target is not a path" in reasons(raw("GET http://elsewhere.test/ HTTP/1.1\nHost: {{Hostname}}\n"))


def test_raw_get_with_a_body_is_excluded():
    assert "raw request body" in reasons(raw("GET /_search HTTP/1.1\nHost: {{Hostname}}\n\n{\"query\": 1}\n"))


def test_body_is_excluded_even_on_get():
    assert "request body" in reasons(with_request(method="GET", body="a=1"))
    assert reasons(with_request(method="GET", body="")) == []


def test_method_override_and_method_parameter_are_excluded():
    assert "method-override header" in reasons(with_request(headers={"X-HTTP-Method-Override": "DELETE"}))
    assert "method-override header" in reasons(raw("GET / HTTP/1.1\nHost: {{Hostname}}\nX-Method-Override: PUT\n"))
    assert reasons(with_request(headers={"X-HTTP-Method-Override": "GET"})) == []
    assert "_method parameter" in reasons(with_request(path=["{{BaseURL}}/users/1?_method=DELETE"]))
    assert "_method parameter" in reasons(raw("GET /u?a=1&_method=delete HTTP/1.1\nHost: {{Hostname}}\n"))


@pytest.mark.parametrize("path", ["https://api.elsewhere.test/{{user}}", "{{BaseURL}}.elsewhere.test/",
                                  "{{BaseURL}}@elsewhere.test/", "{{Host}}:4040/jobs", "/relative"])
def test_paths_off_the_target_are_excluded(path):
    assert "path is not under {{BaseURL}}/{{RootURL}}" in reasons(with_request(path=[path]))


def test_host_header_off_the_target_is_excluded():
    assert "Host header is not the target" in reasons(with_request(headers={"Host": "localhost"}))


@pytest.mark.parametrize("key", ["headless", "network", "tcp", "dns", "file", "code", "javascript", "ssl",
                                 "websocket", "whois", "workflows"])
def test_other_protocols_are_excluded(key):
    doc = {"id": "t", "info": {"name": "t"}, key: [{"x": 1}]}
    assert f"protocol or key {key}" in nucleisafe.classify(doc, yaml.safe_dump(doc))


def test_multi_protocol_http_template_is_excluded():
    doc = yaml.safe_load(with_request())
    doc["javascript"] = [{"code": "1"}]
    assert "protocol or key javascript" in nucleisafe.classify(doc, "")


@pytest.mark.parametrize("snippet", ["{{interactsh-url}}", "abc.oast.me", "x.oast.fun", "interact.sh"])
def test_out_of_band_references_are_excluded(snippet):
    src = with_request(headers={"X-Forwarded-Host": snippet})
    assert reasons(src) == ["out-of-band reference"]


def test_interactsh_matcher_part_is_excluded():
    src = GET_ONLY.replace("type: word", "type: word\n        part: interactsh_protocol")
    assert reasons(src) == ["out-of-band reference"]


def test_self_contained_is_excluded():
    doc = yaml.safe_load(with_request())
    doc["self-contained"] = True
    assert "self-contained (calls fixed URLs)" in nucleisafe.classify(doc, "")


def test_simple_flow_passes_and_scripted_flow_is_excluded():
    doc = yaml.safe_load(with_request())
    doc["http"].append(dict(doc["http"][0]))
    doc["flow"] = "http(1) && http(2)"
    assert nucleisafe.classify(doc, "") == []
    doc["flow"] = "http(1)\nfor (let p of iterate(template.paths)) { set('p', p); http(2) }"
    assert "flow beyond a sequence of http(N)" in nucleisafe.classify(doc, "")


@pytest.mark.parametrize("key,value,why", [
    ("unsafe", True, "unsafe raw-socket request"), ("pipeline", True, "HTTP pipelining"),
    ("race", True, "race requests"), ("race_count", 10, "race requests"), ("threads", 20, "per-template threads"),
    ("digest-username", "admin", "digest authentication"), ("fuzzing", [{"part": "query"}], "fuzzing rules"),
    ("pre-condition", [{"type": "dsl"}], "unknown request key pre-condition"),
    ("brand-new-key", 1, "unknown request key brand-new-key")])
def test_unsafe_pacing_and_unknown_request_keys_are_excluded(key, value, why):
    assert why in reasons(with_request(**{key: value}))


def test_a_template_needs_an_id_and_at_least_one_request():
    assert reasons(GET_ONLY.replace("id: get-only", "")) == ["not a template"]
    assert reasons("id: x\ninfo: {name: x}\nhttp: []\n") == ["no http requests"]


@pytest.mark.parametrize("src", ["", "- just\n- a list\n", "id: x\ninfo: {}\n", "info: {name: x}\nhttp: []\n",
                                 "id: x\nhttp: {path: x}\n", "id: x\nhttp: [notamapping]\n",
                                 "id: x\nhttp:\n  - matchers: []\n"])
def test_non_templates_and_empty_requests_are_excluded(src):
    assert reasons(src) != []


def test_unparseable_file_is_excluded(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("id: [unclosed\n")
    assert nucleisafe.classify_file(str(p)) == ["does not parse"]


def tree(tmp_path):
    (tmp_path / "http" / "exposures").mkdir(parents=True)
    (tmp_path / "network").mkdir()
    (tmp_path / "http" / "exposures" / "ok.yaml").write_text(textwrap.dedent(GET_ONLY))
    (tmp_path / "http" / "exposures" / "post.yaml").write_text(with_request(method="POST"))
    (tmp_path / "network" / "tcp.yaml").write_text("id: n\ninfo: {name: n}\ntcp:\n  - inputs: [{data: x}]\n")
    (tmp_path / "http" / "exposures" / "README.md").write_text("not a template")
    return tmp_path


def test_build_writes_every_excluded_template_and_verify_accepts_it(tmp_path, capsys):
    root = tree(tmp_path / "t")
    out = tmp_path / "exclude.txt"
    assert nucleisafe.build(str(root), str(out)) == 0
    listed = out.read_text().split()
    assert sorted(listed) == sorted([str(root / "http/exposures/post.yaml"), str(root / "network/tcp.yaml")])
    assert nucleisafe.verify(str(root), str(out)) == {"safe": 1, "excluded": 2}
    assert "1 templates read-only, 2 excluded" in capsys.readouterr().out


def test_verify_fails_closed(tmp_path):
    root = tree(tmp_path / "t")
    out = tmp_path / "exclude.txt"
    with pytest.raises(RuntimeError, match="missing or empty"):
        nucleisafe.verify(str(root), str(out))
    out.write_text("")
    with pytest.raises(RuntimeError, match="missing or empty"):
        nucleisafe.verify(str(root), str(out))
    out.write_text(str(root / "network/tcp.yaml") + "\n")          # the POST template is not listed
    with pytest.raises(RuntimeError, match="not provably read-only"):
        nucleisafe.verify(str(root), str(out))
    (root / "http/exposures/ok.yaml").unlink()
    out.write_text(str(root / "network/tcp.yaml") + "\n" + str(root / "http/exposures/post.yaml") + "\n")
    with pytest.raises(RuntimeError, match="no read-only"):
        nucleisafe.verify(str(root), str(out))


def test_build_refuses_a_tree_with_nothing_excluded_or_nothing_left(tmp_path):
    root = tmp_path / "t"
    root.mkdir()
    (root / "ok.yaml").write_text(textwrap.dedent(GET_ONLY))
    assert nucleisafe.build(str(root), str(tmp_path / "x.txt")) == 1
    assert not (tmp_path / "x.txt").exists()


def test_an_unexpected_shape_is_excluded_not_a_crash(tmp_path, monkeypatch):
    p = tmp_path / "odd.yaml"
    p.write_text(textwrap.dedent(GET_ONLY))
    assert nucleisafe.classify_file(str(p)) == []

    def boom(doc, text=""):
        raise TypeError("unexpected")
    monkeypatch.setattr(nucleisafe, "classify", boom)
    assert nucleisafe.classify_file(str(p)) == ["cannot classify (TypeError)"]
