"""Which nuclei templates AttackLedger may run: read-only by construction (D-020, D-024).

An allowlist, not a blocklist. A template may run only if every request it can send is
provably a GET, HEAD or OPTIONS request to the target itself, carrying the research
identification, with no body. Anything this module cannot prove is excluded:

  - protocols other than HTTP (dns, file, network/tcp, headless, code, javascript, ssl,
    websocket, whois, workflows, ...), and HTTP templates that mix in another protocol;
  - self-contained templates (they call hard-coded third-party URLs, whatever the input);
  - a flow other than a plain sequence of the template's own http(N) requests;
  - a request method other than GET/HEAD/OPTIONS, a templated method, a raw request whose
    request line is not GET/HEAD/OPTIONS or whose target is not an origin-form path, a
    Host header other than the target's, an @Host annotation, a request body, a
    method-override header or _method parameter with a write method;
  - a path that does not start with {{BaseURL}} or {{RootURL}} (third-party URLs);
  - unsafe (raw-socket) requests, HTTP pipelining, race and per-template threads, digest
    authentication, fuzzing rules, and any request key this module does not know;
  - any interactsh / out-of-band reference (interactsh-url, oast.*, interact.sh, ...);
  - files that do not parse as a template.

Tags are not trusted (upstream tags have typos such as "instrusive"); they are excluded
separately on the nuclei command line.

The worker image runs `python -m app.nucleisafe build ROOT OUT` at build time and writes
the exclusion list (one absolute path per line). The worker re-classifies the templates
before the first scan of a process (verify) and refuses to scan if the list is missing,
empty, or misses any template that is not provably read-only.
"""
import os
import re
import sys
from collections import Counter

import yaml

READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# Top-level keys a runnable template may have. Anything else (another protocol, workflows,
# a key added upstream later) excludes the template.
TOP_KEYS = frozenset({"id", "info", "http", "requests", "flow", "variables", "self-contained"})
# Request keys that cannot change the method, the destination or the pacing.
REQUEST_KEYS = frozenset({
    "id", "name", "method", "path", "raw", "headers", "matchers", "matchers-condition", "extractors",
    "payloads", "attack", "redirects", "max-redirects", "host-redirects", "stop-at-first-match",
    "skip-variables-check", "max-size", "cookie-reuse", "disable-cookie", "disable-path-automerge",
    "iterate-all", "global-matchers", "read-all", "body",
})
# Known request keys that are never allowed (listed for clear reasons in the build log).
REQUEST_DENY = {
    "unsafe": "unsafe raw-socket request", "pipeline": "HTTP pipelining",
    "pipeline-concurrent-connections": "HTTP pipelining", "pipeline-requests-per-connection": "HTTP pipelining",
    "race": "race requests", "race_count": "race requests", "threads": "per-template threads",
    "digest-username": "digest authentication", "digest-password": "digest authentication",
    "fuzzing": "fuzzing rules", "analyzer": "fuzzing analyzer",
}
OOB_RE = re.compile(r"interactsh|interact\.sh|oast\.(?:me|pro|fun|live|site|online|today)\b|"
                    r"burpcollaborator|\.dnslog\.|requestbin|canarytokens|pipedream\.net", re.I)
PATH_RE = re.compile(r"^\{\{(?:BaseURL|RootURL)\}\}(?:$|[/?#])")
FLOW_RE = re.compile(r"^[\s()!&|;]*(?:http\(\d+\)[\s()!&|;]*)+$")
OVERRIDE_HEADER_RE = re.compile(r"^x-(?:http-)?method(?:-override)?$", re.I)
METHOD_PARAM_RE = re.compile(r"[?&]_method=(?!(?:GET|HEAD|OPTIONS)\b)", re.I)
TARGET_HOSTS = frozenset({"{{Hostname}}", "{{Host}}", "{{Host}}:{{Port}}"})
Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def _raw_reasons(raw) -> list[str]:
    text = str(raw).replace("\r\n", "\n")
    head, sep, body = text.lstrip("\n").partition("\n\n")
    lines = [l for l in head.split("\n") if l.strip()]
    out = []
    if any(l.lstrip().lower().startswith("@host") for l in lines):
        out.append("raw @Host annotation")
    lines = [l for l in lines if not l.lstrip().startswith("@")]
    if not lines:
        return out + ["raw request without a request line"]
    parts = lines[0].strip().split(" ")
    if parts[0] not in READ_METHODS:
        out.append(f"raw {parts[0][:20]} request")
    if len(parts) < 2 or not parts[1].startswith("/"):
        out.append("raw request target is not a path")
    hosts = [l.split(":", 1)[1].strip() for l in lines[1:] if l.lower().startswith("host:")]
    if not hosts or any(h not in TARGET_HOSTS for h in hosts):
        out.append("raw Host header is not the target")
    for l in lines[1:]:
        name, _, value = l.partition(":")
        if OVERRIDE_HEADER_RE.match(name.strip()) and value.strip().upper() not in READ_METHODS:
            out.append("method-override header")
    if METHOD_PARAM_RE.search(lines[0]):
        out.append("_method parameter")
    if body.strip():
        out.append("raw request body")
    return out


def _request_reasons(r) -> list[str]:
    if not isinstance(r, dict):
        return ["request is not a mapping"]
    out = []
    for k in r:
        if k in REQUEST_DENY:
            out.append(REQUEST_DENY[k])
        elif k not in REQUEST_KEYS:
            out.append(f"unknown request key {str(k)[:30]}")
    raws, paths = r.get("raw") or [], r.get("path") or []
    if not isinstance(raws, list) or not isinstance(paths, list):
        return out + ["raw/path is not a list"]
    if not raws and not paths:
        out.append("request without path or raw")
    if paths:
        method = r.get("method", "GET")
        if not isinstance(method, str) or method not in READ_METHODS:   # exact: nuclei's own spelling of GET/HEAD/OPTIONS
            out.append(f"method {str(method)[:20]}")
        for p in paths:
            if not isinstance(p, str) or not PATH_RE.match(p):
                out.append("path is not under {{BaseURL}}/{{RootURL}}")
            elif METHOD_PARAM_RE.search(p):
                out.append("_method parameter")
    if r.get("body") not in (None, ""):
        out.append("request body")
    headers = r.get("headers") or {}
    if not isinstance(headers, dict):
        out.append("headers is not a mapping")
    else:
        for name, value in headers.items():
            if OVERRIDE_HEADER_RE.match(str(name)) and str(value).strip().upper() not in READ_METHODS:
                out.append("method-override header")
            if str(name).strip().lower() == "host" and str(value).strip() not in TARGET_HOSTS:
                out.append("Host header is not the target")
    for raw in raws:
        out += _raw_reasons(raw)
    return out


def classify(doc, text: str = "") -> list[str]:
    """Reasons a template may not run; an empty list means provably read-only."""
    if text and OOB_RE.search(text):
        return ["out-of-band reference"]
    if not isinstance(doc, dict) or not doc.get("id"):
        return ["not a template"]
    out = [f"protocol or key {str(k)[:30]}" for k in doc if k not in TOP_KEYS]
    if doc.get("self-contained"):
        out.append("self-contained (calls fixed URLs)")
    if "http" in doc and "requests" in doc:
        out.append("both http and requests")
    flow = doc.get("flow")
    if flow is not None and not (isinstance(flow, str) and FLOW_RE.match(flow)):
        out.append("flow beyond a sequence of http(N)")
    reqs = doc.get("http", doc.get("requests"))
    if not isinstance(reqs, list) or not reqs:
        out.append("no http requests")
    else:
        for r in reqs:
            out += _request_reasons(r)
    return list(dict.fromkeys(out))


def classify_file(path: str) -> list[str]:
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
        doc = yaml.load(text, Loader=Loader)
    except Exception:
        return ["does not parse"]
    try:
        return classify(doc, text)
    except Exception as e:      # an unexpected shape is not proof of anything: exclude it
        return [f"cannot classify ({type(e).__name__})"]


def scan(root: str) -> tuple[list[str], dict[str, list[str]]]:
    """(provably read-only templates, {excluded template: reasons}) under root."""
    safe, excluded = [], {}
    for dp, dirs, files in os.walk(root):
        dirs.sort()
        for f in sorted(files):
            if not f.endswith((".yaml", ".yml")):
                continue
            p = os.path.join(dp, f)
            reasons = classify_file(p)
            if reasons:
                excluded[p] = reasons
            else:
                safe.append(p)
    return safe, excluded


def read_list(path: str) -> set[str]:
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        raise RuntimeError(f"nuclei exclusion list missing or empty ({path}); refusing to scan")
    with open(path, encoding="utf-8") as f:
        return {l.strip() for l in f if l.strip()}


def verify(root: str, exclude_file: str) -> dict:
    """Re-classify the templates and fail closed if the list misses an unsafe one."""
    listed = read_list(exclude_file)
    safe, excluded = scan(root)
    missing = sorted(set(excluded) - listed)
    if missing:
        raise RuntimeError(f"{len(missing)} nuclei templates are not provably read-only but are not in "
                           f"{exclude_file} (first: {missing[0]}); refusing to scan")
    if not safe:
        raise RuntimeError(f"no read-only nuclei templates under {root}; refusing to scan")
    return {"safe": len(safe), "excluded": len(excluded)}


def build(root: str, out: str) -> int:
    safe, excluded = scan(root)
    if not safe or not excluded:
        print(f"nucleisafe: {len(safe)} read-only, {len(excluded)} excluded under {root}: refusing", file=sys.stderr)
        return 1
    with open(out, "w", encoding="utf-8") as f:
        f.write("".join(p + "\n" for p in sorted(excluded)))
    print(f"nucleisafe: {len(safe)} templates read-only, {len(excluded)} excluded, list {out}")
    rel = lambda p: os.path.relpath(p, root).split(os.sep)
    by_dir = Counter("/".join(rel(p)[:2]) if rel(p)[0] == "http" else rel(p)[0] for p in excluded)
    kept = Counter("/".join(rel(p)[:2]) if rel(p)[0] == "http" else rel(p)[0] for p in safe)
    for d in sorted(set(by_dir) | set(kept)):
        print(f"  {d:<32} {kept[d]:>6} read-only {by_dir[d]:>6} excluded")
    first = Counter(r[0] for r in excluded.values())
    print("  first reason: " + ", ".join(f"{k} {v}" for k, v in first.most_common(25)))
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "build":
        sys.exit(build(sys.argv[2], sys.argv[3]))
    if len(sys.argv) == 4 and sys.argv[1] == "verify":
        print(verify(sys.argv[2], sys.argv[3]))
        sys.exit(0)
    sys.exit("usage: python -m app.nucleisafe build|verify TEMPLATES_DIR EXCLUDE_FILE")
