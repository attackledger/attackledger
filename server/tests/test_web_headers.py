"""The web app's security headers (web/nginx.conf) and the edge's (deploy/Caddyfile).

The app's Content-Security-Policy allows nothing from another origin and no inline script
but the theme line in index.html, by hash, which must match that script's text exactly or the
browser blocks it."""
import base64
import hashlib
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
NGINX = (ROOT / "web" / "nginx.conf").read_text()
CADDY = (ROOT / "deploy" / "Caddyfile").read_text()


def _sha(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode() + "'"


def _location(path: str) -> str:
    m = re.search(r"location " + re.escape(path) + r" \{(.*?)\n  \}", NGINX, re.S)
    assert m, f"no location {path} in web/nginx.conf"
    return m.group(1)


def _headers(block: str) -> dict[str, str]:
    return dict(re.findall(r'^\s*add_header ([\w-]+) "([^"]*)" always;', block, re.M))


def _policy() -> dict[str, list[str]]:
    csp = _headers(_location("/"))["Content-Security-Policy"]
    return {d.split()[0]: d.split()[1:] for d in (x.strip() for x in csp.split(";")) if d}


def test_the_app_policy_allows_only_this_origin_and_hashed_inline_code():
    p = _policy()
    assert p["default-src"] == ["'none'"] and p["object-src"] == ["'none'"] and p["base-uri"] == ["'none'"]
    assert p["frame-ancestors"] == ["'none'"] and p["connect-src"] == ["'self'"]
    sources = [s for v in p.values() for s in v]
    assert not [s for s in sources if s in ("*", "'unsafe-inline'", "'unsafe-eval'", "http:", "https:", "blob:")
                or "://" in s or s.startswith("*.")], sources


def test_the_theme_script_hash_matches_index_html():
    scripts = re.findall(r"<script>(.*?)</script>", (ROOT / "web" / "index.html").read_text(), re.S)
    assert scripts, "index.html has no inline script any more: remove its hash from web/nginx.conf"
    for s in scripts:
        assert _sha(s) in _policy()["script-src"], (
            "an inline script in web/index.html changed: put its new hash in web/nginx.conf script-src")


def test_styles_come_from_the_bundle_only():
    assert _policy()["style-src"] == ["'self'"] and _policy()["font-src"] == ["'self'"]


def test_the_api_gets_no_second_policy_and_both_blocks_share_the_other_headers():
    api, app = _headers(_location("/api/")), _headers(_location("/"))
    assert "Content-Security-Policy" not in api
    assert {k: v for k, v in app.items() if k != "Content-Security-Policy"} == api
    assert api["X-Content-Type-Options"] == "nosniff" and api["X-Frame-Options"] == "DENY"


def test_the_caddyfile_sends_the_same_values_and_no_policy_of_its_own():
    block = re.search(r"\theader \{(.*?)\n\t\}", CADDY, re.S).group(1)
    caddy = dict(re.findall(r'^\t\t([\w-]+) "([^"]*)"', block, re.M))
    assert "Content-Security-Policy" not in caddy and caddy["Strict-Transport-Security"].startswith("max-age=")
    for name, value in _headers(_location("/api/")).items():
        assert caddy.get(name) == value, name


def test_web_image_ships_the_public_folder():
    """Vite copies web/public (favicons) into the build only if the image has it."""
    dockerfile = (ROOT / "web" / "Dockerfile").read_text()
    assert "COPY public ./public" in dockerfile
    assert (ROOT / "web" / "public" / "favicon.svg").is_file()


# ---- the machine routes are refused on the front end (TM-1) ---------------------------------

def _nginx_normalized(target: str) -> str:
    """The path nginx matches locations against: the query cut off, %XX decoded (%2F too), slashes
    merged (merge_slashes is on by default) and dot segments resolved."""
    from urllib.parse import unquote
    path = unquote(target.split("?", 1)[0])
    path = re.sub("/+", "/", path)
    out: list[str] = []
    for seg in path.split("/")[1:]:
        if seg == ".":
            continue
        if seg == "..":
            if out:
                out.pop()
            continue
        out.append(seg)
    return "/" + "/".join(out) + ("/" if path.endswith(("/", "/.", "/..")) and out else "")


def _refused_locations() -> list[re.Pattern]:
    """The regular-expression locations of web/nginx.conf that answer 404 themselves."""
    found = []
    for flag, pattern, body in re.findall(r"location (~\*?) (\S+) \{(.*?)\n  \}", NGINX, re.S):
        if re.search(r"^\s*return 404\b", body, re.M):
            found.append(re.compile(pattern, re.I if flag == "~*" else 0))
    return found


def _refused(target: str) -> bool:
    path = _nginx_normalized(target)
    return any(p.search(path) for p in _refused_locations())


MACHINE_VARIANTS = [
    "/api/gateway/log", "/api/gateway/dns-scopes", "/api/gateway/session", "/api/worker/ping", "/api/worker/claim",
    "/api/worker/jobs/1/finish", "/api/worker/jobs/1/agent/call", "/api/worker", "/api/gateway", "/api/worker/",
    "/api//gateway/log", "/api///worker/ping", "/api/%67ateway/log", "/api/gateway%2Flog", "/api/gateway%2flog",
    "/api/%77orker/ping", "/api/w%6Frker/claim", "/api/GATEWAY/dns-scopes", "/api/Worker/claim", "/api/./worker/ping",
    "/api/x/../worker/ping", "/api/%2e/worker/ping", "/api/worker?x=1", "/api/worker/ping?a=/b",
]


def test_nginx_refuses_the_machine_routes_in_every_spelling():
    assert _refused_locations(), "web/nginx.conf has no location refusing /api/gateway/ and /api/worker/"
    assert not [t for t in MACHINE_VARIANTS if not _refused(t)]
    for target in ("/api/engagements", "/api/auth/login", "/api/health", "/api/workers", "/api/gatewaylog",
                   "/api/engagements/1/gateway-log", "/api/lanes/1/agent-runs", "/", "/index.html"):
        assert not _refused(target), target


def test_the_refusal_comes_before_the_api_prefix_and_answers_like_the_api():
    """A regular-expression location wins over the /api/ prefix only if that prefix has no ^~;
    the refusal sends the API's own 404 body with the /api/ block's headers."""
    assert re.search(r"location /api/ \{", NGINX) and not re.search(r"location \^~ /api/", NGINX)
    block = re.search(r"location ~\*? \S+ \{(.*?)\n  \}", NGINX, re.S).group(1)
    assert "return 404 '{\"detail\":\"Not Found\"}';" in block and "default_type application/json;" in block
    assert _headers(block) == _headers(_location("/api/"))
