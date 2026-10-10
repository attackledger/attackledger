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
