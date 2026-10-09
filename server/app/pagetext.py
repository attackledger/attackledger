"""Reading responses the way a tester does: the text and links of a page, the names in a
directory listing, the fields of robots.txt and security.txt, the routes of a JS bundle.

An agent sees at most 4,000 characters of a response. On the benchmark the /ftp listing
page spent all of them on inline CSS before the first file name, and main.js is 1.2 MB
(docs/BENCHMARK.md, gap 5). `view` gives the agent the part that carries meaning instead:
markup, styles and scripts stripped from HTML (links kept), and an extracted list of routes,
endpoints and operations for a large bundle. The full response is always kept as evidence;
only what the model is shown changes.

Recon uses the same parsers to record robots.txt, security.txt and directory listings as
leads and endpoints. Standard library only.
"""
import re
from html import unescape
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from . import jsanalysis, surface

_DROP_BLOCKS = re.compile(r"<(script|style|noscript|template|svg)\b[^>]*>.*?</\1\s*>", re.I | re.S)
_COMMENT = re.compile(r"<!--.*?-->", re.S)
_LISTING = re.compile(r"<title>\s*(index of|listing directory|directory listing for|directory:)\s*([^<]*)</title>|"
                      r"<h1>\s*index of\s|\[to parent directory\]", re.I)
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


class _Links(HTMLParser):
    """Visible text and every link-like attribute, in document order."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.links: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript", "template", "svg"):
            self._skip += 1
        for k, v in attrs:
            if v and k in ("href", "src", "action", "data-src", "formaction"):
                self.links.append(v.strip())
        if tag in ("br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4", "pre", "table", "section", "form"):
            self.text.append("\n")
        else:
            self.text.append(" ")
        if tag == "input":
            a = dict(attrs)
            if a.get("name"):
                self.text.append(f" [input {a.get('type') or 'text'} {a['name']}] ")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript", "template", "svg") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.text.append(data)


def looks_html(text: str, content_type: str = "") -> bool:
    if "html" in content_type.lower():
        return True
    head = text[:500].lstrip().lower()
    return head.startswith(("<!doctype html", "<html")) or "<head" in head


def looks_js(url: str, content_type: str = "") -> bool:
    ct = content_type.lower()
    return "javascript" in ct or "ecmascript" in ct or urlsplit(url).path.lower().endswith((".js", ".mjs"))


def title_of(text: str) -> str:
    m = _TITLE.search(text[:20000])
    return " ".join(unescape(m.group(1)).split())[:200] if m else ""


def strip_html(text: str) -> tuple[str, list[str]]:
    """(visible text with whitespace collapsed, links in document order without duplicates)."""
    p = _Links()
    try:
        p.feed(_COMMENT.sub(" ", text))
        p.close()
    except Exception:  # noqa: BLE001 - malformed markup: fall back to a regex strip
        body = re.sub(r"<[^>]+>", " ", _DROP_BLOCKS.sub(" ", _COMMENT.sub(" ", text)))
        return re.sub(r"[ \t]+", " ", unescape(body)).strip(), []
    lines = [" ".join(l.split()) for l in "".join(p.text).splitlines()]
    return "\n".join(l for l in lines if l), list(dict.fromkeys(p.links))


def directory_listing(text: str, url: str) -> list[str] | None:
    """Absolute URLs of the entries of a directory listing page, or None if it is not one.
    Parent, self and sort links are left out."""
    if not _LISTING.search(text[:20000]):
        return None
    _, links = strip_html(text)
    base = url if url.endswith("/") else url + "/"
    here = urlsplit(base).path
    out = []
    for href in links:
        if href.startswith(("?", "#", "javascript:", "mailto:")) or href in (".", "..", "./", "../", "/"):
            continue
        # serve-index on /ftp (no slash) links "ftp/x"; most servers link "x" relative to /dir/.
        absolute = urljoin(url, href)
        if urlsplit(absolute).path.rstrip("/") == here.rstrip("/"):
            continue                                   # the listing itself
        if not urlsplit(absolute).path.startswith(here):
            absolute = urljoin(base, href)
        p = urlsplit(absolute)
        if p.netloc != urlsplit(url).netloc or not p.path.startswith(here) or p.path.rstrip("/") == here.rstrip("/"):
            continue
        out.append(absolute.split("#", 1)[0])
    return list(dict.fromkeys(out))


def robots(text: str) -> dict | None:
    """Disallow/Allow paths and sitemaps from a robots.txt body, or None if it is not one
    (a single-page app answers /robots.txt with its index page)."""
    if looks_html(text):
        return None
    out = {"disallow": [], "allow": [], "sitemaps": []}
    seen_directive = False
    for line in text.splitlines():
        key, sep, value = line.split("#", 1)[0].partition(":")
        if not sep:
            continue
        key, value = key.strip().lower(), value.strip()
        if key == "user-agent":
            seen_directive = True
        elif key in ("disallow", "allow") and value:
            seen_directive = True
            out[key].append(value)
        elif key == "sitemap" and value:
            out["sitemaps"].append(value)
    if not seen_directive and not out["sitemaps"]:
        return None
    for k in out:
        out[k] = list(dict.fromkeys(out[k]))[:200]
    return out


def security_txt(text: str) -> dict | None:
    """Fields of a security.txt (RFC 9116) as {field: [values]}, or None without Contact."""
    if looks_html(text):
        return None
    fields: dict[str, list[str]] = {}
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        key, sep, value = line.partition(":")
        if sep and re.fullmatch(r"[A-Za-z-]{2,40}", key.strip()) and value.strip():
            fields.setdefault(key.strip().lower(), []).append(value.strip()[:500])
    return fields if "contact" in fields else None


def bundle_summary(text: str, url: str, limit: int = 400) -> dict:
    """What a JS bundle tells a tester, without its code: client routes, server endpoints
    (full values, query strings included), GraphQL operations, the sourcemap and the kinds
    of secret candidates (masked, as recon stores them)."""
    eps = jsanalysis.extract_endpoints(text, url, routes=False)
    routes = jsanalysis.spa_routes(text)
    host = urlsplit(url)
    origin = f"{host.scheme}://{host.netloc}"
    # API paths first, then the rest; strings that only look like paths are left out.
    eps = sorted((e for e in eps if not surface.is_junk(e)), key=lambda e: (not surface.is_api(e), e))
    server = [e[len(origin):] or "/" for e in eps]
    secrets = [f"{s['kind']} ({s['preview']})" for s in jsanalysis.scan_secrets(text) if s["bucket"] != "noise"]
    return {"routes": routes[:limit], "endpoints": server[:limit], "graphql": jsanalysis.graphql_operations(text)[:100],
            "sourcemap": jsanalysis.sourcemap_ref(text, url), "secret_candidates": secrets[:20],
            "hash_routing": jsanalysis.uses_hash_routing(text)}


def view(body: str, url: str, content_type: str = "", limit: int = 4000) -> tuple[str, str]:
    """(what the model is shown, which view) for a response body.

    raw        short bodies and anything that is not HTML or a large bundle, unchanged
    html-text  an HTML page: visible text, then its links; scripts, styles and markup removed
    js-summary a JavaScript file larger than the limit: its routes, endpoints and operations"""
    if len(body) > limit and looks_js(url, content_type) and not looks_html(body, ""):
        s = bundle_summary(body, url)
        parts = [f"JavaScript file of {len(body):,} characters, summarised (the full file is kept as evidence)."]
        if s["routes"]:
            parts.append("Client routes" + (" (hash routing, open as /#/<route>)" if s["hash_routing"] else "")
                         + ": " + ", ".join(s["routes"]))
        if s["endpoints"]:
            parts.append("Server paths referenced: " + ", ".join(s["endpoints"]))
        if s["graphql"]:
            parts.append("GraphQL operations: " + ", ".join(s["graphql"]))
        if s["sourcemap"]:
            parts.append(f"Sourcemap: {s['sourcemap']}")
        if s["secret_candidates"]:
            parts.append("Secret candidates (masked): " + "; ".join(s["secret_candidates"]))
        return "\n".join(parts), "js-summary"
    if looks_html(body, content_type) and ("<style" in body.lower() or "<script" in body.lower()
                                           or len(body) > limit):
        text, links = strip_html(body)
        listing = directory_listing(body, url)
        out = []
        t = title_of(body)
        if t:
            out.append(f"Title: {t}")
        if listing is not None:
            out.append(f"Directory listing, {len(listing)} entries: "
                       + ", ".join(e.rstrip("/").rsplit("/", 1)[-1] + ("/" if e.endswith("/") else "")
                                   for e in listing))
        out.append(text)
        if links:
            out.append("Links: " + " ".join(links[:300]))
        return "\n".join(out), "html-text"
    return body, "raw"
