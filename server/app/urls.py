"""URL clean-up for crawl and archive output (what the pipeline used `uro` for).

- drops static assets (images, fonts, stylesheets, media), keeps JavaScript,
- collapses URLs that differ only in parameter values: /item?id=1 and
  /item?id=2 become one entry,
- drops anything that is not http(s) or whose host is outside scope.
"""
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from . import scope

STATIC = {"png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp", "tif", "tiff", "css", "woff",
          "woff2", "ttf", "eot", "otf", "mp4", "mp3", "webm", "avi", "mov", "wav", "pdf", "zip",
          "gz", "rar", "7z", "map"}


def host_of(url: str) -> str | None:
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    return parts.hostname.lower()


def extension(path: str) -> str:
    last = path.rsplit("/", 1)[-1]
    return last.rsplit(".", 1)[-1].lower() if "." in last else ""


def dedupe_key(url: str) -> str:
    p = urlsplit(url)
    names = ",".join(sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)}))
    return urlunsplit((p.scheme, p.netloc.lower(), p.path or "/", names, ""))


def clean(urls, include: list[str], exclude: list[str]) -> list[tuple[str, str, bool]]:
    """Return (host, url, is_js) for in-scope, non-static URLs, one per dedupe key."""
    seen, out = set(), []
    for raw in urls:
        url = raw.strip()
        host = host_of(url)
        if not host or not scope.in_scope(host, include, exclude):
            continue
        ext = extension(urlsplit(url).path)
        if ext in STATIC:
            continue
        key = dedupe_key(url)
        if key in seen:
            continue
        seen.add(key)
        out.append((host, url.split("#", 1)[0], ext in ("js", "mjs")))
    return out
