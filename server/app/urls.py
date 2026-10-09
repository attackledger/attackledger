"""URL clean-up for crawl and archive output (what the pipeline used `uro` for).

- drops media assets (images, fonts, stylesheets, audio, video), keeps JavaScript,
- keeps a media file anyway when it sits under a path a tester would look at (uploads,
  backups, ftp, private, ...): the benchmark's photo-wall upload was dropped as an image
  (docs/BENCHMARK.md, gap 6). Archives, sourcemaps and documents are always kept. Kept
  files are recorded, never fetched: no later step requests a non-JS file as content,
- collapses URLs that differ only in parameter values: /item?id=1 and
  /item?id=2 become one entry,
- keeps a single-page app's hash route (/#/score-board) as its own entry; any other
  fragment is dropped,
- drops anything that is not http(s) or whose host is outside scope.
"""
import re
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

from . import scope

MEDIA = {"png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp", "tif", "tiff", "css", "woff",
         "woff2", "ttf", "eot", "otf", "mp4", "mp3", "webm", "avi", "mov", "wav"}
# Not web assets: a backup archive or a sourcemap is worth recording wherever it is.
FILES = {"pdf", "zip", "gz", "rar", "7z", "tar", "tgz", "bz2", "map"}
STATIC = MEDIA | FILES          # kept for callers that ask "is this a static file?"
INTERESTING_DIR = re.compile(
    r"(^|/)(uploads?|files?|ftp|backups?|bak|old|private|internal|admin|secret|export|download|"
    r"downloads|attachments?|documents?|dump|tmp|temp|logs?|user-?content|"
    r"invoices?|receipts?|reports?|keys?|certs?|\.well-known|\.git)(/|$)", re.I)


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


def hash_route(url: str) -> str:
    """'#/route' for a hash-routed SPA URL (#/x or #!/x), else ''."""
    frag = url.split("#", 1)[1] if "#" in url else ""
    return "#" + frag if frag.startswith(("/", "!/")) else ""


def keep_static(path: str) -> bool:
    """Whether a static file is worth recording: any archive, sourcemap or document, and
    media only under an interesting directory."""
    ext = extension(path)
    if ext in FILES:
        return True
    directory = unquote(path.rsplit("/", 1)[0])
    return bool(INTERESTING_DIR.search(directory))


def dedupe_key(url: str) -> str:
    p = urlsplit(url)
    names = ",".join(sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)}))
    route = hash_route(url).split("?", 1)[0]
    return urlunsplit((p.scheme, p.netloc.lower(), p.path or "/", names, route.lstrip("#")))


def clean(urls, include: list[str], exclude: list[str]) -> list[tuple[str, str, bool]]:
    """Return (host, url, is_js) for in-scope URLs worth keeping, one per dedupe key."""
    seen, out = set(), []
    for raw in urls:
        url = raw.strip()
        host = host_of(url)
        if not host or not scope.in_scope(host, include, exclude):
            continue
        path = urlsplit(url).path
        ext = extension(path)
        if ext in STATIC and not keep_static(path):
            continue
        key = dedupe_key(url)
        if key in seen:
            continue
        seen.add(key)
        out.append((host, url.split("#", 1)[0] + hash_route(url), ext in ("js", "mjs")))
    return out
