"""Which recorded endpoints matter: path shapes, junk and a signal score.

Recon stores every URL it sees, and on a single-page app most of them are noise: strings
from a JavaScript bundle that look like paths (`/%60+_%28i...`, `/10`, MIME types). Listing
them alphabetically gave an agent the noise first and cut off the API (docs/BENCHMARK.md,
gap 5). This module ranks them by what a tester would look at first:

  API      the path looks like an API (/api/, /rest/, /graphql, /v2/, .json)       +4
  LEAD     a lead points at this endpoint (or its shape)                          +3
  ROUTED   a parameter lead routes this endpoint to the lane being worked          +2
  KEYWORD  admin, config, backup, ftp, upload, metrics, swagger, logs and so on    +3
  FEATURE  login, password, order, payment, search, file and similar features      +1
  STATUS   content discovery saw 401/403 (+3), a 5xx (+2), a 3xx or a 200 (+1)
  FILE     a non-web file (backup, archive, document, key)                         +2
  ROUTE    a client-side route of a single-page app (#/score-board)                +1
  PARAMS   the URL carries query parameters                                        +1

Junk (percent-encoded code, template placeholders, bare numbers, MIME types, short
random tokens) is dropped, and URLs with the same shape (/api/Products/1 and
/api/Products/2 -> /api/Products/{id}) are collapsed into one entry with a count.
Triage uses the same shapes to see whether a host serves an API at all.
"""
import re
from collections import defaultdict
from urllib.parse import unquote, urlsplit

API_RE = re.compile(r"(^|/)(api|rest|graphql|gql|rpc|jsonrpc|odata|v\d{1,2}|services?)(/|$)|\.(json|xml)$", re.I)
# Names a tester opens first (+3), and features worth a look (+1).
KEYWORD_RE = re.compile(
    r"admin|config|debug|backup|(?<![a-z])dump|export|ftp|upload|internal|private|secret|"
    r"(?<![a-z])keys?(?![a-z])|encryption|metrics|actuator|swagger|api-docs|openapi|graphiql|console|"
    r"(?<![a-z])logs?(?![a-z])|trace|\.well-known|robots\.txt|security\.txt|\.git(?![a-z])|"
    r"\.env(?![a-z])|phpinfo|server-status|redirect|callback|whoami|token", re.I)
FEATURE_RE = re.compile(r"user|account|password|reset|oauth|saml|sso|login|register|order|payment|"
                        r"wallet|basket|cart|invoice|profile|search|file|memor|review|feedback|complain|"
                        r"captcha|chat", re.I)
FILE_EXT = {"bak", "old", "orig", "sql", "db", "sqlite", "zip", "gz", "tgz", "tar", "rar", "7z", "bz2",
            "md", "txt", "log", "yml", "yaml", "ini", "conf", "cfg", "env", "pem", "key", "pub", "kdbx",
            "pyc", "csv", "xls", "xlsx", "doc", "docx", "pdf", "gg", "json", "xml"}
MIME_RE = re.compile(r"^/(application|text|image|audio|video|multipart|font)/[\w.+-]+$", re.I)
# A segment that is an identifier rather than a name: a number, a UUID, a long hex or random token.
_ID_SEG = re.compile(r"^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,}|"
                     r"[A-Za-z0-9_-]{24,})$", re.I)
_CODE_CHARS = re.compile(r"[`{}|()\[\]<>\\^!;,*'\" ]")


def path_of(url: str) -> str:
    try:
        return urlsplit(url).path or "/"
    except ValueError:
        return "/"


def route_of(url: str) -> str | None:
    """The client-side route of a hash-routed single-page app URL (/#/score-board), if any."""
    frag = url.split("#", 1)[1] if "#" in url else ""
    if frag.startswith("!/"):
        frag = frag[1:]
    return frag.split("?", 1)[0] if frag.startswith("/") else None


def is_junk(url: str) -> bool:
    """A string that a bundle or a crawler took for a path but no server would route."""
    raw = path_of(url)
    if route_of(url):
        return False
    path = unquote(raw)
    if path in ("", "/"):
        return False
    if _CODE_CHARS.search(path) or "=" in path:
        return True                                   # code, templates, encoded noise, base64 tails
    if MIME_RE.match(path):
        return True
    segs = [s for s in path.split("/") if s]
    if segs and all(s.isdigit() for s in segs):
        return True                                   # /10, /0/0
    if len(segs) == 1 and "." not in segs[0] and len(segs[0]) <= 2 and not API_RE.search(path):
        return True                                   # /bQ (but not /v1)
    return False


def shape(url: str) -> str:
    """The URL's path with identifiers collapsed: /api/Products/42 -> /api/Products/{id};
    query values dropped, parameter names kept; SPA route parameters (:id) become {id}.
    Scheme and host are left out: shapes are compared within one host."""
    try:
        p = urlsplit(url)
    except ValueError:
        return url
    segs = []
    for s in (p.path or "/").split("/"):
        segs.append("{id}" if s and _ID_SEG.match(s) else s)
    out = "/".join(segs).rstrip("/") or "/"
    route = route_of(url)
    if route:
        out += "#" + re.sub(r"/:[^/]+", "/{id}", route)
    names = sorted({kv.split("=", 1)[0] for kv in p.query.split("&") if kv}) if p.query else []
    return out + ("?" + "&".join(names) if names else "")


def is_api(url: str) -> bool:
    return bool(API_RE.search(path_of(url))) and not route_of(url)


def extension(url: str) -> str:
    last = path_of(url).rsplit("/", 1)[-1]
    return last.rsplit(".", 1)[-1].lower() if "." in last else ""


def status_of(source: str) -> int | None:
    """Content discovery records the status it saw in the endpoint's source, as ferox-403."""
    m = re.search(r"ferox-(\d{3})", source or "")
    return int(m.group(1)) if m else None


def score(url: str, source: str = "", is_js: bool = False, lead_shapes: set[str] = frozenset(),
          routed_shapes: set[str] = frozenset()) -> tuple[int, list[str]]:
    sig: list[tuple[str, int]] = []
    s = shape(url)
    route = route_of(url)
    if is_api(url):
        sig.append(("API", 4))
    if s in lead_shapes or url in lead_shapes:
        sig.append(("LEAD", 3))
    if s in routed_shapes:
        sig.append(("ROUTED", 2))
    where = unquote(route or path_of(url))
    if KEYWORD_RE.search(where):
        sig.append(("KEYWORD", 3))
    elif FEATURE_RE.search(where):
        sig.append(("FEATURE", 1))
    st = status_of(source)
    if st in (401, 403):
        sig.append(("STATUS", 3))
    elif st and st >= 500:
        sig.append(("STATUS", 2))
    elif st:
        sig.append(("STATUS", 1))
    if not is_js and extension(url) in FILE_EXT and not is_api(url):
        sig.append(("FILE", 2))
    if route:
        sig.append(("ROUTE", 1))
    if "?" in url.split("#", 1)[0]:
        sig.append(("PARAMS", 1))
    return sum(w for _, w in sig), [n for n, _ in sig]


def rank_endpoints(endpoints: list[dict], leads: list[dict] = (), lane_role: str = "",
                   limit: int = 50, route_limit: int = 100) -> dict:
    """endpoints: dicts with url, source, js. Returns the top `limit` server endpoints by
    signal, one per shape and spread across path prefixes, the single-page app's client
    routes separately (they are not server paths, so they do not compete for the same
    places), and what was left out."""
    lead_shapes, routed = set(), set()
    for l in leads:
        detail = l.get("detail") or {}
        for u in [l.get("source_url") or ""] + list(detail.get("urls") or []):
            if u:
                lead_shapes.add(shape(u))
                if lane_role and detail.get("lane") == lane_role:
                    routed.add(shape(u))
    groups: dict[str, list[dict]] = defaultdict(list)
    junk = 0
    for e in endpoints:
        if is_junk(e["url"]):
            junk += 1
            continue
        groups[shape(e["url"])].append(e)
    rows, routes = [], []
    for s, members in groups.items():
        first = min(members, key=lambda e: (len(e["url"]), e["url"]))
        sources = sorted({x for e in members for x in (e.get("source") or "").split(",") if x})
        sc, why = score(first["url"], ",".join(sources), bool(first.get("js")), lead_shapes, routed)
        row = {"url": first["url"], "shape": s, "count": len(members), "source": ",".join(sources)[:64],
               "js": bool(first.get("js")), "score": sc, "signals": why}
        (routes if route_of(first["url"]) else rows).append(row)
    rows.sort(key=lambda r: (-r["score"], r["shape"]))
    routes.sort(key=lambda r: (-r["score"], r["shape"]))
    # Breadth: each further pick under the same path prefix costs a quarter point, so forty
    # /api/X entries do not crowd out /ftp or /metrics.
    picked, per_prefix, pool = [], defaultdict(int), rows[:]
    while pool and len(picked) < limit:
        i = max(range(len(pool)), key=lambda k: (pool[k]["score"] - BREADTH * per_prefix[_prefix(pool[k]["shape"])],
                                                 -k))
        best = pool.pop(i)
        per_prefix[_prefix(best["shape"])] += 1
        picked.append(best)
    return {"endpoints": picked, "routes": [r["url"] for r in routes[:route_limit]],
            "total": len(endpoints), "shapes": len(rows), "junk_dropped": junk,
            "omitted": len(rows) - len(picked), "routes_total": len(routes)}


BREADTH = 0.25


def _prefix(s: str) -> str:
    """/api/Users -> api; /rest/user/login -> rest/user; /about -> /."""
    segs = [x for x in s.split("?", 1)[0].split("#", 1)[0].split("/") if x]
    return "/".join(segs[:2]) if len(segs) > 2 else (segs[0] if len(segs) == 2 else "/")


def api_shapes(urls: list[str]) -> set[str]:
    """Distinct API-like path shapes among a host's endpoints (for triage)."""
    return {shape(u).split("?", 1)[0] for u in urls if is_api(u) and not is_junk(u)}
