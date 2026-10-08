"""Passive, computed recon (no traffic at all): parameter routing and dork checklists.

M6: parameter names are sorted into gf-style classes and each class is pointed at
the hunt lane that tests it, so recon output becomes a starting point for hunting.

M10: Google dorks cannot be automated (no API, bots are blocked), so each wildcard
root gets a click-ready checklist. Nothing is sent anywhere.
"""
from urllib.parse import parse_qsl, quote_plus, urlsplit

# Parameter names that commonly carry each kind of input (gf-style), mapped to the
# bug-bounty pack lane that tests it.
PARAM_CLASSES: dict[str, tuple[str, set[str]]] = {
    "ssrf": ("injection", {"url", "uri", "dest", "destination", "callback", "feed", "host", "domain", "site",
                           "proxy", "fetch", "load", "image_url", "img", "src", "source", "webhook", "endpoint",
                           "remote", "server", "link"}),
    "redirect": ("authflow", {"next", "return", "returnto", "return_to", "returnurl", "return_url", "redirect",
                              "redirect_uri", "redirect_url", "redir", "goto", "continue", "target", "rurl",
                              "forward", "dest", "destination", "callback", "checkout_url", "out", "to"}),
    "idor": ("authz", {"id", "uid", "user", "user_id", "userid", "account", "account_id", "order", "order_id",
                       "invoice", "doc", "document", "profile", "customer", "customer_id", "member", "no",
                       "number", "ref", "group", "org", "org_id", "team", "project", "file_id"}),
    "sqli": ("injection", {"id", "sort", "order", "orderby", "order_by", "column", "field", "filter", "where",
                           "query", "search", "q", "select", "table", "from", "limit", "offset", "row", "report"}),
    "lfi": ("injection", {"file", "filename", "path", "filepath", "page", "template", "tpl", "include", "inc",
                          "dir", "folder", "doc", "document", "layout", "view", "lang", "locale", "download",
                          "conf", "config"}),
    "xss": ("injection", {"q", "s", "search", "query", "keyword", "keywords", "term", "name", "message", "msg",
                          "comment", "title", "text", "lang", "callback", "error", "email", "redirect"}),
    "rce": ("injection", {"cmd", "command", "exec", "execute", "run", "ping", "ip", "func", "function", "arg",
                          "code", "eval", "process", "daemon", "shell"}),
}


def classify_param(name: str) -> list[str]:
    n = name.strip().lower()
    return [cls for cls, (_, names) in PARAM_CLASSES.items() if n in names]


def params_of(url: str) -> list[str]:
    try:
        return sorted({k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)})
    except ValueError:
        return []


def route(endpoint_params: dict[str, list[str]]) -> list[dict]:
    """endpoint_params: url -> parameter names. Returns one row per (class, param, host)."""
    rows: dict[tuple, dict] = {}
    for url, params in endpoint_params.items():
        host = (urlsplit(url).hostname or "").lower()
        for p in params:
            for cls in classify_param(p):
                key = (cls, p.lower(), host)
                row = rows.setdefault(key, {"class": cls, "param": p.lower(), "host": host,
                                            "lane": PARAM_CLASSES[cls][0], "urls": []})
                if url not in row["urls"] and len(row["urls"]) < 10:
                    row["urls"].append(url)
    return sorted(rows.values(), key=lambda r: (r["class"], r["host"], r["param"]))


# Mirrors the original dork.sh list.
DORKS = [
    ("Exposed files", 'site:{d} ext:env OR ext:log OR ext:bak OR ext:old OR ext:sql OR ext:yml OR ext:yaml OR ext:ini OR ext:conf'),
    ("Directory listings", 'site:{d} intitle:"index of"'),
    ("API surface", 'site:{d} inurl:api OR inurl:swagger OR inurl:graphql OR inurl:actuator OR inurl:v1 OR inurl:v2'),
    ("Login and admin pages", 'site:{d} inurl:login OR inurl:admin OR inurl:signin OR inurl:portal OR inurl:dashboard'),
    ("Leaked keys in pages", 'site:{d} intext:"api_key" OR intext:"client_secret" OR intext:"access_token"'),
    ("Error pages", 'site:{d} intext:"sql syntax near" OR intext:"stack trace" OR intext:"Warning: mysql"'),
    ("Config files with secrets", 'site:{d} ext:json OR ext:xml intext:"password" OR intext:"secret"'),
    ("Subdomains", 'site:*.{d} -www'),
    ("S3 buckets", 'site:s3.amazonaws.com {d}'),
    ("Azure blobs", 'site:blob.core.windows.net {d}'),
    ("Google Cloud Storage", 'site:storage.googleapis.com {d}'),
    ("DigitalOcean Spaces", 'site:digitaloceanspaces.com {d}'),
    ("GitHub code", 'site:github.com {d} password OR secret OR api_key'),
    ("GitLab", 'site:gitlab.com {d}'),
    ("Pastebin", 'site:pastebin.com {d}'),
    ("Trello", 'site:trello.com {d}'),
    ("Atlassian", 'site:atlassian.net {d}'),
    ("Zendesk", 'site:*.zendesk.com {d}'),
    ("Google Docs", 'site:docs.google.com {d}'),
]


def dorks_for(root: str) -> list[dict]:
    return [{"title": title, "query": q.format(d=root),
             "url": "https://www.google.com/search?q=" + quote_plus(q.format(d=root))} for title, q in DORKS]
