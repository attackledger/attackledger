"""Recon steps that read what a host says about itself, and content discovery that works
on single-page apps (docs/BENCHMARK.md, gaps 3 and 4).

  wellknown  robots.txt, security.txt (/.well-known/ first) and the directories robots.txt
             names: their paths become endpoints; robots rules, security contacts and
             directory listings become leads. At most 13 GET requests per web service.
  content    feroxbuster as before, after a baseline of two random paths. A host that
             answers both with the same 200 page (a single-page app's catch-all route) is
             no longer skipped: that page is filtered out by its size, or its word or line
             count when the size varies, both by feroxbuster and again here. A host that
             answers both with the same error or redirect is still skipped. 200 directories
             it finds are checked for a listing (at most 10 per host).

The runners use the worker's own helpers (fetcher, add_lead, store_endpoints, ferox_cmd),
so every request goes through the same gateway, identification, rate spacing and scope
checks as the other steps; the worker registers them with one line (`runners`).
Requests are GET only and never follow redirects (the fetcher refuses them).
"""
import hashlib
import json
import os
import re
import time
from collections import defaultdict
from functools import partial
from urllib.parse import urljoin, urlsplit

from sqlalchemy import select

from . import pagetext, urls
from .models import Lead
from .text import plural

LISTING_CHECKS = 10            # directories checked for a listing, per host and step
SECURITY_TXT = ("/.well-known/security.txt", "/security.txt")
BASELINE_PATHS = 2


class _Live:
    """The worker's namespace, read at call time (so a test that replaces worker.fetcher is seen)."""

    def __init__(self, ns: dict):
        self._ns = ns

    def __getattr__(self, name):
        try:
            return self._ns[name]
        except KeyError:
            raise AttributeError(name) from None


def runners(worker_globals: dict) -> dict:
    """The runners this module provides, bound to the worker's helpers (its globals())."""
    w = _Live(worker_globals)
    return {"wellknown": partial(run_wellknown, w), "content": partial(run_content, w)}


def _lead_fps(r) -> set[str]:
    return set(r.session.scalars(select(Lead.fingerprint).where(Lead.engagement_id == r.eng.id)))


def _text(body: bytes | None) -> str:
    return body.decode("utf-8", "replace") if body else ""


def _same_host(root: str, value: str) -> str | None:
    """value (a path or a URL) as an absolute URL on root's host, or None if it is elsewhere."""
    v = value.strip().split()[0] if value.strip() else ""
    if not v or v.startswith(("mailto:", "tel:")):
        return None
    u = urljoin(root + "/", v)
    return u if urlsplit(u).netloc == urlsplit(root).netloc else None


def _directory_like(url: str) -> bool:
    path = urlsplit(url).path
    return path.endswith("/") or "." not in path.rsplit("/", 1)[-1]


def check_listing(w, r, get, url: str, endpoints: dict) -> bool:
    """GET url once; if it is a directory listing, record a lead and every entry as an endpoint
    (entries are recorded, not fetched)."""
    body, _ = get(url)
    entries = pagetext.directory_listing(_text(body), url) if body else None
    if entries is None:
        return False
    host = urls.host_of(url)
    path = urlsplit(url).path or "/"
    names = [e.rstrip("/").rsplit("/", 1)[-1] + ("/" if e.endswith("/") else "") for e in entries]
    endpoints[url].add("listing")
    for e in entries:
        if r.in_scope(urls.host_of(e)):
            endpoints[e].add("listing")
    w.add_lead(r, host, url, "listing", f"Directory listing at {path}: {plural(len(entries), 'entry', 'entries')}"
               + (": " + ", ".join(names[:6]) + ("…" if len(names) > 6 else "") if names else ""),
               detail={"url": url, "entries": names[:200], "count": len(names)}, key=path.rstrip("/") or "/")
    return True


def run_wellknown(w, r, urls_: list[str]) -> int:
    get = w.fetcher(r.eng, r.gw, "wellknown")
    r.lead_fps = _lead_fps(r)
    endpoints: dict[str, set] = defaultdict(set)
    found = 0
    skip = re.compile(w.CRAWL_OUT_OF_SCOPE, re.I)
    for base in urls_:
        host = urls.host_of(base)
        if not r.in_scope(host):
            continue
        root = base.rstrip("/")
        body, why = get(root + "/robots.txt")
        rb = pagetext.robots(_text(body)) if body else None
        r.digest.update(f"robots\t{root}\t{hashlib.sha256(body or b'').hexdigest()}\n".encode())
        candidates = []
        if rb:
            endpoints[root + "/robots.txt"].add("robots")
            paths = [p for p in rb["disallow"] + rb["allow"] if "*" not in p and "$" not in p]
            for p in paths:
                u = _same_host(root, p)
                if u and r.in_scope(urls.host_of(u)) and not skip.search(u):   # never logout/delete paths
                    endpoints[u].add("robots")
                    if _directory_like(u) and u.rstrip("/") != root:
                        candidates.append(u)
            for s in rb["sitemaps"]:
                u = _same_host(root, s)
                if u and r.in_scope(urls.host_of(u)):
                    endpoints[u].add("robots")
            shown = ", ".join(rb["disallow"][:5]) + ("…" if len(rb["disallow"]) > 5 else "")
            found += w.add_lead(r, host, root + "/robots.txt", "robots",
                                f"robots.txt: {plural(len(rb['disallow']), 'disallowed path')}"
                                + (f": {shown}" if shown else ""), detail=rb, key=root)
        for path in SECURITY_TXT:
            body, _ = get(root + path)
            st = pagetext.security_txt(_text(body)) if body else None
            r.digest.update(f"security.txt\t{root}{path}\t{hashlib.sha256(body or b'').hexdigest()}\n".encode())
            if not st:
                continue
            endpoints[root + path].add("security.txt")
            for values in st.values():
                for v in values:
                    u = _same_host(root, v) if v.startswith(("/", "http://", "https://")) else None
                    if u and r.in_scope(urls.host_of(u)) and not skip.search(u):
                        endpoints[u].add("security.txt")
            contact = (st.get("contact") or [""])[0]
            found += w.add_lead(r, host, root + path, "security-txt",
                                f"security.txt at {path}: contact {contact}"[:300], detail=st, key=root)
            break
        for u in list(dict.fromkeys(candidates))[:LISTING_CHECKS]:
            found += check_listing(w, r, get, u, endpoints)
        r.check_stop()
    added = w.store_endpoints(r, endpoints) if endpoints else 0
    r.log(f"{plural(found, 'new lead')}, {plural(added, 'new endpoint')}")
    return found + added


# ---- content discovery ---------------------------------------------------------------

def fingerprint(get, url: str) -> dict:
    """status, length, sha256, words, lines and title of one GET (body fields only on a 200)."""
    body, why = get(url)
    if body is None:
        return {"status": why.split()[1] if why.startswith("HTTP ") else "000"}
    text = _text(body)
    return {"status": "200", "length": len(body), "sha256": hashlib.sha256(body).hexdigest(),
            "words": len(text.split()), "lines": len(text.splitlines()), "title": pagetext.title_of(text)}


def baseline(get, url: str) -> list[dict]:
    """Fingerprints of two random paths that should not exist, one of them nested."""
    root = url.rstrip("/")
    return [fingerprint(get, root + f"/zzq-al-{os.urandom(4).hex()}"),
            fingerprint(get, root + f"/xnf-al-{os.urandom(4).hex()}/{os.urandom(2).hex()}")]


def catch_all_filter(fps: list[dict]) -> dict:
    """What to do about a host's answer to paths that do not exist:
      {}                     it answers 404 (or nothing): run as usual
      {"skip": reason}       it answers the same error or redirect everywhere, or a 200 page
                             that cannot be told apart from real content
      {"size"|"words"|"lines": n, "title": t}
                             a catch-all 200 page, filtered out by that measure"""
    a, b = fps
    if a["status"] != b["status"] or a["status"] in ("404", "000"):
        return {}
    if a["status"] != "200":
        return {"skip": f"every path answers {a['status']}"}
    if a["length"] == b["length"]:
        return {"size": a["length"], "title": a["title"]}
    if a["words"] == b["words"]:
        return {"words": a["words"], "title": a["title"]}
    if a["lines"] == b["lines"]:
        return {"lines": a["lines"], "title": a["title"]}
    return {"skip": "every path answers 200 with a page that changes from path to path"}


FEROX_FILTER = {"size": "--filter-size", "words": "--filter-words", "lines": "--filter-lines"}
FEROX_FIELD = {"size": "content_length", "words": "word_count", "lines": "line_count"}


def ferox_with_filter(cmd: list[str], plan: dict) -> list[str]:
    for k, flag in FEROX_FILTER.items():
        if k in plan:
            return [*cmd, flag, str(plan[k])]
    return cmd


def is_catch_all(rec: dict, plan: dict) -> bool:
    """A feroxbuster result that is the catch-all page (checked here too, not only by its filter)."""
    if str(rec.get("status")) != "200":
        return False
    return any(k in plan and rec.get(FEROX_FIELD[k]) == plan[k] for k in FEROX_FIELD)


def run_content(w, r, urls_: list[str]) -> int:
    get = w.fetcher(r.eng, r.gw, "content")
    r.lead_fps = _lead_fps(r)
    plans = []
    for u in urls_:
        if not r.in_scope(urls.host_of(u)):
            continue
        fps = baseline(get, u)
        plan = catch_all_filter(fps)
        r.digest.update(f"baseline\t{u}\t{json.dumps(fps, sort_keys=True)}\n".encode())
        if "skip" in plan:
            r.log(f"skipped {u}: {plan['skip']}")
            continue
        if plan:
            how = next(f"{k} {plan[k]}" for k in FEROX_FILTER if k in plan)
            r.log(f"{u} answers every path with the same page"
                  + (f" ({plan['title']!r})" if plan.get("title") else "") + f"; filtering it out by {how}")
        plans.append((u, plan))
    if not plans:
        return 0
    seen: dict[str, set] = defaultdict(set)
    listings = 0
    skip = re.compile(w.CRAWL_OUT_OF_SCOPE, re.I)
    for u, plan in plans:
        time.sleep(1.5)   # let the previous budget drain before the next scan starts
        dirs, dropped = [], 0
        for line in r.tool_lines("feroxbuster", ferox_with_filter(w.ferox_cmd(r.eng), plan), [u]):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("type") != "response" or not rec.get("url"):
                continue
            if is_catch_all(rec, plan):
                dropped += 1
                continue
            seen[rec["url"]].add(f"ferox-{rec.get('status')}")
            if str(rec.get("status")) == "200" and _directory_like(rec["url"]) and not skip.search(rec["url"]):
                dirs.append(rec["url"])
        if dropped:
            r.log(f"{plural(dropped, 'catch-all answer')} dropped after the scan")
        if dirs:
            time.sleep(1.5)
            for d in dirs[:LISTING_CHECKS]:
                if r.in_scope(urls.host_of(d)):
                    listings += check_listing(w, r, get, d, seen)
    added = w.store_endpoints(r, seen)
    if listings:
        r.log(f"{plural(listings, 'directory listing')} recorded as leads")
    return added
