"""Evidence import: adapter, scope check, redaction, dedupe, inbox; then a person maps (D-029).

    export file ─► adapter ─► scope check ─► redaction ─► dedupe ─► inbox ─► person maps ─► ledger

- **Scope.** An entry whose host is outside the engagement's rules is refused. The batch
  lists it by row number and host so the person can find it in their file; its URL, bytes
  and everything else are never stored. An engagement without scope rules imports nothing.
- **Redaction.** Before anything is stored, the raw request and response go through
  redact.http_message (every header line through the header rules, the URL and body
  through the text rules), and the URL and label through redact.text, unless the
  engagement's owner turned redaction off. The uploaded file itself is never stored; only
  its hash, so the tester can show which file was imported.
- **Dedupe.** An entry whose content (method, URL, status and the hashes of its redacted
  bytes) is already in the inbox, or earlier in the same file, is counted as a duplicate.
- **Storage.** The redacted request and response go into the blob store, and so does a
  small record naming them (RECORD_FORMAT). Mapping an entry appends evidence that commits
  to the record, so the chain reaches the raw bytes through it.
- **Mapping.** Nothing reaches the ledger without a person: they map an entry to one or
  more checklist items on a lane of the entry's own host, and each mapping appends one
  evidence entry with source "import:<tool>". Suggestions come from simple rules on the URL
  and the pack's item texts, and each says why it was made.
"""
import hashlib
import re
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlsplit

from sqlalchemy import select

from . import auditlog, blobs, importers, ledger, redact, scope
from .models import Asset, Engagement, ImportBatch, InboxEntry, Lane, iso_utc

RECORD_FORMAT = "attackledger-import/1"
STATES = ("new", "mapped", "dismissed")
MAX_REFUSED_LISTED = 1_000          # rows listed per batch; the counts are always complete
MAX_MAP_ENTRIES = 200
MAX_MAP_TARGETS = 20


class InboxError(ValueError):
    """A request the inbox refuses; the message is shown to the person."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_hash(method: str, url: str, status: int | None, req: str | None, resp: str | None,
                 tool_id: str | None) -> str:
    """What makes two entries the same exchange, whichever tool exported it. Without raw
    bytes there is too little to tell two requests apart, so the tool's own id counts too."""
    c = {"method": method, "url": url, "status": status, "request": req, "response": resp}
    if req is None and resp is None:
        c["tool_id"] = tool_id
    return ledger.sha256(ledger.canonical(c))


def _facts(response: bytes | None) -> dict:
    """A few facts about the response head, kept for suggestions (no values)."""
    if not response:
        return {}
    head = response.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0].decode("latin-1")
    names = {}
    for line in head.splitlines()[1:]:
        n, _, v = line.partition(":")
        names.setdefault(n.strip().lower(), v.strip())
    return {"content_type": names.get("content-type", "")[:100], "sets_cookie": "set-cookie" in names,
            "cors": "access-control-allow-origin" in names, "upgrade": names.get("upgrade", "").lower()[:20]}


def _refused(rows: list, row: int, host: str | None, reason: str, detail: str | None = None) -> None:
    if len(rows) < MAX_REFUSED_LISTED:
        rows.append({"row": row, "host": host, "reason": reason, "detail": detail})


def _report_from(stored: dict | None) -> redact.Report:
    rep = redact.Report()
    if stored:
        rep.kinds = dict(stored.get("counts") or {k: 1 for k in stored.get("kinds", [])})
        rep.not_redacted = list(stored.get("not_redacted", []))
    return rep


def import_file(session, eng: Engagement, data: bytes, *, fmt: str | None, filename: str | None,
                actor: dict, user_id: int | None) -> ImportBatch:
    """Run one file through the pipeline. Refusals of the whole file raise ImportRefused and
    store nothing. The caller commits."""
    if not eng.scope_include:
        raise importers.ImportRefused("this engagement has no scope rules yet; set the scope before importing, "
                                      "so out-of-scope rows can be refused")
    adapter, parsed = importers.parse(data, fmt)
    on = redact.enabled(eng)
    name = (filename or "").strip().replace("\\", "/").rsplit("/", 1)[-1][:200] or None
    batch = ImportBatch(engagement_id=eng.id, tool=adapter.id, creator=parsed.creator, filename=name,
                        file_sha256=_sha(data), file_bytes=len(data),
                        rows=len(parsed.entries) + len(parsed.unreadable), accepted=0, out_of_scope=0,
                        duplicates=0, unreadable=len(parsed.unreadable), refused=[],
                        created_by=user_id, created_by_name=auditlog.actor_label(actor)[:300])
    session.add(batch)
    session.flush()
    refused: list = []
    for row, why in parsed.unreadable:
        _refused(refused, row, None, "unreadable", why)

    known = set(session.scalars(select(InboxEntry.content_sha256).where(InboxEntry.engagement_id == eng.id)))
    for e in parsed.entries:
        host = urlsplit(e.url).hostname or ""
        try:
            host = scope.normalize_host(host)
        except scope.ScopeError:
            batch.unreadable += 1
            _refused(refused, e.row, None, "unreadable", "the URL's host is not a host name")
            continue
        if not scope.in_scope(host, eng.scope_include, eng.scope_exclude):
            batch.out_of_scope += 1                 # listed by row and host; nothing else is kept
            _refused(refused, e.row, host, "out_of_scope")
            continue

        rep = redact.Report(off=not on)
        url, label, req, resp = e.url, e.label, e.request, e.response
        if on:
            url = redact.text(url, rep)
            label = redact.text(label, rep) if label else label
            req = redact.http_message(req, rep, personal=True, what="binary request body")
            resp = redact.http_message(resp, rep, personal=True, what="binary response body")
        req_sha = _sha(req) if req is not None else None
        resp_sha = _sha(resp) if resp is not None else None
        content = content_hash(e.method, url, e.status, req_sha, resp_sha, e.tool_id)
        if content in known:
            batch.duplicates += 1
            _refused(refused, e.row, host, "duplicate")
            continue
        known.add(content)

        if req is not None:
            blobs.put(req, engagement_id=eng.id)
        if resp is not None:
            blobs.put(resp, engagement_id=eng.id)
        notes = []
        if e.rebuilt:
            notes.append("raw bytes rebuilt from the export's fields")
        if req is None and resp is None:
            notes.append("raw bytes were not in the export")
        notes += [f"{p} cut at {importers.MAX_PART_BYTES // 1_000_000} MB" for p in e.truncated]
        redaction = {**rep.as_dict(), "counts": dict(rep.kinds)}
        record = {"format": RECORD_FORMAT, "tool": adapter.id, "creator": parsed.creator,
                  "file_sha256": batch.file_sha256, "row": e.row, "tool_id": e.tool_id, "time": e.time,
                  "method": e.method, "url": url, "status": e.status, "label": label,
                  "request_sha256": req_sha, "response_sha256": resp_sha,
                  "request_bytes": len(req or b""), "response_bytes": len(resp or b""),
                  "notes": notes, "redaction": rep.as_dict()}
        record_sha = blobs.put(ledger.canonical(record).encode(), engagement_id=eng.id)
        session.add(InboxEntry(engagement_id=eng.id, batch_id=batch.id, row=e.row, tool=adapter.id,
                               tool_id=e.tool_id, tool_time=e.time, host=host, method=e.method, url=url,
                               status=e.status, label=label, request_sha256=req_sha, response_sha256=resp_sha,
                               record_sha256=record_sha, content_sha256=content,
                               request_bytes=len(req or b""), response_bytes=len(resp or b""),
                               facts={**_facts(resp), "notes": notes}, redaction=redaction, mappings=[]))
        batch.accepted += 1
    batch.refused = refused
    session.flush()
    auditlog.append(session, actor=actor, action="import.batch", engagement_id=eng.id,
                    change={"after": {"batch_id": batch.id, "format": adapter.id, "creator": batch.creator,
                                      "filename": batch.filename, "file_sha256": batch.file_sha256,
                                      "rows": batch.rows, "accepted": batch.accepted,
                                      "out_of_scope": batch.out_of_scope, "duplicates": batch.duplicates,
                                      "unreadable": batch.unreadable,
                                      "out_of_scope_hosts": sorted({r["host"] for r in refused
                                                                    if r["reason"] == "out_of_scope"})}})
    return batch


# ---- suggestions ---------------------------------------------------------------------------
#
# Each rule looks at one thing about an entry (a word in its path, a parameter name, the
# method, the status, a response header) and points at checklist items whose text contains
# one of its words. A pack's own item texts add one more rule: a word of the path that also
# appears in an item's text. Suggestions are a starting point; the person decides.

_SEG = re.compile(r"[a-z][a-z0-9]{2,}")
_ID_SEG = re.compile(r"^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24,})$", re.I)
_REDIRECT_PARAMS = {"next", "redirect", "redirecturi", "redirecturl", "return", "returnto", "returnurl", "url",
                    "continue", "dest", "destination", "goto", "callback"}
_COMMON = {"api", "rest", "www", "html", "htm", "php", "aspx", "jsp", "json", "index", "test", "the", "and", "for",
           "with", "http", "https", "com", "net", "org", "static", "assets", "public"}


def _path_has(*words):
    """A rule that matches when one of the words is a whole part of the path."""
    rx = [(w, re.compile(r"(?:^|[/_.\-])" + re.escape(w) + r"(?:$|[/_.\-])")) for w in words]

    def match(_e, path):
        return next((f"the path has “{w}”" for w, r in rx if r.search(path)), None)
    return match


RULES = (
    ("sign-in", "Sign-in pages", _path_has("login", "signin", "sign-in", "logon", "auth", "oauth", "sso", "saml"),
     ("authentication", "credentials", "lockout", "auth")),
    ("password", "Password pages", _path_has("password", "passwd", "reset", "forgot", "recover"),
     ("password",)),
    ("registration", "Sign-up pages", _path_has("register", "registration", "signup", "sign-up", "join"),
     ("registration", "provisioning", "account enumeration")),
    ("logout", "Sign-out pages", _path_has("logout", "signout", "sign-out"), ("logout",)),
    ("admin", "Admin pages", _path_has("admin", "administrator", "manage", "console", "dashboard"),
     ("admin", "privilege", "role")),
    ("graphql", "GraphQL", _path_has("graphql", "graphiql"), ("graphql",)),
    ("upload", "Uploads", _path_has("upload", "uploads", "attachment", "attachments", "file", "files", "import"),
     ("upload", "file")),
    ("metafiles", "Metafiles", _path_has("robots.txt", "sitemap.xml", "security.txt", ".well-known",
                                         "crossdomain.xml", "clientaccesspolicy.xml"),
     ("metafiles", "cross-domain policy")),
    ("scripts", "Scripts and source maps", lambda e, p: "script file" if re.search(r"\.(js|mjs|map)$", p) else None,
     ("javascript", "client code", "sourcemaps", "source")),
    ("backup", "Backup files", lambda e, p: "backup-like name" if re.search(r"(\.bak|\.old|\.orig|\.swp|~)$", p)
     else None, ("backup",)),
    ("object-id", "Object ids in the path",
     lambda e, p: "an id in the path" if any(_ID_SEG.match(s) for s in p.split("/") if s) else None,
     ("direct object", "authorization", "access control", "privilege")),
    ("redirect", "Redirect parameters",
     lambda e, p: next((f"parameter {k}" for k in e["params"] if re.sub(r"[-_]", "", k.lower()) in _REDIRECT_PARAMS),
                       None),
     ("redirect",)),
    ("parameters", "Query parameters", lambda e, p: "query parameters" if e["params"] else None,
     ("injection", "cross-site scripting", "parameter pollution")),
    ("methods", "Unusual methods",
     lambda e, p: f"method {e['method']}" if e["method"] in ("OPTIONS", "TRACE", "PUT", "DELETE", "PATCH") else None,
     ("http methods", "verb tampering")),
    ("cookie", "Cookies set", lambda e, p: "the response sets a cookie" if e["facts"].get("sets_cookie") else None,
     ("cookie", "session")),
    ("cors", "CORS headers",
     lambda e, p: "the response has CORS headers" if e["facts"].get("cors") else None,
     ("cross-origin resource sharing",)),
    ("websocket", "WebSockets",
     lambda e, p: "a WebSocket upgrade" if e["status"] == 101 or e["facts"].get("upgrade") == "websocket" else None,
     ("websocket",)),
    ("denied", "Access denied",
     lambda e, p: f"status {e['status']}" if e["status"] in (401, 403) else None,
     ("authorization", "access control", "bypass")),
    ("errors", "Server errors",
     lambda e, p: f"status {e['status']}" if (e["status"] or 0) >= 500 else None,
     ("error handling", "stack traces")),
    ("plain-http", "Plain HTTP", lambda e, p: "the URL is plain http" if e["scheme"] == "http" else None,
     ("encrypted channel", "unencrypted", "transport")),
)

RULE_HELP = [{"id": rid, "title": title, "words": list(words)} for rid, title, _m, words in RULES]


def _context(entry: InboxEntry) -> tuple[dict, str]:
    parts = urlsplit(entry.url)
    params = [k for k, _ in parse_qsl(parts.query, keep_blank_values=True)][:50]
    return ({"method": entry.method, "status": entry.status, "facts": entry.facts or {}, "params": params,
             "scheme": parts.scheme.lower()}, (parts.path or "/").lower())


PER_LANE = 3


def suggest(entry: InboxEntry, lanes: list[Lane], limit: int = 6) -> list[dict]:
    """Items on the entry's own host that the rules point at, best first, each with why."""
    ctx, path = _context(entry)
    hits = []
    for rid, title, match, words in RULES:
        why = match(ctx, path)
        if why:
            hits.append((rid, title, why, words))
    path_words = {w for w in _SEG.findall(path) if w not in _COMMON and len(w) >= 4}
    scored = {}
    for lane in lanes:
        for item in lane.items:
            t = item.text.lower()
            reasons, score = [], 0
            for rid, title, why, words in hits:
                w = next((w for w in words if w in t), None)
                if w:
                    score += 2
                    reasons.append(f"{why[0].upper() + why[1:]} (rule “{title}”), and the item mentions “{w}”")
            for w in sorted(path_words):
                if re.search(rf"\b{re.escape(w)}", t):
                    score += 1
                    reasons.append(f"The path has the word “{w}”, which the item's text uses")
            if score:
                scored[(lane.id, item.idx)] = {"lane_id": lane.id, "role": lane.role, "item_idx": item.idx,
                                               "key": item.item_key, "text": item.text, "score": score,
                                               "why": reasons}
    # Best first, at most PER_LANE per lane, so one busy rule does not hide the others.
    out, per_lane = [], {}
    for sug in sorted(scored.values(), key=lambda s: (-s["score"], s["lane_id"], s["item_idx"])):
        if per_lane.get(sug["lane_id"], 0) < PER_LANE and len(out) < limit:
            per_lane[sug["lane_id"]] = per_lane.get(sug["lane_id"], 0) + 1
            out.append(sug)
    return out


def lanes_on(session, eng_id: int, host: str) -> list[Lane]:
    asset = session.scalar(select(Asset).where(Asset.engagement_id == eng_id, Asset.host == host))
    return sorted(asset.lanes, key=lambda l: l.id) if asset else []


# ---- mapping and dismissal -----------------------------------------------------------------

def _entries(session, eng_id: int, ids: list[int]) -> list[InboxEntry]:
    ids = list(dict.fromkeys(ids))
    if not ids:
        raise InboxError("choose at least one entry")
    if len(ids) > MAX_MAP_ENTRIES:
        raise InboxError(f"choose at most {MAX_MAP_ENTRIES} entries at a time")
    rows = {e.id: e for e in session.scalars(select(InboxEntry).where(InboxEntry.engagement_id == eng_id,
                                                                       InboxEntry.id.in_(ids)))}
    missing = [i for i in ids if i not in rows]
    if missing:
        raise InboxError(f"no inbox entry {missing[0]} in this engagement")
    return [rows[i] for i in ids]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def map_entries(session, eng: Engagement, entry_ids: list[int], targets: list[tuple[int, int]], *,
                note: str | None, user_id: int | None, user_name: str) -> list[int]:
    """Append one evidence entry per entry and item. Returns the new evidence ids. An entry
    already mapped to an item is not mapped to it again. The caller commits."""
    entries = _entries(session, eng.id, entry_ids)
    if not targets:
        raise InboxError("choose at least one checklist item")
    if len(targets) > MAX_MAP_TARGETS:
        raise InboxError(f"choose at most {MAX_MAP_TARGETS} items at a time")
    on = redact.enabled(eng)
    said = redact.Report()
    note = (note or "").strip()[:2_000]
    if note and on:
        note = redact.text(note, said)
    resolved = []
    for lane_id, idx in dict.fromkeys(targets):
        lane = session.get(Lane, lane_id)
        if lane is None or lane.asset.engagement_id != eng.id:
            raise InboxError(f"no lane {lane_id} in this engagement")
        item = next((i for i in lane.items if i.idx == idx), None)
        if item is None:
            raise InboxError(f"lane {lane_id} has no item {idx}")
        resolved.append((lane, item))
    for e in entries:
        if e.state == "dismissed":
            raise InboxError(f"entry {e.id} was dismissed; restore it before mapping it")
        wrong = [lane for lane, _ in resolved if lane.asset.host != e.host]
        if wrong:
            raise InboxError(f"entry {e.id} is for {e.host}; map it to a lane on {e.host}, "
                             f"not {wrong[0].asset.host}")

    added = []
    for e in entries:
        title = importers.registry()[e.tool].title if e.tool in importers.registry() else e.tool
        done = {(m["lane_id"], m["item_idx"]) for m in e.mappings or []}
        new_maps = list(e.mappings or [])
        for lane, item in resolved:
            if (lane.id, item.idx) in done:
                continue
            rep = _report_from(e.redaction).update(said)
            what = f"{e.method} {e.url[:300]} -> {e.status if e.status is not None else 'no response'}"
            summary = f"Imported from {title}, row {e.row}: {what}"
            if e.label:
                summary += f" ({e.label[:200]})"
            if note:
                summary += f". {note}"
            ev = ledger.append_evidence(session, lane, kind="response" if e.response_sha256 else "request",
                                        sha256_hex=e.record_sha256, uri=e.url[:1000], summary=summary + rep.suffix(),
                                        item_id=item.id, created_by=user_id, redaction=rep.as_dict(),
                                        source=f"import:{e.tool}")
            added.append(ev.id)
            new_maps.append({"evidence_id": ev.id, "lane_id": lane.id, "item_idx": item.idx, "item_key": item.item_key,
                             "by": user_id, "by_name": user_name, "at": _now().isoformat()})
        e.mappings = new_maps
        if new_maps:
            e.state = "mapped"
    session.flush()
    return added


def dismiss(session, eng: Engagement, entry_ids: list[int], *, reason: str | None, actor: dict,
            user_id: int | None) -> list[InboxEntry]:
    entries = _entries(session, eng.id, entry_ids)
    bad = [e.id for e in entries if e.state != "new"]
    if bad:
        raise InboxError(f"entry {bad[0]} is already {next(e.state for e in entries if e.id == bad[0])}; "
                         "only new entries can be dismissed")
    reason = (reason or "").strip()[:500] or None
    if reason and redact.enabled(eng):
        reason = redact.text(reason, redact.Report())
    when = _now()
    for e in entries:
        e.state, e.dismissed_by, e.dismissed_at, e.dismiss_reason = "dismissed", user_id, when, reason
        e.dismissed_by_name = auditlog.actor_label(actor)[:300]
    auditlog.append(session, actor=actor, action="import.dismissed", engagement_id=eng.id,
                    change={"after": {"entries": [e.id for e in entries], "reason": reason}})
    session.flush()
    return entries


def restore(session, eng: Engagement, entry_ids: list[int], *, actor: dict) -> list[InboxEntry]:
    """Undo a dismissal. The dismissal stays in the audit log."""
    entries = _entries(session, eng.id, entry_ids)
    bad = [e.id for e in entries if e.state != "dismissed"]
    if bad:
        raise InboxError(f"entry {bad[0]} is not dismissed")
    for e in entries:
        e.state, e.dismissed_by, e.dismissed_by_name, e.dismissed_at, e.dismiss_reason = "new", None, None, None, None
    auditlog.append(session, actor=actor, action="import.restored", engagement_id=eng.id,
                    change={"after": {"entries": [e.id for e in entries]}})
    session.flush()
    return entries


# ---- views -------------------------------------------------------------------------------

def batch_view(b: ImportBatch) -> dict:
    adapter = importers.registry().get(b.tool)
    return {"id": b.id, "format": b.tool, "format_title": adapter.title if adapter else b.tool,
            "creator": b.creator, "filename": b.filename, "file_sha256": b.file_sha256, "file_bytes": b.file_bytes,
            "rows": b.rows, "accepted": b.accepted, "out_of_scope": b.out_of_scope, "duplicates": b.duplicates,
            "unreadable": b.unreadable, "refused": b.refused or [], "created_by": b.created_by,
            "created_by_name": b.created_by_name, "created_at": iso_utc(b.created_at)}


def entry_view(e: InboxEntry) -> dict:
    return {"id": e.id, "batch_id": e.batch_id, "row": e.row, "format": e.tool, "tool_id": e.tool_id,
            "tool_time": e.tool_time, "host": e.host, "method": e.method, "url": e.url, "status": e.status,
            "label": e.label, "request_sha256": e.request_sha256, "response_sha256": e.response_sha256,
            "record_sha256": e.record_sha256, "request_bytes": e.request_bytes, "response_bytes": e.response_bytes,
            "notes": (e.facts or {}).get("notes", []), "content_type": (e.facts or {}).get("content_type") or None,
            "redaction": {k: v for k, v in (e.redaction or {}).items() if k != "counts"} or None,
            "state": e.state, "mappings": e.mappings or [],
            "dismissed": ({"by": e.dismissed_by, "by_name": e.dismissed_by_name, "at": iso_utc(e.dismissed_at),
                           "reason": e.dismiss_reason} if e.state == "dismissed" else None),
            "created_at": iso_utc(e.created_at)}


def item_targets(lanes: list[Lane]) -> list[dict]:
    return [{"lane_id": l.id, "role": l.role, "items": [{"idx": i.idx, "key": i.item_key, "text": i.text,
                                                         "state": i.state.value} for i in l.items]}
            for l in lanes]

