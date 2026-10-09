"""Append-only, hash-chained log of administrative changes (D-037).

Scope and rules, authorization records, engagement settings, roles and people: every
change appends one entry, in the same transaction as the change, to its organization's log.
Each organization has its own chain, from the same genesis value with its own head (D-042,
docs/ORGANIZATIONS.md), so a report never carries another organization's entries or head. The
record has no organization field: a self-hosted install's chain, the default organization's,
is the chain it always had, and reports issued before 0022 verify unchanged.

    record_sha256 = sha256(canonical(record))
    entry_hash    = sha256(prev_hash + record_sha256)

The same construction as the key log (keylog.py): changing, removing or inserting an entry
breaks every hash after it, and because the link is over each record's hash, a report can
carry the full records of its own engagement and people and only the hashes of the rest.

An entry names who acted (a person with their name and email at the time, the operator
token, the operator on the server, or open mode), a stable action name, the engagement when
there is one, the person a person.* entry is about, and the change as before and after
values. Passwords and secrets are never recorded; that a password was set is.
"""
import json
from datetime import datetime, timezone

from sqlalchemy import and_, or_, select, text

from . import ledger, orgscope
from .models import AuditEntry, Engagement, Membership, Organization, User

GENESIS = ledger.GENESIS
ACTORS = {
    "person": "",                                   # their name and email
    "token": "the operator token",
    "cli": "the operator on the server",
    "open": "open mode (no sign-in)",
    "backfill": "recorded when the audit log was added",
    "retention": "the retention policy",
    "gateway": "the traffic gateway",               # it sends an approved write (D-041)
}
ACTIONS = (
    "engagement.created", "scope.updated", "engagement.authorized", "engagement.settings", "members.updated",
    "engagement.retention", "engagement.content_deleted",
    "person.created", "person.renamed", "person.owner", "person.disabled", "person.enabled",
    "person.password_reset", "person.password_changed",
    "import.batch", "import.dismissed", "import.restored",
    # A receipted lane changed: its receipt is void until someone signs again (gates.py).
    "lane.receipt_voided", "lane.item_updated",
    "account.added", "account.replaced", "account.deleted", "engagement.writes",
    "write.approved", "write.delete_confirmed", "write.rejected", "write.sent",
)
RECORD_FIELDS = ("seq", "at", "actor", "action", "engagement_id", "subject_id", "change")
CLI = {"kind": "cli", "user_id": None, "name": "operator CLI", "email": None}


def now_text() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def actor(who) -> dict:
    """The actor of an API request, from authz.current(request)."""
    if who.kind == "person":
        return {"kind": "person", "user_id": who.user_id, "name": who.name, "email": who.email or None}
    if who.kind == "token":
        return {"kind": "token", "user_id": None, "name": "operator token", "email": None}
    return {"kind": "open", "user_id": None, "name": "open mode", "email": None}


def starter(session, user_id: int | None) -> dict:
    """The actor of something a run did, such as recon evidence: the person who started the
    run, or the operator token or open mode when no person did."""
    user = session.get(User, user_id) if user_id is not None else None
    if user is not None:
        return {"kind": "person", "user_id": user.id, "name": user.name, "email": user.email or None}
    from . import auth
    if auth.mode(session) == "open":
        return {"kind": "open", "user_id": None, "name": "open mode", "email": None}
    return {"kind": "token", "user_id": None, "name": "operator token", "email": None}


def record(e: AuditEntry) -> dict:
    """The fields the chain commits to. The verifier rebuilds exactly this."""
    return {"seq": e.seq, "at": e.at,
            "actor": {"kind": e.actor_kind, "user_id": e.actor_user_id, "name": e.actor_name, "email": e.actor_email},
            "action": e.action, "engagement_id": e.engagement_id, "subject_id": e.subject_id,
            "change": json.loads(e.change)}


def entry_hash(prev_hash: str, record_sha256: str) -> str:
    return ledger.sha256(prev_hash + record_sha256)


def append(session, *, actor: dict, action: str, change: dict, engagement_id: int | None = None,
           subject_id: int | None = None, at: str | None = None) -> AuditEntry:
    """Add one entry. The caller commits, together with the change it records."""
    if action not in ACTIONS or actor.get("kind") not in ACTORS:
        raise ValueError(f"unknown audit action {action!r} or actor {actor.get('kind')!r}")
    # The organization's chain, as in keylog.append: serialize its appends; (organization, seq)
    # is unique too, so a writer that slipped past the lock fails instead of forking the chain.
    org = orgscope.owner(session, (Engagement, engagement_id), (User, subject_id), (User, actor.get("user_id")))
    if session.bind.dialect.name == "postgresql":
        session.execute(text("SELECT pg_advisory_xact_lock(7037, :org)"), {"org": org})
    last = _last(session, org)
    e = AuditEntry(organization_id=org, seq=(last.seq + 1) if last else 1, at=at or now_text(), actor_kind=actor["kind"],
                   actor_user_id=actor.get("user_id"), actor_name=actor.get("name") or "",
                   actor_email=actor.get("email"), action=action, engagement_id=engagement_id,
                   subject_id=subject_id, change=ledger.canonical(change),
                   prev_hash=last.entry_hash if last else GENESIS)
    e.record_sha256 = ledger.sha256(ledger.canonical(record(e)))
    e.entry_hash = entry_hash(e.prev_hash, e.record_sha256)
    session.add(e)
    session.flush()
    return e


def _last(session, org: int) -> AuditEntry | None:
    return session.scalars(select(AuditEntry).where(AuditEntry.organization_id == org)
                           .order_by(AuditEntry.seq.desc()).limit(1)).first()


def chains(session, organization_id: int | None = None) -> list[int]:
    """Whose chains to walk: the one named, the session's, or (the operator) every one."""
    if organization_id is not None:
        return [organization_id]
    if orgscope.current(session) is not None:
        return [orgscope.current(session)]
    with orgscope.unscoped(session):
        return list(session.scalars(select(Organization.id).order_by(Organization.id)))


def verify(session, organization_id: int | None = None) -> list[str]:
    """Walk each organization's log from the genesis value (see chains)."""
    orgs = chains(session, organization_id)
    out = []
    for org in orgs:
        out += [f"organization {org}: {p}" if len(orgs) > 1 else p for p in _verify(session, org)]
    return out


def _verify(session, org: int) -> list[str]:
    problems, prev = [], GENESIS
    rows = session.scalars(select(AuditEntry).where(AuditEntry.organization_id == org).order_by(AuditEntry.seq))
    for n, e in enumerate(rows, start=1):
        if e.seq != n:
            problems.append(f"audit log entry {e.seq} out of order (expected {n})")
        if e.prev_hash != prev:
            problems.append(f"audit log entry {e.seq}: link to the previous entry is broken")
        try:
            same = ledger.sha256(ledger.canonical(record(e))) == e.record_sha256
        except ValueError:
            same = False
        if not same:
            problems.append(f"audit log entry {e.seq}: content does not match its record hash")
        if entry_hash(e.prev_hash, e.record_sha256) != e.entry_hash:
            problems.append(f"audit log entry {e.seq}: does not match its chain hash")
        prev = e.entry_hash
    return problems


# ---- what is recorded ------------------------------------------------------------

def scope_snapshot(eng: Engagement) -> dict:
    return {"include": list(eng.scope_include or []), "exclude": list(eng.scope_exclude or []),
            "rate_limit_rps": eng.rate_limit_rps, "research_header": eng.research_header,
            "research_user_agent": eng.research_user_agent, "enabled_modules": sorted(eng.enabled_modules or []),
            "crawl_depth": eng.crawl_depth}


def settings_snapshot(eng: Engagement) -> dict:
    return {"separation_of_duties": bool(eng.separation_of_duties), "require_signatures": bool(eng.require_signatures),
            "redact_evidence": bool(getattr(eng, "redact_evidence", True))}


def authorization_snapshot(eng: Engagement) -> dict:
    at = eng.authorized_at
    if at is not None and at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    return {"authorized_by": eng.authorized_by, "policy_url": eng.policy_url,
            "authorized_at": at.isoformat() if at else None}


def members_snapshot(session, eng_id: int) -> list[dict]:
    users = {u.id: u for u in session.scalars(select(User))}
    rows = session.scalars(select(Membership).where(Membership.engagement_id == eng_id)).all()
    return sorted(({"user_id": m.user_id, "name": users[m.user_id].name, "email": users[m.user_id].email,
                    "roles": sorted(m.roles or [])} for m in rows if m.user_id in users and m.roles),
                  key=lambda m: m["user_id"])


def person_ref(user: User) -> dict:
    return {"id": user.id, "name": user.name, "email": user.email}


def person_snapshot(user: User) -> dict:
    return {"email": user.email, "name": user.name, "is_owner": bool(user.is_owner), "disabled": bool(user.disabled)}


# ---- reading it ------------------------------------------------------------------

def people_of(session, eng_id: int, signers: set[int] | None = None) -> set[int]:
    """Whose person events belong with an engagement: its members now, everyone a role
    change on it named, and the people who signed its receipts."""
    ids = set(signers or ()) | set(session.scalars(select(Membership.user_id).where(Membership.engagement_id == eng_id)))
    for e in session.scalars(select(AuditEntry).where(AuditEntry.engagement_id == eng_id,
                                                      AuditEntry.action == "members.updated")):
        ch = json.loads(e.change)
        for m in (ch.get("before") or []) + (ch.get("after") or []):
            ids.add(m["user_id"])
    return ids


def for_engagement(session, eng_id: int, people: set[int]) -> list[AuditEntry]:
    q = select(AuditEntry).where(or_(AuditEntry.engagement_id == eng_id,
                                     and_(AuditEntry.action.like("person.%"),
                                          AuditEntry.subject_id.in_(sorted(people)))))
    return list(session.scalars(q.order_by(AuditEntry.seq)))


def head(session, organization_id: int | None = None) -> dict:
    """The head of one organization's chain: the session's, or the default one's."""
    org = organization_id or orgscope.current(session) or orgscope.default_id(session)
    last = _last(session, org)
    return {"seq": last.seq if last else 0, "entry_hash": last.entry_hash if last else GENESIS}


def for_report(session, eng_id: int, people: set[int]) -> dict | None:
    """The engagement's entries and its people's, with the links from the first of them to
    the head of its organization's chain (hashes only), so a reader can check that they are in
    the chain and in order."""
    org = session.get(Engagement, eng_id).organization_id
    entries = [e for e in for_engagement(session, eng_id, people) if e.organization_id == org]
    if not entries:
        return None
    links = session.scalars(select(AuditEntry).where(AuditEntry.organization_id == org,
                                                     AuditEntry.seq >= entries[0].seq).order_by(AuditEntry.seq))
    return {
        "genesis": GENESIS,
        "head": head(session, org),
        "links": [{"seq": e.seq, "prev_hash": e.prev_hash, "record_sha256": e.record_sha256,
                   "entry_hash": e.entry_hash} for e in links],
        "entries": [record(e) for e in entries],
    }


def view(e: AuditEntry) -> dict:
    rec = record(e)
    return {**rec, "actor_label": actor_label(rec["actor"]), "text": describe(rec)}


# ---- plain language ------------------------------------------------------------------

_SCOPE = (("include", "in scope"), ("exclude", "out of scope"), ("rate_limit_rps", "rate limit"),
          ("research_header", "identification header"), ("research_user_agent", "user agent"),
          ("enabled_modules", "opt-in modules"), ("crawl_depth", "crawl depth"))
_SETTINGS = (("separation_of_duties", "separation of duties"), ("require_signatures", "required signatures"),
             ("redact_evidence", "evidence redaction"))


def actor_label(a: dict) -> str:
    if a.get("kind") == "person":
        return f"{a.get('name')} ({a.get('email')})" if a.get("email") else str(a.get("name"))
    return ACTORS.get(a.get("kind"), str(a.get("kind")))


def _scope_value(key: str, v) -> str:
    if isinstance(v, list):
        return ", ".join(v) if v else "none"
    if v is None:
        return "not set"
    if key == "rate_limit_rps":
        return f"{v} requests per second"
    return str(v)


def _who(p: dict | None) -> str:
    p = p or {}
    return f"{p.get('name')} ({p.get('email')})" if p.get("email") else str(p.get("name", "someone"))


def _roles(roles) -> str:
    return ", ".join(roles) if roles else "none"


def _n(n, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


_ITEM_STATE = {"open": "open", "done": "done", "na": "not applicable"}


def _cause(c: dict) -> str:
    """What changed a receipted lane, for lane.* entries."""
    if c.get("kind") == "item":
        old, new = (c.get("before") or {}).get("state"), (c.get("after") or {}).get("state")
        item = f"item {c.get('idx')} ({c.get('key')})"
        if old == new:
            return f"Changed the not-applicable reason of {item}"
        did = {"open": f"Reopened {item}", "done": f"Marked {item} done",
               "na": f"Marked {item} not applicable"}.get(new, f"Set {item} to {new}")
        return f"{did} (it was {_ITEM_STATE.get(old, old)})"
    if c.get("kind") == "evidence":
        to = f"item {c['item_idx']}" if c.get("item_idx") is not None else "the lane"
        return f"Added evidence {c.get('evidence_id')} to {to} ({c.get('source')})"
    if c.get("kind") == "import":
        ev = c.get("evidence") or []
        out = f"Mapped {_n(len(c.get('entries') or []), 'imported entry', 'imported entries')} as " \
              f"{_n(len(ev), 'evidence entry', 'evidence entries')}"
        return out + (" and confirmed that this voids the receipt" if c.get("confirmed") else "")
    return "Changed the lane"


def describe(rec: dict) -> str:
    """One sentence for an entry, for the History view and the report."""
    a, ch = rec.get("action"), rec.get("change") or {}
    before, after = ch.get("before"), ch.get("after") or {}
    snapshot = before is None and (rec.get("actor") or {}).get("kind") == "backfill"
    if a == "engagement.created":
        return (f"Created the engagement “{after.get('name')}” ({after.get('engagement_type')}, "
                f"pack {after.get('pack_id')})")
    if a == "scope.updated":
        if before is None:
            parts = [f"{label} {_scope_value(k, after.get(k))}" for k, label in _SCOPE]
            lead = "Scope when the audit log was added: " if snapshot else "Set the scope: "
        else:
            parts = [f"{label} {_scope_value(k, after.get(k))} (was {_scope_value(k, before.get(k))})"
                     for k, label in _SCOPE if before.get(k) != after.get(k)]
            lead = "Changed the scope: "
        if ch.get("import"):
            lead = f"Imported scope from a CSV ({ch['import']}): "
        out = lead + ("; ".join(parts) or "no rule changed")
        if ch.get("hosts_added"):
            out += f"; added hosts {', '.join(ch['hosts_added'])}"
        return out
    if a == "engagement.authorized":
        out = (f"Recorded authorization to test, by {after.get('authorized_by')}, "
               f"under {after.get('policy_url') or 'no policy URL'}")
        if snapshot:
            out = (f"Authorization when the audit log was added: by {after.get('authorized_by')}, "
                   f"under {after.get('policy_url') or 'no policy URL'}, recorded {after.get('authorized_at')}")
        elif before and before.get("authorized_by"):
            out += f" (replacing the record by {before.get('authorized_by')})"
        return out
    if a == "engagement.settings":
        if before is None:
            return ("Settings when the audit log was added: " if snapshot else "Settings: ") + "; ".join(
                f"{label} {'on' if after.get(k) else 'off'}" for k, label in _SETTINGS)
        return "; ".join(f"Turned {label} {'on' if after.get(k) else 'off'}"
                         for k, label in _SETTINGS if before.get(k) != after.get(k)) or "Saved the settings unchanged"
    if a == "engagement.retention":
        new, old = after.get("retain_until"), (before or {}).get("retain_until")
        if not new:
            return "Removed the retention date: the content is kept until someone deletes it" + (
                f" (was {old})" if old else "")
        return f"Set the retention date: the content is kept until {new}, then deleted" + (f" (was {old})" if old else "")
    if a == "engagement.content_deleted":
        removed, kept = ch.get("removed") or {}, ch.get("kept") or {}
        why = {"retention": "because its retention date had passed", "owner": "at an owner's request",
               "operator": "by the operator on the server"}.get(after.get("reason"), "")
        out = (f"Deleted the engagement's content {why}: its key, its raw evidence, "
               f"{removed.get('summaries', 0)} evidence summaries and its recon results. Hashes, receipts "
               "and this history remain")
        if kept.get("v1_summaries"):
            out += f"; {kept['v1_summaries']} summaries recorded before chain v2 remain, because the chain covers their text"
        return out
    if a == "members.updated":
        old = {m["user_id"]: m for m in (before or [])}
        new = {m["user_id"]: m for m in (ch.get("after") or [])}
        if before is None:
            parts = [f"{_who(m)}: {_roles(m['roles'])}" for m in new.values()]
            return ("Roles when the audit log was added: " if snapshot else "Set the roles: ") + ("; ".join(parts) or "no one")
        parts = []
        for uid in sorted(set(old) | set(new)):
            o, n = old.get(uid), new.get(uid)
            if o and not n:
                parts.append(f"{_who(o)} removed (was {_roles(o['roles'])})")
            elif n and not o:
                parts.append(f"{_who(n)} added as {_roles(n['roles'])}")
            elif o["roles"] != n["roles"]:
                parts.append(f"{_who(n)}: {_roles(n['roles'])} (was {_roles(o['roles'])})")
        return "Changed the roles: " + ("; ".join(parts) or "no change")
    if a == "import.batch":
        # Entries before 0.7 named the file and the refused hosts. The chain keeps them, but the
        # sentence (the History tab and the client report) gives only how many hosts there were.
        tool = f"{after.get('format')}{', ' + after['creator'] if after.get('creator') else ''}"
        if after.get("filename"):
            name = f"“{after['filename']}” ({tool})"
        else:
            name = f"a file ({tool}{', SHA-256 ' + after['file_sha256'][:12] + '…' if after.get('file_sha256') else ''})"
        hosts = after.get("out_of_scope_host_count", len(after.get("out_of_scope_hosts") or []))
        out = (f"Imported {name}: "
               f"{_n(after.get('accepted'), 'entry', 'entries')} to the inbox, "
               f"{after.get('out_of_scope', 0)} refused as out of scope"
               f"{' (' + _n(hosts, 'host', 'hosts') + ')' if hosts else ''}, "
               f"{_n(after.get('duplicates', 0), 'duplicate', 'duplicates')}, "
               f"{after.get('unreadable', 0)} unreadable")
        if after.get("repeat_of"):
            out += f"; the same file as import {after['repeat_of']}, imported again on purpose"
        return out
    if a in ("import.dismissed", "import.restored"):
        ids = after.get("entries") or []
        verb = "Dismissed" if a == "import.dismissed" else "Restored"
        out = f"{verb} {_n(len(ids), 'inbox entry', 'inbox entries')} ({', '.join(str(i) for i in ids[:20])}"
        out += f" and {len(ids) - 20} more)" if len(ids) > 20 else ")"
        return out + (f": {after['reason']}" if after.get("reason") else "")
    if a in ("lane.receipt_voided", "lane.item_updated"):
        lane, rc = ch.get("lane") or {}, ch.get("receipt") or {}
        where = f"{lane.get('host')} / {lane.get('role')}"
        sha = f"{(rc.get('manifest_sha256') or '')[:12]}…"
        what = _cause(ch.get("cause") or {})
        if a == "lane.item_updated":
            return f"{what} on {where}, whose receipt {sha} is void; the lane needs a new signature"
        return (f"{what} on {where}, which voided its receipt {sha} signed by {rc.get('closed_by') or 'someone'}. "
                "The lane needs a new signature, even if it is changed back")
    if a in ("account.added", "account.replaced", "account.deleted"):
        acc = after if a != "account.deleted" else (before or {})
        what = (f"test account {acc.get('label')} ({acc.get('role')}, {acc.get('kind')}, for "
                f"{', '.join(acc.get('hosts') or []) or 'no host'}, fingerprint {acc.get('fingerprint')})")
        if a == "account.added":
            return f"Added {what}; the session material is stored encrypted and never shown"
        if a == "account.deleted":
            return f"Deleted {what}"
        changed = [k for k in ("role", "hosts", "kind", "fingerprint") if (before or {}).get(k) != after.get(k)]
        return f"Replaced {', '.join('the session material' if k == 'fingerprint' else k for k in changed)} of {what}"
    if a == "engagement.writes":
        return ("Allowed agents to propose writes; each one waits for a person's approval" if after.get("allow_writes")
                else "Stopped agents proposing writes: only read-only requests are sent")
    if a.startswith("write."):
        w = after
        req = f"write {w.get('proposal')} ({w.get('method')} on {w.get('host')}" + (
            f" as test account {w['account']}" if w.get("account") else "") + \
            f", request SHA-256 {str(w.get('request_sha256'))[:12]}…)"
        note = f": {w['note']}" if w.get("note") else ""
        if a == "write.approved":
            return f"Approved {req}{note}" + ("; it waits for the DELETE confirmation" if
                                               w.get("waits_for_delete_confirmation") else "")
        if a == "write.delete_confirmed":
            return f"Confirmed the DELETE of {req} by typing its path {w.get('path')}"
        if a == "write.rejected":
            return f"Rejected {req}{note}"
        return f"Sent the approved {req}, once"
    person = _who(ch.get("person"))
    if a == "person.created":
        if snapshot:
            flags = [w for w, on in (("owner", after.get("is_owner")), ("disabled", after.get("disabled"))) if on]
            return f"Person when the audit log was added: {person}" + (f", {', '.join(flags)}" if flags else "")
        return (f"Added {person}{' as an owner' if after.get('is_owner') else ''}; "
                "whoever added them set the first password")
    if a == "person.renamed":
        return f"Renamed {before.get('name')} to {after.get('name')} ({(ch.get('person') or {}).get('email')})"
    if a == "person.owner":
        return f"Made {person} an owner" if after.get("is_owner") else f"Removed owner rights from {person}"
    if a == "person.disabled":
        return f"Disabled the account of {person} and signed them out"
    if a == "person.enabled":
        return f"Enabled the account of {person}"
    if a == "person.password_reset":
        return (f"Reset the password of {person} on the server and signed them out; the operator knows it "
                "until they choose their own")
    if a == "person.password_changed":
        return f"{person} chose their own password"
    return str(a)
