"""Append-only, hash-chained log of signing keys (D-036).

Every key registration and revocation appends one entry to the log of the person's
organization (each has its own chain from the same genesis value, D-042,
docs/ORGANIZATIONS.md; the record has no organization field, so the default organization's
chain is the one a self-hosted install always had):

    record_sha256 = sha256(canonical(record))
    entry_hash    = sha256(prev_hash + record_sha256)

Like the evidence chain, changing, removing or inserting an entry breaks every hash after
it. The link is over each record's hash rather than the record itself, so a report can
carry the full records of the keys that signed it and only the hashes of other people's
entries, and a reader can still walk the chain from the first of them to the head.

The server never holds a private key, so it cannot forge a signature. Someone who runs the
server could register a new key for a person; this log is how that shows: the person sees
it at their next sign-in, and every report carries the history of each key that signed it.
"""
from datetime import datetime, timezone

from sqlalchemy import select, text

from . import ledger, orgscope
from .models import KeyLogEntry, Organization, SigningKey, User

GENESIS = ledger.GENESIS
EVENTS = ("registered", "revoked")
# How it happened.
VIA = {
    "own_session": "from their own session",                       # signed in with a password they chose
    "assigned_password": "from a session signed in with a password someone else set",   # at creation or a reset
    "operator_cli": "by the operator on the server",               # python -m app.people
    "backfill": "before the key log existed (recorded when it was added)",
}
RECORD_FIELDS = ("seq", "user_id", "user_name", "key_fingerprint", "algorithm", "event", "at", "via")


def now_text() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def record(e: KeyLogEntry) -> dict:
    """The fields the chain commits to. The verifier rebuilds exactly this."""
    return {f: getattr(e, f) for f in RECORD_FIELDS}


def entry_hash(prev_hash: str, record_sha256: str) -> str:
    return ledger.sha256(prev_hash + record_sha256)


def append(session, *, user: User, key: SigningKey, event: str, via: str, at: str | None = None) -> KeyLogEntry:
    if event not in EVENTS or via not in VIA:
        raise ValueError(f"unknown key log event {event!r} or origin {via!r}")
    # One chain per organization: serialize its appends. (organization, seq) is unique as well,
    # so a second writer that slipped past the lock fails instead of forking the chain.
    org = orgscope.owner(session, (User, user.id))
    if session.bind.dialect.name == "postgresql":
        session.execute(text("SELECT pg_advisory_xact_lock(7036, :org)"), {"org": org})
    last = _last(session, org)
    e = KeyLogEntry(organization_id=org, seq=(last.seq + 1) if last else 1, user_id=user.id, user_name=user.name,
                    key_fingerprint=key.fingerprint, algorithm=key.algorithm, event=event,
                    at=at or now_text(), via=via, prev_hash=last.entry_hash if last else GENESIS)
    e.record_sha256 = ledger.sha256(ledger.canonical(record(e)))
    e.entry_hash = entry_hash(e.prev_hash, e.record_sha256)
    session.add(e)
    session.flush()
    return e


def _last(session, org: int) -> KeyLogEntry | None:
    return session.scalars(select(KeyLogEntry).where(KeyLogEntry.organization_id == org)
                           .order_by(KeyLogEntry.seq.desc()).limit(1)).first()


def verify(session, organization_id: int | None = None) -> list[str]:
    """Walk each organization's log from the genesis value: the one named, the session's, or
    (the operator) every one."""
    if organization_id is not None:
        orgs = [organization_id]
    elif orgscope.current(session) is not None:
        orgs = [orgscope.current(session)]
    else:
        with orgscope.unscoped(session):
            orgs = list(session.scalars(select(Organization.id).order_by(Organization.id)))
    out = []
    for org in orgs:
        out += [f"organization {org}: {p}" if len(orgs) > 1 else p for p in _verify(session, org)]
    return out


def _verify(session, org: int) -> list[str]:
    problems, prev = [], GENESIS
    rows = session.scalars(select(KeyLogEntry).where(KeyLogEntry.organization_id == org).order_by(KeyLogEntry.seq))
    for n, e in enumerate(rows, start=1):
        if e.seq != n:
            problems.append(f"key log entry {e.seq} out of order (expected {n})")
        if e.prev_hash != prev:
            problems.append(f"key log entry {e.seq}: link to the previous entry is broken")
        if ledger.sha256(ledger.canonical(record(e))) != e.record_sha256:
            problems.append(f"key log entry {e.seq}: content does not match its record hash")
        if entry_hash(e.prev_hash, e.record_sha256) != e.entry_hash:
            problems.append(f"key log entry {e.seq}: does not match its chain hash")
        prev = e.entry_hash
    return problems


def since(session, user_id: int, when: datetime | None) -> list[KeyLogEntry]:
    """This person's key events at or after a time (all of them if there is no time)."""
    q = select(KeyLogEntry).where(KeyLogEntry.user_id == user_id).order_by(KeyLogEntry.seq)
    rows = list(session.scalars(q))
    if when is None:
        return rows
    cut = when if when.tzinfo else when.replace(tzinfo=timezone.utc)
    return [e for e in rows if datetime.fromisoformat(e.at) >= cut]


def for_report(session, fingerprints: set[str], organization_id: int) -> dict | None:
    """The history of the keys that signed a report, and the links from its first entry to
    the head of the organization's chain, so a reader can check that the entries are in the
    chain and in order."""
    if not fingerprints:
        return None
    org = organization_id
    entries = list(session.scalars(select(KeyLogEntry).where(KeyLogEntry.organization_id == org,
                                                             KeyLogEntry.key_fingerprint.in_(sorted(fingerprints)))
                                   .order_by(KeyLogEntry.seq)))
    last = _last(session, org)
    links = [] if not entries else list(session.scalars(
        select(KeyLogEntry).where(KeyLogEntry.organization_id == org, KeyLogEntry.seq >= entries[0].seq)
        .order_by(KeyLogEntry.seq)))
    return {
        "genesis": GENESIS,
        "head": {"seq": last.seq if last else 0, "entry_hash": last.entry_hash if last else GENESIS},
        "links": [{"seq": e.seq, "prev_hash": e.prev_hash, "record_sha256": e.record_sha256,
                   "entry_hash": e.entry_hash} for e in links],
        "entries": [record(e) for e in entries],
    }
