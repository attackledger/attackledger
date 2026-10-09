"""Test accounts: signed-in sessions an agent uses through the gateway, never sees (D-040).

A person creates the accounts on the target and signs in to them, always by hand: AttackLedger
never creates accounts or enters passwords. They paste what the sign-in gave them, one of:

  cookie    the value of a Cookie header ("sid=...; theme=dark")
  bearer    a token, sent as "Authorization: Bearer <token>"
  headers   a set of "Name: value" lines (an API key header, several cookies and a CSRF header)

with a label (A, B, ...), the role the account has in the target application, and the in-scope
hosts it is for. The material is sealed with the engagement's key (vault.seal_secret, D-043) and
never leaves the API again except to the gateway, over its authenticated channel, for a request
an agent job sends "as" that label to one of those hosts. The API shows a fingerprint (a SHA-256
of the material), when it was added, replaced and last used. Adding, replacing and deleting are
audit-logged without the value; deleting the engagement's content deletes the accounts.

  GET  /engagements/{id}/test-accounts                     the accounts, without their material
  POST /engagements/{id}/test-accounts                     add one (tester)
  PUT  /engagements/{id}/test-accounts/{account_id}        replace its material, role or hosts (tester)
  POST /engagements/{id}/test-accounts/{account_id}/delete delete it (tester)

How a request is sent "as" an account is docs/GATEWAY.md, decision 9.
"""
import json
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete as sa_delete, select
from sqlalchemy.orm import Session

from . import auditlog, authz, ledger, scope, vault
from .db import get_session
from .models import Engagement, TestAccount, User, iso_utc

router = APIRouter()

KINDS = ("cookie", "bearer", "headers")
LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,15}$")
PURPOSE = "test-account"
MAX_VALUE = 8000
MAX_HEADERS = 10
# Header names an account may not set: the connection's own, the gateway's and the proxy's.
# The engagement's identification header is refused too (it is always the engagement's).
RESERVED = frozenset({"host", "content-length", "transfer-encoding", "connection", "keep-alive", "te", "trailer",
                      "upgrade", "expect", "proxy-authorization", "proxy-connection", "user-agent"})
_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,100}$")


def now() -> datetime:
    return datetime.now(timezone.utc)


def _bad(value: str) -> bool:
    return any(c in value for c in "\r\n\0")


def material(kind: str, value: str, eng: Engagement) -> list[list[str]]:
    """The headers an account sets, as [name, value] pairs, from what a person pasted.
    Raises ValueError with a sentence for the person."""
    value = (value or "").strip()
    if kind not in KINDS:
        raise ValueError(f"kind must be one of: {', '.join(KINDS)}")
    if not value:
        raise ValueError("paste the session material: a cookie header value, a token or header lines")
    if len(value) > MAX_VALUE:
        raise ValueError(f"the session material is longer than {MAX_VALUE} characters")
    if kind == "cookie":
        if _bad(value):
            raise ValueError("a cookie header value is one line")
        v = value[len("cookie:"):].strip() if value.lower().startswith("cookie:") else value
        if "=" not in v:
            raise ValueError("a cookie header looks like name=value; name2=value2")
        return [["Cookie", v]]
    if kind == "bearer":
        v = value[len("bearer "):].strip() if value.lower().startswith("bearer ") else value
        if _bad(v) or " " in v:
            raise ValueError("a bearer token is one word, without spaces")
        return [["Authorization", f"Bearer {v}"]]
    pairs, seen = [], set()
    ident = (eng.research_header or "").partition(":")[0].strip().lower()
    for line in value.replace("\r\n", "\n").split("\n"):
        if not line.strip():
            continue
        name, sep, v = line.partition(":")
        name, v = name.strip(), v.strip()
        if not sep or not _NAME.match(name) or not v or "\0" in v:
            raise ValueError(f"each line is Name: value ({line[:40]!r} is not)")
        low = name.lower()
        if low in RESERVED or low.startswith("x-attackledger-") or low.startswith("proxy-") or (ident and low == ident):
            raise ValueError(f"{name} is set by AttackLedger or the connection, not by a test account")
        if low in seen:
            raise ValueError(f"{name} appears twice")
        seen.add(low)
        pairs.append([name, v])
    if not pairs:
        raise ValueError("paste at least one Name: value line")
    if len(pairs) > MAX_HEADERS:
        raise ValueError(f"at most {MAX_HEADERS} headers")
    return pairs


def check_hosts(hosts: list[str], eng: Engagement) -> list[str]:
    out = []
    for h in hosts:
        try:
            host = scope.normalize_host(h)
        except scope.ScopeError as e:
            raise ValueError(str(e))
        if not scope.in_scope(host, eng.scope_include or [], eng.scope_exclude or []):
            raise ValueError(f"{host} is not in scope")
        if host not in out:
            out.append(host)
    if not out:
        raise ValueError("name the in-scope hosts this account is for")
    return out


def short(fingerprint: str) -> str:
    return f"sha256:{fingerprint[:16]}"


def view(a: TestAccount, names: dict[int, str] | None = None) -> dict:
    """What anyone may see of an account: never the material."""
    return {"id": a.id, "label": a.label, "role": a.role, "hosts": list(a.hosts or []), "kind": a.kind,
            "header_names": list(a.header_names or []), "fingerprint": short(a.fingerprint),
            "created_at": iso_utc(a.created_at), "created_by": (names or {}).get(a.created_by),
            "replaced_at": iso_utc(a.replaced_at), "last_used_at": iso_utc(a.last_used_at)}


def _audit_ref(a: TestAccount) -> dict:
    return {"label": a.label, "role": a.role, "hosts": list(a.hosts or []), "kind": a.kind,
            "header_names": list(a.header_names or []), "fingerprint": short(a.fingerprint)}


def _seal(eng: Engagement, pairs: list[list[str]]) -> tuple[str, str]:
    return vault.seal_secret(eng.id, PURPOSE, ledger.canonical({"headers": pairs}))


def open_material(a: TestAccount) -> list[list[str]] | None:
    text = vault.open_secret(a.engagement_id, PURPOSE, a.material_enc, a.fingerprint)
    return None if text is None else json.loads(text)["headers"]


def for_context(session, eng: Engagement, host: str) -> list[dict]:
    """The lane context's list (agents): labels, roles and whether each is usable on the lane's
    host. No secrets, and not even the header names."""
    rows = session.scalars(select(TestAccount).where(TestAccount.engagement_id == eng.id).order_by(TestAccount.label))
    on = redact_on(eng)
    return [{"label": a.label, "role": a.role, "usable_on_this_host": on and host in (a.hosts or [])} for a in rows]


def usable(session, eng: Engagement, label: str, host: str) -> TestAccount:
    """The account `label` if a request to `host` may be sent as it, or ValueError saying why."""
    if not redact_on(eng):
        raise ValueError("test accounts are used only while evidence redaction is on (D-038)")
    a = session.scalar(select(TestAccount).where(TestAccount.engagement_id == eng.id, TestAccount.label == label))
    if a is None:
        raise ValueError(f"this engagement has no test account {label[:16]!r}")
    if host not in (a.hosts or []):
        raise ValueError(f"test account {a.label} is not for {host} (it is for {', '.join(a.hosts) or 'no host'})")
    if not scope.in_scope(host, eng.scope_include or [], eng.scope_exclude or []):
        raise ValueError(f"{host} is not in scope")
    return a


def redact_on(eng: Engagement) -> bool:
    return getattr(eng, "redact_evidence", True) is not False


def wipe(session, eng_id: int) -> dict:
    """Deleting an engagement's content deletes its test accounts (D-043)."""
    n = session.execute(sa_delete(TestAccount).where(TestAccount.engagement_id == eng_id)).rowcount or 0
    return {"test_accounts": n}


# ---- routes ------------------------------------------------------------------------

class AccountIn(BaseModel):
    label: str = Field(min_length=1, max_length=16)
    role: str = Field(min_length=1, max_length=100)
    hosts: list[str] = Field(min_length=1, max_length=20)
    kind: str = Field(pattern="^(cookie|bearer|headers)$")
    value: str = Field(min_length=1, max_length=MAX_VALUE)


class AccountReplace(BaseModel):
    role: str | None = Field(default=None, min_length=1, max_length=100)
    hosts: list[str] | None = Field(default=None, min_length=1, max_length=20)
    kind: str | None = Field(default=None, pattern="^(cookie|bearer|headers)$")
    value: str | None = Field(default=None, min_length=1, max_length=MAX_VALUE)


def _eng(session, eng_id: int) -> Engagement:
    eng = session.get(Engagement, eng_id)
    if eng is None:
        raise HTTPException(404, "not found")
    return eng


def _writable(eng: Engagement) -> None:
    try:
        vault.check_writable(eng)
    except vault.ContentDeleted as e:
        raise HTTPException(409, str(e))
    if not redact_on(eng):
        raise HTTPException(409, "turn evidence redaction on first: test accounts are used only with it (D-038)")


def _names(session) -> dict[int, str]:
    return {u.id: u.name for u in session.scalars(select(User))}


def _account(session, eng_id: int, account_id: int) -> TestAccount:
    a = session.get(TestAccount, account_id)
    if a is None or a.engagement_id != eng_id:
        raise HTTPException(404, "no such test account on this engagement")
    return a


@router.get("/engagements/{eng_id}/test-accounts")
def list_accounts(eng_id: int, session: Session = Depends(get_session)):
    _eng(session, eng_id)
    names = _names(session)
    rows = session.scalars(select(TestAccount).where(TestAccount.engagement_id == eng_id).order_by(TestAccount.label))
    return [view(a, names) for a in rows]


@router.post("/engagements/{eng_id}/test-accounts", status_code=201)
def add_account(eng_id: int, body: AccountIn, request: Request, session: Session = Depends(get_session)):
    eng = _eng(session, eng_id)
    _writable(eng)
    label = body.label.strip()
    if not LABEL_RE.match(label):
        raise HTTPException(422, "a label is a short name such as A, B or admin-1 (letters, digits, - and _)")
    if session.scalar(select(TestAccount.id).where(TestAccount.engagement_id == eng_id, TestAccount.label == label)):
        raise HTTPException(409, f"there is already a test account {label}; replace it instead")
    try:
        pairs = material(body.kind, body.value, eng)
        hosts = check_hosts(body.hosts, eng)
    except ValueError as e:
        raise HTTPException(422, str(e))
    who = authz.current(request)
    sealed, fp = _seal(eng, pairs)
    a = TestAccount(engagement_id=eng.id, label=label, role=body.role.strip(), hosts=hosts, kind=body.kind,
                    header_names=[n for n, _ in pairs], material_enc=sealed, fingerprint=fp, created_by=who.user_id)
    session.add(a)
    session.flush()
    auditlog.append(session, actor=auditlog.actor(who), action="account.added", engagement_id=eng.id,
                    change={"after": _audit_ref(a)})
    session.commit()
    return view(a, _names(session))


@router.put("/engagements/{eng_id}/test-accounts/{account_id}")
def replace_account(eng_id: int, account_id: int, body: AccountReplace, request: Request,
                    session: Session = Depends(get_session)):
    eng = _eng(session, eng_id)
    _writable(eng)
    a = _account(session, eng_id, account_id)
    before = _audit_ref(a)
    try:
        if body.value is not None:
            pairs = material(body.kind or a.kind, body.value, eng)
            a.material_enc, a.fingerprint = _seal(eng, pairs)
            a.kind, a.header_names = body.kind or a.kind, [n for n, _ in pairs]
        elif body.kind is not None and body.kind != a.kind:
            raise ValueError("paste the new session material when changing its kind")
        if body.hosts is not None:
            a.hosts = check_hosts(body.hosts, eng)
    except ValueError as e:
        raise HTTPException(422, str(e))
    if body.role is not None:
        a.role = body.role.strip()
    after = _audit_ref(a)
    if after != before:
        a.replaced_at = now()
        auditlog.append(session, actor=auditlog.actor(authz.current(request)), action="account.replaced",
                        engagement_id=eng.id, change={"before": before, "after": after})
    session.commit()
    return view(a, _names(session))


@router.post("/engagements/{eng_id}/test-accounts/{account_id}/delete")
def delete_account(eng_id: int, account_id: int, request: Request, session: Session = Depends(get_session)):
    _eng(session, eng_id)
    a = _account(session, eng_id, account_id)
    auditlog.append(session, actor=auditlog.actor(authz.current(request)), action="account.deleted",
                    engagement_id=eng_id, change={"before": _audit_ref(a)})
    session.delete(a)
    session.commit()
    return {"deleted": account_id}
