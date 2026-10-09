"""Who is calling: people with passwords and sessions, or the operator token.

Three modes, chosen by what exists:

  open    no people and no ATTACKLEDGER_API_TOKEN: local use only, everyone is an owner.
          /health says so; do not expose an open API beyond localhost.
  token   no people, ATTACKLEDGER_API_TOKEN set: the token (bearer header, or a session
          cookie holding an HMAC of it) is required and acts as an owner.
  people  at least one person exists: people sign in with email and password. The token,
          if set, still works as an owner for automation.

Passwords are hashed with scrypt (standard library). A session cookie holds a random
value; only its SHA-256 is stored, so a database leak does not leak sessions. Cookies
are HttpOnly and SameSite=Strict. Failed sign-ins are counted per email and address,
and further attempts are refused for a while after too many.
"""
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select

COOKIE = "al_session"
SESSION_HOURS = 12
OPEN_PATHS = {"/health", "/auth/login", "/auth/logout", "/docs", "/openapi.json"}
# scrypt: memory-hard, in the standard library. n=2**14, r=8, p=1 is about 16 MB per hash.
_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1, "maxmem": 64 * 1024 * 1024, "dklen": 32}
LOCKOUT_FAILURES = 5
LOCKOUT_SECONDS = 15 * 60


@dataclass(frozen=True)
class Principal:
    kind: str                        # "open", "token" or "person"
    user_id: int | None = None
    name: str = ""
    is_owner: bool = False
    roles: dict = field(default_factory=dict, compare=False, hash=False)  # engagement id -> roles

    def has(self, eng_id: int | None, role: str) -> bool:
        return self.is_owner or (eng_id is not None and role in self.roles.get(eng_id, ()))

    def can_read(self, eng_id: int | None) -> bool:
        return self.is_owner or (eng_id is not None and bool(self.roles.get(eng_id)))


def token() -> str | None:
    t = os.environ.get("ATTACKLEDGER_API_TOKEN", "").strip()
    return t or None


def token_session_value(tok: str) -> str:
    return hmac.new(tok.encode(), b"attackledger-session-v1", hashlib.sha256).hexdigest()


# ---- passwords ---------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
    return f"scrypt${_SCRYPT['n']}${_SCRYPT['r']}${_SCRYPT['p']}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, want = stored.split("$")
        if algo != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                            maxmem=_SCRYPT["maxmem"], dklen=len(want) // 2)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk.hex(), want)


# Spent on unknown emails too, so response time does not reveal which emails exist.
_DUMMY_HASH = hash_password(secrets.token_hex(16))


def check_password_rules(password: str) -> str | None:
    if len(password) < 12:
        return "use at least 12 characters"
    if len(password) > 256:
        return "use at most 256 characters"
    return None


# ---- failed sign-ins ---------------------------------------------------------

_failures: dict[tuple[str, str], list[float]] = {}


def locked(email: str, addr: str, now: float | None = None) -> bool:
    now = now or time.time()
    recent = [t for t in _failures.get((email, addr), []) if now - t < LOCKOUT_SECONDS]
    _failures[(email, addr)] = recent
    return len(recent) >= LOCKOUT_FAILURES


def record_failure(email: str, addr: str) -> None:
    _failures.setdefault((email, addr), []).append(time.time())


def clear_failures(email: str, addr: str) -> None:
    _failures.pop((email, addr), None)


# ---- sessions ----------------------------------------------------------------

def _sha(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()


def new_session(session, user_id: int) -> str:
    from .models import UserSession
    value = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    session.add(UserSession(token_sha256=_sha(value), user_id=user_id, created_at=now,
                            expires_at=now + timedelta(hours=SESSION_HOURS)))
    session.commit()
    return value


def end_session(session, value: str) -> None:
    from .models import UserSession
    row = session.scalar(select(UserSession).where(UserSession.token_sha256 == _sha(value)))
    if row:
        session.delete(row)
        session.commit()


def people_exist(session) -> bool:
    from .models import User
    return bool(session.scalar(select(func.count()).select_from(User)))


def mode(session) -> str:
    if people_exist(session):
        return "people"
    return "token" if token() else "open"


def _aware(t: datetime) -> datetime:
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def principal(session, request: Request) -> Principal | None:
    """Who is calling, or None if they must sign in."""
    from .models import Membership, User, UserSession
    m = mode(session)
    if m == "open":
        return Principal(kind="open", name="local operator", is_owner=True)
    tok = token()
    header = request.headers.get("authorization", "")
    cookie = request.cookies.get(COOKIE, "")
    if tok and ((header.lower().startswith("bearer ") and hmac.compare_digest(header[7:].strip(), tok))
                or (cookie and hmac.compare_digest(cookie, token_session_value(tok)))):
        return Principal(kind="token", name="operator token", is_owner=True)
    if m != "people" or not cookie:
        return None
    row = session.scalar(select(UserSession).where(UserSession.token_sha256 == _sha(cookie)))
    if row is None or _aware(row.expires_at) < datetime.now(timezone.utc):
        return None
    user = session.get(User, row.user_id)
    if user is None or user.disabled:
        return None
    roles = {mb.engagement_id: tuple(mb.roles or ())
             for mb in session.scalars(select(Membership).where(Membership.user_id == user.id))}
    return Principal(kind="person", user_id=user.id, name=user.name, is_owner=user.is_owner, roles=roles)
