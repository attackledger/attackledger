"""Who is calling: people with passwords and sessions, or the operator token.

Four modes, chosen by what exists:

  open    no people and no ATTACKLEDGER_API_TOKEN: local use only, everyone is an owner.
          /health says so; do not expose an open API beyond localhost.
  setup   the same, but ATTACKLEDGER_REQUIRE_SIGN_IN=1 (production): nobody gets in until
          the first owner is created on the server (python -m app.people create --owner).
          Whoever reaches the server first over the network cannot make themselves owner.
  token   no people, ATTACKLEDGER_API_TOKEN set: the token (bearer header, or a session
          cookie from signing in with it) is required and acts as an owner.
  people  at least one person exists: people sign in with email and password. The token,
          if set, still works as an owner for automation.

Passwords are hashed with scrypt (standard library). A session cookie holds a random
value; only its SHA-256 is stored, so a database leak does not leak sessions. Signing in with
the token gives the browser such a session too (D-056): it names nobody, is bound to the token,
ends on sign-out or after SESSION_HOURS, and ends for good when the API starts with another token. Cookies
are HttpOnly and SameSite=Strict, and a change that a page of another origin sends (a sibling
subdomain is the same site) is refused (from_another_site). Failed sign-ins are counted per email and address,
and further attempts are refused for a while after too many.

Each person belongs to one organization (D-042, docs/ORGANIZATIONS.md), and so does the
caller: a person's own, and for the operator token and open mode, the default one. Owners
manage their own organization only; nothing in the product spans organizations.

An owner sets a person's first password when adding them. After that only the person
changes it (POST /auth/password, with their current one), or an operator resets it on the
server (python -m app.people set-password). Nobody sets another person's password through
the API, so an owner cannot sign in as someone else and register a key in their name.
"""
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from functools import lru_cache
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

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
    organization_id: int = 0         # whose rows this caller sees (orgscope.py)
    user_id: int | None = None
    name: str = ""
    is_owner: bool = False
    email: str = ""
    roles: dict = field(default_factory=dict, compare=False, hash=False)  # engagement id -> roles

    def has(self, eng_id: int | None, role: str) -> bool:
        return self.is_owner or (eng_id is not None and role in self.roles.get(eng_id, ()))

    def can_read(self, eng_id: int | None) -> bool:
        return self.is_owner or (eng_id is not None and bool(self.roles.get(eng_id)))


def token() -> str | None:
    t = os.environ.get("ATTACKLEDGER_API_TOKEN", "").strip()
    return t or None


def require_sign_in() -> bool:
    """Production setting: the API is never open. Unknown values count as on, so a typo
    such as "ture" fails closed rather than leaving the ledger open."""
    v = os.environ.get("ATTACKLEDGER_REQUIRE_SIGN_IN", "").strip().lower()
    return v not in ("", "0", "false", "no", "off")


SETUP_HINT = ("nobody can sign in yet: create the first owner on the server with "
              "python -m app.people create --owner")


SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def from_another_site(request: Request) -> bool:
    """Whether a browser sent this request from a page of another origin: a form or a script on
    another site, or on a sibling subdomain, which is the same site and so gets the SameSite=Strict
    cookie. Browsers say where a request comes from in Sec-Fetch-Site, older ones in Origin; other
    clients (the worker, the gateway, scripts) send neither, and are not affected."""
    site = request.headers.get("sec-fetch-site", "").strip().lower()
    if site:
        return site not in ("same-origin", "none")
    origin = request.headers.get("origin")
    if origin is None:
        return False
    try:
        theirs = urlsplit(origin.strip()).hostname
        ours = urlsplit("//" + request.headers.get("host", "")).hostname
    except ValueError:
        return True
    return not theirs or theirs != ours      # "null" (a sandboxed page) has no host: refused


def same_secret(presented: str, expected: str) -> bool:
    """A presented token or cookie against the expected one, in constant time, as UTF-8 bytes.
    hmac.compare_digest raises TypeError on a str with a non-ASCII character (Starlette decodes
    headers as Latin-1; a JSON body may hold anything), which was a 500 instead of a 401
    (security review AUTH-4)."""
    return hmac.compare_digest(presented.encode("utf-8", "surrogatepass"), expected.encode("utf-8", "surrogatepass"))


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


@lru_cache(maxsize=4)
def token_binding(tok: str) -> str:
    """What a token session is bound to: a slow hash of the token, so a database leak makes
    guessing a weak token no easier than guessing a password. Computed once per token value."""
    return hashlib.scrypt(tok.encode("utf-8", "surrogatepass"), salt=b"attackledger-token-session-v2",
                          **_SCRYPT).hex()


def new_token_session(session, tok: str) -> str:
    """A browser signed in with the operator token (D-056): a session like a person's, bound to
    the token instead of a person. Sessions of an earlier token are deleted first."""
    from .models import UserSession
    end_stale_token_sessions(session, commit=False)
    value = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    session.add(UserSession(token_sha256=_sha(value), user_id=None, token_binding=token_binding(tok),
                            created_at=now, expires_at=now + timedelta(hours=SESSION_HOURS)))
    session.commit()
    return value


def end_stale_token_sessions(session, commit: bool = True) -> int:
    """Delete the token sessions that no longer open anything: expired, or opened with another
    token than the current one (all of them when no token is set). Run when the API starts, so a
    token change ends them for good, and at each token sign-in. Returns how many went."""
    from .models import UserSession
    tok, now, n = token(), datetime.now(timezone.utc), 0
    for row in session.scalars(select(UserSession).where(UserSession.user_id.is_(None))):
        if tok is None or not same_secret(row.token_binding or "", token_binding(tok)) or _aware(row.expires_at) < now:
            session.delete(row)
            n += 1
    if commit:
        session.commit()
    return n


def end_sessions(session, user_id: int, keep: str | None = None) -> None:
    """Sign a person out everywhere (but the session `keep`, if given). The caller commits."""
    from .models import UserSession
    q = select(UserSession).where(UserSession.user_id == user_id)
    if keep:
        q = q.where(UserSession.token_sha256 != _sha(keep))
    for row in session.scalars(q):
        session.delete(row)


def people_exist(session) -> bool:
    """Whether anyone at all has an account: it decides the mode for the whole deployment."""
    from . import orgscope
    from .models import User
    with orgscope.unscoped(session):
        return bool(session.scalar(select(func.count()).select_from(User)))


def mode(session) -> str:
    if people_exist(session):
        return "people"
    if token():
        return "token"
    return "setup" if require_sign_in() else "open"


def _aware(t: datetime) -> datetime:
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def principal(session, request: Request) -> Principal | None:
    """Who is calling, or None if they must sign in. Looked up before the organization is
    known (the session or token decides it), so without the organization filter."""
    from . import orgscope
    with orgscope.unscoped(session):
        return _principal(session, request)


def _principal(session, request: Request) -> Principal | None:
    from . import orgscope
    from .models import Membership, User, UserSession
    m = mode(session)
    if m == "open":
        return Principal(kind="open", organization_id=orgscope.default_id(session), name="local operator",
                         is_owner=True)
    tok = token()
    header = request.headers.get("authorization", "")
    cookie = request.cookies.get(COOKIE, "")

    def operator() -> Principal:
        # The deployment's token: an owner of the default organization, as before there were others.
        return Principal(kind="token", organization_id=orgscope.default_id(session), name="operator token",
                         is_owner=True)
    if tok and header.lower().startswith("bearer ") and same_secret(header[7:].strip(), tok):
        return operator()
    if not cookie:
        return None
    row = session.scalar(select(UserSession).where(UserSession.token_sha256 == _sha(cookie)))
    if row is None or _aware(row.expires_at) < datetime.now(timezone.utc):
        return None
    if row.user_id is None:             # a browser signed in with the token, while it is the same token
        ok = tok is not None and same_secret(row.token_binding or "", token_binding(tok))
        return operator() if ok else None
    if m != "people":
        return None
    user = session.get(User, row.user_id)
    if user is None or user.disabled:
        return None
    roles = {mb.engagement_id: tuple(mb.roles or ())
             for mb in session.scalars(select(Membership).where(Membership.user_id == user.id))}
    return Principal(kind="person", organization_id=user.organization_id, user_id=user.id, name=user.name,
                     is_owner=user.is_owner, email=user.email, roles=roles)
