"""API authentication: one operator token, as a bearer header or a session cookie.

Set ATTACKLEDGER_API_TOKEN to require it on every route except /health and the
login route. Unset, the API stays open for local use, and /health says so: do not
expose an unauthenticated API beyond localhost.

The session cookie holds an HMAC derived from the token (never the token itself),
is HttpOnly and SameSite=Strict, so cross-site requests do not carry it.
Comparisons are constant-time.
"""
import hashlib
import hmac
import os

from fastapi import Request
from fastapi.responses import JSONResponse

COOKIE = "al_session"
OPEN_PATHS = {"/health", "/auth/login", "/auth/logout", "/docs", "/openapi.json"}


def token() -> str | None:
    t = os.environ.get("ATTACKLEDGER_API_TOKEN", "").strip()
    return t or None


def session_value(tok: str) -> str:
    return hmac.new(tok.encode(), b"attackledger-session-v1", hashlib.sha256).hexdigest()


def authorized(request: Request) -> bool:
    tok = token()
    if tok is None:
        return True
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer ") and hmac.compare_digest(header[7:].strip(), tok):
        return True
    cookie = request.cookies.get(COOKIE, "")
    return bool(cookie) and hmac.compare_digest(cookie, session_value(tok))


async def middleware(request: Request, call_next):
    if request.url.path in OPEN_PATHS or authorized(request):
        return await call_next(request)
    return JSONResponse({"detail": "authentication required"}, status_code=401)
