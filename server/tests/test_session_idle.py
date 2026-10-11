"""Sessions end after a time without use (TM-3, auth.session_over), people's and the token's.

A session ends ATTACKLEDGER_SESSION_IDLE_MINUTES (default 30) after it was last used, and in any
case SESSION_HOURS (12) after sign-in. Its last use is written at most once a minute, and a request
the web app sends on its own (X-AttackLedger-Background) does not count as use. The clock is a
fake one (auth.now)."""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, select
from sqlalchemy.orm import sessionmaker

import testdb
from app import auth, db
from app.main import app
from app.models import UserSession

PW = "correct horse battery"
TOKEN = "operator-token-for-idle-tests-0001"


class Clock:
    def __init__(self):
        self.t = datetime(2026, 10, 11, 9, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.t

    def advance(self, **kw) -> None:
        self.t += timedelta(**kw)


@pytest.fixture()
def env(monkeypatch):
    monkeypatch.delenv("ATTACKLEDGER_API_TOKEN", raising=False)
    monkeypatch.delenv("ATTACKLEDGER_SESSION_IDLE_MINUTES", raising=False)
    auth._failures.clear()
    clock = Clock()
    monkeypatch.setattr(auth, "now", clock)
    eng = testdb.memory_engine()
    db.Base.metadata.create_all(eng)
    Session = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
    writes = []

    @event.listens_for(eng, "before_cursor_execute")
    def _count(_conn, _cur, statement, *_a):
        if statement.lstrip().upper().startswith("UPDATE USER_SESSIONS"):
            writes.append(statement)

    def _session():
        s = Session()
        try:
            yield s
        finally:
            s.close()
    app.dependency_overrides[db.get_session] = _session
    with TestClient(app) as c:
        r = c.post("/people", json={"email": "owner@lab.test", "name": "Olive", "password": PW, "is_owner": True})
        assert r.status_code == 201, r.text
        yield c, clock, Session, writes
    app.dependency_overrides.clear()


def sign_in(c) -> None:
    c.cookies.clear()
    assert c.post("/auth/login", json={"email": "owner@lab.test", "password": PW}).status_code == 200


def me(c, background=False) -> int:
    return c.get("/auth/me", headers={"x-attackledger-background": "1"} if background else {}).status_code


def test_a_session_ends_after_thirty_minutes_without_use(env):
    c, clock, Session, _ = env
    sign_in(c)
    clock.advance(minutes=29)
    assert me(c) == 200
    clock.advance(minutes=29, seconds=59)            # 29:59 since it was last used
    assert me(c) == 200
    clock.advance(minutes=30)
    assert me(c) == 401 and c.get("/engagements").status_code == 401
    with Session() as s:
        assert s.scalars(select(UserSession)).all() == []      # ended for good, not only refused


def test_use_keeps_it_open_until_twelve_hours_after_sign_in(env):
    c, clock, _, _ = env
    sign_in(c)
    for _ in range(12 * 3 - 1):                      # a request every 20 minutes, for 11h40
        clock.advance(minutes=20)
        assert me(c) == 200
    clock.advance(minutes=20)                        # 12 hours after sign-in, however it was used
    assert me(c) == 401


def test_the_last_use_is_written_at_most_once_a_minute(env):
    c, clock, Session, writes = env
    sign_in(c)
    writes.clear()
    for _ in range(50):                              # 50 requests within 50 seconds: no write
        clock.advance(seconds=1)
        assert me(c) == 200
    assert writes == []
    clock.advance(seconds=10)                        # a minute after sign-in: one write
    assert me(c) == 200 and me(c) == 200
    assert len(writes) == 1
    with Session() as s:
        assert auth._aware(s.scalars(select(UserSession)).one().last_seen_at) == clock()


def test_requests_the_app_sends_on_its_own_do_not_keep_it_open(env):
    c, clock, _, writes = env
    sign_in(c)
    writes.clear()
    for _ in range(29):                              # a poll every minute, nobody at the page
        clock.advance(minutes=1)
        assert me(c, background=True) == 200
    assert writes == []
    clock.advance(minutes=1)
    assert me(c, background=True) == 401


def test_the_idle_limit_is_configurable_and_a_bad_value_keeps_the_default(env, monkeypatch):
    c, clock, _, _ = env
    for value, minutes in (("5", 5), ("720", 720), ("100000", 720), ("0", 30), ("-3", 30), ("off", 30), ("", 30)):
        monkeypatch.setenv("ATTACKLEDGER_SESSION_IDLE_MINUTES", value)
        assert auth.idle_minutes() == minutes, value
    monkeypatch.setenv("ATTACKLEDGER_SESSION_IDLE_MINUTES", "5")
    sign_in(c)
    clock.advance(minutes=4)
    assert me(c) == 200
    clock.advance(minutes=5)
    assert me(c) == 401


def test_a_short_limit_is_extended_by_use_too(env, monkeypatch):
    """With a limit of a minute, the last use is written every 6 seconds, not once a minute
    (which would end a session in use: found on a running stack)."""
    c, clock, _, writes = env
    monkeypatch.setenv("ATTACKLEDGER_SESSION_IDLE_MINUTES", "1")
    assert auth.seen_every() == timedelta(seconds=6)
    sign_in(c)
    writes.clear()
    for _ in range(10):                              # a request every 22 seconds, for 220 seconds
        clock.advance(seconds=22)
        assert me(c) == 200
    assert len(writes) == 10
    clock.advance(seconds=60)
    assert me(c) == 401


def test_token_sessions_end_after_the_same_time_without_use(env, monkeypatch):
    c, clock, Session, _ = env
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", TOKEN)
    c.cookies.clear()
    assert c.post("/auth/login", json={"token": TOKEN}).status_code == 200
    clock.advance(minutes=25)
    assert c.get("/engagements").status_code == 200
    clock.advance(minutes=31)
    assert c.get("/engagements").status_code == 401
    # The token itself, sent as a bearer header by a script, has no session to idle.
    c.cookies.clear()
    assert c.get("/engagements", headers={"authorization": f"Bearer {TOKEN}"}).status_code == 200
    # An idle token session is cleaned up at the next token sign-in too.
    assert c.post("/auth/login", json={"token": TOKEN}).status_code == 200
    clock.advance(minutes=40)
    with Session() as s:
        assert auth.end_stale_token_sessions(s) == 1


def test_a_session_from_before_the_upgrade_counts_from_its_sign_in(env):
    c, clock, Session, _ = env
    sign_in(c)
    with Session() as s:
        row = s.scalars(select(UserSession)).one()
        row.last_seen_at = None                      # as migration 0027 leaves it
        s.commit()
    clock.advance(minutes=31)
    assert me(c) == 401
