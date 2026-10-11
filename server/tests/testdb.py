"""The database a test runs on: SQLite by default, Postgres when ATTACKLEDGER_TEST_PG is set.

ATTACKLEDGER_TEST_PG is the URL of a Postgres database whose role may create databases (for
example postgresql+psycopg://postgres:...@host/postgres). Each engine a test asks for is then
a new, empty database of its own, dropped once it has ended (conftest.py), so tests share no
rows, sequences or locks, as they share nothing on SQLite. tools/test_postgres.sh runs the
whole suite this way against a throwaway Postgres.

  memory_engine()      what create_engine("sqlite://", StaticPool) was: one empty database
  file_engine(path)    what create_engine(f"sqlite:///{path}") was: a database separate
                       connections share (the race tests, the migration tests)

The application's own engine (db.engine and db.SessionLocal, used by the API's start-up and
the few paths that open their own session) points, during each test, at a fresh database
already migrated to head, as the API leaves it on SQLite.
"""
import ipaddress
import os
from contextlib import contextmanager
import socket
import uuid

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool, StaticPool

PG = os.environ.get("ATTACKLEDGER_TEST_PG", "")


def _pinned(url: str) -> str:
    """The URL with its host's address resolved now (libpq's hostaddr): some tests refuse every
    name lookup (test_import's adapters only parse), and that must not reach the test database."""
    if not url:
        return url
    u = make_url(url)
    host = u.host or ""
    if not host or host.startswith("/") or "hostaddr" in u.query:
        return url
    try:
        ipaddress.ip_address(host)
        return url
    except ValueError:
        pass
    addr = socket.getaddrinfo(host, u.port or 5432, type=socket.SOCK_STREAM)[0][4][0]
    return u.update_query_dict({"hostaddr": addr}).render_as_string(hide_password=False)


PG = _pinned(PG)

_engines: list = []          # made during the current test
_databases: list[str] = []
_admin = None
_head_template: str | None = None


def on_postgres() -> bool:
    return bool(PG)


def _admin_engine():
    global _admin
    if _admin is None:
        _admin = create_engine(PG, isolation_level="AUTOCOMMIT", poolclass=NullPool)
    return _admin


def _create_database(template: str | None = None) -> str:
    name = f"al_test_{uuid.uuid4().hex[:16]}"
    with _admin_engine().connect() as c:
        c.execute(text(f'CREATE DATABASE "{name}"' + (f' TEMPLATE "{template}"' if template else "")))
    return name


def _url(name: str) -> str:
    return make_url(PG).set(database=name).render_as_string(hide_password=False)


def _postgres_engine(template: str | None = None):
    from app import db
    name = _create_database(template)
    _databases.append(name)
    eng = db.make_engine(_url(name))
    _engines.append(eng)
    return eng


def memory_engine():
    if not PG:
        return create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    return _postgres_engine()


def file_engine(path, **sqlite_connect_args):
    if not PG:
        return create_engine(f"sqlite:///{path}", connect_args=sqlite_connect_args)
    return _postgres_engine()


def head_engine():
    """A fresh database at the head migration (copied from one migrated once per run)."""
    global _head_template
    if _head_template is None:
        from app import db, migrate
        name = _create_database()
        eng = db.make_engine(_url(name))
        old_db, old_migrate = db.engine, migrate.engine
        db.engine = migrate.engine = eng
        try:
            migrate.upgrade_head()
        finally:
            db.engine, migrate.engine = old_db, old_migrate
            eng.dispose()
        _head_template = name
    return _postgres_engine(template=_head_template)


def release() -> None:
    """After a test: close what it opened. Its databases are dropped before the next test
    starts (drop_released), when no fixture of this one still blocks the network (test_import
    refuses every connection until its monkeypatch is undone, after this runs)."""
    while _engines:
        _engines.pop().dispose()


def drop_released() -> None:
    """Drop the databases of the tests before (FORCE ends connections left open, for example
    by a thread a failed test left behind)."""
    release()
    while _databases:
        with _admin_engine().connect() as c:
            c.execute(text(f'DROP DATABASE IF EXISTS "{_databases[-1]}" WITH (FORCE)'))
        _databases.pop()


def drop_template() -> None:
    global _head_template
    if _head_template is not None:
        with _admin_engine().connect() as c:
            c.execute(text(f'DROP DATABASE IF EXISTS "{_head_template}" WITH (FORCE)'))
        _head_template = None


@contextmanager
def append_only_off(session):
    """What a database superuser, or whoever can write the SQLite file, can do (TM-5): drop the
    append-only triggers (app/appendonly.py), for the tests that show the hash chains and the
    verifier still catch what the triggers would have refused, and for tests that make rows as an
    older release left them. The triggers are made again afterwards."""
    from app import appendonly, db
    dialect = session.get_bind().dialect.name
    for stmt in appendonly.drop_statements(dialect):
        session.connection().exec_driver_sql(stmt)
    session.commit()
    try:
        yield
    finally:
        session.rollback()
        for stmt in appendonly.create_statements(dialect, appendonly.model_columns(db.Base.metadata)):
            session.connection().exec_driver_sql(stmt)
        session.commit()
