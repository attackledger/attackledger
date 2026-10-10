import os

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./attackledger.db")


def make_engine(url: str, **kw):
    """The engine for a database URL, with the settings the application relies on (the tests
    make theirs here too, tests/testdb.py).

    On Postgres every connection works in UTC. Times are stored without a zone and read back
    as UTC (models.iso_utc); a timezone-aware value written on a session in another zone (the
    server's TimeZone setting, or PGTZ) was stored in that zone's local time, so an approval
    or a session expired hours late (or early), and a receipt's stored issue time no longer
    matched the time it was signed for."""
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine = create_engine(url, connect_args=connect_args, **kw)
    if engine.dialect.name == "postgresql":
        event.listen(engine, "connect", _utc_session)
    return engine


def _utc_session(dbapi_connection, _record) -> None:
    autocommit = dbapi_connection.autocommit
    dbapi_connection.autocommit = True          # a SET inside a transaction ends with its rollback
    try:
        with dbapi_connection.cursor() as cur:
            cur.execute("SET TIME ZONE 'UTC'")
    finally:
        dbapi_connection.autocommit = autocommit


engine = make_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
