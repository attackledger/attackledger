import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
import testdb
from sqlalchemy import BigInteger, inspect, text

from app import db, migrate, models  # noqa: F401


@pytest.fixture()
def file_db(tmp_path, monkeypatch):
    eng = testdb.file_engine(tmp_path / 'al.db')
    monkeypatch.setattr(db, "engine", eng)
    monkeypatch.setattr(migrate, "engine", eng)
    return eng


def drift(eng):
    with eng.connect() as c:
        return compare_metadata(MigrationContext.configure(c), db.Base.metadata)


def test_fresh_database_migrates_to_models(file_db):
    migrate.upgrade_head()
    assert migrate.current() == migrate.head()
    assert drift(file_db) == []


def test_downgrade_and_upgrade_again(file_db):
    migrate.upgrade_head()
    command.downgrade(migrate._config(), "base")
    assert "engagements" not in inspect(file_db).get_table_names()
    migrate.upgrade_head()
    assert migrate.current() == migrate.head()


def test_pre_migration_database_is_stamped_when_it_matches(file_db):
    db.Base.metadata.create_all(file_db)          # how databases were created before v0.2
    migrate.upgrade_head()
    assert migrate.current() == migrate.head()


def test_pre_migration_database_that_drifted_is_refused(file_db):
    db.Base.metadata.create_all(file_db)
    with file_db.begin() as c:
        c.execute(text("ALTER TABLE engagements ADD COLUMN surprise TEXT"))
    with pytest.raises(migrate.MigrationError, match="does not match"):
        migrate.upgrade_head()
    assert "alembic_version" not in inspect(file_db).get_table_names()  # nothing stamped


def test_gateway_log_counts_hold_64_bits_and_a_downgrade_keeps_the_old_maximum(file_db):
    """Migration 0025: bytes_sent, bytes_received and duration_ms are BIGINT. On Postgres a count
    past 2**31 - 1 did not fit before; a downgrade stores such counts as that maximum, as the API
    kept them before 0025."""
    migrate.upgrade_head()

    def columns():
        return {c["name"]: c["type"] for c in inspect(file_db).get_columns("gateway_requests")}

    def counts():
        with file_db.connect() as c:
            return c.execute(text("SELECT bytes_sent, bytes_received, duration_ms FROM gateway_requests")).one()
    for name in ("bytes_sent", "bytes_received", "duration_ms"):
        assert isinstance(columns()[name], BigInteger), name
    with file_db.begin() as c:
        org = c.execute(text("SELECT id FROM organizations ORDER BY id LIMIT 1")).scalar_one()
        c.execute(text("INSERT INTO gateway_requests (organization_id, at, tool, kind, method, url, host, verdict, "
                       "reason, bytes_sent, bytes_received, duration_ms) VALUES (:org, '2026-10-10 12:00:00', 'httpx', "
                       "'target', 'GET', 'https://app.example.com/', 'app.example.com', 'allowed', '', :a, :b, :d)"),
                  {"org": org, "a": 2**62, "b": 3_000_000_000, "d": 2**40})
    assert tuple(counts()) == (2**62, 3_000_000_000, 2**40)
    command.downgrade(migrate._config(), "0024")
    assert not isinstance(columns()["bytes_received"], BigInteger)
    assert tuple(counts()) == (2**31 - 1, 2**31 - 1, 2**31 - 1)
    migrate.upgrade_head()
    assert migrate.current() == migrate.head() and drift(file_db) == []
    assert isinstance(columns()["bytes_received"], BigInteger)
