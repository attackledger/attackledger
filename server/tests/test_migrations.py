import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text

from app import db, migrate, models  # noqa: F401


@pytest.fixture()
def file_db(tmp_path, monkeypatch):
    eng = create_engine(f"sqlite:///{tmp_path / 'al.db'}")
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
