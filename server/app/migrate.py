"""Database migrations (Alembic), run by the API at startup.

A database that has tables but no alembic_version (created with create_all
before migrations existed) is stamped at the current head only if its schema
matches the current models exactly. Otherwise startup fails and nothing is
touched.
"""
import time
from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect

from .db import Base, engine

INI = Path(__file__).resolve().parents[1] / "alembic.ini"
class MigrationError(RuntimeError):
    pass


def _config() -> Config:
    cfg = Config(str(INI))
    cfg.set_main_option("script_location", str(INI.parent / "migrations"))
    return cfg


def head() -> str:
    return ScriptDirectory.from_config(_config()).get_current_head()


def current() -> str | None:
    with engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()


def upgrade_head() -> None:
    from . import models  # noqa: F401  (register tables)

    tables = set(inspect(engine).get_table_names())
    if "engagements" in tables and "alembic_version" not in tables:
        with engine.connect() as conn:
            diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
        if diff:
            raise MigrationError(
                f"existing database predates migrations and does not match the models "
                f"({len(diff)} difference(s)); refusing to stamp it. Back it up and migrate by hand."
            )
        command.stamp(_config(), "head")
    command.upgrade(_config(), "head")


def wait_for_head(timeout: float = 120) -> None:
    """For processes that must not migrate themselves (the worker)."""
    want, deadline = head(), time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if current() == want:
                return
        except Exception:
            pass
        time.sleep(2)
    raise MigrationError(f"database is not at migration {want}; is the API running?")
