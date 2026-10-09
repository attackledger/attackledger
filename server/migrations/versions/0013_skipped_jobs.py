"""skipped jobs: a pipeline step with nothing to work on ends "skipped", not "done"

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-09 20:00:00
"""
from alembic import op


revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # SQLite stores the enum as text; only Postgres has a type to extend.
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TYPE jobstatus ADD VALUE IF NOT EXISTS 'skipped'")


def downgrade() -> None:
    # Before this revision such a step ended "done" with no results.
    op.execute("UPDATE jobs SET status = 'done' WHERE status = 'skipped'")
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TYPE jobstatus RENAME TO jobstatus_old")
        op.execute("CREATE TYPE jobstatus AS ENUM ('queued', 'running', 'done', 'failed', 'cancelled', 'partial')")
        op.execute("ALTER TABLE jobs ALTER COLUMN status TYPE jobstatus USING status::text::jobstatus")
        op.execute("DROP TYPE jobstatus_old")
