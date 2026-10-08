"""job progress: partial status, targets_done, remaining_targets

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-08
"""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        # Postgres enums need an explicit new value; ADD VALUE is safe inside a transaction on 12+.
        op.execute("ALTER TYPE jobstatus ADD VALUE IF NOT EXISTS 'partial'")
    with op.batch_alter_table("jobs") as batch:
        batch.add_column(sa.Column("targets_done", sa.Integer(), server_default="0", nullable=False))
        batch.add_column(sa.Column("remaining_targets", sa.JSON(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    with op.batch_alter_table("jobs") as batch:
        batch.drop_column("remaining_targets")
        batch.drop_column("targets_done")
    if bind.dialect.name == "postgresql":
        # Postgres cannot drop an enum value: rebuild the type without 'partial'.
        op.execute("UPDATE jobs SET status = 'failed' WHERE status = 'partial'")
        op.execute("ALTER TYPE jobstatus RENAME TO jobstatus_old")
        op.execute("CREATE TYPE jobstatus AS ENUM ('queued', 'running', 'done', 'failed', 'cancelled')")
        op.execute("ALTER TABLE jobs ALTER COLUMN status TYPE jobstatus USING status::text::jobstatus")
        op.execute("DROP TYPE jobstatus_old")
