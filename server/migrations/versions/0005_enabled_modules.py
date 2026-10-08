"""opt-in modules per engagement (replaces allow_port_scan)

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-08
"""
from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("engagements") as batch:
        batch.add_column(sa.Column("enabled_modules", sa.JSON(), nullable=True))
    # Carry the old switch over: port scanning stays enabled where it was.
    op.execute("UPDATE engagements SET enabled_modules = '[\"ports\"]' WHERE allow_port_scan")
    op.execute("UPDATE engagements SET enabled_modules = '[]' WHERE enabled_modules IS NULL")
    with op.batch_alter_table("engagements") as batch:
        batch.alter_column("enabled_modules", existing_type=sa.JSON(), nullable=False)
        batch.drop_column("allow_port_scan")


def downgrade() -> None:
    with op.batch_alter_table("engagements") as batch:
        batch.add_column(sa.Column("allow_port_scan", sa.Boolean(), server_default=sa.text("false"),
                                   nullable=False))
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("UPDATE engagements SET allow_port_scan = true "
                   "WHERE enabled_modules::jsonb ? 'ports'")
    else:
        op.execute("UPDATE engagements SET allow_port_scan = 1 WHERE enabled_modules LIKE '%\"ports\"%'")
    with op.batch_alter_table("engagements") as batch:
        batch.drop_column("enabled_modules")
