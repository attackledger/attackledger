"""sessions end after a time without use: user_sessions.last_seen_at (TM-3)

A session (a person's, or a browser signed in with the operator token) now ends after
ATTACKLEDGER_SESSION_IDLE_MINUTES (default 30) without use, as well as 12 hours after sign-in.
The API writes last_seen_at at most once a minute per session. Sessions made before this
migration have none, and count from their sign-in: those older than the idle limit end at the
first request after the upgrade, and their people sign in again.

Downgrade: the column is dropped; sessions then last their 12 hours again.

Revision ID: 0027
Revises: 0026
Create Date: 2026-10-11 00:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0027'
down_revision = '0026'
branch_labels = None
depends_on = None

# As in 0022 and 0023: Postgres's own names for the constraints it made unnamed, for SQLite's table copy.
NAMES = {'uq': '%(table_name)s_%(column_0_N_name)s_key', 'fk': '%(table_name)s_%(column_0_name)s_fkey'}


def upgrade() -> None:
    op.add_column('user_sessions', sa.Column('last_seen_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('user_sessions', naming_convention=NAMES) as b:
        b.drop_column('last_seen_at')
