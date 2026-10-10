"""token sessions: a browser signed in with the operator token gets a real session (D-056)

Until now the token-mode cookie was HMAC(token, constant): signing out could not revoke it, and a
copy worked until the token changed (security review AUTH-6). Such a browser now gets a random
session in user_sessions, like a person's, that names nobody (user_id NULL) and is bound to the
token it was opened with (token_binding). Old token-mode cookies are not accepted any more, so a
browser signed in with the token signs in once more after the upgrade.

Downgrade deletes the token sessions (they name nobody) and puts user_id back to NOT NULL.

Revision ID: 0023
Revises: 0022
Create Date: 2026-10-10 18:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0023'
down_revision = '0022'
branch_labels = None
depends_on = None

# As in 0022: Postgres's own names for the constraints it made unnamed, for SQLite's table copy.
NAMES = {'uq': '%(table_name)s_%(column_0_N_name)s_key', 'fk': '%(table_name)s_%(column_0_name)s_fkey'}


def upgrade() -> None:
    with op.batch_alter_table('user_sessions', naming_convention=NAMES) as b:
        b.alter_column('user_id', existing_type=sa.Integer(), nullable=True)
        b.add_column(sa.Column('token_binding', sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.execute('DELETE FROM user_sessions WHERE user_id IS NULL')
    with op.batch_alter_table('user_sessions', naming_convention=NAMES) as b:
        b.drop_column('token_binding')
        b.alter_column('user_id', existing_type=sa.Integer(), nullable=False)
