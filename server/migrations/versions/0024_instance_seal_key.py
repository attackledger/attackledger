"""instance seal key: a key log entry may belong to the instance rather than a person (D-055)

Reports are sealed when they are exported, with this instance's own Ed25519 key. Its public
key is registered in each organization's key log, like a reviewer's key, so it is chained
with them: that entry names no person, so key_log.user_id may now be empty. Nothing else
changes; the chains and their hashes are untouched.

Downgrade requires the column again only while the key log holds no instance entry. Those
entries cannot be removed without breaking the chain, so with them the column stays optional;
the code before 0024 reads them as entries of no person, and their hashes are unchanged.

Revision ID: 0024
Revises: 0023
Create Date: 2026-10-10 20:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0024'
down_revision = '0023'
branch_labels = None
depends_on = None

# As in 0022, so SQLite and Postgres use the same constraint names when the table is rebuilt.
NAMES = {'uq': '%(table_name)s_%(column_0_N_name)s_key', 'fk': '%(table_name)s_%(column_0_name)s_fkey'}


def upgrade() -> None:
    with op.batch_alter_table('key_log', naming_convention=NAMES) as b:
        b.alter_column('user_id', existing_type=sa.Integer(), nullable=True)


def downgrade() -> None:
    if op.get_bind().scalar(sa.text('SELECT count(*) FROM key_log WHERE user_id IS NULL')):
        return          # instance entries are part of the chain: keep them, and the column optional
    with op.batch_alter_table('key_log', naming_convention=NAMES) as b:
        b.alter_column('user_id', existing_type=sa.Integer(), nullable=False)
