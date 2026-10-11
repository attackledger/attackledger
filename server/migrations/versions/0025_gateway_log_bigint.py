"""gateway log counts in 64 bits: bytes_sent, bytes_received and duration_ms become BIGINT

A target decides how large its response is and how long it takes. On Postgres these columns
were 32-bit INTEGER, so the API kept a count past 2 GiB (2**31 - 1 bytes) as that maximum, and
before that fix such a row made the API refuse the gateway's whole log batch. BIGINT holds any
count a target can produce; the API now keeps the exact value (up to 2**63 - 1).

SQLite stores every integer in up to 64 bits whatever the declared type; its table is rebuilt
only so the declared type matches the models.

Downgrade: values past 2**31 - 1 become 2**31 - 1 first, as the API kept them before 0025, so
the columns fit INTEGER again.

Revision ID: 0025
Revises: 0024
Create Date: 2026-10-11 00:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0025'
down_revision = '0024'
branch_labels = None
depends_on = None

# As in 0022 and 0024, so SQLite and Postgres use the same constraint names when the table is rebuilt.
NAMES = {'uq': '%(table_name)s_%(column_0_N_name)s_key', 'fk': '%(table_name)s_%(column_0_name)s_fkey'}
COLUMNS = (('bytes_sent', False), ('bytes_received', False), ('duration_ms', True))
INT4_MAX = 2**31 - 1


def upgrade() -> None:
    with op.batch_alter_table('gateway_requests', naming_convention=NAMES) as b:
        for name, nullable in COLUMNS:
            b.alter_column(name, existing_type=sa.Integer(), type_=sa.BigInteger(), existing_nullable=nullable)


def downgrade() -> None:
    for name, _ in COLUMNS:
        op.execute(sa.text(f'UPDATE gateway_requests SET {name} = {INT4_MAX} WHERE {name} > {INT4_MAX}'))
    with op.batch_alter_table('gateway_requests', naming_convention=NAMES) as b:
        for name, nullable in COLUMNS:
            b.alter_column(name, existing_type=sa.BigInteger(), type_=sa.Integer(), existing_nullable=nullable)
