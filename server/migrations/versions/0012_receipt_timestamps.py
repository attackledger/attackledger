"""receipt timestamps: RFC 3161 token, time, authority and last error on receipts

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-09 16:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0012'
down_revision = '0011'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('receipts', sa.Column('timestamp_token', sa.Text(), nullable=True))
    op.add_column('receipts', sa.Column('timestamp_time', sa.DateTime(), nullable=True))
    op.add_column('receipts', sa.Column('timestamp_tsa', sa.String(length=500), nullable=True))
    op.add_column('receipts', sa.Column('timestamp_error', sa.String(length=500), nullable=True))


def downgrade() -> None:
    for c in ('timestamp_error', 'timestamp_tsa', 'timestamp_time', 'timestamp_token'):
        op.drop_column('receipts', c)
