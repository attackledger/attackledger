"""signed receipts: reviewer keys, signature fields on receipts, per-engagement requirement

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-09 14:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0011'
down_revision = '0010'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'signing_keys',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('algorithm', sa.String(length=20), nullable=False),
        sa.Column('public_key', sa.Text(), nullable=False),
        sa.Column('fingerprint', sa.String(length=64), nullable=False, unique=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
    )
    op.add_column('engagements', sa.Column('require_signatures', sa.Boolean(),
                                           server_default=sa.text('false'), nullable=False))
    op.add_column('receipts', sa.Column('payload', sa.Text(), nullable=True))
    op.add_column('receipts', sa.Column('signature', sa.String(length=200), nullable=True))
    op.add_column('receipts', sa.Column('algorithm', sa.String(length=20), nullable=True))
    op.add_column('receipts', sa.Column('public_key', sa.Text(), nullable=True))
    op.add_column('receipts', sa.Column('key_fingerprint', sa.String(length=64), nullable=True))


def downgrade() -> None:
    for c in ('key_fingerprint', 'public_key', 'algorithm', 'signature', 'payload'):
        op.drop_column('receipts', c)
    op.drop_column('engagements', 'require_signatures')
    op.drop_table('signing_keys')
