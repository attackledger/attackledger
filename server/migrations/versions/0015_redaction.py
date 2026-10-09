"""redaction: per-engagement setting, and what was redacted from each evidence entry

Revision ID: 0015
Revises: 0014 (becomes 0015 when the audit log branch, which adds 0015, is merged first)
Create Date: 2026-10-09 21:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0015'
down_revision = '0014'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # On for every engagement, existing ones included: evidence stored from now on is redacted.
    op.add_column('engagements', sa.Column('redact_evidence', sa.Boolean(), server_default=sa.text('true'),
                                           nullable=False))
    op.add_column('evidence', sa.Column('redaction', sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column('evidence', 'redaction')
    op.drop_column('engagements', 'redact_evidence')
