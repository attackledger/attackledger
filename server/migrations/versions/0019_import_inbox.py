"""evidence import: import batches and the inbox (D-029)

Revision ID: 0019
Revises: 0017 (encryption); becomes 0018 when the gateway branch, which adds 0018, is merged
first
Create Date: 2026-10-09 23:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0019'
down_revision = '0017'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'import_batches',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('engagement_id', sa.Integer(), sa.ForeignKey('engagements.id'), nullable=False),
        sa.Column('tool', sa.String(length=16), nullable=False),
        sa.Column('creator', sa.String(length=200), nullable=True),
        sa.Column('filename', sa.String(length=200), nullable=True),
        sa.Column('file_sha256', sa.String(length=64), nullable=False),
        sa.Column('file_bytes', sa.Integer(), nullable=False),
        sa.Column('rows', sa.Integer(), nullable=False),
        sa.Column('accepted', sa.Integer(), nullable=False),
        sa.Column('out_of_scope', sa.Integer(), nullable=False),
        sa.Column('duplicates', sa.Integer(), nullable=False),
        sa.Column('unreadable', sa.Integer(), nullable=False),
        sa.Column('refused', sa.JSON(), nullable=False),
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('created_by_name', sa.String(length=300), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_import_batches_engagement_id', 'import_batches', ['engagement_id'])
    op.create_table(
        'inbox_entries',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('engagement_id', sa.Integer(), sa.ForeignKey('engagements.id'), nullable=False),
        sa.Column('batch_id', sa.Integer(), sa.ForeignKey('import_batches.id'), nullable=False),
        sa.Column('row', sa.Integer(), nullable=False),
        sa.Column('tool', sa.String(length=16), nullable=False),
        sa.Column('tool_id', sa.String(length=100), nullable=True),
        sa.Column('tool_time', sa.String(length=64), nullable=True),
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.Column('method', sa.String(length=20), nullable=False),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('status', sa.Integer(), nullable=True),
        sa.Column('label', sa.String(length=300), nullable=True),
        sa.Column('request_sha256', sa.String(length=64), nullable=True),
        sa.Column('response_sha256', sa.String(length=64), nullable=True),
        sa.Column('record_sha256', sa.String(length=64), nullable=False),
        sa.Column('content_sha256', sa.String(length=64), nullable=False),
        sa.Column('request_bytes', sa.Integer(), nullable=False),
        sa.Column('response_bytes', sa.Integer(), nullable=False),
        sa.Column('facts', sa.JSON(), nullable=False),
        sa.Column('redaction', sa.JSON(), nullable=True),
        sa.Column('state', sa.String(length=16), server_default='new', nullable=False),
        sa.Column('mappings', sa.JSON(), nullable=False),
        sa.Column('dismissed_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('dismissed_by_name', sa.String(length=300), nullable=True),
        sa.Column('dismissed_at', sa.DateTime(), nullable=True),
        sa.Column('dismiss_reason', sa.String(length=500), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint('engagement_id', 'content_sha256'),
    )
    op.create_index('ix_inbox_entries_engagement_id', 'inbox_entries', ['engagement_id'])
    op.create_index('ix_inbox_entries_batch_id', 'inbox_entries', ['batch_id'])


def downgrade() -> None:
    op.drop_index('ix_inbox_entries_batch_id', table_name='inbox_entries')
    op.drop_index('ix_inbox_entries_engagement_id', table_name='inbox_entries')
    op.drop_table('inbox_entries')
    op.drop_index('ix_import_batches_engagement_id', table_name='import_batches')
    op.drop_table('import_batches')
