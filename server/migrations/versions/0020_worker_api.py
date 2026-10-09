"""worker api: job tokens, heartbeats, outside drivers and agent exchanges (D-042)

Revision ID: 0020
Revises: 0019
Create Date: 2026-10-09 09:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0020'
down_revision = '0019'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('jobs', sa.Column('worker_token_sha256', sa.String(length=64), nullable=True))
    op.add_column('jobs', sa.Column('heartbeat_at', sa.DateTime(), nullable=True))
    op.add_column('jobs', sa.Column('driver', sa.String(length=200), nullable=True))
    op.create_table(
        'agent_exchanges',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('job_id', sa.Integer(), sa.ForeignKey('jobs.id'), nullable=False),
        sa.Column('xid', sa.String(length=16), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('method', sa.String(length=16), nullable=False),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('status', sa.Integer(), nullable=False),
        sa.Column('redaction', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint('job_id', 'xid'),
    )
    op.create_index('ix_agent_exchanges_job_id', 'agent_exchanges', ['job_id'])


def downgrade() -> None:
    op.drop_index('ix_agent_exchanges_job_id', 'agent_exchanges')
    op.drop_table('agent_exchanges')
    op.drop_column('jobs', 'driver')
    op.drop_column('jobs', 'heartbeat_at')
    op.drop_column('jobs', 'worker_token_sha256')
