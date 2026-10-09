"""gateway: job credentials and the request log (D-039)

Revision ID: 0019
Revises: 0018
Create Date: 2026-10-09 23:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0019'
down_revision = '0018'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('jobs', sa.Column('gateway_secret_sha256', sa.String(length=64), nullable=True))
    op.create_table(
        'gateway_requests',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('at', sa.DateTime(), nullable=False),
        sa.Column('engagement_id', sa.Integer(), sa.ForeignKey('engagements.id'), nullable=True),
        sa.Column('job_id', sa.Integer(), sa.ForeignKey('jobs.id'), nullable=True),
        sa.Column('tool', sa.String(length=32), nullable=False),
        sa.Column('kind', sa.String(length=16), nullable=False),
        sa.Column('method', sa.String(length=16), nullable=False),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('status', sa.Integer(), nullable=True),
        sa.Column('verdict', sa.String(length=8), nullable=False),
        sa.Column('reason', sa.String(length=300), nullable=False),
        sa.Column('bytes_sent', sa.Integer(), nullable=False),
        sa.Column('bytes_received', sa.Integer(), nullable=False),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
    )
    op.create_index('ix_gateway_requests_engagement_id', 'gateway_requests', ['engagement_id'])
    op.create_index('ix_gateway_requests_job_id', 'gateway_requests', ['job_id'])


def downgrade() -> None:
    op.drop_index('ix_gateway_requests_job_id', 'gateway_requests')
    op.drop_index('ix_gateway_requests_engagement_id', 'gateway_requests')
    op.drop_table('gateway_requests')
    op.drop_column('jobs', 'gateway_secret_sha256')
