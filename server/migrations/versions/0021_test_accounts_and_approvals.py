"""test accounts (D-040) and writes with a person's approval (D-041)

Revision ID: 0021
Revises: 0020
Create Date: 2026-10-09 12:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0021'
down_revision = '0020'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('engagements', sa.Column('allow_writes', sa.Boolean(), server_default=sa.text('false'),
                                           nullable=False))
    op.create_table(
        'test_accounts',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('engagement_id', sa.Integer(), sa.ForeignKey('engagements.id'), nullable=False),
        sa.Column('label', sa.String(length=16), nullable=False),
        sa.Column('role', sa.String(length=100), nullable=False),
        sa.Column('hosts', sa.JSON(), nullable=False),
        sa.Column('kind', sa.String(length=16), nullable=False),
        sa.Column('header_names', sa.JSON(), nullable=False),
        sa.Column('material_enc', sa.Text(), nullable=False),
        sa.Column('fingerprint', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('replaced_at', sa.DateTime(), nullable=True),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.UniqueConstraint('engagement_id', 'label'),
    )
    op.create_index('ix_test_accounts_engagement_id', 'test_accounts', ['engagement_id'])
    op.create_table(
        'write_proposals',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('engagement_id', sa.Integer(), sa.ForeignKey('engagements.id'), nullable=False),
        sa.Column('lane_id', sa.Integer(), sa.ForeignKey('lanes.id'), nullable=False),
        sa.Column('job_id', sa.Integer(), sa.ForeignKey('jobs.id'), nullable=True),
        sa.Column('item_idx', sa.Integer(), nullable=True),
        sa.Column('method', sa.String(length=8), nullable=False),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.Column('account', sa.String(length=16), nullable=True),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('request_enc', sa.Text(), nullable=True),
        sa.Column('request_sha256', sa.String(length=64), nullable=False),
        sa.Column('body_sha256', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('decided_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('decided_by_name', sa.String(length=460), nullable=True),
        sa.Column('decided_at', sa.DateTime(), nullable=True),
        sa.Column('decision_note', sa.Text(), nullable=True),
        sa.Column('approved_sha256', sa.String(length=64), nullable=True),
        sa.Column('delete_confirmed_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('sent_at', sa.DateTime(), nullable=True),
        sa.Column('response_status', sa.Integer(), nullable=True),
        sa.Column('exchange_id', sa.String(length=16), nullable=True),
        sa.Column('evidence_id', sa.Integer(), sa.ForeignKey('evidence.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_write_proposals_engagement_id', 'write_proposals', ['engagement_id'])
    op.create_index('ix_write_proposals_job_id', 'write_proposals', ['job_id'])
    for table in ('gateway_requests', 'agent_exchanges'):
        op.add_column(table, sa.Column('account', sa.String(length=16), nullable=True))
        op.add_column(table, sa.Column('approval_id', sa.Integer(), nullable=True))


def downgrade() -> None:
    for table in ('agent_exchanges', 'gateway_requests'):
        op.drop_column(table, 'approval_id')
        op.drop_column(table, 'account')
    op.drop_index('ix_write_proposals_job_id', 'write_proposals')
    op.drop_index('ix_write_proposals_engagement_id', 'write_proposals')
    op.drop_table('write_proposals')
    op.drop_index('ix_test_accounts_engagement_id', 'test_accounts')
    op.drop_table('test_accounts')
    op.drop_column('engagements', 'allow_writes')
