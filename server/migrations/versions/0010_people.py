"""people: users, sessions, per-engagement roles, separation of duties, authorship

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-09 12:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('email', sa.String(length=254), nullable=False, unique=True),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('password_hash', sa.String(length=300), nullable=False),
        sa.Column('is_owner', sa.Boolean(), server_default=sa.text('false'), nullable=False),
        sa.Column('disabled', sa.Boolean(), server_default=sa.text('false'), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_table(
        'user_sessions',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('token_sha256', sa.String(length=64), nullable=False, unique=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
    )
    op.create_table(
        'memberships',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('engagement_id', sa.Integer(), sa.ForeignKey('engagements.id'), nullable=False),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('roles', sa.JSON(), nullable=False),
        sa.UniqueConstraint('engagement_id', 'user_id'),
    )
    op.add_column('engagements', sa.Column('separation_of_duties', sa.Boolean(),
                                           server_default=sa.text('false'), nullable=False))
    for table, fk in (('evidence', 'fk_evidence_created_by_users'), ('jobs', 'fk_jobs_created_by_users')):
        op.add_column(table, sa.Column('created_by', sa.Integer(), nullable=True))
        with op.batch_alter_table(table) as batch:
            batch.create_foreign_key(fk, 'users', ['created_by'], ['id'])
    op.add_column('receipts', sa.Column('closed_by_user', sa.Integer(), nullable=True))
    with op.batch_alter_table('receipts') as batch:
        batch.create_foreign_key('fk_receipts_closed_by_user_users', 'users', ['closed_by_user'], ['id'])


def downgrade() -> None:
    with op.batch_alter_table('receipts') as batch:
        batch.drop_constraint('fk_receipts_closed_by_user_users', type_='foreignkey')
    op.drop_column('receipts', 'closed_by_user')
    for table, fk in (('jobs', 'fk_jobs_created_by_users'), ('evidence', 'fk_evidence_created_by_users')):
        with op.batch_alter_table(table) as batch:
            batch.drop_constraint(fk, type_='foreignkey')
        op.drop_column(table, 'created_by')
    op.drop_column('engagements', 'separation_of_duties')
    op.drop_table('memberships')
    op.drop_table('user_sessions')
    op.drop_table('users')
