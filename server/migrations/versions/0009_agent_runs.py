"""agent runs: a job can work a lane, and keeps a structured result

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-09 00:40:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('jobs', sa.Column('lane_id', sa.Integer(), nullable=True))
    op.add_column('jobs', sa.Column('result', sa.JSON(), nullable=True))
    with op.batch_alter_table('jobs') as batch:
        batch.create_foreign_key('fk_jobs_lane_id_lanes', 'lanes', ['lane_id'], ['id'])


def downgrade() -> None:
    with op.batch_alter_table('jobs') as batch:
        batch.drop_constraint('fk_jobs_lane_id_lanes', type_='foreignkey')
    op.drop_column('jobs', 'result')
    op.drop_column('jobs', 'lane_id')
