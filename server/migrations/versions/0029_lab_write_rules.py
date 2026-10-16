"""lab write rules: a standing approval of writes on an intentionally vulnerable lab (D-062)

  lab_write_rules             an owner's rule: methods, lab hosts, paths, a cap, an end
  write_proposals.rule_id     the rule that approved a write, instead of a person reading it
  write_proposals.rule_sod_met  whether the rule's maker was not the run's starter

Nothing changes for existing rows: they were approved by a person, so rule_id is NULL.

Downgrade: the columns and the table are dropped; the writes stay in the audit log.

Revision ID: 0029
Revises: 0028
Create Date: 2026-10-16 00:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0029'
down_revision = '0028'
branch_labels = None
depends_on = None

# As in 0022 and 0023: Postgres's own names for the constraints it made unnamed, for SQLite's table copy.
NAMES = {'uq': '%(table_name)s_%(column_0_N_name)s_key', 'fk': '%(table_name)s_%(column_0_name)s_fkey'}


def upgrade() -> None:
    op.create_table(
        'lab_write_rules',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('organization_id', sa.Integer(), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('engagement_id', sa.Integer(), sa.ForeignKey('engagements.id'), nullable=False),
        sa.Column('methods', sa.JSON(), nullable=False),
        sa.Column('hosts', sa.JSON(), nullable=False),
        sa.Column('paths', sa.JSON(), nullable=False),
        sa.Column('max_writes', sa.Integer(), nullable=False),
        sa.Column('used', sa.Integer(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('note', sa.Text(), nullable=True),
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('created_by_name', sa.String(length=460), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_lab_write_rules_engagement_id', 'lab_write_rules', ['engagement_id'])
    op.create_index('ix_lab_write_rules_organization_id', 'lab_write_rules', ['organization_id'])
    with op.batch_alter_table('write_proposals', naming_convention=NAMES) as b:
        b.add_column(sa.Column('rule_id', sa.Integer(), nullable=True))
        b.add_column(sa.Column('rule_sod_met', sa.Boolean(), nullable=True))
        b.create_foreign_key('write_proposals_rule_id_fkey', 'lab_write_rules', ['rule_id'], ['id'])


def downgrade() -> None:
    with op.batch_alter_table('write_proposals', naming_convention=NAMES) as b:
        b.drop_constraint('write_proposals_rule_id_fkey', type_='foreignkey')
        b.drop_column('rule_sod_met')
        b.drop_column('rule_id')
    op.drop_index('ix_lab_write_rules_organization_id', 'lab_write_rules')
    op.drop_index('ix_lab_write_rules_engagement_id', 'lab_write_rules')
    op.drop_table('lab_write_rules')
