"""organizations: every record belongs to one (D-042, docs/ORGANIZATIONS.md)

Creates `organizations` with one row, the default organization, and gives every table that
is owned directly an `organization_id` that names it. Existing rows all go to the default
organization, so a self-hosted install is the same install with one organization.

Names, emails and the two log chains become unique per organization: engagement names and
emails within one, and the key log and the audit log each one chain per organization, keyed
(organization_id, seq). The chains themselves are untouched: the default organization's chain
is the deployment's chain as it was, with the same seq and hashes, so reports issued before
this verify as before.

Tables owned through a parent get no column (orgscope.THROUGH): checklist_items and receipts
(their lane), agent_exchanges (its job), signing_keys and user_sessions (their person).

Downgrade puts everything back, and refuses while there is more than one organization: their
names, emails and chain positions could collide once unique for the whole deployment again.

Revision ID: 0022
Revises: 0021
Create Date: 2026-10-10 12:00:00
"""
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa


revision = '0022'
down_revision = '0021'
branch_labels = None
depends_on = None

DEFAULT = 'Default organization'
# Owned directly, in the order the column is added (parents first).
DIRECT = ('users', 'engagements', 'memberships', 'assets', 'lanes', 'evidence', 'jobs', 'observations',
          'endpoints', 'leads', 'key_log', 'audit_log', 'import_batches', 'inbox_entries', 'test_accounts',
          'write_proposals', 'gateway_requests')
# Unique for the deployment until now, per organization from now on: (table, column).
PER_ORG = {'engagements': 'name', 'users': 'email', 'key_log': 'seq', 'audit_log': 'seq'}
# Postgres's own names for constraints it made unnamed, so SQLite (which reflects them without
# a name) and Postgres use the same names here.
NAMES = {'uq': '%(table_name)s_%(column_0_N_name)s_key', 'fk': '%(table_name)s_%(column_0_name)s_fkey'}


def upgrade() -> None:
    conn = op.get_bind()
    orgs = op.create_table(
        'organizations',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(length=200), nullable=False, unique=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('worker_token_sha256', sa.String(length=64), nullable=True, unique=True),
        sa.Column('gateway_token_sha256', sa.String(length=64), nullable=True, unique=True),
    )
    conn.execute(orgs.insert().values(name=DEFAULT, created_at=datetime.now(timezone.utc).replace(tzinfo=None)))
    default = conn.scalar(sa.select(orgs.c.id).where(orgs.c.name == DEFAULT))
    for table in DIRECT:
        op.add_column(table, sa.Column('organization_id', sa.Integer(), nullable=True))
        conn.execute(sa.text(f'UPDATE {table} SET organization_id = :org'), {'org': default})
    for table in DIRECT:
        with op.batch_alter_table(table, naming_convention=NAMES) as b:
            b.alter_column('organization_id', existing_type=sa.Integer(), nullable=False)
            b.create_foreign_key(f'{table}_organization_id_fkey', 'organizations', ['organization_id'], ['id'])
            if table in PER_ORG:
                col = PER_ORG[table]
                b.drop_constraint(f'{table}_{col}_key', type_='unique')
                b.create_unique_constraint(f'{table}_organization_id_{col}_key', ['organization_id', col])
            else:
                b.create_index(f'ix_{table}_organization_id', ['organization_id'])


def downgrade() -> None:
    conn = op.get_bind()
    n = conn.scalar(sa.text('SELECT count(*) FROM organizations'))
    if n > 1:
        raise RuntimeError(f'this database has {n} organizations; a database before 0022 holds one. '
                           'Nothing was changed.')
    for table in reversed(DIRECT):
        with op.batch_alter_table(table, naming_convention=NAMES) as b:
            if table in PER_ORG:
                col = PER_ORG[table]
                b.drop_constraint(f'{table}_organization_id_{col}_key', type_='unique')
                b.create_unique_constraint(f'{table}_{col}_key', [col])
            else:
                b.drop_index(f'ix_{table}_organization_id')
            b.drop_constraint(f'{table}_organization_id_fkey', type_='foreignkey')
            b.drop_column('organization_id')
    op.drop_table('organizations')
