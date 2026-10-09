"""key log: hash-chained key registrations and revocations; sign-in times; own password

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-09 18:00:00
"""
import hashlib
import json
from datetime import timezone

from alembic import op
import sqlalchemy as sa


revision = '0013'
down_revision = '0012'
branch_labels = None
depends_on = None

GENESIS = '0' * 64


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _at(dt) -> str:
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat(timespec='microseconds')


def upgrade() -> None:
    op.add_column('users', sa.Column('password_chosen', sa.Boolean(), server_default=sa.text('false'), nullable=False))
    op.add_column('users', sa.Column('last_sign_in_at', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('previous_sign_in_at', sa.DateTime(), nullable=True))
    log = op.create_table(
        'key_log',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('seq', sa.Integer(), nullable=False, unique=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('user_name', sa.String(length=200), nullable=False),
        sa.Column('key_fingerprint', sa.String(length=64), nullable=False),
        sa.Column('algorithm', sa.String(length=20), nullable=False),
        sa.Column('event', sa.String(length=16), nullable=False),
        sa.Column('at', sa.String(length=40), nullable=False),
        sa.Column('via', sa.String(length=24), nullable=False),
        sa.Column('record_sha256', sa.String(length=64), nullable=False),
        sa.Column('prev_hash', sa.String(length=64), nullable=False),
        sa.Column('entry_hash', sa.String(length=64), nullable=False),
    )
    op.create_index('ix_key_log_user_id', 'key_log', ['user_id'])
    op.create_index('ix_key_log_key_fingerprint', 'key_log', ['key_fingerprint'])

    # Keys that exist already get their entries now, marked "backfill": when and how they
    # were registered is what signing_keys says, and nothing more is known.
    keys = sa.table('signing_keys', sa.column('id', sa.Integer), sa.column('user_id', sa.Integer),
                    sa.column('algorithm', sa.String), sa.column('fingerprint', sa.String),
                    sa.column('created_at', sa.DateTime), sa.column('revoked_at', sa.DateTime))
    users = sa.table('users', sa.column('id', sa.Integer), sa.column('name', sa.String))
    conn = op.get_bind()
    names = dict(conn.execute(sa.select(users.c.id, users.c.name)).all())
    events = []
    for k in conn.execute(sa.select(keys).order_by(keys.c.id)).mappings():
        events.append((_at(k['created_at']), 0, k['id'], 'registered', k))
        if k['revoked_at'] is not None:
            events.append((_at(k['revoked_at']), 1, k['id'], 'revoked', k))
    rows, prev = [], GENESIS
    for seq, (at, _, _, event, k) in enumerate(sorted(events, key=lambda e: e[:3]), start=1):
        record = {'seq': seq, 'user_id': k['user_id'], 'user_name': names.get(k['user_id'], ''),
                  'key_fingerprint': k['fingerprint'], 'algorithm': k['algorithm'], 'event': event,
                  'at': at, 'via': 'backfill'}
        rsha = _sha(json.dumps(record, sort_keys=True, separators=(',', ':'), ensure_ascii=False))
        entry = _sha(prev + rsha)
        rows.append({**record, 'record_sha256': rsha, 'prev_hash': prev, 'entry_hash': entry})
        prev = entry
    if rows:
        op.bulk_insert(log, rows)


def downgrade() -> None:
    op.drop_index('ix_key_log_key_fingerprint', table_name='key_log')
    op.drop_index('ix_key_log_user_id', table_name='key_log')
    op.drop_table('key_log')
    for c in ('previous_sign_in_at', 'last_sign_in_at', 'password_chosen'):
        op.drop_column('users', c)
