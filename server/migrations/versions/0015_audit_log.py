"""audit log: hash-chained administrative changes; the signer's email on receipts

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-09 22:00:00
"""
import hashlib
import json
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa


revision = '0015'
down_revision = '0014'
branch_labels = None
depends_on = None

GENESIS = '0' * 64
BACKFILL = {'kind': 'backfill', 'user_id': None, 'name': 'audit log backfill', 'email': None}


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _iso(dt):
    return None if dt is None else (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


def upgrade() -> None:
    op.add_column('receipts', sa.Column('closed_by_email', sa.String(length=254), nullable=True))
    log = op.create_table(
        'audit_log',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('seq', sa.Integer(), nullable=False, unique=True),
        sa.Column('at', sa.String(length=40), nullable=False),
        sa.Column('actor_kind', sa.String(length=16), nullable=False),
        sa.Column('actor_user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('actor_name', sa.String(length=200), nullable=False),
        sa.Column('actor_email', sa.String(length=254), nullable=True),
        sa.Column('action', sa.String(length=40), nullable=False),
        sa.Column('engagement_id', sa.Integer(), sa.ForeignKey('engagements.id'), nullable=True),
        sa.Column('subject_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('change', sa.Text(), nullable=False),
        sa.Column('record_sha256', sa.String(length=64), nullable=False),
        sa.Column('prev_hash', sa.String(length=64), nullable=False),
        sa.Column('entry_hash', sa.String(length=64), nullable=False),
    )
    op.create_index('ix_audit_log_engagement_id', 'audit_log', ['engagement_id'])
    op.create_index('ix_audit_log_subject_id', 'audit_log', ['subject_id'])

    # What exists already is recorded once, as it is now, by "backfill": who set it and when
    # is not known. Receipts issued before this have no role history to check against.
    conn = op.get_bind()
    users = sa.table('users', sa.column('id', sa.Integer), sa.column('email', sa.String), sa.column('name', sa.String),
                     sa.column('is_owner', sa.Boolean), sa.column('disabled', sa.Boolean))
    engs = sa.table('engagements', sa.column('id', sa.Integer), sa.column('scope_include', sa.JSON),
                    sa.column('scope_exclude', sa.JSON), sa.column('rate_limit_rps', sa.Integer),
                    sa.column('research_header', sa.String), sa.column('research_user_agent', sa.String),
                    sa.column('enabled_modules', sa.JSON), sa.column('crawl_depth', sa.Integer),
                    sa.column('separation_of_duties', sa.Boolean), sa.column('require_signatures', sa.Boolean),
                    sa.column('authorized_by', sa.String), sa.column('authorized_at', sa.DateTime),
                    sa.column('policy_url', sa.String))
    members = sa.table('memberships', sa.column('engagement_id', sa.Integer), sa.column('user_id', sa.Integer),
                       sa.column('roles', sa.JSON))
    people = {u['id']: u for u in conn.execute(sa.select(users).order_by(users.c.id)).mappings()}
    events = []          # (action, engagement_id, subject_id, change)
    for u in people.values():
        ref = {'id': u['id'], 'name': u['name'], 'email': u['email']}
        events.append(('person.created', None, u['id'], {
            'person': ref, 'after': {'email': u['email'], 'name': u['name'], 'is_owner': bool(u['is_owner']),
                                     'disabled': bool(u['disabled'])}}))
    roles: dict[int, list] = {}
    for m in conn.execute(sa.select(members)).mappings():
        if m['user_id'] in people and m['roles']:
            u = people[m['user_id']]
            roles.setdefault(m['engagement_id'], []).append(
                {'user_id': u['id'], 'name': u['name'], 'email': u['email'], 'roles': sorted(m['roles'])})
    for e in conn.execute(sa.select(engs).order_by(engs.c.id)).mappings():
        events.append(('scope.updated', e['id'], None, {'before': None, 'after': {
            'include': list(e['scope_include'] or []), 'exclude': list(e['scope_exclude'] or []),
            'rate_limit_rps': e['rate_limit_rps'], 'research_header': e['research_header'],
            'research_user_agent': e['research_user_agent'], 'enabled_modules': sorted(e['enabled_modules'] or []),
            'crawl_depth': e['crawl_depth']}}))
        events.append(('engagement.settings', e['id'], None, {'before': None, 'after': {
            'separation_of_duties': bool(e['separation_of_duties']),
            'require_signatures': bool(e['require_signatures'])}}))
        if e['authorized_at'] is not None:
            events.append(('engagement.authorized', e['id'], None, {'before': None, 'after': {
                'authorized_by': e['authorized_by'], 'policy_url': e['policy_url'],
                'authorized_at': _iso(e['authorized_at'])}}))
        events.append(('members.updated', e['id'], None, {
            'before': None, 'after': sorted(roles.get(e['id'], []), key=lambda m: m['user_id'])}))
    at = datetime.now(timezone.utc).isoformat(timespec='microseconds')
    rows, prev = [], GENESIS
    for seq, (action, eng_id, subject, change) in enumerate(events, start=1):
        record = {'seq': seq, 'at': at, 'actor': BACKFILL, 'action': action, 'engagement_id': eng_id,
                  'subject_id': subject, 'change': change}
        rsha = _sha(_canonical(record))
        entry = _sha(prev + rsha)
        rows.append({'seq': seq, 'at': at, 'actor_kind': 'backfill', 'actor_user_id': None,
                     'actor_name': BACKFILL['name'], 'actor_email': None, 'action': action,
                     'engagement_id': eng_id, 'subject_id': subject, 'change': _canonical(change),
                     'record_sha256': rsha, 'prev_hash': prev, 'entry_hash': entry})
        prev = entry
    if rows:
        op.bulk_insert(log, rows)


def downgrade() -> None:
    op.drop_index('ix_audit_log_subject_id', table_name='audit_log')
    op.drop_index('ix_audit_log_engagement_id', table_name='audit_log')
    op.drop_table('audit_log')
    op.drop_column('receipts', 'closed_by_email')
