"""encryption at rest and retention: chain record v2, evidence source, retention date

Revision ID: 0017
Revises: 0016 on this branch (becomes 0017 when the gateway branch, which adds 0017, is merged first)
Create Date: 2026-10-09 23:00:00

Existing rows stay chain v1 with their plaintext summary, because their chain hash covers
the text, and their source is not known (null). Nothing is encrypted here: new content is
encrypted when it is written, and blobs stored before this are encrypted by an explicit
command (python -m app.vault encrypt-existing). See docs/ENCRYPTION.md.
"""
from alembic import op
import sqlalchemy as sa


revision = '0017'
down_revision = '0016'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('evidence') as b:
        b.add_column(sa.Column('record_version', sa.Integer(), server_default='1', nullable=False))
        b.alter_column('summary', existing_type=sa.Text(), nullable=True)
        b.add_column(sa.Column('summary_sha256', sa.String(length=64), nullable=True))
        b.add_column(sa.Column('summary_enc', sa.Text(), nullable=True))
        b.add_column(sa.Column('source', sa.String(length=40), nullable=True))
    op.add_column('engagements', sa.Column('retain_until', sa.Date(), nullable=True))
    op.add_column('engagements', sa.Column('content_deleted_at', sa.DateTime(), nullable=True))
    op.add_column('engagements', sa.Column('content_deleted_by', sa.String(length=460), nullable=True))
    op.add_column('engagements', sa.Column('content_deleted_reason', sa.String(length=16), nullable=True))


def downgrade() -> None:
    # Only safe before any v2 row exists: v2 rows have no plaintext summary to fall back to.
    conn = op.get_bind()
    if conn.execute(sa.text("SELECT count(*) FROM evidence WHERE record_version = 2")).scalar():
        raise RuntimeError("evidence in chain record v2 exists; downgrading would lose its summaries")
    op.drop_column('engagements', 'content_deleted_reason')
    op.drop_column('engagements', 'content_deleted_by')
    op.drop_column('engagements', 'content_deleted_at')
    op.drop_column('engagements', 'retain_until')
    with op.batch_alter_table('evidence') as b:
        b.drop_column('source')
        b.drop_column('summary_enc')
        b.drop_column('summary_sha256')
        b.alter_column('summary', existing_type=sa.Text(), nullable=False)
        b.drop_column('record_version')
