"""append-only tables are protected by the database too: triggers refuse UPDATE and DELETE (TM-5)

Until now only the application kept evidence, receipts, the request log, the audit log and the
key log append-only. These triggers refuse, in the database, every DELETE of their rows (and on
Postgres every TRUNCATE), and every UPDATE except the column changes the product makes:

  evidence           summary_enc becomes NULL (an engagement's content is deleted)
  receipts           the timestamp columns, while the receipt has no timestamp token
  gateway_requests   url and reason become '' (an engagement's content is deleted)
  audit_log, key_log none

A database superuser can still drop them; the hash chains remain the proof (app/appendonly.py,
docs/THREAT_MODEL.md, TM-5). A later migration that changes rows of these tables drops the
trigger first and makes it again; one that rebuilds such a table on SQLite makes its triggers
again. The generator and the column lists below are frozen copies of app/appendonly.py at this
revision; tests/test_appendonly.py checks that a database migrated to head has the triggers a
database made from the models has.

Downgrade: the triggers and their functions are dropped.

Revision ID: 0026
Revises: 0025
Create Date: 2026-10-11 00:00:00
"""
from dataclasses import dataclass

from alembic import op


revision = '0026'
down_revision = '0025'
branch_labels = None
depends_on = None

COLUMNS = {
    'evidence': (
        'chain_hash', 'created_at', 'created_by', 'engagement_id', 'id', 'item_id',
        'kind', 'lane_id', 'organization_id', 'prev_hash', 'record_version', 'redaction',
        'seq', 'sha256', 'source', 'summary', 'summary_enc', 'summary_sha256',
        'uri',
    ),
    'receipts': (
        'algorithm', 'closed_by', 'closed_by_email', 'closed_by_user', 'created_at', 'id',
        'key_fingerprint', 'lane_id', 'manifest_sha256', 'payload', 'public_key', 'signature',
        'timestamp_error', 'timestamp_time', 'timestamp_token', 'timestamp_tsa',
    ),
    'gateway_requests': (
        'account', 'approval_id', 'at', 'bytes_received', 'bytes_sent', 'duration_ms',
        'engagement_id', 'host', 'id', 'job_id', 'kind', 'method',
        'organization_id', 'port', 'reason', 'status', 'tool', 'url',
        'verdict',
    ),
    'audit_log': (
        'action', 'actor_email', 'actor_kind', 'actor_name', 'actor_user_id', 'at',
        'change', 'engagement_id', 'entry_hash', 'id', 'organization_id', 'prev_hash',
        'record_sha256', 'seq', 'subject_id',
    ),
    'key_log': (
        'algorithm', 'at', 'entry_hash', 'event', 'id', 'key_fingerprint',
        'organization_id', 'prev_hash', 'record_sha256', 'seq', 'user_id', 'user_name',
        'via',
    ),
}


PREFIX = "attackledger_append_only"


@dataclass(frozen=True)
class Rule:
    may_change: tuple[str, ...] = ()
    # When the columns that may change did change, the change must also meet this condition
    # (Postgres and SQLite spellings).
    pg: str = "FALSE"
    sqlite: str = "0"
    why: str = "rows are never changed"


RULES: dict[str, Rule] = {
    "evidence": Rule(
        ("summary_enc",),
        pg="NEW.summary_enc IS NULL", sqlite="NEW.summary_enc IS NULL",
        why="only an encrypted summary may be removed, when the engagement's content is deleted"),
    "receipts": Rule(
        ("timestamp_error", "timestamp_time", "timestamp_token", "timestamp_tsa"),
        pg="OLD.timestamp_token IS NULL", sqlite="OLD.timestamp_token IS NULL",
        why="only a receipt without a timestamp token may get one"),
    "gateway_requests": Rule(
        ("reason", "url"),
        pg="(NEW.url = '' OR NEW.url = OLD.url) AND (NEW.reason = '' OR NEW.reason = OLD.reason)",
        sqlite="(NEW.url = '' OR NEW.url IS OLD.url) AND (NEW.reason = '' OR NEW.reason IS OLD.reason)",
        why="only the URL and the reason may be removed, when the engagement's content is deleted"),
    "audit_log": Rule(),
    "key_log": Rule(),
}


def _message(table: str, what: str, rule: Rule) -> str:
    text = f"{table} is append-only (TM-5): {what}"
    if what == "rows are never updated" and rule.may_change:
        text = f"{table} is append-only (TM-5): {rule.why}"
    return text.replace("'", "''")


def create_statements(dialect: str, columns: dict[str, list[str]], rules: dict[str, Rule] = RULES) -> list[str]:
    """The DDL that makes the triggers. columns: each table's column names (SQLite compares them
    one by one; Postgres compares the whole row, so a column added later is protected too)."""
    out: list[str] = []
    if dialect == "postgresql":
        out.append(f"""CREATE OR REPLACE FUNCTION {PREFIX}_truncate() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
  RAISE EXCEPTION USING MESSAGE = TG_TABLE_NAME || ' is append-only (TM-5): it is never truncated';
END
$fn$""")
        for table, rule in rules.items():
            free = ", ".join(f"'{c}'" for c in rule.may_change)
            same = (f"(to_jsonb(NEW) - ARRAY[{free}]::text[]) IS NOT DISTINCT FROM (to_jsonb(OLD) - ARRAY[{free}]::text[])"
                    if rule.may_change else "to_jsonb(NEW) IS NOT DISTINCT FROM to_jsonb(OLD)")
            unchanged = (" AND ".join(f"NEW.{c} IS NOT DISTINCT FROM OLD.{c}" for c in rule.may_change)
                         if rule.may_change else "TRUE")
            out.append(f"""CREATE OR REPLACE FUNCTION {PREFIX}_{table}() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING MESSAGE = '{_message(table, "rows are never deleted", rule)}';
  END IF;
  IF NOT ({same}) OR NOT (({unchanged}) OR ({rule.pg})) THEN
    RAISE EXCEPTION USING MESSAGE = '{_message(table, "rows are never updated", rule)}';
  END IF;
  RETURN NEW;
END
$fn$""")
            out.append(f"CREATE TRIGGER {PREFIX}_{table} BEFORE UPDATE OR DELETE ON {table} "
                       f"FOR EACH ROW EXECUTE FUNCTION {PREFIX}_{table}()")
            out.append(f"CREATE TRIGGER {PREFIX}_{table}_truncate BEFORE TRUNCATE ON {table} "
                       f"FOR EACH STATEMENT EXECUTE FUNCTION {PREFIX}_truncate()")
    elif dialect == "sqlite":
        for table, rule in rules.items():
            fixed = [c for c in sorted(columns[table]) if c not in rule.may_change]
            changed = " OR ".join(f"NEW.{c} IS NOT OLD.{c}" for c in fixed)
            if rule.may_change:
                moved = " OR ".join(f"NEW.{c} IS NOT OLD.{c}" for c in rule.may_change)
                changed += f" OR (({moved}) AND NOT ({rule.sqlite}))"
            out.append(f"CREATE TRIGGER {PREFIX}_{table}_delete BEFORE DELETE ON {table} "
                       f"BEGIN SELECT RAISE(ABORT, '{_message(table, 'rows are never deleted', rule)}'); END")
            out.append(f"CREATE TRIGGER {PREFIX}_{table}_update BEFORE UPDATE ON {table} WHEN {changed} "
                       f"BEGIN SELECT RAISE(ABORT, '{_message(table, 'rows are never updated', rule)}'); END")
    return out


def drop_statements(dialect: str, rules: dict[str, Rule] = RULES) -> list[str]:
    out: list[str] = []
    for table in rules:
        if dialect == "postgresql":
            out.append(f"DROP TRIGGER IF EXISTS {PREFIX}_{table} ON {table}")
            out.append(f"DROP TRIGGER IF EXISTS {PREFIX}_{table}_truncate ON {table}")
            out.append(f"DROP FUNCTION IF EXISTS {PREFIX}_{table}()")
        elif dialect == "sqlite":
            out.append(f"DROP TRIGGER IF EXISTS {PREFIX}_{table}_delete")
            out.append(f"DROP TRIGGER IF EXISTS {PREFIX}_{table}_update")
    if dialect == "postgresql":
        out.append(f"DROP FUNCTION IF EXISTS {PREFIX}_truncate()")
    return out


def upgrade() -> None:
    bind = op.get_bind()
    for stmt in create_statements(bind.dialect.name, {t: list(c) for t, c in COLUMNS.items()}):
        bind.exec_driver_sql(stmt)


def downgrade() -> None:
    bind = op.get_bind()
    for stmt in drop_statements(bind.dialect.name):
        bind.exec_driver_sql(stmt)
