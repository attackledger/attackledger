"""audit record v2: the chain commits to a salted hash of each free-text field (D-058)

The audit log kept free text that deleting an engagement's content could not remove without
breaking its hash chain: notes on approved and rejected writes, the path typed to confirm a
DELETE, test accounts' roles, hosts and header names, dismissal reasons, the tool that made an
imported file. Entries written from now on are record version 2: those fields leave the change,
the record commits to text_sha256 (a salted SHA-256 per field), and the salt and the value are kept
in texts, outside the hashed bytes, which deleting the content sets to NULL.

  audit_log.record_version   1 for every existing entry, which keeps its text and verifies as before
  audit_log.text_sha256      v2: canonical JSON {path: hash}
  audit_log.texts            v2: canonical JSON {path: {salt, value}}; NULL once deleted

The append-only triggers of audit_log (0026) are made again, with the new columns, so that texts
may become NULL and nothing else changes. The generator below is a frozen copy of
app/appendonly.py at this revision, for this table; tests/test_appendonly.py checks that a
database migrated to head has the triggers a database made from the models has.

Downgrade: refused once a v2 entry exists (its record would no longer be rebuilt); otherwise the
columns are dropped and the triggers of 0026 made again.

Revision ID: 0028
Revises: 0027
Create Date: 2026-10-14 00:00:00
"""
from dataclasses import dataclass

from alembic import op
import sqlalchemy as sa


revision = '0028'
down_revision = '0027'
branch_labels = None
depends_on = None

TABLE = 'audit_log'
COLUMNS_0026 = (
    'action', 'actor_email', 'actor_kind', 'actor_name', 'actor_user_id', 'at',
    'change', 'engagement_id', 'entry_hash', 'id', 'organization_id', 'prev_hash',
    'record_sha256', 'seq', 'subject_id',
)
COLUMNS = COLUMNS_0026 + ('record_version', 'text_sha256', 'texts')
# As in 0022, 0023 and 0027: Postgres's own names for the constraints it made unnamed, for SQLite's table copy.
NAMES = {'uq': '%(table_name)s_%(column_0_N_name)s_key', 'fk': '%(table_name)s_%(column_0_name)s_fkey'}

PREFIX = "attackledger_append_only"


@dataclass(frozen=True)
class Rule:
    may_change: tuple[str, ...] = ()
    pg: str = "FALSE"
    sqlite: str = "0"
    why: str = "rows are never changed"


RULE_0026 = Rule()
RULE = Rule(
    ("texts",),
    pg="NEW.texts IS NULL", sqlite="NEW.texts IS NULL",
    why="only the free text of an entry may be removed, when its engagement's content is deleted")


def _message(table: str, what: str, rule: Rule) -> str:
    text = f"{table} is append-only (TM-5): {what}"
    if what == "rows are never updated" and rule.may_change:
        text = f"{table} is append-only (TM-5): {rule.why}"
    return text.replace("'", "''")


def create_statements(dialect: str, columns, rule: Rule, table: str = TABLE) -> list[str]:
    out: list[str] = []
    if dialect == "postgresql":
        out.append(f"""CREATE OR REPLACE FUNCTION {PREFIX}_truncate() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
  RAISE EXCEPTION USING MESSAGE = TG_TABLE_NAME || ' is append-only (TM-5): it is never truncated';
END
$fn$""")
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
        fixed = [c for c in sorted(columns) if c not in rule.may_change]
        changed = " OR ".join(f"NEW.{c} IS NOT OLD.{c}" for c in fixed)
        if rule.may_change:
            moved = " OR ".join(f"NEW.{c} IS NOT OLD.{c}" for c in rule.may_change)
            changed += f" OR (({moved}) AND NOT ({rule.sqlite}))"
        out.append(f"CREATE TRIGGER {PREFIX}_{table}_delete BEFORE DELETE ON {table} "
                   f"BEGIN SELECT RAISE(ABORT, '{_message(table, 'rows are never deleted', rule)}'); END")
        out.append(f"CREATE TRIGGER {PREFIX}_{table}_update BEFORE UPDATE ON {table} WHEN {changed} "
                   f"BEGIN SELECT RAISE(ABORT, '{_message(table, 'rows are never updated', rule)}'); END")
    return out


def drop_statements(dialect: str, table: str = TABLE) -> list[str]:
    """This table's triggers and function only: the shared truncate function stays, the other
    tables' truncate triggers use it."""
    if dialect == "postgresql":
        return [f"DROP TRIGGER IF EXISTS {PREFIX}_{table} ON {table}",
                f"DROP TRIGGER IF EXISTS {PREFIX}_{table}_truncate ON {table}",
                f"DROP FUNCTION IF EXISTS {PREFIX}_{table}()"]
    if dialect == "sqlite":
        return [f"DROP TRIGGER IF EXISTS {PREFIX}_{table}_delete", f"DROP TRIGGER IF EXISTS {PREFIX}_{table}_update"]
    return []


def _run(statements: list[str]) -> None:
    bind = op.get_bind()
    for stmt in statements:
        bind.exec_driver_sql(stmt)


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    _run(drop_statements(dialect))
    op.add_column(TABLE, sa.Column('record_version', sa.Integer(), server_default='1', nullable=False))
    op.add_column(TABLE, sa.Column('text_sha256', sa.Text(), nullable=True))
    op.add_column(TABLE, sa.Column('texts', sa.Text(), nullable=True))
    _run(create_statements(dialect, COLUMNS, RULE))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT count(*) FROM audit_log WHERE record_version = 2")).scalar():
        raise RuntimeError("audit log entries in record version 2 exist; downgrading would make them unverifiable")
    dialect = bind.dialect.name
    _run(drop_statements(dialect))
    with op.batch_alter_table(TABLE, naming_convention=NAMES) as b:
        b.drop_column('texts')
        b.drop_column('text_sha256')
        b.drop_column('record_version')
    _run(create_statements(dialect, COLUMNS_0026, RULE_0026))
