"""Append-only tables, enforced by the database as well as the application (TM-5).

The API never deletes a row of these tables, and updates only the columns listed here, in the
one way the product needs. Triggers on Postgres and on SQLite refuse every other UPDATE and every
DELETE (and, on Postgres, TRUNCATE), whoever sends it: a bug, a script run with the database
password, an injected query.

  evidence           summary_enc may become NULL: deleting an engagement's content, by an owner
                     or the retention policy (vault.delete_content). The chain commits to
                     summary_sha256, which stays.
  receipts           the four timestamp columns may change while the receipt has no timestamp
                     token: a timestamp asked for again after an attempt failed, or for a receipt
                     issued before a timestamp authority was set (main.timestamp_receipt). Once a
                     token is stored, nothing changes.
  gateway_requests   url and reason may become '': deleting the engagement's content
                     (vault.delete_content). Method, host, port, status, verdict and bytes stay.
  audit_log          texts may become NULL: deleting an engagement's content blanks the free text
                     of its v2 entries (D-058). The record commits to text_sha256, which stays.
  key_log            nothing changes.

Who these triggers do not stop: a database superuser (the role the Postgres image makes from
POSTGRES_USER, which the API connects as) can drop or disable them, and anyone who can write the
SQLite file can rewrite it. They are a second layer against mistakes and against SQL sent through
the application; the hash chains (ledger.py, auditlog.py, keylog.py), the reviewers' signatures
and the report seal remain what proves that nothing changed (docs/THREAT_MODEL.md, TM-5).

The same triggers are made by migration 0026 (with the column lists of that time, frozen there;
0028 makes audit_log's again with its new columns and rule) and, for a database made from the models (tests, create_all), by attach() below. A migration that
must change one of these tables' rows drops the trigger first and makes it again; on SQLite, a
migration that rebuilds one of these tables (batch_alter_table) must make its triggers again,
since a rebuilt table has none. tests/test_appendonly.py compares the two.
"""
from dataclasses import dataclass

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
    "audit_log": Rule(
        ("texts",),
        pg="NEW.texts IS NULL", sqlite="NEW.texts IS NULL",
        why="only the free text of an entry may be removed, when its engagement's content is deleted"),
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


def model_columns(metadata) -> dict[str, list[str]]:
    return {t: [c.name for c in metadata.tables[t].columns] for t in RULES if t in metadata.tables}


def attach(metadata) -> None:
    """Make the triggers whenever create_all makes these tables (tests, databases from before
    migrations), as migration 0026 makes them for every migrated database."""
    from sqlalchemy import DDL, event

    def make(target, connection, tables=(), **_kw):
        made = {t.name for t in tables}
        rules = {name: rule for name, rule in RULES.items() if name in made}
        if not rules:
            return
        # DDL() formats the text with %: a literal % would have to be doubled; there is none.
        for stmt in create_statements(connection.dialect.name, model_columns(target), rules):
            connection.execute(DDL(stmt))
    event.listen(metadata, "after_create", make)
