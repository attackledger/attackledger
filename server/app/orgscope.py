"""Every query scoped to the caller's organization, in one place (D-042, docs/ORGANIZATIONS.md).

A session carries the organization it works for in session.info, set by authz.authorize from
whoever calls: a person, the operator token, the worker, one job, or the gateway. While it does:

  - every SELECT, UPDATE and DELETE on a table owned directly (models.OrgOwned) gets
    `organization_id = <the session's>` wherever the table appears, joins and subqueries
    included (with_loader_criteria, from do_orm_execute). A route cannot forget the filter,
    because it never writes it;
  - every new row takes its organization from its parents, and a row whose parents belong to
    two organizations, or to another one than the session's, is refused (before_flush). That
    holds for tables owned through a parent (THROUGH) too, so no row ever points across.

A session is in one of three states:

  absent    the operator's: the command line, the API's maintenance thread, migrations and
            tests. Not filtered; new rows still take their parents' organization, or the
            default one when they have no parent.
  PENDING   a request whose caller is not known yet (authz sets it first). Any query raises:
            the few routes that run before they know who calls (sign-in, sign-out) say so with
            unscoped().
  <id>      a request for that organization.
"""
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import event, func, inspect, select
from sqlalchemy.orm import RelationshipDirection, Session, with_loader_criteria

from .db import Base
from .models import AgentExchange, ChecklistItem, Organization, OrgOwned, Receipt, SigningKey, UserSession

KEY = "organization_id"
PENDING = "pending"

# Tables owned through a parent, and why they need no column of their own (docs/ORGANIZATIONS.md):
# each is reached only through that parent, which the session has already scoped.
THROUGH: dict[type, str] = {
    ChecklistItem: "lane_id",       # lane.items, by index; never listed alone
    Receipt: "lane_id",             # lane.receipts; the report and history reach them by lane
    AgentExchange: "job_id",        # one running job's own token only; deleted when the job ends
    SigningKey: "user_id",          # the caller's own keys; fingerprints are unique in the deployment
    UserSession: "user_id",         # found by the cookie's hash before the organization is known
}


class TenancyError(RuntimeError):
    """Code tried to read before it knew the caller, or to join rows of two organizations."""


def scope(session, organization_id: int) -> None:
    session.info[KEY] = int(organization_id)


def pend(session) -> None:
    session.info[KEY] = PENDING


def current(session) -> int | None:
    v = session.info.get(KEY)
    return v if isinstance(v, int) else None


@contextmanager
def unscoped(session):
    """Run without the filter: sign-in (the email decides the organization), and the few
    deployment-wide facts (whether anyone exists, which plaintext blobs are still cited)."""
    had, old = KEY in session.info, session.info.pop(KEY, None)
    try:
        yield session
    finally:
        session.info.pop(KEY, None)
        if had:
            session.info[KEY] = old


def default_id(session) -> int:
    """The default organization: the first one, made by migration 0022 or with the tables."""
    with unscoped(session):
        org = session.scalar(select(func.min(Organization.id)))
    if org is None:
        raise TenancyError("no organization exists: the database is not migrated (the API migrates it when it starts)")
    return org


def count(session) -> int:
    with unscoped(session):
        return session.scalar(select(func.count()).select_from(Organization)) or 0


# ---- the filter ------------------------------------------------------------------------------

@event.listens_for(Session, "do_orm_execute")
def _filter(state) -> None:
    org = state.session.info.get(KEY)
    if org is None:
        return
    if org == PENDING:
        raise TenancyError("a query ran before the caller's organization was known")
    if (state.is_select or state.is_update or state.is_delete) and not state.is_column_load:
        state.statement = state.statement.options(
            with_loader_criteria(OrgOwned, lambda cls: cls.organization_id == org, include_aliases=True))


# ---- new rows --------------------------------------------------------------------------------

@lru_cache(maxsize=None)
def _parents(cls) -> tuple[tuple[str, str | None, type], ...]:
    """(foreign key attribute, many-to-one relationship or None, parent class) for each
    reference to a tenant-owned row, organization_id itself excepted."""
    mapper = inspect(cls)
    by_table = {m.local_table.name: m.class_ for m in Base.registry.mappers}
    out = []
    for prop in mapper.column_attrs:
        col = prop.columns[0]
        if prop.key == KEY:
            continue
        for fk in col.foreign_keys:
            target = by_table.get(fk.column.table.name)
            if target is None or not (issubclass(target, OrgOwned) or target in THROUGH):
                continue
            rel = next((r.key for r in mapper.relationships if r.direction is RelationshipDirection.MANYTOONE
                        and set(r.local_columns) == {col}), None)
            out.append((prop.key, rel, target))
    return tuple(out)


def _tenant(cls) -> bool:
    return issubclass(cls, OrgOwned) or cls in THROUGH


def organization_of(session, obj) -> int | None:
    """The organization a row belongs to, new or stored."""
    if isinstance(obj, OrgOwned) and obj.organization_id is not None:
        return obj.organization_id
    found = _from_parents(session, obj)
    return next(iter(found)) if len(found) == 1 else None


def _from_parents(session, obj) -> set[int]:
    found = set()
    for fk, rel, target in _parents(type(obj)):
        parent = getattr(obj, rel) if rel and rel in obj.__dict__ else None
        if parent is None:
            ref = getattr(obj, fk)
            if ref is None:
                continue
            with unscoped(session):
                parent = session.get(target, ref)
            if parent is None:
                continue                # the database refuses the reference itself
        org = organization_of(session, parent)
        if org is not None:
            found.add(org)
    return found


def owner(session, *parents) -> int:
    """The organization for something about to be written that names these (class, id)
    parents (the chains, which need it before the row exists): the session's, which every
    parent must share, or the parents' own, or the default one."""
    found = set()
    for target, ref in parents:
        if ref is None:
            continue
        with unscoped(session):
            parent = session.get(target, ref)
        org = organization_of(session, parent) if parent is not None else None
        if org is not None:
            found.add(org)
    return _decide(session, found, "an entry")


def _decide(session, found: set[int], what: str) -> int:
    org = current(session)
    if session.info.get(KEY) == PENDING:
        raise TenancyError("a row was written before the caller's organization was known")
    if org is not None:
        found = found | {org}
    if len(found) > 1:
        raise TenancyError(f"{what} would join rows of different organizations")
    return found.pop() if found else default_id(session)


@event.listens_for(Session, "before_flush")
def _place(session, _ctx, _instances) -> None:
    for obj in list(session.new):
        if not _tenant(type(obj)):
            continue
        found = _from_parents(session, obj)
        if isinstance(obj, OrgOwned) and obj.organization_id is not None:
            found.add(obj.organization_id)
        org = _decide(session, found, f"a new {type(obj).__name__}")
        if isinstance(obj, OrgOwned):
            obj.organization_id = org
    for obj in list(session.dirty):
        if not _tenant(type(obj)) or not session.is_modified(obj):
            continue
        state = inspect(obj)
        keys = [fk for fk, _, _ in _parents(type(obj))] + ([KEY] if isinstance(obj, OrgOwned) else [])
        if not any(state.attrs[k].history.has_changes() for k in keys):
            continue
        found = _from_parents(session, obj)
        if isinstance(obj, OrgOwned):
            found.add(obj.organization_id)
        _decide(session, found, f"a changed {type(obj).__name__}")
