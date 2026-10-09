"""Organizations from the command line, for a hosted service later (D-042, docs/ORGANIZATIONS.md).

A self-hosted install is one organization, made by migration 0022, and needs none of this.
There is no organization administration in the product and no one above the owners: whoever
runs the server makes organizations here, and gives each its first owner with
python -m app.people create --org.

  docker compose exec api python -m app.orgs list
  docker compose exec api python -m app.orgs create --name "Example Bank"
  docker compose exec api python -m app.orgs worker-token --org "Example Bank"
  docker compose exec api python -m app.orgs gateway-token --org "Example Bank"

The deployment's own worker and gateway tokens (the token files, WORKER_API.md and GATEWAY.md)
belong to the default organization. Another organization's worker and gateway, which would run
in that customer's network, use a token made here: it claims only that organization's jobs and
answers only for them. The token is printed once; only its SHA-256 is kept, and making a new
one replaces it.
"""
import argparse
import hashlib
import hmac
import secrets
import sys

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from . import orgscope
from .models import Organization


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _by_token(session, column, token: str) -> int | None:
    if not token:
        return None
    with orgscope.unscoped(session):
        return session.scalar(select(Organization.id).where(column == _sha(token)))


def channel_org(session, kind: str, deployment_token: str | None, presented: str) -> int | None:
    """The organization a worker or gateway token opens (kind "worker" or "gateway"), or None.
    The deployment's token opens the default organization; an issued one, its own."""
    if deployment_token and presented and hmac.compare_digest(presented, deployment_token):
        return orgscope.default_id(session)
    column = Organization.worker_token_sha256 if kind == "worker" else Organization.gateway_token_sha256
    return _by_token(session, column, presented)


def channel_configured(session, kind: str, deployment_token: str | None) -> bool:
    """Whether any token could open this channel; without one the routes stay closed (503)."""
    if deployment_token:
        return True
    column = Organization.worker_token_sha256 if kind == "worker" else Organization.gateway_token_sha256
    with orgscope.unscoped(session):
        return session.scalar(select(Organization.id).where(column.is_not(None)).limit(1)) is not None


def visible(session, organization_id: int) -> dict | None:
    """What the web app shows of the caller's organization: nothing while the deployment has
    only one, so a self-hosted install looks exactly as before."""
    if orgscope.count(session) <= 1:
        return None
    with orgscope.unscoped(session):
        org = session.get(Organization, organization_id)
    return {"id": org.id, "name": org.name} if org else None


# ---- command line ---------------------------------------------------------------------------

def find(s, ref: str | None) -> Organization | None:
    """An organization by id or exact name; the default one when none is named."""
    if ref is None:
        return s.get(Organization, orgscope.default_id(s))
    org = s.get(Organization, int(ref)) if ref.isdigit() else None
    return org or s.scalar(select(Organization).where(Organization.name == ref))


def _list(s, _args) -> int:
    default = orgscope.default_id(s)
    for org in s.scalars(select(Organization).order_by(Organization.id)):
        flags = [w for w, on in (("default", org.id == default), ("own worker token", org.worker_token_sha256),
                                 ("own gateway token", org.gateway_token_sha256)) if on]
        print(f"{org.id:>4}  {org.name}" + (f"  ({', '.join(flags)})" if flags else ""))
    return 0


def _create(s, args) -> int:
    name = args.name.strip()
    if not name:
        print("give the organization a name", file=sys.stderr)
        return 2
    org = Organization(name=name)
    s.add(org)
    try:
        s.commit()
    except IntegrityError:
        print(f"an organization named {name!r} exists already", file=sys.stderr)
        return 1
    print(f"created organization {org.id} ({org.name}). Give it its first owner with "
          f"python -m app.people create --org {org.id} --owner --email ... --name ...")
    return 0


def _token(s, args) -> int:
    org = find(s, args.org)
    if org is None:
        print(f"no organization {args.org!r}", file=sys.stderr)
        return 1
    value = secrets.token_urlsafe(32)
    if args.cmd == "worker-token":
        org.worker_token_sha256 = _sha(value)
        where = "ATTACKLEDGER_WORKER_TOKEN on that organization's worker"
    else:
        org.gateway_token_sha256 = _sha(value)
        where = "ATTACKLEDGER_GATEWAY_TOKEN on that organization's gateway"
    s.commit()
    print(value)
    print(f"the {args.cmd} of organization {org.id} ({org.name}); set it as {where}. "
          "It is shown once; a new one replaces it.", file=sys.stderr)
    return 0


def main(argv: list[str]) -> int:
    from .db import SessionLocal
    ap = argparse.ArgumentParser(prog="python -m app.orgs")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list the organizations")
    c = sub.add_parser("create", help="add an organization (for a hosted service)")
    c.add_argument("--name", required=True)
    for cmd in ("worker-token", "gateway-token"):
        t = sub.add_parser(cmd, help=f"issue the {cmd.split('-')[0]} token of one organization (replaces the last)")
        t.add_argument("--org", required=True, help="the organization's id or exact name")
    args = ap.parse_args(argv)
    run = {"list": _list, "create": _create, "worker-token": _token, "gateway-token": _token}[args.cmd]
    with SessionLocal() as s:
        return run(s, args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
