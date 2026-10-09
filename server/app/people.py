"""People from the command line: the first owner, password resets, key revocation.

  docker compose exec -it api python -m app.people create --email you@example.com --name "Your Name" --owner
  docker compose exec -it api python -m app.people set-password --email someone@example.com
  docker compose exec -it api python -m app.people revoke-key --email someone@example.com --fingerprint 6d50ab12
  docker compose exec -it api python -m app.people key-log
  docker compose exec -it api python -m app.people audit-log

A self-hosted install has one organization and never names it. With more than one (made with
python -m app.orgs), --org names the organization a person is created in, and the one meant
when an email has an account in more than one; the logs are listed and checked per organization.

The password is read from the terminal (not echoed) or, for scripts, from the
ATTACKLEDGER_NEW_PASSWORD environment variable. It is never taken as an argument,
so it does not end up in shell history or process lists.

A reset is for a forgotten password, and only here: through the API, nobody sets another
person's password. It signs the person out everywhere. Whoever runs the server can do
more than this (it is the root of trust); what they cannot do is forge a signature, and a
key they register for someone shows in the key log, to that person and in reports. Adding a
person and resetting a password here are entries in the audit log, made by "the operator on
the server"; the password itself is never recorded.
"""
import argparse
import getpass
import os
import sys

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from . import auditlog, auth, keylog, orgs, orgscope
from .db import SessionLocal
from .models import AuditEntry, KeyLogEntry, SigningKey, User, utcnow


def _password() -> str | None:
    try:
        password = os.environ.get("ATTACKLEDGER_NEW_PASSWORD") or getpass.getpass("Password: ")
    except EOFError:
        print("no password given: run it in a terminal (-it) or set ATTACKLEDGER_NEW_PASSWORD",
              file=sys.stderr)
        return None
    why = auth.check_password_rules(password)
    if why:
        print(f"password: {why}", file=sys.stderr)
        return None
    return password


def _user(s, email: str, org_ref: str | None = None) -> User | None:
    q = select(User).where(User.email == email.strip().lower())
    if org_ref is not None:
        org = orgs.find(s, org_ref)
        if org is None:
            print(f"no organization {org_ref!r}", file=sys.stderr)
            return None
        q = q.where(User.organization_id == org.id)
    users = s.scalars(q).all()
    if not users:
        print(f"nobody with the email {email}", file=sys.stderr)
        return None
    if len(users) > 1:
        print(f"{email} has an account in organizations {', '.join(str(u.organization_id) for u in users)}; "
              "name one with --org", file=sys.stderr)
        return None
    return users[0]


def create(s, args) -> int:
    org = orgs.find(s, args.org)
    if org is None:
        print(f"no organization {args.org!r}", file=sys.stderr)
        return 1
    if not s.scalar(select(User.id).where(User.organization_id == org.id).limit(1)) and not args.owner:
        print("the first person must be an owner (--owner)", file=sys.stderr)
        return 2
    password = _password()
    if password is None:
        return 2
    user = User(organization_id=org.id, email=args.email.strip().lower(), name=args.name.strip(),
                password_hash=auth.hash_password(password), is_owner=args.owner)
    s.add(user)
    try:
        s.flush()
    except IntegrityError:
        print("someone with that email already exists", file=sys.stderr)
        return 1
    auditlog.append(s, actor=auditlog.CLI, action="person.created", subject_id=user.id,
                    change={"person": auditlog.person_ref(user), "after": auditlog.person_snapshot(user),
                            "password": "assigned"})
    s.commit()
    print(f"created {args.email}{' (owner)' if args.owner else ''}")
    return 0


def set_password(s, args) -> int:
    user = _user(s, args.email, args.org)
    if user is None:
        return 1
    password = _password()
    if password is None:
        return 2
    # You know this password too, so it is not the person's own until they change it.
    user.password_hash, user.password_chosen = auth.hash_password(password), False
    auth.end_sessions(s, user.id)
    auditlog.append(s, actor=auditlog.CLI, action="person.password_reset", subject_id=user.id,
                    change={"person": auditlog.person_ref(user), "password": "assigned", "sessions_ended": True})
    s.commit()
    print(f"password reset for {user.email}; they are signed out everywhere. "
          "Ask them to choose their own password after signing in.")
    return 0


def revoke_key(s, args) -> int:
    user = _user(s, args.email, args.org)
    if user is None:
        return 1
    fp = args.fingerprint.strip().lower()
    keys = [k for k in s.scalars(select(SigningKey).where(SigningKey.user_id == user.id))
            if k.fingerprint.startswith(fp)]
    if len(fp) < 8 or len(keys) != 1:
        print("give at least 8 characters of a fingerprint that matches exactly one of their keys",
              file=sys.stderr)
        return 1
    key = keys[0]
    if key.revoked_at is not None:
        print(f"key {key.fingerprint[:16]} was already revoked")
        return 0
    key.revoked_at = utcnow()
    keylog.append(s, user=user, key=key, event="revoked", via="operator_cli")
    s.commit()
    print(f"revoked key {key.fingerprint[:16]} of {user.email}")
    return 0


def _org_label(s, e) -> str:
    """Each organization has its own chains; the column appears once there is more than one."""
    return f"org {e.organization_id}  " if orgscope.count(s) > 1 else ""


def key_log(s, _args) -> int:
    for e in s.scalars(select(KeyLogEntry).order_by(KeyLogEntry.organization_id, KeyLogEntry.seq)):
        print(f"{_org_label(s, e)}{e.seq:>5}  {e.at}  {e.event:<10} {e.key_fingerprint[:16]}  {e.algorithm:<10} "
              f"{e.user_name} (id {e.user_id}), {keylog.VIA.get(e.via, e.via)}")
    problems = keylog.verify(s)
    for p in problems:
        print(f"FAIL  {p}", file=sys.stderr)
    print("key log chain: " + ("broken" if problems else "intact"))
    return 1 if problems else 0


def audit_log(s, _args) -> int:
    for e in s.scalars(select(AuditEntry).order_by(AuditEntry.organization_id, AuditEntry.seq)):
        rec = auditlog.record(e)
        where = f"engagement {e.engagement_id}  " if e.engagement_id is not None else ""
        print(f"{_org_label(s, e)}{e.seq:>5}  {e.at}  {e.action:<24} {where}{auditlog.actor_label(rec['actor'])}: {auditlog.describe(rec)}")
    problems = auditlog.verify(s)
    for p in problems:
        print(f"FAIL  {p}", file=sys.stderr)
    print("audit log chain: " + ("broken" if problems else "intact"))
    return 1 if problems else 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.people")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create", help="add a person")
    c.add_argument("--email", required=True)
    c.add_argument("--name", required=True)
    c.add_argument("--owner", action="store_true")
    c.add_argument("--org", help="the organization's id or exact name (default: the default organization)")
    p = sub.add_parser("set-password", help="reset a forgotten password and sign the person out")
    p.add_argument("--email", required=True)
    p.add_argument("--org", help="the organization, when the email has an account in more than one")
    r = sub.add_parser("revoke-key", help="revoke one of a person's signing keys")
    r.add_argument("--email", required=True)
    r.add_argument("--org", help="the organization, when the email has an account in more than one")
    r.add_argument("--fingerprint", required=True, help="the fingerprint or its first 8+ characters")
    sub.add_parser("key-log", help="list every key registration and revocation and check the chain")
    sub.add_parser("audit-log", help="list every administrative change and check the chain")
    args = ap.parse_args(argv)
    run = {"create": create, "set-password": set_password, "revoke-key": revoke_key, "key-log": key_log,
           "audit-log": audit_log}[args.cmd]
    with SessionLocal() as s:
        return run(s, args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
