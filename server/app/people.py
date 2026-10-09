"""Create a person from the command line, for example the first owner.

  docker compose exec -it api python -m app.people create --email you@example.com --name "Your Name" --owner

The password is read from the terminal (not echoed) or, for scripts, from the
ATTACKLEDGER_NEW_PASSWORD environment variable. It is never taken as an argument,
so it does not end up in shell history or process lists.
"""
import argparse
import getpass
import os
import sys

from sqlalchemy.exc import IntegrityError

from . import auth
from .db import SessionLocal
from .models import User


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.people")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create", help="add a person")
    c.add_argument("--email", required=True)
    c.add_argument("--name", required=True)
    c.add_argument("--owner", action="store_true")
    args = ap.parse_args(argv)

    with SessionLocal() as s:
        if not auth.people_exist(s) and not args.owner:
            print("the first person must be an owner (--owner)", file=sys.stderr)
            return 2
        try:
            password = os.environ.get("ATTACKLEDGER_NEW_PASSWORD") or getpass.getpass("Password: ")
        except EOFError:
            print("no password given: run it in a terminal (-it) or set ATTACKLEDGER_NEW_PASSWORD",
                  file=sys.stderr)
            return 2
        why = auth.check_password_rules(password)
        if why:
            print(f"password: {why}", file=sys.stderr)
            return 2
        s.add(User(email=args.email.strip().lower(), name=args.name.strip(),
                   password_hash=auth.hash_password(password), is_owner=args.owner))
        try:
            s.commit()
        except IntegrityError:
            print("someone with that email already exists", file=sys.stderr)
            return 1
    print(f"created {args.email}{' (owner)' if args.owner else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
