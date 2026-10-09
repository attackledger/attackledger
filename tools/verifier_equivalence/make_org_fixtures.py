#!/usr/bin/env python3
"""Make the organization fixtures for the verifier equivalence tests (D-042, docs/ORGANIZATIONS.md).

The report format did not change with organizations; these show it, on reports from both
sides of migration 0022 and from a second organization:

  org-before-0022.json      the report the 0.7.1 API issued at migration 0021
                            (server/tests/data/org-migration/report.json)
  org-after-0022.json       the same engagement's report after the upgrade, from the same database
  org-second.json           a report of a second organization, whose key log and audit log are
                            chains of their own, from seq 1, beside the default organization's
  org-second-foreign-head.json
                            that report with the default organization's audit log head put in:
                            another organization's head does not fit the chain, and fails

It runs in the API image, as make_fixtures.py does:

    docker run --rm --user 1000:1000 -e HOME=/tmp -v "$PWD":/w -w /w/server \\
      --entrypoint python attackledger-api:latest /w/tools/verifier_equivalence/make_org_fixtures.py

Everything is fictional (example.com hosts, made-up people). Writes into fixtures/.
"""
import copy
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUT = HERE / "fixtures"
FIXTURE = ROOT / "server" / "tests" / "data" / "org-migration"
WORK = Path(tempfile.mkdtemp(prefix="al-org-fixtures-"))
os.environ.update(DATABASE_URL=f"sqlite:///{WORK / 'upgraded.db'}", ATTACKLEDGER_DEV_KEY="1",
                  ATTACKLEDGER_BLOBS=str(WORK / "blobs"), ATTACKLEDGER_MAINTENANCE_SECONDS="0",
                  ATTACKLEDGER_WORKER_TOKEN="worker-token-for-org-fixtures-00000",
                  ATTACKLEDGER_GATEWAY_TOKEN="gateway-token-for-org-fixtures-0000")
os.environ.pop("ATTACKLEDGER_API_TOKEN", None)
os.environ.pop("ATTACKLEDGER_TSA_URL", None)
sys.path[:0] = [str(ROOT / "server"), str(ROOT / "server" / "tests")]

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

import orgfill  # noqa: E402
from app import auth, db, migrate, people  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Organization  # noqa: E402


def client_on(Session) -> TestClient:
    def _session():
        s = Session()
        try:
            yield s
        finally:
            s.close()
    app.dependency_overrides[db.get_session] = _session
    people.SessionLocal = Session
    auth._failures.clear()
    return TestClient(app)


def write(name: str, report: dict) -> None:
    (OUT / name).write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(f"wrote {name}")


def after_upgrade() -> None:
    """The 0021 fixture database, upgraded to 0022, and its engagement's report again."""
    con = sqlite3.connect(WORK / "upgraded.db")
    con.executescript((FIXTURE / "fixture.sql").read_text())
    con.close()
    shutil.copytree(FIXTURE / "blobs", WORK / "blobs")
    migrate.upgrade_head()
    ids = json.loads((FIXTURE / "ids.json").read_text())
    c = client_on(sessionmaker(bind=db.engine, autoflush=False, expire_on_commit=False))
    orgfill.sign_in(c, ids["owner_email"])
    write("org-before-0022.json", json.loads((FIXTURE / "report.json").read_text()))
    write("org-after-0022.json", orgfill._ok(c.get(f"/engagements/{ids['eng']}/report")))


def second_organization() -> None:
    os.environ["ATTACKLEDGER_BLOBS"] = str(WORK / "blobs-two")
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    db.Base.metadata.create_all(eng)
    Session = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
    c = client_on(Session)
    w, g = os.environ["ATTACKLEDGER_WORKER_TOKEN"], os.environ["ATTACKLEDGER_GATEWAY_TOKEN"]
    orgfill._ok(c.post("/people", json={"email": "owner-one@example.com", "name": "Olive One", "password": orgfill.PW,
                                        "is_owner": True}))
    orgfill.sign_in(c, "owner-one@example.com")
    one = orgfill.fill(c, tag="one", owner_email="owner-one@example.com", worker_token=w, gateway_token=g)
    w2, g2 = "worker-token-of-the-second-org-0000", "gateway-token-of-the-second-org-000"
    with Session() as s:
        s.add(Organization(name="Second organization", worker_token_sha256=hashlib.sha256(w2.encode()).hexdigest(),
                           gateway_token_sha256=hashlib.sha256(g2.encode()).hexdigest()))
        s.commit()
        two_id = s.query(Organization).filter_by(name="Second organization").one().id
    os.environ["ATTACKLEDGER_NEW_PASSWORD"] = orgfill.PW
    assert people.main(["create", "--org", str(two_id), "--owner", "--email", "owner-two@example.com",
                        "--name", "Olive Two"]) == 0
    c2 = TestClient(app)
    orgfill.sign_in(c2, "owner-two@example.com")
    two = orgfill.fill(c2, tag="two", owner_email="owner-two@example.com", worker_token=w2, gateway_token=g2)
    r1 = orgfill._ok(c.get(f"/engagements/{one['eng']}/report"))
    r2 = orgfill._ok(c2.get(f"/engagements/{two['eng']}/report"))
    # Its own chains: one key registered in it, and an audit log that does not continue org 1's.
    assert r2["key_log"]["head"]["seq"] == 1 and r2["key_log"]["links"][0]["prev_hash"] == "0" * 64
    assert r2["audit_log"]["head"] != r1["audit_log"]["head"]
    write("org-second.json", r2)
    bad = copy.deepcopy(r2)
    bad["audit_log"]["head"] = r1["audit_log"]["head"]
    body = {k: v for k, v in bad.items() if k != "integrity"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    bad["integrity"]["body_sha256"] = hashlib.sha256(canonical.encode()).hexdigest()   # only the head is wrong
    write("org-second-foreign-head.json", bad)


if __name__ == "__main__":
    after_upgrade()
    second_organization()
    shutil.rmtree(WORK, ignore_errors=True)
