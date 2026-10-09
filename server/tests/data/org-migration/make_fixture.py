"""Make the migration-0022 fixture: a database at migration 0021, filled through the 0.7.1 API.

Run it with the code at migration 0021 (commit ac64591, the parent of the organization
change), from server/:

    DATABASE_URL=sqlite:////tmp/al-0021.db python tests/data/org-migration/make_fixture.py OUT

It writes OUT/fixture.sql (SQLite only: the database as SQL), OUT/blobs/ (the engagement's
key, wrapped with the public development key, and its encrypted blobs) and OUT/report.json
(the report the API issued at 0021). With a Postgres DATABASE_URL it fills that database
and writes the report and the blobs only; test_organizations.py and the upgrade check in
docs/ORGANIZATIONS.md then work on that database.
"""
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

OUT = Path(sys.argv[1]).resolve()
HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[3]))           # server/
sys.path.insert(0, str(HERE.parents[2]))           # server/tests/
blobs = Path(tempfile.mkdtemp(prefix="al-fixture-"))
os.environ.update(ATTACKLEDGER_BLOBS=str(blobs), ATTACKLEDGER_DEV_KEY="1", ATTACKLEDGER_MAINTENANCE_SECONDS="0",
                  ATTACKLEDGER_WORKER_TOKEN="worker-token-for-the-fixture-0000000",
                  ATTACKLEDGER_GATEWAY_TOKEN="gateway-token-for-the-fixture-000000",
                  ATTACKLEDGER_GATEWAY="gateway.invalid:8080", ATTACKLEDGER_GATEWAY_DNS="gateway.invalid:53")
os.environ.pop("ATTACKLEDGER_TSA_URL", None)
ca = blobs.parent / f"{blobs.name}-ca.pem"
ca.write_text("test CA\n")
os.environ["ATTACKLEDGER_GATEWAY_CA"] = str(ca)

from fastapi.testclient import TestClient  # noqa: E402

import orgfill  # noqa: E402
from app import db, migrate  # noqa: E402
from app.main import app  # noqa: E402

assert migrate.head() == "0021", f"run this with the code at migration 0021, not {migrate.head()}"
OUT.mkdir(parents=True, exist_ok=True)
with TestClient(app) as c:
    orgfill_owner = "owner-alpha@example.com"
    orgfill._ok(c.post("/people", json={"email": orgfill_owner, "name": "Olive alpha", "password": orgfill.PW,
                                        "is_owner": True}))
    orgfill.sign_in(c, orgfill_owner)
    ids = orgfill.fill(c, tag="alpha", owner_email=orgfill_owner, worker_token=os.environ["ATTACKLEDGER_WORKER_TOKEN"],
                       gateway_token=os.environ["ATTACKLEDGER_GATEWAY_TOKEN"])
    report = orgfill._ok(c.get(f"/engagements/{ids['eng']}/report"))
(OUT / "report.json").write_text(json.dumps(report, indent=1, sort_keys=True))
(OUT / "ids.json").write_text(json.dumps({k: v for k, v in ids.items() if "token" not in k and "secret" not in k},
                                          indent=1, sort_keys=True))
shutil.rmtree(OUT / "blobs", ignore_errors=True)
shutil.copytree(blobs, OUT / "blobs")
if db.engine.dialect.name == "sqlite":
    con = sqlite3.connect(db.engine.url.database)
    (OUT / "fixture.sql").write_text("\n".join(con.iterdump()) + "\n")
    con.close()
print(f"wrote {OUT}")
