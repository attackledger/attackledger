"""The API with a throwaway database, and the worker's channel to it (D-042).

The worker's client (app.workerclient) talks to the real API routes here, as it does through
the gateway's relay in the compose stack, so tests of the worker run every gate the API runs.
"""
import importlib.util
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "server"))
os.environ.setdefault("DATABASE_URL", "sqlite://")    # never a file next to the code

from app import db, workerclient  # noqa: E402
from app.models import Asset, ChecklistItem, Engagement, Job, Lane  # noqa: E402

WORKER_TOKEN = "worker-token-for-tests-000000000000"


def load_worker(name: str = "worker"):
    spec = importlib.util.spec_from_file_location(name, ROOT / "worker" / "worker.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Stack:
    def __init__(self, client, Session):
        self.api, self.Session = client, Session
        self.client = workerclient.Client("http://testserver", send=self._send)
        self.worker = workerclient.Worker(self.client, WORKER_TOKEN)

    def _send(self, method, path, headers, body):
        r = self.api.request(method, path, headers=headers, content=body)
        return r.status_code, r.content

    def claim(self, job_id: int | None = None) -> "workerclient.JobChannel | None":
        spec = self.worker.claim(job_id)
        return workerclient.JobChannel(self.client, spec) if spec else None

    def call(self, method, path, token, body=None):
        """A raw call with any token: (status, json)."""
        r = self.api.request(method, path, headers={"authorization": f"Bearer {token}"} if token else {},
                             json=body)
        return r.status_code, (r.json() if r.content else {})

    def job(self, job_id: int) -> Job:
        with self.Session() as s:
            return s.get(Job, job_id)

    def engagement(self, *, name="eng", include=("*.example.com",), exclude=(), header="X-Bug-Bounty: r1",
                   ua=None, rps=5, modules=(), authorized=True, redact=True) -> int:
        with self.Session() as s:
            e = Engagement(name=name, scope_include=list(include), scope_exclude=list(exclude), rate_limit_rps=rps,
                           research_header=header, research_user_agent=ua, enabled_modules=list(modules),
                           redact_evidence=redact, authorized_by="op" if authorized else None,
                           authorized_at=datetime.now(timezone.utc) if authorized else None)
            s.add(e)
            s.commit()
            return e.id

    def lane(self, eng_id: int, host: str, role: str = "recon", items: int = 3, executor: str = "manual") -> int:
        with self.Session() as s:
            a = s.query(Asset).filter_by(engagement_id=eng_id, host=host).first() or Asset(
                engagement_id=eng_id, host=host, in_scope=True)
            lane = Lane(asset=a, role=role, executor=executor)
            lane.items = [ChecklistItem(idx=n, item_key=f"R-{n}", text=f"check {n}", controls=[])
                          for n in range(1, items + 1)]
            s.add_all([a, lane])
            s.commit()
            return lane.id

    def queue(self, eng_id: int, kind: str, targets=(), **kw) -> int:
        with self.Session() as s:
            j = Job(engagement_id=eng_id, kind=kind, targets=list(targets), **kw)
            s.add(j)
            s.commit()
            return j.id


@pytest.fixture()
def stack(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    monkeypatch.setenv("ATTACKLEDGER_WORKER_TOKEN", WORKER_TOKEN)
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    db.Base.metadata.create_all(eng)
    Session = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

    def _session():
        s = Session()
        try:
            yield s
        finally:
            s.close()
    app.dependency_overrides[db.get_session] = _session
    with TestClient(app) as c:
        yield Stack(c, Session)
    app.dependency_overrides.clear()
