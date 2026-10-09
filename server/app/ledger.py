"""Append-only evidence chain.

Every evidence row in an engagement is linked to the previous one:

    chain_hash = sha256(prev_hash + canonical(record))

Removing, reordering or editing a row breaks every hash after it, so a report
built from the ledger can be verified offline (tools/verify_report.py).

Two record versions share one chain. Rows written before migration 0018 keep v1, which
commits to the summary text. New rows are v2, which commits to the summary's sha256
instead, so the summary can be encrypted with the engagement's key and become unreadable
when that key is deleted while the chain still verifies (D-043, docs/ENCRYPTION.md).
"""
import hashlib
import json
import re

from sqlalchemy import func, select

from . import vault
from .models import Engagement, Evidence, Lane

GENESIS = "0" * 64
V1_FIELDS = ("seq", "lane_id", "host", "role", "item_id", "kind", "sha256", "uri", "summary")
V2_FIELDS = ("v", "seq", "lane_id", "host", "role", "item_id", "kind", "sha256", "uri", "summary_sha256", "source")
SOURCES = ("manual", "recon", "agent")
_IMPORT = re.compile(r"^import:[a-z0-9][a-z0-9_-]{0,30}$")


def check_source(source: str) -> str:
    if source in SOURCES or _IMPORT.match(source or ""):
        return source
    raise ValueError(f"unknown evidence source {source!r}")


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def evidence_record(ev: Evidence, host: str, role: str) -> dict:
    """The fields that the chain commits to. The verifier rebuilds exactly this."""
    if ev.record_version == 2:
        return {"v": 2, "seq": ev.seq, "lane_id": ev.lane_id, "host": host, "role": role, "item_id": ev.item_id,
                "kind": ev.kind, "sha256": ev.sha256, "uri": ev.uri, "summary_sha256": ev.summary_sha256,
                "source": ev.source}
    return {
        "seq": ev.seq,
        "lane_id": ev.lane_id,
        "host": host,
        "role": role,
        "item_id": ev.item_id,
        "kind": ev.kind,
        "sha256": ev.sha256,
        "uri": ev.uri,
        "summary": ev.summary,
    }


def chain_hash(prev_hash: str, record: dict) -> str:
    return sha256(prev_hash + canonical(record))


def append_evidence(session, lane: Lane, *, kind: str, sha256_hex: str, summary: str, source: str,
                    uri: str | None = None, item_id: int | None = None,
                    created_by: int | None = None, redaction: dict | None = None) -> Evidence:
    """Append a v2 row. The summary is stored encrypted with the engagement's key; the chain
    commits to its hash. Raises vault.ContentDeleted once the engagement's content was deleted."""
    check_source(source)
    eng_id = lane.asset.engagement_id
    # Serialize appends per engagement so two writers cannot fork the chain.
    lock = select(Engagement).where(Engagement.id == eng_id)
    if session.bind.dialect.name == "postgresql":
        lock = lock.with_for_update()
    session.execute(lock)
    eng = session.get(Engagement, eng_id)
    session.refresh(eng, ["content_deleted_at", "content_deleted_by", "content_deleted_reason"])
    vault.check_writable(eng)
    summary_sha256 = sha256(summary)

    last = session.scalars(
        select(Evidence).where(Evidence.engagement_id == eng_id).order_by(Evidence.seq.desc()).limit(1)
    ).first()
    seq = (last.seq + 1) if last else 1
    prev = last.chain_hash if last else GENESIS

    ev = Evidence(engagement_id=eng_id, lane_id=lane.id, item_id=item_id, kind=kind,
                  sha256=sha256_hex, uri=uri, summary=None, record_version=2, summary_sha256=summary_sha256,
                  summary_enc=vault.seal_summary(eng_id, summary, summary_sha256), source=source,
                  seq=seq, prev_hash=prev, created_by=created_by, redaction=redaction)
    ev.chain_hash = chain_hash(prev, evidence_record(ev, lane.asset.host, lane.role))
    session.add(ev)
    session.flush()
    return ev


def verify_chain(rows: list[dict]) -> list[str]:
    """rows: evidence records in seq order, each with prev_hash/chain_hash."""
    problems, prev = [], GENESIS
    for n, r in enumerate(rows, start=1):
        if r["seq"] != n:
            problems.append(f"evidence seq {r['seq']} out of order (expected {n})")
        if r["prev_hash"] != prev:
            problems.append(f"evidence {r['seq']}: link to previous entry is broken")
        v2 = r.get("v") == 2
        rec = {k: r.get(k) for k in (V2_FIELDS if v2 else V1_FIELDS)}
        if chain_hash(r["prev_hash"], rec) != r["chain_hash"]:
            problems.append(f"evidence {r['seq']}: content does not match its chain hash")
        if v2 and r.get("summary") is not None and sha256(r["summary"]) != r.get("summary_sha256"):
            problems.append(f"evidence {r['seq']}: summary does not match its summary_sha256")
        prev = r["chain_hash"]
    return problems


def chain_head(session, eng_id: int) -> tuple[int, str]:
    n = session.scalar(select(func.count()).select_from(Evidence).where(Evidence.engagement_id == eng_id))
    last = session.scalars(
        select(Evidence).where(Evidence.engagement_id == eng_id).order_by(Evidence.seq.desc()).limit(1)
    ).first()
    return n or 0, (last.chain_hash if last else GENESIS)
