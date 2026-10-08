"""Append-only evidence chain.

Every evidence row in an engagement is linked to the previous one:

    chain_hash = sha256(prev_hash + canonical(record))

Removing, reordering or editing a row breaks every hash after it, so a report
built from the ledger can be verified offline (tools/verify_report.py).
"""
import hashlib
import json

from sqlalchemy import func, select

from .models import Engagement, Evidence, Lane

GENESIS = "0" * 64


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def evidence_record(ev: Evidence, host: str, role: str) -> dict:
    """The fields that the chain commits to. The verifier rebuilds exactly this."""
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


def append_evidence(session, lane: Lane, *, kind: str, sha256_hex: str, summary: str,
                    uri: str | None = None, item_id: int | None = None) -> Evidence:
    eng_id = lane.asset.engagement_id
    # Serialize appends per engagement so two writers cannot fork the chain.
    lock = select(Engagement).where(Engagement.id == eng_id)
    if session.bind.dialect.name == "postgresql":
        lock = lock.with_for_update()
    session.execute(lock)

    last = session.scalars(
        select(Evidence).where(Evidence.engagement_id == eng_id).order_by(Evidence.seq.desc()).limit(1)
    ).first()
    seq = (last.seq + 1) if last else 1
    prev = last.chain_hash if last else GENESIS

    ev = Evidence(engagement_id=eng_id, lane_id=lane.id, item_id=item_id, kind=kind,
                  sha256=sha256_hex, uri=uri, summary=summary, seq=seq, prev_hash=prev)
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
        rec = {k: r[k] for k in ("seq", "lane_id", "host", "role", "item_id", "kind", "sha256", "uri", "summary")}
        if chain_hash(r["prev_hash"], rec) != r["chain_hash"]:
            problems.append(f"evidence {r['seq']}: content does not match its chain hash")
        prev = r["chain_hash"]
    return problems


def chain_head(session, eng_id: int) -> tuple[int, str]:
    n = session.scalar(select(func.count()).select_from(Evidence).where(Evidence.engagement_id == eng_id))
    last = session.scalars(
        select(Evidence).where(Evidence.engagement_id == eng_id).order_by(Evidence.seq.desc()).limit(1)
    ).first()
    return n or 0, (last.chain_hash if last else GENESIS)
