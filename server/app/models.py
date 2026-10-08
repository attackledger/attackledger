"""Ledger data model.

Evidence and receipts are append-only: the API exposes no update or delete for
them. A lane's status is never stored; it is computed from its items, evidence
and latest receipt (see gates.py).
"""
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import JSON, ForeignKey, String, Text, UniqueConstraint, false as sa_false
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ItemState(str, Enum):
    open = "open"
    done = "done"
    na = "na"


class Engagement(Base):
    __tablename__ = "engagements"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    # Methodology pack (packs/<id>.yaml) that defines this engagement's lanes and items.
    pack_id: Mapped[str] = mapped_column(String(64), default="bug-bounty")
    engagement_type: Mapped[str] = mapped_column(String(20), default="bug_bounty")
    policy_url: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    # Scope as written in the program policy. Empty include list = nothing in scope.
    scope_include: Mapped[list] = mapped_column(JSON, default=list)
    scope_exclude: Mapped[list] = mapped_column(JSON, default=list)
    # No job runs until an operator attests they are authorized to test this program.
    authorized_by: Mapped[str | None] = mapped_column(String(200))
    authorized_at: Mapped[datetime | None]
    rate_limit_rps: Mapped[int] = mapped_column(default=5)
    # Identification many programs require on test traffic, e.g.
    # "X-HackerOne-Research: <handle>" and/or a User-Agent containing the handle.
    research_header: Mapped[str | None] = mapped_column(String(300))
    research_user_agent: Mapped[str | None] = mapped_column(String(300))
    # Opt-in modules (see modules.py) the operator enabled because the program allows them.
    enabled_modules: Mapped[list] = mapped_column(JSON, default=list)
    crawl_depth: Mapped[int] = mapped_column(default=3, server_default="3")
    assets: Mapped[list["Asset"]] = relationship(back_populates="engagement")
    jobs: Mapped[list["Job"]] = relationship(back_populates="engagement", order_by="Job.id.desc()")


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("engagement_id", "host"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    host: Mapped[str] = mapped_column(String(255))
    in_scope: Mapped[bool] = mapped_column(default=True)
    engagement: Mapped[Engagement] = relationship(back_populates="assets")
    lanes: Mapped[list["Lane"]] = relationship(back_populates="asset")


class Lane(Base):
    __tablename__ = "lanes"
    __table_args__ = (UniqueConstraint("asset_id", "role"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    role: Mapped[str] = mapped_column(String(32))  # lane key from the engagement's pack
    executor: Mapped[str] = mapped_column(String(16), default="manual", server_default="manual")
    opened_at: Mapped[datetime] = mapped_column(default=utcnow)
    asset: Mapped[Asset] = relationship(back_populates="lanes")
    items: Mapped[list["ChecklistItem"]] = relationship(
        back_populates="lane", order_by="ChecklistItem.idx"
    )
    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="lane", order_by="Evidence.id"
    )
    receipts: Mapped[list["Receipt"]] = relationship(
        back_populates="lane", order_by="Receipt.id"
    )


class ChecklistItem(Base):
    __tablename__ = "checklist_items"
    id: Mapped[int] = mapped_column(primary_key=True)
    lane_id: Mapped[int] = mapped_column(ForeignKey("lanes.id"))
    idx: Mapped[int]
    item_key: Mapped[str] = mapped_column(String(64))  # e.g. WSTG-ATHZ-04
    text: Mapped[str] = mapped_column(Text)
    controls: Mapped[list] = mapped_column(JSON, default=list)
    state: Mapped[ItemState] = mapped_column(default=ItemState.open)
    na_reason: Mapped[str | None] = mapped_column(Text)
    lane: Mapped[Lane] = relationship(back_populates="items")


class Evidence(Base):
    """Append-only. Linked into a per-engagement hash chain (see ledger.py)."""
    __tablename__ = "evidence"
    __table_args__ = (UniqueConstraint("engagement_id", "seq"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    seq: Mapped[int]
    prev_hash: Mapped[str] = mapped_column(String(64))
    chain_hash: Mapped[str] = mapped_column(String(64))
    lane_id: Mapped[int] = mapped_column(ForeignKey("lanes.id"))
    item_id: Mapped[int | None] = mapped_column(ForeignKey("checklist_items.id"))
    kind: Mapped[str] = mapped_column(String(40))  # request, response, file, note
    sha256: Mapped[str] = mapped_column(String(64))
    uri: Mapped[str | None] = mapped_column(String(1000))
    summary: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    lane: Mapped[Lane] = relationship(back_populates="evidence")


class Receipt(Base):
    __tablename__ = "receipts"
    id: Mapped[int] = mapped_column(primary_key=True)
    lane_id: Mapped[int] = mapped_column(ForeignKey("lanes.id"))
    manifest_sha256: Mapped[str] = mapped_column(String(64))
    # The person who reviewed the lane and closed it. Executors never issue receipts (D-018).
    closed_by: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    lane: Mapped[Lane] = relationship(back_populates="receipts")


class JobStatus(str, Enum):
    queued = "queued"
    running = "running"
    done = "done"
    failed = "failed"
    cancelled = "cancelled"
    partial = "partial"   # stopped at the time limit; remaining_targets lists what was not run


class Job(Base):
    """A tool run requested from the UI and executed by the worker."""
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    kind: Mapped[str] = mapped_column(String(40))
    targets: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[JobStatus] = mapped_column(default=JobStatus.queued)
    log: Mapped[str] = mapped_column(Text, default="")
    result_count: Mapped[int] = mapped_column(default=0)
    output_sha256: Mapped[str | None] = mapped_column(String(64))
    # Targets run in batches; a batch counts only when it finished. Anything not
    # finished is listed in remaining_targets, so a stopped job never looks complete.
    # A deferred job (pipeline run) resolves its targets when it starts, from the
    # output of the steps queued before it.
    deferred: Mapped[bool] = mapped_column(default=False, server_default=sa_false())
    targets_done: Mapped[int] = mapped_column(default=0, server_default="0")
    remaining_targets: Mapped[list | None] = mapped_column(JSON)
    # An agent run (kind "agent") works one lane; result holds its limits, outcome and token use.
    lane_id: Mapped[int | None] = mapped_column(ForeignKey("lanes.id"))
    result: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    engagement: Mapped[Engagement] = relationship(back_populates="jobs")


class Observation(Base):
    """What a recon job saw about a host (one row per host per job)."""
    __tablename__ = "observations"
    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"))
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    host: Mapped[str] = mapped_column(String(255))
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class Endpoint(Base):
    """A URL seen by a crawl or an archive source. Only in-scope hosts are stored."""
    __tablename__ = "endpoints"
    # Unique on a hash: archive URLs can exceed the size of a btree index entry.
    __table_args__ = (UniqueConstraint("engagement_id", "url_sha256"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"))
    host: Mapped[str] = mapped_column(String(255))
    url: Mapped[str] = mapped_column(Text)
    url_sha256: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(32))  # katana, gau, wayback
    is_js: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class Lead(Base):
    """Something recon noticed that a hunt lane should look at (secret candidate,
    GraphQL operation, sourcemap). Secrets are stored masked and hashed only."""
    __tablename__ = "leads"
    __table_args__ = (UniqueConstraint("engagement_id", "fingerprint"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"))
    host: Mapped[str] = mapped_column(String(255))
    source_url: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(32))       # secret, graphql, sourcemap
    title: Mapped[str] = mapped_column(String(300))
    bucket: Mapped[str] = mapped_column(String(16), default="")   # real, public (secrets)
    severity: Mapped[str] = mapped_column(String(16), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    fingerprint: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
