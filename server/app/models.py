"""Ledger data model.

Evidence and receipts are append-only: the API exposes no update or delete for
them. A lane's status is never stored; it is computed from its items, evidence
and latest receipt (see gates.py).
"""
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import JSON, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Role(str, Enum):
    recon = "recon"
    mapper = "mapper"
    authz = "authz"
    authflow = "authflow"
    logic = "logic"
    injection = "injection"
    mobile = "mobile"


# Roles that need a closed mapper lane (an application model) on the same asset.
MODEL_GATED_ROLES = {Role.authz, Role.authflow, Role.logic, Role.injection}


class ItemState(str, Enum):
    open = "open"
    done = "done"
    na = "na"


class Engagement(Base):
    __tablename__ = "engagements"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
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
    role: Mapped[Role]
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
    text: Mapped[str] = mapped_column(Text)
    state: Mapped[ItemState] = mapped_column(default=ItemState.open)
    na_reason: Mapped[str | None] = mapped_column(Text)
    lane: Mapped[Lane] = relationship(back_populates="items")


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(primary_key=True)
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
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    lane: Mapped[Lane] = relationship(back_populates="receipts")


class JobStatus(str, Enum):
    queued = "queued"
    running = "running"
    done = "done"
    failed = "failed"
    cancelled = "cancelled"


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
