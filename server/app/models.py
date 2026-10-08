"""Ledger data model.

Evidence and receipts are append-only: the API exposes no update or delete for
them. A lane's status is never stored; it is computed from its items, evidence
and latest receipt (see gates.py).
"""
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
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
    assets: Mapped[list["Asset"]] = relationship(back_populates="engagement")


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
