"""Ledger data model.

Evidence and receipts are append-only: the API exposes no update or delete for
them. A lane's status is never stored; it is computed from its items, evidence
and latest receipt (see gates.py).
"""
from datetime import date, datetime, timezone
from enum import Enum

from sqlalchemy import DDL, JSON, ForeignKey, String, Text, UniqueConstraint, event, false as sa_false, true as sa_true
from sqlalchemy.orm import Mapped, declared_attr, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(dt: datetime | None) -> str | None:
    """ISO 8601 with the offset. Times are stored in UTC, but Postgres and SQLite give them
    back without a zone, and a browser would read such a value as its own local time."""
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


# ---- organizations (D-042, docs/ORGANIZATIONS.md) -----------------------------------------

DEFAULT_ORGANIZATION = "Default organization"


class Organization(Base):
    """A customer of this deployment. A self-hosted install is one organization, made by
    migration 0022 (or with the tables, below); more are made on the server only
    (python -m app.orgs create), for a hosted service. Every tenant-owned row belongs to one,
    directly (OrgOwned) or through its parent (orgscope.THROUGH)."""
    __tablename__ = "organizations"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    # SHA-256 of a worker or gateway token issued for this organization only (orgs.py). The
    # deployment's own tokens (the token files, D-039 and D-042) belong to the default organization.
    worker_token_sha256: Mapped[str | None] = mapped_column(String(64), unique=True)
    gateway_token_sha256: Mapped[str | None] = mapped_column(String(64), unique=True)


# A database made from the models (tests, and databases from before migrations) gets the
# default organization with its tables, as migration 0022 makes it for everyone else.
event.listen(Organization.__table__, "after_create", DDL(
    f"INSERT INTO organizations (name, created_at) VALUES ('{DEFAULT_ORGANIZATION}', CURRENT_TIMESTAMP)"))


class OrgOwned:
    """A row that belongs to one organization directly. orgscope.py adds
    organization_id = <the caller's> to every query on these tables and sets it on new rows
    from their parents; nothing else needs to remember it. Tables whose leading unique
    constraint starts with organization_id set __org_index__ = False (that index serves)."""
    __org_index__ = True

    @declared_attr
    def organization_id(cls) -> Mapped[int]:
        return mapped_column(ForeignKey("organizations.id"), index=cls.__org_index__)


class ItemState(str, Enum):
    open = "open"
    done = "done"
    na = "na"


class Engagement(OrgOwned, Base):
    __tablename__ = "engagements"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)   # names are per organization
    __org_index__ = False
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
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
    # When on, the person who attached a lane's evidence cannot sign its receipt.
    separation_of_duties: Mapped[bool] = mapped_column(default=False, server_default=sa_false())
    # When on, a receipt needs a valid signature from the reviewer's own key (D-027).
    require_signatures: Mapped[bool] = mapped_column(default=False, server_default=sa_false())
    # When on (the default), credentials and some personal data are replaced before raw
    # evidence is stored (redact.py, D-038). An owner may turn it off for a lab.
    redact_evidence: Mapped[bool] = mapped_column(default=True, server_default=sa_true())
    # Retention (D-043, vault.py): the content is kept through this UTC date, then the worker
    # deletes the engagement's key. No date: kept until an owner deletes it.
    retain_until: Mapped[date | None]
    # Set when the content was deleted: when, by whom (name and email, or "the retention
    # policy"), and why (owner, retention, operator). Hashes, receipts and history remain.
    content_deleted_at: Mapped[datetime | None]
    content_deleted_by: Mapped[str | None] = mapped_column(String(460))
    content_deleted_reason: Mapped[str | None] = mapped_column(String(16))
    # When on, agents may propose POST, PUT, PATCH and DELETE requests; each waits for a
    # person's approval before the gateway sends it (D-041, approvals.py). Off by default.
    allow_writes: Mapped[bool] = mapped_column(default=False, server_default=sa_false())
    assets: Mapped[list["Asset"]] = relationship(back_populates="engagement")
    jobs: Mapped[list["Job"]] = relationship(back_populates="engagement", order_by="Job.id.desc()")


class Asset(OrgOwned, Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("engagement_id", "host"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    host: Mapped[str] = mapped_column(String(255))
    in_scope: Mapped[bool] = mapped_column(default=True)
    engagement: Mapped[Engagement] = relationship(back_populates="assets")
    lanes: Mapped[list["Lane"]] = relationship(back_populates="asset")


class Lane(OrgOwned, Base):
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


class Evidence(OrgOwned, Base):
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
    # Chain record version (ledger.py). v1 rows (before 0018) keep their summary here in
    # plaintext, because their chain hash covers the text. v2 rows keep it encrypted with the
    # engagement's key in summary_enc, and the chain commits to summary_sha256; summary_enc is
    # null once the engagement's content was deleted (vault.py).
    record_version: Mapped[int] = mapped_column(default=1, server_default="1")
    summary: Mapped[str | None] = mapped_column(Text)
    summary_sha256: Mapped[str | None] = mapped_column(String(64))
    summary_enc: Mapped[str | None] = mapped_column(Text)
    # Where it came from: manual, recon, agent or import:<tool>. Null on v1 rows, which did not record it.
    source: Mapped[str | None] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))   # who attached it, or started the run
    # What was redacted from the stored bytes (redact.Report.as_dict): counts and kinds, never
    # values. The chain commits to the same facts through the summary's note.
    redaction: Mapped[dict | None] = mapped_column(JSON)
    lane: Mapped[Lane] = relationship(back_populates="evidence")


class Receipt(Base):
    __tablename__ = "receipts"
    id: Mapped[int] = mapped_column(primary_key=True)
    lane_id: Mapped[int] = mapped_column(ForeignKey("lanes.id"))
    manifest_sha256: Mapped[str] = mapped_column(String(64))
    # The person who reviewed the lane and closed it. Executors never issue receipts (D-018).
    closed_by: Mapped[str | None] = mapped_column(String(200))
    closed_by_user: Mapped[int | None] = mapped_column(ForeignKey("users.id"))   # set when people sign in
    closed_by_email: Mapped[str | None] = mapped_column(String(254))             # the account's email at the time
    # Signed receipts: the exact signed text, the signature and the key, copied so that a
    # report stays verifiable even if the key is later revoked.
    payload: Mapped[str | None] = mapped_column(Text)
    signature: Mapped[str | None] = mapped_column(String(200))
    algorithm: Mapped[str | None] = mapped_column(String(20))
    public_key: Mapped[str | None] = mapped_column(Text)
    key_fingerprint: Mapped[str | None] = mapped_column(String(64))
    # RFC 3161 timestamp of the manifest hash and signature (timestamps.py): the token as
    # base64 DER, its time, the authority asked, and why the last attempt failed, if it did.
    timestamp_token: Mapped[str | None] = mapped_column(Text)
    timestamp_time: Mapped[datetime | None] = mapped_column()
    timestamp_tsa: Mapped[str | None] = mapped_column(String(500))
    timestamp_error: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    lane: Mapped[Lane] = relationship(back_populates="receipts")


class JobStatus(str, Enum):
    queued = "queued"
    running = "running"
    done = "done"
    failed = "failed"
    cancelled = "cancelled"
    partial = "partial"   # stopped at the time limit; remaining_targets lists what was not run
    skipped = "skipped"   # a pipeline step with nothing to work on; result["skipped_reason"] says why


class Job(OrgOwned, Base):
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
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    # SHA-256 of the secret the worker made when it claimed the job. The job's tools present
    # the secret to the gateway (D-039), which asks the API; it is valid while the job runs.
    gateway_secret_sha256: Mapped[str | None] = mapped_column(String(64))
    # SHA-256 of the job token the API issued when the worker claimed the job: it opens this
    # job's /worker/jobs/{id}/... routes only, while the job runs (docs/WORKER_API.md). Cleared
    # when the job ends, with the gateway secret.
    worker_token_sha256: Mapped[str | None] = mapped_column(String(64))
    # The last time the worker reported on this job. A running job whose heartbeat is too old
    # has no live worker and is marked interrupted by the API.
    heartbeat_at: Mapped[datetime | None]
    # An agent run made by an outside driver (tools/agent_bridge.py, D-031): who drives it. The
    # worker's own loop never claims these.
    driver: Mapped[str | None] = mapped_column(String(200))
    engagement: Mapped[Engagement] = relationship(back_populates="jobs")


class AgentExchange(Base):
    """An HTTP exchange of a running agent job, as the API stored it: the id the model cites
    (x1, x2, ...) and the blob it names. Kept only while the job runs; add_evidence may cite
    only these, so evidence never points at a blob the API did not store for this run."""
    __tablename__ = "agent_exchanges"
    __table_args__ = (UniqueConstraint("job_id", "xid"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"), index=True)
    xid: Mapped[str] = mapped_column(String(16))
    sha256: Mapped[str] = mapped_column(String(64))
    method: Mapped[str] = mapped_column(String(16))
    url: Mapped[str] = mapped_column(Text)
    status: Mapped[int]
    redaction: Mapped[dict | None] = mapped_column(JSON)
    # The test account the gateway sent it as (D-040), and the approval it carried (D-041).
    account: Mapped[str | None] = mapped_column(String(16))
    approval_id: Mapped[int | None]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class TestAccount(OrgOwned, Base):
    """A test account a person signed in to on the target (D-040, testaccounts.py). Its session
    material (a cookie header, a bearer token or a set of headers) is sealed with the
    engagement's key and is never returned by the API; the gateway adds it to requests sent "as"
    the label, for the hosts named here only."""
    __tablename__ = "test_accounts"
    __test__ = False                    # not a pytest test class
    __table_args__ = (UniqueConstraint("engagement_id", "label"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"), index=True)
    label: Mapped[str] = mapped_column(String(16))           # A, B, ...
    role: Mapped[str] = mapped_column(String(100))           # the role in the target application
    hosts: Mapped[list] = mapped_column(JSON, default=list)  # in-scope hosts it is used for
    kind: Mapped[str] = mapped_column(String(16))            # cookie, bearer, headers
    header_names: Mapped[list] = mapped_column(JSON, default=list)   # which headers it sets, never their values
    material_enc: Mapped[str] = mapped_column(Text)          # sealed with the engagement's key (vault.seal_secret)
    fingerprint: Mapped[str] = mapped_column(String(64))     # SHA-256 of the material: the binding, shown shortened
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    replaced_at: Mapped[datetime | None]
    last_used_at: Mapped[datetime | None]


class WriteProposal(OrgOwned, Base):
    """A state-changing request an agent proposed (D-041, approvals.py). Nothing is sent until a
    person approves it; the approval is for this exact request (request_sha256), expires, and
    the gateway uses it once. The request itself is sealed with the engagement's key."""
    __tablename__ = "write_proposals"
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"), index=True)
    lane_id: Mapped[int] = mapped_column(ForeignKey("lanes.id"))
    job_id: Mapped[int | None] = mapped_column(ForeignKey("jobs.id"), index=True)
    item_idx: Mapped[int | None]
    method: Mapped[str] = mapped_column(String(8))
    url: Mapped[str] = mapped_column(Text)                   # redacted, for lists; the exact one is sealed
    host: Mapped[str] = mapped_column(String(255))
    account: Mapped[str | None] = mapped_column(String(16))  # test account label, or none
    reason: Mapped[str] = mapped_column(Text)                # the agent's stated reason (redacted)
    request_enc: Mapped[str | None] = mapped_column(Text)    # sealed canonical request; null once content is deleted
    request_sha256: Mapped[str] = mapped_column(String(64))
    body_sha256: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="pending")   # see approvals.STATUSES
    decided_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    decided_by_name: Mapped[str | None] = mapped_column(String(460))
    decided_at: Mapped[datetime | None]
    decision_note: Mapped[str | None] = mapped_column(Text)
    approved_sha256: Mapped[str | None] = mapped_column(String(64))
    delete_confirmed_at: Mapped[datetime | None]
    expires_at: Mapped[datetime | None]
    sent_at: Mapped[datetime | None]
    response_status: Mapped[int | None]
    exchange_id: Mapped[str | None] = mapped_column(String(16))
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class GatewayRequest(OrgOwned, Base):
    """One request, port probe or DNS question that reached the gateway (D-039), allowed or
    refused, with the reason. Written by the gateway through the API; never updated."""
    __tablename__ = "gateway_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime]
    engagement_id: Mapped[int | None] = mapped_column(ForeignKey("engagements.id"), index=True)
    job_id: Mapped[int | None] = mapped_column(ForeignKey("jobs.id"), index=True)
    tool: Mapped[str] = mapped_column(String(32))        # as the job's credential names it
    kind: Mapped[str] = mapped_column(String(16))        # target, passive, service, dns
    method: Mapped[str] = mapped_column(String(16))      # GET, ..., PROBE (port probe), DNS
    url: Mapped[str] = mapped_column(Text)               # redacted unless the engagement turned it off
    host: Mapped[str] = mapped_column(String(255), default="")
    port: Mapped[int | None]
    status: Mapped[int | None]                           # the target's, or the gateway's refusal
    verdict: Mapped[str] = mapped_column(String(8))      # allowed, refused, failed (upstream error)
    reason: Mapped[str] = mapped_column(String(300), default="")
    bytes_sent: Mapped[int] = mapped_column(default=0)
    bytes_received: Mapped[int] = mapped_column(default=0)
    duration_ms: Mapped[int | None]
    account: Mapped[str | None] = mapped_column(String(16))     # test account label it was sent as (D-040)
    approval_id: Mapped[int | None]                              # the approved write it sent (D-041)


class Observation(OrgOwned, Base):
    """What a recon job saw about a host (one row per host per job)."""
    __tablename__ = "observations"
    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"))
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    host: Mapped[str] = mapped_column(String(255))
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class Endpoint(OrgOwned, Base):
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


class Lead(OrgOwned, Base):
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


# ---- people -----------------------------------------------------------------

ROLES = ("viewer", "tester", "reviewer")


class User(OrgOwned, Base):
    """A person who signs in. Owners manage people and engagements and can do everything;
    everyone else gets roles per engagement (Membership)."""
    __tablename__ = "users"
    # An email is unique within an organization; sign-in finds the account whose password matches.
    __table_args__ = (UniqueConstraint("organization_id", "email"),)
    __org_index__ = False
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254))
    name: Mapped[str] = mapped_column(String(200))
    password_hash: Mapped[str] = mapped_column(String(300))
    is_owner: Mapped[bool] = mapped_column(default=False, server_default=sa_false())
    disabled: Mapped[bool] = mapped_column(default=False, server_default=sa_false())
    # True once the person set their own password (POST /auth/password). A password set at
    # account creation or by an operator reset is also known to whoever set it.
    password_chosen: Mapped[bool] = mapped_column(default=False, server_default=sa_false())
    # The last two sign-ins: the app shows key changes made since the previous one.
    last_sign_in_at: Mapped[datetime | None]
    previous_sign_in_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class UserSession(Base):
    """A signed-in browser. Only the hash of the cookie value is stored."""
    __tablename__ = "user_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    token_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime]


class Membership(OrgOwned, Base):
    """A person's roles on one engagement: viewer (read), tester (work), reviewer (sign)."""
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("engagement_id", "user_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    roles: Mapped[list] = mapped_column(JSON, default=list)


class SigningKey(Base):
    """A reviewer's public key. The private key stays in their browser and never reaches
    the server. Revoked keys sign nothing new; earlier signatures stay valid."""
    __tablename__ = "signing_keys"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    algorithm: Mapped[str] = mapped_column(String(20))
    public_key: Mapped[str] = mapped_column(Text)             # SPKI, base64
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    revoked_at: Mapped[datetime | None]


class KeyLogEntry(OrgOwned, Base):
    """Append-only, hash-chained record of every key registration and revocation (keylog.py).
    Nothing updates or deletes a row. Reports carry the entries of the keys that signed them."""
    __tablename__ = "key_log"
    __table_args__ = (UniqueConstraint("organization_id", "seq"),)   # one chain per organization
    __org_index__ = False
    id: Mapped[int] = mapped_column(primary_key=True)
    seq: Mapped[int]
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    user_name: Mapped[str] = mapped_column(String(200))                  # the name at the time
    key_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    algorithm: Mapped[str] = mapped_column(String(20))
    event: Mapped[str] = mapped_column(String(16))                       # registered, revoked
    at: Mapped[str] = mapped_column(String(40))     # ISO 8601 UTC with microseconds, hashed as stored
    via: Mapped[str] = mapped_column(String(24))    # see keylog.VIA
    record_sha256: Mapped[str] = mapped_column(String(64))
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))


class AuditEntry(OrgOwned, Base):
    """Append-only, hash-chained record of administrative changes (auditlog.py): scope and
    rules, authorization, engagement settings, roles, and people. Nothing updates or deletes
    a row. Reports carry the entries of their engagement and of its people."""
    __tablename__ = "audit_log"
    __table_args__ = (UniqueConstraint("organization_id", "seq"),)   # one chain per organization
    __org_index__ = False
    id: Mapped[int] = mapped_column(primary_key=True)
    seq: Mapped[int]
    at: Mapped[str] = mapped_column(String(40))     # ISO 8601 UTC with microseconds, hashed as stored
    actor_kind: Mapped[str] = mapped_column(String(16))      # see auditlog.ACTORS
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    actor_name: Mapped[str] = mapped_column(String(200))     # the name and email at the time
    actor_email: Mapped[str | None] = mapped_column(String(254))
    action: Mapped[str] = mapped_column(String(40))          # see auditlog.ACTIONS
    engagement_id: Mapped[int | None] = mapped_column(ForeignKey("engagements.id"), index=True)
    subject_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)   # the person a person.* entry is about
    change: Mapped[str] = mapped_column(Text)       # canonical JSON: before and after values, never secrets
    record_sha256: Mapped[str] = mapped_column(String(64))
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))


# ---- evidence import (D-029) ------------------------------------------------------------

class ImportBatch(OrgOwned, Base):
    """One uploaded export file: who uploaded it, when, from which tool, and what became of
    each row. Rows refused as out of scope are listed by row number and host only; nothing
    else about them is kept."""
    __tablename__ = "import_batches"
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"), index=True)
    tool: Mapped[str] = mapped_column(String(16))                 # adapter id: har, burp, caido
    creator: Mapped[str | None] = mapped_column(String(200))      # the tool the file names, with its version
    filename: Mapped[str | None] = mapped_column(String(200))
    file_sha256: Mapped[str] = mapped_column(String(64))          # of the file as uploaded
    file_bytes: Mapped[int]
    rows: Mapped[int]
    accepted: Mapped[int]
    out_of_scope: Mapped[int]
    duplicates: Mapped[int]
    unreadable: Mapped[int]
    refused: Mapped[list] = mapped_column(JSON, default=list)     # [{row, host, reason, detail}]
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_by_name: Mapped[str] = mapped_column(String(300))     # who it was at the time
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class InboxEntry(OrgOwned, Base):
    """One imported request and response, waiting for a person to map it to checklist items.
    Nothing here is evidence until it is mapped; mapping appends to the ledger and lists the
    evidence here. A dismissed entry stays, with who dismissed it and why."""
    __tablename__ = "inbox_entries"
    __table_args__ = (UniqueConstraint("engagement_id", "content_sha256"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"), index=True)
    batch_id: Mapped[int] = mapped_column(ForeignKey("import_batches.id"), index=True)
    row: Mapped[int]
    tool: Mapped[str] = mapped_column(String(16))
    tool_id: Mapped[str | None] = mapped_column(String(100))
    tool_time: Mapped[str | None] = mapped_column(String(64))
    host: Mapped[str] = mapped_column(String(255))
    method: Mapped[str] = mapped_column(String(20))
    url: Mapped[str] = mapped_column(Text)                        # redacted
    status: Mapped[int | None]
    label: Mapped[str | None] = mapped_column(String(300))        # redacted
    # Blob digests of the redacted raw bytes, and of the record that names them (what
    # evidence commits to when the entry is mapped).
    request_sha256: Mapped[str | None] = mapped_column(String(64))
    response_sha256: Mapped[str | None] = mapped_column(String(64))
    record_sha256: Mapped[str] = mapped_column(String(64))
    content_sha256: Mapped[str] = mapped_column(String(64))       # dedupe key, see inbox.content_hash
    request_bytes: Mapped[int] = mapped_column(default=0)
    response_bytes: Mapped[int] = mapped_column(default=0)
    facts: Mapped[dict] = mapped_column(JSON, default=dict)       # content type, cookies set: for suggestions
    redaction: Mapped[dict | None] = mapped_column(JSON)
    state: Mapped[str] = mapped_column(String(16), default="new", server_default="new")   # new, mapped, dismissed
    mappings: Mapped[list] = mapped_column(JSON, default=list)    # [{evidence_id, lane_id, item_idx, item_key, by, at}]
    dismissed_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    dismissed_by_name: Mapped[str | None] = mapped_column(String(300))
    dismissed_at: Mapped[datetime | None]
    dismiss_reason: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


from . import orgscope  # noqa: E402,F401  (scopes every session to its organization)
