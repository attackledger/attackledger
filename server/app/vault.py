"""Per-engagement encryption at rest, and deleting an engagement's content (D-043).

Each engagement has a random 256-bit data key. It is stored wrapped by the deployment's
master key (AES-256-GCM) in the blob store, next to the blobs it protects:

    <blobs>/e/<engagement id>/key.json      the wrapped data key
    <blobs>/e/<engagement id>/<dd>/<sha>    encrypted blobs (blobs.py)
    <blobs>/e/<engagement id>/deleted.json  tombstone, once the content was deleted

The blob store has no database session and is shared by the API and the worker, so the
key lives where both can reach it without one. Deleting an engagement's folder deletes its
key and its blobs together and touches nothing else. docs/ENCRYPTION.md has the design.

Master key: ATTACKLEDGER_MASTER_KEY_FILE, else ATTACKLEDGER_MASTER_KEY (base64 or hex, 32
bytes). ATTACKLEDGER_DEV_KEY=1 uses a public development key instead. With neither, the
API, the worker and these commands refuse to start.

    python -m app.vault generate
    python -m app.vault status
    python -m app.vault encrypt-existing [--engagement N]
    python -m app.vault rotate-master --old-key-file PATH | --old-dev-key
    python -m app.vault delete-content --engagement N
"""
import argparse
import base64
import binascii
import hashlib
import json
import os
import secrets
import shutil
import sys
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_FORMAT = "attackledger-data-key/1"
BLOB_MAGIC = b"ALE1"
SUMMARY_PREFIX = "ale1:"
# Public on purpose: anyone can read it here. It only lets tests and local trials run
# without configuring a key, and gives no confidentiality.
DEV_KEY = hashlib.sha256(b"attackledger development master key: public, never for real data").digest()


class MasterKeyError(RuntimeError):
    """No usable master key: the process must not start."""


class StoreError(RuntimeError):
    """The key files do not match the configuration or the database."""


class ContentDeleted(RuntimeError):
    def __init__(self, eng_id: int, info: dict | None = None):
        self.eng_id, self.info = eng_id, info or {}
        super().__init__(deleted_sentence(self.info) if self.info else
                         f"the content of engagement {eng_id} was deleted")


# ---- master key ---------------------------------------------------------------------

def _decode_key(text: str, where: str) -> bytes:
    s = text.strip()
    try:
        raw = bytes.fromhex(s) if len(s) == 64 else base64.b64decode(s, validate=True)
    except (ValueError, binascii.Error):
        raw = b""
    if len(raw) != 32:
        raise MasterKeyError(f"{where} is not a 256-bit key (base64 or 64 hex digits); "
                             "make one with: python -m app.vault generate")
    return raw


@dataclass(frozen=True)
class MasterKey:
    key: bytes
    source: str          # "file", "env" or "development"

    @property
    def id(self) -> str:
        return key_id(self.key)


def key_id(key: bytes) -> str:
    """Names a master key without revealing it."""
    return hashlib.sha256(b"attackledger-master-key-id\0" + key).hexdigest()[:16]


def master_key() -> MasterKey:
    path = os.environ.get("ATTACKLEDGER_MASTER_KEY_FILE", "").strip()
    if path:
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as e:
            raise MasterKeyError(f"ATTACKLEDGER_MASTER_KEY_FILE ({path}) cannot be read: {e.strerror}")
        return MasterKey(_decode_key(text, "ATTACKLEDGER_MASTER_KEY_FILE"), "file")
    value = os.environ.get("ATTACKLEDGER_MASTER_KEY", "").strip()
    if value:
        return MasterKey(_decode_key(value, "ATTACKLEDGER_MASTER_KEY"), "env")
    if os.environ.get("ATTACKLEDGER_DEV_KEY", "").strip() == "1":
        return MasterKey(DEV_KEY, "development")
    raise MasterKeyError("no master key: set ATTACKLEDGER_MASTER_KEY_FILE (or ATTACKLEDGER_MASTER_KEY) to a key "
                         "made with python -m app.vault generate, or ATTACKLEDGER_DEV_KEY=1 for a local trial "
                         "with the public development key")


def describe_master() -> dict:
    """For /health: which kind of key is in use, never the key."""
    try:
        mk = master_key()
    except MasterKeyError:
        return {"master_key": "missing"}
    return {"master_key": "development" if mk.source == "development" else "configured"}


# ---- data keys ------------------------------------------------------------------------

def blob_root() -> Path:
    return Path(os.environ.get("ATTACKLEDGER_BLOBS", "/data/blobs"))


def eng_dir(eng_id: int) -> Path:
    return blob_root() / "e" / str(int(eng_id))


def _key_path(eng_id: int) -> Path:
    return eng_dir(eng_id) / "key.json"


def _tomb_path(eng_id: int) -> Path:
    return eng_dir(eng_id) / "deleted.json"


def _wrap_aad(eng_id: int) -> bytes:
    return b"attackledger-data-key\0" + str(int(eng_id)).encode()


def _wrap(mk: MasterKey, eng_id: int, data_key: bytes, created_at: str) -> dict:
    nonce = secrets.token_bytes(12)
    return {"format": KEY_FORMAT, "engagement_id": int(eng_id), "master_key_id": mk.id, "created_at": created_at,
            "wrapped": base64.b64encode(nonce + AESGCM(mk.key).encrypt(nonce, data_key, _wrap_aad(eng_id))).decode()}


def _unwrap(key: bytes, eng_id: int, doc: dict) -> bytes:
    raw = base64.b64decode(doc["wrapped"])
    return AESGCM(key).decrypt(raw[:12], raw[12:], _wrap_aad(eng_id))


def _write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def tombstone(eng_id: int) -> dict | None:
    try:
        return json.loads(_tomb_path(eng_id).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return {"at": None, "by": None, "reason": None}


def has_key(eng_id: int) -> bool:
    return _key_path(eng_id).is_file()


def data_key(eng_id: int, *, create: bool = False) -> bytes | None:
    """The engagement's data key; None if it has none (and create is False).
    Raises ContentDeleted once the content was deleted, StoreError if the key file was
    wrapped by another master key or does not open."""
    info = tombstone(eng_id)
    if info is not None:
        raise ContentDeleted(eng_id, info)
    mk = master_key()
    path = _key_path(eng_id)
    if not path.is_file():
        if not create:
            return None
        key = secrets.token_bytes(32)
        doc = _wrap(mk, eng_id, key, datetime.now(timezone.utc).isoformat(timespec="seconds"))
        path.parent.mkdir(parents=True, exist_ok=True)
        try:   # O_EXCL: if the API and the worker race, one key wins and both use it
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return data_key(eng_id, create=False)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(doc))
        if tombstone(eng_id) is not None:      # deleted while this key was being made
            path.unlink(missing_ok=True)
            raise ContentDeleted(eng_id, tombstone(eng_id))
        return key
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:               # deleted in between
        raise ContentDeleted(eng_id, tombstone(eng_id))
    except (OSError, ValueError):
        raise StoreError(f"the key file of engagement {eng_id} cannot be read")
    if doc.get("master_key_id") != mk.id:
        raise StoreError(f"the key of engagement {eng_id} was wrapped by another master key "
                         f"({doc.get('master_key_id')}, configured {mk.id}); configure that key or rotate "
                         "(python -m app.vault rotate-master)")
    try:
        return _unwrap(mk.key, eng_id, doc)
    except (InvalidTag, KeyError, ValueError, binascii.Error):
        raise StoreError(f"the key of engagement {eng_id} does not open with the master key")


# ---- sealing ---------------------------------------------------------------------------

def _blob_aad(eng_id: int, digest: str) -> bytes:
    return b"attackledger-blob\0" + f"{int(eng_id)}\0{digest}".encode()


def seal_blob(eng_id: int, digest: str, data: bytes) -> bytes:
    key = data_key(eng_id, create=True)
    nonce = secrets.token_bytes(12)
    return BLOB_MAGIC + nonce + AESGCM(key).encrypt(nonce, data, _blob_aad(eng_id, digest))


def open_blob(eng_id: int, digest: str, raw: bytes, key: bytes | None = None) -> bytes | None:
    """The plaintext, or None for a wrong key, a tampered file or a missing key."""
    if not raw.startswith(BLOB_MAGIC) or len(raw) < len(BLOB_MAGIC) + 12 + 16:
        return None
    key = key or data_key(eng_id)
    if key is None:
        return None
    n = len(BLOB_MAGIC)
    try:
        return AESGCM(key).decrypt(raw[n:n + 12], raw[n + 12:], _blob_aad(eng_id, digest))
    except InvalidTag:
        return None


def _summary_aad(eng_id: int, summary_sha256: str) -> bytes:
    return b"attackledger-summary\0" + f"{int(eng_id)}\0{summary_sha256}".encode()


def seal_summary(eng_id: int, summary: str, summary_sha256: str) -> str:
    key = data_key(eng_id, create=True)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, summary.encode(), _summary_aad(eng_id, summary_sha256))
    return SUMMARY_PREFIX + base64.b64encode(nonce + ct).decode()


def open_summary(eng_id: int, sealed: str, summary_sha256: str, key: bytes | None = None) -> str | None:
    """The summary text, or None if it does not open or does not match its hash."""
    if not sealed or not sealed.startswith(SUMMARY_PREFIX):
        return None
    try:
        key = key or data_key(eng_id)
    except (ContentDeleted, StoreError):
        return None
    if key is None:
        return None
    try:
        raw = base64.b64decode(sealed[len(SUMMARY_PREFIX):], validate=True)
        text = AESGCM(key).decrypt(raw[:12], raw[12:], _summary_aad(eng_id, summary_sha256)).decode()
    except (InvalidTag, ValueError, binascii.Error, UnicodeDecodeError):
        return None
    return text if hashlib.sha256(text.encode()).hexdigest() == summary_sha256 else None


class Keys:
    """Data keys for one request or report, read once per engagement."""

    def __init__(self):
        self._keys: dict[int, bytes | None] = {}

    def get(self, eng_id: int) -> bytes | None:
        if eng_id not in self._keys:
            try:
                self._keys[eng_id] = data_key(eng_id)
            except (ContentDeleted, StoreError):
                self._keys[eng_id] = None
        return self._keys[eng_id]


def summary_of(ev, keys: Keys | None = None) -> str | None:
    """The text of an evidence summary: plaintext (v1 rows), or decrypted (v2 rows).
    None when the content was deleted or the ciphertext does not open."""
    if ev.summary is not None:
        return ev.summary
    if not ev.summary_enc or not ev.summary_sha256:
        return None
    key = (keys or Keys()).get(ev.engagement_id)
    return open_summary(ev.engagement_id, ev.summary_enc, ev.summary_sha256, key) if key else None


# ---- deletion ---------------------------------------------------------------------------

def deleted_info(eng) -> dict | None:
    """What the API, the UI and the report say about deleted content."""
    if eng.content_deleted_at is None:
        return None
    at = eng.content_deleted_at
    at = (at if at.tzinfo else at.replace(tzinfo=timezone.utc)).isoformat()
    return {"at": at, "by": eng.content_deleted_by, "reason": eng.content_deleted_reason}


def deleted_sentence(info: dict) -> str:
    when = (info.get("at") or "")[:10] or "an unknown date"
    return f"The content of this engagement was deleted on {when} by {info.get('by') or 'someone'}."


def check_writable(eng) -> None:
    """New content into an engagement whose content was deleted is refused."""
    info = deleted_info(eng)
    if info is not None:
        raise ContentDeleted(eng.id, info)


RETENTION_ACTOR = {"kind": "retention", "user_id": None, "name": "retention policy", "email": None}
REASONS = ("owner", "retention", "operator")


def delete_content(session, eng, *, actor: dict, reason: str) -> dict:
    """Delete an engagement's content: record it, null the summaries, drop recon results,
    then delete the key and the blobs. Commits. Idempotent: a second call only finishes the
    file step. Returns what was done."""
    from sqlalchemy import delete as sa_delete, select

    from . import auditlog
    from .models import Endpoint, Engagement, Evidence, Job, Lead, Observation

    if reason not in REASONS:
        raise ValueError(f"unknown reason {reason!r}")
    if session.bind.dialect.name == "postgresql":   # serialize with ledger.append_evidence
        session.execute(select(Engagement).where(Engagement.id == eng.id).with_for_update())
    if eng.content_deleted_at is not None:
        files = finish_deletion(session, eng)
        return {"already_deleted": True, **deleted_info(eng), **files}

    rows = session.scalars(select(Evidence).where(Evidence.engagement_id == eng.id)).all()
    sealed = [e for e in rows if e.summary_enc is not None]
    kept = sum(1 for e in rows if e.summary is not None)
    for e in sealed:
        e.summary_enc = None
    counts = {}
    for model, name in ((Observation, "observations"), (Endpoint, "endpoints"), (Lead, "leads")):
        counts[name] = session.execute(sa_delete(model).where(model.engagement_id == eng.id)).rowcount or 0
    now = datetime.now(timezone.utc)
    by = "the retention policy" if reason == "retention" else auditlog.actor_label(actor)
    note = f"Log deleted with the engagement's content on {now.date().isoformat()}.\n"
    jobs = session.scalars(select(Job).where(Job.engagement_id == eng.id)).all()
    for j in jobs:
        j.log = note
        if j.result and "summary" in j.result:
            j.result = {k: v for k, v in j.result.items() if k != "summary"}
    eng.content_deleted_at, eng.content_deleted_by, eng.content_deleted_reason = now, by, reason
    change = {"after": {"deleted_at": now.isoformat(), "reason": reason,
                        "retain_until": eng.retain_until.isoformat() if eng.retain_until else None},
              "removed": {"summaries": len(sealed), "job_logs": len(jobs), **counts},
              "kept": {"v1_summaries": kept, "evidence_entries": len(rows)}}
    auditlog.append(session, actor=actor, action="engagement.content_deleted", engagement_id=eng.id, change=change)
    session.commit()
    files = finish_deletion(session, eng)
    return {"already_deleted": False, **deleted_info(eng), "summaries_removed": len(sealed),
            "v1_summaries_kept": kept, **counts, **files}


def finish_deletion(session, eng) -> dict:
    """The file step of a deletion: tombstone first (so no new key is made), then the key,
    then the blobs, then plaintext blobs from before 0018 that no other engagement cites."""
    from . import blobs

    info = deleted_info(eng) or {"at": None, "by": None, "reason": None}
    d = eng_dir(eng.id)
    if tombstone(eng.id) is None:
        _write_atomic(_tomb_path(eng.id), json.dumps(info))
    _key_path(eng.id).unlink(missing_ok=True)
    removed = 0
    for child in list(d.iterdir()) if d.is_dir() else []:
        if child.name == "deleted.json":
            continue
        if child.is_dir():
            removed += sum(1 for p in child.rglob("*") if p.is_file())
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)
    legacy = 0
    for digest in _legacy_only_here(session, eng.id):
        if blobs.remove_plain(digest):
            legacy += 1
    return {"blobs_removed": removed, "plaintext_blobs_removed": legacy}


def _legacy_only_here(session, eng_id: int) -> list[str]:
    from sqlalchemy import select

    from .models import Engagement, Evidence

    mine = set(session.scalars(select(Evidence.sha256).where(Evidence.engagement_id == eng_id)))
    others = {}
    for sha, other in session.execute(select(Evidence.sha256, Evidence.engagement_id)
                                      .where(Evidence.sha256.in_(sorted(mine)), Evidence.engagement_id != eng_id)):
        others.setdefault(sha, set()).add(other)
    live = {e.id for e in session.scalars(select(Engagement).where(Engagement.content_deleted_at.is_(None)))}
    return sorted(s for s in mine if not (others.get(s, set()) & live))


def due_for_retention(session, today: date | None = None) -> list:
    from sqlalchemy import select

    from .models import Engagement

    today = today or datetime.now(timezone.utc).date()
    return list(session.scalars(select(Engagement).where(Engagement.content_deleted_at.is_(None),
                                                          Engagement.retain_until.is_not(None),
                                                          Engagement.retain_until < today)))


def apply_retention(session, today: date | None = None) -> list[int]:
    """The worker's pass: delete the content of engagements past their retention date, and
    finish any deletion whose file step did not complete. Returns the engagement ids deleted."""
    from sqlalchemy import select

    from .models import Engagement

    done = []
    for eng in due_for_retention(session, today):
        delete_content(session, eng, actor=RETENTION_ACTOR, reason="retention")
        done.append(eng.id)
    for eng in session.scalars(select(Engagement).where(Engagement.content_deleted_at.is_not(None))):
        if has_key(eng.id) or tombstone(eng.id) is None:
            finish_deletion(session, eng)
    return done


# ---- startup ------------------------------------------------------------------------------

def key_files() -> list[tuple[int, Path]]:
    root = blob_root() / "e"
    out = []
    for p in sorted(root.glob("*/key.json")) if root.is_dir() else []:
        try:
            out.append((int(p.parent.name), p))
        except ValueError:
            continue
    return out


def check_store(session=None) -> MasterKey:
    """Fail closed: a master key must be configured, every key file must be wrapped by it,
    and (with a session) every engagement with encrypted summaries must still have its key."""
    mk = master_key()
    root = blob_root()
    unwritable = [str(d) for d in [root, root / "e", *sorted((root / "e").glob("*"))]
                  if d.is_dir() and not os.access(d, os.W_OK | os.X_OK)]
    if unwritable:
        raise StoreError(f"this process (uid {os.getuid()}) cannot write to {', '.join(unwritable[:5])} in the blob "
                         "store, which the API and the worker share; give it to that user, for example "
                         "docker compose run --rm --user 0 --no-deps api chown -R 10001 /data/blobs")
    wrong = []
    for eng_id, path in key_files():
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            wrong.append(f"{eng_id} (unreadable)")
            continue
        if doc.get("master_key_id") != mk.id:
            wrong.append(f"{eng_id} (wrapped by {doc.get('master_key_id')})")
    if wrong:
        raise StoreError(f"the configured master key ({mk.id}) did not wrap the keys of engagement "
                         f"{', '.join(wrong)}; configure the key they were made with, or rotate with "
                         "python -m app.vault rotate-master")
    if session is not None:
        from sqlalchemy import select

        from .models import Engagement, Evidence

        ids = set(session.scalars(select(Evidence.engagement_id).join(Engagement, Engagement.id == Evidence.engagement_id)
                                  .where(Evidence.summary_enc.is_not(None), Engagement.content_deleted_at.is_(None))))
        missing = sorted(i for i in ids if not has_key(i))
        if missing:
            raise StoreError(f"the blob store at {blob_root()} has no key for engagement "
                             f"{', '.join(map(str, missing))}, whose evidence is encrypted; is the blob volume "
                             "mounted? If the key is really lost, record it with python -m app.vault "
                             "delete-content --engagement N")
    return mk


# ---- command line --------------------------------------------------------------------------

def _status(s, args) -> int:
    from sqlalchemy import select

    from . import blobs
    from .models import Engagement, Evidence

    for eng in s.scalars(select(Engagement).order_by(Engagement.id)):
        rows = s.scalars(select(Evidence).where(Evidence.engagement_id == eng.id)).all()
        digests = {e.sha256 for e in rows}
        enc = sum(1 for d in digests if blobs.encrypted_path(d, eng.id).is_file())
        plain = sum(1 for d in digests if not blobs.encrypted_path(d, eng.id).is_file() and blobs.plain_path(d).is_file())
        info = deleted_info(eng)
        print(f"engagement {eng.id} {eng.name!r}: "
              + (f"content deleted {info['at'][:10]} by {info['by']}; " if info else "")
              + f"{len(rows)} evidence entries, {sum(1 for e in rows if e.summary_enc)} encrypted summaries, "
              f"{sum(1 for e in rows if e.summary is not None)} plaintext (chain v1) summaries; "
              f"{enc} encrypted blobs, {plain} plaintext blobs; key {'present' if has_key(eng.id) else 'none'}"
              + (f"; keep until {eng.retain_until.isoformat()}" if eng.retain_until else ""))
    return 0


def encrypt_existing(s, eng_ids: list[int] | None = None) -> dict:
    """Encrypt the plaintext blobs that engagements' evidence cites, then remove each
    plaintext copy once every engagement citing it has its own encrypted copy."""
    from sqlalchemy import select

    from . import blobs
    from .models import Engagement, Evidence

    engs = [e for e in s.scalars(select(Engagement).order_by(Engagement.id))
            if e.content_deleted_at is None and (eng_ids is None or e.id in eng_ids)]
    copied, already = 0, 0
    for eng in engs:
        for digest in sorted(set(s.scalars(select(Evidence.sha256).where(Evidence.engagement_id == eng.id)))):
            if blobs.encrypted_path(digest, eng.id).is_file():
                already += 1
                continue
            data = blobs.get(digest)               # plaintext store, digest checked
            if data is None:
                continue
            blobs.put(data, engagement_id=eng.id)
            if blobs.get(digest, engagement_id=eng.id) != data:
                raise StoreError(f"encrypted copy of {digest} for engagement {eng.id} does not read back")
            copied += 1
    removed = 0
    live = {e.id for e in s.scalars(select(Engagement).where(Engagement.content_deleted_at.is_(None)))}
    citing: dict[str, set[int]] = {}
    for sha, eid in s.execute(select(Evidence.sha256, Evidence.engagement_id)):
        citing.setdefault(sha, set()).add(eid)
    for digest, ids in citing.items():
        if blobs.plain_path(digest).is_file() and all(blobs.encrypted_path(digest, i).is_file()
                                                       for i in ids & live):
            removed += int(blobs.remove_plain(digest))
    return {"encrypted": copied, "already_encrypted": already, "plaintext_removed": removed}


def rotate_master(old: bytes) -> dict:
    mk = master_key()
    old_id = key_id(old)
    rewrapped, skipped, failed = 0, 0, []
    for eng_id, path in key_files():
        doc = json.loads(path.read_text(encoding="utf-8"))
        if doc.get("master_key_id") == mk.id:
            skipped += 1
            continue
        if doc.get("master_key_id") != old_id:
            failed.append(eng_id)
            continue
        key = _unwrap(old, eng_id, doc)
        _write_atomic(path, json.dumps(_wrap(mk, eng_id, key, doc.get("created_at") or "")))
        rewrapped += 1
    return {"rewrapped": rewrapped, "skipped": skipped, "failed": failed, "master_key_id": mk.id}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.vault", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("generate", help="print a new random master key (base64)")
    sub.add_parser("status", help="per engagement: what is encrypted, what is plaintext, what was deleted")
    enc = sub.add_parser("encrypt-existing", help="encrypt blobs stored before encryption was added")
    enc.add_argument("--engagement", type=int, action="append")
    rot = sub.add_parser("rotate-master", help="re-wrap every data key under the configured master key")
    g = rot.add_mutually_exclusive_group(required=True)
    g.add_argument("--old-key-file")
    g.add_argument("--old-dev-key", action="store_true")
    dl = sub.add_parser("delete-content", help="delete an engagement's content (cannot be undone)")
    dl.add_argument("--engagement", type=int, required=True)
    dl.add_argument("--yes", action="store_true", help="do not ask for the engagement's name")
    args = p.parse_args(argv)

    if args.cmd == "generate":
        print(base64.b64encode(secrets.token_bytes(32)).decode())
        return 0
    try:
        if args.cmd == "rotate-master":
            old = DEV_KEY if args.old_dev_key else _decode_key(Path(args.old_key_file).read_text(), args.old_key_file)
            res = rotate_master(old)
            print(f"re-wrapped {res['rewrapped']}, already under {res['master_key_id']}: {res['skipped']}"
                  + (f"; under neither key: engagement {', '.join(map(str, res['failed']))}" if res["failed"] else ""))
            return 1 if res["failed"] else 0
        from .db import SessionLocal
        from .models import Engagement
        with SessionLocal() as s:
            if args.cmd == "status":
                master_key()
                return _status(s, args)
            if args.cmd == "encrypt-existing":
                check_store(s)
                res = encrypt_existing(s, args.engagement)
                print(f"encrypted {res['encrypted']} blobs ({res['already_encrypted']} were already); "
                      f"removed {res['plaintext_removed']} plaintext copies")
                return 0
            eng = s.get(Engagement, args.engagement)
            if eng is None:
                print(f"no engagement {args.engagement}", file=sys.stderr)
                return 2
            if not args.yes and input(f"Type the engagement's name to delete its content ({eng.name}): ") != eng.name:
                print("the name does not match; nothing was deleted", file=sys.stderr)
                return 2
            from . import auditlog
            res = delete_content(s, eng, actor=auditlog.CLI, reason="operator")
            print(deleted_sentence(res) + f" Removed {res.get('blobs_removed', 0)} blobs.")
            return 0
    except (MasterKeyError, StoreError, OSError) as e:
        print(str(e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
