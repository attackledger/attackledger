"""Content-addressed store for raw evidence: the HTTP exchanges an agent made and its notes.

An evidence row commits to the sha256 of these bytes, and the bytes are kept here so
a reviewer can open what the hash refers to. A blob is written once and never changed:
its name is the hash of its plaintext.

With an engagement id (D-043), the blob is encrypted with that engagement's key and kept in
the engagement's own folder, so deleting the key makes it unreadable and deleting the folder
touches no other engagement (vault.py):

    <root>/e/<engagement id>/<dd>/<sha256>   AES-256-GCM, the id and the hash as associated data
    <root>/<dd>/<sha256>                     plaintext, without an engagement id (before 0018)

Reading with an engagement id falls back to the plaintext location, so evidence stored
before encryption opens as before.

ATTACKLEDGER_BLOBS sets the directory (default /data/blobs, a volume shared by the API
and the worker).
"""
import hashlib
import os
import re
from pathlib import Path

from . import vault

_HEX = re.compile(r"^[0-9a-f]{64}$")
ContentDeleted = vault.ContentDeleted


def root() -> Path:
    return vault.blob_root()


def plain_path(digest: str) -> Path:
    return root() / digest[:2] / digest


def encrypted_path(digest: str, engagement_id: int) -> Path:
    return vault.eng_dir(engagement_id) / digest[:2] / digest


def _write(path: Path, digest: str, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{digest}.{os.getpid()}.tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def put(data: bytes, *, engagement_id: int | None = None) -> str:
    """Store the bytes; returns the sha256 of the plaintext. Raises ContentDeleted for an
    engagement whose content was deleted."""
    digest = hashlib.sha256(data).hexdigest()
    if engagement_id is None:
        path = plain_path(digest)
        if not path.exists():
            _write(path, digest, data)
        return digest
    path = encrypted_path(digest, engagement_id)
    sealed = vault.seal_blob(engagement_id, digest, data)   # refuses after deletion, makes the key if needed
    if not path.exists():
        _write(path, digest, sealed)
    return digest


def get(digest: str, *, engagement_id: int | None = None) -> bytes | None:
    """The plaintext, or None: not stored, deleted, the wrong engagement's key, tampered,
    or bytes that no longer match their hash."""
    if not _HEX.match(digest or ""):
        return None
    if engagement_id is not None:
        if vault.tombstone(engagement_id) is not None:
            return None
        path = encrypted_path(digest, engagement_id)
        if path.is_file():
            try:
                data = vault.open_blob(engagement_id, digest, path.read_bytes())
            except vault.StoreError:
                return None
            return data if data is not None and hashlib.sha256(data).hexdigest() == digest else None
    path = plain_path(digest)
    if not path.is_file():
        return None
    data = path.read_bytes()
    # A blob whose bytes no longer match its name is not evidence of anything.
    return data if hashlib.sha256(data).hexdigest() == digest else None


def remove_plain(digest: str) -> bool:
    """Delete a plaintext blob (vault.py decides which may go)."""
    if not _HEX.match(digest or ""):
        return False
    path = plain_path(digest)
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    except PermissionError:      # a folder made by another user before the store was shared; status shows it
        return False
    return True
