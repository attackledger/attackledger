"""Content-addressed store for raw evidence: the HTTP exchanges an agent made and its notes.

An evidence row commits to the sha256 of these bytes, and the bytes are kept here so
a reviewer can open what the hash refers to. A blob is written once and never changed:
its name is its hash.

ATTACKLEDGER_BLOBS sets the directory (default /data/blobs, a volume shared by the API
and the worker).
"""
import hashlib
import os
import re
from pathlib import Path

_HEX = re.compile(r"^[0-9a-f]{64}$")


def root() -> Path:
    return Path(os.environ.get("ATTACKLEDGER_BLOBS", "/data/blobs"))


def _path(digest: str) -> Path:
    return root() / digest[:2] / digest


def put(data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    path = _path(digest)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{digest}.{os.getpid()}.tmp")
        tmp.write_bytes(data)
        os.replace(tmp, path)
    return digest


def get(digest: str) -> bytes | None:
    if not _HEX.match(digest or ""):
        return None
    path = _path(digest)
    if not path.is_file():
        return None
    data = path.read_bytes()
    # A blob whose bytes no longer match its name is not evidence of anything.
    return data if hashlib.sha256(data).hexdigest() == digest else None
