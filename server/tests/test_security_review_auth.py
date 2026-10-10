"""Regression tests from the security review of authentication, authorization and tenant
isolation (docs/security-review/AUTH.md). Each test names the finding it closes."""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import auth, blobs, vault
from app.models import Lane
from test_agent import api  # noqa: F401  (fixture)
from test_encryption import delete, engagement, v1_row
from test_people import person, sign_in


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _people(api, monkeypatch):
    monkeypatch.delenv("ATTACKLEDGER_API_TOKEN", raising=False)
    auth._failures.clear()
    person(api, "owner@lab.test", "Olive Owner", owner=True)     # open mode: the first owner
    assert sign_in(api, "owner@lab.test").status_code == 200


# ---- AUTH-1: a cited hash opened another engagement's pre-encryption blob ----------------------

def test_auth1_citing_a_hash_does_not_open_another_engagements_plaintext_blob(api, monkeypatch):
    """A tester on engagement X cites the hash of a plaintext blob (stored before encryption,
    cited by v1 evidence of engagement Y only). The citation must not open Y's bytes for X, must
    not copy them into X's encrypted store, and must not keep them alive after Y's deletion."""
    _people(api, monkeypatch)
    y, y_lane = engagement(api, "victim")
    x, x_lane = engagement(api, "attacker")
    secret = b"pre-encryption note of the victim engagement: admin password reset link"
    blobs.put(secret)                                                   # the old plaintext store
    with api.Session() as s:
        v1_row(s, s.get(Lane, y_lane["id"]), "old note", sha(secret))
    tess = person(api, "tess@lab.test", "Tess Tester")
    assert api.put(f"/engagements/{x}/members",
                   json={"members": [{"user_id": tess, "roles": ["tester"]}]}).status_code == 200

    sign_in(api, "tess@lab.test")
    assert api.get(f"/blobs/{sha(secret)}").status_code == 404        # control: not hers to read
    r = api.post(f"/lanes/{x_lane['id']}/evidence",
                 json={"item_idx": 1, "kind": "note", "sha256": sha(secret), "summary": "cited"})
    assert r.status_code == 201, r.text
    r = api.get(f"/blobs/{sha(secret)}")
    assert r.status_code == 404 and secret not in r.content

    sign_in(api, "owner@lab.test")                                     # Y's own evidence still opens it
    assert api.get(f"/blobs/{sha(secret)}").content == secret

    with api.Session() as s:                                           # encrypting copies it to Y only
        res = vault.encrypt_existing(s)
    assert res == {"encrypted": 1, "already_encrypted": 0, "plaintext_removed": 1}
    assert blobs.get(sha(secret), engagement_id=y) == secret
    assert not blobs.encrypted_path(sha(secret), x).exists()

    blobs.put(secret)                                                  # again, as before encryption
    blobs.encrypted_path(sha(secret), y).unlink()
    res = delete(api, y, "victim")                                     # X's citation does not keep it
    assert res["removed"]["plaintext_blobs_removed"] == 1
    assert not blobs.plain_path(sha(secret)).exists()
    sign_in(api, "tess@lab.test")
    assert api.get(f"/blobs/{sha(secret)}").status_code == 404
