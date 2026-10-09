import pytest


@pytest.fixture(autouse=True)
def _blob_store(tmp_path, monkeypatch):
    """Every test writes raw evidence to its own folder. The default, /data/blobs, exists in
    the Docker image but not on a CI runner, and tests must not share stored blobs."""
    monkeypatch.setenv("ATTACKLEDGER_BLOBS", str(tmp_path / "blobs"))
