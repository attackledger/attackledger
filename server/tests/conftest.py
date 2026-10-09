import pytest


@pytest.fixture(autouse=True)
def _blob_store(tmp_path, monkeypatch):
    """Every test writes raw evidence to its own folder. The default, /data/blobs, exists in
    the Docker image but not on a CI runner, and tests must not share stored blobs."""
    monkeypatch.setenv("ATTACKLEDGER_BLOBS", str(tmp_path / "blobs"))


@pytest.fixture(autouse=True)
def _master_key(monkeypatch):
    """Tests use the public development master key unless a test sets its own (vault.py).
    Without one, the API and the worker refuse to start."""
    monkeypatch.delenv("ATTACKLEDGER_MASTER_KEY_FILE", raising=False)
    monkeypatch.delenv("ATTACKLEDGER_MASTER_KEY", raising=False)
    monkeypatch.setenv("ATTACKLEDGER_DEV_KEY", "1")
