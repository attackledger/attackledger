import socket

import pytest

_real_gethostbyname = socket.gethostbyname
_real_getaddrinfo = socket.getaddrinfo


@pytest.fixture(autouse=True)
def _no_dns_for_invalid_names(monkeypatch):
    """Names under .invalid never resolve (RFC 6761), so they are answered here, at once, and
    never asked of the machine's resolver: the gateway address the tests configure
    (gateway.invalid) must not depend on DNS timing or a resolver's search domains, which made
    test_worker's gateway test flaky."""
    def invalid(host) -> bool:
        name = host.decode() if isinstance(host, bytes) else str(host or "")
        return name.lower().rstrip(".").endswith(".invalid") or name.lower() == "invalid"

    def gethostbyname(host):
        if invalid(host):
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return _real_gethostbyname(host)

    def getaddrinfo(host, *args, **kwargs):
        if invalid(host):
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return _real_getaddrinfo(host, *args, **kwargs)
    monkeypatch.setattr(socket, "gethostbyname", gethostbyname)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


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


@pytest.fixture(autouse=True)
def _gateway_settings(tmp_path, monkeypatch):
    """Tests run as the worker does in the compose stack: a gateway address and its CA are
    configured (nothing listens there; tests that send traffic use fakes). Tests of the
    fail-closed paths remove them."""
    ca = tmp_path / "gateway-ca.pem"
    ca.write_text("test CA\n")
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY", "gateway.invalid:8080")
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_DNS", "gateway.invalid:53")
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_CA", str(ca))
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_TOKEN_FILE", str(tmp_path / "gateway-token"))
    monkeypatch.delenv("ATTACKLEDGER_GATEWAY_TOKEN", raising=False)


@pytest.fixture(autouse=True)
def _worker_settings(tmp_path, monkeypatch):
    """The worker's token lives in a test folder, and the API's background passes (retention,
    interrupted jobs) are off: tests call them directly (workerapi.sweep, retention_pass)."""
    monkeypatch.setenv("ATTACKLEDGER_WORKER_TOKEN_FILE", str(tmp_path / "worker-token"))
    monkeypatch.delenv("ATTACKLEDGER_WORKER_TOKEN", raising=False)
    monkeypatch.setenv("ATTACKLEDGER_MAINTENANCE_SECONDS", "0")
