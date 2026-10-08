import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_ledger import client  # noqa: F401  (fixture)


def test_open_without_a_token(client, monkeypatch):
    monkeypatch.delenv("ATTACKLEDGER_API_TOKEN", raising=False)
    assert client.get("/health").json()["auth_required"] is False
    assert client.get("/engagements").status_code == 200


def test_token_required_when_configured(client, monkeypatch):
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", "s3cret-token")
    assert client.get("/health").status_code == 200 and client.get("/health").json()["auth_required"]
    assert client.get("/engagements").status_code == 401
    assert client.get("/engagements", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/engagements", headers={"Authorization": "Bearer s3cret-token"}).status_code == 200


def test_login_sets_a_derived_strict_cookie(client, monkeypatch):
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", "s3cret-token")
    assert client.post("/auth/login", json={"token": "nope"}).status_code == 401
    r = client.post("/auth/login", json={"token": "s3cret-token"})
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie and "s3cret-token" not in cookie
    assert client.get("/engagements").status_code == 200          # cookie carried by the client
    client.post("/auth/logout")
    client.cookies.clear()
    assert client.get("/engagements").status_code == 401
