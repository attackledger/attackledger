"""The worker's channel to the API (D-042, docs/WORKER_API.md).

The worker has no database. It claims jobs, writes results and reports status through the
API's /worker/* routes, which the gateway relays (ATTACKLEDGER_WORKER_API, default
http://gateway:8081). Two credentials:

  worker token   claims queued jobs and pings. Created by the worker on first start in the
                 volume it shares with the API only (ATTACKLEDGER_WORKER_TOKEN replaces it).
  job token      issued by the API with each claim; opens only that job's routes, only while
                 it runs. Never given to a tool (tools get the gateway secret, D-039).

This module has no database or web-framework imports: the worker and tools/agent_bridge.py
use it inside the worker container.
"""
import base64
import json
import os
import secrets
import urllib.error
import urllib.request
from collections.abc import Callable

DEFAULT_URL = "http://gateway:8081"
DEFAULT_TOKEN_FILE = "/data/worker-control/token"
TIMEOUT = 120

# (method, path, headers, body) -> (status, body)
Send = Callable[[str, str, dict[str, str], bytes | None], tuple[int, bytes]]


class ApiError(RuntimeError):
    """The API refused a call, or could not be reached (status 0)."""

    def __init__(self, status: int, detail: str):
        self.status, self.detail = status, detail
        super().__init__(f"API answered {status}: {detail}" if status else detail)


def worker_token(create: bool = False) -> str | None:
    """ATTACKLEDGER_WORKER_TOKEN, or the token file in the volume the worker shares with the API
    only. The worker creates the file on first start; the API only reads it."""
    tok = os.environ.get("ATTACKLEDGER_WORKER_TOKEN", "").strip()
    if tok:
        return tok
    path = os.environ.get("ATTACKLEDGER_WORKER_TOKEN_FILE", DEFAULT_TOKEN_FILE)
    try:
        with open(path) as f:
            return f.read().strip() or None
    except FileNotFoundError:
        if not create:
            return None
    except OSError:
        return None
    os.makedirs(os.path.dirname(path), exist_ok=True)
    value = secrets.token_urlsafe(32)
    # The API runs as the same user and mounts the volume read-only; nothing else mounts it.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value)
    return value


def urllib_send(base: str) -> Send:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # never through a proxy variable

    def send(method, path, headers, body):
        req = urllib.request.Request(base.rstrip("/") + path, method=method, data=body, headers=headers)
        try:
            with opener.open(req, timeout=TIMEOUT) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except (OSError, ValueError) as e:
            raise ApiError(0, f"the API cannot be reached through {base}: {str(e)[:200] or type(e).__name__}")
    return send


class Client:
    def __init__(self, base: str | None = None, send: Send | None = None):
        self.base = (base or os.environ.get("ATTACKLEDGER_WORKER_API", "").strip() or DEFAULT_URL)
        self.send = send or urllib_send(self.base)

    def call(self, method: str, path: str, token: str, body: dict | None = None) -> dict:
        headers = {"authorization": f"Bearer {token}", "content-type": "application/json"}
        data = json.dumps(body).encode() if body is not None else None
        status, raw = self.send(method, path, headers, data)
        try:
            out = json.loads(raw or b"{}")
        except ValueError:
            out = {"detail": raw[:300].decode("utf-8", "replace")}
        if not 200 <= status < 300:
            detail = out.get("detail") if isinstance(out, dict) else out
            raise ApiError(status, detail if isinstance(detail, str) else json.dumps(detail)[:500])
        return out


class Worker:
    """What the worker token can do: ping, and claim a job."""

    def __init__(self, client: Client, token: str | None):
        self.client, self.token = client, token

    @classmethod
    def from_env(cls, create_token: bool = False) -> "Worker":
        return cls(Client(), worker_token(create=create_token))

    def _call(self, method, path, body=None):
        if not self.token:
            raise ApiError(0, "no worker token (ATTACKLEDGER_WORKER_TOKEN or the worker-control volume)")
        return self.client.call(method, path, self.token, body)

    def ping(self) -> dict:
        return self._call("GET", "/worker/ping")

    def claim(self, job_id: int | None = None) -> dict | None:
        """The next job's specification, or None when nothing is queued."""
        return self._call("POST", "/worker/claim", {"job_id": job_id})["job"]


class JobChannel:
    """One claimed job: what its token can do. Everything the job reads came with the claim."""

    def __init__(self, client: Client, spec: dict):
        self.client, self.spec = client, spec
        self.id, self.kind, self.token = spec["id"], spec["kind"], spec["token"]
        self.gateway_secret = spec["gateway_secret"]

    def _call(self, path: str, body: dict | None = None) -> dict:
        return self.client.call("POST", f"/worker/jobs/{self.id}/{path}", self.token, body or {})

    def heartbeat(self) -> str:
        """The job's status: running, or cancelled."""
        return self._call("heartbeat")["status"]

    def log(self, *lines: str) -> None:
        if lines:
            self._call("log", {"lines": list(lines)})

    def progress(self, done: list[str]) -> dict:
        return self._call("progress", {"done": done})

    def results(self, *, observations=(), endpoints=(), leads=()) -> dict:
        return self._call("results", {"observations": list(observations), "endpoints": list(endpoints),
                                      "leads": list(leads)})

    def finish(self, **body) -> dict:
        return self._call("finish", body)

    def agent_exchange(self, *, method: str, url: str, headers: dict, status: int,
                       response_headers: list, body: bytes, at: str, view: str = "auto",
                       account: str | None = None, approval_id: int | None = None,
                       request_body: bytes | None = None) -> dict:
        """account: the test account the gateway sent it as (D-040); approval_id and request_body:
        an approved write the gateway sent (D-041)."""
        return self._call("agent/exchange", {
            "method": method, "url": url, "headers": headers, "status": status,
            "response_headers": [[k, v] for k, v in response_headers],
            "body_b64": base64.b64encode(body).decode(), "at": at, "view": view, "account": account,
            "approval_id": approval_id,
            "request_body_b64": base64.b64encode(request_body).decode() if request_body is not None else None})

    def agent_call(self, name: str, args: dict) -> dict:
        return self._call("agent/call", {"name": name, "args": args})
