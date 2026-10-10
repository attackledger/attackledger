"""The gateway's request log rows: what both sides agree a row is, and the placeholder that takes
the place of a row the API cannot store (docs/GATEWAY.md, "The request log").

The gateway keeps every row it has not written yet and refuses all traffic once 5,000 wait (it
fails closed), so a row the API refuses must not stay in that queue: it would be sent again for
ever, the log would stop, and then the traffic. Such a row is set aside instead, in the gateway's
quarantine file, and a placeholder is stored in its place: verdict "unlogged", the engagement,
job, tool, kind, method and host it named where they are valid, no URL, and why it was not
stored. The log then still shows that there was traffic, and how much of it, that it could not
store. A refusal that resending can fix (the API or the database is down, a 5xx, a wrong token)
is not this: the row stays queued, and the gateway keeps failing closed.

The API makes the placeholder for a row it refuses on its own (POST /gateway/log answers which);
the gateway makes it for a row the API refused with the whole batch (a body limit in front of the
API, a row that breaks the request), once the API has taken that placeholder by itself.
"""
from datetime import datetime, timezone

UNLOGGED = "unlogged"                      # fits gateway_requests.verdict (8 characters)
VERDICTS = ("allowed", "refused", "failed")
KINDS = ("target", "passive", "service", "dns")
INT4_MAX = 2**31 - 1                       # INTEGER: ids, ports, statuses
INT8_MAX = 2**63 - 1                       # BIGINT: byte counts and durations (migration 0025)


def _an_id(v):
    return v if type(v) is int and 1 <= v <= INT4_MAX else None


def _text(v, n: int) -> str:
    return v[:n] if isinstance(v, str) else ""


def _time(v) -> str:
    """The row's own time if it is one that converts to UTC, else now."""
    if isinstance(v, str):
        try:
            t = datetime.fromisoformat(v)
            return (t if t.tzinfo else t.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat()
        except (ValueError, OverflowError):
            pass
    return datetime.now(timezone.utc).isoformat()


def placeholder(row, why: str) -> dict:
    """The row stored in place of `row`, which could not be stored (`why`). It repeats only fields
    that are valid as they are, and never the URL: whatever was refused may be in it."""
    d = row if isinstance(row, dict) else {}
    verdict = d.get("verdict") if d.get("verdict") in VERDICTS else None
    was = f"; the request was {verdict}" if verdict else ""
    return {"at": _time(d.get("at")), "engagement_id": _an_id(d.get("engagement_id")), "job_id": _an_id(d.get("job_id")),
            "tool": _text(d.get("tool"), 32) or "unknown", "kind": d.get("kind") if d.get("kind") in KINDS else "target",
            "method": _text(d.get("method"), 16), "url": "", "host": _text(d.get("host"), 255), "port": None,
            "status": None, "verdict": UNLOGGED,
            "reason": f"not stored ({why[:200]}){was}; the gateway set the row aside in its quarantine file"[:300],
            "bytes_sent": 0, "bytes_received": 0, "duration_ms": None,
            "account": _text(d.get("account"), 16) or None, "approval_id": _an_id(d.get("approval_id"))}
