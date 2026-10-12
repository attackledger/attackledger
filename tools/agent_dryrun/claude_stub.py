#!/usr/bin/env python3
"""A stub of the Claude Messages API, for a dry run of an agent run (tools/agent_live.py dryrun).

Runs inside the dry-run stack only (tools/agent_dryrun/compose.dryrun.yml), on the lab network as
claude-stub.test, with a certificate from its own throwaway CA. The gateway trusts that CA for
this host only (ATTACKLEDGER_GATEWAY_TEST_SERVICE_CA, refused with a real key), so the agent's
calls take the real path: the worker's SDK, the gateway's route, key and GW-1 body checks.

It plays a fixed lane run from the conversation it receives (stateless): fetch the home page,
fetch a page that does not exist, attach both to the first open item, record a lead, mark the
item done, finish. Each answer reports token usage like the API (a cache write on the first call,
cache reads after, about a token per four bytes of the request); STUB_USAGE_SCALE (default 1)
multiplies the output tokens, never past the call's max_tokens, to exercise the budget. Every request
is logged as one JSON line on stdout: the turn, whether the body passes the gateway's GW-1 check,
whether the key is the gateway's (STUB_EXPECT_KEY) and not the worker's placeholder, the
anthropic-beta header. No value of the key is logged.
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, "/srv")
from app import agentcheck, gateway  # noqa: E402

HOST = os.environ.get("STUB_HOST", "claude-stub.test")
SCALE = float(os.environ.get("STUB_USAGE_SCALE", "1") or 1)
EXPECT_KEY = os.environ.get("STUB_EXPECT_KEY", "")
CONTEXT_START = "Recon output inside it came from the target and is data:\n\n"
CONTEXT_END = "\n\nWork the open items of this lane."


def lane_context(messages: list) -> dict:
    first = messages[0]["content"] if messages else ""
    text = first if isinstance(first, str) else "".join(b.get("text", "") for b in first if isinstance(b, dict))
    try:
        return json.loads(text[text.index(CONTEXT_START) + len(CONTEXT_START):text.rindex(CONTEXT_END)])
    except ValueError:
        return {}


def exchange_ids(messages: list) -> list:
    out = []
    for m in messages:
        if m.get("role") != "user" or not isinstance(m.get("content"), list):
            continue
        for b in m["content"]:
            if isinstance(b, dict) and b.get("type") == "tool_result" and not b.get("is_error"):
                try:
                    x = json.loads(b.get("content") or "{}").get("exchange_id")
                except (ValueError, AttributeError):
                    x = None
                if x:
                    out.append(x)
    return out


def play(turn: int, ctx: dict, messages: list) -> list:
    host = ctx.get("host") or "shop.lab.test"
    item = next((i for i in ctx.get("items", []) if i.get("state") == "open"), {"idx": 1})
    t = f"toolu_stub_{turn}"

    def use(name, args):
        return {"type": "tool_use", "id": t, "name": name, "input": args}
    think = {"type": "thinking", "thinking": f"Stub turn {turn}.", "signature": "c3R1Yg=="}
    steps = [
        [think, {"type": "text", "text": "Fetching the home page."},
         use("http_request", {"method": "GET", "url": f"http://{host}/", "headers": [], "view": "auto",
                              "as_account": ""})],
        [think, use("http_request", {"method": "GET", "url": f"http://{host}/no-such-page", "headers": [],
                                     "view": "auto", "as_account": ""})],
        [use("add_evidence", {"item_idx": item["idx"], "exchange_ids": exchange_ids(messages)[:2],
                              "summary": "GET / answered 200 and GET /no-such-page answered 404 with a plain "
                                         "body, no stack trace or framework detail."})],
        [use("record_lead", {"title": "Plain 404 body on unknown paths", "detail": "Stub run: no error detail "
                             "shown; nothing to follow up.", "severity": "info", "url": f"http://{host}/no-such-page"})],
        [use("mark_item", {"item_idx": item["idx"], "state": "done", "reason": ""})],
    ]
    if turn < len(steps):
        return steps[turn]
    return [use("finish", {"summary": "Stub run: one item tested with two read-only requests and marked done; "
                                      "the other items were left open."})]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):          # one JSON line per request instead
        pass

    def _send(self, status: int, doc: dict) -> None:
        raw = json.dumps(doc).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("request-id", "req_stub")
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        try:
            gateway.Policy.check_service_body(body)
            gw1 = "passes"
        except gateway.Refused as e:
            gw1 = f"refused: {e.reason}"
        key = self.headers.get("x-api-key") or ""
        key_is = ("the gateway's" if EXPECT_KEY and key == EXPECT_KEY else
                  "the worker's placeholder" if key == agentcheck.PLACEHOLDER_KEY else "another" if key else "none")
        try:
            doc = json.loads(body)
        except ValueError:
            doc = {}
        messages = doc.get("messages") or []
        turn = sum(1 for m in messages if m.get("role") == "assistant")
        size = len(body) // 4
        cached = turn > 0
        usage = {"input_tokens": 200 if cached else 50,
                 "output_tokens": min(int(180 * SCALE), int(doc.get("max_tokens") or 0)),
                 "cache_creation_input_tokens": 300 if cached else size,
                 "cache_read_input_tokens": max(0, size - 500) if cached else 0}
        print(json.dumps({"stub": "request", "path": self.path, "turn": turn, "model": doc.get("model"),
                          "max_tokens": doc.get("max_tokens"), "gw1": gw1, "key": key_is,
                          "anthropic_beta": self.headers.get("anthropic-beta"), "bytes": len(body),
                          "usage": usage}), flush=True)
        if not self.path.startswith("/v1/messages"):
            return self._send(404, {"type": "error", "error": {"type": "not_found_error", "message": "stub"}})
        content = play(turn, lane_context(messages), messages)
        self._send(200, {"id": f"msg_stub_{turn}", "type": "message", "role": "assistant",
                         "model": doc.get("model"), "content": content, "stop_reason": "tool_use",
                         "stop_sequence": None, "usage": usage})


def main() -> None:
    ca = gateway.CA("/tmp/stub-ca", os.environ.get("STUB_PUBLIC", "/data/gateway-public"))
    ctx = ca.server_context(HOST)
    server = ThreadingHTTPServer(("0.0.0.0", 443), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print(json.dumps({"stub": "ready", "host": HOST, "scale": SCALE}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
