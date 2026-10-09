#!/usr/bin/env python3
"""A byte-for-byte TCP relay that logs every HTTP request head it relays (benchmark only).

The benchmark puts it in front of Juice Shop as juice.lab.test:3000, so every request the
recon tools and the agent send can be counted per step, checked for the research
identification and checked against the rate limit. Bytes are relayed unchanged in both
directions: response headers, status codes and bodies are exactly what Juice Shop sends.

Each log line is JSON:
  {"t": epoch seconds, "conn": n, "event": "connect"}
  {"t": ..., "conn": n, "event": "request", "method": "GET", "target": "/x",
   "ua": "...", "research": "...", "headers": [names]}
  {"t": ..., "conn": n, "event": "non-http", "first_bytes": "16 03 01"}   (TLS, port probes)

Standard library only. Usage:
  countproxy.py --listen 3000 --upstream juice:3000 --log /tmp/requests.jsonl
"""
import argparse
import asyncio
import json
import re
import time

METHOD_RE = re.compile(rb"^[A-Z]{3,10} \S+ HTTP/\d\.\d$")
MAX_HEAD = 64 * 1024


class Log:
    def __init__(self, path: str, research_header: str):
        self.f = open(path, "a", buffering=1)
        self.research = research_header.lower()

    def write(self, **rec) -> None:
        rec.setdefault("t", round(time.time(), 4))
        self.f.write(json.dumps(rec, ensure_ascii=False) + "\n")


class RequestParser:
    """Follows the client side of one connection and logs each request head."""

    def __init__(self, log: Log, conn: int):
        self.log, self.conn = log, conn
        self.buf = b""
        self.skip = 0           # body bytes still to pass before the next head
        self.dead = False       # stopped parsing (non-HTTP, chunked body, oversized head)

    def feed(self, data: bytes) -> None:
        if self.dead:
            return
        self.buf += data
        while not self.dead:
            if self.skip:
                n = min(self.skip, len(self.buf))
                self.buf, self.skip = self.buf[n:], self.skip - n
                if self.skip:
                    return
            end = self.buf.find(b"\r\n\r\n")
            if end < 0:
                if len(self.buf) > MAX_HEAD or (self.buf and not self.buf[:1].isalpha()):
                    self._non_http()
                return
            head, self.buf = self.buf[:end], self.buf[end + 4:]
            lines = head.split(b"\r\n")
            if not METHOD_RE.match(lines[0]):
                self._non_http(lines[0][:8])
                return
            method, target, _ = lines[0].decode("latin-1").split(" ", 2)
            headers = {}
            names = []
            for raw in lines[1:]:
                name, _, value = raw.decode("latin-1").partition(":")
                names.append(name.strip())
                headers[name.strip().lower()] = value.strip()
            self.log.write(conn=self.conn, event="request", method=method, target=target,
                           ua=headers.get("user-agent"), research=headers.get(self.log.research),
                           headers=names)
            if "chunked" in headers.get("transfer-encoding", "").lower():
                self.dead = True   # not needed for this benchmark (no tool sends chunked bodies)
                return
            try:
                self.skip = int(headers.get("content-length", "0") or 0)
            except ValueError:
                self.dead = True

    def _non_http(self, first: bytes = b"") -> None:
        sample = first or self.buf[:8]
        self.log.write(conn=self.conn, event="non-http", first_bytes=sample.hex(" "))
        self.dead = True


async def pipe(reader, writer, parser=None):
    try:
        while data := await reader.read(65536):
            if parser:
                parser.feed(data)
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, default=3000)
    ap.add_argument("--upstream", default="juice:3000")
    ap.add_argument("--log", default="/tmp/requests.jsonl")
    ap.add_argument("--research-header", default="X-Bug-Bounty")
    args = ap.parse_args()
    up_host, up_port = args.upstream.rsplit(":", 1)
    log = Log(args.log, args.research_header)
    counter = 0

    async def handle(c_reader, c_writer):
        nonlocal counter
        counter += 1
        conn = counter
        log.write(conn=conn, event="connect")
        try:
            u_reader, u_writer = await asyncio.open_connection(up_host, int(up_port))
        except OSError as e:
            log.write(conn=conn, event="upstream-error", error=str(e)[:200])
            c_writer.close()
            return
        await asyncio.gather(pipe(c_reader, u_writer, RequestParser(log, conn)), pipe(u_reader, c_writer))

    server = await asyncio.start_server(handle, "0.0.0.0", args.listen)
    print(f"relaying :{args.listen} -> {args.upstream}, log {args.log}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
