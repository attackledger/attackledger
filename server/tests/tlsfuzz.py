"""TLS ClientHellos for the gateway's TLS fuzzing (docs/security-review/FUZZING.md, "Third pass").

A real ClientHello from Python's ssl, with its server name (SNI) and ALPN extensions replaced by
any bytes at all: an IP literal, an empty or overlong name, one that is not ASCII, a NUL, an ALPN
list without http/1.1. Built in memory (ssl.MemoryBIO); nothing is sent anywhere by this module.
"""
import socket
import ssl
import struct

PLACEHOLDER = "placeholder.example.com"


def client_hello(sni: bytes | None = b"app.example.com", alpn: list[bytes] | None = None, *,
                 tls13: bool = True) -> bytes:
    """One TLS record holding a ClientHello. sni None: no server name extension at all; alpn None:
    the extension as Python wrote it (none)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    if not tls13:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    if alpn is not None:
        ctx.set_alpn_protocols(["http/1.1"])        # a placeholder extension, replaced below
    out = ssl.MemoryBIO()
    obj = ctx.wrap_bio(ssl.MemoryBIO(), out, server_hostname=PLACEHOLDER)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    record = out.read()
    body = record[5 + 4:]                           # record header, handshake header
    i = 2 + 32                                      # version, random
    i += 1 + body[i]                                # session id
    i += 2 + struct.unpack("!H", body[i:i + 2])[0]  # cipher suites
    i += 1 + body[i]                                # compression methods
    head, n = body[:i], struct.unpack("!H", body[i:i + 2])[0]
    exts, j, kept = body[i + 2:i + 2 + n], 0, []
    while j < len(exts):
        kind, length = struct.unpack("!HH", exts[j:j + 4])
        data = exts[j + 4:j + 4 + length]
        j += 4 + length
        if kind == 0:                               # server_name
            if sni is None:
                continue
            name = struct.pack("!BH", 0, len(sni)) + sni
            data = struct.pack("!H", len(name)) + name
        elif kind == 16 and alpn is not None:       # application_layer_protocol_negotiation
            names = b"".join(bytes([len(p)]) + p for p in alpn)
            data = struct.pack("!H", len(names)) + names
        kept.append(struct.pack("!HH", kind, len(data)) + data)
    ext_bytes = b"".join(kept)
    hs_body = head + struct.pack("!H", len(ext_bytes)) + ext_bytes
    hs = b"\x01" + len(hs_body).to_bytes(3, "big") + hs_body
    return record[:3] + struct.pack("!H", len(hs)) + hs


SNIS = [b"app.example.com", b"APP.Example.COM", b"app.example.com.", b"192.0.2.10", b"[::1]", b"", b"a" * 64 + b".x",
        b"a" * 255, b"a" * 256, b"a" * 4000, "é.example.com".encode(), b"\xff\xfe", b"app\x00.example.com",
        b"evil.example.net", b"app.example.com\r\nHost: evil", b"*.example.com", b"xn--zz.example.com", None]
ALPNS = [None, [b"http/1.1"], [b"h2"], [b"h2", b"http/1.1"], [b""], [b"x" * 255] * 3, [b"h3"], [b"http/1.0"]]


def connect(port: int, auth: str, host: str = "app.example.com:443", timeout: float = 10) -> socket.socket:
    """A connection to the gateway on 127.0.0.1 with an open tunnel (the 200 read)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.sendall(f"CONNECT {host} HTTP/1.1\r\nHost: {host}\r\nProxy-Authorization: {auth}\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = s.recv(4096)
        if not chunk:
            break
        head += chunk
    assert head.startswith(b"HTTP/1.1 200"), head[:200]
    return s


def drain(s, timeout: float = 10) -> bytes:
    """Everything until the other side closes (or the time is up)."""
    s.settimeout(timeout)
    out = b""
    try:
        while chunk := s.recv(65536):
            out += chunk
    except (OSError, ssl.SSLError):
        pass
    return out
