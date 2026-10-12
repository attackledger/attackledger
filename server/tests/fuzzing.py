"""Seeded mutation fuzzing with the standard library (docs/security-review/FUZZING.md).

No third-party fuzzer: the default test run stays offline and fast, and every input a test
tries comes from a fixed seed, so a failure is reproduced by running the same test again.

    ATTACKLEDGER_FUZZ_ITERATIONS=5000   inputs per fuzz test (default: each test's own, small)
    ATTACKLEDGER_FUZZ_SEED=7            another seed (default 20261010)

A failure names the seed, the iteration and a short repr of the input. Each one found so far
was minimised by hand and kept as a deterministic test in test_security_fuzz.py.
"""
import contextlib
import datetime as _dt
import json
import os
import random
import signal
import time

SEED = int(os.environ.get("ATTACKLEDGER_FUZZ_SEED") or 20261010)
ITERATIONS = int(os.environ.get("ATTACKLEDGER_FUZZ_ITERATIONS") or 0)


# What the report fuzz pins report.datetime and seal.datetime to. It must come after every real event
# the test records (a seal key registered, an audit entry), or the seal's key looks registered after
# the report was sealed: a fixed date did that the day after it was written. Fixed for the run, so
# the report is the same bytes in every process (passed to them in ATTACKLEDGER_TEST_FIXED_NOW).
FIXED_NOW = (_dt.datetime.fromisoformat(os.environ["ATTACKLEDGER_TEST_FIXED_NOW"])
             if os.environ.get("ATTACKLEDGER_TEST_FIXED_NOW") else
             (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(hours=2)).replace(minute=0, second=0, microsecond=0))


def fixed_clock() -> type:
    """A datetime whose now() is FIXED_NOW (its wall-clock fields, in the zone asked for)."""
    class Fixed(_dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return FIXED_NOW.replace(tzinfo=tz)
    return Fixed


def iterations(default: int) -> int:
    return ITERATIONS or default


def rng(name: str) -> random.Random:
    """One generator per test, so adding a test does not change the inputs of another."""
    return random.Random(f"{SEED}:{name}")


class TooSlow(AssertionError):
    pass


@contextlib.contextmanager
def time_limit(seconds: float, what: str = "input"):
    """Fail if the block takes longer than `seconds`. SIGALRM interrupts a regular expression
    match too (Python 3.12), so a catastrophic backtrack fails the test instead of hanging it."""
    def expired(*_):
        raise TooSlow(f"{what} took more than {seconds} s")
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def elapsed(f, *a, **k):
    start = time.perf_counter()
    out = f(*a, **k)
    return out, time.perf_counter() - start


def show(data, n: int = 1500) -> str:
    r = repr(data)
    return r if len(r) <= n else r[:n] + f"... ({len(data)} long)"


# ---- bytes ------------------------------------------------------------------------------------

INTERESTING = [b"\x00", b"\xff", b"\xfe", b'"', b"'", b"\\", b"\\u0000", b"\\ud800", b"\r", b"\n", b"\r\n",
               b"\r\n\r\n", b"<", b">", b"&", b"]]>", b"<![CDATA[", b"<!--", b"{", b"}", b"[", b"]", b",", b":",
               b"1e400", b"-1e400", b"-0", b"NaN", b"Infinity", b"9" * 5000, b"0.5", b"\xef\xbb\xbf",
               b"\xed\xa0\x80", b"\xc3\x28", b"\xe2\x80\xae", b"%00", b"%2e%2e/", b"@", b"#", b"?", b"=", b";",
               b"null", b"true", b"[]", b"{}", b"A" * 70_000]


def mutate_bytes(r: random.Random, data: bytes, rounds: int | None = None) -> bytes:
    """Byte flips, inserted tokens, deleted and duplicated spans, and splices of the input."""
    b = bytearray(data)
    for _ in range(rounds or r.randint(1, 4)):
        op = r.randrange(6)
        i = r.randrange(len(b) + 1)
        if op == 0 and b:                                   # flip bits
            j = min(i, len(b) - 1)
            b[j] ^= 1 << r.randrange(8)
        elif op == 1:                                       # insert a token
            b[i:i] = r.choice(INTERESTING)
        elif op == 2 and b:                                 # delete a span
            del b[i:i + r.randint(1, 64)]
        elif op == 3 and b:                                 # duplicate a span
            span = bytes(b[i:i + r.randint(1, 256)])
            b[i:i] = span * r.randint(1, 8)
        elif op == 4 and b:                                 # overwrite with a random byte
            b[min(i, len(b) - 1)] = r.randrange(256)
        else:                                               # splice a part of the input elsewhere
            j = r.randrange(len(b) + 1)
            b[i:i] = b[j:j + r.randint(1, 512)]
    return bytes(b)


# ---- JSON trees -------------------------------------------------------------------------------

class Obj(list):
    """A JSON object as its (key, value) pairs, so duplicate keys and order survive."""


class Raw(str):
    """A JSON number written exactly as given (1e400, -0, 1E2, a 5,000-digit integer)."""


def loads(text: str):
    return json.loads(text, object_pairs_hook=Obj)


NUMBERS = ["0", "-0", "1", "1.0", "1e0", "1E2", "-1", "0.1", "1e-7", "5e-324", "1e308", "1e400", "-1e400",
           "9007199254740993", "12345678901234567890123", "1" + "0" * 4400, "200", "200.5", "599", "65535",
           "65536", "1791540000000", "-1791540000000", "1e20"]
STRINGS = ["", " ", "a", "\x00", "\ud800", "\U0001F600", "‮", "é", "\r\n", "../../etc/passwd", "*.", ".",
           "[::1]", "http://", "https://shop.example.com/", "https://shop.example.com\\@evil.example.net/",
           "https://user:pw@shop.example.com/", "HTTP/9.9", "GET", "get", "CONNECT", "x" * 5000, "true", "1e400",
           "QUJD", "=", "QQ", "2026-10-09T15:26:05Z", "9999-99-99", "None", "NaN"]


def value(r: random.Random, depth: int = 0):
    k = r.randrange(9 if depth < 3 else 6)
    if k == 0:
        return None
    if k == 1:
        return r.choice([True, False])
    if k in (2, 3):
        return Raw(r.choice(NUMBERS))
    if k in (4, 5):
        return r.choice(STRINGS)
    if k == 6:
        return [value(r, depth + 1) for _ in range(r.randint(0, 3))]
    if k == 7:
        return Obj((r.choice(STRINGS[:6] + ["id", "url", "raw", "host"]), value(r, depth + 1))
                   for _ in range(r.randint(0, 3)))
    return "x" * r.choice([1, 100, 10_000])


def _nodes(tree, path=()):
    yield path, tree
    if isinstance(tree, Obj):
        for i, (_, v) in enumerate(tree):
            yield from _nodes(v, path + (i,))
    elif isinstance(tree, list):
        for i, v in enumerate(tree):
            yield from _nodes(v, path + (i,))


def _get(tree, path):
    for i in path:
        tree = tree[i][1] if isinstance(tree, Obj) else tree[i]
    return tree


def _set(tree, path, new):
    parent = _get(tree, path[:-1])
    i = path[-1]
    if isinstance(parent, Obj):
        parent[i] = (parent[i][0], new)
    else:
        parent[i] = new


def mutate_tree(r: random.Random, tree, rounds: int | None = None):
    """Change values (type, number format, size), delete, duplicate or reorder keys, and
    wrap or unwrap values. The tree is changed in place and returned."""
    for _ in range(rounds or r.randint(1, 3)):
        nodes = list(_nodes(tree))
        path, node = r.choice(nodes)
        op = r.randrange(7)
        if op <= 2 and path:
            _set(tree, path, value(r))
        elif op == 3 and isinstance(node, Obj) and node:
            del node[r.randrange(len(node))]
        elif op == 4 and isinstance(node, Obj) and node:
            k, v = node[r.randrange(len(node))]
            node.insert(r.randrange(len(node) + 1), (k, value(r) if r.random() < 0.5 else v))   # duplicate key
        elif op == 5 and isinstance(node, list) and len(node) > 1:
            r.shuffle(node)
        elif path:
            _set(tree, path, [node] if r.random() < 0.5 else Obj([("value", node)]))
    return tree


def dumps(tree, r: random.Random | None = None) -> str:
    """JSON text for a tree; with a generator, some characters become \\u escapes and the
    spacing varies (both mean the same JSON)."""
    def s(x: str) -> str:
        if r is None or r.random() < 0.7:
            return json.dumps(x)
        return '"' + "".join(f"\\u{ord(c):04x}" if ord(c) < 0x10000 and r.random() < 0.3
                             else json.dumps(c)[1:-1] for c in x) + '"'

    def go(t) -> str:
        sep = (r.choice([",", ", ", ",\n  "]) if r else ",")
        if isinstance(t, Obj):
            return "{" + sep.join(f"{s(k)}:{go(v)}" for k, v in t) + "}"
        if isinstance(t, list):
            return "[" + sep.join(go(v) for v in t) + "]"
        if isinstance(t, Raw):
            return str(t)
        if isinstance(t, str):
            return s(t)
        if isinstance(t, bool) or t is None:
            return json.dumps(t)
        if isinstance(t, float) and t != t:
            return "NaN"
        return json.dumps(t)
    return go(tree)


def mutate_json(r: random.Random, text: str) -> bytes:
    """A structural mutation of JSON text, then sometimes a byte-level one on top."""
    out = dumps(mutate_tree(r, loads(text)), r).encode("utf-8", "surrogatepass")
    return mutate_bytes(r, out, 1) if r.random() < 0.2 else out
