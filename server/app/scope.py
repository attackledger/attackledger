"""Scope rules. Fail-closed: a host is in scope only if an include rule matches
and no exclude rule does. Unknown hosts are out of scope.

Pattern forms:
  app.example.com     exact host
  *.example.com       any subdomain of example.com, NOT the apex itself
                      (list example.com separately if the program includes it)
"""
import re

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_HOST_RE = re.compile(rf"^{_LABEL}(\.{_LABEL})+$")


class ScopeError(ValueError):
    pass


def normalize_host(host: str) -> str:
    h = host.strip().lower().rstrip(".")
    if "://" in h:
        raise ScopeError(f"expected a host, got a URL: {host}")
    if not _HOST_RE.match(h):
        raise ScopeError(f"not a valid host name: {host}")
    return h


def normalize_pattern(pattern: str) -> str:
    p = pattern.strip().lower().rstrip(".")
    if p.startswith("*."):
        normalize_host(p[2:])
        return p
    if "*" in p:
        raise ScopeError(f"only leading '*.' wildcards are supported: {pattern}")
    return normalize_host(p)


def matches(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        return host.endswith(pattern[1:])  # ".example.com" suffix; apex excluded
    return host == pattern


def in_scope(host: str, include: list[str], exclude: list[str]) -> bool:
    try:
        h = normalize_host(host)
    except ScopeError:
        return False
    if any(matches(p, h) for p in exclude):
        return False
    return any(matches(p, h) for p in include)
