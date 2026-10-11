"""Scope rules. Fail-closed: a host is in scope only if an include rule matches
and no exclude rule does. Unknown hosts are out of scope.

Pattern forms:
  app.example.com     exact host
  *.example.com       any subdomain of example.com, NOT the apex itself
                      (list example.com separately if the program includes it)
"""
import re

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
# fullmatch, not "$": "$" also matches before a final line end, which let "admin.example.com\n"
# through as a host name, and an exclude rule written that way excluded nothing (fuzzing, FZ-4).
_HOST_RE = re.compile(rf"{_LABEL}(\.{_LABEL})+")
_TRAILING = re.compile(r"[\s.]+\Z")          # dots and spaces at the end, in any order: "x.com\n."


class ScopeError(ValueError):
    pass


def normalize_host(host: str) -> str:
    h = _TRAILING.sub("", host.strip().lower())
    if "://" in h:
        raise ScopeError(f"expected a host, got a URL: {host}")
    if not _HOST_RE.fullmatch(h):
        raise ScopeError(f"not a valid host name: {host}")
    return h


def normalize_pattern(pattern: str) -> str:
    p = _TRAILING.sub("", pattern.strip().lower())
    if p.startswith("*."):
        return "*." + normalize_host(p[2:])
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
