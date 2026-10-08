"""JavaScript analysis (pipeline module 8): endpoints, GraphQL operations,
sourcemaps and secret candidates from JS files.

Ported from the original js_analyze.py and secret_triage.py. Secret candidates
are sorted into three buckets, REAL / PUBLIC (by design) / NOISE, with REAL
patterns checked first. Matching noise first would drop a real-shaped token
that happens to contain a filler pattern.

Secrets are never stored in full and never tested against any service: only a
masked preview, a SHA-256 of the value and where it was found are kept.
"""
import hashlib
import re
from urllib.parse import urljoin, urlsplit

# LinkFinder-style endpoint regex (simplified), as in js_analyze.py.
ENDPOINT_RE = re.compile(r"""
  (?:"|'|`)
  (
    (?:https?://[^"'`<>\s]{4,})
    |
    (?:/[a-zA-Z0-9_?&=/\-\#\.]{2,})
    |
    (?:[a-zA-Z0-9_\-/]+/[a-zA-Z0-9_\-/]+\.(?:php|asp|aspx|jsp|json|do|action|api)(?:\?[^"'`<>\s]*)?)
  )
  (?:"|'|`)
""", re.VERBOSE)

GQL_OP_RE = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)\s*[\(\{]")
GQL_TAG_RE = re.compile(r"(?:gql|graphql)\s*`([^`]{0,4000})`", re.DOTALL)
SMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")

# Published in the client on purpose: finding one is not a finding.
PUBLIC_BY_DESIGN = [
    (r"\bpk_(?:live|test)_[0-9A-Za-z]{10,}", "Stripe publishable key"),
    (r"\bAIza[0-9A-Za-z_\-]{35}", "Google API key (check its restrictions separately)"),
    (r"\bkey_(?:live|test)_[0-9A-Za-z]{10,}", "Branch.io client key"),
    (r"https://[0-9a-f]{32}@[\w.\-]*sentry\.io/\d+", "Sentry DSN"),
    (r"\d+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "Google OAuth client id"),
    (r"\b6L[0-9A-Za-z_\-]{38}\b", "reCAPTCHA site key"),
    (r"\bpk\.eyJ[0-9A-Za-z_\-\.]{20,}", "Mapbox public token"),
    (r"\bphc_[0-9A-Za-z]{40,}", "PostHog project key"),
]

# Must never reach the client. If one did, it is a finding candidate.
REAL = [
    (r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}", "critical", "Stripe secret or restricted live key"),
    (r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "critical", "AWS access key id"),
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", "critical", "Private key"),
    (r'"type"\s*:\s*"service_account"', "critical", "GCP service account JSON"),
    (r"\bxox[baprs]-[0-9A-Za-z\-]{10,}", "high", "Slack token"),
    (r"\b(?:ghp|ghs|gho|ghu)_[0-9A-Za-z]{36}\b", "high", "GitHub token"),
    (r"\bgithub_pat_[0-9A-Za-z_]{80,}", "high", "GitHub fine-grained token"),
    (r"\bSG\.[0-9A-Za-z_\-]{20,}\.[0-9A-Za-z_\-]{20,}", "high", "SendGrid API key"),
    (r"\bSK[0-9a-f]{32}\b", "high", "Twilio API key sid"),
    (r"\bsk\.eyJ[0-9A-Za-z_\-\.]{20,}", "high", "Mapbox secret token"),
    (r"\bnpm_[0-9A-Za-z]{36}\b", "high", "npm token"),
    (r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/\"']+:[^\s@/\"']+@[^\s\"']+",
     "critical", "Database or broker URI with credentials"),
    (r"\bglpat-[0-9A-Za-z_\-]{20}\b", "high", "GitLab token"),
    (r"\bdop_v1_[0-9a-f]{64}\b", "high", "DigitalOcean token"),
    (r"\bshpat_[0-9a-f]{32}\b", "high", "Shopify admin token"),
]

# Measured noise: template values and filler that look like secrets.
NOISE = [
    r"\b(?:example|sample|dummy|fake|placeholder|your[_-]?key|xxx+|changeme)\b",
    r"\b0{8,}\b|abcdef0123",
]

_REAL = [(re.compile(p), sev, why) for p, sev, why in REAL]
_PUBLIC = [(re.compile(p), why) for p, why in PUBLIC_BY_DESIGN]
_NOISE = [re.compile(p, re.I) for p in NOISE]


def mask(value: str) -> str:
    v = value.strip()
    if len(v) <= 12:
        return v[:2] + "…"
    return f"{v[:4]}…{v[-4:]}"


def scan_secrets(text: str) -> list[dict]:
    """Secret candidates in a JS body: bucket, severity, kind, masked preview, hash.

    REAL patterns run first, then PUBLIC. A REAL-shaped match is downgraded to
    NOISE only when the text around it is plainly a template or example value.
    """
    out, seen = [], set()
    for rx, sev, why in _REAL:
        for m in rx.finditer(text):
            val = m.group(0)
            ctx = text[max(0, m.start() - 40): m.end() + 40]
            bucket = "noise" if any(n.search(ctx) for n in _NOISE) else "real"
            key = (why, val)
            if key not in seen:
                seen.add(key)
                out.append({"bucket": bucket, "severity": sev if bucket == "real" else "",
                            "kind": why, "preview": mask(val),
                            "value_sha256": hashlib.sha256(val.encode()).hexdigest()})
    for rx, why in _PUBLIC:
        for m in rx.finditer(text):
            val = m.group(0)
            key = (why, val)
            if key not in seen:
                seen.add(key)
                out.append({"bucket": "public", "severity": "", "kind": why, "preview": mask(val),
                            "value_sha256": hashlib.sha256(val.encode()).hexdigest()})
    return out


def extract_endpoints(text: str, js_url: str) -> list[str]:
    """Absolute URLs for endpoints referenced in a JS file, on the file's own host."""
    base = urlsplit(js_url)
    found = set()
    for m in ENDPOINT_RE.finditer(text):
        e = m.group(1).strip()
        if not e or len(e) > 400:
            continue
        if e.startswith(("http://", "https://")):
            url = e
        elif e.startswith("//"):
            continue  # protocol-relative: another host more often than not
        elif e.startswith("/"):
            url = f"{base.scheme}://{base.netloc}{e}"
        elif "/" in e and not e.startswith("."):
            url = urljoin(js_url, e)
        else:
            continue
        # Whatever the form, keep only what resolves to the file's own host.
        if urlsplit(url).hostname == base.hostname:
            found.add(url)
    return sorted(found)


def graphql_operations(text: str) -> list[str]:
    ops = {f"{m.group(1)} {m.group(2)}" for m in GQL_OP_RE.finditer(text)}
    for m in GQL_TAG_RE.finditer(text):
        ops |= {f"{mm.group(1)} {mm.group(2)}" for mm in GQL_OP_RE.finditer(m.group(1))}
    return sorted(ops)


def sourcemap_ref(text: str, js_url: str) -> str | None:
    """'inline', an absolute .map URL, or None."""
    m = SMAP_RE.search(text)
    if not m:
        return None
    ref = m.group(1)
    if ref.startswith("data:"):
        return "inline"
    return urljoin(js_url, ref)
