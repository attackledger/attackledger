#!/usr/bin/env python3
"""
js_analyze.py -- recon pipeline module 8b.
Reads a JS URL list from stdin; for each file:
  - endpoint / path extraction (LinkFinder-style regex)
  - sourcemap detection + fetching the .map and reporting the source tree / embedded source (sourcesContent)
  - GraphQL operation names (query/mutation/subscription + gql`` templates)
No external dependencies (stdlib only). Bounded: max files, max size, short timeout.
Output into --outdir: js_endpoints.txt, js_endpoints_abs.txt, js_sourcemaps.txt, js_graphql_ops.txt
"""
import sys, os, re, json, argparse, urllib.request, urllib.parse, ssl

MAX_FILES = 250
MAX_BYTES = 5 * 1024 * 1024
TIMEOUT = 15

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

UA = os.environ.get("RESEARCH_USER_AGENT") or "Mozilla/5.0 (recon js_analyze)"
HDR = os.environ.get("RESEARCH_HEADER", "").strip()

# LinkFinder's endpoint regex (simplified)
ENDPOINT_RE = re.compile(r"""
  (?:"|')                                  # opening quote
  (
    (?:https?://[^"'<>\s]{4,})              # full URL
    |
    (?:/[a-zA-Z0-9_?&=/\-\#\.]{2,})         # root-relative path
    |
    (?:[a-zA-Z0-9_\-/]+/[a-zA-Z0-9_\-/]+\.(?:php|asp|aspx|jsp|json|do|action|api)(?:\?[^"'<>\s]*)?)
  )
  (?:"|')                                  # closing quote
""", re.VERBOSE)

GQL_OP_RE = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)\s*[\(\{]")
GQL_TAG_RE = re.compile(r"(?:gql|graphql)\s*`([^`]{0,4000})`", re.DOTALL)
SMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")


def fetch(url, want_bytes=MAX_BYTES):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    if HDR and ":" in HDR:
        k, v = HDR.split(":", 1)
        req.add_header(k.strip(), v.strip())
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=CTX) as r:
        return r.read(want_bytes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", required=True)
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    urls = []
    for line in sys.stdin:
        u = line.strip()
        if u.startswith("http") and u not in urls:
            urls.append(u)
        if len(urls) >= MAX_FILES:
            break

    endpoints = set()
    endpoints_abs = set()
    smap_report = []
    gql_ops = set()

    for u in urls:
        try:
            body = fetch(u)
        except Exception:
            continue
        try:
            text = body.decode("utf-8", "replace")
        except Exception:
            continue

        base = urllib.parse.urlparse(u)
        for m in ENDPOINT_RE.finditer(text):
            e = m.group(1).strip()
            if not e or len(e) > 400:
                continue
            endpoints.add(e)
            if e.startswith("http"):
                p = urllib.parse.urlparse(e)
                if p.hostname == base.hostname:
                    endpoints_abs.add(e)
            elif e.startswith("/") and not e.startswith("//"):
                endpoints_abs.add(f"{base.scheme}://{base.netloc}{e}")

        for m in GQL_OP_RE.finditer(text):
            gql_ops.add(f"{m.group(1)} {m.group(2)}\t{u}")
        for m in GQL_TAG_RE.finditer(text):
            for mm in GQL_OP_RE.finditer(m.group(1)):
                gql_ops.add(f"{mm.group(1)} {mm.group(2)}\t{u}")

        sm = SMAP_RE.search(text)
        if sm:
            ref = sm.group(1)
            if ref.startswith("data:"):
                smap_report.append(f"{u}\t-> INLINE data: URI sourcemap (sourcesContent embedded)")
            else:
                map_url = urllib.parse.urljoin(u, ref)
                try:
                    mb = fetch(map_url)
                    mj = json.loads(mb.decode("utf-8", "replace"))
                    srcs = mj.get("sources", []) or []
                    has_content = bool(mj.get("sourcesContent"))
                    smap_report.append(
                        f"{u}\t-> {map_url}\tsourcesContent={'YES' if has_content else 'no'}\tsources={len(srcs)}"
                    )
                    for s in srcs[:400]:
                        smap_report.append(f"    {s}")
                except Exception:
                    smap_report.append(f"{u}\t-> {map_url}\t(could not fetch / invalid)")

    def dump(name, lines):
        with open(os.path.join(args.outdir, name), "w") as f:
            f.write("\n".join(lines))
            if lines:
                f.write("\n")

    dump("js_endpoints.txt", sorted(endpoints))
    dump("js_endpoints_abs.txt", sorted(endpoints_abs))
    dump("js_graphql_ops.txt", sorted(gql_ops))
    dump("js_sourcemaps.txt", smap_report)


if __name__ == "__main__":
    main()
