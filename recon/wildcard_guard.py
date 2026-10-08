#!/usr/bin/env python3
"""
wildcard_guard.py <root_dir> [--write]

Finds WILDCARD DNS zones among the resolved hosts of a recon run and flags which
hosts only appear to "resolve" because of the wildcard.

WHY: in a wildcard zone ANY made-up name resolves, so the "resolved" signal carries
no information; counts inflate and a single DNS record looks like hundreds of
separate findings. A large share of candidates in one zone can be
the same *.sub.internal.example.com wildcard -- one record, not many findings.

METHOD
  1. Derive every parent zone from the resolved hosts (a.b.c.d -> b.c.d, c.d).
  2. Ask each zone for 3 random names. If all resolve and return the SAME IP set,
     the zone is a wildcard; the IP set is recorded.
     (3 names: one name could be real by chance; 3 at once cannot.)
  3. If a host's IP set EQUALS the set of a wildcard zone above it, the host is
     flagged "wildcard only".

It does NOT delete. It flags. A host that resolves to the wildcard IP can still be
real and may return different content in httpx -- decide from alive/httpx data,
not from DNS.

Output (into the root dir with --write):
  wildcard_zones.txt   <zone>\t<ip,ip,ip>
  wildcard_hosts.txt   wildcard-only hosts
"""
import sys, os, re, random, string, subprocess
from collections import defaultdict

PROBE = 3          # random names per zone
MIN_HOST = 3       # minimum hosts needed to test a zone
MAX_ZONE = 60      # cap the number of DNS queries


def resolve(name):
    """Return the A records as a set; on error/empty -> empty set."""
    try:
        r = subprocess.run(["dig", "+short", "+time=2", "+tries=1", "A", name],
                           capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        return frozenset()
    return frozenset(x.strip() for x in r.stdout.split()
                     if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", x.strip()))


def random_label(n=14):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def main():
    if len(sys.argv) < 2:
        print(__doc__.strip()); sys.exit(1)
    root = sys.argv[1]
    write = "--write" in sys.argv

    st = os.path.join(root, ".pipeline_state")
    date = None
    if os.path.isfile(st):
        for line in open(st, encoding="utf-8", errors="replace"):
            if line.startswith("DATE="):
                date = line.strip().split("=", 1)[1]
    if not date:
        print(f"[-] no DATE in {st}"); sys.exit(1)

    src = os.path.join(root, "subdomains", f"resolved_inscope_{date}.txt")
    if not os.path.isfile(src):
        src = os.path.join(root, "subdomains", f"resolved_{date}.txt")
    if not os.path.isfile(src):
        print(f"[-] resolved-hosts file missing: {src}"); sys.exit(1)

    hosts = [l.strip().lower().rstrip(".") for l in
             open(src, encoding="utf-8", errors="replace") if l.strip()]
    print(f"[+] read {len(hosts)} hosts: {os.path.basename(src)}")

    # zone candidates: all parent levels of each host, keeping those with at least MIN_HOST hosts
    counts = defaultdict(int)
    for h in hosts:
        p = h.split(".")
        for i in range(1, len(p) - 1):
            counts[".".join(p[i:])] += 1
    zones = [z for z, n in sorted(counts.items(), key=lambda x: -x[1])
                if n >= MIN_HOST][:MAX_ZONE]
    print(f"[+] {len(zones)} zones to test ({PROBE} random names/zone)")

    wildcard = {}
    for z in zones:
        answer_sets = [resolve(f"{random_label()}.{z}") for _ in range(PROBE)]
        if all(k for k in answer_sets) and len(set(answer_sets)) == 1:
            wildcard[z] = answer_sets[0]
            print(f"    WILDCARD  {z}  -> {','.join(sorted(answer_sets[0]))}")

    # Zones UNDER a wildcard zone inevitably look like wildcards too (if *.a.b.X is
    # a wildcard, x.y.a.b.X also resolves). They are not separate findings, only the
    # shadow of the same record. Keep the shallowest, drop the children.
    roots_ = sorted(wildcard, key=lambda z: z.count("."))
    simplified = {}
    for z in roots_:
        parent = next((k for k in simplified
                    if z.endswith("." + k) and wildcard[z] == simplified[k]), None)
        if parent is None:
            simplified[z] = wildcard[z]
    shadow = len(wildcard) - len(simplified)
    if shadow:
        print(f"    ({shadow} sub-zones, shadows of the wildcard above -- dropped)")
    wildcard = simplified

    if not wildcard:
        print("[+] NO wildcard zones -- the resolution signal is reliable.")
        if write:
            open(os.path.join(root, "wildcard_zones.txt"), "w").close()
            open(os.path.join(root, "wildcard_hosts.txt"), "w").close()
        return

    # wildcard-only hosts: own IP set equals the wildcard set above them
    only_wc = []
    for h in hosts:
        for z, ips in wildcard.items():
            if h == z or h.endswith("." + z):
                if resolve(h) == ips:
                    only_wc.append(h)
                break

    print(f"\n[!] {len(wildcard)} wildcard zones - {len(only_wc)}/{len(hosts)} hosts "
          f"resolve ONLY because of the wildcard")
    print("    These were not deleted -- one that returns different content in httpx may be real.")
    print("    But do not claim 'exists' from DNS alone, and do not count them one by one.")
    print()
    print("    A WILDCARD BEHIND A CDN IS A SEPARATE CASE (CloudFront/Cloudflare):")
    print("    the IPs are edge nodes and do not say whether the host exists. The")
    print("    distinguishing signal is the RESPONSE BODY -- CloudFront's 'ERROR: The request could")
    print("    not be satisfied' page means there is NO distribution for that name.")
    print("    So in these zones the decision is made from httpx output, not DNS.")

    if write:
        with open(os.path.join(root, "wildcard_zones.txt"), "w") as f:
            for z, ips in sorted(wildcard.items()):
                f.write(f"{z}\t{','.join(sorted(ips))}\n")
        with open(os.path.join(root, "wildcard_hosts.txt"), "w") as f:
            for h in sorted(only_wc):
                f.write(h + "\n")
        print(f"[+] written: {root}/wildcard_zones.txt - wildcard_hosts.txt")


if __name__ == "__main__":
    main()
