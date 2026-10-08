#!/usr/bin/env python3
"""
Converts a scope CSV downloaded from HackerOne into the files run_pipeline.sh expects.

Usage:
    python3 csv_to_scope.py <h1_scope.csv> <outdir>

Produces (in outdir):
    scope.txt   -> for filter_scope(): exact hosts + "*.domain" wildcards (one per line)
    domains.txt -> for subfinder/pipeline arg1: root (registrable) domains derived from wildcards,
                   with shared third-party platform roots (s3.amazonaws.com, myshopify.com, ...) removed
    apps.txt    -> GOOGLE_PLAY_APP_ID / APPLE_STORE_APP_ID  (passed to run_pipeline.sh as APK_PACKAGES)
    cidrs.txt   -> CIDR / IP_RANGE  (feed to naabu by hand; filter_scope does no CIDR math)
    other.txt   -> SOURCE_CODE / HARDWARE / OTHER ... (review manually)

Rules:
- A row whose "eligible_for_submission" (or "eligible") column is False/No/0 is SKIPPED.
- A "*." prefix is KEPT for WILDCARD types (suffix match); URL types are written as exact hosts.
"""
import csv
import sys
import os
import re

DOMAIN_TYPES = {"URL", "WILDCARD", "API", "IP_ADDRESS"}
CIDR_TYPES = {"CIDR", "IP_RANGE"}
APP_TYPES = {"GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID", "OTHER_APK", "TESTFLIGHT"}

# Rows with asset_type=OTHER normally land in other.txt, but some programs list
# their MOST VALUABLE wildcards as OTHER (e.g. *.example.com, *.internal.example.net).
# To rescue them, a "does it look like a host" test: no scheme, no path, no spaces,
# at least one dot + an alphabetic TLD. This way "Billing Provider" / "Tier 3" stay in
# other.txt and "https://apps.example.org/some-app" is not mistaken for a domain and
# added to the root domain list.
HOSTISH = re.compile(
    r'^\*?\.?(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}$', re.I)

# shared hosting roots that must not be given to subfinder as roots
SHARED_PLATFORMS = {
    "amazonaws.com", "s3.amazonaws.com", "cloudfront.net", "azurewebsites.net",
    "blob.core.windows.net", "myshopify.com", "zendesk.com", "freshdesk.com",
    "statuspage.io", "herokuapp.com", "firebaseapp.com", "web.app", "appspot.com",
    "github.io", "gitlab.io", "netlify.app", "vercel.app",
    "force.com", "salesforce.com", "atlassian.net", "pardot.com", "apple.com",
    "googleapis.com", "google.com", "windows.net", "sharepoint.com",
}


def normalize_host(raw):
    v = raw.strip()
    v = re.sub(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://', '', v)   # scheme
    v = v.split('/', 1)[0]                                # path
    v = v.split('?', 1)[0]
    # drop the port but leave IPv6/CIDR alone
    if v.count(':') == 1 and not v.startswith('['):
        v = v.split(':', 1)[0]
    return v.strip().lower().rstrip('.')


def registrable(host):
    """Rough registrable-domain guess (no public-suffix list): last 2 labels,
    last 3 for known two-part TLDs."""
    h = host.lstrip('*.').strip('.')
    parts = h.split('.')
    if len(parts) < 2:
        return h
    two_level_tld = {"co.uk", "org.uk", "com.au", "com.br", "com.tr", "co.jp",
                     "co.nz", "co.za", "com.mx", "com.sg", "co.in", "com.hk",
                     "com.ar", "com.bo", "com.co", "com.do", "com.ec", "com.gt",
                     "com.hn", "com.ni", "com.pa", "com.pe", "com.py", "com.sv",
                     "com.uy", "com.ve", "co.cr", "com.pk", "com.eg", "com.ph"}
    last2 = '.'.join(parts[-2:])
    if last2 in two_level_tld and len(parts) >= 3:
        return '.'.join(parts[-3:])
    return last2


def find_col(fieldnames, *cands):
    lm = {f.lower(): f for f in fieldnames}
    for c in cands:
        if c in lm:
            return lm[c]
    for f in fieldnames:
        if any(c in f.lower() for c in cands):
            return f
    return None


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 csv_to_scope.py <h1_scope.csv> <outdir>")
        sys.exit(1)
    in_csv, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)

    with open(in_csv, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        fn = reader.fieldnames or []
        id_col = find_col(fn, "identifier", "asset")
        type_col = find_col(fn, "asset_type", "type")
        elig_col = find_col(fn, "eligible_for_submission", "eligible")
        if not id_col:
            print(f"[-] no identifier column. Columns: {fn}")
            sys.exit(1)

        scope_hosts, root_domains = set(), set()
        apps, cidrs, others = [], [], []
        total = ineligible = 0

        for row in reader:
            total += 1
            raw = (row.get(id_col) or "").strip()
            if not raw:
                continue
            atype = ((row.get(type_col) or "").strip().upper()) if type_col else ""
            elig = ((row.get(elig_col) or "").strip().lower()) if elig_col else ""
            if elig_col and elig in ("false", "no", "0"):
                ineligible += 1
                continue

            if atype in APP_TYPES:
                apps.append(raw.split('/')[-1].split('?')[0])
            elif atype in CIDR_TYPES or re.match(r'^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$', raw):
                cidrs.append(raw)
            elif (atype in DOMAIN_TYPES or (not type_col) or atype == ""
                  or HOSTISH.match(raw.strip())):
                star = raw.lstrip().startswith('*.')
                is_wild = star or atype == "WILDCARD"
                host = normalize_host(raw)
                if not host:
                    continue
                if is_wild:
                    bare = host.lstrip('*.')
                    scope_hosts.add('*.' + bare)
                    if not star and '*' not in bare:
                        # WILDCARD type but no star in the identifier
                        # (e.g. "www.example.net" entered as WILDCARD).
                        # Only adding '*.' yields "*.www.example.net", which
                        # matches NO host -> the actual host would fall out of scope.
                        scope_hosts.add(bare)
                    rd = registrable(bare)
                    if rd not in SHARED_PLATFORMS and '*' not in rd:
                        # If a '*' remains in the middle (e.g. a multi-country TLD wildcard
                        # like "example.com.*") it is NOT a scannable root domain --
                        # it already sits in scope_hosts (for policy reference) and is not
                        # written to domains.txt (so the pipeline gets no invalid target).
                        root_domains.add(rd)
                else:
                    scope_hosts.add(host)
                    # derive a root from an exact-host asset too (subfinder is still useful),
                    # but do not add it if it is a shared platform
                    rd = registrable(host)
                    if rd not in SHARED_PLATFORMS and host not in SHARED_PLATFORMS:
                        root_domains.add(rd)
            else:
                others.append(f"{raw}\t[{atype}]")

    def dump(name, items):
        with open(os.path.join(outdir, name), "w") as f:
            for x in sorted(set(items)):
                f.write(x + "\n")
        return len(set(items))

    n_scope = dump("scope.txt", scope_hosts)
    n_dom = dump("domains.txt", root_domains)
    n_app = dump("apps.txt", apps)
    n_cidr = dump("cidrs.txt", cidrs)
    n_oth = dump("other.txt", others)

    print(f"[+] Total rows: {total}  (dropped eligible=false: {ineligible})")
    print(f"[+] scope.txt   : {n_scope} hosts/wildcards -> run_pipeline.sh arg2")
    print(f"[+] domains.txt : {n_dom} root domains     -> run_pipeline.sh arg1 (multi-domain sweep)")
    print(f"[+] apps.txt    : {n_app} mobile app ids  -> APK_PACKAGES='$(paste -sd, apps.txt)'")
    print(f"[+] cidrs.txt   : {n_cidr} CIDR            -> naabu -l cidrs.txt (if in scope, by hand)")
    print(f"[+] other.txt   : {n_oth} non-domain assets (review manually)")
    if n_dom == 0 and n_scope > 0:
        print("[!] domains.txt is empty but scope is not -- probably all exact hosts (no WILDCARD). "
              "In that case pass hosts one by one, or scope.txt, as arg1.")
    if not type_col:
        print("[!] no asset_type column -- every row was treated as a domain; apps/cidrs may be empty. Check.")


if __name__ == "__main__":
    main()
