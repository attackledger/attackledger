#!/usr/bin/env python3
"""
secret_triage.py <trufflehog.jsonl | dir> [...]   -- SECRET HUNT PHASE 3: CLASSIFICATION

Why it exists (field measurements):
  A public JS bundle scan : 468 hits  ->   0 verified
  An internal-zone scan   : 287 "secrets" -> ALL false positives (marketing-tag/jQuery/GTM noise)
  A mobile app (APK)      : 0 reportable -- everything found was public ON PURPOSE (pk_live_, AIza, Branch, Sentry)
=> The bottleneck is not scanning, it is SORTING. Raising the volume only grows the pile.

Three buckets: REAL (reportable) / PUBLIC-BY-DESIGN (never a finding) / NOISE.
"""
import sys, os, json, re, collections

# --- PUBLISHED IN THE CLIENT BY DESIGN -- "I found it" is NOT a finding -----
PUBLIC_BY_DESIGN = [
    (r"\bpk_(live|test)_[0-9A-Za-z]+",              "Stripe PUBLISHABLE key (a finding only if it were sk_)"),
    (r"\bAIza[0-9A-Za-z_\-]{35}",                   "Google API key -- Firebase/Maps, should be package/referrer restricted (see NOTE)"),
    (r"\bkey_(live|test)_[0-9A-Za-z]+",             "Branch.io client key"),
    (r"https://[0-9a-f]{32}@[\w.\-]*sentry\.io/",   "Sentry DSN -- client side, public by design"),
    (r"\d+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "Google OAuth client_id -- public by design"),
    (r"\b6L[0-9A-Za-z_\-]{38}",                     "reCAPTCHA SITE key (the secret key is separate)"),
    (r"\bpk\.eyJ[0-9A-Za-z_\-\.]+",                 "Mapbox public token (a finding only if it were sk.)"),
    (r"\b1/[0-9a-f]{40}\b",                         "Transifex Native CDS read-only token (seen verbatim in the field)"),
    (r"\b(GTM|UA|G)-[A-Z0-9]{4,}",                  "Google Tag Manager / Analytics id"),
    (r"\bphc_[0-9A-Za-z]{40,}",                     "PostHog project API key (write-only)"),
]
# --- REAL: must NEVER reach the client; if it did, it is a finding candidate ---
REAL = [
    (r"\b(sk|rk)_live_[0-9A-Za-z]{20,}",            "CRITICAL", "Stripe SECRET/restricted live key"),
    (r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",                "CRITICAL", "AWS access key id (full access if paired with the secret)"),
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY", "CRITICAL", "Private key"),
    (r'"type"\s*:\s*"service_account"',             "CRITICAL", "GCP service-account JSON"),
    (r"\bxox[baprs]-[0-9A-Za-z\-]{10,}",            "HIGH",     "Slack token"),
    (r"\b(ghp|ghs|gho|ghu)_[0-9A-Za-z]{36}",        "HIGH",     "GitHub token"),
    (r"\bgithub_pat_[0-9A-Za-z_]{80,}",             "HIGH",     "GitHub fine-grained PAT"),
    (r"\bSG\.[0-9A-Za-z_\-]{20,}\.[0-9A-Za-z_\-]{20,}", "HIGH", "SendGrid API key"),
    (r"\bSK[0-9a-f]{32}\b",                         "HIGH",     "Twilio API key sid"),
    (r"\bsk\.eyJ[0-9A-Za-z_\-\.]+",                 "HIGH",     "Mapbox SECRET token"),
    (r"\bnpm_[0-9A-Za-z]{36}",                      "HIGH",     "npm token"),
    (r"\b(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp)://[^\s:@/]+:[^\s@/]+@", "CRITICAL", "DB/broker URI with credentials"),
    (r"\bglpat-[0-9A-Za-z_\-]{20}",                 "HIGH",     "GitLab PAT"),
    (r"\bdop_v1_[0-9a-f]{64}",                      "HIGH",     "DigitalOcean token"),
    (r"\bshpat_[0-9a-f]{32}",                       "HIGH",     "Shopify admin token"),
]
# --- MEASURED NOISE: the source of 287 false positives in one engagement ------
NOISE = [
    (r"D27CDB6E-AE6D-11cf",                         "Flash/Shockwave GUID (jQuery/swfobject)"),
    (r"password\s*:\s*function",                    "jQuery/minified JS member name"),
    (r"\b(example|sample|dummy|test|fake|placeholder|your[_-]?key|xxx+|changeme|TODO)\b", "template/example value"),
    (r"\b0{8,}\b|\b1234567|abcdef0123",             "filler pattern"),
    (r"(androidx?|kotlinx?|okhttp3|retrofit2|io/reactivex|com/google/android|bouncycastle)/", "library path"),
]

def classify(raw, detector=""):
    # WARNING: ORDER IS CRITICAL (measured). If noise runs FIRST it produces FALSE NEGATIVES:
    # `xoxb-1234567890-ABCdefGHIjklMNOpqrs` is a real-shaped Slack token, but the
    # "1234567" filler pattern inside it hit the noise rule and it was DROPPED.
    # REAL patterns are far more specific (prefix + length + alphabet) while noise is
    # heuristic => the specific ones ALWAYS run first. "did not find" != "cannot see".
    for pat, sev, why in REAL:
        if re.search(pat, raw): return ("REAL", sev, why)
    for pat, why in PUBLIC_BY_DESIGN:
        if re.search(pat, raw): return ("PUBLIC", "", why)
    for pat, why in NOISE:
        if re.search(pat, raw, re.I): return ("NOISE", "", why)
    return ("UNKNOWN", "", f"unclassified (detector={detector or '?'})")

def load(path):
    out=[]
    files=[]
    if os.path.isdir(path):
        for r,_,fs in os.walk(path):
            files += [os.path.join(r,f) for f in fs if f.endswith((".json",".jsonl",".txt"))]
    else: files=[path]
    for f in files:
        try: lines=open(f, errors="replace").read().splitlines()
        except Exception: continue
        for ln in lines:
            ln=ln.strip()
            if not ln: continue
            if ln.startswith("{"):
                try:
                    d=json.loads(ln)
                    out.append({"raw": d.get("Raw") or d.get("RawV2") or ln,
                                "det": d.get("DetectorName",""),
                                "ver": bool(d.get("Verified")),
                                "src": (d.get("SourceMetadata") or {}).get("Data",{}),
                                "file": f})
                    continue
                except Exception: pass
            out.append({"raw": ln, "det":"", "ver": False, "src":{}, "file": f})
    return out

def main(paths):
    items=[]
    for p in paths: items += load(p)
    buckets=collections.defaultdict(list)
    for it in items:
        b,sev,why = classify(it["raw"], it["det"])
        it["sev"], it["why"] = sev, why
        buckets[b].append(it)

    print(f"=== SECRET TRIAGE -- {len(items)} raw lines ===\n")
    order=["REAL","UNKNOWN","PUBLIC","NOISE"]
    for b in order:
        n=len(buckets[b]); ver=sum(1 for i in buckets[b] if i["ver"])
        print(f"  {b:<12} {n:>6}" + (f"   (verified: {ver})" if b in ("REAL","UNKNOWN") else ""))

    print("\n=== REAL -- FINDING CANDIDATES ===")
    if not buckets["REAL"]: print("  (none) -- the correct result; most scans end this way.\n")
    for it in buckets["REAL"][:40]:
        v = "✅VERIFIED" if it["ver"] else "⚠️unverified"
        print(f"  [{it['sev']}] {v}  {it['why']}")
        print(f"      {it['raw'][:90]}")
        print(f"      source: {it['src'].get('Filesystem',{}).get('file') or it['file']}")

    print("\n=== UNKNOWN -- CHECK MANUALLY (classifier did not recognize) ===")
    for it in buckets["UNKNOWN"][:25]:
        print(f"  {'✅VER ' if it['ver'] else '     '}{it['det'] or '?':<22} {it['raw'][:80]}")
    if len(buckets["UNKNOWN"])>25: print(f"  ... +{len(buckets['UNKNOWN'])-25} lines")

    pub=collections.Counter(i["why"] for i in buckets["PUBLIC"])
    if pub:
        print("\n=== PUBLIC BY DESIGN -- DO NOT FILE ===")
        for why,n in pub.most_common(): print(f"  {n:>5}x  {why}")
        print("  NOTE: `AIza` exception -- a Google API key is itself public, but if it is UNRESTRICTED")
        print("       (no package/SHA-1/referrer/API restriction) billable abuse becomes possible.")
        print("       You CANNOT tell this from the key itself; a restriction test is a separate measurement.")

    noi=collections.Counter(i["why"] for i in buckets["NOISE"])
    if noi:
        print("\n=== NOISE ===")
        for why,n in noi.most_common(): print(f"  {n:>5}x  {why}")

    print("\n=== DECISION ===")
    g=[i for i in buckets["REAL"] if i["ver"]]
    if g:   print(f"  {len(g)} VERIFIED real secret(s) -> before taking them to the finding validator:")
    elif buckets["REAL"]: print(f"  {len(buckets['REAL'])} real-class but UNVERIFIED -> that does NOT mean 'exists'.")
    else:   print("  No secret to file. This is a correct and common outcome.")
    print("  If the program has a 'stop and report' rule: do NOT use the key, only report it.")
    print("  Third-party (vendor) keys are OOS in most policies -- determine the owner first.")

if __name__=="__main__":
    if len(sys.argv)<2: sys.exit("usage: secret_triage.py <trufflehog.jsonl|dir> [...]")
    main(sys.argv[1:])
