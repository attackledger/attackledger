#!/usr/bin/env python3
"""
secret_gate.py <h1_handle>   -- SECRET/CREDENTIAL HUNT PHASE 0: PAYOUT GATE

Before spending hours on APK/secret hunting in a program, answers these two questions
from the LIVE API:
  1. Does this program PAY for credential/secret disclosure, or does it close such
     reports as informative with an "unless exploitable" clause?
  2. How many of the mobile assets are actually bounty-eligible?

Output: GO / TIMEBOX / SKIP decision + a READY command for a mobile recon script
(with the correct package count).
Rule: only hunt credentials in programs that pay for them.

Env: H1_CREDS_FILE -- file containing "username:api_token" (default ~/.config/h1_creds).
"""
import sys, json, re, urllib.request, base64, os

H1 = "https://api.hackerone.com/v1/hackers"

def creds():
    p = os.path.expanduser(os.environ.get("H1_CREDS_FILE", "~/.config/h1_creds"))
    u, t = open(p).read().strip().split(":", 1)
    return base64.b64encode(f"{u}:{t}".encode()).decode()

def api(path):
    req = urllib.request.Request(H1 + path)
    req.add_header("Authorization", "Basic " + creds())
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=40) as r:
        return json.load(r)

# --- policy phrases about credentials -------------------------------------
CRED_TERMS = r"(credential|secret|api[ _-]?key|access[ _-]?key|hardcoded|hard-coded|token|password)"
# WARNING (measured): OOS lines may NOT contain the word "credential". One program's
# "Disclosure of publicly available information" line slipped through exactly this way.
# So the patterns below are searched across the WHOLE policy, WITHOUT the CRED_TERMS filter.
GLOBAL_KILL = [
    (r"theoretical\s+impact\s+rather\s+than\s+demonstrat", "IMPACT GATE: 'theoretical impact' is explicitly listed as an informative reason"),
    (r"disclosure\s+of\s+publicly\s+available\s+information", "OOS: 'publicly available information'"),
    (r"most\s+common\s+reason\s+reports\s+are\s+rejected", "the program's OWN statement of a rejection reason"),
]
# Operational conduct rules (not findings; they set HOW we behave)
HANDLING = [
    (r"stop\s+and\s+report", "on finding a credential, STOP and report IMMEDIATELY -- do not use/validate it"),
    (r"(do\s+not|never)\s+.{0,30}(access|use)\s+.{0,30}(account|data)", "ban on accessing other people's data"),
]
# these patterns push a credential to OOS/informative
KILL = [
    (r"unless\s+(it\s+is\s+)?exploitab", "\"unless exploitable\" clause"),
    (r"without\s+(demonstrat|proof|impact)", "requirement to demonstrate impact"),
    (r"(informative|not\s+eligible|out[- ]of[- ]scope|we\s+do\s+not\s+accept)", "explicitly OOS/informative"),
    (r"publicly\s+available\s+information", "\"publicly available information\" exclusion"),
    (r"(third[- ]party|vendor)\s+.{0,40}(key|credential)", "third-party key exclusion"),
]
# these patterns make a credential PAYABLE
GO = [
    (r"(leaked|exposed|disclosed)\s+.{0,30}(credential|secret|key)", "disclosed credentials are explicitly recognized"),
    (r"(credential|secret|key)\s+.{0,30}(leak|exposure|disclosure)", "credential disclosure is recognized"),
    (r"sensitive\s+(data|information)\s+(exposure|disclosure)", "sensitive data disclosure"),
]
MOBILE = {"GOOGLE_PLAY_APP_ID","APPLE_STORE_APP_ID","OTHER_APK","TESTFLIGHT","WINDOWS_APP_STORE_APP_ID"}

def sentences(text):
    return [s.strip() for s in re.split(r"(?<=[.!?\n])\s+", text) if s.strip()]

def main(handle):
    prog = api(f"/programs/{handle}")
    pol = prog.get("attributes", {}).get("policy", "") or ""
    print(f"=== {handle} -- SECRET/CREDENTIAL PAYOUT GATE ===")
    print(f"policy length: {len(pol)} chars\n")

    hits_kill, hits_go = [], []
    for s in sentences(pol):
        if not re.search(CRED_TERMS, s, re.I):
            continue
        for pat, why in KILL:
            if re.search(pat, s, re.I):
                hits_kill.append((why, s[:240])); break
        else:
            for pat, why in GO:
                if re.search(pat, s, re.I):
                    hits_go.append((why, s[:240])); break

    # patterns searched across the WHOLE policy (WITHOUT the CRED_TERMS filter)
    glob = [(why, m.group(0)) for pat, why in GLOBAL_KILL
            for m in [re.search(pat, pol, re.I)] if m]
    hand = [(why, m.group(0)) for pat, why in HANDLING
            for m in [re.search(pat, pol, re.I)] if m]
    for why, frag in glob:
        hits_kill.append((why, frag))

    print("--- PHRASES THAT PUSH CREDENTIALS TO OOS/INFORMATIVE ---")
    if hits_kill:
        for why, s in hits_kill[:8]: print(f"  [{why}]\n    {s}\n")
    else: print("  (none)\n")

    print("--- PHRASES SUGGESTING CREDENTIALS ARE PAYABLE ---")
    if hits_go:
        for why, s in hits_go[:8]: print(f"  [{why}]\n    {s}\n")
    else: print("  (none)\n")

    if hand:
        print("--- OPERATIONAL CONDUCT RULES (from the policy) ---")
        for why, frag in hand: print(f"  [{why}]  <- \"{frag}\"")
        print()

    # --- mobile asset eligibility ---
    scopes, page = [], f"/programs/{handle}/structured_scopes?page%5Bsize%5D=100"
    while page:
        d = api(page); scopes += d.get("data", [])
        nxt = d.get("links", {}).get("next")
        page = nxt.replace(H1, "") if nxt else None

    mob = [s for s in scopes if s["attributes"].get("asset_type") in MOBILE]
    elig = [s for s in mob if s["attributes"].get("eligible_for_submission")]
    paid = [s for s in elig if s["attributes"].get("eligible_for_bounty")]
    print(f"--- MOBILE ASSETS: {len(mob)} total / {len(elig)} submittable / {len(paid)} BOUNTY ---")
    for s in mob:
        a = s["attributes"]
        print(f"  {'✅' if a.get('eligible_for_bounty') else ('🟡' if a.get('eligible_for_submission') else '⛔')} "
              f"{a['asset_identifier']}  [{a['asset_type']}]  max={a.get('max_severity','?')}")

    # WARNING: scope entries can be MALFORMED, e.g. "com.example.app Android"
    # (an extra word). Passed raw, the shell splits it into 2 arguments. Force a package shape.
    PKG_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$")
    android, dirty = [], []
    for s_ in paid:
        a = s_["attributes"]
        if a["asset_type"] not in ("GOOGLE_PLAY_APP_ID", "OTHER_APK"): continue
        raw = a["asset_identifier"].strip()
        tok = next((t for t in raw.split() if PKG_RE.match(t)), None)
        if tok:
            android.append(tok)
            if tok != raw: dirty.append((raw, tok))
        else:
            dirty.append((raw, None))
    if dirty:
        print("\n--- MALFORMED SCOPE ENTRY CORRECTED ---")
        for raw, tok in dirty:
            print(f"  \"{raw}\"  ->  {tok or 'NOT A PACKAGE NAME, SKIPPED'}")

    # --- decision ---
    print("\n=== DECISION ===")
    if hits_kill and not hits_go:
        v = "SKIP" if not paid else "TIMEBOX"
        print(f"  {v} -- the policy excludes credentials via: {hits_kill[0][0]}.")
        print("  Condition: only an EXPLOITABLE credential (live, privileged, verified) gets filed.")
        print("  A bare 'there is a key in the APK' report comes back informative in this program.")
    elif paid:
        print("  GO -- there is a bounty-eligible mobile asset and the policy does not explicitly exclude credentials.")
    else:
        print("  SKIP -- NO bounty-eligible mobile asset.")

    if android:
        print(f"\n=== READY COMMAND ({len(android)} packages) ===")
        print("  # WARNING: the MOBILE_MAX_PKGS default is 3 and EXTRAS ARE SILENTLY DROPPED.")
        print(f"  MOBILE_MAX_PKGS={len(android)} <path-to>/mobile_recon.sh \\")
        print(f"      $ATTACKLEDGER_WORKDIR/targets/{handle}/mobile {' '.join(android)}")
    print("\n  Then: classify with secret_triage.py (filters out keys that are public by design).")

if __name__ == "__main__":
    if len(sys.argv) != 2: sys.exit("usage: secret_gate.py <h1_handle>")
    main(sys.argv[1])
