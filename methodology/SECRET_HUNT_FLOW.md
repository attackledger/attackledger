# Credential / Secret Hunting — STANDARD FLOW
> Standing operator instruction: for every program, include a credential/secret flow — but only
> where the program PAYS for credentials. The condition itself is PHASE 0.

On every new program **Phase 0 is MANDATORY**; the rest depends on the decision Phase 0 returns.

---
## PHASE 0 — PAYMENT GATE (this first, 30 seconds)
```bash
python3 recon/secret_gate.py <program_handle>
```
Answers two questions from the live program API and returns **GO / TIMEBOX / SKIP**:
1. Does the policy pay for credential disclosure, or does it push it to informative with
   *"unless exploitable"* / *"theoretical impact"* / *"publicly available information"*?
2. How many of the mobile assets are `eligible_for_bounty`?

It also extracts the **operational behavior rule** (such as `stop and report`) and a **ready-made mobile_recon command**.

| decision | what to do |
|---|---|
| **SKIP** | no bounty-eligible mobile asset, or the policy explicitly excludes it -> the lane is not opened |
| **TIMEBOX** | the policy has an impact condition -> chase only **exploitable** credentials; do NOT write a bare "there is a key in the APK" |
| **GO** | full lane |

Warning: if Phase 0 is skipped, the typical outcome is hours spent and an **informative**. Field data: a long tail of informatives came from exactly this.

---
## PHASE 1 — CORPUS (IN-SCOPE assets only)
```bash
MOBILE_MAX_PKGS=<PACKAGE_COUNT> mobile_recon.sh \
    targets/<handle>/mobile <pkg1> <pkg2> ...
```
**`MOBILE_MAX_PKGS` DEFAULTS TO 3 AND SILENTLY DROPS ANYTHING BEYOND IT.** This is how a 5-package
program was silently reduced to 3 — `secret_gate.py` already prints the correct count, USE IT.

Web side: JS bundles + sourcemaps + `_next` chunks (on one program this yielded new in-scope hosts twice).
Repo side: `trufflehog github --org=... --only-verified` inside `recon/dork.sh`.

Warning: `apkeep` is NOT "blocked by infrastructure". On one engagement that claim was disproved — the cause was a
**wrong package name**. The program's scope entry can also be malformed (for example a package name with a
platform label glued onto it); `secret_gate.py` cleans this up.
Warning: in a React-Native/Expo app the real surface is `assets/index.android.bundle` — it is NOT in the jadx output.
Give the scan directory the **unpacked root** of the APK too, not only `jadx/`.

---
## PHASE 2 — SCAN
`mobile_recon.sh` already runs `trufflehog filesystem --only-verified`.
**Keep unverified output too, but count it as a LEAD, not a finding.**

---
## PHASE 3 — TRIAGE (the real value of the flow)
```bash
python3 recon/secret_triage.py <trufflehog.jsonl|directory>
```
Splits into three buckets: **REAL** / **PUBLIC-BY-DESIGN** / **NOISE** (+ UNKNOWN = look manually).

Why it is required — our own measurements:
| source | raw "findings" | real |
|---|---|---|
| a public JS bundle of a trading platform | 468 hits | **0 verified** |
| an internal-looking web bundle | 287 "secrets" | **all false positives** (analytics/jQuery/tag-manager, Flash GUID, `password:function`) |
| a mobile APK deep-mine | — | **0 fileable**, all deliberately public (`pk_live_`, `AIza`, attribution SDK, Sentry DSN) |

=> The bottleneck is not scanning but **triage**. Scaling volume up to millions only scales the pile up to millions.

**The `pk_` vs `sk_` distinction is the essence of the flow.** Finding `pk_live_` is NOT a finding — it is
meant to ship to the client. Finding `sk_live_` is a finding.
**The `AIza` exception:** the key itself is public, but if it is **unrestricted** (no package/SHA-1/referrer/API
restriction) billable abuse becomes possible. You cannot tell that by looking at the key — **the restriction test
is a SEPARATE measurement** and it is not a "finding" until it has been done.

Warning: classifier order: **REAL -> PUBLIC -> NOISE**. If noise runs first it produces false negatives
(measured: `xoxb-1234567890-...`, a real Slack token, was being dropped because of the `1234567` inside it).

---
## PHASE 4 — VALIDATION LIMIT
- If the policy says `stop and report`, **do NOT USE the key**, only report it.
- Third-party/vendor keys are OOS in most policies -> **determine the owner first**.
- NEVER access someone else's data. If a validity check is needed, make the **least privileged** call
  (whoami/metadata) and STOP there.
- `finding-validator` is mandatory; also search your own report history for duplicates.

---
## OUT OF SCOPE — permanent
Bulk-downloading and scanning applications that no program has authorized (**mass targeting**) is
itself the attack, not research. A key pulled from a random app cannot be reported or paid anywhere.
Only assets **inside the scope of the program being hunted** are scanned.
