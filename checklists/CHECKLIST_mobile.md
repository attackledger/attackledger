# LANE CHECKLIST — mobile · <package>
# done -> `- [x]` · not applicable -> `- [~] N/A: <reason>`
# While any `- [ ]` remains, the lane does NOT close. Tick a box only after the work is written to disk.

- [ ] STEP 0 attestation (2 files: wc -l + literal text of the requested line)
- [ ] ELIGIBILITY (live program API eligible_for_submission)
- [ ] ACQUISITION: size + hash verified (no truncation)
- [ ] DECOMPILE (jadx output directory recorded)
- [ ] HARVEST + secret_triage.py three-bucket triage
- [ ] If a real secret exists, secret_gate.py PHASE 0 decision (else N/A)
- [ ] SURFACE DIFF: endpoints absent from the web ENDPOINTS_*.tsv
- [ ] COMPONENT INVENTORY (exported / deep link / pinned cert / debuggable)
- [ ] MOBILE_SURFACE_<package>.md
- [ ] Handoff note for authz/authflow/injection

## COMMON CLOSE-OUT
- [ ] ODD/UNEXPECTED observations written to CROSS_LANE_LEADS.md (else N/A: none) — duplicate/hidden pages, forms without inputs, unexpected redirects, inconsistent behavior
- [ ] If there is a finding candidate, finding-validator was invoked (else N/A)
- [ ] For every closed item: 3 classes + 3 tools + positive control recorded
- [ ] Temp files are in scratchpad/evidence, not in the working directory
