# LANE CHECKLIST — logic · <host>
# done -> `- [x]` · not applicable -> `- [~] N/A: <reason>`
# While any `- [ ]` remains, the lane does NOT close. Tick a box only after the work is written to disk.

- [ ] STEP 0 attestation (2 files: wc -l + literal text of the requested line)
- [ ] Allowed transitions listed from the STATE MACHINE
- [ ] Unauthorized-transition candidates (A -> C, skipping B) + the precondition removed
- [ ] Each candidate: single request + comparison with the allowed flow + positive control
- [ ] Window measurement on race candidates (within the rate budget, not a load test)
- [ ] hunt-business-logic artifact
- [ ] hunt-race-condition artifact
- [ ] hunt-exceptional-conditions artifact
- [ ] hunt-brute-force (single requests, no flooding)
- [ ] hunt-captcha-bypass (N/A if no CAPTCHA)
- [ ] Section 14 Card Payment (N/A if no payment surface)
- [ ] TRANSITION MATRIX
- [ ] CLASS_MATRIX.tsv sections 10 + 11 + 14 appended MANUALLY in long format (do NOT use set)

## COMMON CLOSE-OUT
- [ ] ODD/UNEXPECTED observations written to CROSS_LANE_LEADS.md (else N/A: none) — duplicate/hidden pages, forms without inputs, unexpected redirects, inconsistent behavior
- [ ] If there is a finding candidate, finding-validator was invoked (else N/A)
- [ ] For every closed item: 3 classes + 3 tools + positive control recorded
- [ ] Temp files are in scratchpad/evidence, not in the working directory
