# LANE CHECKLIST — mapper · <host>
# done -> `- [x]` · not applicable -> `- [~] N/A: <reason>`
# While any `- [ ]` remains, the lane does NOT close. Tick a box only after the work is written to disk.

- [ ] STEP 0 attestation (2 files: wc -l + literal text of the requested line)
- [ ] JS bundle + lazy chunks downloaded; hunt-spa-api literal -> call-site -> path table
- [ ] hunt-graphql inventory (N/A + evidence if no GraphQL)
- [ ] Calls made BEFORE the IdP redirect -> ARTIFACT_mapper_pre-redirect_<host>.md (file is required even without an IdP redirect: N/A + final-URL evidence)
- [ ] APP_MODEL section 1 ROLES (every principal + whether an account exists)
- [ ] APP_MODEL section 2 OBJECTS (id format + ownership field + reading/writing endpoints)
- [ ] APP_MODEL section 3 FLOWS (step by step: method + path + precondition)
- [ ] APP_MODEL section 4 STATE MACHINE (states + allowed transitions + triggering endpoint)
- [ ] Auth requirement of every endpoint (anon/auth/step-up) + observed methods
- [ ] 30 KB cap checked (overflow goes to ENDPOINTS_<host>.tsv)
- [ ] Unobserved roles/objects marked UNVERIFIED, nothing invented

## COMMON CLOSE-OUT
- [ ] ODD/UNEXPECTED observations written to CROSS_LANE_LEADS.md (else N/A: none) — duplicate/hidden pages, forms without inputs, unexpected redirects, inconsistent behavior
- [ ] If there is a finding candidate, finding-validator was invoked (else N/A)
- [ ] For every closed item: 3 classes + 3 tools + positive control recorded
- [ ] Temp files are in scratchpad/evidence, not in the working directory
