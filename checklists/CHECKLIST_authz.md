# LANE CHECKLIST — authz · <host>
# done -> `- [x]` · not applicable -> `- [~] N/A: <reason>`
# While any `- [ ]` remains, the lane does NOT close. Tick a box only after the work is written to disk.

- [ ] STEP 0 attestation (2 files: wc -l + literal text of the requested line)
- [ ] Dead route vs auth-gated distinction (OPTIONS + made-up-path canary)
- [ ] Second-account status recorded (A<->B available? if not, "waiting on operator action: 2nd account")
- [ ] AUTHZ MATRIX (object x role, every cell backed by a real request)
- [ ] Hidden parameter discovery -> ARTIFACT_authz_param-discovery_<host>.md
- [ ] hunt-idor artifact
- [ ] hunt-graphql artifact (N/A if no GraphQL)
- [ ] hunt-fintech-graphql (N/A if no payment/balance surface)
- [ ] hunt-shadow-api: v1/v2 authz behavior diff
- [ ] hunt-api-misconfig (mass assignment + verb tampering)
- [ ] hunt-websocket (N/A if no WebSocket)
- [ ] Every 401/403 re-tested with the same session plus a canary
- [ ] CLASS_MATRIX.tsv section 8 appended MANUALLY in long format (do NOT use set)
- [ ] If there is a finding, a lateral-spread table (else N/A)

## COMMON CLOSE-OUT
- [ ] ODD/UNEXPECTED observations written to CROSS_LANE_LEADS.md (else N/A: none) — duplicate/hidden pages, forms without inputs, unexpected redirects, inconsistent behavior
- [ ] If there is a finding candidate, finding-validator was invoked (else N/A)
- [ ] For every closed item: 3 classes + 3 tools + positive control recorded
- [ ] Temp files are in scratchpad/evidence, not in the working directory
