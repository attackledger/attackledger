# LANE CHECKLIST — recon · <host>
# done -> `- [x]` · not applicable -> `- [~] N/A: <reason>`
# While any `- [ ]` remains, the lane does NOT close. Tick a box only after the work is written to disk.

- [ ] STEP 0 attestation (2 files: wc -l + literal text of the requested line)
- [ ] Scope + mandatory header + rate verified
- [ ] Section 3 InfoGath items
- [ ] Section 4 ConfigMgmt items
- [ ] Section 5 SecTransmit items
- [ ] Section 12 Crypto items
- [ ] hunt-source-leak artifact
- [ ] hunt-subdomain artifact
- [ ] hunt-shadow-api artifact
- [ ] hunt-tls-network artifact
- [ ] hunt-cloud-misconfig artifact
- [ ] hunt-grpc artifact (N/A + signal if no gRPC/Envoy)
- [ ] STACK_FINGERPRINT_<HOST>.md ("NONE" is a valid result; includes the IdP redirect signal)
- [ ] Secret flow PHASE 0 decision (secret_gate.py: GO/TIMEBOX/SKIP)
- [ ] mapper handoff note (live endpoints + auth surface)
- [ ] CLASS_MATRIX.tsv section 3/4/5/12 rows appended MANUALLY in long format (do NOT use set)

## COMMON CLOSE-OUT
- [ ] ODD/UNEXPECTED observations written to CROSS_LANE_LEADS.md (else N/A: none) — duplicate/hidden pages, forms without inputs, unexpected redirects, inconsistent behavior
- [ ] If there is a finding candidate, finding-validator was invoked (else N/A)
- [ ] For every closed item: 3 classes + 3 tools + positive control recorded
- [ ] Temp files are in scratchpad/evidence, not in the working directory
