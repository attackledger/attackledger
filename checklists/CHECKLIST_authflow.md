# LANE CHECKLIST — authflow · <host>
# done -> `- [x]` · not applicable -> `- [~] N/A: <reason>`
# While any `- [ ]` remains, the lane does NOT close. Tick a box only after the work is written to disk.

- [ ] STEP 0 attestation (2 files: wc -l + literal text of the requested line)
- [ ] STACK_FINGERPRINT read -> decision to open/skip okta-attack / m365-entra-attack
- [ ] Auth flows listed: login · register · forgot · reset · verify · MFA · email/password change · invite
- [ ] Visible-field vs sent-field comparison (flows with missing/extra fields flagged separately)
- [ ] Hidden parameter discovery -> ARTIFACT_authflow_param-discovery_<host>.md
- [ ] hunt-oauth (N/A if no OAuth)
- [ ] hunt-saml (N/A if no SAML)
- [ ] hunt-session
- [ ] hunt-jwt-crypto (N/A if no JWT)
- [ ] hunt-mfa-bypass (N/A if no MFA)
- [ ] hunt-ato
- [ ] hunt-forgot-password
- [ ] hunt-auth-bypass
- [ ] hunt-open-redirect
- [ ] hunt-csrf
- [ ] hunt-cors
- [ ] CHAIN NOTE (including Low-severity primitives)
- [ ] CLASS_MATRIX.tsv sections 6 + 7 appended MANUALLY in long format (do NOT use set)

## COMMON CLOSE-OUT
- [ ] ODD/UNEXPECTED observations written to CROSS_LANE_LEADS.md (else N/A: none) — duplicate/hidden pages, forms without inputs, unexpected redirects, inconsistent behavior
- [ ] If there is a finding candidate, finding-validator was invoked (else N/A)
- [ ] For every closed item: 3 classes + 3 tools + positive control recorded
- [ ] Temp files are in scratchpad/evidence, not in the working directory
