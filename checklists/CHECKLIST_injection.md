# LANE CHECKLIST — injection · <host>
# done -> `- [x]` · not applicable -> `- [~] N/A: <reason>`
# While any `- [ ]` remains, the lane does NOT close. Tick a box only after the work is written to disk.

- [ ] STEP 0 attestation (2 files: wc -l + literal text of the requested line)
- [ ] SINK INVENTORY (APP_MODEL OBJECTS + parameters)
- [ ] Context identification for every sink
- [ ] Reflection check with a harmless marker (dead sinks eliminated)
- [ ] Context-specific escaping analysis on reflecting sinks
- [ ] Classification (html-injection, not xss, if nothing executes)
- [ ] Skill set: those used have artifacts, those dropped have a one-line rationale
- [ ] STACK_FINGERPRINT -> hunt-aspnet / hunt-laravel decision
- [ ] supply-chain-attack-recon + hunt-cicd trigger decision
- [ ] SINK MATRIX
- [ ] CLASS_MATRIX.tsv sections 9 + 13 + 15 appended MANUALLY in long format (do NOT use set)

## COMMON CLOSE-OUT
- [ ] ODD/UNEXPECTED observations written to CROSS_LANE_LEADS.md (else N/A: none) — duplicate/hidden pages, forms without inputs, unexpected redirects, inconsistent behavior
- [ ] If there is a finding candidate, finding-validator was invoked (else N/A)
- [ ] For every closed item: 3 classes + 3 tools + positive control recorded
- [ ] Temp files are in scratchpad/evidence, not in the working directory
