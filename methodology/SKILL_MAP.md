# SKILL lines to put in a brief — by target type
# `role` column: every row belongs to EXACTLY ONE role (see roles/ROLE_<role>.md).

Every agent brief carries a **"SKILL TO LOAD"** line and the handoff requires that skill's
**output artifact**. Loading is not enough; produce the output.

NOTE ON `claude-bughunter:*` SKILLS: these come from an external, third-party Claude Code plugin
(claude-bughunter) and are OPTIONAL. This framework references them by name; if the plugin is not
installed, substitute your own per-class skill or the equivalent section of
`skills/webapp-checklist/`. The tables, artifacts and gates below stay the same either way.

The `role` column is a partition: a row is opened only in its own role's lane.
Role definitions are in `roles/ROLE_<role>.md`, dispatch rules in `methodology/ORCHESTRATOR_PLAYBOOK.md` §1.

**Note:** `claude-bughunter:hunt-dispatch` was INTENTIONALLY not added to this table —
that skill is the internal loader of the plugin's own SEPARATE `/hunt` slash command ("Not for
direct user invocation") and has nothing to do with our own `hunt-orchestrate` playbook.

| lane target | required skill | handoff artifact | role |
|---|---|---|---|
| new host / broad surface | `webapp-checklist` | **PASS/FINDING/N/A/BLOCKED matrix** (13 sections) | _like a matrix — 5 roles fill the slices_ |
| file/document upload | `claude-bughunter:hunt-file-upload` | technique x file x response table | injection |
| OAuth / SSO / redirect_uri | `claude-bughunter:hunt-oauth` | allowlist table + bypass class | authflow |
| SAML | `claude-bughunter:hunt-saml` | assertion/signature table | authflow |
| JWT / signature / alg | `claude-bughunter:hunt-jwt-crypto` | header/claim table (**WITHOUT writing values**) | authflow |
| cache / CDN / ISR | `claude-bughunter:hunt-cache-poison` | cache-key axis table | injection |
| IDOR / BOLA | `claude-bughunter:hunt-idor` | own-id vs made-up-id differential | authz |
| session / cookie | `claude-bughunter:hunt-session` | flag + rotation + fixation table | authflow |
| MFA | `claude-bughunter:hunt-mfa-bypass` | flow step x bypass attempt | authflow |
| password reset | `claude-bughunter:hunt-forgot-password` | token/flow table | authflow |
| race condition | `claude-bughunter:hunt-race-condition` | window + concurrency measurement | logic |
| business logic | `claude-bughunter:hunt-business-logic` | flow x manipulation table | logic |
| SSRF / URL fetch | `claude-bughunter:hunt-ssrf` | allowlist + bypass class (metadata FORBIDDEN) | injection |
| GraphQL | `claude-bughunter:hunt-graphql` | schema/introspection + operation table | authz _(schema inventory is in mapper)_ |
| WebSocket | `claude-bughunter:hunt-websocket` | message type x authz table | authz _(CSWSH/handshake is in authflow)_ |
| SPA / bundle mining | `claude-bughunter:hunt-spa-api` | literal -> consuming call-site -> full path | mapper |
| Next.js | `claude-bughunter:hunt-nextjs` | route/manifest + `/_next/*` table | mapper |
| subdomain / surface | `claude-bughunter:hunt-subdomain` | host x class x decision table | recon |
| TLS / network | `claude-bughunter:hunt-tls-network` | certificate/SAN grouping | recon |
| cloud misconfiguration | `claude-bughunter:hunt-cloud-misconfig` | bucket/service x access table | recon |
| API misconfiguration | `claude-bughunter:hunt-api-misconfig` | endpoint x method x authz table | authz _(prototype pollution is in injection)_ |
| source leakage | `claude-bughunter:hunt-source-leak` | file x content x impact | recon |
| **credential / secret disclosure** | `claude-bughunter:hunt-source-leak` + **`methodology/SECRET_HUNT_FLOW.md`** | **Phase 0 payment decision** + `secret_triage.py` three-bucket table (REAL/PUBLIC/NOISE) | recon |
| host header | `claude-bughunter:hunt-host-header` | header variant x reflection | injection |
| deserialization (RCE) | `claude-bughunter:hunt-deserialization` | gadget chain x sink x RCE proof | injection |
| components/CVE (supply chain) | `claude-bughunter:supply-chain-attack-recon` | package squatting/dependency confusion/SBOM/CI-CD disclosure (APP_MODEL EXEMPT) | injection |
| CI/CD pipeline | `claude-bughunter:hunt-cicd` | GitHub Actions/Jenkins/runner poisoning (APP_MODEL EXEMPT) | injection |
| prototype pollution | `claude-bughunter:hunt-nodejs` | pollution chain x sink table (UNIVERSAL) | injection |
| Spring Boot actuator | `claude-bughunter:hunt-springboot` | `/actuator/*` access x disclosure table (UNIVERSAL, eliminated with a single request) | injection |
| RAG/vector-DB injection | `claude-bughunter:hunt-rag-vector` | embedding poisoning x cross-tenant leakage (if the target has AI/RAG) | injection |
| .NET/ASP.NET (CONDITIONAL) | `claude-bughunter:hunt-aspnet` | ViewState/IIS table — ONLY if `STACK_FINGERPRINT` says present | injection |
| Laravel/PHP (CONDITIONAL) | `claude-bughunter:hunt-laravel` | APP_KEY/debug-mode table — ONLY if `STACK_FINGERPRINT` says present | injection |
| fintech GraphQL (payment/balance) | `claude-bughunter:hunt-fintech-graphql` | fintech-specific authz patterns, IN ADDITION to `hunt-graphql` | authz |
| gRPC / Envoy transcoder | `claude-bughunter:hunt-grpc` | `:set`-suffixed undeclared route inventory (UNIVERSAL) | recon |
| Okta IdP (CONDITIONAL) | `claude-bughunter:okta-attack` | SSO-bypass table — ONLY if `STACK_FINGERPRINT` says present | authflow |
| Microsoft Entra/M365 (CONDITIONAL) | `claude-bughunter:m365-entra-attack` | same rule, tied to the Entra/Azure AD signal | authflow |
| HTTP smuggling | `claude-bughunter:hunt-http-smuggling` | CL/TE variant x response | injection |
| XSS / DOM | `claude-bughunter:hunt-xss` + `hunt-dom` | sink x payload x context escape | injection |
| open redirect | `claude-bughunter:hunt-open-redirect` | parameter x target x allowlist | authflow |
| CORS | `claude-bughunter:hunt-cors` | origin class x ACAO/ACAC | authflow |
| shadow API | `claude-bughunter:hunt-shadow-api` | undeclared-endpoint inventory | recon _(version diff is in authz)_ |
| LLM / AI endpoint | `claude-bughunter:hunt-llm-ai` | prompt/injection table | injection |
| ATO chain | `claude-bughunter:hunt-ato` | step x precondition x impact | authflow |
| auth bypass | `claude-bughunter:hunt-auth-bypass` | gate x bypass class | authflow |
| CSRF | `claude-bughunter:hunt-csrf` | action x SameSite x token table | authflow |
| anti-automation / threshold | `claude-bughunter:hunt-brute-force` + `hunt-captcha-bypass` | threshold measurement (SINGLE request, NO flooding) | logic |
| error-path behavior | `claude-bughunter:hunt-exceptional-conditions` | error path x behavior table | logic |
| mobile application (APK/IPA) | `claude-bughunter:apk-redteam-pipeline` | package x endpoint x web-DIFF table + exported component inventory | mobile |
| mobile-only API surface | `claude-bughunter:hunt-shadow-api` | endpoints declared in the APK but ABSENT on the web | mobile |
| SQL injection | `claude-bughunter:hunt-sqli` | payload x sink x error/blind-oracle table | injection |
| NoSQL injection | `claude-bughunter:hunt-nosqli` | operator injection x sink table | injection |
| XXE | `claude-bughunter:hunt-xxe` | parser x entity x OOB-proof table | injection |
| RCE (general) | `claude-bughunter:hunt-rce` | command injection x sink x proof table (deserialization RCE is a separate row above) | injection |
| SSTI | `claude-bughunter:hunt-ssti` | template engine x payload x RCE chain | injection |
| LFI / path traversal | `claude-bughunter:hunt-lfi` | wrapper/encoding x sink table (see the 403-bypass addendum in `hunt-api-misconfig`) | injection |
| LDAP injection | `claude-bughunter:hunt-ldap` | filter injection x auth-bypass table | injection |
| HTML injection | `claude-bughunter:hunt-html-injection` | sink x context x impact below the XSS threshold | injection |
| clickjacking | `claude-bughunter:hunt-clickjacking` | X-Frame-Options/CSP frame-ancestors x UI-redress scenario | injection |
| SharePoint (CONDITIONAL) | `claude-bughunter:hunt-sharepoint` | SharePoint-specific endpoint/misconfig table — ONLY if `STACK_FINGERPRINT` says present | injection |
| NTLM info disclosure | `claude-bughunter:hunt-ntlm-info` | NTLM handshake/hash-disclosure signals | recon |
| Kubernetes / K8s | `claude-bughunter:hunt-k8s` | API-server/kubelet/etcd access table | recon |
| other / undispatchable classes | `claude-bughunter:hunt-misc` | patterns from 225 disclosed reports, residual findings that fit no specific skill | injection _(lowest priority)_ |
| report text | `h1-report-body` + `claude-bughunter:report-writing` | report body + CVSS 4.0 VECTOR | _orchestrator — no separate role_ |
| evidence hygiene | `claude-bughunter:evidence-hygiene` | redacted screenshot + clean HAR | _orchestrator — no separate role_ |

**Orchestrator rule:** when writing a brief, pick the rows of this table that belong to the lane's ROLE and
write them by name. Do NOT open another role's row in that lane — that role will run in its own lane.
If I do not see the artifact in the handoff, the lane is NOT COUNTED as complete.
