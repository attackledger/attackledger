# Trusted timestamp roots

`verify_report.py` trusts the root certificates in this folder (PEM, `*.pem`) when it
checks receipt timestamps, plus any you pass with `--tsa-root FILE`.

Add a root only after you check its fingerprint against a source you trust (your
operating system's root store, the authority's own site). Removing a file here makes
timestamps from that authority fail verification. The browser verifier (the public page and
the app's Verify tab) trusts the same files: `tools/build_verify.sh` copies them into
`web/src/tsa_roots.ts`, and `tools/verifier_equivalence/run.sh` fails if the copy is stale.

| File | Authority | SHA-256 fingerprint |
|---|---|---|
| `digicert-trusted-root-g4.pem` | DigiCert (`http://timestamp.digicert.com`) | `552F7BDCF1A7AF9E6CE672017F4F12ABF77240C78E761AC203D1D9D20AC89988` |
