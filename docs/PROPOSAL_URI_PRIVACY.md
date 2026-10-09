# Proposal: evidence URIs that can be deleted with the content

Status: proposal (2026-10-10), not built. From the second design-partner review.

## The gap

Deleting an engagement's content (D-043) makes summaries and raw evidence unreadable, but
every evidence entry keeps its URI, query string included. Chain record v2 commits to `uri`
(`ledger.V2_FIELDS`), so removing or shortening it breaks every chain hash after it. A query
string often carries what a retention policy is meant to remove: search terms, e-mail
addresses, order numbers, tokens that redaction did not recognise.

Since this review, `GET /engagements/{id}/content` says so before and after deletion
(`keeps`, `evidence_uris`, `uris_with_query`).

## Options

1. **Chain record v3 commits to `uri_sha256`, and stores the URI encrypted.**
   - The record: `{"v": 3, ..., "uri_sha256": sha256(uri), "uri_origin": scheme://host[:port]}`.
   - The URI goes in an encrypted column, like the summary in v2; deletion removes it.
   - The report carries `uri` (null after deletion) next to `uri_sha256`. The verifier checks
     one against the other when the URI is present, as it does for `summary_sha256`.
   - Host and scheme stay in clear, because coverage is per host and the report needs it.
   - Cost: a new record version in `ledger.py`, `report.py`, `tools/verify_report.py`,
     `web/src/verify_report.ts`, and equivalence cases (D-046). v1 and v2 rows keep
     verifying as now.
2. **Keep v2, and store the URI without its query string.** The path stays readable and the
   query is never stored. Simple, but it loses evidence that testers need (which parameter was
   tested), and the full URI is still in the raw evidence, so nothing is gained for content
   that is kept.
3. **Keep v2 and say so.** What is built now. Honest, but a client with a strict retention
   policy cannot meet it for URIs.

## Recommendation

Option 1, as chain record v3, when the next chain change is due. It follows the v2 pattern
(commit to a hash, keep the value encrypted) and it is the only option that keeps the full URI
as evidence while letting deletion remove it. Path and query both go under the hash: a path
can carry personal data too (`/users/jane@example.com`).

Open questions:
- Whether the path should stay in clear for coverage views. The views use the host and the
  item, not the path, so the proposal hides it.
- Imported entries already wipe their URLs on deletion (`inbox.wipe`); evidence mapped from
  them keeps the URI in the chain, so v3 closes that too.
- The gateway request log keeps its URLs after deletion (the docs say so). It is
  not part of the chain, so it can be cleared without a format change. That is a separate
  decision.
