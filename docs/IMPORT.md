# Evidence import

Status: built 2026-10-09 (D-029, MVP item 4). The design is in `TARGET_ARCHITECTURE.md`,
"Evidence import". This page says what was built and how each format is read.

A tester uploads an export file from a tool they already use. Its in-scope entries wait
in the engagement's inbox, redacted, until a person maps each one to checklist items.
Nothing reaches the ledger without that step. Import is file-only: no tokens and no API
pulls (Caido's local API is not in the MVP).

```
file ─► adapter ─► scope check ─► redaction ─► dedupe ─► inbox ─► person maps ─► ledger
        (parse)    (out-of-scope    (before     (content   (per        (with           (evidence,
                    rows refused,   anything    hash)      engagement)  suggestions)    source import:<tool>)
                    listed by row   is stored)
                    and host only)
```

## Formats and field mappings

Adapters live in `server/app/importers/`. Each is a pure parser: it never opens a
connection, a file or a URL named inside the export. The registry is checked when the API
starts; an adapter that does not meet the contract stops the start.

| Entry field | HAR 1.2 (`har`) | Burp Suite XML (`burp`) | Caido JSON (`caido`) |
|---|---|---|---|
| URL | `request.url` | `<url>`, or `<protocol>://<host>:<port><path>` | `https`/`http` from `is_tls`, `host`, `:port` unless default, `path`, `?query` |
| Method | `request.method` | `<method>` | `method` |
| Status | `response.status` (0: none) | `<status>` (empty: none) | `response.status_code` (no `response`: none) |
| Request bytes | rebuilt: request line, `request.headers`, `postData.text` (or its `params` as a form body) | `<request>`, base64-decoded when `base64="true"` | `raw`, base64-decoded |
| Response bytes | rebuilt: status line, `response.headers`, `content.text` (base64-decoded when `encoding` is `base64`) | `<response>`, the same way | `response.raw`, base64-decoded |
| Time | `startedDateTime` | `<time>`, as written | `created_at` (epoch ms, to ISO 8601 UTC) |
| Tool id | `_id` or `_requestId` if present | none | `id` |
| Label | `comment` | `<comment>` | `source`, plus "edited" and the alteration when set |
| Creator | `log.creator.name` and `version` | `burpVersion` of `<items>` | "Caido" |

Notes:
- HAR keeps no raw bytes, so its request and response are rebuilt from the fields, and the
  entry says so. HAR's separate `cookies` and `queryString` lists are not read: the same
  values are in the headers and the URL.
- Burp with `base64="false"`: an XML parser turns CR LF into LF, even inside CDATA, so line
  ends in the stored bytes are not exact. Burp's base64 option keeps them.
- A Caido row without `raw` is still imported with its URL, method and status, and says that
  the raw bytes were not exported.

## Limits and hostile files

- 50 MB per file and 5,000 entries per file; a file over either is refused, never imported
  in part. A request or response over 5 MB is kept up to 5 MB and marked as cut; base64 is
  decoded only up to that size.
- XML is read with `defusedxml`: entity declarations and external references are refused
  (XXE, billion laughs, parameter entities), external DTDs are never fetched, and nesting
  deeper than 32 levels is refused. Burp's own DOCTYPE, which declares only elements and
  attributes, is allowed.
- Invalid JSON, nesting beyond what the JSON parser handles, and integers too long to
  convert are refused with a message. A readable file with bad rows imports the good rows
  and lists the others by row number with the reason.

## Scope, redaction, dedupe, storage

- **Scope.** An engagement without scope rules imports nothing. A row whose host is not in
  scope (or is excluded) is refused; the batch lists it by row number and host, and nothing
  else about it is stored.
- **Redaction** (`redact.http_message`, D-038 conventions). Every header line of the raw
  request and response goes through the header rules whatever its name (Cookie,
  Set-Cookie, Authorization, Proxy-Authorization, X-Api-Key and other secret names, and
  tokens or secret parameters inside other headers); the request line and body go through
  the text rules (secret query and form parameters, JSON keys, JWTs, bearer tokens, key
  formats; email addresses and card numbers). Binary or compressed bodies are kept and noted.
  The URL and label are redacted too. The engagement's `redact_evidence` setting applies.
  The uploaded file itself is never stored, only its SHA-256.
- **Dedupe.** By content: method, redacted URL, status and the hashes of the redacted
  request and response. Without raw bytes, the tool's id counts too, so two different
  requests are not merged because the export lacked their bytes.
- **Storage.** Request, response and a small record (`attackledger-import/1`: tool, file
  hash, row, tool id and time, method, URL, status, label, the two blob hashes, notes,
  redaction) go through `blobs.put(..., engagement_id=...)`. Mapped evidence commits to
  the record's hash, so the chain reaches the raw bytes through it.

## Inbox and mapping

- Tables `import_batches` and `inbox_entries` (migration `0019`).
- A person maps entries to one or more items on a lane of the entry's own host. Each pair
  appends one evidence entry: kind `response` (or `request` without a response), the
  record's hash, the URL, and a summary "Imported from <format>, row <n>: <method> <url> ->
  <status> (<label>). <note>" with the redaction note; `source="import:<tool>"`. Mapping
  the same entry to the same item again adds nothing.
- Suggestions: rules on the path, parameter names, method, status and response headers
  point at items whose text uses one of their words, plus path words that appear in an
  item's text. At most three per lane, six in all, each with its reason. The rules are
  listed in the Import view and at `GET /imports/formats`.
- Dismissing sets an entry aside with who, when and why; it is never deleted and can be
  restored. Each import, dismissal and restore is an audit log entry (`import.batch`,
  `import.dismissed`, `import.restored`).
- Roles: testers and owners import, map, dismiss and restore; viewers read the inbox,
  the files and the stored bytes.

API: `GET /imports/formats`; `POST /engagements/{id}/imports?format=&filename=` (the file is
the request body); `GET /engagements/{id}/imports`; `GET /engagements/{id}/inbox` (filters
`state`, `host`, `method`, `status` as `404`, `4xx` or `none`, `batch`, `q`, paging);
`GET /engagements/{id}/inbox/{entry}`, `.../raw/{request|response|record}`;
`POST /engagements/{id}/inbox/map`, `/dismiss`, `/restore`.

## Caido: what to check against a real export

The Caido adapter follows the sample on Caido's documentation page "Exporting Request
Data", not a file exported from a running Caido. Before relying on it:
1. The top level is a JSON array (the adapter also accepts `{"requests": [...]}`, which is
   a guess).
2. `created_at` is epoch milliseconds on the request (and on the response).
3. `raw` and `response.raw` are base64 of the exact bytes, and are empty or missing when
   the export leaves them out (the UI's options).
4. `port` is a number and `query` has no leading `?`.
5. `source`, `edited` and `alteration` values, used as the label.
6. Large exports: whether Caido splits them, and whether the file is ever compressed.
7. Findings export (not imported yet): its layout was not found in public sources.
