# Evidence import

Status: built 2026-10-09 (D-029, MVP item 4). The design is in `TARGET_ARCHITECTURE.md`,
"Evidence import". This page says what was built and how each format is read.
It is the technical description. For how a tester exports from Burp, Caido or a browser
and maps entries in the app, see [`TESTER_GUIDE.md`](TESTER_GUIDE.md), section 5.

A tester uploads an export file from a tool they already use. Its in-scope entries wait
in the engagement's inbox, redacted, until a person maps each one to checklist items.
Nothing reaches the ledger without that step. The server imports files only and holds no
tool's token. To pull history from Caido's API instead of exporting it by hand, a tester
runs `tools/caido_pull.py` on their own machine; it writes the same Caido JSON file and can
upload it (see "Pull from Caido" below).

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
  else about it is stored. The audit log entry `import.batch` records counts only,
  including how many distinct hosts were refused, and never their names or the file name.
  Names stay in the batch row, which deleting the engagement's content clears. Entries
  written before 0.7 still name the refused hosts and the file: the audit log is
  hash-chained and cannot be edited, so they stay in it and in the JSON of reports that
  carry it; History and the HTML report show only a count.
- **Redaction** (`redact.http_message`, D-038 conventions). Every header line of the raw
  request and response goes through the header rules whatever its name (Cookie,
  Set-Cookie, Authorization, Proxy-Authorization, X-Api-Key and other secret names, and
  tokens or secret parameters inside other headers); the request line and body go through
  the text rules (secret query and form parameters, JSON keys, JWTs, bearer tokens, key
  formats; email addresses and card numbers). Binary or compressed bodies are kept and noted.
  A Content-Length that matched the body is rewritten to the stored body's length.
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

- Tables `import_batches` and `inbox_entries` (migration `0018`).
- Every lane of the pack on the entry's host is offered. Choosing an item on a lane that
  is not open opens it, and adds the host if it is in the scope rules but not yet in the
  ledger. Mapping does not mark items done unless `mark_done` is set ("Mark these items
  done"); lanes count items that have evidence and wait to be marked done
  (`awaiting_done`).
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
- Roles: testers and owners import, map, dismiss and restore; reviewers and viewers read
  the inbox, including dismissed entries and their reasons, the files and the stored
  bytes. The lane view carries the host's inbox counts (`inbox: {new, mapped, dismissed}`)
  for the reviewer.
- A file with the same SHA-256 as an earlier import is refused with 409
  (`already_imported`, naming the earlier batch). Send it again with `reimport=true` to
  import it anyway; its rows already in the inbox count as duplicates.

API: `GET /imports/formats`; `POST /engagements/{id}/imports?format=&filename=&reimport=` (the file is
the request body); `GET /engagements/{id}/imports`; `GET /engagements/{id}/inbox` (filters
`state`, `host`, `method`, `status` as `404`, `4xx` or `none`, `batch`, `q`, paging);
`GET /engagements/{id}/inbox/{entry}`, `.../raw/{request|response|record}`;
`POST /engagements/{id}/inbox/map` (with `mark_done`), `/dismiss`, `/restore`.

## Pull from Caido (`tools/caido_pull.py`)

Added 2026-10-09 (D-035). A command-line tool the tester runs on their own machine, next to
their Caido. Standard library only (Python 3.9 or later), so nothing has to be installed.

```
your machine                                                       AttackLedger server
Caido ◄── GraphQL, Bearer <Caido token> ── caido_pull.py ── file ── POST /engagements/{id}/imports
(127.0.0.1:8080)                            (redacts if asked)       (your session or the operator token;
                                                                      the Caido token is never sent)
```

1. It reads the Caido token from an environment variable (`CAIDO_TOKEN`, or the name given
   with `--token-env`) or from a file (`--token-file`). It never takes it on the command line,
   because shell history would keep it; an unknown option such as `--token` is refused and
   its value is not echoed. A token file readable by other users gets a warning. A Caido
   personal access token (`caido_...`) is refused before anything is sent; see below.
2. It checks Caido's version (`runtime { version }`), then pages through the `requests`
   query with the HTTPQL filter (`--filter`, required) and an optional window (`--since`,
   `--until`, sent as `req.created_at.gt` / `.lt`), oldest first, 100 per page by default.
3. It writes a JSON array in the layout the Caido adapter above reads: `id`, `host`, `port`,
   `is_tls`, `method`, `path`, `query`, `created_at` (epoch ms), `raw` (base64), `source`,
   `alteration` and `edited` (in lower case, as Caido's own export writes them), `length`,
   and `response` with `id`, `status_code`, `raw`, `created_at`, `roundtrip_time`, `length`.
   A request Caido holds no raw bytes for is written without `raw`, as in an export. The
   file is written with owner-only permissions and is never overwritten without
   `--overwrite`. It stops at one import's worth (5,000 rows or 50 MB) and prints the
   `--since` value to continue from.
4. With `--upload <AttackLedger address> --engagement <name or number>` it sends the file
   to the import API (a name is looked up in `GET /engagements`, among those the tester can
   read): signed in with `--al-email` (the password is asked for at the prompt; the session
   is ended afterwards) or with the operator token (`ATTACKLEDGER_TOKEN` or
   `--al-token-file`). The tester needs the tester role on the engagement. A file already
   imported is refused unless `--reimport` is given.

What goes where:
- The **Caido token** goes only to the Caido address given (`--caido`, default
  `http://127.0.0.1:8080`), in the `Authorization` header. It is never sent to AttackLedger,
  written to the file, printed or logged; every message the tool prints is scrubbed of it
  and of the AttackLedger credentials. Tests check each of these.
- **No proxy, no redirects.** The tool ignores `HTTP_PROXY` and the like (a tester's proxy is
  often Caido itself, which would record the token in its own history) and refuses to
  follow a redirect (urllib would resend the `Authorization` header to the new address).
  Plain `http://` to anything but this machine is refused unless `--insecure-http` is given.
- **Redaction** still happens on the server at import, as for any file. With
  `--redact-locally` the tool applies the same rules before writing the file, so cookies,
  authorization headers and other secrets never reach the disk: `server/app/redact.py`
  itself when the tool runs from the repository (the raw request and response through
  `http_message`, as the import does, and the `path` and `query` fields through `text`;
  this needs Python 3.10 or later, like the server); otherwise, a minimal copy of its header and parameter rules inside the tool
  (cookies, authorization, secret header names, secret query and form parameters; not
  bodies, JWT and key formats elsewhere, or personal data, which the server still redacts).
  A test checks the copy against the server's rules, and that a file redacted locally
  imports as exact duplicates of the same rows redacted by the server.

**The Caido token.** Caido's instance API takes an access token. Caido documents getting
one from a signed-in Caido (docs.caido.io, "GraphQL"): open the developer tools
(Ctrl+Shift+I), and in the Console run
`JSON.parse(localStorage.CAIDO_AUTHENTICATION).accessToken`. It expires after 7 days.
A Caido personal access token (`caido_...`, made on the Developer page of the Caido
dashboard) is not accepted by the instance directly: Caido's SDK exchanges it through a
device-code flow with Caido's cloud (`api.caido.io`) and a WebSocket subscription. This tool
does not do that exchange, so the token never leaves the machine at all.

**Checked against.** Caido's public GraphQL schema, `caido/schemas` on GitHub,
`schemas/proxy/schema.graphql` at proxy schema **v0.58.3** (commit 7ec5a39, 2026-09-04), and
the query shapes in Caido's client SDK (`caido/sdk-js`, `packages/sdk-client/src/transport/
latest/documents/request.graphql`: fragments `RequestFull` and `ResponseFull`, query
`Requests`). Raw bytes (`Blob`) are base64, as the SDK decodes them; `createdAt`
(`Timestamp`) is read as epoch milliseconds, a string of digits or an ISO 8601 time;
authorization errors carry `extensions.CAIDO.code = "AUTHORIZATION"` with a reason
(`INVALID_TOKEN`, `FORBIDDEN`, `MISSING_SCOPE`); HTTPQL's `created_at` takes `gt` and `lt`
(docs.caido.io, HTTPQL reference). **The queries were checked against this public schema and
Caido's documentation, not against a live Caido instance.** Caido says its schema may change
with any release. An answer of another shape (a missing field, a field of another type,
invalid base64, a query the server rejects as naming unknown fields) stops the pull with a
message naming the field, the schema version above and the version the instance reports;
nothing is written. The tests use a fake Caido GraphQL server on localhost that follows the
schema above, and answers wrongly on purpose.

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
8. `tools/caido_pull.py` against a live Caido: that its `requests` query is accepted, that
   `createdAt` and `raw` come as read here, and that its file imports like an export from
   Caido's Exports page.
