# Security review: traffic gateway and worker isolation

Date: 2026-10-10. Branch `sec-review-gw`, from `c3557a5`. White-box review of AttackLedger's own
code, with every suspected issue proved by a failing test first. All traffic stayed on localhost:
the tests run a real gateway in-process in front of local stub upstreams on 127.0.0.1, and one
Docker experiment (compose project `al-sec-gw`, no published ports, torn down) measured how
Docker's resolver answers for a container on two networks.

The question asked: does the gateway keep every test in scope, and is the worker really
isolated? The threat model is the one in `docs/GATEWAY.md`: a tool or the whole worker process
is buggy or malicious, and targets are untrusted.

## Summary

| ID | Severity | Finding | Fix | Regression tests |
|---|---|---|---|---|
| GW-1 | High | An agent job could make Anthropic's servers fetch any URL (server tools, MCP connector, URL sources) | `8bf5ba1` | `test_gw1_*` (3 tests, 7 cases) |
| GW-2 | Medium | Upstream connections and TLS handshakes were not paced by the rate ceiling | `524089b` | `test_gw2_*` (2) |
| GW-3 | Medium | A compressed response leaked a test account's session to the worker and the evidence | `d15013f` | `test_gw3_*` (2 tests, 3 cases) |
| GW-4 | Low | A reflected session in another encoding (URL-decoded, escaped) was not scrubbed | `d15013f` | `test_gw4_*` (1) |
| GW-5 | Low | Cloud metadata services outside link-local were not refused | `9c0a042` | `test_gw5_*` (1) |
| GW-6 | Low | One of the API's two addresses was not in the deny set | `1d19f53` | `test_gw6_*` (2 cases) |
| GW-7 | Low | A job target with a newline passed the scope gate and became two tool targets | `6e069cd` | `test_gw7_*` (5 cases) |

All tests are in `server/tests/test_security_gateway.py`. Each one failed before its fix and
passes after it. Test suite: 758 passed and 1 skipped before; 779 passed and 1 skipped after.

A second pass (branch `sec2-hardening`, from `c7a0c25`) closed the recommendations listed under
"Not changed; worth knowing", and found one more way out to the Docker host while measuring the
first (GW-8):

| ID | Severity | Finding | Fix | Regression tests |
|---|---|---|---|---|
| GW-8 | Medium | The Docker host was reachable: through the gateway at its address on the gateway's networks, and from the worker directly on the internal network | `a86247d` | `test_gw8_*` (4 tests, 6 cases) |
| GW-9 | Low | The proxy, the resolver and the control relay listened on every network of the gateway | `a86247d` | `test_gw9_*`, `test_gw8_gw9_*` (3 tests, 5 cases) |
| GW-10 | Low | A test account's or an approved write's header with CR, LF or another character the gateway cannot write ended the connection after the approval was used, with no log row | `52606b4` | `test_gw10_*` (7 tests, 13 cases) |
| (test) | none | A flaky worker test depended on DNS answers for `gateway.invalid` | `bccdc48` | `test_worker.py` (2 tests, made deterministic) |

GW-8 to GW-10 tests are in `test_security_gateway.py`, the end-to-end ones for GW-10 (real API,
real gateway) in `test_test_accounts.py`. Test suite: 790 passed and 1 skipped before; 816 passed
and 1 skipped after, three runs in a row.

## Findings

### GW-1 (High): Claude API calls could make Anthropic fetch for the worker

**Where.** `gateway.Policy.check` for kind `service`, and `Gateway._request`.

**What.** An agent job may reach `api.anthropic.com` with `POST /v1/messages` and
`/v1/messages/count_tokens`. The gateway checked the method and the path, added its own API key,
and forwarded the body unread. The Messages API can reach other hosts on a request's behalf:

- server tools (`web_fetch_*`, `web_search_*`) fetch or search URLs from Anthropic's servers;
- the MCP connector (`mcp_servers`, with the `anthropic-beta` header, which the gateway also
  forwarded) connects to any URL the request names;
- `image` and `document` blocks with a `{"type": "url"}` source are fetched by Anthropic.

So a compromised worker holding an agent job's credential could send requests to hosts outside
the engagement's scope, without the research identification, outside the rate ceiling, and with
nothing in the request log but one `POST /v1/messages` row. It could also send everything the
worker holds (lane context, recon output) to a server of its choice through an MCP URL, a channel
that `GATEWAY.md` did not list among the remaining exfiltration paths. The agent loop itself
(`agentloop.request_params`) uses only its own custom tools, so none of this is needed.

**Reproduction.** `test_gw1_claude_api_calls_cannot_make_anthropic_fetch_for_the_worker`: an
agent job sends five bodies through the gateway (a `web_fetch` tool, a `web_search` tool beside
the agent's own tool, `mcp_servers`, an image URL source, a document URL source). Before the
fix, each reached the stub upstream with status 200.

**Fix.** `Policy.check_service_body`. The gateway reads the body (it already did, to forward it)
and sends it only if it is a single JSON object, parsed with duplicate keys refused (the body is
forwarded as received, and another parser might keep the other copy of a key); its top-level
keys are among those an agent run sends (`SERVICE_BODY_KEYS`); every tool is a custom tool; and
no dictionary in `messages` or `system` has `"type": "url"`. Anything else is refused with 403
and logged. `test_gw1_duplicate_keys_and_non_json_bodies_are_refused` covers the strict parse
(including a gzip body); `test_gw1_the_agents_own_calls_are_still_sent` is the positive control:
the request `agentloop.request_params` builds, with a tool result whose text contains
`{"type": "url"}`, is still sent, and so is `count_tokens`.

### GW-2 (Medium): connections to targets were not paced

**Where.** `Gateway._forward`.

**What.** The rate token is taken after the upstream connection is open, just before the request
head is written. That is deliberate (`GATEWAY.md` decision 5): it keeps the head's departure
close to the token's time, which is what makes "no 1.05-second window holds more than *rate*
requests" hold downstream. But the TCP connection, and for HTTPS the whole TLS handshake, came
before the token and were not limited at all. A tool with high concurrency, or a buggy one that
ignores its own `-rl`, opened as many connections to the target at once as it had threads; each
then waited for a token, up to 30 seconds, and a request refused with 429 had already connected.
Targets and their WAFs see connections and TLS handshakes, not only request heads.

**Reproduction.** `test_gw2_connections_to_targets_are_paced_like_requests`: rate 3, nine
concurrent requests. Before the fix all nine connections opened within 1 ms (`peak = 9`);
request heads stayed at 3 per window. `test_gw2_a_request_refused_for_the_rate_opens_no_connection`:
rate 1, a 0.2-second wait limit, five concurrent requests: before the fix all five connected.

**Fix.** A second limiter, taken before resolving and connecting (`Gateway.connect_limiter`): per
engagement at the engagement's rate for targets, per host at `PASSIVE_RPS` for passive sources.
The request token stays where it was, so both the connections and the request heads are each at
most *rate* per window. A single limiter taken before connecting was rejected: connect times
vary by seconds, so heads could bunch up and break the per-window ceiling. Service calls (the
Claude API) are not paced, as before.

**Recheck.** Port probes still connected after the request token only, so probes beside requests
opened up to twice the rate in connections. Since the recheck a probe waits for the connection
limiter too (`RECHECK.md`, GW-2).

### GW-3 (Medium): a compressed response leaked a test account's session

**Where.** `Gateway._scrubbed`, `scrub_response`.

**What.** A request sent as a test account goes out with `Accept-Encoding: identity`, and its
response is read whole and scrubbed: each value of the account's headers becomes a redaction
marker, then `redact.data` redacts cookies and tokens. A target may compress anyway (some
servers and frameworks ignore `Accept-Encoding`). The literal search found nothing in gzip or
deflate bytes, and `redact.data` treats compressed bytes as binary and keeps them unchanged. The
response went back with its `Content-Encoding`, so a page that reflects the session (a debug page,
an echo endpoint) handed it to the worker, which decompresses it in one line. It also reached the
evidence: `agenttools.record_exchange` redacts with the same `redact.data`, which skips binary
content, so the stored exchange held the live session for anyone who can read the evidence.

**Reproduction.** `test_gw3_a_compressed_response_is_scrubbed_too[gzip]` and `[deflate]`: the stub
upstream echoes the request's `Cookie` header in a compressed body. Before the fix the client
received the session value after decompressing.

**Fix.** `_scrubbed` decodes a gzip, x-gzip or deflate body (bounded at `MAX_SCRUBBED_BODY`, so a
compression bomb is cut off) and removes `Content-Encoding` before the scrub. A body in an
encoding the gateway cannot read (br, zstd, several encodings) is withheld: the client gets the
status and headers with an empty body, and the log row says why
(`test_gw3_an_encoding_the_gateway_cannot_read_is_not_passed_on`).

**Recheck.** A gzip body of several members was cut to its first (no leak, but a silently
shortened response); every member is now decoded (`RECHECK.md`, GW-3).

### GW-4 (Low): reflected sessions in another encoding were not scrubbed

**Where.** `gateway.account_values`.

**What.** The scrub searched for each header value, each cookie value and a bearer token
exactly as sent. Pages often show them transformed: `phpinfo()` and framework debug pages list
`$_COOKIE` URL-decoded (a Laravel session cookie ends in `%3D`, shown as `=`), JSON encoders in
PHP escape `/` as `\/`, and HTML escapes `&`. `redact.data` does not catch a long base64 value
in an HTML table cell. The session then reached the worker and the evidence.

**Reproduction.** `test_gw4_a_reflected_session_is_scrubbed_in_its_decoded_and_escaped_forms`:
`scrub_response` over a phpinfo-like page with the cookie value URL-decoded, a value with
JSON-escaped slashes and one HTML-escaped. Before the fix all three were left in place.

**Fix.** Each value is also searched for URL-decoded (`unquote`, `unquote_plus`), URL-encoded,
HTML-escaped (with and without quotes) and with escaped slashes, longest first, at least
`MIN_SCRUB` characters. Other transformations (base64 of a value, partial values) are not covered;
the gateway still cannot know every way a target re-encodes what it was sent.

### GW-5 (Low): cloud metadata services outside link-local

**Where.** `Gateway.resolve`.

**What.** The gateway refuses link-local addresses, which covers 169.254.169.254 (AWS over IPv4,
GCP, Azure IMDS, Oracle). Several metadata services live elsewhere and were allowed: Alibaba
Cloud at 100.100.100.200, AWS over IPv6 at `fd00:ec2::254` (Nitro instances), Azure's WireServer
at 168.63.129.16, Oracle Cloud Classic at 192.0.0.192. A gateway deployed there was one in-scope
name away from them (an internal pentest scope, or a target's DNS record).

**Reproduction.** `test_gw5_metadata_addresses_outside_link_local_are_refused`: names resolving
to each address, and the address literal, were allowed before the fix.

**Fix.** `METADATA_ADDRESSES`, refused like loopback. A neighbouring address (100.100.100.201)
stays allowed.

### GW-6 (Low): one of the API's two addresses was not refused

**Where.** `Gateway._denied_addresses`, `DENY_HOSTS`, `docker-compose.yml`.

**What.** The gateway refuses the deployment's own containers by resolving their names (`db`,
`api`, `web`, `worker`, `gateway`) and refusing those addresses. Docker's resolver answers a
service name with the container's address on one shared network only. Measured with a two-network
compose project: the API container had 172.22.0.2 and 172.23.0.2, and `getaddrinfo("api")` from
the gateway returned only one of them (which one varied between runs). The API is on both the
`control` and `default` networks with the gateway, so its other address was reachable through
the proxy whenever an in-scope name resolved to it (internal DNS records pointing at RFC 1918
addresses are common, and private addresses are allowed on purpose). Without accounts the API
treats every caller as an owner; in production it trusts `X-Forwarded-For` from any peer
(`--forwarded-allow-ips "*"`), and the proxy forwards a tool's headers. In production Caddy (on
the default network) and the lab proxy (on two networks) were not in the list either.

**Reproduction.** `test_gw6_every_address_of_the_deployments_containers_is_refused`, for the
development and the production compose files: for every service that shares networks with the
gateway, one shared network needs its name in `DENY_HOSTS`, and two need an alias per network
that is in it. It failed on `api` before the fix.

**Fix.** The API has the aliases `api-control` and `api-default`, the lab proxy `lab-proxy-lab`
and `lab-proxy-default`, and `DENY_HOSTS` lists them with `caddy` and `lab-proxy`. A name that
does not exist in a deployment (Caddy in development) simply resolves to nothing.

### GW-7 (Low): a job target could carry a second target to the tools

**Where.** `jobgates.split_targets` (applied when a job is queued and again at claim time).

**What.** Recon tools read their targets one per line on stdin (`worker.Run.tool_lines`). The
scope check for URL targets uses `urllib.parse.urlsplit`, which removes tabs and newlines before
parsing, so `https://in.scope/\nhttps://elsewhere/` was checked as one in-scope URL and given to
the tool as two targets. Such a value can come from a person queueing a job or from recon output
(an endpoint stored from a crawled page, which later becomes a target). The gateway still refuses
the second host, so nothing out of scope is sent; this restores the first layer.

**Reproduction.** `test_gw7_a_target_cannot_carry_a_second_line_to_the_tools`: newline, carriage
return, tab, space and NUL inside a URL target were allowed before the fix.

**Fix.** `jobgates.one_line`: a target with whitespace or a control character is refused (the
claim then logs it as skipped, like any target outside scope). Targets are already stripped at
both ends before this check (`normalize_targets`).

## Second pass: the recommendations, closed

### GW-8 (Medium): the Docker host was reachable through the gateway, and from the worker

**Where.** `Gateway.resolve`, the networks in `docker-compose.yml`.

**What.** Private addresses are allowed (internal pentests need them), so an in-scope name that
resolved to the Docker host's address on one of the gateway's networks (`172.x.0.1`), or to
anything else in those subnets, was connected to. Measured on Docker 29.5.2 (compose project
`al-sec2`, no published ports, torn down): the host holds the first address of *every* bridge
network, internal ones included, and a listener the host ran on those addresses answered:

- through the gateway's own sockets, on the default network's, the internal network's and the
  lab network's host address (172.24.0.1, 172.25.0.1, 172.21.0.1 in that run), and on another
  compose project's bridge (172.20.0.1), which the gateway reaches over its default route;
- **from the worker itself, without the gateway**, on the internal network's host address
  (172.25.0.1). The worker has no route out, but it had the host: any service the host runs on
  all interfaces (SSH, a database, a metrics agent) was one connection away from a compromised
  tool, with nothing in the request log.

**Reproduction.** `test_gw8_the_gateways_own_networks_are_refused_except_the_labs`: names that
resolve to the host's bridge address, to a container's address and to an IPv6 address in the
gateway's networks were allowed before the fix; `test_gw8_the_docker_host_has_no_address_on_the_worker_and_gateway_internal_networks`
(both compose files and the benchmark override) failed on `internal`.

**Fix.**

- The gateway reads the subnets of its interfaces from `/proc/net/route` (directly connected
  routes, not the default route) and `/proc/net/if_inet6` (global prefixes), standard library
  only (`gateway.interface_networks`, refreshed every minute), and refuses every address in
  them (`Gateway.own_networks`). The exception is a network that holds targets:
  `ATTACKLEDGER_GATEWAY_TARGET_NETWORKS` names it, in the compose files by `gateway-lab`, the
  gateway's own alias on the lab network (Docker answers an alias with the address on that
  network). An address or a subnet works too, for a deployment whose gateway sits on a
  customer's LAN. A name that does not resolve marks nothing, so its network stays refused
  (fail closed). `gateway-lab` is in `DENY_HOSTS`, so the gateway's own lab address is refused.
- Real internal targets stay allowed: a destination inside the subnet of one of the gateway's
  interfaces is routed to that Docker network, never to a customer's network that happens to
  use the same range, so refusing it takes nothing away. 10.x, 172.16/12 and 192.168/16
  addresses outside those subnets are allowed as before (`bank.example.com`, `corp.example.com`
  in the test).
- The four internal networks (`internal`, `control`, `database`, `lab`) set
  `com.docker.network.bridge.inhibit_ipv4`: the host has no address on them. Measured after the
  change: the host's address list no longer holds them, the host cannot even bind one, the
  worker reaches nothing but the gateway, and lab recon through the gateway still works (a probe
  job: `GET http://shop.lab.test/` 200, DNS answered), while a job against `172.25.0.1` (the
  default network's host address) is refused with "on the gateway's own network".
  `test_gw8_the_gateway_reads_its_networks_from_proc` covers the parsing (default route,
  routed and down routes, loopback and link-local left out).

**Left open.** The host is still reachable through the gateway at addresses on networks the
gateway is not on: another compose project's bridge, `docker0`, the host's LAN address. The
gateway cannot know them from inside its container, and a customer's network may well be the
host's LAN. Closing that needs a rule on the host (drop the new connections the project's
default bridge opens to the host itself, `INPUT -i br-<id> --ctstate NEW`), which
`docs/INSTALL.md` section 6 now suggests; that rule was not measured in this pass.

### GW-9 (Low): the gateway listened on every network it is on

**Where.** `Gateway.serve`, `main`.

**What.** The proxy (8080), the resolver (53) and the control relay (8081) were bound to
`0.0.0.0`, so they also answered on the `control`, `default` and `lab` networks. Each still needs
a job credential or a worker token, so this was defence in depth only.

**Fix.** `ATTACKLEDGER_GATEWAY_LISTEN=gateway-internal` (both compose files, through
`docker-compose.yml`; the benchmark override keeps the alias): `gateway.listen_addresses`
resolves the gateway's alias on the worker's network, keeps only this container's own
addresses (a name another container shares is skipped), and `Gateway.start` binds the three
there. The proxy is bound to loopback too, so the healthchecks (`127.0.0.1:8080`) keep working.
Measured in `al-sec2`: the gateway listened on its internal address only; from the API's
container its control and default addresses refused 8080 and 8081; the worker reached the
proxy (407 without a credential), the resolver (REFUSED for an unknown name) and the relay
(it claimed jobs). Empty, the setting keeps the old behaviour (`0.0.0.0`).

Why by address, and what makes it fragile: Docker gives no interface names in a container, so
the address is the only handle. It is read once, at start: Docker keeps a container's address
for as long as it is attached, and a restarted gateway reads it again. A gateway disconnected
and reconnected to the network (`docker network connect`) by hand would keep listening on the
old address until it is restarted. Docker's resolver may not answer the alias in the first
instant, so the gateway retries for 30 seconds, then exits with the reason instead of falling
back to every interface; the restart policy starts it again. The worker and its configuration
did not change: it resolves `gateway` on its only network, which gives this same address
(`test_gw8_gw9_the_compose_files_name_the_lab_network_and_the_workers_network` checks that
both compose files and the benchmark override agree). `test_gw9_the_relay_the_proxy_and_the_resolver_answer_on_the_listen_address_only`
binds to 127.0.0.2 and finds every part refusing on 127.0.0.3.

### GW-10 (Low): a header the gateway cannot write ended the connection

**Where.** `testaccounts.material`, `agenttools.check_headers`, `approvals.propose`, `approve`,
`consume`; `Policy.headers`, `Policy.inject_credentials`, `Gateway.account_for`, `_forward`.

**What.** An approved write's headers (D-041) and a test account's (D-040) come from people and
the API, and were checked by h11 only when the gateway wrote the request. Measured before the
fix: a test account pasted as header lines kept a lone CR inside a line, and a control character
or a non-Latin-1 cookie was stored; an approved request with a CR, LF, NUL or a character outside
Latin-1 in a header was used (`write.sent` in the audit log) and then the gateway's connection
ended (`UnicodeEncodeError`, or h11's `LocalProtocolError`) with no row in the request log, so
the approval was spent and nothing said why. An agent could propose a header name that is not a
token (`X(y)`) or a value with `€`.

**Reproduction.** `test_gw10_an_approved_header_the_gateway_cannot_write_is_a_refused_row` (four
values) and `test_gw10_a_test_accounts_header_the_gateway_cannot_write_is_refused_before_the_approval`
got a closed connection (status 0) and no log row; `test_gw10_account_material_the_gateway_cannot_send_is_refused_with_422`
(four materials) got 201; `test_gw10_the_agent_cannot_propose_or_send_a_header_the_gateway_cannot_write`
got a stored proposal; `test_gw10_an_approval_of_a_header_the_gateway_cannot_write_is_never_used`
could approve it.

**Fix.** One rule, `gateway.header_problem`: a header name is a token, a value has no control
character (a tab inside aside), nothing outside Latin-1 and no space at either end. It is stricter
than h11, never looser (`test_gw10_what_the_gateway_accepts_h11_can_write` tries every character
up to U+017F). Where the values come in: test accounts answer 422 with the header's name and the
reason; the agent's `http_request` and `propose_write` get a tool error; a stored proposal with
such a header cannot be approved (422, "reject it instead"), and an approval given before it is
not used: `consume` marks the write failed with the reason, before `write.sent`. In the gateway, a
test account's headers are checked when they arrive (403, before any approval is used), an
approved request's when it is built (400, a `refused` row with the approval id), and the whole
head is built by h11 before anything is connected, so whatever still fails is a `refused` row,
never a connection ended by an error. No message or log row repeats a value (it may be a session).
The engagement's research header was already one line (`main.ScopeIn`); one that h11 would still
refuse (a vertical tab) is now a refusal in the log too
(`test_gw10_an_identification_h11_would_not_write_is_a_refused_row`, added with this report).

### The flaky worker test

`test_worker.py::test_tool_runs_get_the_gateway_and_never_log_the_secret_or_the_tokens` built the
tool's environment and its expected proxy URL with two separate lookups of `gateway.invalid`
(`Egress._proxy_address`). A resolver that answers that name inconsistently (a search domain that
answers some of the time, a timeout) made the two differ. Reproduced with an injected resolver
that alternates: it failed every time, and so did `test_every_tool_is_pointed_at_the_gateway`.
`conftest.py` now answers names under `.invalid` itself, at once, as RFC 6761 says they resolve:
never (the suite also stops sending those questions to the machine's resolver). The test spells
out the expected URL (this job's credential, the configured address) instead of recomputing it,
and checks `HTTP_PROXY` and `ALL_PROXY` too.

## What was checked and found sound

Files read in full: `server/app/gateway.py`, `gatewayapi.py`, `egress.py`, `scope.py`, `urls.py`,
`workerapi.py`, `workerclient.py`, `nucleisafe.py`, `jobgates.py`, `executors.py`, the relevant
parts of `reconsteps.py`, `authz.py`, `auth.py`, `orgscope.py`, `redact.py`, `agenttools.py`,
`agentloop.py`, `worker/worker.py`, both compose files and the Caddyfile.

**Scope and host parsing** (`split_authority`, `scope.normalize_host`, `scope.in_scope`,
`Policy.classify`):

- IP literals in other notations fail closed. Scope matching is an exact string comparison after
  lower-casing and removing one trailing dot; `2130706433`, `0x7f.0.0.1` and `0177.0.0.1` match
  only a rule written that way, and a decimal integer has no dot, so `normalize_host` rejects it.
  IPv6 literals cannot be in scope at all (`:` is not a host-name character). `resolve` uses
  `ipaddress`, which rejects leading zeros, and only for a host that already passed the scope.
- Trailing dots and case are normalised the same way for the scope check and the connection.
  Non-ASCII names are out of scope; punycode matches only a rule that names it.
- Userinfo (`a@b`) is refused twice: `urlsplit` username or password, and `@` in
  `split_authority`. Backslashes, spaces and `#`/`?` in the authority are refused.
- Absolute form against `Host`: the client's `Host` is dropped (`HOP_BY_HOP`) and rebuilt from the
  URL. Inside a tunnel, `Host` must name the tunnel's host; the upstream `Host` is rebuilt from the
  tunnel either way. `https://` in absolute form is refused.

**CONNECT and tunnels** (`_connect`, `_serve`, `_probe`): the credential and the scope are checked
before the tunnel opens; a deployment name (no dot) is never in scope and its addresses are
refused at connect time; bytes sent before the `200` are not relayed; a tunnel that does not start
TLS with the gateway's certificate is closed; each request inside re-checks the credential
(2-second cache) and the scope. Probes are for in-scope targets only, take a rate token, refuse
port 25 and relay nothing.

**Redirects.** The gateway never follows one (one request per connection, the response is passed
back). The worker's openers refuse them (`egress._NoRedirect`, `worker._NoRedirect`), nuclei runs
with `-dr`.

**DNS rebinding and addresses** (`resolve`, `_forward`): the gateway resolves the name itself,
checks the first address, connects to that address (SNI and `Host` keep the name), so an answer
cannot change between check and use. Tools' own DNS answers do not matter: tools never connect to
targets themselves. Loopback, link-local (including 169.254.169.254), multicast, unspecified and
IPv4-mapped forms of them are refused (since the recheck also the NAT64, 6to4 and IPv4-compatible
forms: `RECHECK.md`). Private addresses are allowed by design.

**Request smuggling and header injection** (`Policy.check`, `Policy.headers`, `_forward`):
requests are parsed by h11 0.16 and re-serialised; client `Content-Length` and
`Transfer-Encoding` are never forwarded (the gateway frames the body itself); a read-only request
with `Transfer-Encoding` or `Content-Length` above 0 is refused and must end at the head; h11
rejects CR, LF and NUL in names and values on parse and on send, and unfolds obsolete line
folding into one value. Method overrides (`X-HTTP-Method-Override` and the like, `_method=`),
`Upgrade`, asterisk-form and methods other than GET, HEAD and OPTIONS (without an approval) are
refused. The identification cannot be forged: headers of the same names are removed first.
`Proxy-Authorization` and every `X-AttackLedger-*` header are removed.

**Rate ceiling** (`Limiter`, `limiter`): one limiter per engagement, shared by every job, worker
and connection (existing test with two jobs and 40 concurrent clients); with GW-2 fixed,
connections are paced too. A finished or cancelled job's credential stops working within the
2-second cache (`RULES_TTL`), as documented.

**Job credentials** (`credential`, `rules_for`, `gatewayapi._running_job`, `workerapi.end_tokens`):
the secret is 256 bits, stored as a SHA-256 and compared with `hmac.compare_digest`; the API
answers only for a running job of an authorized engagement with scope; the answer names one
engagement and the job's traffic class; the secret is cleared when the job finishes and when the
sweep marks it interrupted. 503 answers are not cached.

**Secrets kept from the worker and the logs.** The Anthropic key is added only to service calls,
after any client key header is removed, and is never logged; the worker's tools get a minimal
environment (`Egress.env`). Test-account headers are not in the claim, the lane context or the
request log (labels only). The job log masks the gateway secret (`Run.log`, `Egress.mask`).

**Worker channel** (`Gateway.handle_control`, `CONTROL_PATH`, `authz.RULES`, `authz._job_caller`):
the relay accepts only `GET`/`POST` and paths matching `^/worker/[a-z0-9/_-]{0,200}$`, so `..`,
`%2e%2e`, `;`, `?`, encoded slashes and backslashes never reach the API (existing tests); `//`
reaches no route. Only `Authorization` and `Content-Type` are forwarded. urllib follows a redirect
for a GET only, and Starlette's slash redirect stays on the API's own `/worker/` path. Every
`/worker/*` route needs the worker token or the job token of the job in its path, while the job
is held.

**What a job may write** (`workerapi.WRITES`, `results`, `progress`, `agent_exchange`,
`agent_call`): categories, observation fields and lead kinds are checked per kind; every host and
URL is checked against the job's own engagement's current scope; the worker cannot name an
engagement or organization (both come from the job); agent writes go through `agenttools.Toolbox`
with the lane's gates and `AGENT_CALLS`; the token stops working at `finish`.

**Job arguments and nuclei** (`nucleisafe.classify`, `worker.nuclei_cmd`, `worker.commands`):
tools run from argument lists, never a shell. The arguments a job influences are its targets
(fed on stdin, now one line each) and nuclei's stack tags, which are reduced to `[a-z0-9-]`. The
template classifier is an allowlist (methods, raw request line and target, `Host`, bodies,
override headers, `_method`, flows, self-contained templates, out-of-band references); the
exclusion list is re-verified before the first scan; nuclei runs with `-et`, `-ni`, `-dr` and the
gateway proxy, so a classifier miss would still meet the gateway's method and scope checks.

## Not changed; worth knowing

- ~~**The Docker host is reachable.**~~ Closed for the gateway's own networks and the worker:
  GW-8. Still open: the host's addresses on networks the gateway is not on (see GW-8, "Left open").
- ~~**The gateway listens on every network it is on.**~~ Closed: GW-9.
- ~~**Headers with CR or LF from the API.**~~ Closed: GW-10.
- **Documented limits stay:** DNS answers in-scope names of any engagement with a running job;
  the gateway does not verify target certificates; a compromised worker can send within its
  engagement's whole scope, not only the agent lane's host; GET URLs to passive sources are a
  fixed exfiltration channel.
- ~~**A flaky test.**~~ Fixed: see "The flaky worker test" above.
- **IPv6.** The compose networks have no IPv6. If an operator enables it, `inhibit_ipv4` does not
  keep the host's IPv6 address off the internal networks; the gateway still refuses its own IPv6
  prefixes (GW-8), but the worker could reach the host's IPv6 address directly.
