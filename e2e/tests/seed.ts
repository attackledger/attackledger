// Global setup of the token phase: fills the empty test stack with hostile content, through the
// API as a tester, an owner and a worker would send it. Fictional *.xss.test and *.clean.test
// hosts only; no request leaves the test network (the worker's results are posted, never fetched).
//
//   "E2E <img ...>"      hostile names, notes, N/A reasons, a receipt signed by a hostile name, an
//                        import with hostile URLs, headers, bodies and file name, a test account
//                        with a hostile label, recon results (hosts, titles, URLs, leads, findings)
//                        and a write proposal from an outside agent driver, each a hostile string
//   "E2E clean report"   one receipted lane, for the verifier tests
//   "Müşteri portalı …"  a name in three scripts, for the report downloads
import { createHash } from "node:crypto";
import { api, ApiError, hostile, hostileShort, NAMES, P, waitForApi, WORKER_TOKEN, API } from "./lib";

const sha = (s: string) => createHash("sha256").update(s).digest("hex");

interface Lane { id: number; items: { idx: number; state: string }[] }

export async function seedHostile(): Promise<void> {
  const eng = await api.call<{ id: number }>("POST", "/engagements", { name: NAMES.hostileEng });
  const id = eng.id;
  await api.call("PUT", `/engagements/${id}/scope`, {
    include: [NAMES.scope], exclude: [], rate_limit_rps: 5, research_header: "X-E2E: e2e-test",
    research_user_agent: `e2e ${hostileShort("ua")}`, enabled_modules: ["ports", "content", "params", "nuclei"],
  });
  // A javascript: policy URL should be refused; a hostile query string is a URL like any other.
  await expectRefused(() => api.call("POST", `/engagements/${id}/attest`,
    { operator: "e2e", policy_url: P.js("policy"), confirm: true }), "a javascript: policy URL");
  await api.call("POST", `/engagements/${id}/attest`, {
    operator: hostileShort("operator"), policy_url: `https://example.com/policy?q=${encodeURIComponent(P.img("policy-q"))}`,
    confirm: true,
  });
  const app = await api.call<{ id: number }>("POST", `/engagements/${id}/assets`, { host: NAMES.app });
  await api.call("POST", `/engagements/${id}/assets`, { host: NAMES.api });
  await expectRefused(() => api.call("POST", `/engagements/${id}/assets`, { host: P.img("host") }), "a hostile host name");

  // A receipted lane: every item has a hostile note or N/A reason, signed by a hostile name.
  const recon = await api.call<Lane>("POST", "/lanes", { asset_id: app.id, role: "recon" });
  for (const item of recon.items) {
    if (item.idx % 3 === 0) {
      await api.call("PATCH", `/lanes/${recon.id}/items/${item.idx}`, { state: "na", na_reason: hostile(`na-${item.idx}`) });
      continue;
    }
    const text = hostile(`summary-${item.idx}`);
    await api.call("POST", `/lanes/${recon.id}/evidence`, { item_idx: item.idx, kind: "note", sha256: sha(text), summary: text });
    await api.call("PATCH", `/lanes/${recon.id}/items/${item.idx}`, { state: "done" });
  }
  await api.call("POST", `/lanes/${recon.id}/close`, { closed_by: `${hostileShort("closed-by")} ${P.rtl}`, reviewed: true });

  // An open lane with notes kept in the blob store (View raw) and a long one.
  const mapper = await api.call<Lane>("POST", "/lanes", { asset_id: app.id, role: "mapper" });
  await api.call("POST", `/lanes/${mapper.id}/attach`, { item_idx: 1, kind: "note", text: hostile("attached-note") });
  await api.call("POST", `/lanes/${mapper.id}/attach`, { item_idx: 2, kind: "note", text: P.long("note") });
  await api.call("POST", `/lanes/${mapper.id}/attach`, {
    item_idx: 3, kind: "file", filename: `${hostileShort("file-name")}.html`,
    content_b64: Buffer.from(`<!doctype html><script>${"__xss('file-body')"}</script>${P.img("file-body")}`).toString("base64"),
    summary: hostile("file-summary").slice(0, 2000),
  });
  await api.call("PATCH", `/lanes/${mapper.id}/items/4`, { state: "na", na_reason: P.long("na") });

  await seedImport(id);
  await seedTestAccount(id);
  if (WORKER_TOKEN) {
    await seedRecon(id);
    await seedProposal(id, mapper);
  }
}

async function seedImport(engId: number): Promise<void> {
  const entry = (url: string, extra: Record<string, unknown> = {}) => ({
    startedDateTime: "2026-10-01T10:00:00.000Z", time: 1,
    request: { method: "GET", url, httpVersion: "HTTP/1.1", headers: [{ name: "X-E2E", value: hostileShort("har-req-header") }],
               queryString: [], cookies: [], headersSize: -1, bodySize: 0 },
    response: { status: 200, statusText: hostileShort("har-status"), httpVersion: "HTTP/1.1",
                headers: [{ name: "Content-Type", value: "text/html" }], cookies: [],
                content: { size: 0, mimeType: "text/html", text: `<!doctype html><script>__xss('har-body')</script>${hostile("har-body")}` },
                redirectURL: "", headersSize: -1, bodySize: 0 },
    cache: {}, timings: { send: 0, wait: 1, receive: 0 }, ...extra,
  });
  const har = {
    log: {
      version: "1.2", creator: { name: hostileShort("har-creator"), version: "1" },
      entries: [
        entry(`https://${NAMES.app}/search?q=<script>__xss('har-url')</script>&r=${P.img("har-query")}`, { comment: hostile("har-comment") }),
        entry(`https://${NAMES.app}/${P.svg("har-path")}`),
        entry(`https://${NAMES.app}/long/${"a".repeat(4000)}`),
        entry(P.js("har-js-url")),                                   // not an http URL: unreadable
        entry(`https://evil.example/${P.img("har-out-of-scope")}`),  // out of scope
      ],
    },
  };
  const name = `${hostileShort("import-file")}.har`;
  await api.call("POST", `/engagements/${engId}/imports?filename=${encodeURIComponent(name)}`,
                 new TextEncoder().encode(JSON.stringify(har)));
}

async function seedTestAccount(engId: number): Promise<void> {
  await api.call("POST", `/engagements/${engId}/test-accounts`, {
    label: "e2e-1", role: hostileShort("account-role").slice(0, 100), hosts: [NAMES.app], kind: "headers",
    value: "X-E2E-Fake: not-a-real-credential-0000",
  });
}

// ---- a worker's results ------------------------------------------------------------------------

const worker = () => ({ authorization: `Bearer ${WORKER_TOKEN}` });

async function claim(jobId?: number): Promise<{ id: number; token: string }> {
  const r = await fetch(`${API}/worker/claim`, {
    method: "POST", headers: { ...worker(), "content-type": "application/json" },
    body: JSON.stringify(jobId ? { job_id: jobId } : {}),
  });
  const body = await r.json() as { job: { id: number; token: string } | null; log?: string };
  if (!r.ok || !body.job) throw new Error(`the worker could not claim a job: ${r.status} ${JSON.stringify(body).slice(0, 400)}`);
  return body.job;
}

async function asJob<T = unknown>(job: { id: number; token: string }, path: string, body: unknown): Promise<T> {
  const r = await fetch(`${API}/worker/jobs/${job.id}/${path}`, {
    method: "POST", headers: { authorization: `Bearer ${job.token}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`worker ${path} for job ${job.id} -> ${r.status}: ${text.slice(0, 400)}`);
  return JSON.parse(text) as T;
}

async function runJob(engId: number, kind: string, targets: string[], results: Record<string, unknown>): Promise<{ refused: number }> {
  const queued = await api.call<{ id: number; targets: string[] }>("POST", `/engagements/${engId}/jobs`, { kind, targets });
  const job = await claim();
  if (job.id !== queued.id) throw new Error(`claimed job ${job.id}, expected ${queued.id}`);
  const out = await asJob<{ refused: number }>(job, "results", results);
  await asJob(job, "progress", { done: queued.targets });
  await asJob(job, "finish", { output_sha256: sha(`${kind} ${job.id}`), result_count: 1 });
  return out;
}

async function seedRecon(engId: number): Promise<void> {
  const app = `https://${NAMES.app}`;
  // The API refuses a probe URL that is not an http(s) URL of the probed host (the web app links to
  // it); hostile.spec.ts checks that the app shows such a URL as text when a server sends one.
  const probe = await runJob(engId, "probe", [NAMES.app, NAMES.api], {
    observations: [
      { host: NAMES.app, data: { url: P.js("probe-url"), title: "refused", status_code: 200, live: true } },
      { host: NAMES.app, data: { url: `https://${NAMES.api}/`, title: "refused: another host's URL", live: true } },
      { host: NAMES.app, data: { url: `https://${NAMES.app}/`, title: hostile("probe-title"), status_code: 200, live: true,
                                 tech: [hostileShort("tech"), "nginx"], webserver: hostileShort("webserver"),
                                 location: P.js("probe-location") } },
      { host: NAMES.api, data: { url: `https://${NAMES.api}/`, title: P.svg("probe-title-2"), status_code: 302, live: true,
                                 location: P.js("probe-location-2") } },
    ],
  });
  if (probe.refused !== 2) throw new Error(`the API stored a probe URL of another scheme or host (refused ${probe.refused} of 2)`);
  await runJob(engId, "crawl", [`${app}/`], {
    endpoints: [
      { url: `${app}/${P.img("endpoint")}?q=<script>__xss('endpoint-q')</script>`, sources: [hostileShort("source")] },
      { url: `javascript://${NAMES.app}/%0a__xss('endpoint-js')`, sources: ["katana"] },
      { url: `${app}/static/app.js`, sources: ["katana"] },
    ],
  });
  await runJob(engId, "jsanalyze", [`${app}/static/app.js`], {
    leads: [
      { host: NAMES.app, source_url: `${app}/static/${P.svg("lead-src")}.js`, kind: "secret", title: hostile("secret-title"),
        bucket: "real", severity: "high", key: "k1",
        detail: { preview: hostileShort("preview"), value_sha256: sha("x"), sources: [hostile("lead-sources")] } },
      { host: NAMES.app, source_url: `${app}/static/app.js`, kind: "sourcemap", title: hostile("sourcemap-title"), key: "k2",
        detail: { map_url: P.js("map-url") } },
      { host: NAMES.app, source_url: `javascript://${NAMES.app}/%0a__xss('lead-js')`, kind: "graphql", title: "dropped", key: "k3" },
    ],
  });
  await runJob(engId, "nuclei", [`${app}/`], {
    leads: [
      { host: NAMES.app, source_url: `${app}/${P.img("finding-url")}`, kind: "nuclei", title: hostile("finding-title"),
        severity: "<b>high</b>", key: "f1",
        detail: { template: hostileShort("template"), matched_at: P.js("matched-at"), pass: hostileShort("pass") } },
    ],
  });
}

async function seedProposal(engId: number, lane: Lane): Promise<void> {
  await api.call("PATCH", `/engagements/${engId}`, { allow_writes: true });
  const run = await api.call<{ id: number }>("POST", `/lanes/${lane.id}/agent-runs`, { driver: hostileShort("driver") });
  const job = await claim(run.id);
  const call = (name: string, args: Record<string, unknown>) =>
    asJob<{ is_error: boolean; text: string }>(job, "agent/call", { name, args }).then((r) => {
      if (r.is_error) throw new Error(`${name}: ${r.text}`);
      return r;
    });
  await call("propose_write", {
    method: "POST", url: `https://${NAMES.app}/api/${encodeURIComponent(P.img("approval-url"))}?x=${P.svg("approval-q")}`,
    headers: [{ name: "X-Note", value: hostileShort("approval-header") }], body: hostile("approval-body"),
    as_account: "", item_idx: lane.items[lane.items.length - 1].idx, reason: hostile("approval-reason"),
  });
  // The run stays running (an outside driver's run may wait for minutes), so its proposal stays pending.
}

export async function seedClean(): Promise<void> {
  const eng = await api.call<{ id: number }>("POST", "/engagements", { name: NAMES.cleanEng });
  await api.call("PUT", `/engagements/${eng.id}/scope`, { include: ["*.clean.test"], research_header: "X-E2E: e2e-test" });
  await api.call("POST", `/engagements/${eng.id}/attest`, { operator: "E2E operator", policy_url: "https://example.com/policy", confirm: true });
  const asset = await api.call<{ id: number }>("POST", `/engagements/${eng.id}/assets`, { host: "www.clean.test" });
  const lane = await api.call<Lane>("POST", "/lanes", { asset_id: asset.id, role: "recon" });
  for (const item of lane.items) {
    const text = `checked item ${item.idx}`;
    await api.call("POST", `/lanes/${lane.id}/evidence`, { item_idx: item.idx, kind: "note", sha256: sha(text), summary: text });
    await api.call("PATCH", `/lanes/${lane.id}/items/${item.idx}`, { state: "done" });
  }
  await api.call("POST", `/lanes/${lane.id}/close`, { closed_by: "E2E Reviewer", reviewed: true });
  // An open lane for the draft tests.
  await api.call("POST", "/lanes", { asset_id: asset.id, role: "mapper" });

  const u = await api.call<{ id: number }>("POST", "/engagements", { name: NAMES.unicodeEng });
  await api.call("POST", `/engagements/${u.id}/assets`, { host: "portal.clean.test" });
}

async function expectRefused(fn: () => Promise<unknown>, what: string): Promise<void> {
  try {
    await fn();
  } catch (e) {
    if (e instanceof ApiError && e.status >= 400 && e.status < 500) return;
    throw e;
  }
  throw new Error(`the API accepted ${what}`);
}

export default async function globalSetup(): Promise<void> {
  await waitForApi();
  const existing = await api.call<{ name: string }[]>("GET", "/engagements");
  if (existing.some((e) => e.name === NAMES.hostileEng)) return;      // a stack kept with --keep: seeded already
  if (existing.length) throw new Error("the test stack already has engagements; start it from empty volumes");
  await seedHostile();
  await seedClean();
}
