import { DEMO, demoCall } from "./demo";

export type CellStatus = "not_opened" | "open" | "closed" | "stale";

export interface Cell {
  status: CellStatus;
  lane_id?: number;
  unresolved?: number;
  receipt?: string;
}

export interface CoverageRow {
  asset_id: number;
  host: string;
  in_scope: boolean;
  roles: Record<string, Cell>;
}

export interface LaneInfo {
  key: string;
  name: string;
  needs: string[];
}

export interface Coverage {
  engagement: string;
  separation_of_duties?: boolean;
  require_signatures?: boolean;
  retain_until?: string | null;              // YYYY-MM-DD (UTC): the content is kept through this day
  content_deleted?: ContentDeleted | null;
  pack: { id: string; name: string };
  roles: string[];
  lanes: LaneInfo[];
  closed_cells: number;
  total_cells: number;
  assets: CoverageRow[];
}

/** What deleting an engagement's data removes and keeps, or when it was deleted. */
export interface ContentStatus {
  engagement: string;
  retain_until: string | null;
  content_deleted: ContentDeleted | null;
  encryption: { master_key: "configured" | "development" | "missing" };
  evidence_entries: number;
  encrypted_summaries: number;
  v1_summaries: number;
  observations: number;
  endpoints: number;
  leads: number;
}

export interface EngagementSummary {
  id: number;
  name: string;
  policy_url: string | null;
  assets: number;
  pack_id: string;
  engagement_type: string;
}

export interface PackSummary {
  id: string;
  name: string;
  version: string;
  description: string;
  engagement_types: string[];
  lanes: { key: string; name: string; needs: string[]; items: number }[];
}

export interface ControlRow {
  id: string;
  text: string;
  framework: string;
  framework_name: string;
  required: number;
  evidenced: number;
  not_applicable?: number;   // resolved as not applicable, with a reason; never counted as evidence
  lanes: string[];
  status: "evidenced" | "resolved" | "not_applicable" | "partial" | "none";
}

export interface ControlsReport {
  engagement: string;
  pack: string;
  hosts_in_scope: number;
  disclaimer: string;
  controls: ControlRow[];
}

export interface LaneItem {
  idx: number;
  key: string;
  controls: string[];
  text: string;
  state: "open" | "done" | "na";
  na_reason: string | null;
}

/** When and by whom an engagement's content was deleted (D-043): its key, raw evidence and
 *  summaries. Hashes, receipts and the history remain. */
export interface ContentDeleted {
  at: string;
  by: string;
  reason: "owner" | "retention" | "operator";
}

export interface EvidenceEntry {
  id: number;
  item_idx: number | null;
  kind: string;
  sha256: string;
  uri: string | null;
  // Null when the engagement's content was deleted ("deleted") or the stored text does not
  // open ("unreadable"). Entries recorded before chain record v2 keep theirs.
  summary: string | null;
  content?: "available" | "deleted" | "unreadable";
  v?: number;
  source?: string | null;   // manual, recon, agent or import:<tool>; null before chain record v2
  // What was redacted from the stored bytes (D-038): counts and kinds, never values. Null for
  // entries with nothing stored by AttackLedger (a recon run, a hash given through the API).
  redaction?: Redaction | null;
  created_at: string;
}

export interface Redaction {
  redacted: number;
  kinds: string[];
  not_redacted: string[];
}

export interface LaneDetail {
  id: number;
  engagement_id: number;
  host: string;
  role: string;
  role_name: string;
  executor: string;
  status: CellStatus;
  unresolved: string[];
  items: LaneItem[];
  evidence: EvidenceEntry[];
  content_deleted?: ContentDeleted | null;
  receipt: { sha256: string; closed_by: string | null; closed_by_email?: string | null; created_at: string; signed?: boolean;
             algorithm?: string | null; key_fingerprint?: string | null;
             timestamp?: { time: string; tsa: string | null } | null; timestamp_error?: string | null } | null;
}

/** One administrative change from the server's audit log, with the server's own wording. */
export interface AuditEntry {
  seq: number;
  at: string;
  actor: { kind: "person" | "token" | "cli" | "open" | "backfill" | "retention"; user_id: number | null; name: string; email: string | null };
  actor_label: string;
  action: string;
  engagement_id: number | null;
  subject_id: number | null;
  change: Record<string, unknown>;
  text: string;
}

export interface AuditLog {
  chain: { intact: boolean; problems: string[]; head: { seq: number; entry_hash: string } };
  entries: AuditEntry[];
}

export interface Scope {
  include: string[];
  exclude: string[];
  rate_limit_rps: number;
  policy_url: string | null;
  research_header: string | null;
  research_user_agent: string | null;
  enabled_modules: string[];
  crawl_depth: number;
  authorized_by: string | null;
  authorized_at: string | null;
  separation_of_duties?: boolean;
  redact_evidence?: boolean;   // off only for a lab: raw evidence is then stored as captured
  hosts_added?: string[];   // returned by a save: exact scope entries that became hosts
}

export type JobStatus = "queued" | "running" | "done" | "failed" | "cancelled" | "partial" | "skipped";

export interface Job {
  id: number;
  kind: string;
  status: JobStatus;
  targets: string[];
  result_count: number;
  output_sha256: string | null;
  targets_done: number;
  remaining: number;
  deferred: boolean;
  lane_id: number | null;
  result: AgentResult | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  log?: string;
}

export interface AgentResult {
  limits?: { max_turns?: number; max_requests?: number; max_cost_usd?: number };
  status?: "finished" | "ended" | "turn_limit" | "cost_limit" | "cancelled" | "refused" | "timed_out";
  model?: string;
  turns?: number | null;
  tool_calls?: number;   // runs driven outside the Messages API count tool calls, not turns
  requests?: number;
  evidence_added?: number;
  items_marked?: number;
  leads_added?: number;
  summary?: string;
  detail?: string;
  cost_usd_estimate?: number;
  reason?: string;           // a step that could not run ("skipped"): why
  skipped_reason?: string;
}

export interface Me {
  kind: "open" | "token" | "person";
  user_id: number | null;
  name: string;
  is_owner: boolean;
  mode: "open" | "token" | "people";
  roles: Record<string, string[]>;
  password_chosen?: boolean;     // people only: false while the password is one someone else set
  key_notice?: KeyNotice;        // people only
}

/** Keys registered or revoked for you since your previous sign-in (D-036). */
export interface KeyNotice {
  since: string | null;
  events: { event: "registered" | "revoked"; key_fingerprint: string; algorithm: string; at: string;
            via: string; key_id: number | null; key_revoked: boolean }[];
}

export interface SigningKeyView {
  id: number;
  algorithm: string;
  fingerprint: string;
  created_at: string;
  revoked: boolean;
}

export interface Person {
  id: number;
  email: string;
  name: string;
  is_owner: boolean;
  disabled: boolean;
  password_chosen?: boolean;
}

export interface Member {
  user_id: number;
  name: string;
  email: string;
  roles: string[];
}

export interface ExecutorInfo {
  key: string;
  title: string;
  summary: string;
  available: boolean;
  unavailable_reason: string;
}

export interface ObservationRow {
  host: string;
  url?: string;
  status_code?: number;
  title?: string;
  tech?: string[];
  webserver?: string;
  a?: string[];
  cname?: string[];
  live?: boolean;
  source?: string;
}

export interface ScopeImport {
  include: string[];
  exclude: string[];
  not_imported: { identifier: string; type: string }[];
  invalid: { identifier: string; reason: string }[];
  result: { include: string[]; exclude: string[] };
  applied: boolean;
  hosts_added?: string[];
}

export interface ReconModule {
  kind: string;
  title: string;
  summary: string;
  input: "roots" | "hosts" | "urls";
  traffic: "passive" | "dns" | "target";
  http: boolean;
  opt_in: boolean;
  after: string[];
  produces: string[];
  pipeline: string;
  caution: string;
  needs_identification: boolean;
  tools: string[];
  phase: string;
  min_rps: number;
}

export interface ReconPhase {
  key: string;
  title: string;
  summary: string;
  help: string;
  kinds: string[];
}

export interface ReconSummary {
  hosts: number;
  resolved: number;
  live: number;
  golden: number;
  urls: number;
  js: number;
  leads: number;
  lead_kinds: Record<string, number>;
}

export interface LaneContext {
  host: string;
  lane: { executor: string };
  recon: { observations: unknown[]; endpoints: unknown[]; leads: unknown[] };
}

export interface TriageHost {
  host: string;
  score: number;
  signals: string[];
  golden: boolean;
  statuses: string[];
  ports: string[];
  titles: string[];
  tech: string[];
  urls: string[];
  endpoints: number;
  js: number;
  leads: number;
}

export interface Lead {
  id: number;
  host: string;
  source_url: string;
  kind: string;
  title: string;
  bucket: string;
  severity: string;
  detail: { preview?: string; value_sha256?: string; map_url?: string; sources?: string[]; sources_content?: boolean;
            inline?: boolean; template?: string; matched_at?: string; pass?: string };
}

export interface TriageReport {
  golden_min_score: number;
  weights: Record<string, number>;
  hosts: TriageHost[];
}

export interface EndpointRow {
  host: string;
  url: string;
  source: string;
  js: boolean;
}

/** A refused request: the message is readable; status and detail are kept for callers that need them. */
export class ApiError extends Error {
  status: number;
  detail: unknown;
  constructor(message: string, status: number, detail: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

// Request fields as the forms name them, for validation messages.
const FIELD_LABEL: Record<string, string> = {
  policy_url: "Program policy URL", operator: "Your name or handle", host: "Host", include: "In scope",
  exclude: "Out of scope", rate_limit_rps: "Requests per second", research_header: "Research header",
  research_user_agent: "Research user agent", crawl_depth: "Crawl depth", name: "Name", na_reason: "Reason",
  email: "Email", password: "Password", closed_by: "Your name", targets: "Targets", kind: "Step",
};

function fieldLabel(loc: unknown[] | undefined): string {
  const key = [...(loc ?? [])].reverse().find((x) => typeof x === "string" && x !== "body");
  if (typeof key !== "string") return "";
  return FIELD_LABEL[key] ?? key.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
}

/** The server's `detail` as a sentence a person can act on. */
export function readableDetail(detail: unknown, status: number): string {
  if (typeof detail === "string" && detail.trim()) return detail;
  if (Array.isArray(detail)) {
    // Request validation: one line per field, named as the form names it.
    return detail.map((d: { loc?: unknown[]; msg?: string; type?: string; ctx?: { pattern?: string } }) => {
      const msg = d?.type === "missing" ? "is required"
        : d?.type === "string_pattern_mismatch" && d.ctx?.pattern === "^https://" ? "must start with https://"
        : d?.type === "string_pattern_mismatch" ? "is not in the expected format"
        : String(d?.msg ?? "is not valid").replace(/^Value error, /, "");
      const field = fieldLabel(d?.loc);
      return field ? `${field}: ${msg}` : msg;
    }).join("\n");
  }
  if (detail && typeof detail === "object") {
    const d = detail as { unresolved?: string[]; skipped?: { kind: string; reason: string }[];
                          error?: string; message?: string; reason?: string };
    if (d.unresolved?.length) return `This lane cannot close yet:\n${d.unresolved.join("\n")}`;
    if (d.skipped?.length) return `${d.error ?? "Not run"}: ${d.skipped.map((x) => `${x.kind}: ${x.reason}`).join("; ")}`;
    const text = d.message ?? d.error ?? d.reason;
    if (typeof text === "string" && text.trim()) return text;
  }
  if (status === 401) return "Sign in again to continue.";
  if (status === 403) return "Your role on this engagement does not allow this.";
  if (status === 404) return "Not found. It may have been removed; reload the page.";
  if (status >= 500) return `The ledger API failed (${status}). Its log says why.`;
  return `Request failed (${status})`;
}

// ---- evidence import (D-029) ------------------------------------------------------------

export interface ImportFormat { id: string; title: string; summary: string; extensions: string[] }

export interface ImportFormats {
  formats: ImportFormat[];
  limits: { file_bytes: number; entries: number; part_bytes: number };
  suggestion_rules: { id: string; title: string; words: string[] }[];
}

/** A row of an uploaded file that did not become an inbox entry, by row number and host only. */
export interface RefusedRow {
  row: number;
  host: string | null;
  reason: "out_of_scope" | "duplicate" | "unreadable";
  detail: string | null;
}

export interface ImportBatch {
  id: number;
  format: string;
  format_title: string;
  creator: string | null;
  filename: string | null;
  file_sha256: string;
  file_bytes: number;
  rows: number;
  accepted: number;
  out_of_scope: number;
  duplicates: number;
  unreadable: number;
  refused: RefusedRow[];
  created_by_name: string;
  created_at: string;
}

export interface InboxMapping {
  evidence_id: number; lane_id: number; item_idx: number; item_key: string; by_name: string; at: string;
}

export interface InboxEntry {
  id: number;
  batch_id: number;
  row: number;
  format: string;
  tool_id: string | null;
  tool_time: string | null;
  host: string;
  method: string;
  url: string;
  status: number | null;
  label: string | null;
  request_sha256: string | null;
  response_sha256: string | null;
  record_sha256: string;
  request_bytes: number;
  response_bytes: number;
  notes: string[];
  content_type: string | null;
  redaction: Redaction | null;
  state: "new" | "mapped" | "dismissed";
  mappings: InboxMapping[];
  dismissed: { by_name: string | null; at: string; reason: string | null } | null;
  created_at: string;
}

export interface InboxSuggestion {
  lane_id: number; role: string; item_idx: number; key: string; text: string; score: number; why: string[];
}

export interface InboxEntryDetail extends InboxEntry {
  targets: { lane_id: number; role: string; items: { idx: number; key: string; text: string; state: string }[] }[];
  suggestions: InboxSuggestion[];
}

export interface InboxPage {
  total: number;
  offset: number;
  limit: number;
  counts: Record<"new" | "mapped" | "dismissed", number>;
  hosts: string[];
  entries: InboxEntry[];
}

export interface InboxFilter {
  state?: string; host?: string; method?: string; status?: string; batch?: number; q?: string; offset?: number;
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  if (DEMO) return demoCall<T>(path, init);
  let res: Response;
  try {
    res = await fetch(`/api${path}`, {
      headers: { "content-type": "application/json" },
      ...init,
    });
  } catch {
    throw new ApiError("Can't reach the ledger API. Check that it is running, then try again.", 0, null);
  }
  const body = await res.json().catch(() => null);
  if (res.status === 401 && !path.startsWith("/auth/")) {
    window.dispatchEvent(new Event("attackledger:auth-required"));
  }
  if (!res.ok) {
    const detail = body?.detail;
    throw new ApiError(readableDetail(detail, res.status), res.status, detail);
  }
  return body as T;
}

export const api = {
  login: (token: string) => call<{ ok: boolean }>("/auth/login", { method: "POST", body: JSON.stringify({ token }) }),
  loginPerson: (email: string, password: string) =>
    call<{ ok: boolean; name: string; key_notice: KeyNotice }>("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  changePassword: (current_password: string, new_password: string) =>
    call<{ ok: boolean }>("/auth/password", { method: "POST", body: JSON.stringify({ current_password, new_password }) }),
  health: () => call<{ ok: boolean; auth_required: boolean; mode: "open" | "token" | "people"; timestamps?: boolean }>("/health"),
  me: () => call<Me>("/auth/me"),
  people: () => call<Person[]>("/people"),
  createPerson: (body: { email: string; name: string; password: string; is_owner: boolean }) =>
    call<Person>("/people", { method: "POST", body: JSON.stringify(body) }),
  updatePerson: (id: number, body: Partial<{ name: string; is_owner: boolean; disabled: boolean }>) =>
    call<Person>(`/people/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  members: (engId: number) => call<Member[]>(`/engagements/${engId}/members`),
  setMembers: (engId: number, members: { user_id: number; roles: string[] }[]) =>
    call<Member[]>(`/engagements/${engId}/members`, { method: "PUT", body: JSON.stringify({ members }) }),
  keys: () => call<SigningKeyView[]>("/auth/keys"),
  revokeKey: (id: number) => call<SigningKeyView>(`/auth/keys/${id}/revoke`, { method: "POST" }),
  addKey: (algorithm: string, public_key: string) =>
    call<{ id: number; fingerprint: string }>("/auth/keys", { method: "POST", body: JSON.stringify({ algorithm, public_key }) }),
  receiptPayload: (laneId: number, key: string) =>
    call<{ payload: string }>(`/lanes/${laneId}/receipt-payload?key=${encodeURIComponent(key)}`),
  closeLaneSigned: (laneId: number, payload: string, signature: string, key_fingerprint: string) =>
    call<LaneDetail>(`/lanes/${laneId}/close`, {
      method: "POST", body: JSON.stringify({ reviewed: true, payload, signature, key_fingerprint }),
    }),
  timestampReceipt: (laneId: number) =>
    call<LaneDetail>(`/lanes/${laneId}/receipt/timestamp`, { method: "POST", body: "{}" }),
  updateEngagement: (engId: number, body: { separation_of_duties?: boolean; require_signatures?: boolean;
                                            redact_evidence?: boolean; retain_until?: string | null }) =>
    call<{ id: number; separation_of_duties: boolean; require_signatures: boolean; redact_evidence: boolean;
           retain_until: string | null }>(`/engagements/${engId}`, { method: "PATCH", body: JSON.stringify(body) }),
  contentStatus: (engId: number) => call<ContentStatus>(`/engagements/${engId}/content`),
  deleteContent: (engId: number, confirm_name: string) =>
    call<ContentStatus>(`/engagements/${engId}/content/delete`, { method: "POST", body: JSON.stringify({ confirm_name }) }),
  logout: () => call<{ ok: boolean }>("/auth/logout", { method: "POST", body: "{}" }),
  engagements: () => call<EngagementSummary[]>("/engagements"),
  createEngagement: (name: string, pack_id: string) =>
    call<{ id: number }>("/engagements", {
      method: "POST",
      body: JSON.stringify({ name, pack_id }),
    }),
  packs: () => call<PackSummary[]>("/packs"),
  controls: (engId: number) => call<ControlsReport>(`/engagements/${engId}/controls`),
  addAsset: (engId: number, host: string, in_scope: boolean) =>
    call<{ id: number }>(`/engagements/${engId}/assets`, {
      method: "POST",
      body: JSON.stringify({ host, in_scope }),
    }),
  coverage: (engId: number) => call<Coverage>(`/engagements/${engId}/coverage`),
  openLane: (asset_id: number, role: string) =>
    call<LaneDetail>("/lanes", { method: "POST", body: JSON.stringify({ asset_id, role }) }),
  lane: (laneId: number) => call<LaneDetail>(`/lanes/${laneId}`),
  scope: (engId: number) => call<Scope>(`/engagements/${engId}/scope`),
  saveScope: (engId: number, body: Partial<Scope>) =>
    call<Scope>(`/engagements/${engId}/scope`, { method: "PUT", body: JSON.stringify(body) }),
  attest: (engId: number, operator: string, policy_url: string) =>
    call<Scope>(`/engagements/${engId}/attest`, {
      method: "POST",
      body: JSON.stringify({ operator, policy_url, confirm: true }),
    }),
  jobs: (engId: number) => call<Job[]>(`/engagements/${engId}/jobs`),
  job: (jobId: number) => call<Job>(`/jobs/${jobId}`),
  importScope: (engId: number, csv: string, apply: boolean) =>
    call<ScopeImport>(`/engagements/${engId}/scope/import`, { method: "POST", body: JSON.stringify({ csv, apply }) }),
  runPipeline: (engId: number, kinds?: string[]) =>
    call<{ queued: string[]; skipped: { kind: string; reason: string }[] }>(`/engagements/${engId}/pipeline`, {
      method: "POST", body: JSON.stringify(kinds ? { kinds } : {}),
    }),
  phases: () => call<ReconPhase[]>("/recon/phases"),
  reconSummary: (engId: number) => call<ReconSummary>(`/engagements/${engId}/recon/summary`),
  runJob: (engId: number, kind: string, targets: string[] = []) =>
    call<Job>(`/engagements/${engId}/jobs`, { method: "POST", body: JSON.stringify({ kind, targets }) }),
  resumeJob: (jobId: number) => call<Job>(`/jobs/${jobId}/resume`, { method: "POST" }),
  cancelJob: (jobId: number) => call<Job>(`/jobs/${jobId}/cancel`, { method: "POST" }),
  observations: (engId: number) => call<ObservationRow[]>(`/engagements/${engId}/observations`),
  modules: () => call<ReconModule[]>("/modules"),
  laneContext: (laneId: number) => call<LaneContext>(`/lanes/${laneId}/context`),
  leads: (engId: number, module?: string) =>
    call<Lead[]>(`/engagements/${engId}/leads${module ? `?module=${encodeURIComponent(module)}` : ""}`),
  triage: (engId: number) => call<TriageReport>(`/engagements/${engId}/triage`),
  endpoints: (engId: number, opts: { js?: boolean; q?: string; offset?: number; module?: string } = {}) => {
    const p = new URLSearchParams();
    if (opts.module) p.set("module", opts.module);
    if (opts.js !== undefined) p.set("js", String(opts.js));
    if (opts.q) p.set("q", opts.q);
    p.set("limit", "100");
    p.set("offset", String(opts.offset ?? 0));
    return call<{ total: number; items: EndpointRow[] }>(`/engagements/${engId}/endpoints?${p}`);
  },
  executors: () => call<ExecutorInfo[]>("/executors"),
  setExecutor: (laneId: number, executor: string) =>
    call<LaneDetail>(`/lanes/${laneId}`, { method: "PATCH", body: JSON.stringify({ executor }) }),
  agentRuns: (laneId: number) => call<Job[]>(`/lanes/${laneId}/agent-runs`),
  startAgentRun: (laneId: number, max_turns: number, max_requests: number, max_cost_usd: number) =>
    call<Job>(`/lanes/${laneId}/agent-runs`, {
      method: "POST", body: JSON.stringify({ max_turns, max_requests, max_cost_usd }),
    }),
  report: <T,>(engId: number) => call<T>(`/engagements/${engId}/report`),
  audit: (engId: number) => call<AuditLog>(`/engagements/${engId}/audit`),
  importFormats: () => call<ImportFormats>("/imports/formats"),
  imports: (engId: number) => call<ImportBatch[]>(`/engagements/${engId}/imports`),
  /** The file goes as the request body, as it is: no base64, no JSON around it. */
  importFile: (engId: number, file: File, format: string | null) => {
    const p = new URLSearchParams({ filename: file.name });
    if (format) p.set("format", format);
    return call<ImportBatch>(`/engagements/${engId}/imports?${p}`, {
      method: "POST", body: file, headers: { "content-type": "application/octet-stream" },
    });
  },
  inbox: (engId: number, f: InboxFilter = {}) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(f)) if (v !== undefined && v !== "") p.set(k, String(v));
    p.set("limit", "50");
    return call<InboxPage>(`/engagements/${engId}/inbox?${p}`);
  },
  inboxEntry: (engId: number, id: number) => call<InboxEntryDetail>(`/engagements/${engId}/inbox/${id}`),
  mapEntries: (engId: number, entry_ids: number[], targets: { lane_id: number; item_idx: number }[], note: string) =>
    call<{ evidence_added: number[]; entries: InboxEntry[] }>(`/engagements/${engId}/inbox/map`, {
      method: "POST", body: JSON.stringify({ entry_ids, targets, note: note || null }),
    }),
  dismissEntries: (engId: number, entry_ids: number[], reason: string) =>
    call<{ entries: InboxEntry[] }>(`/engagements/${engId}/inbox/dismiss`, {
      method: "POST", body: JSON.stringify({ entry_ids, reason: reason || null }),
    }),
  restoreEntries: (engId: number, entry_ids: number[]) =>
    call<{ entries: InboxEntry[] }>(`/engagements/${engId}/inbox/restore`, {
      method: "POST", body: JSON.stringify({ entry_ids }),
    }),
  attach: (laneId: number, body: {
    item_idx: number; kind: "note" | "file" | "run"; text?: string; filename?: string; content_b64?: string;
    job_id?: number; summary?: string;
  }) => call<LaneDetail>(`/lanes/${laneId}/attach`, { method: "POST", body: JSON.stringify(body) }),
  updateItem: (laneId: number, idx: number, state: "open" | "done" | "na", na_reason?: string) =>
    call<LaneDetail>(`/lanes/${laneId}/items/${idx}`, { method: "PATCH", body: JSON.stringify({ state, na_reason }) }),
  closeLane: (laneId: number, closed_by: string | null, reviewed: boolean) =>
    call<LaneDetail>(`/lanes/${laneId}/close`, { method: "POST", body: JSON.stringify({ closed_by, reviewed }) }),
};
