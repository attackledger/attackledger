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
  pack: { id: string; name: string };
  roles: string[];
  lanes: LaneInfo[];
  closed_cells: number;
  total_cells: number;
  assets: CoverageRow[];
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
  lanes: string[];
  status: "evidenced" | "partial" | "none";
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

export interface EvidenceEntry {
  id: number;
  item_idx: number | null;
  kind: string;
  sha256: string;
  uri: string | null;
  summary: string;
  created_at: string;
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
  receipt: { sha256: string; closed_by: string | null; created_at: string } | null;
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
}

export type JobStatus = "queued" | "running" | "done" | "failed" | "cancelled" | "partial";

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
  turns?: number;
  requests?: number;
  evidence_added?: number;
  items_marked?: number;
  leads_added?: number;
  summary?: string;
  detail?: string;
  cost_usd_estimate?: number;
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

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  if (DEMO) return demoCall<T>(path, init);
  const res = await fetch(`/api${path}`, {
    headers: { "content-type": "application/json" },
    ...init,
  });
  const body = await res.json().catch(() => null);
  if (res.status === 401 && !path.startsWith("/auth/")) {
    window.dispatchEvent(new Event("attackledger:auth-required"));
  }
  if (!res.ok) {
    const detail = body?.detail;
    const msg =
      typeof detail === "string"
        ? detail
        : Array.isArray(detail)
          ? detail.map((d: { loc?: string[]; msg: string }) => `${d.loc?.slice(-1)[0] ?? "field"}: ${d.msg}`).join("\n")
          : detail?.unresolved?.join("\n")
            ?? (detail?.skipped ? `${detail.error}: ` + detail.skipped.map((x: { kind: string; reason: string }) => `${x.kind}: ${x.reason}`).join("; ") : undefined)
            ?? `Request failed (${res.status})`;
    throw new Error(msg);
  }
  return body as T;
}

export const api = {
  login: (token: string) => call<{ ok: boolean }>("/auth/login", { method: "POST", body: JSON.stringify({ token }) }),
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
  attach: (laneId: number, body: {
    item_idx: number; kind: "note" | "file" | "run"; text?: string; filename?: string; content_b64?: string;
    job_id?: number; summary?: string;
  }) => call<LaneDetail>(`/lanes/${laneId}/attach`, { method: "POST", body: JSON.stringify(body) }),
  updateItem: (laneId: number, idx: number, state: "open" | "done" | "na", na_reason?: string) =>
    call<LaneDetail>(`/lanes/${laneId}/items/${idx}`, { method: "PATCH", body: JSON.stringify({ state, na_reason }) }),
  closeLane: (laneId: number, closed_by: string, reviewed: boolean) =>
    call<LaneDetail>(`/lanes/${laneId}/close`, { method: "POST", body: JSON.stringify({ closed_by, reviewed }) }),
};
