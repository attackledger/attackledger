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
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  log?: string;
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
  const res = await fetch(`/api${path}`, {
    headers: { "content-type": "application/json" },
    ...init,
  });
  const body = await res.json().catch(() => null);
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
  runPipeline: (engId: number) =>
    call<{ queued: string[]; skipped: { kind: string; reason: string }[] }>(`/engagements/${engId}/pipeline`, { method: "POST", body: "{}" }),
  runJob: (engId: number, kind: string, targets: string[] = []) =>
    call<Job>(`/engagements/${engId}/jobs`, { method: "POST", body: JSON.stringify({ kind, targets }) }),
  resumeJob: (jobId: number) => call<Job>(`/jobs/${jobId}/resume`, { method: "POST" }),
  cancelJob: (jobId: number) => call<Job>(`/jobs/${jobId}/cancel`, { method: "POST" }),
  observations: (engId: number) => call<ObservationRow[]>(`/engagements/${engId}/observations`),
  modules: () => call<ReconModule[]>("/modules"),
  laneContext: (laneId: number) => call<LaneContext>(`/lanes/${laneId}/context`),
  leads: (engId: number) => call<Lead[]>(`/engagements/${engId}/leads`),
  triage: (engId: number) => call<TriageReport>(`/engagements/${engId}/triage`),
  endpoints: (engId: number, opts: { js?: boolean; q?: string; offset?: number } = {}) => {
    const p = new URLSearchParams();
    if (opts.js !== undefined) p.set("js", String(opts.js));
    if (opts.q) p.set("q", opts.q);
    p.set("limit", "100");
    p.set("offset", String(opts.offset ?? 0));
    return call<{ total: number; items: EndpointRow[] }>(`/engagements/${engId}/endpoints?${p}`);
  },
  closeLane: (laneId: number, closed_by: string, reviewed: boolean) =>
    call<LaneDetail>(`/lanes/${laneId}/close`, { method: "POST", body: JSON.stringify({ closed_by, reviewed }) }),
};
