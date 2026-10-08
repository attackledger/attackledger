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

export interface Coverage {
  engagement: string;
  roles: string[];
  closed_cells: number;
  total_cells: number;
  assets: CoverageRow[];
}

export interface EngagementSummary {
  id: number;
  name: string;
  policy_url: string | null;
  assets: number;
}

export interface LaneItem {
  idx: number;
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
  status: CellStatus;
  unresolved: string[];
  items: LaneItem[];
  evidence: EvidenceEntry[];
  receipt: { sha256: string; created_at: string } | null;
}

export interface Scope {
  include: string[];
  exclude: string[];
  rate_limit_rps: number;
  policy_url: string | null;
  research_header: string | null;
  research_user_agent: string | null;
  authorized_by: string | null;
  authorized_at: string | null;
}

export type JobStatus = "queued" | "running" | "done" | "failed" | "cancelled";

export interface Job {
  id: number;
  kind: string;
  status: JobStatus;
  targets: string[];
  result_count: number;
  output_sha256: string | null;
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
          : detail?.unresolved?.join("\n") ?? `Request failed (${res.status})`;
    throw new Error(msg);
  }
  return body as T;
}

export const api = {
  engagements: () => call<EngagementSummary[]>("/engagements"),
  createEngagement: (name: string, policy_url?: string) =>
    call<{ id: number }>("/engagements", {
      method: "POST",
      body: JSON.stringify({ name, policy_url: policy_url || null }),
    }),
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
  runJob: (engId: number, kind: string, targets: string[] = []) =>
    call<Job>(`/engagements/${engId}/jobs`, { method: "POST", body: JSON.stringify({ kind, targets }) }),
  cancelJob: (jobId: number) => call<Job>(`/jobs/${jobId}/cancel`, { method: "POST" }),
  observations: (engId: number) => call<ObservationRow[]>(`/engagements/${engId}/observations`),
  closeLane: (laneId: number) => call<LaneDetail>(`/lanes/${laneId}/close`, { method: "POST" }),
};
