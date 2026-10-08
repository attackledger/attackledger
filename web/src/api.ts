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
  closeLane: (laneId: number) => call<LaneDetail>(`/lanes/${laneId}/close`, { method: "POST" }),
};
