// Read-only demo: built with VITE_DEMO=1, the app answers every read from a snapshot
// (demo-data.json, exported from a lab run by tools/export_demo.py) and refuses every
// change. Nothing is sent anywhere.

export const DEMO = import.meta.env.VITE_DEMO === "1";

export const READ_ONLY =
  "This is a read-only demo with fictional data, so nothing can be changed or run here. " +
  "Run AttackLedger yourself to do this.";

type Row = Record<string, unknown> & { module?: string | null };

interface Snapshot {
  get: Record<string, unknown>;
  endpoints: Record<string, Row[]>;
  leads: Record<string, Row[]>;
  inbox?: Record<string, Row[]>;
}

let snapshot: Promise<Snapshot> | null = null;

function load(): Promise<Snapshot> {
  snapshot ??= fetch(`${import.meta.env.BASE_URL}demo-data.json`).then((r) => {
    if (!r.ok) throw new Error("The demo data could not be loaded.");
    return r.json() as Promise<Snapshot>;
  });
  return snapshot;
}

export function demoUrl(path: string): string {
  return `${import.meta.env.BASE_URL}${path.replace(/^\//, "")}`;
}

export async function demoCall<T>(path: string, init?: RequestInit): Promise<T> {
  const method = (init?.method ?? "GET").toUpperCase();
  if (method !== "GET") throw new Error(READ_ONLY);
  const data = await load();
  const url = new URL(path, "http://demo.invalid");
  const q = url.searchParams;

  const eps = url.pathname.match(/^\/engagements\/(\d+)\/endpoints$/);
  if (eps) {
    const text = (q.get("q") ?? "").trim();
    const rows = (data.endpoints[eps[1]] ?? []).filter((r) =>
      (!q.has("js") || String(r.js) === q.get("js")) &&
      (!q.get("module") || r.module === q.get("module")) &&
      (!text || String(r.url).includes(text)));
    const offset = Number(q.get("offset") ?? 0);
    const limit = Number(q.get("limit") ?? 200);
    return { total: rows.length, items: rows.slice(offset, offset + limit) } as T;
  }
  const leads = url.pathname.match(/^\/engagements\/(\d+)\/leads$/);
  if (leads) {
    return (data.leads[leads[1]] ?? []).filter((r) =>
      (!q.get("module") || r.module === q.get("module")) &&
      (!q.get("kind") || r.kind === q.get("kind"))) as T;
  }
  const inbox = url.pathname.match(/^\/engagements\/(\d+)\/inbox$/);
  if (inbox) {
    // The same filters as GET /engagements/{id}/inbox, over every entry of the snapshot.
    const all = data.inbox?.[inbox[1]] ?? [];
    const text = (q.get("q") ?? "").trim();
    const status = (q.get("status") ?? "").trim().toLowerCase();
    const code = (r: Row) => (typeof r.status === "number" ? r.status : null);
    const statusOk = (r: Row) => {
      const c = code(r);
      if (status === "none") return c === null;
      if (/^[1-5]xx$/.test(status)) return c !== null && Math.floor(c / 100) === Number(status[0]);
      return String(c) === status;
    };
    const rows = all.filter((r) =>
      (!q.get("state") || r.state === q.get("state")) &&
      (!q.get("host") || r.host === q.get("host")) &&
      (!q.get("method") || r.method === q.get("method")?.toUpperCase()) &&
      (!q.get("batch") || String(r.batch_id) === q.get("batch")) &&
      (!status || statusOk(r)) &&
      (!text || String(r.url).includes(text)));
    const counts = { new: 0, mapped: 0, dismissed: 0 } as Record<string, number>;
    for (const r of all) counts[String(r.state)] = (counts[String(r.state)] ?? 0) + 1;
    const offset = Number(q.get("offset") ?? 0);
    const limit = Number(q.get("limit") ?? 100);
    return {
      total: rows.length, offset, limit, counts, hosts: [...new Set(all.map((r) => String(r.host)))].sort(),
      entries: rows.slice(offset, offset + limit),
    } as T;
  }
  if (url.pathname in data.get) return data.get[url.pathname] as T;
  throw new Error("That part of the app is not in the demo data.");
}

/** An imported entry's stored request, response or record: a file next to the demo. */
export function demoInboxRaw(engId: number, entryId: number, part: string): string {
  return demoUrl(`inbox/${engId}/${entryId}-${part}.txt`);
}
