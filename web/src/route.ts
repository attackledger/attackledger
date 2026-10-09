// Where the app is, in the URL: the engagement, its tab, the open lane and the open import entry.
// Hash routes ("#/e/3/ledger/lane/12"), because they work unchanged behind nginx's SPA fallback,
// under the demo's /demo/ folder on a static host, and from a saved link: the part after "#" never
// reaches the server, so there is nothing to configure and nothing for the server to refuse.

export interface Route {
  page: "work" | "people";
  eng?: number;
  tab?: string;
  lane?: number;
  entry?: number;   // an import inbox entry, on the Import tab
}

const id = (s: string | undefined) => (s && /^\d{1,12}$/.test(s) ? Number(s) : undefined);

export function parseRoute(hash: string): Route {
  const parts = hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  if (parts[0] === "people") return { page: "people" };
  if (parts[0] !== "e") return { page: "work" };
  const r: Route = { page: "work", eng: id(parts[1]) };
  if (r.eng == null) return { page: "work" };
  if (parts[2] && /^[a-z]{1,20}$/.test(parts[2])) r.tab = parts[2];
  for (let i = 3; i + 1 < parts.length; i += 2) {
    if (parts[i] === "lane") r.lane = id(parts[i + 1]);
    if (parts[i] === "entry") r.entry = id(parts[i + 1]);
  }
  return r;
}

export function formatRoute(r: Route): string {
  if (r.page === "people") return "#/people";
  if (r.eng == null) return "";
  let h = `#/e/${r.eng}`;
  if (r.tab) h += `/${r.tab}`;
  if (r.tab && r.entry != null) h += `/entry/${r.entry}`;
  if (r.tab && r.lane != null) h += `/lane/${r.lane}`;
  return h;
}

/** The address of a place in the app, to share with someone on the same server. */
export function linkTo(r: Route): string {
  const { origin, pathname, search } = window.location;
  return `${origin}${pathname}${search}${formatRoute(r)}`;
}
