// The public site as Cloudflare Pages serves it (attackledger.com), for the site phase
// (playwright.config.ts, E2E_PHASE=site). Started by Playwright and stopped with it.
//
// It builds the site with tools/build_pages.sh into the runner's /tmp (never into the checkout:
// /repo is mounted read-only), then serves that folder on 127.0.0.1:18183 and [::1]:18183, so
// the browsers open http://localhost:18183, a secure context as https://attackledger.com is.
//
// Why a small server of our own and not nginx with a config made from _headers: what has to match
// Cloudflare is how Pages reads _headers and routes paths, and nginx does neither the same way.
// Pages applies every rule whose pattern matches and joins a header that two rules set with ", "
// (so /verify gets the site's policy and its own, two policies, both enforced); nginx's add_header
// in a nested location replaces the outer ones instead. Pages also serves /x from x.html,
// redirects /x.html to /x, and answers an unknown path with the nearest 404.html and status 404.
// Here all of that is ~150 lines in the runner's own Node, with no other image to pin.
//
// What Pages does that this does not: compression, caching headers and ETags, the
// `access-control-allow-origin` and other defaults Cloudflare adds on its own, _redirects (the
// site has none), and absolute-URL rules in _headers (the site has none; a rule this server cannot
// read fails the start, so a new kind is not silently ignored).
import { execFileSync } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import http from "node:http";
import path from "node:path";

const OUT = process.env.E2E_PAGES_OUT ?? "/tmp/pages";
const BUILD = process.env.E2E_BUILD_PAGES ?? "/repo/tools/build_pages.sh";
const PORT = 18183;

/** Parses _headers: a line at the start is a path pattern; indented lines below it are
 *  "Name: value" (set) or "! Name" (remove). As https://developers.cloudflare.com/pages/configuration/headers/ */
export function parseHeaders(text) {
  const rules = [];
  let rule = null;
  for (const [n, raw] of text.split("\n").entries()) {
    const line = raw.replace(/\s+$/, "");
    if (!line.trim() || line.trim().startsWith("#")) continue;
    if (!/^\s/.test(line)) {
      if (!line.startsWith("/")) throw new Error(`_headers line ${n + 1}: a pattern this server does not read: ${line}`);
      rule = { pattern: line, match: compile(line), set: [], remove: [] };
      rules.push(rule);
      continue;
    }
    if (!rule) throw new Error(`_headers line ${n + 1}: a header before any path`);
    const t = line.trim();
    if (t.startsWith("!")) { rule.remove.push(t.slice(1).trim().toLowerCase()); continue; }
    const i = t.indexOf(":");
    if (i <= 0) throw new Error(`_headers line ${n + 1}: not "Name: value": ${t}`);
    rule.set.push([t.slice(0, i).trim().toLowerCase(), t.slice(i + 1).trim()]);
  }
  return rules;
}

/** A pattern: "*" (a splat) matches anything, ":name" one path segment, the rest itself. */
function compile(pattern) {
  let re = "";
  for (const part of pattern.split(/(\*|:[A-Za-z]\w*)/)) {
    if (part === "*") re += ".*";
    else if (part.startsWith(":") && part.length > 1) re += "[^/]+";
    else re += part.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

/** The headers _headers gives a path: every matching rule in order; a header set twice is joined. */
export function headersFor(rules, pathname) {
  const out = new Map();
  for (const r of rules) {
    if (!r.match.test(pathname)) continue;
    for (const name of r.remove) out.delete(name);
    for (const [name, value] of r.set) out.set(name, out.has(name) ? `${out.get(name)}, ${value}` : value);
  }
  return out;
}

const TYPES = {
  ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "application/javascript",
  ".json": "application/json", ".txt": "text/plain; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png",
  ".woff2": "font/woff2", ".woff": "font/woff", ".py": "text/x-python", ".pem": "application/x-pem-file",
};

async function isFile(p) {
  try { return (await stat(p)).isFile(); } catch { return false; }
}

/** Pages' route matching for HTML: which file a path serves, or where it redirects. */
async function resolve(pathname) {
  const local = (p) => path.join(OUT, p);
  // Never the configuration files, and nothing outside the folder.
  if (/^\/_(headers|redirects|routes\.json)$/.test(pathname)) return null;
  if (pathname.split("/").some((s) => s === "..")) return null;
  if (pathname.endsWith("/index.html")) return { redirect: pathname.slice(0, -"index.html".length) };
  if (pathname.endsWith(".html")) {
    if (await isFile(local(pathname))) return { redirect: pathname.slice(0, -".html".length) };
    return null;
  }
  if (pathname.endsWith("/")) {
    if (await isFile(local(pathname + "index.html"))) return { file: local(pathname + "index.html") };
    if (pathname !== "/" && await isFile(local(pathname.slice(0, -1) + ".html"))) return { redirect: pathname.slice(0, -1) };
    return null;
  }
  if (await isFile(local(pathname))) return { file: local(pathname) };
  if (await isFile(local(pathname + ".html"))) return { file: local(pathname + ".html") };
  if (await isFile(local(pathname + "/index.html"))) return { redirect: pathname + "/" };
  return null;
}

/** The nearest 404.html above a path, as Pages looks for it. */
async function notFoundPage(pathname) {
  const parts = pathname.split("/").slice(1, -1);
  for (let i = parts.length; i >= 0; i--) {
    const p = path.join(OUT, ...parts.slice(0, i), "404.html");
    if (await isFile(p)) return p;
  }
  return null;
}

export async function startPagesServer() {
  execFileSync("bash", [BUILD, OUT], { stdio: ["ignore", "inherit", "inherit"] });
  const rules = parseHeaders(await readFile(path.join(OUT, "_headers"), "utf8"));

  async function handle(req, res) {
    const url = new URL(req.url ?? "/", "http://localhost");
    let pathname;
    try { pathname = decodeURIComponent(url.pathname); } catch { res.statusCode = 400; res.end(); return; }
    if (req.method !== "GET" && req.method !== "HEAD") { res.statusCode = 405; res.end(); return; }
    const found = await resolve(pathname);
    if (found?.redirect) {
      res.statusCode = 308;
      res.setHeader("location", found.redirect + url.search);
      res.end();
      return;
    }
    let file = found?.file ?? null;
    let status = 200;
    if (!file) {
      file = await notFoundPage(pathname);
      status = 404;
    }
    const headers = new Map([["content-type", file ? TYPES[path.extname(file)] ?? "application/octet-stream" : "text/plain"]]);
    for (const [k, v] of headersFor(rules, pathname)) headers.set(k, v);    // _headers replaces the type
    for (const [k, v] of headers) res.setHeader(k, v);
    res.statusCode = status;
    if (!file) { res.end("not found"); return; }
    const body = await readFile(file);
    res.setHeader("content-length", body.length);
    res.end(req.method === "HEAD" ? undefined : body);
  }

  const serve = (req, res) => { handle(req, res).catch(() => { res.statusCode = 500; res.end(); }); };
  http.createServer(serve).listen(PORT, "127.0.0.1");
  http.createServer(serve).on("error", () => undefined).listen(PORT, "::1");   // no IPv6 loopback: IPv4 alone
  console.log(`e2e site: ${OUT} served as Cloudflare Pages would, on port ${PORT}`);
}

if (import.meta.url === `file://${process.argv[1]}`) await startPagesServer();
