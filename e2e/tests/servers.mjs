// The runner's local servers, started by Playwright (playwright.config.ts, webServer) and stopped
// with it. Each listens on the runner's loopback only.
//
//   127.0.0.1:18180  the web app: a plain TCP forward to the web container. The browsers open
//                    http://localhost:18180, so the app runs in a secure context (WebCrypto) and
//                    under its real nginx headers, as on a workstation.
//   127.0.0.1:18181  pages of another origin, for the CSRF tests (AUTH-2). Opened as
//                    http://localhost:18181 they are the same site as the app (a sibling, which
//                    gets the SameSite=Strict cookie); as http://127.0.0.1:18181, another site.
//   127.0.0.1:18182  the public verifier page, site/verify.html, as a static file.
import { readFile } from "node:fs/promises";
import http from "node:http";
import net from "node:net";

const WEB_HOST = process.env.E2E_WEB_HOST ?? "web";
const APP = "http://localhost:18180";

net.createServer((client) => {
  const upstream = net.connect(80, WEB_HOST);
  client.pipe(upstream);
  upstream.pipe(client);
  const end = () => { client.destroy(); upstream.destroy(); };
  client.on("error", end);
  upstream.on("error", end);
  client.on("close", end);
  upstream.on("close", end);
}).listen(18180, "127.0.0.1");

// Each page runs its attempts when opened and writes what it saw into #out, as JSON.
const CSRF_PAGES = {
  // A form posts JSON-looking text: a "simple" request, sent with the cookie when same-site.
  "/form-create.html": (q) => `<!doctype html><title>form</title>
<form method="POST" action="${APP}/api/engagements" enctype="text/plain">
<input type="hidden" name='{"name":"${q.get("name")}","x":"' value='"}'></form>
<script>document.forms[0].submit()</script>`,
  "/form-logout.html": () => `<!doctype html><title>logout</title>
<form method="POST" action="${APP}/api/auth/logout"></form><script>document.forms[0].submit()</script>`,
  "/form-login.html": (q) => `<!doctype html><title>login</title>
<form method="POST" action="${APP}/api/auth/login" enctype="text/plain">
<input type="hidden" name='{"token":"${q.get("token") ?? ""}","x":"' value='"}'></form>
<script>document.forms[0].submit()</script>`,
  // Scripted requests: no-cors simple requests (sent, answer unreadable) and a JSON request,
  // which needs a CORS preflight the API never grants.
  "/fetch.html": (q) => `<!doctype html><title>fetch</title><pre id="out"></pre><script>
const api = ${JSON.stringify(APP)} + "/api";
const name = ${JSON.stringify(q.get("name") ?? "csrf-fetch")};
const tries = [
  ["no-cors text/plain", () => fetch(api + "/engagements", { method: "POST", mode: "no-cors", credentials: "include",
    headers: { "content-type": "text/plain" }, body: JSON.stringify({ name: name + "-plain" }) })],
  ["no-cors form", () => fetch(api + "/engagements", { method: "POST", mode: "no-cors", credentials: "include",
    body: new URLSearchParams({ name: name + "-form" }) })],
  ["cors json", () => fetch(api + "/engagements", { method: "POST", credentials: "include",
    headers: { "content-type": "application/json" }, body: JSON.stringify({ name: name + "-json" }) })],
  ["cors read", () => fetch(api + "/engagements", { credentials: "include" }).then((r) => r.text())],
  ["no-cors logout", () => fetch(api + "/auth/logout", { method: "POST", mode: "no-cors", credentials: "include" })],
];
(async () => {
  const out = {};
  for (const [label, go] of tries) {
    try { const r = await go(); out[label] = typeof r === "string" ? "read:" + r.slice(0, 200) : "sent:" + r.type + ":" + r.status; }
    catch (e) { out[label] = "error:" + e.name; }
  }
  document.getElementById("out").textContent = JSON.stringify(out);
})();
</script>`,
};

http.createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname === "/health") { res.end("ok"); return; }
  const page = CSRF_PAGES[url.pathname];
  if (!page) { res.statusCode = 404; res.end("not found"); return; }
  res.setHeader("content-type", "text/html; charset=utf-8");
  res.end(page(url.searchParams));
}).listen(18181, "127.0.0.1");

http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname !== "/verify.html") { res.statusCode = 404; res.end("not found"); return; }
  try {
    const body = await readFile(process.env.E2E_SITE_VERIFY ?? "/site/verify.html");
    res.setHeader("content-type", "text/html; charset=utf-8");
    res.setHeader("x-content-type-options", "nosniff");
    res.end(body);
  } catch {
    res.statusCode = 500;
    res.end("site/verify.html is not mounted");
  }
}).listen(18182, "127.0.0.1");

console.log("e2e servers: app forward 18180, other origins 18181, verifier page 18182");
