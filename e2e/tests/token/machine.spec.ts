// The machine routes through the web app (TM-1): nginx refuses /api/gateway/ and /api/worker/ in
// every spelling, with the API's own 404, and the API refuses them on any address but its control
// one. The requests are sent with node:http, which sends the path exactly as written (fetch and the
// browsers would resolve the dot segments first). The worker token is valid: only where the call
// arrives decides.
import http from "node:http";
import { expect, test, TOKEN, WORKER_API, WORKER_TOKEN } from "../lib";

function raw(host: string, port: number, path: string, token: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host, port, path, method: "GET", headers: { authorization: `Bearer ${token}` } }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (c) => { body += c; });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

const SPELLINGS = ["/api/worker/ping", "/api//worker/ping", "/api/%77orker/ping", "/api/Worker/ping", "/api/./worker/ping",
                   "/api/x/../worker/ping", "/api/worker%2Fping", "/api/gateway/dns-scopes", "/api/%67ateway/dns-scopes",
                   "/api/GATEWAY/dns-scopes", "/api/gateway%2Fdns-scopes"];

test("the machine routes are not reachable through the web app", async () => {
  expect(WORKER_TOKEN, "tools/test_e2e.sh makes a worker token").not.toBe("");
  for (const path of SPELLINGS) {
    for (const token of [WORKER_TOKEN, TOKEN]) {
      const r = await raw("web", 80, path, token);
      expect({ path, ...r }).toEqual({ path, status: 404, body: '{"detail":"Not Found"}' });
    }
  }
  // A route for people still answers, and the worker's route answers on the control network.
  expect((await raw("web", 80, "/api/health", TOKEN)).status).toBe(200);
  const control = new URL(WORKER_API);
  expect(await raw(control.hostname, Number(control.port), "/worker/ping", WORKER_TOKEN))
    .toEqual({ status: 200, body: '{"ok":true}' });
});
