// Global setup of the people phase. tools/test_e2e.sh has just created the first owner on the
// server (docs/INSTALL.md section 9) with a password made for this run. Here the owner chooses a
// password of their own (step 3 there), adds the test people with first passwords (section 10),
// each person chooses their own, and the owner gives them roles. Every password is derived from
// the run's owner password, so it is new on every run and never written anywhere.
import { createHash } from "node:crypto";
import { api, type Api, NAMES, OWNER, PEOPLE, person, waitForApi } from "./lib";

const sha = (s: string) => createHash("sha256").update(s).digest("hex");

export default async function globalSetup(): Promise<void> {
  await waitForApi();
  const health = await (await fetch("http://web/api/health")).json() as { mode: string };
  if (health.mode !== "people") throw new Error(`the API is in ${health.mode} mode; the owner was not created`);

  // The owner signs in with the password set on the server and chooses one of their own.
  let owner: Api;
  try {
    owner = await person(OWNER.email, OWNER.password);
  } catch {
    owner = await person(OWNER.email, OWNER.firstPassword);
    await owner.call("POST", "/auth/password", { current_password: OWNER.firstPassword, new_password: OWNER.password });
    owner = await person(OWNER.email, OWNER.password);
  }

  const people = await owner.call<{ id: number; email: string }[]>("GET", "/people");
  for (const p of Object.values(PEOPLE)) {
    if (people.some((x) => x.email === p.email)) continue;
    await owner.call("POST", "/people", { email: p.email, name: p.name, password: p.firstPassword, is_owner: false });
    const self = await person(p.email, p.firstPassword);
    await self.call("POST", "/auth/password", { current_password: p.firstPassword, new_password: p.password });
  }
  const ids = Object.fromEntries((await owner.call<{ id: number; email: string }[]>("GET", "/people")).map((x) => [x.email, x.id]));
  const member = (key: keyof typeof PEOPLE, roles: string[]) => ({ user_id: ids[PEOPLE[key].email], roles });

  // Roles: the reader reads the clean and the hostile engagement; the tester works and the
  // reviewer signs the clean one.
  const clean = await api.engagementId(NAMES.cleanEng);
  const hostile = await api.engagementId(NAMES.hostileEng);
  await owner.call("PUT", `/engagements/${clean}/members`, { members: [
    member("reader", ["viewer"]), member("tester", ["tester"]), member("reviewer", ["reviewer"])] });
  await owner.call("PUT", `/engagements/${hostile}/members`, { members: [member("reader", ["viewer"])] });

  // One engagement per browser for a receipt the reviewer signs with a key made in the browser:
  // its only lane has every item evidenced by the owner, and waits for the signature.
  for (const browser of ["chromium", "firefox"]) {
    const name = `${NAMES.signedEng} ${browser}`;
    if ((await owner.call<{ name: string }[]>("GET", "/engagements")).some((e) => e.name === name)) continue;
    const eng = await owner.call<{ id: number }>("POST", "/engagements", { name });
    await owner.call("PUT", `/engagements/${eng.id}/scope`, { include: ["*.clean.test"], research_header: "X-E2E: e2e-test" });
    await owner.call("POST", `/engagements/${eng.id}/attest`, { operator: "E2E Owner", policy_url: "https://example.com/policy", confirm: true });
    const asset = await owner.call<{ id: number }>("POST", `/engagements/${eng.id}/assets`, { host: `sign-${browser}.clean.test` });
    const lane = await owner.call<{ id: number; items: { idx: number }[] }>("POST", "/lanes", { asset_id: asset.id, role: "recon" });
    for (const item of lane.items) {
      const text = `checked item ${item.idx} for the signing test`;
      await owner.call("POST", `/lanes/${lane.id}/evidence`, { item_idx: item.idx, kind: "note", sha256: sha(text), summary: text });
      await owner.call("PATCH", `/lanes/${lane.id}/items/${item.idx}`, { state: "done" });
    }
    await owner.call("PUT", `/engagements/${eng.id}/members`, { members: [member("reviewer", ["reviewer"])] });
  }
}
