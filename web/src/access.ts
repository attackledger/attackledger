// What the signed-in caller may do on an engagement, so the app offers only actions the
// server will accept. The server decides (authz.RULES); this mirrors it for the UI.
//
//   owners (and the token and open modes): everything
//   tester:   recon runs, hosts, lanes, evidence, item states, executor, agent runs
//   reviewer: sign and close lanes, timestamp receipts
//   viewer:   read only
//
// The demo shows every control as before (its API refuses changes), but has no people.

import type { Me } from "./api";
import { DEMO } from "./demo";

export type Action =
  | "create"   // new engagements (owners)
  | "rules"    // scope, rules of engagement, authorization (owners)
  | "team"     // people and engagement roles (owners)
  | "work"     // tester work
  | "sign";    // reviewer: sign and close

const ROLE: Record<Action, string | null> = {
  create: null, rules: null, team: null,   // null: owners only
  work: "tester",
  sign: "reviewer",
};

export function rolesOn(me: Me | null, engId: number | null): string[] {
  if (!me || engId == null) return [];
  return me.roles?.[String(engId)] ?? [];
}

export function can(me: Me | null, engId: number | null, action: Action): boolean {
  if (DEMO) return action !== "team";
  if (!me) return false;            // until we know who this is, offer nothing that changes state
  if (me.is_owner) return true;
  const role = ROLE[action];
  return role !== null && rolesOn(me, engId).includes(role);
}

/** True when the caller can only read this engagement (a viewer, and nothing more). */
export function readOnly(me: Me | null, engId: number | null): boolean {
  if (DEMO || !me || me.is_owner) return false;
  return !can(me, engId, "work") && !can(me, engId, "sign");
}
