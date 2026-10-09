// The guided first run: the steps from a new engagement to its first lane, each one's state
// worked out from the engagement as it is (its scope, its team, its runs and imports, its
// ledger), never from a wizard state of its own that could drift from it.

import type { Coverage, Job, Member, Scope } from "./api";
import { termsFor } from "./words";

export type SetupTab = "recon" | "ledger" | "import" | "team";
export type StepKey = "rules" | "auth" | "team" | "hosts" | "recon" | "lane";
export type StepState = "done" | "todo" | "waiting";

export interface SetupStep {
  key: StepKey;
  title: string;
  state: StepState;
  text: string;          // what is there, or what is missing
  tab: SetupTab;         // where the step is done
  focus: string;         // what to focus there (a CSS selector)
  who: "rules" | "work" | "team"; // the access it needs (access.ts)
  alt?: { label: string; tab: SetupTab; focus: string };   // a second way to do the step
}

/** Who can sign in besides owners, and the roles they hold here. Only owners can read this, so
 *  the team step is shown to owners only, and only when people sign in. */
export interface TeamState { others: number; members: Member[] }

export interface SetupData {
  engId: number;
  scope: Scope;
  jobs: Job[];
  imports: number;             // files imported into this engagement
  team: TeamState | null;
  engagementType?: string;
}

function teamStep(team: TeamState, coverage: Coverage): SetupStep {
  const has = (r: string) => team.members.filter((m) => m.roles.includes(r)).length;
  const withRole = team.members.filter((m) => m.roles.length > 0).length;
  const rules = `Separation of duties ${coverage.separation_of_duties ? "on" : "off"}; signed receipts `
    + `${coverage.require_signatures ? "required" : "not required"}.`;
  const roles = [["tester", "tester", "testers"], ["reviewer", "reviewer", "reviewers"], ["viewer", "viewer", "viewers"]]
    .map(([r, one, many]) => [has(r), one, many] as const).filter(([k]) => k > 0)
    .map(([k, one, many]) => `${k} ${k === 1 ? one : many}`).join(", ");
  const base = { key: "team" as const, title: "Team", tab: "team" as const, focus: ".team input[type=checkbox]", who: "team" as const };
  if (withRole > 0) return { ...base, state: "done", text: `${roles}. ${rules}` };
  if (team.others === 0)
    return { ...base, state: "done",
             text: `Only owners sign in, and owners hold every role. Add people on the People page to give them roles. ${rules}` };
  return {
    ...base, state: "todo",
    text: "Give people roles: testers do the work, reviewers sign receipts, viewers read the report. Then choose "
      + "separation of duties (whoever attached a lane's evidence cannot sign it) and whether receipts must be signed.",
  };
}

export function setupSteps({ scope, jobs, imports, team, engagementType }: SetupData, coverage: Coverage): SetupStep[] {
  const terms = termsFor(engagementType);
  const hasScope = scope.include.length > 0;
  const identified = !!(scope.research_header || scope.research_user_agent);
  const wildcard = scope.include.find((p) => p.startsWith("*."));
  const hosts = coverage.assets.filter((a) => a.in_scope).length;
  const ran = jobs.some((j) => j.kind !== "agent" && (j.status === "done" || j.status === "partial"));
  const lanes = coverage.assets.some((a) => Object.values(a.roles).some((c) => c.status !== "not_opened"));
  const n = (k: number, one: string, many: string) => `${k} ${k === 1 ? one : many}`;

  return [
    {
      key: "rules", title: "Scope and rules", tab: "recon", focus: "#roe-include", who: "rules",
      state: hasScope && identified ? "done" : "todo",
      text: hasScope && identified ? `${n(scope.include.length, "scope entry", "scope entries")}, research identification set`
        : !hasScope ? `List what is in scope, the rate limit, and the research header or user agent ${terms.asks} for.`
        : `Set the research header or user agent ${terms.asks} for.`,
    },
    {
      key: "auth", title: "Authorization", tab: "recon", focus: "#roe-operator", who: "rules",
      state: scope.authorized_at ? "done" : "todo",
      text: scope.authorized_at ? `Recorded by ${scope.authorized_by}, ${new Date(scope.authorized_at).toLocaleDateString()}`
        : engagementType === "bug_bounty" ? "Record who authorized the test and the policy it follows. Nothing runs before this."
        : "Record who authorized the test and the statement of work it follows. Nothing runs before this.",
    },
    ...(team ? [teamStep(team, coverage)] : []),
    {
      key: "hosts", title: "Hosts", tab: "recon", focus: "#recon-new-host", who: "work",
      state: hosts > 0 ? "done" : wildcard && !ran ? "waiting" : "todo",
      text: hosts > 0 ? `${n(hosts, "host", "hosts")} in scope, each a row in the ledger`
        : wildcard && !ran ? `Recon finds the hosts under ${wildcard}. You can also add one by hand.`
        : "Exact scope entries become hosts when the rules are saved; or add a host by hand.",
    },
    {
      // Either one counts: a team that tests with its own tools only imports what it captured.
      key: "recon", title: "Run recon, or import evidence", tab: "recon", focus: "#run-all", who: "work",
      alt: { label: "Go to import", tab: "import", focus: ".import input[type=file]" },
      state: ran || imports > 0 ? "done" : "todo",
      text: ran || imports > 0
        ? [ran ? `${n(jobs.filter((j) => j.status === "done" || j.status === "partial").length, "recon step has", "recon steps have")} run` : "",
           imports > 0 ? `${n(imports, "file", "files")} imported` : ""].filter(Boolean).join("; ")
        : "Run recon here, or import what you captured in Burp, Caido or a browser (HAR). Either one completes this step.",
    },
    {
      key: "lane", title: "Open a lane", tab: "ledger", focus: "button.cell.unopened", who: "work",
      state: lanes ? "done" : "todo",
      text: lanes ? "Testing has started: work the checklist and attach evidence"
        : "Pick a host and a lane in the ledger. The lane's checklist is what gets receipted.",
    },
  ];
}

/** The step to do now: the first one not done that is not waiting on a later step. */
export function nextStep(steps: SetupStep[]): SetupStep | undefined {
  return steps.find((s) => s.state === "todo");
}

export function setupComplete(steps: SetupStep[]): boolean {
  return steps.every((s) => s.state === "done");
}

/** Focus a control that appears once its tab has loaded. */
export function focusWhenReady(selector: string, tries = 40) {
  const el = document.querySelector<HTMLElement>(selector);
  if (el) {
    el.scrollIntoView({ behavior: "smooth", block: "center" });
    el.focus({ preventScroll: true });
    return;
  }
  if (tries > 0) setTimeout(() => focusWhenReady(selector, tries - 1), 100);
}

const STATE_WORD: Record<StepState, string> = { done: "Done", todo: "To do", waiting: "After recon" };

export function SetupGuide({ steps, canDo, onGo }: {
  steps: SetupStep[];
  canDo: (who: SetupStep["who"]) => boolean;
  onGo: (step: SetupStep) => void;
}) {
  const next = nextStep(steps);
  const done = steps.filter((s) => s.state === "done").length;
  return (
    <section className="setup" aria-labelledby="setup-title">
      <div className="setup-head">
        <h3 id="setup-title" className="setup-title">Set up this engagement</h3>
        <p className="setup-progress">
          {done} of {steps.length} steps done{next ? <>. Next: <strong>{next.title}</strong></> : null}
        </p>
      </div>
      <ol className="setup-steps">
        {steps.map((s, i) => {
          const current = s === next;
          const allowed = canDo(s.who);
          return (
            <li key={s.key} className={`setup-step ${s.state}${current ? " current" : ""}`}
                aria-current={current ? "step" : undefined}>
              <span className="setup-n" aria-hidden="true">{s.state === "done" ? "✓" : i + 1}</span>
              <div className="setup-body">
                <p className="setup-step-title">
                  <span className="sr-only">Step {i + 1}: </span>{s.title}
                  <span className="setup-state">{current ? "Next" : STATE_WORD[s.state]}</span>
                </p>
                <p className="setup-text">
                  {s.text}
                  {s.state !== "done" && !allowed && (
                    <> {s.who === "work" ? "A tester on this engagement does this." : "An owner of this engagement records this."}</>
                  )}
                </p>
                {current && allowed && (
                  <div className="setup-go">
                    <button type="button" className="btn small" onClick={() => onGo(s)}>
                      {s.key === "lane" ? "Go to the ledger" : s.key === "recon" ? "Go to the recon steps" : `Go to ${s.title.toLowerCase()}`}
                    </button>
                    {s.alt && (
                      <button type="button" className="btn ghost small" onClick={() => onGo({ ...s, tab: s.alt!.tab, focus: s.alt!.focus })}>
                        {s.alt.label}
                      </button>
                    )}
                  </div>
                )}
              </div>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
