// The guided first run: the five steps from a new engagement to its first lane, each one's
// state worked out from the engagement as it is (its scope, its runs, its ledger), never from
// a wizard state of its own that could drift from it.

import type { Coverage, Job, Scope } from "./api";

export type SetupTab = "recon" | "ledger";
export type StepKey = "rules" | "auth" | "hosts" | "recon" | "lane";
export type StepState = "done" | "todo" | "waiting";

export interface SetupStep {
  key: StepKey;
  title: string;
  state: StepState;
  text: string;          // what is there, or what is missing
  tab: SetupTab;         // where the step is done
  focus: string;         // what to focus there (a CSS selector)
  who: "rules" | "work"; // the access it needs (access.ts)
}

export interface SetupData { engId: number; scope: Scope; jobs: Job[] }

export function setupSteps({ scope, jobs }: SetupData, coverage: Coverage): SetupStep[] {
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
        : !hasScope ? "List what is in scope, the rate limit, and the research header or user agent the program asks for."
        : "Set the research header or user agent the program asks for.",
    },
    {
      key: "auth", title: "Authorization", tab: "recon", focus: "#roe-operator", who: "rules",
      state: scope.authorized_at ? "done" : "todo",
      text: scope.authorized_at ? `Recorded by ${scope.authorized_by}, ${new Date(scope.authorized_at).toLocaleDateString()}`
        : "Record who authorized the test and the policy it follows. Nothing runs before this.",
    },
    {
      key: "hosts", title: "Hosts", tab: "recon", focus: "#recon-new-host", who: "work",
      state: hosts > 0 ? "done" : wildcard && !ran ? "waiting" : "todo",
      text: hosts > 0 ? `${n(hosts, "host", "hosts")} in scope, each a row in the ledger`
        : wildcard && !ran ? `Recon finds the hosts under ${wildcard}. You can also add one by hand.`
        : "Exact scope entries become hosts when the rules are saved; or add a host by hand.",
    },
    {
      key: "recon", title: "Run recon", tab: "recon", focus: "#run-all", who: "work",
      state: ran ? "done" : "todo",
      text: ran ? `${n(jobs.filter((j) => j.status === "done" || j.status === "partial").length, "step has", "steps have")} run`
        : "Run every step at once, or one at a time. Each step checks the rules before it sends anything.",
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
                    <> {s.who === "rules" ? "An owner of this engagement records this." : "A tester on this engagement does this."}</>
                  )}
                </p>
                {current && allowed && (
                  <button type="button" className="btn small" onClick={() => onGo(s)}>
                    {s.key === "lane" ? "Go to the ledger" : s.key === "recon" ? "Go to the recon steps" : `Go to ${s.title.toLowerCase()}`}
                  </button>
                )}
              </div>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
