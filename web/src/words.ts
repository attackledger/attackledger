// Small wording helpers shared by every view, so counts read the same everywhere.

/** "1 host", "2 hosts", "1 query", "3 queries". */
export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}

/** A duration in seconds as "45 s", "12 min 5 s" or "1 h 20 min". */
export function duration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min${s % 60 ? ` ${s % 60} s` : ""}`;
  const h = Math.floor(m / 60);
  return `${h} h${m % 60 ? ` ${m % 60} min` : ""}`;
}

/** The words a view uses for who sets the rules: a bug bounty program publishes a policy; a pentest or
 *  an internal assessment is done for a client under a statement of work and rules of engagement. */
export interface Terms {
  rulesBy: string;           // "the program", "the rules of engagement"
  allows: string;            // "the program allows", "the rules of engagement allow"
  asks: string;
  requires: string;
  policyLabel: string;
  policyPlaceholder: string;
  attest: string;
  scopeImport: string;
  leadsCheck: string;
  headerPlaceholder: string;
}

export function termsFor(engagementType: string | null | undefined): Terms {
  if (engagementType === "bug_bounty") {
    return {
      rulesBy: "the program",
      allows: "the program allows",
      asks: "the program asks",
      requires: "the program requires",
      policyLabel: "Program policy URL",
      policyPlaceholder: "https://hackerone.com/example",
      attest: "I am authorized to test this program and will follow its policy.",
      scopeImport: "Import a HackerOne scope CSV",
      leadsCheck: "check the program policy",
      headerPlaceholder: "X-Bug-Bounty: your-handle",
    };
  }
  return {
    rulesBy: "the rules of engagement",
    allows: "the rules of engagement allow",
    asks: "the rules of engagement ask",
    requires: "the rules of engagement require",
    policyLabel: "Statement of work or rules of engagement URL",
    policyPlaceholder: "https://docs.example.com/statement-of-work",
    attest: "I am authorized by the client to test these hosts under the statement of work and will follow its rules of engagement.",
    scopeImport: "Import a scope CSV (HackerOne's export format)",
    leadsCheck: "check the rules of engagement",
    headerPlaceholder: "X-Pentest: your-team",
  };
}
