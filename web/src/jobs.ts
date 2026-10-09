import type { Job } from "./api";

/** How a job reads in the UI. A step that had nothing to work on is "skipped", never "done":
 *  the server reports that as its own status; older servers finished such a step as "done"
 *  with no targets, which is the same thing. */
export type ShownStatus = Job["status"];

export function shownStatus(j: Job): ShownStatus {
  if (j.status === "done" && j.deferred && j.targets.length === 0 && j.result_count === 0) return "skipped";
  return j.status;
}

export const STATUS_WORD: Record<ShownStatus, string> = {
  queued: "Queued", running: "Running", done: "Done", failed: "Failed", cancelled: "Cancelled",
  partial: "Partial", skipped: "Skipped",
};

/** Why a skipped step did not run: the server's reason in the result, else the log's own line. */
export function skipReason(j: Job): string | null {
  const r = j.result as Record<string, unknown> | null;
  for (const k of ["skipped_reason", "reason", "detail", "summary"]) {
    const v = r?.[k];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  if (!j.log) return null;
  const ls = j.log.split("\n").map((l) => l.trim()).filter(Boolean);
  const hit = [...ls].reverse().find((l) => /^(nothing to run|skipped)\b/i.test(l));
  const line = hit ?? ls[ls.length - 1];
  return line ? line.replace(/^(nothing to run|skipped):\s*/i, "") : null;
}

/** The last line the worker wrote, for following a running step. */
export function latestLine(log: string | undefined): string | null {
  if (!log) return null;
  const ls = log.split("\n").map((l) => l.trim()).filter(Boolean);
  return ls[ls.length - 1] ?? null;
}

export function secondsSince(iso: string | null): number | null {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  return Number.isNaN(t) ? null : Math.max(0, (Date.now() - t) / 1000);
}
