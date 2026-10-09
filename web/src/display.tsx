// How times, sizes and key fingerprints read, the same on every view: times in the reader's own
// time zone, with UTC on hover for anyone comparing with a report or a log; sizes without a
// trailing ".0"; fingerprints in groups of four, so two can be compared by eye.

/** "9 Oct 2026, 14:03 CEST": the reader's local time, with its zone. */
export function localTime(iso: string | null | undefined): string {
  if (!iso) return "unknown";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { timeZoneName: "short" });
}

/** "2026-10-09 12:03 UTC": what reports, logs and the server record. */
export function utcTime(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

/** A time as the reader's local time, with UTC on hover. */
export function When({ iso }: { iso: string | null | undefined }) {
  if (!iso) return <>unknown</>;
  return <time dateTime={iso} title={utcTime(iso)}>{localTime(iso)}</time>;
}

/** "50 MB", "1.5 kB", "812 B". */
export function bytes(n: number): string {
  const one = (x: number) => String(Math.round(x * 10) / 10);
  if (n < 1000) return `${n} B`;
  if (n < 1_000_000) return `${one(n / 1000)} kB`;
  return `${one(n / 1_000_000)} MB`;
}

const group = (hex: string) => (hex.match(/.{1,4}/g) ?? []).join(" ");

/** "3f9a e9de 7c0a 71ec…": the first 16 hex digits, grouped. The full fingerprint is on hover. */
export function shortFingerprint(fp: string): string {
  return `${group(fp.slice(0, 16))}${fp.length > 16 ? "…" : ""}`;
}

/** A key fingerprint, written one way everywhere. `full` shows every digit, in the same groups. */
export function Fingerprint({ fp, full = false }: { fp: string | null | undefined; full?: boolean }) {
  if (!fp) return <code>unknown</code>;
  return full
    ? <code className="hash-wrap">{group(fp)}</code>
    : <code title={group(fp)}>{shortFingerprint(fp)}</code>;
}
