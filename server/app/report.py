"""Audit report: a self-describing, verifiable snapshot of an engagement.

The JSON bundle carries everything needed to re-check it offline:
  - each lane's receipt can be recomputed from its items and evidence,
  - the evidence hash chain can be walked from the genesis value,
  - the bundle hash covers the whole body,
  - (format 2) signed receipts carry their payload, signature and public key, and
    timestamped receipts their RFC 3161 token,
  - (format 2) the key log history of every key that signed a receipt (keylog.py), with
    the chain links from its first entry to the head,
  - (format 2) the audit log entries of the engagement and the person events of its
    signers and members (auditlog.py), with the chain links from the first to the head.
tools/verify_report.py checks all of it with the Python standard library only.
"""
import html
import json
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

from sqlalchemy import select

from . import auditlog, gates, keylog, ledger, modules, packs
from .models import Engagement, Evidence, iso_utc
from .text import plural

REPORT_FORMAT = "attackledger-report/2"   # 2: receipts may carry a signature


def _receipt(rc) -> dict:
    out = {"manifest_sha256": rc.manifest_sha256, "closed_by": rc.closed_by, "issued_at": _iso(rc.created_at)}
    if rc.closed_by_user is not None:
        out["closed_by_user"], out["closed_by_email"] = rc.closed_by_user, rc.closed_by_email
    if rc.signature:
        out["signature"] = {"algorithm": rc.algorithm, "public_key": rc.public_key,
                            "key_fingerprint": rc.key_fingerprint, "payload": rc.payload, "value": rc.signature}
    if rc.timestamp_token:
        out["timestamp"] = {"tsa": rc.timestamp_tsa, "time": _iso(rc.timestamp_time), "token": rc.timestamp_token}
    return out


def _iso(dt):
    return iso_utc(dt)


def build(session, eng: Engagement, controls: dict) -> dict:
    pack = packs.get_pack(eng.pack_id)
    lane_names = {l.key: l.name for l in pack.lanes}

    hosts, lanes = [], []
    for a in sorted(eng.assets, key=lambda a: a.host):
        hosts.append({"host": a.host, "in_scope": a.in_scope})
        for lane in sorted(a.lanes, key=lambda l: l.id):
            status = gates.lane_status(lane).value
            lanes.append({
                "lane_id": lane.id,
                "host": a.host,
                "role": lane.role,
                "name": lane_names.get(lane.role, lane.role),
                "status": status,
                "items": [{"item_id": i.id, "idx": i.idx, "key": i.item_key, "text": i.text,
                           "state": i.state.value, "na_reason": i.na_reason, "controls": i.controls}
                          for i in lane.items],
                "evidence_ids": [e.id for e in lane.evidence],
                "receipt": (_receipt(lane.receipts[-1]) if lane.receipts else None),
            })

    rows = session.scalars(
        select(Evidence).where(Evidence.engagement_id == eng.id).order_by(Evidence.seq)
    ).all()
    lane_meta = {l["lane_id"]: (l["host"], l["role"]) for l in lanes}
    evidence = []
    for e in rows:
        host, role = lane_meta[e.lane_id]
        evidence.append({"id": e.id, **ledger.evidence_record(e, host, role),
                         "created_at": _iso(e.created_at), "prev_hash": e.prev_hash,
                         "chain_hash": e.chain_hash})

    jobs = [{"id": j.id, "kind": j.kind, "status": j.status.value, "targets": len(j.targets),
             "result_count": j.result_count, "output_sha256": j.output_sha256,
             "started_at": _iso(j.started_at), "finished_at": _iso(j.finished_at)}
            for j in sorted(eng.jobs, key=lambda j: j.id)]

    in_scope = [l for l in lanes if any(h["host"] == l["host"] and h["in_scope"] for h in hosts)]
    body = {
        "format": REPORT_FORMAT,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "engagement": {
            "id": eng.id, "name": eng.name, "type": eng.engagement_type,
            "pack": {"id": pack.id, "name": pack.name, "version": pack.version,
                     "lanes": [{"key": l.key, "name": l.name} for l in pack.lanes]},
            "policy_url": eng.policy_url,
            "authorized_by": eng.authorized_by, "authorized_at": _iso(eng.authorized_at),
            "scope": {"include": eng.scope_include, "exclude": eng.scope_exclude},
            "research_identification": {"header": eng.research_header,
                                        "user_agent": eng.research_user_agent},
            "rate_limit_rps": eng.rate_limit_rps,
            "separation_of_duties": eng.separation_of_duties,
            "require_signatures": eng.require_signatures,
            "redact_evidence": eng.redact_evidence,
        },
        "summary": {
            "hosts_in_scope": sum(1 for h in hosts if h["in_scope"]),
            "lanes_per_host": len(pack.lanes),
            "lanes_possible": sum(1 for h in hosts if h["in_scope"]) * len(pack.lanes),
            "lanes_opened": len(in_scope),
            "lanes_receipted": sum(1 for l in in_scope if l["status"] == "closed"),
            "lanes_stale": sum(1 for l in in_scope if l["status"] == "stale"),
            "evidence_entries": len(evidence),
            "chain_head": evidence[-1]["chain_hash"] if evidence else ledger.GENESIS,
        },
        "hosts": hosts,
        "lanes": lanes,
        "evidence": evidence,
        "jobs": jobs,
        "controls": controls,
    }
    signing_keys = {l["receipt"]["signature"]["key_fingerprint"] for l in lanes
                    if l["receipt"] and l["receipt"].get("signature")}
    history = keylog.for_report(session, signing_keys)
    if history is not None:
        body["key_log"] = history
    signers = {rc.closed_by_user for a in eng.assets for l in a.lanes for rc in l.receipts if rc.closed_by_user}
    changes = auditlog.for_report(session, eng.id, auditlog.people_of(session, eng.id, signers))
    if changes is not None:
        body["audit_log"] = changes
    return {**body, "integrity": {"algorithm": "sha256", "body_sha256": ledger.sha256(ledger.canonical(body)),
                                  "chain_genesis": ledger.GENESIS}}




# ---- HTML ---------------------------------------------------------------------
# A client-facing document: cover, summary, scope, coverage, receipts and how to verify,
# then the detail. Static and self-contained (the route's CSP allows no scripts and no
# fetches); the only script element is the JSON bundle that verify_report.py reads.

def _e(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


_STATUS = {"closed": "Receipted", "stale": "Void", "open": "In progress", None: "Not opened"}
_TYPES = {"bug_bounty": "Bug bounty", "pentest": "Penetration test", "internal": "Internal assessment"}
_ITEM = {"done": "Evidence recorded", "na": "Not applicable", "open": "Open"}
_EVIDENCE = {"note": "Note", "file": "File", "request": "Request", "response": "Response"}
_JOB = {"done": "Done", "partial": "Partial", "skipped": "Skipped", "failed": "Failed", "cancelled": "Cancelled",
        "queued": "Queued", "running": "Running"}


def _evidence_label(e: dict) -> str:
    if (e.get("uri") or "").startswith("job:"):
        return "Recon run"
    return _EVIDENCE.get(e["kind"], e["kind"])
# tools/tsa-roots/README.md lists the same root; shown so a reader can check the file they use.
_DIGICERT_ROOT = ("digicert-trusted-root-g4.pem", "DigiCert Trusted Root G4",
                  "552F7BDCF1A7AF9E6CE672017F4F12ABF77240C78E761AC203D1D9D20AC89988")
_MATRIX_HOSTS = 4   # host columns per coverage table, so it fits an A4 page
# The AttackLedger mark (site/favicon.svg), inline so the report stays one self-contained file.
_FAVICON = "data:image/svg+xml," + quote(' '.join("""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <rect x="1" y="1" width="30" height="30" rx="6" fill="#14221a"/>
  <rect x="3.75" y="3.75" width="24.5" height="24.5" rx="4" fill="none" stroke="#86d3a2" stroke-width="1.5"/>
  <path d="M9.5 16.5l4.4 4.4 8.6-9.2" fill="none" stroke="#86d3a2" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/>
</svg>""".split()))


def _when(iso: str | None) -> str:
    """An ISO time as 'YYYY-MM-DD HH:MM:SS UTC'."""
    if not iso:
        return ""
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return str(iso)
    if dt.tzinfo:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _host_of(url: str | None) -> str:
    return urlsplit(url or "").hostname or url or ""


def _status(status: str | None) -> str:
    return f"<span class='st st-{_e(status or 'none')}'>{_e(_STATUS.get(status, status))}</span>"


def _table(head: list[str], rows: list[str], cls: str = "") -> str:
    th = "".join(f"<th>{h}</th>" for h in head)
    return f"<div class='tw'><table class='{cls}'><thead><tr>{th}</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"


def _dl(rows: list[tuple[str, str]]) -> str:
    return "<dl class='meta'>" + "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows) + "</dl>"


def _list(values: list, empty: str) -> str:
    if not values:
        return f"<span class='muted'>{empty}</span>"
    return "<ul class='plain'>" + "".join(f"<li><code>{_e(v)}</code></li>" for v in values) + "</ul>"


_CSS = """
:root{color-scheme:light;--text:#1d2125;--soft:#59616a;--rule:#d6dadf;--rule2:#9aa2ab;--panel:#f4f6f8;--accent:#1f3a5f;
--ok:#1d6a43;--ok-bg:#e7f2eb;--bad:#a3281f;--bad-bg:#f8e8e6;--wait:#755600;--wait-bg:#fbf2d9}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:#fff;color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;font-variant-numeric:tabular-nums}
main{max-width:60rem;margin:0 auto;padding:2.5rem 1.5rem 4rem}
h1,h2,h3{font-family:Georgia,"Times New Roman",serif;line-height:1.2;color:#111}
h1{font-size:2.1rem;margin:.35rem 0 0}h2{font-size:1.45rem;margin:2.75rem 0 .75rem;padding-top:.85rem;border-top:1px solid var(--rule2)}
h3{font-size:1.05rem;margin:1.6rem 0 .4rem}p{margin:.6rem 0}
.cover{border-bottom:3px solid var(--accent);padding-bottom:1.5rem}.cover+section>h2{border-top:0}.kicker{margin:0;color:var(--soft);font-size:.9rem}
.meta{display:grid;grid-template-columns:14rem minmax(0,1fr);gap:.4rem 1.25rem;margin:1rem 0 0}
.meta dt{color:var(--soft)}.meta dd{margin:0;overflow-wrap:anywhere}
.toc{margin:1.5rem 0 0}.toc ol{margin:.3rem 0 0;padding-left:1.4rem;columns:2;column-gap:2rem}.toc a{color:var(--accent)}
.tiles{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.75rem;margin:1rem 0 1.25rem}
.tile{border:1px solid var(--rule);border-top:3px solid var(--accent);background:var(--panel);padding:.7rem .85rem}
.tile b{display:block;font:700 1.6rem/1.15 Georgia,serif}.tile span{display:block;font-size:13px;color:var(--soft)}
.tw{overflow-x:auto;margin:.5rem 0 1rem}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:.42rem .55rem;border-bottom:1px solid var(--rule);vertical-align:top}
thead th{background:var(--panel);border-bottom:2px solid var(--rule2);font-weight:600}
table.matrix{table-layout:fixed}table.matrix th:first-child{width:13rem}table.matrix td,table.matrix th{text-align:center}table.matrix td:first-child,table.matrix th:first-child{text-align:left}
table.receipts tbody{border-bottom:1px solid var(--rule2)}table.receipts td{border-bottom:0}table.receipts tr.hashes td{padding-top:0}
table.matrix tfoot td{font-weight:600;border-top:2px solid var(--rule2);border-bottom:0}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}code{font-size:12px;overflow-wrap:anywhere}.nw{white-space:nowrap}
pre{font-size:12.5px;background:var(--panel);border:1px solid var(--rule);padding:.6rem .8rem;white-space:pre-wrap;overflow-wrap:anywhere;margin:.4rem 0 .8rem}
ul.plain{list-style:none;margin:0;padding:0}
.st{display:inline-block;padding:0 .45rem;border:1px solid;border-radius:3px;font:600 12px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;white-space:nowrap;vertical-align:middle}
.st-closed{color:var(--ok);background:var(--ok-bg)}.st-stale{color:var(--bad);background:var(--bad-bg)}
.st-open{color:var(--wait);background:var(--wait-bg)}.st-none{color:var(--soft);border-style:dashed}
.legend{display:flex;flex-wrap:wrap;gap:.4rem 1.25rem;font-size:13px;color:var(--soft);margin:.5rem 0}
.ok{color:var(--ok);font-weight:600}.muted{color:var(--soft)}.note{font-size:13px;color:var(--soft)}.small{font-size:12px}
.callout{border-left:4px solid var(--accent);background:var(--panel);padding:.75rem 1rem;margin:1rem 0}.callout .meta{grid-template-columns:10rem minmax(0,1fr);margin:0}
.warn{border-left:4px solid var(--bad);background:var(--bad-bg);color:var(--bad);padding:.6rem .85rem;font-weight:600;margin:1rem 0}
@media (max-width:40rem){main{padding:1.5rem 1rem 3rem}h1{font-size:1.65rem}.meta{grid-template-columns:minmax(0,1fr);gap:0}
.meta dt{margin-top:.6rem}.toc ol{columns:1}.tiles{grid-template-columns:repeat(2,minmax(0,1fr))}
table.matrix{table-layout:auto}table.matrix th:first-child{width:auto}
table.receipts thead{display:none}table.receipts,table.receipts tbody,table.receipts tr,table.receipts td{display:block}
table.receipts td{padding:.2rem 0}table.receipts tbody{padding:.5rem 0}table.receipts td[data-label]::before{content:attr(data-label);display:block;color:var(--soft);font-size:12px}th,td{padding:.38rem .4rem}}
@page{size:A4;margin:16mm 14mm 18mm;@bottom-left{content:"AttackLedger coverage report";font:8pt system-ui,sans-serif;color:#59616a}
@bottom-right{content:"Page " counter(page) " of " counter(pages);font:8pt system-ui,sans-serif;color:#59616a}}
@media print{*{-webkit-print-color-adjust:exact;print-color-adjust:exact}body{font-size:10pt}main{max-width:none;padding:0}
.pb{break-before:page}.pb>h2:first-child{margin-top:0;border-top:0;padding-top:0}h2{margin-top:1.75rem}
h2,h3{break-after:avoid}tr,table.receipts tbody,.tile,.callout,.warn,pre,dl.meta{break-inside:avoid}.tw{overflow:visible}
table{font-size:8.5pt}code{font-size:8pt}pre{font-size:8.5pt}a{color:inherit;text-decoration:none}
.tw.keep{break-inside:avoid}tfoot{display:table-row-group}}
"""

_SECTIONS = [("summary", "Summary"), ("scope", "Scope and authorization"), ("coverage", "Coverage matrix"),
             ("receipts", "Receipts"), ("history", "Change history"), ("verify", "How to verify"), ("controls", "Control evidence"),
             ("items", "Item detail"), ("recon", "Recon runs"), ("integrity", "Integrity")]


def render_html(r: dict) -> str:
    eng, s = r["engagement"], r["summary"]
    in_scope = [h["host"] for h in r["hosts"] if h["in_scope"]]
    lanes = [l for l in r["lanes"] if l["host"] in in_scope]
    sections = [x for x in _SECTIONS if (x[0] != "recon" or r["jobs"]) and (x[0] != "history" or "audit_log" in r)]
    parts = [f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Coverage report: {_e(eng['name'])}</title><link rel="icon" href="{_FAVICON}"><style>{_CSS}</style></head><body><main>
<header class="cover">
<p class="kicker">AttackLedger coverage report</p>
<h1>{_e(eng['name'])}</h1>
{_dl([("Engagement type", _e(_TYPES.get(eng['type'], eng['type']))),
      ("Methodology pack", f"{_e(eng['pack']['name'])}, version {_e(eng['pack']['version'])}"),
      ("Generated", _e(_when(r['generated_at']))),
      ("Report format", f"<code>{_e(r['format'])}</code>"),
      ("Report body SHA-256", f"<code>{_e(r['integrity']['body_sha256'])}</code>")])}
{'' if eng['authorized_at'] else '<p class="warn">No authorization was recorded for this engagement. The tests below are not backed by a recorded permission to test.</p>'}
<nav class="toc" aria-label="Contents"><strong>Contents</strong><ol>
{''.join(f'<li><a href="#{k}">{t}</a></li>' for k, t in sections)}
</ol></nav>
</header>
"""]
    parts += [_summary(r, lanes), _scope(r), _coverage(r, in_scope), _receipts(r), _history(r), _verify(r),
              _controls(r), _items(r)]
    if r["jobs"]:
        parts.append(_recon(r))
    integ = r["integrity"]
    parts.append(f"""<section id="integrity"><h2>Integrity</h2>
<div class="callout">
{_dl([("Evidence entries", _e(s['evidence_entries'])),
      ("Chain genesis", f"<code>{_e(integ['chain_genesis'])}</code>"),
      ("Chain head", f"<code>{_e(s['chain_head'])}</code>"),
      ("Report body SHA-256", f"<code>{_e(integ['body_sha256'])}</code>")])}
</div>
<p class="note">Every evidence entry commits to the hash of the entry before it, starting from the genesis value, so
removing, reordering or editing any entry changes the chain head. The body hash covers everything in the report
except this section. The full report is embedded in this page as JSON; see <a href="#verify">How to verify</a>.</p>
<script type="application/json" id="attackledger-report">{_json_for_html(r)}</script>
</section>
</main></body></html>""")
    return "".join(parts)


def _summary(r: dict, lanes: list) -> str:
    s = r["summary"]
    items = [i for l in lanes for i in l["items"]]
    done = sum(1 for i in items if i["state"] == "done")
    na = sum(1 for i in items if i["state"] == "na")
    with_rc = [l for l in lanes if l["receipt"]]
    signed = sum(1 for l in with_rc if l["receipt"].get("signature"))
    stamped = sum(1 for l in with_rc if l["receipt"].get("timestamp"))
    tiles = [
        (s["hosts_in_scope"], "In-scope hosts"),
        (f"{s['lanes_receipted']} of {s['lanes_opened']}", f"Lanes receipted, of those opened; {s['lanes_possible']} possible"),
        (done, "Items with evidence"),
        (na, "Items not applicable, with a reason"),
        (len(items) - done - na, "Items still open"),
        (f"{signed} of {len(with_rc)}", f"Receipts signed with a key; {stamped} timestamped"),
    ]
    void = s["lanes_stale"]
    name_only = len(with_rc) - signed
    return f"""<section id="summary" class="pb"><h2>Summary</h2>
<div class="tiles">{''.join(f'<div class="tile"><b>{_e(v)}</b><span>{_e(t)}</span></div>' for v, t in tiles)}</div>
{f'<p class="warn">{plural(void, "receipt is", "receipts are")} void: the ledger changed after the receipt was issued, so it no longer proves that lane.</p>' if void else ''}
<p>Of {plural(s['lanes_possible'], 'possible lane', 'possible lanes')} ({plural(s['hosts_in_scope'], 'in-scope host', 'in-scope hosts')}
× {plural(s['lanes_per_host'], 'lane')}), {s['lanes_opened']} {'was' if s['lanes_opened'] == 1 else 'were'} opened and
<strong>{s['lanes_receipted']} {'is' if s['lanes_receipted'] == 1 else 'are'} receipted</strong>: every checklist item
has evidence or a written reason, the receipt matches the ledger, and a named person reviewed the lane and closed it.
{'No receipts are void.' if not void else plural(void, 'receipt is', 'receipts are') + ' void.'}
Lanes that were not opened were not tested.</p>
<div class="callout"><p><strong>What this report proves.</strong> It is a record of what was tested, not a judgement of
how well. It shows which checklist items were recorded as tested or not applicable, which evidence was attached to each,
who closed each lane and when, and that none of this changed after it was recorded: the evidence is hash-chained,
{'' if not signed else 'signed receipts carry a signature from the reviewer’s own key, '}{'' if not stamped else 'timestamped receipts carry a token from an independent timestamp authority, '}and anyone can
re-check all of it offline.</p>
<p>It does not prove that the tests themselves were thorough or correct, that untested lanes or hosts are free of issues,
or that a signing key belongs to the person named; compare key fingerprints with the signers for that. It is not a list
of findings.{' ' + plural(name_only, 'receipt carries', 'receipts carry') + ' only a name, which rests on the tester’s own records.' if name_only else ''}</p></div>
</section>"""


def _scope(r: dict) -> str:
    eng = r["engagement"]
    ident = eng["research_identification"]
    out_hosts = [h["host"] for h in r["hosts"] if not h["in_scope"]]
    rows = [
        ("Authorization recorded by", _e(eng["authorized_by"]) if eng["authorized_by"] else "<span class='muted'>Not recorded</span>"),
        ("Recorded at", _e(_when(eng["authorized_at"])) or "<span class='muted'>Not recorded</span>"),
        ("Policy or statement of work", f"<code>{_e(eng['policy_url'])}</code>" if eng["policy_url"] else "<span class='muted'>Not recorded</span>"),
        ("In scope (rules)", _list(eng["scope"]["include"], "None defined")),
        ("Out of scope (rules)", _list(eng["scope"]["exclude"], "None")),
        ("Rate limit", f"{_e(eng['rate_limit_rps'])} requests per second"),
        ("Identification header", f"<code>{_e(ident['header'])}</code>" if ident["header"] else "<span class='muted'>Not set</span>"),
        ("User agent", f"<code>{_e(ident['user_agent'])}</code>" if ident["user_agent"] else "<span class='muted'>Not set</span>"),
    ]
    if "separation_of_duties" in eng:
        rows.append(("Separation of duties", "On: whoever attached a lane’s evidence cannot sign its receipt"
                     if eng["separation_of_duties"] else "Off"))
        rows.append(("Signatures required", "Yes: a receipt needs a signature from the reviewer’s key"
                     if eng["require_signatures"] else "No: a receipt may carry a name only"))
    if "redact_evidence" in eng:
        rows.append(("Evidence redaction", "On: credentials, and email addresses and card numbers in captured responses "
                     "and files, are replaced by a hash marker before raw evidence is stored; each entry "
                     "says what was redacted"
                     if eng["redact_evidence"] else "Off: raw evidence is stored as captured"))
    if out_hosts:
        rows.append(("Hosts recorded as out of scope", _list(out_hosts, "")))
    return f"""<section id="scope"><h2>Scope and authorization</h2>
{_dl(rows)}
<p class="note">The authorization entry is the tester’s own statement that they were permitted to test, with the policy
or statement of work it refers to. Recon and agent runs only reach hosts that match these rules, at this rate.</p>
</section>"""


def _coverage(r: dict, hosts: list) -> str:
    pack_lanes = r["engagement"]["pack"].get("lanes") or []
    order = [(l["key"], l["name"]) for l in pack_lanes]
    for l in r["lanes"]:
        if l["role"] not in {k for k, _ in order}:
            order.append((l["role"], l["name"]))
    status = {(l["host"], l["role"]): l["status"] for l in r["lanes"]}
    out = ["""<section id="coverage" class="pb"><h2>Coverage matrix</h2>
<p>Each in-scope host against each lane of the methodology pack.</p>
<div class="legend"><span><span class='st st-closed'>Receipted</span> every item resolved, reviewed and closed</span>
<span><span class='st st-stale'>Void</span> receipted, then the ledger changed</span>
<span><span class='st st-open'>In progress</span> opened, not closed</span>
<span><span class='st st-none'>Not opened</span> not tested</span></div>"""]
    if not hosts:
        out.append("<p class='muted'>No in-scope hosts.</p>")
    tables = -(-len(hosts) // _MATRIX_HOSTS)
    for n in range(tables):
        chunk = hosts[n * len(hosts) // tables:(n + 1) * len(hosts) // tables]
        rows = [f"<tr><td>{_e(name)}</td>" + "".join(f"<td>{_status(status.get((h, key)))}</td>" for h in chunk) + "</tr>"
                for key, name in order]
        foot = "<tfoot><tr><td>Receipted</td>" + "".join(
            f"<td>{sum(1 for k, _ in order if status.get((h, k)) == 'closed')} of {len(order)}</td>" for h in chunk) + "</tr></tfoot>"
        head = "".join(f"<th><code>{_e(h)}</code></th>" for h in chunk)
        out.append(f"<div class='tw keep'><table class='matrix'><thead><tr><th>Lane</th>{head}</tr></thead>"
                   f"<tbody>{''.join(rows)}</tbody>{foot}</table></div>")
    out.append("</section>")
    return "".join(out)


def _receipts(r: dict) -> str:
    with_rc = [l for l in r["lanes"] if l["receipt"]]
    out = ["""<section id="receipts" class="pb"><h2>Receipts</h2>
<p>A receipt is the SHA-256 of the lane’s manifest: its items, their states and reasons, and the hashes of its evidence.
A person issues it when they close the lane. A signature ties it to the reviewer’s key; a timestamp from an independent
authority shows it existed at that time.</p>"""]
    if not with_rc:
        out.append("<p class='muted'>No lane has a receipt yet.</p></section>")
        return "".join(out)
    rows = []
    registered = {e["key_fingerprint"]: e for e in reversed((r.get("key_log") or {}).get("entries", []))
                  if e["event"] == "registered"}
    revoked = {e["key_fingerprint"]: e for e in (r.get("key_log") or {}).get("entries", []) if e["event"] == "revoked"}
    for l in with_rc:
        rc = l["receipt"]
        sig, ts = rc.get("signature"), rc.get("timestamp")
        lane = f"<strong>{_e(l['name'])}</strong><br><code>{_e(l['host'])}</code><br>{_status(l['status'])}"
        if l["status"] == "stale":
            lane += "<br><span class='small'>The ledger changed after this receipt was issued.</span>"
        email = rc.get("closed_by_email") or _payload_email(sig)
        signer = _e(rc.get("closed_by") or "") + (f"<br><span class='small'>{_e(email)}</span>" if email else "") + (
            "<br>Signed with a key" if sig
                                                  else "<br><span class='muted'>Name only, not signed</span>")
        stamp = (f"Timestamped <span class='nw'>{_e(_when(ts.get('time')))}</span> by {_e(_host_of(ts.get('tsa')))}" if ts
                 else "<span class='muted'>Not timestamped; the issue time is the server’s clock</span>")
        hashes = f"Manifest SHA-256 <code>{_e(rc['manifest_sha256'])}</code>"
        if sig:
            hashes += f"<br>{_e(sig['algorithm'])} key <code>{_e(sig['key_fingerprint'])}</code>"
            reg, rev = registered.get(sig["key_fingerprint"]), revoked.get(sig["key_fingerprint"])
            if reg:
                hashes += (f", registered <span class='nw'>{_e(_when(reg['at']))}</span> "
                           f"{_e(keylog.VIA.get(reg['via'], reg['via']))}")
            if rev:
                hashes += f", revoked <span class='nw'>{_e(_when(rev['at']))}</span>"
        rows.append(f"<tbody><tr><td>{lane}</td><td data-label='Signed by'>{signer}</td>"
                    f"<td data-label='Time'>Issued <span class='nw'>{_e(_when(rc.get('issued_at')))}</span><br>{stamp}</td></tr>"
                    f"<tr class='hashes'><td colspan='3' class='small'>{hashes}</td></tr></tbody>")
    out.append(f"<div class='tw'><table class='receipts'><thead><tr><th>Lane</th><th>Signed by</th><th>Time</th></tr></thead>"
               f"{''.join(rows)}</table></div>")
    unclosed = sum(1 for l in r["lanes"] if not l["receipt"])
    if unclosed:
        out.append(f"<p class='note'>{plural(unclosed, 'opened lane has', 'opened lanes have')} no receipt yet.</p>")
    out.append("</section>")
    return "".join(out)


def _payload_email(sig: dict | None) -> str | None:
    """The signer's email inside a v3 payload."""
    try:
        return (json.loads(sig["payload"]).get("signer") or {}).get("email") if sig else None
    except (ValueError, TypeError, KeyError, AttributeError):
        return None


def _history(r: dict) -> str:
    log = r.get("audit_log")
    if log is None:
        return ""
    rows = []
    for e in log.get("entries", []):
        rows.append(f"<tr><td class='nw'>{_e(_when(e['at']))}</td><td>{_e(auditlog.actor_label(e['actor']))}</td>"
                    f"<td>{_e(auditlog.describe(e))}</td></tr>")
    people = sum(1 for e in log.get("entries", []) if str(e.get("action", "")).startswith("person."))
    return f"""<section id="history" class="pb"><h2>Change history</h2>
<p>Every change to this engagement’s scope and rules, settings, roles and authorization, and to the accounts of the people
who work on it or signed its receipts, from the server’s audit log. Each entry is hash-chained to the one before it, like the
evidence; the verifier checks the links and uses them to say, for each receipt, which scope was in force and whether its
signer held the reviewer role when it was issued.</p>
{_table(["Time", "By", "Change"], rows, "history") if rows else "<p class='muted'>No changes were recorded.</p>"}
<p class="note">{plural(len(rows) - people, 'engagement entry', 'engagement entries')} and
{plural(people, 'person entry', 'person entries')}. Entries made by “recorded when the audit log was added” are the state
at that time; who set it before then is not known. Passwords are never recorded, only that one was set.</p>
</section>"""


def _verify(r: dict) -> str:
    tsas = sorted({_host_of(l["receipt"]["timestamp"].get("tsa")) for l in r["lanes"]
                   if l["receipt"] and l["receipt"].get("timestamp")})
    file, name, fp = _DIGICERT_ROOT
    others = [t for t in tsas if not t.endswith("digicert.com")]
    other_note = (f"<p>This report also has timestamps from {_e(', '.join(others))}. The verifier fails those until you "
                  "pass that authority’s root certificate with <code>--tsa-root</code>; obtain it from the authority and "
                  "check its fingerprint first.</p>") if others else ""
    checks = [
        ("Report body hash", "The report has not been edited since it was generated: its SHA-256 matches the recorded value."),
        ("Evidence chain", "Every evidence entry links to the one before it, from the genesis value to the chain head. "
                           "No entry was removed, reordered or changed."),
        ("Lane receipts", "For every receipted lane, a manifest rebuilt from the report’s own items and evidence has the "
                          "receipt’s hash, every item marked done has evidence, and every not-applicable item has a reason."),
        ("Receipt signatures", "Each signed receipt verifies with the public key in the report, the key matches its "
                               "fingerprint, and the signed text names this lane, this manifest and a chain head in the report. "
                               "SKIP when no receipt is signed."),
        ("Signing key history", "Each signing key’s entries in the key log hash correctly and link into the log in order, "
                                "and the key was registered to the signer before the receipt was issued and not revoked "
                                "before it. Shown only when the report has signed receipts."),
        ("Change history", "The audit log entries in the report hash correctly and link into the log in order. For each "
                           "receipt, the signer held the reviewer role on this engagement (or was an owner) and had the "
                           "name in the receipt when it was issued; NOTE lines give the scope in force then. Shown only "
                           "when the report carries the audit log."),
        ("Receipt timestamps", "Each timestamp token covers this receipt’s manifest hash and signature, the authority’s "
                               "signature verifies, and its certificate chain reaches a root you trust. SKIP when no receipt "
                               "is timestamped."),
    ]
    return f"""<section id="verify" class="pb"><h2>How to verify</h2>
<p>Anyone can check this report without AttackLedger, the tester’s server or a network connection. The verifier is one
file, <code>tools/verify_report.py</code> in the AttackLedger repository, and needs only Python 3 and its standard library.</p>
<h3>1. Get the files</h3>
<p>Save this report as JSON (or keep this HTML file: it embeds the same report). Copy <code>verify_report.py</code> and the
<code>tools/tsa-roots/</code> folder from the repository into one folder, keeping the folder name <code>tsa-roots</code>.</p>
<h3>2. Run the verifier</h3>
<pre>python3 verify_report.py report.json --tsa-root &lt;root.pem&gt;</pre>
<p>For example, with the DigiCert root from the repository, or with this HTML file:</p>
<pre>python3 verify_report.py report.json --tsa-root tsa-roots/{_e(file)}
python3 verify_report.py report.html</pre>
<p class="note">Roots in <code>tsa-roots/</code> next to the script are trusted without <code>--tsa-root</code>; pass it for
any other authority. Running <code>python3 -I</code> keeps Python from loading modules from the current folder.</p>
<h3>3. Read the result</h3>
<p>Each check prints <code>PASS</code> or <code>FAIL</code>, or <code>SKIP</code> when there was nothing for it to check,
such as signatures in a report whose receipts carry only a name. A skipped check neither passes nor fails. The last line
says <code>Verified.</code> and the exit code is 0 only if no check failed. Add <code>--require-signatures</code> to fail
any receipt that is not signed. <code>NOTE</code> lines are information, such as who signed and which receipts are not
timestamped.</p>
{_table(["Check", "What it means"], [f"<tr><td>{_e(c)}</td><td>{_e(m)}</td></tr>" for c, m in checks])}
<h3>Where the timestamp root comes from</h3>
<p><code>tools/tsa-roots/{_e(file)}</code> is {_e(name)}, the root of DigiCert’s public timestamp service
(<code>timestamp.digicert.com</code>), taken from the macOS root store and matched against DigiCert’s download. Before you
rely on it, compare its SHA-256 fingerprint with your operating system’s root store or DigiCert’s site:</p>
<pre>{_e(fp)}</pre>
{other_note}
<h3>Tie keys to people</h3>
<p>A valid signature proves the holder of that key signed. The key log shows when each key was registered to its signer
and how; the server never holds a private key, but whoever runs it could register a new key for someone, and that key
would appear here with its own registration. For high assurance, ask each signer for their key
fingerprint through a channel you trust and compare it with the one in <a href="#receipts">Receipts</a>. To make sure
this is the report you were sent, compare the report body SHA-256 on the cover with the value the tester gave you.</p>
</section>"""


_CONTROL_STATUS = {"evidenced": "Evidenced", "resolved": "Resolved, partly not applicable",
                   "not_applicable": "Not applicable", "partial": "Partial", "none": "No evidence"}


def _controls(r: dict) -> str:
    c = r["controls"]
    rows = []
    for x in c.get("controls", []):
        cls = {"evidenced": "ok", "not_applicable": "muted", "none": "muted"}.get(x["status"], "")
        na = x.get("not_applicable", 0)
        counts = f"{_e(x['evidenced'])} of {_e(x['required'])} with evidence" + (f"<br>{_e(na)} not applicable" if na else "")
        rows.append(f"<tr><td><strong>{_e(x['id'])}</strong><br><span class='muted'>{_e(x['text'])}</span></td>"
                    f"<td>{_e(x['framework_name'])}</td><td>{counts}</td>"
                    f"<td class='{cls}'>{_e(_CONTROL_STATUS.get(x['status'], x['status']))}</td></tr>")
    body = _table(["Control", "Framework", "Receipted items", "Status"], rows) if rows else \
        "<p class='muted'>This pack maps no items to controls.</p>"
    return f"""<section id="controls" class="pb"><h2>Control evidence</h2>
<p class="note">{_e(c.get('disclaimer', ''))}</p>{body}</section>"""


def _items(r: dict) -> str:
    in_scope = {h["host"] for h in r["hosts"] if h["in_scope"]}
    ev_by_id = {e["id"]: e for e in r["evidence"]}
    out = ["<section id='items' class='pb'><h2>Item detail</h2>"]
    if not r["lanes"]:
        out.append("<p class='muted'>No lanes were opened.</p>")
    for l in r["lanes"]:
        scope_note = "" if l["host"] in in_scope else " <span class='muted'>(host out of scope)</span>"
        out.append(f"<h3>{_e(l['host'])} · {_e(l['name'])}{scope_note} {_status(l['status'])}</h3>")
        rows = []
        for i in l["items"]:
            evs = [ev_by_id[x] for x in l["evidence_ids"] if ev_by_id[x]["item_id"] == i["item_id"]]
            result = _ITEM.get(i["state"], i["state"])
            if i["state"] == "na":
                result = f"{_e(result)}: {_e(i['na_reason'])}"
            else:
                result = _e(result)
            ev_html = "<br>".join(
                f"#{_e(e['seq'])} {_e(_evidence_label(e))}: {_e(e['summary'])} <code>{_e(e['sha256'][:12])}</code>"
                + (f"<br><span class='muted small'>{_e(e['uri'])}</span>" if e.get("uri") else "") for e in evs)
            rows.append(f"<tr><td><span class='muted'>{_e(i['key'])}</span><br>{_e(i['text'])}</td>"
                        f"<td>{result}</td><td>{ev_html or '<span class=muted>none</span>'}</td></tr>")
        out.append(_table(["Item", "Result", "Evidence"], rows))
    out.append("</section>")
    return "".join(out)


def _recon(r: dict) -> str:
    title = lambda kind: (modules.get(kind).title if modules.get(kind) else "Claude agent" if kind == "agent" else kind)  # noqa: E731
    rows = [f"<tr><td>#{_e(j['id'])} {_e(title(j['kind']))}</td><td>{_e(_JOB.get(j['status'], j['status']))}</td><td>{_e(j['targets'])}</td>"
            f"<td>{_e(j['result_count'])}</td><td>{_e(_when(j['started_at']))}<br>{_e(_when(j['finished_at']))}</td>"
            f"<td><code>{_e(j['output_sha256'] or '')}</code></td></tr>" for j in r["jobs"]]
    return ("<section id='recon'><h2>Recon runs</h2>"
            + _table(["Run", "Status", "Targets", "Results", "Started, finished", "Output SHA-256"], rows) + "</section>")


def _json_for_html(r: dict) -> str:
    # Escape "<" so no evidence text can close the script element.
    return json.dumps(r, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
