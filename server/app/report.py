"""Audit report: a self-describing, verifiable snapshot of an engagement.

The JSON bundle carries everything needed to re-check it offline:
  - each lane's receipt can be recomputed from its items and evidence,
  - the evidence hash chain can be walked from the genesis value,
  - the bundle hash covers the whole body,
  - (format 2) signed receipts carry their payload, signature and public key, and
    timestamped receipts their RFC 3161 token.
tools/verify_report.py checks all of it with the Python standard library only.
"""
import html
import json
from datetime import datetime, timezone
from urllib.parse import urlsplit

from sqlalchemy import select

from . import gates, ledger, packs
from .models import Engagement, Evidence, iso_utc

REPORT_FORMAT = "attackledger-report/2"   # 2: receipts may carry a signature


def _receipt(rc) -> dict:
    out = {"manifest_sha256": rc.manifest_sha256, "closed_by": rc.closed_by, "issued_at": _iso(rc.created_at)}
    if rc.signature:
        out["signature"] = {"algorithm": rc.algorithm, "public_key": rc.public_key,
                            "key_fingerprint": rc.key_fingerprint, "payload": rc.payload, "value": rc.signature}
    if rc.timestamp_token:
        out["timestamp"] = {"tsa": rc.timestamp_tsa, "time": _iso(rc.timestamp_time), "token": rc.timestamp_token}
    return out


def _signed_by(rc: dict | None) -> str:
    """The signer, and what backs the name: a key and a timestamp, or nothing."""
    if not rc:
        return ""
    out = _e(rc.get("closed_by") or "")
    sig, ts = rc.get("signature"), rc.get("timestamp")
    out += (f"<br><span class='muted'>{_e(sig['algorithm'])} key <code>{_e(sig['key_fingerprint'][:16])}</code></span>"
            if sig else "<br><span class='muted'>name only, not signed</span>")
    if ts:
        host = urlsplit(ts.get("tsa") or "").hostname or ts.get("tsa") or ""
        out += f"<br><span class='muted'>timestamped {_e((ts.get('time') or '')[:19].replace('T', ' '))} UTC by {_e(host)}</span>"
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
            "pack": {"id": pack.id, "name": pack.name, "version": pack.version},
            "policy_url": eng.policy_url,
            "authorized_by": eng.authorized_by, "authorized_at": _iso(eng.authorized_at),
            "scope": {"include": eng.scope_include, "exclude": eng.scope_exclude},
            "research_identification": {"header": eng.research_header,
                                        "user_agent": eng.research_user_agent},
            "rate_limit_rps": eng.rate_limit_rps,
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
    return {**body, "integrity": {"algorithm": "sha256", "body_sha256": ledger.sha256(ledger.canonical(body)),
                                  "chain_genesis": ledger.GENESIS}}


# ---- HTML ---------------------------------------------------------------------

def _e(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


_STATUS = {"closed": "Receipted", "stale": "Void", "open": "Open"}
_TYPES = {"bug_bounty": "Bug bounty", "pentest": "Penetration test", "internal": "Internal assessment"}


def _n(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"

_CSS = """
:root{--paper:#f6f9f1;--rule:#c9d8bf;--text:#2b2f2a;--soft:#5d6559;--ink:#1f3a93;--red:#b8322a;--stamp:#2e7d4f}
*{box-sizing:border-box}body{margin:0;background:#fff;color:var(--text);font:15px/1.5 "Atkinson Hyperlegible","Segoe UI",system-ui,sans-serif;font-variant-numeric:tabular-nums}
main{max-width:58rem;margin:0 auto;padding:2.5rem 1.5rem 4rem}
h1,h2,h3{font-family:"Zilla Slab",Rockwell,Georgia,serif;line-height:1.15}h1{font-size:2rem;margin:0}h2{font-size:1.4rem;margin:2.25rem 0 .6rem;padding-top:.6rem;border-top:3px double var(--rule)}h3{font-size:1.05rem;margin:1.25rem 0 .3rem}
.sub{color:var(--soft);margin:.25rem 0 0}.meta{display:grid;grid-template-columns:12rem 1fr;gap:.25rem 1rem;margin:1rem 0 0}.meta dt{color:var(--soft)}.meta dd{margin:0}
table{width:100%;border-collapse:collapse;font-size:13px;margin:.4rem 0}th,td{text-align:left;padding:.35rem .5rem;border-bottom:1px solid var(--rule);vertical-align:top}thead th{border-bottom:2px solid var(--soft);font-weight:700}
code{font:12px ui-monospace,Menlo,monospace;word-break:break-all}.ok{color:var(--stamp);font-weight:700}.bad{color:var(--red);font-weight:700}.muted{color:var(--soft)}
.stamp{display:inline-block;border:3px double var(--stamp);color:var(--stamp);padding:.15rem .5rem;transform:rotate(-4deg);font:700 .8rem "Zilla Slab",Georgia,serif;letter-spacing:.12em}
.integrity{background:var(--paper);border-left:4px double var(--red);padding:.8rem 1rem;margin-top:1rem}
.note{font-size:13px;color:var(--soft)}
.warn{margin:1rem 0 0;padding:.6rem .8rem;border-left:4px solid var(--red);background:#f7e9e4;color:var(--red);font-weight:700}
@media print{main{padding:0}h2{break-after:avoid}tr{break-inside:avoid}a{color:inherit}}
"""


def render_html(r: dict) -> str:
    eng, s = r["engagement"], r["summary"]
    lanes_by_host: dict[str, list] = {}
    for l in r["lanes"]:
        lanes_by_host.setdefault(l["host"], []).append(l)
    ev_by_id = {e["id"]: e for e in r["evidence"]}

    parts = [f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Coverage report: {_e(eng['name'])}</title><style>{_CSS}</style></head><body><main>
<h1>Coverage report: {_e(eng['name'])}</h1>
<p class="sub">{_e(eng['pack']['name'])} methodology, version {_e(eng['pack']['version'])}. Generated {_e(r['generated_at'])}.</p>
{'' if eng['authorized_at'] else '<p class="warn">No authorization was recorded for this engagement. The tests below are not backed by a recorded permission to test.</p>'}
<dl class="meta">
<dt>Engagement type</dt><dd>{_e(_TYPES.get(eng['type'], eng['type']))}</dd>
<dt>Authorized by</dt><dd>{_e(eng['authorized_by'] or 'Not recorded')} {('on ' + _e(eng['authorized_at'])) if eng['authorized_at'] else ''}</dd>
<dt>Program policy</dt><dd>{_e(eng['policy_url'] or 'Not recorded')}</dd>
<dt>In scope</dt><dd>{_e(', '.join(eng['scope']['include']) or 'None defined')}</dd>
<dt>Out of scope</dt><dd>{_e(', '.join(eng['scope']['exclude']) or 'None')}</dd>
<dt>Research identification</dt><dd>{_e(' · '.join(x for x in (eng['research_identification']['header'], eng['research_identification']['user_agent']) if x) or 'Not set')}</dd>
</dl>

<h2>Coverage statement</h2>
<p>Of {_n(s['lanes_possible'], 'possible lane', 'possible lanes')} ({_n(s['hosts_in_scope'], 'in-scope host', 'in-scope hosts')} × {s['lanes_per_host']} lanes),
{s['lanes_opened']} {'was' if s['lanes_opened'] == 1 else 'were'} opened and <strong>{s['lanes_receipted']} {'is' if s['lanes_receipted'] == 1 else 'are'} receipted</strong>: every checklist item has evidence
or a written reason, the receipt matches the ledger, and a person reviewed and signed it.
{'No receipts are void.' if not s['lanes_stale'] else _n(s['lanes_stale'], 'receipt is', 'receipts are') + ' void because the ledger changed after issue.'}
Lanes that were not opened were not tested.</p>
"""]

    parts.append("<h2>Lanes by host</h2>")
    for h in r["hosts"]:
        if not h["in_scope"]:
            continue
        parts.append(f"<h3>{_e(h['host'])}</h3>")
        hl = lanes_by_host.get(h["host"], [])
        if not hl:
            parts.append('<p class="muted">No lanes opened.</p>')
            continue
        parts.append("<table><thead><tr><th>Lane</th><th>Status</th><th>Items</th><th>Receipt</th><th>Signed by</th></tr></thead><tbody>")
        for l in hl:
            done = sum(1 for i in l["items"] if i["state"] == "done")
            na = sum(1 for i in l["items"] if i["state"] == "na")
            cls = "ok" if l["status"] == "closed" else "bad"
            rc = f"<code>{_e(l['receipt']['manifest_sha256'][:16])}</code>" if l["receipt"] else '<span class="muted">none</span>'
            parts.append(f"<tr><td>{_e(l['name'])}</td><td class='{cls}'>{_STATUS[l['status']]}</td>"
                         f"<td>{done} with evidence, {na} not applicable, {len(l['items']) - done - na} open</td><td>{rc}</td>"
                         f"<td>{_signed_by(l['receipt'])}</td></tr>")
        parts.append("</tbody></table>")

    parts.append("<h2>Control evidence</h2>")
    parts.append(f"<p class='note'>{_e(r['controls'].get('disclaimer', ''))}</p>")
    parts.append("<table><thead><tr><th>Control</th><th>Framework</th><th>Receipted items</th><th>Status</th></tr></thead><tbody>")
    for c in r["controls"].get("controls", []):
        cls = {"evidenced": "ok", "partial": "", "none": "muted"}[c["status"]]
        parts.append(f"<tr><td><strong>{_e(c['id'])}</strong><br><span class='muted'>{_e(c['text'])}</span></td>"
                     f"<td>{_e(c['framework_name'])}</td><td>{c['evidenced']}/{c['required']}</td>"
                     f"<td class='{cls}'>{_e(c['status'].capitalize())}</td></tr>")
    parts.append("</tbody></table>")

    parts.append("<h2>Item detail</h2>")
    for l in r["lanes"]:
        parts.append(f"<h3>{_e(l['host'])} · {_e(l['name'])}</h3><table><thead><tr><th>Item</th><th>Result</th><th>Evidence</th></tr></thead><tbody>")
        for i in l["items"]:
            evs = [ev_by_id[x] for x in l["evidence_ids"] if ev_by_id[x]["item_id"] == i["item_id"]]
            result = {"done": "Evidence recorded", "na": f"Not applicable: {i['na_reason']}", "open": "Open"}[i["state"]]
            ev_html = "<br>".join(f"#{e['seq']} {_e(e['kind'])}: {_e(e['summary'])} <code>{_e(e['sha256'][:12])}</code>" for e in evs)
            parts.append(f"<tr><td><span class='muted'>{_e(i['key'])}</span><br>{_e(i['text'])}</td>"
                         f"<td>{_e(result)}</td><td>{ev_html or '<span class=muted>none</span>'}</td></tr>")
        parts.append("</tbody></table>")

    if r["jobs"]:
        parts.append("<h2>Recon runs</h2><table><thead><tr><th>Run</th><th>Status</th><th>Targets</th><th>Results</th><th>Output SHA-256</th></tr></thead><tbody>")
        for j in r["jobs"]:
            parts.append(f"<tr><td>#{j['id']} {_e(j['kind'])}</td><td>{_e(j['status'])}</td><td>{j['targets']}</td>"
                         f"<td>{j['result_count']}</td><td><code>{_e(j['output_sha256'] or '')}</code></td></tr>")
        parts.append("</tbody></table>")

    integ = r["integrity"]
    parts.append(f"""<h2>Integrity</h2>
<div class="integrity">
<p><span class="stamp">LEDGER</span> {s['evidence_entries']} evidence entries, chain head <code>{_e(s['chain_head'])}</code></p>
<p>Report body SHA-256 <code>{_e(integ['body_sha256'])}</code></p>
<p class="note">To verify: <code>python3 tools/verify_report.py this-file.html</code>. The verifier recomputes every receipt
from its items and evidence, walks the evidence chain from the genesis value, and recomputes the body hash. It needs only the Python standard library.</p>
</div>
<script type="application/json" id="attackledger-report">{_json_for_html(r)}</script>
</main></body></html>""")
    return "".join(parts)


def _json_for_html(r: dict) -> str:
    # Escape "<" so no evidence text can close the script element.
    return json.dumps(r, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
