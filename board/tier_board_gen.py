#!/usr/bin/env python3
"""Tier Board generator -- TIER_BOARD_TEMPLATE.html + program config -> publishable board.

Usage:  python3 board/tier_board_gen.py <config.json> <output.html>

The same template is used for every program. The page expects a `db` + `user`
runtime capability (a small key-value store); status marks (deep/probe/revisit)
are kept in the `hosts` collection.

config.json schema:
{
  "title","h1","sub","hdrmeta",
  "funnel":[{"n","lab","why"}],            # 3-5 steps, each says WHY rows dropped
  "warns":[{"title","body","oos":[...]}],  # if oos is given it renders as struck-through chips
  "gaps":[{"dt","tag","dd","fail":bool}],  # counted gaps, not guesses
  "tiers":[{"k","name","color","why"}],
  "packs":[{"k","name","color","auth","why"}],
  "short":{"KEY":"short name"},
  "rows":[{"t","p","h","c","s","g","b","k","w","r","n","cp","sz","loc"}]
}
"""
import json, os, sys, html

def esc(x): return html.escape(str(x or ""), quote=True)

def funnel(steps):
    out = ['<div class="funnel">']
    for st in steps:
        out.append('    <div class="fstep">')
        out.append(f'      <div class="fnum">{esc(st["n"])}</div>')
        out.append(f'      <div class="flab">{esc(st["lab"])}</div>')
        out.append(f'      <div class="fwhy">{st["why"]}</div>')
        out.append('    </div>')
    out.append('  </div>')
    return "\n".join(out)

def warns(ws):
    out = []
    for w in ws:
        style = f' style="border-color:{w["color"]}"' if w.get("color") else ""
        hstyle = f' style="color:{w["color"]}"' if w.get("color") else ""
        out.append(f'<div class="warn"{style}>')
        out.append(f'    <h3{hstyle}>{w["title"]}</h3>')
        out.append(f'    <p>{w["body"]}</p>')
        if w.get("oos"):
            chips = "".join(f'<code>{esc(h)}</code>' for h in w["oos"])
            out.append(f'    <div class="oos">{chips}</div>')
        out.append('  </div>')
    return "\n\n  ".join(out)

def gaps(gs, intro):
    out = ['<div class="gaps">', '    <h2>What this board does not cover</h2>',
           f'    <p>{intro}</p>', '    <dl class="glist">']
    for g in gs:
        cls = ' class="g fail"' if g.get("fail") else ' class="g"'
        out.append(f'      <div{cls}>')
        tag = f' <span>{esc(g["tag"])}</span>' if g.get("tag") else ""
        out.append(f'        <dt>{esc(g["dt"])}{tag}</dt>')
        out.append(f'        <dd>{g["dd"]}</dd>')
        out.append('      </div>')
    out += ['    </dl>', '  </div>']
    return "\n".join(out)

def main():
    cfg = json.load(open(sys.argv[1], encoding="utf-8"))
    tpl = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "TIER_BOARD_TEMPLATE.html"), encoding="utf-8").read()

    rows = cfg["rows"]
    kept = [r for r in rows if r.get("w", 1) == 1]

    packs = [[p["k"], p["name"], p.get("color","var(--t5)"), p.get("auth",""), p["why"]]
             for p in cfg["packs"]]
    tiers = [[t["k"], t["name"], t.get("color","var(--t5)"), t["why"]] for t in cfg["tiers"]]

    rep = {
        "__TITLE__":   esc(cfg["title"]),
        "__H1__":      cfg["h1"],
        "__SUB__":     cfg["sub"],
        "__HDRMETA__": cfg["hdrmeta"],
        "__FUNNEL__":  funnel(cfg["funnel"]),
        "__WARNS__":   warns(cfg["warns"]),
        "__NTOTAL__":  str(len(kept)),
        "__GAPS__":    gaps(cfg["gaps"], cfg.get("gaps_intro","")),
        "__ROWS__":    json.dumps(rows, ensure_ascii=False, separators=(",",":")),
        "__PACKS__":   json.dumps(packs, ensure_ascii=False),
        "__TIERS__":   json.dumps(tiers, ensure_ascii=False),
        "__SHORT__":   json.dumps(cfg["short"], ensure_ascii=False),
    }
    for k, v in rep.items():
        if k not in tpl: sys.exit(f"ERROR: template has no {k}")
        tpl = tpl.replace(k, v)
    for leftover in ("__ROWS__","__PACKS__","__TIERS__","__TITLE__"):
        assert leftover not in tpl
    open(sys.argv[2], "w", encoding="utf-8").write(tpl)
    print(f"board written: {sys.argv[2]}  {len(tpl)} bytes")
    print(f"  {len(rows)} rows ({len(kept)} kept / {len(rows)-len(kept)} dropped)"
          f" | {len(tiers)} tiers | {len(packs)} packs | {len(cfg['gaps'])} gaps")

if __name__ == "__main__":
    main()
