#!/usr/bin/env python3
"""Which in-reach ground-truth items an agent can see in its lane context (docs/BENCHMARK.md).

  python3 tools/benchmark/agent_context.py CONTEXT.json [--first 50] [--views DIR [--raw-views]]

CONTEXT.json is GET /lanes/{id}/context for the Juice Shop recon lane. The agent's first
message carries the endpoints, client routes (spa_routes, when present) and leads in it;
--first N keeps only the first N endpoints (what an agent run got before ranking, when the
context route had no limit). --views DIR adds what the model is shown of response bodies saved
in DIR (DIR/views.json maps each file name to {"url", "content_type"}): the reading view, or
with --raw-views the first 4,000 characters as received (the view before this change).
The same matchers as run.py score are applied: endpoint rules to the URLs, lead rules to the
leads and the views, "any" rules to both. Prints JSON.
"""
import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "server"))


def visible(ctx: dict, first: int | None) -> tuple[list[str], list[dict]]:
    recon = ctx["recon"]
    eps = [e["url"] for e in recon["endpoints"]][:first] if first else [e["url"] for e in recon["endpoints"]]
    eps += recon.get("spa_routes") or []
    return eps, recon["leads"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("context")
    ap.add_argument("--first", type=int)
    ap.add_argument("--views", help="directory of saved bodies: <name> files with a views.json index")
    ap.add_argument("--raw-views", action="store_true", help="show the raw first 4,000 characters instead")
    a = ap.parse_args()
    gt = json.loads((HERE / "ground_truth.json").read_text())
    ctx = json.loads(Path(a.context).read_text())
    urls, leads = visible(ctx, a.first)
    ep_text = "\n".join(urls)
    text = "\n".join(f"{l['title']} {l['source_url']} {json.dumps(l['detail'])}" for l in leads)
    if a.views:
        from app import pagetext
        index = json.loads((Path(a.views) / "views.json").read_text())
        for name, meta in index.items():
            body = (Path(a.views) / name).read_text(errors="replace")
            shown = body if a.raw_views else pagetext.view(body, meta["url"], meta["content_type"])[0]
            text += "\n" + shown[:4000]        # what the model is shown of that response
    items = {**{k: v for k, v in gt["challenges"].items() if v["in_reach"]}, **gt["surface"]}
    seen = {}
    for key, g in items.items():
        for where, rx in g.get("recon") or []:
            hay = {"endpoint": ep_text, "lead": text}.get(where, ep_text + "\n" + text)
            m = re.search(rx, hay, re.I)
            if m:
                seen[key] = m.group(0)
                break
    print(json.dumps({"endpoints_shown": len(urls), "leads_shown": len(leads), "visible": seen,
                      "visible_count": len(seen), "of": len(items)}, indent=1))


if __name__ == "__main__":
    main()
