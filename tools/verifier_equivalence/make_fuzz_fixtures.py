#!/usr/bin/env python3
"""Fixtures for what fuzzing found in the verifiers (docs/security-review/FUZZING.md, FZ-16 to
FZ-19): copies of fixtures/unsigned.json, each changed the way a minimised fuzz mutant was.
Standard library only:  python3 tools/verifier_equivalence/make_fuzz_fixtures.py"""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "fixtures"
BASE = json.loads((OUT / "unsigned.json").read_text())


def write(name: str, text: str) -> None:
    (OUT / name).write_text(text, encoding="utf-8")


def copy():
    return json.loads(json.dumps(BASE))


r = copy()                                                   # FZ-16: a key the checks read is missing
del r["summary"]
write("fuzz-key-missing.json", json.dumps(r))
r = copy()                                                   # FZ-16: a value of another type
r["lanes"] = {"0": r["lanes"][0]}
write("fuzz-wrong-type.json", json.dumps(r))
r = copy()                                                   # FZ-19: an item without its text (was a traceback)
del r["lanes"][0]["items"][0]["text"]
write("fuzz-item-without-text.json", json.dumps(r))
text = json.dumps(copy())                                    # FZ-17: nested past the limit, and just under it
write("fuzz-nested-too-deep.json", text[:-1] + ', "x": ' + "[" * 501 + "]" * 501 + "}")
write("fuzz-nested-500.json", text[:-1] + ', "x": ' + "[" * 499 + "]" * 499 + "}")
r = copy()                                                   # FZ-18: a lone surrogate in printed text
r["engagement"]["name"] = "lab \ud800 name"
write("fuzz-lone-surrogate.json", json.dumps(r))
(OUT / "fuzz-not-utf8.json").write_bytes(json.dumps(copy()).encode()[:-2] + b'\xff"}')   # FZ-16
write("fuzz-not-json.json", json.dumps(copy())[:-1])
