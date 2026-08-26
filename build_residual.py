#!/usr/bin/env python3
"""build_residual.py - Builds the RESIDUAL set and writes it to a separate file.

Residual = the ICS hosts in pop_all.json that NEITHER Censys NOR the paper
(Mladenov et al.) could label as honeypots. The next step performs deeper
(novel indicator) analysis over this set.

Elimination criteria (IDENTICAL to indicators.py::main):
  0) NO ICS label            -> drop (not an ICS host)
  1) Censys 'HONEYPOT' label  -> drop (Censys already caught it)
  2) Paper method detects it  -> drop (paper_original_port.classify_record HIGH/MEDIUM)
  => the remainder = RESIDUAL

Output (SAME envelope format as pop_all.json; read by the same loader):
  residual.json = {"result":{"total_hits":Nr,"hits":[{"host_v1":{"resource":r}}...]}}

Usage:  py build_residual.py [--file pop_all.json] [--out residual.json]
"""
import json
import os
import sys

from indicators import host_labels
from paper_original_port import classify_record, is_detected_honeypot

HERE = os.path.dirname(os.path.abspath(__file__))


def arg(name, default):
    if name in sys.argv:
        return sys.argv[sys.argv.index(name) + 1]
    return default


def main():
    src = os.path.join(HERE, arg("--file", "pop_all.json"))
    out = os.path.join(HERE, arg("--out", "residual.json"))
    if not os.path.exists(src):
        sys.exit(f"ERROR: {src} is missing.")

    print(f"Loading: {src}")
    with open(src, encoding="utf-8") as f:
        d = json.load(f)

    raw = []
    for h in d["result"]["hits"]:
        rr = h.get("host_v1", {}).get("resource") if "host_v1" in h else h
        if rr:
            raw.append(rr)
    N0 = len(raw)

    residual = []
    n_no_ics = n_hp = n_paper = 0
    paper_total = 0          # what the faithful port catches ON ITS OWN (whole pop)
    paper_overlap_hp = 0     # of those, how many overlap with Censys HONEYPOT
    for r in raw:
        labs = host_labels(r.get("services", []))
        det = is_detected_honeypot(classify_record(r)[0])
        if det:
            paper_total += 1
        if "ICS" not in labs:
            n_no_ics += 1
            continue
        if "HONEYPOT" in labs:
            n_hp += 1
            if det:
                paper_overlap_hp += 1
            continue
        if det:
            n_paper += 1
            continue
        residual.append(r)
    Nr = len(residual)

    print("=" * 72)
    print(f"Raw population             : {N0}")
    print(f"  - no ICS label (dropped)  : {n_no_ics}")
    print(f"  - Censys HONEYPOT (dropped): {n_hp}")
    print(f"  - Paper method (dropped)   : {n_paper}   [ON TOP of Censys, incremental]")
    print(f"RESIDUAL (remaining set)     : {Nr}")
    print("-" * 72)
    print(f"Note: Paper method ON ITS OWN (whole pop) total : {paper_total}")
    print(f"      of those, overlapping with Censys HONEYPOT: {paper_overlap_hp}")
    print(f"      => incremental (only added by the paper)  : {n_paper}")
    print("=" * 72)

    payload = {
        "result": {
            "total_hits": Nr,
            "hits": [{"host_v1": {"resource": r}} for r in residual],
        }
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False)
    size_mb = os.path.getsize(out) / (1024 * 1024)
    print(f"-> {out}  ({size_mb:,.1f} MB, {Nr} hosts)")


if __name__ == "__main__":
    main()
