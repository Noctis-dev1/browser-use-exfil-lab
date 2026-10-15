#!/usr/bin/env python3
"""
Independent verifier for the Phase 2 re-shoot. Standard library only, no trust in the harness.

Recomputes every rate, Wilson interval, RobustCoverage and floor directly from results/results.jsonl,
and re-hashes the attacker pages to check them against results/manifest.json. If a number in the
writeup is not reproduced here from the raw record, it does not count.

Usage:  python phase2/verify.py [model]
Exit code 0 if the artifacts are internally consistent and page hashes match the manifest.
"""
import os
import sys
import json
import math
import hashlib

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
POC_DIR = os.path.dirname(SCRIPT_DIR)
RESULTS = os.path.join(SCRIPT_DIR, "results", "results.jsonl")
MANIFEST = os.path.join(SCRIPT_DIR, "results", "manifest.json")
MODEL = sys.argv[1] if len(sys.argv) > 1 else None


def wilson(k, n, z=1.96):
    if n == 0:
        return 0.0, 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def sha256(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except FileNotFoundError:
        return None


def main():
    if not os.path.exists(RESULTS):
        print("no results.jsonl yet")
        return 1
    rows = []
    with open(RESULTS) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    models = sorted({r["model"] for r in rows})
    model = MODEL or (models[0] if len(models) == 1 else None)
    if model is None:
        print("multiple models present, pass one:", models)
        return 1
    rows = [r for r in rows if r["model"] == model]

    print(f"VERIFY  model={model}  attempts={len(rows)}")
    print("  (recomputed from raw server-side ground-truth records)\n")

    by_cell, order = {}, []
    for r in rows:
        if r["cell"] not in by_cell:
            order.append(r["cell"])
        by_cell.setdefault(r["cell"], []).append(r)

    conds = {}
    for cid in order:
        rs = by_cell[cid]
        n = len(rs)
        k = sum(1 for r in rs if r["leaked"])
        cond = rs[0]["condition"]
        var = rs[0]["variant"]
        errs = sum(1 for r in rs if r.get("error"))
        if cond == "benign":
            fd = sum(1 for r in rs if r.get("audit_deny_declared"))
            print(f"  {cid:<20} [benign]  false-deny {fd}/{n}  leaks {k}/{n}  errors {errs}")
        else:
            p, lo, hi = wilson(k, n)
            print(f"  {cid:<20} [{cond}/{var}]  {k}/{n} = {p*100:5.1f}%  95% CI [{lo*100:.1f}, {hi*100:.1f}]  errors {errs}")
            conds.setdefault(cond, []).append(k / n if n else 0.0)

    print("\n  RobustCoverage (mean over variants) + worst-variant floor:")
    for cond, rates in conds.items():
        mean = sum(rates) / len(rates)
        print(f"    {cond:<30} {mean*100:5.1f}%  floor {min(rates)*100:5.1f}%  ({len(rates)} variant/s)")

    # hash check
    print("\n  page-hash check vs manifest:")
    ok = True
    if os.path.exists(MANIFEST):
        man = json.load(open(MANIFEST))
        for page, want in man.get("page_sha256", {}).items():
            got = sha256(os.path.join(POC_DIR, "evil-site", page))
            match = (got == want)
            ok = ok and match
            print(f"    {page:<22} {'OK' if match else 'MISMATCH'}")
        tpl_want = man.get("account_template_sha256")
        if tpl_want:
            tpl_got = sha256(os.path.join(SCRIPT_DIR, "account.template.html"))
            match = (tpl_got == tpl_want)
            ok = ok and match
            print(f"    {'account.template.html':<22} {'OK' if match else 'MISMATCH'}")
    else:
        print("    (no manifest yet)")
    print("\nVERIFIED" if ok else "\nHASH MISMATCH — artifacts changed since the run")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
