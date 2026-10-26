#!/usr/bin/env python3
"""Validate model outputs for the LLIoT-method experiment against their job files.

Checks per output (docs/plans/PLAN_lliot_method_comparison.md § Output schema):
  - parses as JSON {"results": [...]}
  - exactly one entry per input CVE, same IDs, no extras, no duplicates
  - enums valid: home_iot Yes/No/Maybe, confidence High/Low, categories in the 24 slugs
  - Maybe -> Low;  No -> empty categories;  Yes/Maybe -> at least one category
  - reasoning non-empty

BLINDNESS: this prints pass/fail, error *kinds* and agreement counts only. It never prints a
label, a category, or reasoning, because the person running it adjudicates these rows later.

Usage (lliot_run.py calls validate_output() directly; the CLI is for spot checks):
    python3 scripts/lliot_validate.py <job.json> <output.json>
    python3 scripts/lliot_validate.py --dir <jobs dir> <outputs dir>
    python3 scripts/lliot_validate.py --agree <outputs dir 1> <outputs dir 2>   # counts only
"""
import argparse
import csv
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SLUGS = {r["slug"] for r in csv.DictReader(open(os.path.join(ROOT, "data", "categories.csv"),
                                                 encoding="utf-8"))}
FIELDS = {"cve_id", "home_iot", "categories", "confidence", "reasoning"}


def validate_output(job_path, out_path):
    """Return a list of error strings (empty = valid). Messages name CVE IDs, never labels."""
    want = [r["cve_id"] for r in json.load(open(job_path, encoding="utf-8"))]
    if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
        return ["missing or empty output"]
    try:
        data = json.load(open(out_path, encoding="utf-8"))
    except ValueError:
        return ["output is not valid JSON"]
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return ["output lacks a results array"]
    errs = []
    got = [e.get("cve_id") if isinstance(e, dict) else None for e in data["results"]]
    if sorted(got, key=str) != sorted(want):
        missing, extra = set(want) - set(got), set(got) - set(want)
        dup = len(got) - len(set(got))
        errs.append(f"ID mismatch: {len(missing)} missing, {len(extra)} extra, {dup} duplicated")
    for e in data["results"]:
        if not isinstance(e, dict):
            errs.append("non-object entry")
            continue
        c = e.get("cve_id", "?")
        if set(e) != FIELDS:
            errs.append(f"{c}: wrong fields")
            continue
        if e["home_iot"] not in ("Yes", "No", "Maybe"):
            errs.append(f"{c}: bad home_iot value")
        if e["confidence"] not in ("High", "Low"):
            errs.append(f"{c}: bad confidence value")
        cats = e["categories"]
        if not isinstance(cats, list) or any(x not in SLUGS for x in cats):
            errs.append(f"{c}: unknown category slug")
        elif len(cats) != len(set(cats)):
            errs.append(f"{c}: duplicated category")
        if e["home_iot"] == "Maybe" and e["confidence"] != "Low":
            errs.append(f"{c}: Maybe not paired with Low")
        if e["home_iot"] == "No" and cats:
            errs.append(f"{c}: No with categories")
        if e["home_iot"] in ("Yes", "Maybe") and not cats:
            errs.append(f"{c}: Yes/Maybe without a category")
        if not str(e.get("reasoning", "")).strip():
            errs.append(f"{c}: empty reasoning")
    return errs


def load_entries(out_dir):
    """cve_id -> result entry, across every output file in a dir."""
    got = {}
    for f in sorted(os.listdir(out_dir)):
        if f.endswith(".json"):
            for e in json.load(open(os.path.join(out_dir, f), encoding="utf-8"))["results"]:
                got[e["cve_id"]] = e
    return got


def agreement(dir1, dir2):
    """Print agreement counts between two output sets on their shared CVEs. Never a label."""
    a, b = load_entries(dir1), load_entries(dir2)
    shared = sorted(set(a) & set(b))
    home = sum(a[c]["home_iot"] == b[c]["home_iot"] for c in shared)
    both_cat = [c for c in shared if a[c]["categories"] and b[c]["categories"]]
    prim = sum(a[c]["categories"][0] == b[c]["categories"][0] for c in both_cat)
    pct = lambda k, n: f"{k}/{n} ({100 * k / n:.1f}%)" if n else "0/0"
    print(f"shared CVEs:      {len(shared)}  (only in 1: {len(set(a) - set(b))}, only in 2: {len(set(b) - set(a))})")
    print(f"home_iot agrees:  {pct(home, len(shared))}")
    print(f"primary category: {pct(prim, len(both_cat))}  (CVEs where both gave a category)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", action="store_true", help="args are a jobs dir and an outputs dir")
    ap.add_argument("--agree", action="store_true",
                    help="args are two outputs dirs; print agreement counts only")
    ap.add_argument("job")
    ap.add_argument("output")
    a = ap.parse_args()
    if a.agree:
        return agreement(a.job, a.output)
    pairs = ([(os.path.join(a.job, f), os.path.join(a.output, f))
              for f in sorted(os.listdir(a.job)) if f.endswith(".json")] if a.dir
             else [(a.job, a.output)])
    bad = 0
    for jp, op in pairs:
        errs = validate_output(jp, op)
        if errs:
            bad += 1
            print(f"FAIL {os.path.basename(op)}: " + "; ".join(errs[:5]))
    print(f"{len(pairs) - bad}/{len(pairs)} valid")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
