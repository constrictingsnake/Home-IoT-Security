#!/usr/bin/env python3
"""One-off bulk flag — mark judgment_store.csv rows `Excluded` (out of the analysis
population) without touching any AI/human judgment cell or Final Judgment.

This is how a scope ruling (e.g. "tvOS CVEs are out of `streaming`, 2026-07") gets applied
retroactively to already-settled rows: `Final Judgment` stays what the reviewers said (they
were right, under the scope note in force when they judged), but `Excluded` marks the row
out of the analysis population going forward. finalize_judgments.py drops non-blank-Excluded
rows from 03_final.csv/final_resolved.csv while keeping them, and their judgments, in the
store. See docs/plans/PLAN_scope_exclusion.md for the full design rationale.

Like the three discovery miners (cpe_brand_mining.py, keyword_mining.py,
cpe_product_scan.py), this is a human judgment call — NOT chained into
pipeline.py refresh/settle.

Usage:
    python3 scripts/mark_excluded.py --category streaming --cpe-vp apple:tvos \\
        --reason scope:tvos-2026-07
    python3 scripts/mark_excluded.py --category streaming --cpe-vp apple:tvos \\
        --reason scope:tvos-2026-07 --dry-run
    python3 scripts/mark_excluded.py --category streaming --cpe-vp apple:tvos --clear
    python3 scripts/mark_excluded.py --category streaming --cve-file cves.txt \\
        --reason scope:tvos-2026-07
"""
import argparse
import csv
import os
from collections import Counter

from cpe_expansion import parse_cpe

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
SNAPSHOT = os.path.join(DATA, "nvd-snapshot", "nvd_all.csv")
STORE_PATH = os.path.join(DATA, "difference", "judgment_store.csv")

csv.field_size_limit(1 << 24)


def load_cve_ids_for_cpe_vp(cpe_vp):
    """CVE ids in the snapshot whose cpe_strings include this vendor:product (any part)."""
    target = cpe_vp.strip().lower()
    hits = set()
    with open(SNAPSHOT, newline="") as f:
        for r in csv.DictReader(f):
            for c in (r.get("cpe_strings") or "").split("|"):
                c = c.strip()
                if not c:
                    continue
                _part, vp = parse_cpe(c)
                if vp == target:
                    hits.add(r["cve_id"])
                    break
    return hits


def load_cve_ids_from_file(path):
    with open(path) as f:
        return {line.strip() for line in f if line.strip()}


def main():
    ap = argparse.ArgumentParser(
        description="Bulk-flag judgment_store.csv rows Excluded (out of the analysis "
                    "population) without touching any judgment cell.")
    ap.add_argument("--category", required=True, help="category slug, e.g. streaming")
    sel = ap.add_mutually_exclusive_group(required=True)
    sel.add_argument("--cpe-vp", help="vendor:product, e.g. apple:tvos")
    sel.add_argument("--cve-file", help="path to a file of CVE ids, one per line")
    ap.add_argument("--reason", help="reason slug, e.g. scope:tvos-2026-07 "
                                     "(required unless --clear)")
    ap.add_argument("--dry-run", action="store_true", help="print the selection only; "
                                                            "do not write the store")
    ap.add_argument("--clear", action="store_true",
                    help="blank the Excluded flag for the selection instead of setting it "
                         "(reversibility)")
    args = ap.parse_args()

    if not args.clear and not args.reason:
        ap.error("--reason is required unless --clear")

    if args.cpe_vp:
        target_ids = load_cve_ids_for_cpe_vp(args.cpe_vp)
        print(f"{len(target_ids)} CVE(s) in the snapshot carry CPE {args.cpe_vp}")
    else:
        target_ids = load_cve_ids_from_file(args.cve_file)
        print(f"{len(target_ids)} CVE(s) read from {args.cve_file}")

    if not os.path.isfile(STORE_PATH):
        raise SystemExit(f"judgment store not found: {STORE_PATH}")

    with open(STORE_PATH, newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames)
        rows = list(reader)

    if "Excluded" not in fieldnames:
        fieldnames = fieldnames + ["Excluded"]
        for r in rows:
            r.setdefault("Excluded", "")

    by_type, by_source = Counter(), Counter()
    n_matched = n_changed = 0
    new_val = "" if args.clear else args.reason
    for r in rows:
        if r["category"] != args.category or r["cve_id"] not in target_ids:
            continue
        n_matched += 1
        if (r.get("Excluded") or "") != new_val:
            n_changed += 1
        r["Excluded"] = new_val
        by_type[r.get("Difference Type", "")] += 1
        by_source[r.get("Final Source", "")] += 1

    action = "clear" if args.clear else f"set to '{args.reason}'"
    verb = "would change" if args.dry_run else "changed"
    print(f"\n{n_matched} store row(s) for category={args.category} matched the selection "
          f"({n_changed} {verb} value)")
    print(f"  by Difference Type: {dict(by_type)}")
    print(f"  by Final Source:    {dict(by_source)}")
    print(f"  action: {action}")

    if args.dry_run:
        print("\n(dry run — judgment_store.csv NOT written)")
        return

    with open(STORE_PATH, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    print(f"\n-> {os.path.relpath(STORE_PATH, ROOT)} updated")


if __name__ == "__main__":
    main()
