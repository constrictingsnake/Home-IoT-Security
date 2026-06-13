#!/usr/bin/env python3
"""Batch-generate the raw difference set (01_raw.csv) for every category in a list.

For each category it computes vendor − keyword_union and writes
`data/difference/<category>/01_raw.csv`, where:
  - vendor file   = data/vendor-search/results_all_<category>.xlsx
  - keyword union = every workbook in data/keyword-search/*.xlsx

The keyword union is the same for every category, so it is built **once** and reused.

By default a category whose 01_raw.csv already exists is **skipped** (so an in-progress
review is never clobbered); pass --overwrite to regenerate.

Usage:
    python build_difference_sets.py data/device_lst.txt
    python build_difference_sets.py data/device_lst.txt --overwrite
    python build_difference_sets.py --categories cameras thermostat
"""
import argparse
import glob
import os

from full_difference import load_cves, collect_workbook_cves, difference_rows

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR_DIR = os.path.join(ROOT, "data", "vendor-search")
KEYWORD_DIR = os.path.join(ROOT, "data", "keyword-search")
DIFF_DIR = os.path.join(ROOT, "data", "difference")


def read_categories(path):
    categories = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            name = line.strip()
            if name and not name.startswith("#"):
                categories.append(name)
    return categories


def main():
    ap = argparse.ArgumentParser(
        description="Batch-generate 01_raw.csv (vendor − keyword) for many categories."
    )
    ap.add_argument("categories_file", nargs="?", help="Text file, one category per line")
    ap.add_argument("--categories", nargs="+", help="Category names directly (instead of a file)")
    ap.add_argument("--overwrite", action="store_true", help="Regenerate even if 01_raw.csv exists")
    args = ap.parse_args()

    if args.categories:
        categories = args.categories
    elif args.categories_file:
        if not os.path.isfile(args.categories_file):
            ap.error(f"Category file not found: {args.categories_file}")
        categories = read_categories(args.categories_file)
    else:
        ap.error("Provide a categories file or --categories")

    if not categories:
        print("No categories to process.")
        return

    workbooks = sorted(glob.glob(os.path.join(KEYWORD_DIR, "*.xlsx")))
    if not workbooks:
        ap.error(f"No keyword workbooks found in {KEYWORD_DIR}")

    # The keyword union is identical for every category — build it once.
    print(f"Building keyword union from {len(workbooks)} workbooks ...")
    keyword_cves = set()
    for wb in workbooks:
        keyword_cves |= collect_workbook_cves(wb)
    print(f"\nKeyword union: {len(keyword_cves)} CVEs\n")

    made = skipped = problems = 0
    for cat in categories:
        out_dir = os.path.join(DIFF_DIR, cat)
        out = os.path.join(out_dir, "01_raw.csv")
        if os.path.exists(out) and not args.overwrite:
            print(f"  skip (exists): {cat}")
            skipped += 1
            continue

        vendor = os.path.join(VENDOR_DIR, f"results_all_{cat}.xlsx")
        if not os.path.isfile(vendor):
            print(f"  MISSING vendor file for '{cat}': {os.path.relpath(vendor, ROOT)}")
            problems += 1
            continue

        try:
            vendor_df, vendor_cves = load_cves(vendor)
        except ValueError as e:
            print(f"  ERROR '{cat}': {e}")
            problems += 1
            continue

        result = difference_rows(vendor_df, vendor_cves, keyword_cves)
        os.makedirs(out_dir, exist_ok=True)
        result.to_csv(out, index=False)
        print(
            f"  {cat}: vendor={len(vendor_cves)}  union={len(keyword_cves)}  "
            f"-> 01_raw = {len(result)} rows"
        )
        made += 1

    print(f"\nDone. {made} generated, {skipped} skipped, {problems} missing/errored "
          f"({len(categories)} in list).")


if __name__ == "__main__":
    main()
