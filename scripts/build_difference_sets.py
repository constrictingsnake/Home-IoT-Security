#!/usr/bin/env python3
"""Batch-generate the raw difference set(s) (01_raw.csv) for every category in a list.

The difference is **per-category and bidirectional**. For each category and each requested
direction it writes `data/difference/<category>/<direction>/01_raw.csv`:

  - vendor_only  = vendor_<cat> − keyword_<cat>   (vendor CVEs the keyword search missed)
  - keyword_only = keyword_<cat> − vendor_<cat>   (keyword CVEs the brand/vendor search missed)

where
  - vendor file  = data/vendor-search/results_all_<category>.xlsx
  - keyword file = data/keyword-search/keyword_<category>.csv   (Stage 1, build_keyword_search.py)

Because vendor_only and keyword_only are disjoint sets, both are full review units fed to the
same direction-agnostic Stage-4 pipeline. A direction whose *source* file is missing is skipped;
a missing *other* side is treated as an empty set (with a warning) so the math still runs.

By default a direction whose 01_raw.csv already exists is **skipped** (so an in-progress review
is never clobbered); pass --overwrite to regenerate.

Usage:
    python build_difference_sets.py data/device_lst.txt                 # both directions
    python build_difference_sets.py data/device_lst.txt --direction keyword_only
    python build_difference_sets.py --categories cameras thermostat --overwrite
"""
import argparse
import os

from full_difference import load_cves, difference_rows

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR_DIR = os.path.join(ROOT, "data", "vendor-search")
KEYWORD_DIR = os.path.join(ROOT, "data", "keyword-search")
DIFF_DIR = os.path.join(ROOT, "data", "difference")

DIRECTIONS = ("vendor_only", "keyword_only")


def read_categories(path):
    categories = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            name = line.strip()
            if name and not name.startswith("#"):
                categories.append(name)
    return categories


def load_side(path, label, category):
    """Return (df, cve_set) for a side, or (None, None) if the file is missing.
    `label` is just for messages (vendor / keyword)."""
    if not os.path.isfile(path):
        return None, None
    try:
        return load_cves(path)  # load_cves handles both .xlsx (vendor) and .csv (keyword)
    except ValueError as e:
        print(f"  ERROR '{category}' {label}: {e}")
        return None, None


def build_one(category, direction, overwrite):
    """Build a single <category>/<direction>/01_raw.csv. Returns 'made'/'skipped'/'problem'."""
    out_dir = os.path.join(DIFF_DIR, category, direction)
    out = os.path.join(out_dir, "01_raw.csv")
    if os.path.exists(out) and not overwrite:
        print(f"  skip (exists): {category}/{direction}")
        return "skipped"

    vendor_path = os.path.join(VENDOR_DIR, f"results_all_{category}.xlsx")
    keyword_path = os.path.join(KEYWORD_DIR, f"keyword_{category}.csv")
    vendor_df, vendor_cves = load_side(vendor_path, "vendor", category)
    keyword_df, keyword_cves = load_side(keyword_path, "keyword", category)

    if direction == "vendor_only":
        if vendor_df is None:
            print(f"  MISSING vendor file for '{category}': {os.path.relpath(vendor_path, ROOT)}")
            return "problem"
        if keyword_cves is None:
            print(f"  WARNING '{category}' vendor_only: no keyword file "
                  f"({os.path.relpath(keyword_path, ROOT)}) — run build_keyword_search.py; "
                  "differencing against empty keyword set.")
            keyword_cves = set()
        source_df, source_cves, other_cves = vendor_df, vendor_cves, keyword_cves
    else:  # keyword_only
        if keyword_df is None:
            print(f"  MISSING keyword file for '{category}': {os.path.relpath(keyword_path, ROOT)} "
                  "— run build_keyword_search.py first.")
            return "problem"
        if vendor_cves is None:
            print(f"  WARNING '{category}' keyword_only: no vendor file "
                  f"({os.path.relpath(vendor_path, ROOT)}) — differencing against empty vendor set.")
            vendor_cves = set()
        source_df, source_cves, other_cves = keyword_df, keyword_cves, vendor_cves

    result = difference_rows(source_df, source_cves, other_cves, label=direction)
    os.makedirs(out_dir, exist_ok=True)
    result.to_csv(out, index=False)
    print(f"  {category}/{direction}: source={len(source_cves)}  other={len(other_cves)}  "
          f"-> 01_raw = {len(result)} rows")
    return "made"


def main():
    ap = argparse.ArgumentParser(
        description="Batch-generate per-category, bidirectional 01_raw.csv difference sets."
    )
    ap.add_argument("categories_file", nargs="?", help="Text file, one category per line")
    ap.add_argument("--categories", nargs="+", help="Category names directly (instead of a file)")
    ap.add_argument("--direction", choices=["vendor_only", "keyword_only", "both"], default="both",
                    help="Which difference direction(s) to build (default: both)")
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

    directions = DIRECTIONS if args.direction == "both" else (args.direction,)

    tally = {"made": 0, "skipped": 0, "problem": 0}
    for cat in categories:
        for direction in directions:
            tally[build_one(cat, direction, args.overwrite)] += 1

    print(f"\nDone. {tally['made']} generated, {tally['skipped']} skipped, "
          f"{tally['problem']} missing/errored "
          f"({len(categories)} categories × {len(directions)} direction(s)).")


if __name__ == "__main__":
    main()
