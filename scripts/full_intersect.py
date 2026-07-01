#!/usr/bin/env python3
"""Batch-generate the per-category intersection (matched_<cat>_cves.csv) for every category in a list.

The intersection is **per-category**: the CVEs surfaced by BOTH search methods for a category —

    matched_<cat> = vendor_<cat> ∩ keyword_<cat>

where
  - vendor file  = data/vendor-search/results_all_<category>.xlsx  (Stage 2, build_vendor_search.py)
  - keyword file = data/keyword-search/keyword_<category>.csv       (Stage 1, build_keyword_search.py)

These agreement rows are the high-confidence true positives — the exact complement of the
bidirectional difference sets from build_difference_sets.py (vendor_only / keyword_only). This
tool shares those scripts' conventions: it is non-interactive (argparse), normalizes CVE IDs the
same way (load_cves → `_cve_norm`), and emits the common schema. Output rows are pulled from the
keyword file (clean common schema — no reviewer columns) and tagged with a leading Category column.

Both sides are required: an intersection with a missing side is empty, so a category lacking either
a vendor or keyword file is reported and skipped rather than written as an empty file.

Usage:
    python full_intersect.py                                 # every category in data/device_lst.txt
    python full_intersect.py data/device_lst.txt
    python full_intersect.py --categories cameras thermostat
    python full_intersect.py --categories cameras --outdir /tmp/inter
"""
import argparse
import os

# Reuse the shared per-category helpers so CVE handling stays identical across Stage 3/4:
#   load_side   — reads .xlsx (vendor) or .csv (keyword), returns (df, cve_set) with `_cve_norm`
#   read_categories — parse a one-slug-per-line list (blank/#-comment aware)
#   DROP_COLS   — helper + reviewer-judgment columns stripped from the output
from full_difference import DROP_COLS
from build_difference_sets import read_categories, load_side

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR_DIR = os.path.join(ROOT, "data", "vendor-search")
KEYWORD_DIR = os.path.join(ROOT, "data", "keyword-search")
INTERSECT_DIR = os.path.join(ROOT, "data", "intersection")

DEFAULT_CATEGORIES_FILE = os.path.join(ROOT, "data", "device_lst.txt")


def intersect_rows(source_df, source_cves, other_cves, category):
    """Rows for the CVEs present in BOTH sets, pulled from source_df, tagged with Category.

    Mirrors full_difference.difference_rows: filter by the normalized `_cve_norm`, drop the helper
    and reviewer-judgment columns, then insert the provenance column at the front."""
    both = source_cves & other_cves
    result = source_df[source_df['_cve_norm'].isin(both)].copy()
    result = result.drop(columns=DROP_COLS, errors='ignore')
    result.insert(0, "Category", category)
    return result


def build_one(category, outdir):
    """Build a single matched_<category>_cves.csv. Returns 'made' / 'problem'."""
    vendor_path = os.path.join(VENDOR_DIR, f"results_all_{category}.xlsx")
    keyword_path = os.path.join(KEYWORD_DIR, f"keyword_{category}.csv")

    vendor_df, vendor_cves = load_side(vendor_path, "vendor", category)
    keyword_df, keyword_cves = load_side(keyword_path, "keyword", category)

    if vendor_df is None:
        print(f"  MISSING vendor file for '{category}': {os.path.relpath(vendor_path, ROOT)} "
              "— run build_vendor_search.py first; skipping.")
        return "problem"
    if keyword_df is None:
        print(f"  MISSING keyword file for '{category}': {os.path.relpath(keyword_path, ROOT)} "
              "— run build_keyword_search.py first; skipping.")
        return "problem"

    result = intersect_rows(keyword_df, keyword_cves, vendor_cves, category)
    os.makedirs(outdir, exist_ok=True)
    out = os.path.join(outdir, f"matched_{category}_cves.csv")
    result.to_csv(out, index=False)
    print(f"  {category}: vendor={len(vendor_cves)}  keyword={len(keyword_cves)}  "
          f"-> matched = {len(result)} rows")
    return "made"


def main():
    ap = argparse.ArgumentParser(
        description="Batch-generate per-category intersection sets (vendor ∩ keyword)."
    )
    ap.add_argument("categories_file", nargs="?", default=DEFAULT_CATEGORIES_FILE,
                    help="Text file, one category per line (default: data/device_lst.txt)")
    ap.add_argument("--categories", nargs="+", help="Category names directly (instead of a file)")
    ap.add_argument("--outdir", default=INTERSECT_DIR,
                    help="Where to write matched_<cat>_cves.csv (default: data/intersection/)")
    args = ap.parse_args()

    if args.categories:
        categories = args.categories
    else:
        if not os.path.isfile(args.categories_file):
            ap.error(f"Category file not found: {args.categories_file}")
        categories = read_categories(args.categories_file)

    if not categories:
        print("No categories to process.")
        return

    print(f"------ CVE Per-Category Intersection (vendor ∩ keyword) ------\n"
          f"{len(categories)} categor(y/ies) -> {os.path.relpath(args.outdir, ROOT)}\n")

    tally = {"made": 0, "problem": 0}
    for cat in categories:
        tally[build_one(cat, args.outdir)] += 1

    print(f"\nDone. {tally['made']} generated, {tally['problem']} missing/errored "
          f"({len(categories)} categories).")


if __name__ == "__main__":
    main()
