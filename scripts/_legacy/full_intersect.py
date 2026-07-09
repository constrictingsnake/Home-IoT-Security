#!/usr/bin/env python3
"""RETIRED — batch-generate the per-category intersection (matched_<cat>_cves.csv).

Superseded by `build_review_sets.py --direction intersection`, which routes the same
vendor_<cat> ∩ keyword_<cat> rows through the Stage-4 triple-AI review instead of writing
an unreviewed side file (see CLAUDE.md "Stage 3 — intersection audit"). Kept for reference
only; not part of the live pipeline.

The intersection is **per-category**: the CVEs surfaced by BOTH search methods for a category —

    matched_<cat> = vendor_<cat> ∩ keyword_<cat>

where
  - vendor file  = data/vendor-search/results_all_<category>.csv  (Stage 2, build_search.py --method vendor)
  - keyword file = data/keyword-search/keyword_<category>.csv       (Stage 1, build_search.py --method keyword)

Usage (if resurrected):
    python _legacy/full_intersect.py                                 # every category in data/categories.csv
    python _legacy/full_intersect.py --categories cameras thermostat
    python _legacy/full_intersect.py --categories cameras --outdir /tmp/inter
"""
import argparse
import os
import sys

# Reuse the shared per-category helpers so CVE handling stays identical across Stage 3/4:
#   load_side   — reads the per-category CSV (vendor or keyword), returns (df, cve_set) with `_cve_norm`
#   read_categories — parse categories.csv (slug column, header-aware)
#   DROP_COLS   — helper + reviewer-judgment columns stripped from the output
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from review_lib import DROP_COLS  # noqa: E402
from build_review_sets import read_categories, load_side  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VENDOR_DIR = os.path.join(ROOT, "data", "vendor-search")
KEYWORD_DIR = os.path.join(ROOT, "data", "keyword-search")
INTERSECT_DIR = os.path.join(ROOT, "data", "intersection")

DEFAULT_CATEGORIES_FILE = os.path.join(ROOT, "data", "categories.csv")


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
    vendor_path = os.path.join(VENDOR_DIR, f"results_all_{category}.csv")
    keyword_path = os.path.join(KEYWORD_DIR, f"keyword_{category}.csv")

    vendor_df, vendor_cves = load_side(vendor_path, "vendor", category)
    keyword_df, keyword_cves = load_side(keyword_path, "keyword", category)

    if vendor_df is None:
        print(f"  MISSING vendor file for '{category}': {os.path.relpath(vendor_path, ROOT)} "
              "— run build_search.py --method vendor first; skipping.")
        return "problem"
    if keyword_df is None:
        print(f"  MISSING keyword file for '{category}': {os.path.relpath(keyword_path, ROOT)} "
              "— run build_search.py --method keyword first; skipping.")
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
                    help="Categories CSV with a slug column (default: data/categories.csv)")
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
