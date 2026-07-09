#!/usr/bin/env python3
"""Batch-generate per-category review-set 01_raw.csv files, one per direction.

Merges the former build_difference_sets.py (vendor_only / keyword_only) and
build_intersection_sets.py (intersection) into one driver. For each category and each
requested direction it writes data/difference/<category>/<direction>/01_raw.csv in the
canonical 8-column RAW_COLS schema (Difference Type + the 7 common data columns):

  vendor_only  = vendor_<cat> − keyword_<cat>   (vendor CVEs the keyword search missed)
  keyword_only = keyword_<cat> − vendor_<cat>   (keyword CVEs the brand/vendor search missed)
  intersection = vendor_<cat> ∩ keyword_<cat>   (both methods agree — audit direction, NOT clean)

vendor_only, keyword_only, and intersection are disjoint and together partition V ∪ K; the
Stage-5 cpe_expansion direction (cpe_expansion.py) sits outside it. Inputs:
  vendor file  = data/vendor-search/results_all_<category>.csv  (build_search.py --method vendor)
  keyword file = data/keyword-search/keyword_<category>.csv     (build_search.py --method keyword)

For the difference directions a missing *other* side is treated as an empty set (with a
warning) so the math still runs; the intersection requires BOTH sides and writes nothing when
the overlap is empty. By default a direction whose 01_raw.csv already exists is skipped (so an
in-progress review is never clobbered); pass --overwrite to regenerate.

Usage:
    python build_review_sets.py data/categories.csv                     # all directions
    python build_review_sets.py data/categories.csv --direction intersection
    python build_review_sets.py --categories cameras thermostat --overwrite
"""
import argparse
import csv
import os

from review_lib import (
    load_cves, difference_rows, intersection_rows, RAW_COLS, write_raw,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR_DIR = os.path.join(ROOT, "data", "vendor-search")
KEYWORD_DIR = os.path.join(ROOT, "data", "keyword-search")
DIFF_DIR = os.path.join(ROOT, "data", "difference")

DIRECTIONS = ("vendor_only", "keyword_only", "intersection")


def read_categories(path):
    """Parse a categories file -> list of slugs, preserving order.

    Accepts data/categories.csv (header row with a `slug` column, extra columns
    ignored) or a plain one-slug-per-line list (blank lines / '#' comments ignored)
    for ad hoc use."""
    with open(path, encoding="utf-8") as fh:
        first = fh.readline()
        fh.seek(0)
        if "slug" in [c.strip().lower() for c in first.split(",")]:
            return [row["slug"].strip() for row in csv.DictReader(fh) if row.get("slug", "").strip()]
        categories = []
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
        return load_cves(path)  # load_cves reads the per-category CSV (vendor or keyword)
    except ValueError as e:
        print(f"  ERROR '{category}' {label}: {e}")
        return None, None


def _write(result, out):
    """Write a difference/intersection DataFrame via the shared RAW_COLS writer."""
    write_raw(result.reindex(columns=RAW_COLS).fillna("").to_dict("records"), out)


def build_one(category, direction, overwrite):
    """Build a single <category>/<direction>/01_raw.csv. Returns 'made'/'skipped'/'problem'."""
    out = os.path.join(DIFF_DIR, category, direction, "01_raw.csv")
    if os.path.exists(out) and not overwrite:
        print(f"  skip (exists): {category}/{direction}")
        return "skipped"

    vendor_path = os.path.join(VENDOR_DIR, f"results_all_{category}.csv")
    keyword_path = os.path.join(KEYWORD_DIR, f"keyword_{category}.csv")
    vendor_df, vendor_cves = load_side(vendor_path, "vendor", category)
    keyword_df, keyword_cves = load_side(keyword_path, "keyword", category)

    if direction == "intersection":
        # Both sides required — the intersection is undefined if either is missing.
        if vendor_df is None:
            print(f"  MISSING vendor file for '{category}': {os.path.relpath(vendor_path, ROOT)} "
                  "— run build_search.py --method vendor first.")
            return "problem"
        if keyword_df is None:
            print(f"  MISSING keyword file for '{category}': {os.path.relpath(keyword_path, ROOT)} "
                  "— run build_search.py --method keyword first.")
            return "problem"
        result = intersection_rows(vendor_df, vendor_cves, keyword_cves, label="intersection")
        if len(result) == 0:
            print(f"  {category}/intersection: vendor={len(vendor_cves)}  keyword={len(keyword_cves)}"
                  "  -> empty intersection (nothing written)")
            return "skipped"
        _write(result, out)
        print(f"  {category}/intersection: vendor={len(vendor_cves)}  keyword={len(keyword_cves)}  "
              f"-> 01_raw = {len(result)} rows")
        return "made"

    # Difference directions: source side required, missing other side -> empty set.
    if direction == "vendor_only":
        if vendor_df is None:
            print(f"  MISSING vendor file for '{category}': {os.path.relpath(vendor_path, ROOT)}")
            return "problem"
        if keyword_cves is None:
            print(f"  WARNING '{category}' vendor_only: no keyword file "
                  f"({os.path.relpath(keyword_path, ROOT)}) — run build_search.py --method keyword; "
                  "differencing against empty keyword set.")
            keyword_cves = set()
        source_df, source_cves, other_cves = vendor_df, vendor_cves, keyword_cves
    else:  # keyword_only
        if keyword_df is None:
            print(f"  MISSING keyword file for '{category}': {os.path.relpath(keyword_path, ROOT)} "
                  "— run build_search.py --method keyword first.")
            return "problem"
        if vendor_cves is None:
            print(f"  WARNING '{category}' keyword_only: no vendor file "
                  f"({os.path.relpath(vendor_path, ROOT)}) — differencing against empty vendor set.")
            vendor_cves = set()
        source_df, source_cves, other_cves = keyword_df, keyword_cves, vendor_cves

    result = difference_rows(source_df, source_cves, other_cves, label=direction)
    _write(result, out)
    print(f"  {category}/{direction}: source={len(source_cves)}  other={len(other_cves)}  "
          f"-> 01_raw = {len(result)} rows")
    return "made"


def main():
    ap = argparse.ArgumentParser(
        description="Batch-generate per-category review-set 01_raw.csv files (all directions)."
    )
    ap.add_argument("categories_file", nargs="?", help="Text file, one category per line")
    ap.add_argument("--categories", nargs="+", help="Category names directly (instead of a file)")
    ap.add_argument("--direction",
                    choices=["vendor_only", "keyword_only", "intersection", "all"], default="all",
                    help="Which direction(s) to build (default: all).")
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

    directions = DIRECTIONS if args.direction == "all" else (args.direction,)

    tally = {"made": 0, "skipped": 0, "problem": 0}
    for cat in categories:
        for direction in directions:
            tally[build_one(cat, direction, args.overwrite)] += 1

    print(f"\nDone. {tally['made']} generated, {tally['skipped']} skipped, "
          f"{tally['problem']} missing/errored "
          f"({len(categories)} categories × {len(directions)} direction(s)).")


if __name__ == "__main__":
    main()
