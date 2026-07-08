#!/usr/bin/env python3
"""Batch-generate the raw intersection set (01_raw.csv) for every category in a list.

The intersection is **per-category**: for each category it writes
`data/difference/<category>/intersection/01_raw.csv` containing the CVEs found by **both**
search methods:

  - intersection = vendor_<cat> ∩ keyword_<cat>   (CVEs both methods agree on)

where
  - vendor file  = data/vendor-search/results_all_<category>.xlsx
  - keyword file = data/keyword-search/keyword_<category>.csv   (Stage 1, build_keyword_search.py)

Rows are pulled from the vendor file (its schema matches the keyword file). Each row is tagged
`Difference Type = intersection`, which is **disjoint** from vendor_only (V − K), keyword_only
(K − V), and cpe_expansion. So the intersection flows through the *same* Stage-4 review as the
difference set: after building it, run `make_review_copies.py <cat> --refresh` to fold the new
rows into the blind reviewer copies (only the new intersection rows are left blank), then the
normal triple-AI + human chain (merge → extract → finalize).

**Why review the intersection at all?** The pipeline historically treated "both methods agree"
as high-precision and skipped it. An audit showed that assumption holds for most categories but
NOT for `cameras`, where generic device-phrase keywords ("ip camera", "security camera") collide
with pro/enterprise surveillance brands, so a large minority of the intersection is out of scope.
Reviewing it closes the one unmeasured precision gap in the dataset. See CLAUDE.md Stage 3/4.

By default a category whose intersection/01_raw.csv already exists is **skipped** (so an
in-progress review is never clobbered); pass --overwrite to regenerate.

Usage:
    python build_intersection_sets.py data/device_lst.txt
    python build_intersection_sets.py --categories cameras thermostat
    python build_intersection_sets.py data/device_lst.txt --overwrite
"""
import argparse
import os

from full_difference import load_cves, intersection_rows

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR_DIR = os.path.join(ROOT, "data", "vendor-search")
KEYWORD_DIR = os.path.join(ROOT, "data", "keyword-search")
DIFF_DIR = os.path.join(ROOT, "data", "difference")

DIRECTION = "intersection"


def read_categories(path):
    categories = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            name = line.strip()
            if name and not name.startswith("#"):
                categories.append(name)
    return categories


def load_side(path, label, category):
    """Return (df, cve_set) for a side, or (None, None) if the file is missing/unreadable."""
    if not os.path.isfile(path):
        return None, None
    try:
        return load_cves(path)  # load_cves handles both .xlsx (vendor) and .csv (keyword)
    except ValueError as e:
        print(f"  ERROR '{category}' {label}: {e}")
        return None, None


def build_one(category, overwrite):
    """Build a single <category>/intersection/01_raw.csv. Returns 'made'/'skipped'/'problem'."""
    out_dir = os.path.join(DIFF_DIR, category, DIRECTION)
    out = os.path.join(out_dir, "01_raw.csv")
    if os.path.exists(out) and not overwrite:
        print(f"  skip (exists): {category}/{DIRECTION}")
        return "skipped"

    vendor_path = os.path.join(VENDOR_DIR, f"results_all_{category}.xlsx")
    keyword_path = os.path.join(KEYWORD_DIR, f"keyword_{category}.csv")
    vendor_df, vendor_cves = load_side(vendor_path, "vendor", category)
    keyword_df, keyword_cves = load_side(keyword_path, "keyword", category)

    # The intersection needs BOTH sides. A missing side means an empty intersection — nothing
    # to review — so we skip rather than write an empty file.
    if vendor_df is None:
        print(f"  MISSING vendor file for '{category}': {os.path.relpath(vendor_path, ROOT)}"
              " — no intersection")
        return "problem"
    if keyword_cves is None:
        print(f"  MISSING keyword file for '{category}': {os.path.relpath(keyword_path, ROOT)}"
              " — run build_keyword_search.py; no intersection")
        return "problem"

    result = intersection_rows(vendor_df, vendor_cves, keyword_cves, label=DIRECTION)
    if len(result) == 0:
        print(f"  {category}/{DIRECTION}: vendor={len(vendor_cves)}  keyword={len(keyword_cves)}"
              "  -> empty intersection (nothing written)")
        return "skipped"

    os.makedirs(out_dir, exist_ok=True)
    result.to_csv(out, index=False)
    print(f"  {category}/{DIRECTION}: vendor={len(vendor_cves)}  keyword={len(keyword_cves)}  "
          f"-> 01_raw = {len(result)} rows")
    return "made"


def main():
    ap = argparse.ArgumentParser(
        description="Batch-generate per-category intersection (V ∩ K) 01_raw.csv review sets."
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

    tally = {"made": 0, "skipped": 0, "problem": 0}
    for cat in categories:
        tally[build_one(cat, args.overwrite)] += 1

    print(f"\nDone. {tally['made']} generated, {tally['skipped']} skipped/empty, "
          f"{tally['problem']} missing/errored ({len(categories)} categories).")


if __name__ == "__main__":
    main()
