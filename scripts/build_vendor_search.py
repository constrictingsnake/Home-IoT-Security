#!/usr/bin/env python3
"""Stage 2 — offline per-category VENDOR/brand search.

The vendor-side companion to build_keyword_search.py. Runs per-category
brand/manufacturer keyword strings through the SAME offline engine
(cve_search.filter_by_keywords — description + CPE against one fixed NVD
snapshot) and writes, for each category with terms:

    data/vendor-search/results_all_<slug>.xlsx

in the common schema (cve_id, published, description, cvss_score,
cvss_version, cwe_ids, cpe_strings) — identical to the keyword files and to the
difference 01_raw.csv, so both search methods are directly comparable and the
difference pipeline can read either side.

Brand terms are authored in data/vendor-search/vendor_terms.csv (slug,term),
same format as keyword_terms.csv: '#'-comments and blank lines ignored, a
'slug,term' header tolerated anywhere. A category with no active terms is
skipped with a message (not an error).

Usage:
    python3 scripts/build_vendor_search.py                          # all categories with terms
    python3 scripts/build_vendor_search.py --categories hub lighting
    python3 scripts/build_vendor_search.py --terms data/vendor-search/vendor_terms_proposed.csv
    python3 scripts/build_vendor_search.py --overwrite
"""
import argparse
import os

import pandas as pd

from cve_search import (
    OUTPUT_COLS,
    load_dataset,
    filter_by_keywords,
    print_keyword_breakdown,
    _cve_to_row,
)

# Reuse the keyword driver's terms parser (identical slug,term format).
from build_keyword_search import read_terms

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR_DIR = os.path.join(ROOT, "data", "vendor-search")
DEFAULT_TERMS = os.path.join(VENDOR_DIR, "vendor_terms.csv")
DEFAULT_SNAPSHOT = os.path.join(ROOT, "data", "nvd-snapshot", "nvd_all.csv")


def main():
    ap = argparse.ArgumentParser(
        description="Offline per-category vendor/brand search over a fixed NVD snapshot."
    )
    ap.add_argument("--snapshot", default=DEFAULT_SNAPSHOT,
                    help=f"NVD snapshot .csv/.json to search (default: {os.path.relpath(DEFAULT_SNAPSHOT, ROOT)})")
    ap.add_argument("--terms", default=DEFAULT_TERMS,
                    help=f"Brand terms CSV (slug,term) (default: {os.path.relpath(DEFAULT_TERMS, ROOT)})")
    ap.add_argument("--categories", nargs="+",
                    help="Only build these slugs (default: every slug with terms).")
    ap.add_argument("--outdir", default=VENDOR_DIR,
                    help=f"Where to write results_all_<slug>.xlsx (default: {os.path.relpath(VENDOR_DIR, ROOT)})")
    ap.add_argument("--overwrite", action="store_true",
                    help="Rebuild even if results_all_<slug>.xlsx already exists (default: skip).")
    args = ap.parse_args()

    if not os.path.isfile(args.terms):
        ap.error(f"Terms file not found: {args.terms}")

    terms_by_slug = read_terms(args.terms)
    if not terms_by_slug:
        print(f"No active terms in {os.path.relpath(args.terms, ROOT)}.")
        return

    if not os.path.isfile(args.snapshot):
        ap.error(
            f"Snapshot not found: {args.snapshot}\n"
            "Build one first — see cve_search.py header (STEP 1-2) / "
            "data/nvd-snapshot/SNAPSHOT.md."
        )

    wanted = list(args.categories) if args.categories else list(terms_by_slug.keys())

    print(f"\n📦  Loading snapshot: {os.path.relpath(args.snapshot, ROOT)}")
    all_cves = load_dataset(args.snapshot)

    os.makedirs(args.outdir, exist_ok=True)
    built = skipped = empty = 0
    for slug in wanted:
        kws = terms_by_slug.get(slug)
        if not kws:
            print(f"  skip (no brand terms defined for '{slug}')")
            empty += 1
            continue

        out = os.path.join(args.outdir, f"results_all_{slug}.xlsx")
        if os.path.exists(out) and not args.overwrite:
            print(f"  skip (exists): {slug}  ({os.path.relpath(out, ROOT)})")
            skipped += 1
            continue

        print(f"\n🔍  {slug}: {len(kws)} brand term(s)")
        matched, counts, terms = filter_by_keywords(all_cves, kws, whole_word=True)
        print_keyword_breakdown(counts, len(matched))

        # Flatten via the engine's row builder so list fields (cwe_ids, cpe_strings,
        # matched_terms) are pipe-joined and None→"" — IDENTICAL to the keyword CSVs.
        # (A bare DataFrame(matched) would write Python list reprs and break
        # comparability with the keyword side.)
        df = pd.DataFrame(
            [_cve_to_row(c, terms.get(c["cve_id"], [])) for c in matched],
            columns=OUTPUT_COLS,
        )
        df.to_excel(out, index=False)
        print(f"  💾  XLSX → {out}")
        built += 1

    print(f"\n✨  Done. {built} built, {skipped} skipped (exist), {empty} empty "
          f"({len(wanted)} requested).")


if __name__ == "__main__":
    main()
