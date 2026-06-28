#!/usr/bin/env python3
"""Stage 1 — offline per-category keyword search.

Runs the user-authored device-phrase keywords (one set per analysis category)
through the SAME offline engine as the vendor search (cve_search.filter_by_keywords,
which matches description + CPE against one fixed NVD snapshot). For each category
with terms it writes:

    data/keyword-search/keyword_<slug>.csv

in the common CSV schema (cve_id, published, description, cvss_score, cvss_version,
cwe_ids, cpe_strings) — identical to the vendor files and to the difference 01_raw.csv,
and now WITH CPE strings, so the two search methods are directly comparable.

Keywords are USER-AUTHORED in data/keyword-search/keyword_terms.csv (this file ships
empty with commented examples). Suggested starter terms live in
keyword_terms.suggested.csv, which this driver never reads. A category with no active
terms is skipped with a message (not an error).

Usage:
    # Build a fixed snapshot first (one-time, see cve_search.py header STEP 1-2):
    #   python3 scripts/cve_search.py --convert nvdcve-1.1-2024.json --csv-out nvd_2024.csv
    #   python3 scripts/cve_search.py --merge nvd_*.csv --merged-out data/nvd-snapshot/nvd_all.csv

    python3 scripts/build_keyword_search.py                       # all categories with terms
    python3 scripts/build_keyword_search.py --categories cameras thermostat
    python3 scripts/build_keyword_search.py --snapshot path/to/nvd_all.csv
"""
import argparse
import csv
import os
import sys

from cve_search import (
    load_dataset,
    filter_by_keywords,
    save_results_csv,
    print_keyword_breakdown,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYWORD_DIR = os.path.join(ROOT, "data", "keyword-search")
DEFAULT_TERMS = os.path.join(KEYWORD_DIR, "keyword_terms.csv")
DEFAULT_SNAPSHOT = os.path.join(ROOT, "data", "nvd-snapshot", "nvd_all.csv")


def read_terms(path):
    """Parse keyword_terms.csv -> {slug: [terms]}, preserving order, skipping
    '#' comment lines, blanks, and the 'slug,term' header row."""
    terms = {}
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # tolerate the header row in any position
            row = next(csv.reader([line]))
            if len(row) < 2:
                continue
            slug, term = row[0].strip(), row[1].strip()
            if not slug or not term or slug.lower() == "slug":
                continue
            terms.setdefault(slug, [])
            if term not in terms[slug]:  # dedupe within a category
                terms[slug].append(term)
    return terms


def main():
    ap = argparse.ArgumentParser(
        description="Offline per-category keyword search over a fixed NVD snapshot."
    )
    ap.add_argument("--snapshot", default=DEFAULT_SNAPSHOT,
                    help=f"NVD snapshot .csv/.json to search (default: {os.path.relpath(DEFAULT_SNAPSHOT, ROOT)})")
    ap.add_argument("--terms", default=DEFAULT_TERMS,
                    help=f"User-authored keyword terms CSV (default: {os.path.relpath(DEFAULT_TERMS, ROOT)})")
    ap.add_argument("--categories", nargs="+",
                    help="Only build these slugs (default: every slug with terms).")
    ap.add_argument("--outdir", default=KEYWORD_DIR,
                    help=f"Where to write keyword_<slug>.csv (default: {os.path.relpath(KEYWORD_DIR, ROOT)})")
    ap.add_argument("--overwrite", action="store_true",
                    help="Rebuild even if keyword_<slug>.csv already exists (default: skip).")
    args = ap.parse_args()

    if not os.path.isfile(args.terms):
        ap.error(f"Terms file not found: {args.terms}")

    # Read terms first — an empty terms file is a friendly no-op, no need to
    # touch (or even require) the large snapshot.
    terms_by_slug = read_terms(args.terms)
    if not terms_by_slug:
        print(
            f"No active terms in {os.path.relpath(args.terms, ROOT)}.\n"
            "Add device-phrase rows (copy from keyword_terms.suggested.csv), then re-run."
        )
        return

    if not os.path.isfile(args.snapshot):
        ap.error(
            f"Snapshot not found: {args.snapshot}\n"
            "Build one first — see cve_search.py header (STEP 1-2) / "
            "data/nvd-snapshot/SNAPSHOT.md."
        )

    if args.categories:
        wanted = list(args.categories)
    else:
        wanted = list(terms_by_slug.keys())

    # Load the snapshot ONCE, then filter per category.
    print(f"\n📦  Loading snapshot: {os.path.relpath(args.snapshot, ROOT)}")
    all_cves = load_dataset(args.snapshot)

    os.makedirs(args.outdir, exist_ok=True)
    built = skipped = empty = 0
    for slug in wanted:
        kws = terms_by_slug.get(slug)
        if not kws:
            print(f"  skip (no keywords defined for '{slug}' — add rows in "
                  f"{os.path.basename(args.terms)}, see keyword_terms.suggested.csv)")
            empty += 1
            continue

        out = os.path.join(args.outdir, f"keyword_{slug}.csv")
        if os.path.exists(out) and not args.overwrite:
            print(f"  skip (exists): {slug}  ({os.path.relpath(out, ROOT)})")
            skipped += 1
            continue

        print(f"\n🔍  {slug}: {len(kws)} term(s)")
        matched, counts = filter_by_keywords(all_cves, kws, whole_word=True)
        print_keyword_breakdown(counts, len(matched))
        save_results_csv(matched, out)
        built += 1

    print(f"\n✨  Done. {built} built, {skipped} skipped (exist), {empty} empty "
          f"({len(wanted)} requested).")


if __name__ == "__main__":
    main()
