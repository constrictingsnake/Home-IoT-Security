#!/usr/bin/env python3
"""Stage 1 & 2 — offline per-category search (keyword and/or vendor).

One driver for both discovery methods. Each runs its per-category search terms
through the SAME offline engine (cve_search.filter_by_keywords — matches
description + CPE against one fixed NVD snapshot, whole_word=True) and writes one
file per analysis category in the common CSV schema:

    keyword method → data/keyword-search/keyword_<slug>.csv     (device-phrase terms)
    vendor  method → data/vendor-search/results_all_<slug>.csv  (brand terms)

Both outputs share the identical 8-column schema (cve_id, published, description,
cvss_score, cvss_version, cwe_ids, cpe_strings, matched_terms), so the two methods
are directly comparable and every downstream stage reads either side the same way.

The ONLY difference between the two methods is the search terms (device phrases vs.
brands) and where they live/land. Terms are authored in slug,term CSVs
(keyword_terms.csv / vendor_terms.csv): '#'-comments and blank lines ignored, a
'slug,term' header tolerated anywhere. A category with no active terms is skipped
with a message (not an error).

Usage:
    # Build a fixed snapshot first (one-time, see cve_search.py header STEP 1-2):
    #   python3 scripts/cve_search.py --convert nvdcve-1.1-2024.json --csv-out nvd_2024.csv
    #   python3 scripts/cve_search.py --merge nvd_*.csv --merged-out data/nvd-snapshot/nvd_all.csv

    python3 scripts/build_search.py                              # both methods, all categories
    python3 scripts/build_search.py --method keyword            # keyword method only
    python3 scripts/build_search.py --method vendor --overwrite
    python3 scripts/build_search.py --categories cameras thermostat
    python3 scripts/build_search.py --method vendor --terms data/vendor-search/vendor_terms_proposed.csv
"""
import argparse
import csv
import os

from cve_search import (
    load_dataset,
    filter_by_keywords,
    save_results_csv,
    print_keyword_breakdown,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYWORD_DIR = os.path.join(ROOT, "data", "keyword-search")
VENDOR_DIR = os.path.join(ROOT, "data", "vendor-search")
DEFAULT_SNAPSHOT = os.path.join(ROOT, "data", "nvd-snapshot", "nvd_all.csv")

# Per-method config — the only real fork between the two searches.
METHODS = {
    "keyword": {
        "terms": os.path.join(KEYWORD_DIR, "keyword_terms.csv"),
        "outdir": KEYWORD_DIR,
        "pattern": "keyword_{slug}.csv",
        "noun": "keyword",
        "empty_hint": " (copy from keyword_terms.suggested.csv)",
    },
    "vendor": {
        "terms": os.path.join(VENDOR_DIR, "vendor_terms.csv"),
        "outdir": VENDOR_DIR,
        "pattern": "results_all_{slug}.csv",
        "noun": "brand",
        "empty_hint": "",
    },
}


def read_terms(path):
    """Parse a slug,term terms CSV -> {slug: [terms]}, preserving order, skipping
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


def build_method(method, terms_by_slug, all_cves, categories, outdir, overwrite):
    """Run one method's search over the loaded snapshot, writing one CSV per
    category with terms. Returns (built, skipped, empty)."""
    cfg = METHODS[method]
    wanted = list(categories) if categories else list(terms_by_slug.keys())
    os.makedirs(outdir, exist_ok=True)
    built = skipped = empty = 0
    print(f"\n=== {method} search ===")
    for slug in wanted:
        kws = terms_by_slug.get(slug)
        if not kws:
            print(f"  skip (no {cfg['noun']} terms defined for '{slug}'{cfg['empty_hint']})")
            empty += 1
            continue

        out = os.path.join(outdir, cfg["pattern"].format(slug=slug))
        if os.path.exists(out) and not overwrite:
            print(f"  skip (exists): {slug}  ({os.path.relpath(out, ROOT)})")
            skipped += 1
            continue

        print(f"\n🔍  {slug}: {len(kws)} {cfg['noun']} term(s)")
        matched, counts, terms = filter_by_keywords(all_cves, kws, whole_word=True)
        print_keyword_breakdown(counts, len(matched))
        save_results_csv(matched, out, matched_terms=terms)
        print(f"  💾  CSV → {os.path.relpath(out, ROOT)}")
        built += 1

    print(f"  {method}: {built} built, {skipped} skipped (exist), {empty} empty "
          f"({len(wanted)} requested).")
    return built, skipped, empty


def main():
    ap = argparse.ArgumentParser(
        description="Offline per-category keyword/vendor search over a fixed NVD snapshot."
    )
    ap.add_argument("--method", choices=("keyword", "vendor", "both"), default="both",
                    help="Which search method(s) to run (default: both).")
    ap.add_argument("--snapshot", default=DEFAULT_SNAPSHOT,
                    help=f"NVD snapshot .csv/.json to search (default: {os.path.relpath(DEFAULT_SNAPSHOT, ROOT)})")
    ap.add_argument("--terms", default=None,
                    help="Terms CSV override (requires a single --method; default: per-method file).")
    ap.add_argument("--categories", nargs="+",
                    help="Only build these slugs (default: every slug with terms).")
    ap.add_argument("--outdir", default=None,
                    help="Output dir override (requires a single --method; default: per-method dir).")
    ap.add_argument("--overwrite", action="store_true",
                    help="Rebuild even if the output already exists (default: skip).")
    args = ap.parse_args()

    methods = ["keyword", "vendor"] if args.method == "both" else [args.method]

    if (args.terms or args.outdir) and len(methods) > 1:
        ap.error("--terms/--outdir require a single --method (not 'both').")

    # Read terms for each selected method first — an all-empty run is a friendly
    # no-op that never has to touch (or require) the large snapshot.
    per_method = {}
    for m in methods:
        terms_path = args.terms or METHODS[m]["terms"]
        if not os.path.isfile(terms_path):
            ap.error(f"Terms file not found: {terms_path}")
        per_method[m] = {
            "terms_by_slug": read_terms(terms_path),
            "terms_path": terms_path,
            "outdir": args.outdir or METHODS[m]["outdir"],
        }

    if not any(pm["terms_by_slug"] for pm in per_method.values()):
        for m, pm in per_method.items():
            print(f"No active terms in {os.path.relpath(pm['terms_path'], ROOT)}.")
        print("Add slug,term rows, then re-run.")
        return

    if not os.path.isfile(args.snapshot):
        ap.error(
            f"Snapshot not found: {args.snapshot}\n"
            "Build one first — see cve_search.py header (STEP 1-2) / "
            "data/nvd-snapshot/SNAPSHOT.md."
        )

    # Load the snapshot ONCE, then run every selected method against it.
    print(f"\n📦  Loading snapshot: {os.path.relpath(args.snapshot, ROOT)}")
    all_cves = load_dataset(args.snapshot)

    totals = [0, 0, 0]
    for m in methods:
        pm = per_method[m]
        if not pm["terms_by_slug"]:
            print(f"\n=== {m} search ===\n  No active terms in "
                  f"{os.path.relpath(pm['terms_path'], ROOT)} — skipped.")
            continue
        b, s, e = build_method(m, pm["terms_by_slug"], all_cves,
                               args.categories, pm["outdir"], args.overwrite)
        totals[0] += b
        totals[1] += s
        totals[2] += e

    print(f"\n✨  Done. {totals[0]} built, {totals[1]} skipped (exist), "
          f"{totals[2]} empty across {len(methods)} method(s).")


if __name__ == "__main__":
    main()
