#!/usr/bin/env python3
"""Build blind per-AI review copies for a category from its combined difference rows.

Concatenates both directions (vendor_only + keyword_only) for the given category slug,
pre-fills known AI judgments from judgment_store.csv (keyed by (category, cve_id)),
and writes one blind copy per reviewer to <diff-dir>/<category>/reviews/.

The Difference Type column (vendor_only / keyword_only) on every row lets reviewers
sort back to their direction at any time — no separate per-direction copies needed.

Carry-forward is automatic: no --preserve flag. If judgment_store.csv has a judgment
for a (category, cve_id), it is restored into the reviewer's copy. Only genuinely new
CVEs (absent from the store) are left blank. Rows that no longer appear in 01_raw.csv
are simply not included — the store retains them but they don't end up in the copy.

Modes:
  (default)    skip reviewer copies that already exist
  --refresh    rebuild existing copies to fold in NEW rows (e.g. after CPE expansion adds
               a cpe_expansion/01_raw.csv), carrying prior judgments forward from the
               store — only genuinely new CVEs are left blank, so no settled row is
               re-reviewed. This is the flag to use when routing Stage-5 candidates in.
  --overwrite  blank-rebuild (ignores judgment store; re-reviews everything)
  --all        process every category listed in device_lst.txt

Usage:
    python scripts/make_review_copies.py cameras
    python scripts/make_review_copies.py cameras --refresh    # fold in new rows, keep judgments
    python scripts/make_review_copies.py cameras --overwrite
    python scripts/make_review_copies.py --all --refresh
    python scripts/make_review_copies.py cameras --diff-dir data/difference
"""
import argparse
import os
import pandas as pd

REVIEWERS = ["Claude", "Codex", "Gemini"]
JUDGMENT_FIELDS = ["Judgment", "Confidence", "Reasoning"]

# Review directions concatenated into each category's combined copy. All are disjoint,
# so the Difference Type column on every row sorts back to its direction. cpe_expansion
# (Stage 5) is the third: CVEs in neither text method's output, seeded from confirmed Yes.
DIRECTIONS = ("vendor_only", "keyword_only", "cpe_expansion")


def review_columns(reviewer):
    return [f"{reviewer} {field}" for field in JUDGMENT_FIELDS]


def load_store(store_path):
    if not os.path.isfile(store_path):
        return pd.DataFrame()
    return pd.read_csv(store_path, dtype=str).fillna("")


def build_combined(cat_dir):
    """Concatenate every direction's 01_raw.csv (see DIRECTIONS) for a category."""
    frames = []
    for direction in DIRECTIONS:
        raw = os.path.join(cat_dir, direction, "01_raw.csv")
        if os.path.isfile(raw):
            frames.append(pd.read_csv(raw, dtype=str).fillna(""))
    if not frames:
        return None
    return pd.concat(frames, ignore_index=True)


def process_category(cat, diff_dir, store_df, overwrite, refresh=False):
    cat_dir = os.path.join(diff_dir, cat)
    combined = build_combined(cat_dir)
    if combined is None:
        print(f"  {cat}: no 01_raw.csv files found — skipped")
        return

    if "cve_id" not in combined.columns:
        print(f"  {cat}: 01_raw.csv missing cve_id column — skipped")
        return

    outdir = os.path.join(cat_dir, "reviews")
    os.makedirs(outdir, exist_ok=True)

    # Build a per-cve_id lookup from the store for this category
    store_lookup = {}
    if not overwrite and not store_df.empty and "category" in store_df.columns:
        cat_rows = store_df[store_df["category"] == cat]
        if not cat_rows.empty:
            store_lookup = cat_rows.drop_duplicates("cve_id").set_index("cve_id")

    for reviewer in REVIEWERS:
        out_path = os.path.join(outdir, f"{reviewer.lower()}.csv")
        if os.path.isfile(out_path) and not overwrite and not refresh:
            print(f"  skip (exists): {out_path}  — use --refresh to fold in new rows "
                  f"(keeps prior judgments) or --overwrite to blank-rebuild")
            continue

        cols = review_columns(reviewer)
        copy = combined.copy()
        for col in cols:
            copy[col] = ""

        filled = 0
        if store_lookup is not None and len(store_lookup):
            store_cols = [c for c in cols if c in store_lookup.columns]
            for col in store_cols:
                mapped = copy["cve_id"].map(store_lookup[col]).fillna("")
                copy[col] = mapped
            filled = int((copy[cols[0]].astype(str).str.strip() != "").sum())

        copy.to_csv(out_path, index=False)
        new_blank = len(copy) - filled
        if filled:
            print(f"  wrote {len(copy)} rows -> {out_path}  "
                  f"(restored {filled} from store, {new_blank} blank/new)")
        else:
            print(f"  wrote {len(copy)} rows -> {out_path}")

    n_dirs = sum(1 for d in DIRECTIONS if os.path.isfile(os.path.join(cat_dir, d, "01_raw.csv")))
    print(f"  {cat}: {len(combined)} total rows ({n_dirs} directions)")


def read_device_list(diff_dir):
    lst_path = os.path.join(os.path.dirname(os.path.abspath(diff_dir)), "device_lst.txt")
    if not os.path.isfile(lst_path):
        raise SystemExit(f"device_lst.txt not found at {lst_path}")
    cats = []
    with open(lst_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                cats.append(line)
    return cats


def main():
    ap = argparse.ArgumentParser(
        description="Build combined blind review copies for a category from judgment store."
    )
    ap.add_argument("category", nargs="?", help="Category slug (e.g. cameras)")
    ap.add_argument("--all", action="store_true",
                    help="Process all categories in device_lst.txt")
    ap.add_argument("--diff-dir", default="data/difference",
                    help="Difference directory root (default: data/difference)")
    ap.add_argument("--store", default=None,
                    help="Path to judgment_store.csv (default: <diff-dir>/judgment_store.csv)")
    ap.add_argument("--overwrite", action="store_true",
                    help="Blank-rebuild existing review copies (ignore judgment store)")
    ap.add_argument("--refresh", action="store_true",
                    help="Rebuild existing copies to fold in new rows (e.g. after CPE "
                         "expansion), carrying prior judgments forward from the store — only "
                         "genuinely new CVEs are left blank. Ignored where --overwrite is set.")
    args = ap.parse_args()

    if not args.category and not args.all:
        ap.error("Provide a category slug or use --all")

    store_path = args.store or os.path.join(args.diff_dir, "judgment_store.csv")
    store_df = load_store(store_path)
    if store_df.empty:
        print(f"Note: judgment store not found or empty ({store_path}) — no pre-filling\n")
    else:
        print(f"Loaded {len(store_df)} rows from judgment store\n")

    if args.all:
        categories = read_device_list(args.diff_dir)
        for cat in categories:
            print(f"\n=== {cat} ===")
            process_category(cat, args.diff_dir, store_df, args.overwrite, args.refresh)
    else:
        process_category(args.category, args.diff_dir, store_df, args.overwrite, args.refresh)

    print("\nDone.")


if __name__ == "__main__":
    main()
