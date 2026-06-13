#!/usr/bin/env python3
"""Split a raw difference CSV into three blind review copies — one per AI reviewer.

Each reviewer (Claude Code, Codex, Gemini) gets its OWN file containing only the raw
difference data plus its own three empty judgment columns. Keeping the copies separate
*guarantees* blindness: a reviewer cannot see another reviewer's judgment because it is
not present in the file it reads. (For Gemini this is also enforced by gemini_classify.py,
which only ever sends the description + CPE to the API.)

After all three copies are filled in, recombine them with merge_judgments.py.

Usage:
    python make_review_copies.py path/to/01_raw.csv
    python make_review_copies.py path/to/01_raw.csv --outdir path/to/reviews --overwrite
"""
import argparse
import os
import pandas as pd

REVIEWERS = ["Claude", "Codex", "Gemini"]
JUDGMENT_FIELDS = ["Judgment", "Confidence", "Reasoning"]


def review_columns(reviewer):
    return [f"{reviewer} {field}" for field in JUDGMENT_FIELDS]


def main():
    ap = argparse.ArgumentParser(
        description="Split a raw difference CSV into per-AI blind review copies."
    )
    ap.add_argument("raw_csv", help="Path to the raw difference CSV (e.g. 01_raw.csv)")
    ap.add_argument(
        "--outdir",
        default=None,
        help="Directory for the review copies (default: <raw_dir>/reviews)",
    )
    ap.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing review copies instead of skipping them",
    )
    args = ap.parse_args()

    if not os.path.isfile(args.raw_csv):
        ap.error(f"Raw CSV not found: {args.raw_csv}")

    df = pd.read_csv(args.raw_csv, dtype=str).fillna("")
    if "cve_id" not in df.columns:
        ap.error("Raw CSV must contain a 'cve_id' column.")

    outdir = args.outdir or os.path.join(
        os.path.dirname(os.path.abspath(args.raw_csv)), "reviews"
    )
    os.makedirs(outdir, exist_ok=True)

    for reviewer in REVIEWERS:
        out_path = os.path.join(outdir, f"{reviewer.lower()}.csv")
        if os.path.exists(out_path) and not args.overwrite:
            print(f"  skip (exists): {out_path}  — use --overwrite to replace")
            continue
        copy = df.copy()
        for col in review_columns(reviewer):
            copy[col] = ""
        copy.to_csv(out_path, index=False)
        print(f"  wrote {len(copy)} rows -> {out_path}")

    print(f"\nDone. {len(df)} rows split into blind copies in {outdir}")


if __name__ == "__main__":
    main()
