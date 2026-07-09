#!/usr/bin/env python3
"""One-time bootstrap: seed judgment_store.csv from the existing final_resolved.csv.

Run once when migrating to the new pipeline structure. After this, finalize_judgments.py
upserts into the store on every run — keeping all settled AI judgments durable across
01_raw.csv regenerations and folder restructures.

Usage:
    python scripts/seed_judgment_store.py
    python scripts/seed_judgment_store.py --diff-dir data/difference
"""
import argparse
import os
import pandas as pd

STORE_COLS = [
    "category", "cve_id", "Difference Type",
    "Claude Judgment", "Claude Confidence", "Claude Reasoning",
    "Codex Judgment", "Codex Confidence", "Codex Reasoning",
    "Gemini Judgment", "Gemini Confidence", "Gemini Reasoning",
    "Final Judgment", "Final Source",
]


def main():
    ap = argparse.ArgumentParser(description="Seed judgment_store.csv from final_resolved.csv.")
    ap.add_argument("--diff-dir", default="data/difference",
                    help="Difference directory (default: data/difference)")
    ap.add_argument("--overwrite", action="store_true",
                    help="Overwrite existing judgment_store.csv if present")
    args = ap.parse_args()

    out = os.path.join(args.diff_dir, "judgment_store.csv")
    if os.path.isfile(out) and not args.overwrite:
        raise SystemExit(f"Already exists: {out}  — use --overwrite to reseed")

    src = os.path.join(args.diff_dir, "final_resolved.csv")
    if not os.path.isfile(src):
        raise SystemExit(f"Not found: {src} — run finalize_judgments.py first.")

    df = pd.read_csv(src, dtype=str).fillna("")
    df = df.rename(columns={"Category": "category"})

    missing = [c for c in STORE_COLS if c not in df.columns]
    if missing:
        print(f"Note: columns absent in source (will be empty in store): {missing}")
        for c in missing:
            df[c] = ""

    store = df[STORE_COLS].drop_duplicates(subset=["category", "cve_id"])
    store.to_csv(out, index=False)
    print(f"Seeded {len(store)} rows -> {out}")


if __name__ == "__main__":
    main()
