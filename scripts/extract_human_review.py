#!/usr/bin/env python3
"""Extract the rows that need human adjudication from the merged triple-AI files.

Reads each category's 02_merged.csv and pulls out the rows flagged
`Needs Human Review = Yes` (set by merge_judgments.py: the two strong reviewers both
Low, or the three judgments not unanimous). Writes a focused, ready-to-adjudicate sheet:

  - per category : data/difference/<cat>/02_needs_human_review.csv
  - combined     : data/difference/human_review_queue.csv   (adds a Category column)

The sheet leads with a compact `Verdicts` summary and the `Review Reason`, keeps the full
evidence (description, CPE) and all three reviewers' reasoning, and adds blank
`Human Verdict` / `Human Notes` columns to fill in. Rows still `incomplete` (an AI hasn't
reviewed yet) are reported but NOT included — they're pending, not contested.

Usage:
    python extract_human_review.py                      # all categories under data/difference
    python extract_human_review.py --diff-dir data/difference
    python extract_human_review.py --merged data/difference/alarms/02_merged.csv
"""
import argparse
import glob
import os
import pandas as pd

REVIEWERS = ["Claude", "Codex", "Gemini"]

# Columns the human sheet leads with / ends with; the rest (raw + AI triples) sit in between.
LEAD = ["Verdicts", "Review Reason", "cve_id", "description", "cpe_strings"]
AI_COLS = [f"{r} {f}" for r in REVIEWERS for f in ("Judgment", "Confidence", "Reasoning")]
TAIL = ["Human Verdict", "Human Notes"]
# Stray generic-AI columns left over from the pre-rename schema — drop them from the sheet.
DROP = {"AI Judgment", "AI Judgment Reasoning", "AI Confidence",
        "Needs Human Review", "Review Status", "Verdicts"}


def verdicts_summary(row):
    """Compact one-glance summary, e.g. 'C:No/High  X:No/High  G:Yes/High'."""
    parts = []
    for r, tag in zip(REVIEWERS, ("C", "X", "G")):
        j = str(row.get(f"{r} Judgment", "")).strip() or "?"
        c = str(row.get(f"{r} Confidence", "")).strip() or "?"
        parts.append(f"{tag}:{j}/{c}")
    return "  ".join(parts)


def build_queue(merged_path):
    """Return (queue_df, n_flagged, n_incomplete) for one merged file."""
    df = pd.read_csv(merged_path, dtype=str).fillna("")
    incomplete = int((df.get("Review Status", "") == "incomplete").sum())
    flagged = df[df.get("Needs Human Review", "") == "Yes"].copy()
    if flagged.empty:
        return flagged, 0, incomplete
    flagged["Verdicts"] = flagged.apply(verdicts_summary, axis=1)
    flagged["Human Verdict"] = ""
    flagged["Human Notes"] = ""
    # order: lead summary cols, then any remaining raw cols, then AI triples, then human cols
    middle = [c for c in flagged.columns
              if c not in LEAD + AI_COLS + TAIL and c not in DROP]
    cols = LEAD + middle + AI_COLS + TAIL
    cols = [c for c in cols if c in flagged.columns]
    return flagged[cols], len(flagged), incomplete


def main():
    ap = argparse.ArgumentParser(description="Extract Needs-Human-Review rows from merged files.")
    ap.add_argument("--diff-dir", default="data/difference",
                    help="Directory holding <category>/02_merged.csv (default: data/difference)")
    ap.add_argument("--merged", help="Run on a single 02_merged.csv instead of scanning the dir")
    args = ap.parse_args()

    if args.merged:
        merged_files = [args.merged]
    else:
        merged_files = sorted(glob.glob(os.path.join(args.diff_dir, "*", "02_merged.csv")))
    if not merged_files:
        raise SystemExit("No 02_merged.csv files found — run merge_judgments.py first.")

    combined = []
    total_flagged = total_incomplete = 0
    for mp in merged_files:
        cat = os.path.basename(os.path.dirname(mp))
        q, n, inc = build_queue(mp)
        out = os.path.join(os.path.dirname(mp), "02_needs_human_review.csv")
        q.to_csv(out, index=False)
        note = f" ({inc} still incomplete — queue partial)" if inc else ""
        print(f"  {cat:14} {n:4} flagged -> {out}{note}")
        if n:
            q.insert(0, "Category", cat)
            combined.append(q)
        total_flagged += n
        total_incomplete += inc

    if not args.merged:
        combined_path = os.path.join(args.diff_dir, "human_review_queue.csv")
        if combined:
            pd.concat(combined, ignore_index=True).to_csv(combined_path, index=False)
            print(f"\nCombined: {total_flagged} rows -> {combined_path}")
        else:
            print("\nNo flagged rows in any category.")
    if total_incomplete:
        print(f"Note: {total_incomplete} rows still incomplete (an AI hasn't reviewed) — not yet queued.")


if __name__ == "__main__":
    main()
