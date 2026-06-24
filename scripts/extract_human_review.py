#!/usr/bin/env python3
"""Extract the rows that need human adjudication from the merged triple-AI files.

Reads each direction's 02_merged.csv (<cat>/vendor_only/ and <cat>/keyword_only/) and pulls
out the rows flagged `Needs Human Review = Yes` (set by merge_judgments.py: the two strong
reviewers both Low, or the three judgments not unanimous). Writes a focused, ready-to-adjudicate
sheet:

  - per cat+direction : data/difference/<cat>/<direction>/02_needs_human_review.csv
  - combined          : data/difference/human_review_queue.csv  (adds Category + Direction columns)

**Verdict-preserving:** before overwriting, it reads any Human Verdict / Human Notes already
filled in (in the existing combined queue or per-category sheets) and carries them forward, keyed
by (category, cve_id). vendor_only and keyword_only are disjoint, so that key is unambiguous.
This makes re-running safe — earlier hand-filled verdicts are never lost.

The sheet leads with a compact `Verdicts` summary and the `Review Reason`, keeps the full
evidence (description, CPE) and all three reviewers' reasoning, and ends with
`Human Verdict` / `Human Notes`. Rows still `incomplete` (an AI hasn't reviewed yet) are
reported but NOT included — they're pending, not contested.

Usage:
    python extract_human_review.py                      # all categories/directions
    python extract_human_review.py --diff-dir data/difference
    python extract_human_review.py --merged data/difference/alarms/vendor_only/02_merged.csv
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


def cat_dir_of(path):
    """(category, direction) from a .../<cat>/<direction>/02_*.csv path."""
    direction = os.path.basename(os.path.dirname(path))
    category = os.path.basename(os.path.dirname(os.path.dirname(path)))
    return category, direction


def norm(cve):
    return str(cve).strip().upper()


def load_existing_verdicts(diff_dir):
    """{(category, CVE-ID): (Human Verdict, Human Notes)} from any already-filled sheets —
    the combined queue and every per-category 02_needs_human_review.csv. Used to carry verdicts
    forward across re-runs so nothing hand-filled is lost."""
    out = {}

    def ingest(path, category):  # category=None -> read from the row's Category column
        if not os.path.isfile(path):
            return
        df = pd.read_csv(path, dtype=str).fillna("")
        if "Human Verdict" not in df.columns or "cve_id" not in df.columns:
            return
        for _, r in df.iterrows():
            hv = str(r.get("Human Verdict", "")).strip()
            hn = str(r.get("Human Notes", "")).strip()
            if not hv and not hn:
                continue
            cat = category if category is not None else str(r.get("Category", "")).strip()
            out.setdefault((cat, norm(r["cve_id"])), (hv, hn))

    ingest(os.path.join(diff_dir, "human_review_queue.csv"), category=None)
    for p in sorted(glob.glob(os.path.join(diff_dir, "*", "*", "02_needs_human_review.csv"))):
        ingest(p, category=cat_dir_of(p)[0])
    return out


def verdicts_summary(row):
    """Compact one-glance summary, e.g. 'C:No/High  X:No/High  G:Yes/High'."""
    parts = []
    for r, tag in zip(REVIEWERS, ("C", "X", "G")):
        j = str(row.get(f"{r} Judgment", "")).strip() or "?"
        c = str(row.get(f"{r} Confidence", "")).strip() or "?"
        parts.append(f"{tag}:{j}/{c}")
    return "  ".join(parts)


def build_queue(merged_path, existing):
    """Return (queue_df, n_flagged, n_incomplete) for one merged file, carrying forward any
    existing Human Verdict/Notes from `existing` keyed (category, cve_id)."""
    cat, _direction = cat_dir_of(merged_path)
    df = pd.read_csv(merged_path, dtype=str).fillna("")
    incomplete = int((df.get("Review Status", "") == "incomplete").sum())
    flagged = df[df.get("Needs Human Review", "") == "Yes"].copy()
    if flagged.empty:
        return flagged, 0, incomplete
    flagged["Verdicts"] = flagged.apply(verdicts_summary, axis=1)
    carried = flagged["cve_id"].map(lambda c: existing.get((cat, norm(c)), ("", "")))
    flagged["Human Verdict"] = [v for v, _ in carried]
    flagged["Human Notes"] = [n for _, n in carried]
    # order: lead summary cols, then any remaining raw cols, then AI triples, then human cols
    middle = [c for c in flagged.columns
              if c not in LEAD + AI_COLS + TAIL and c not in DROP]
    cols = LEAD + middle + AI_COLS + TAIL
    cols = [c for c in cols if c in flagged.columns]
    return flagged[cols], len(flagged), incomplete


def main():
    ap = argparse.ArgumentParser(description="Extract Needs-Human-Review rows from merged files.")
    ap.add_argument("--diff-dir", default="data/difference",
                    help="Directory holding <category>/<direction>/02_merged.csv (default: data/difference)")
    ap.add_argument("--merged", help="Run on a single 02_merged.csv instead of scanning the dir")
    args = ap.parse_args()

    if args.merged:
        merged_files = [args.merged]
    else:
        merged_files = sorted(glob.glob(os.path.join(args.diff_dir, "*", "*", "02_merged.csv")))
    if not merged_files:
        raise SystemExit("No 02_merged.csv files found — run merge_judgments.py first.")

    # Read existing verdicts BEFORE overwriting anything, so re-runs preserve them.
    existing = load_existing_verdicts(args.diff_dir)
    if existing:
        print(f"Carrying forward {len(existing)} existing human verdict(s).\n")

    combined = []
    total_flagged = total_incomplete = 0
    for mp in merged_files:
        cat, direction = cat_dir_of(mp)
        q, n, inc = build_queue(mp, existing)
        out = os.path.join(os.path.dirname(mp), "02_needs_human_review.csv")
        q.to_csv(out, index=False)
        note = f" ({inc} still incomplete — queue partial)" if inc else ""
        print(f"  {cat:14} {direction:12} {n:4} flagged -> {out}{note}")
        if n:
            q.insert(0, "Direction", direction)
            q.insert(0, "Category", cat)
            combined.append(q)
        total_flagged += n
        total_incomplete += inc

    if not args.merged:
        combined_path = os.path.join(args.diff_dir, "human_review_queue.csv")
        if combined:
            out_df = pd.concat(combined, ignore_index=True)
            carried = int((out_df["Human Verdict"].str.strip() != "").sum())
            out_df.to_csv(combined_path, index=False)
            print(f"\nCombined: {total_flagged} rows ({carried} with a human verdict) -> {combined_path}")
        else:
            print("\nNo flagged rows in any category.")
    if total_incomplete:
        print(f"Note: {total_incomplete} rows still incomplete (an AI hasn't reviewed) — not yet queued.")


if __name__ == "__main__":
    main()
