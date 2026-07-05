#!/usr/bin/env python3
"""Extract the rows that need human adjudication from the merged triple-AI files.

Reads each category's 02_merged.csv (at data/difference/<cat>/02_merged.csv) and pulls
out the rows flagged `Needs Human Review = Yes`. The Difference Type column on each row
(vendor_only / keyword_only) tells you which direction the CVE came from.

Writes a focused, ready-to-adjudicate sheet with TWO independent human reviewer slots
(Human Verdict 1/Notes 1, Human Verdict 2/Notes 2) — mirroring the AI triple-review model
with two humans instead of one. finalize_judgments.py only settles a row when both agree.

  - per category : data/difference/<cat>/02_needs_human_review.csv
  - combined     : data/difference/human_review_queue.csv  (adds Category + Direction columns)

**Verdict-preserving:** before overwriting, reads any Human Verdict 1/2 / Human Notes 1/2
already filled in (from the existing combined queue or per-category sheets) and carries them
forward, keyed by (category, cve_id). This makes re-running safe — earlier hand-filled
verdicts are never lost. Sheets still on the old single-reviewer schema (Human Verdict /
Human Notes) are read as Reviewer 1's answer, migrating them forward automatically.

Rows still `incomplete` (an AI hasn't reviewed yet) are reported but NOT included — they're
pending, not contested.

Usage:
    python extract_human_review.py                      # all categories
    python extract_human_review.py --diff-dir data/difference
    python extract_human_review.py --merged data/difference/alarms/02_merged.csv
"""
import argparse
import glob
import os
import pandas as pd

REVIEWERS = ["Claude", "Codex", "Gemini"]

LEAD = ["Verdicts", "Review Reason", "cve_id", "description", "cpe_strings"]
AI_COLS = [f"{r} {f}" for r in REVIEWERS for f in ("Judgment", "Confidence", "Reasoning")]
TAIL = ["Human Verdict 1", "Human Notes 1", "Human Verdict 2", "Human Notes 2"]
DROP = {"AI Judgment", "AI Judgment Reasoning", "AI Confidence",
        "Needs Human Review", "Review Status", "Verdicts"}


def cat_of(path):
    return os.path.basename(os.path.dirname(path))


def norm(cve):
    return str(cve).strip().upper()


def load_existing_verdicts(diff_dir):
    """{(category, CVE-ID): (HV1, HN1, HV2, HN2)} from any already-filled sheets.

    Sheets on the old single-reviewer schema (Human Verdict / Human Notes) are read as
    Reviewer 1's answer; Reviewer 2's slot comes back blank for those rows.
    """
    out = {}

    def ingest(path, category):
        if not os.path.isfile(path):
            return
        df = pd.read_csv(path, dtype=str).fillna("")
        if "cve_id" not in df.columns:
            return
        has_v2 = "Human Verdict 1" in df.columns
        has_legacy = "Human Verdict" in df.columns
        if not has_v2 and not has_legacy:
            return
        for _, r in df.iterrows():
            if has_v2:
                hv1 = str(r.get("Human Verdict 1", "")).strip()
                hn1 = str(r.get("Human Notes 1", "")).strip()
                hv2 = str(r.get("Human Verdict 2", "")).strip()
                hn2 = str(r.get("Human Notes 2", "")).strip()
            else:
                hv1 = str(r.get("Human Verdict", "")).strip()
                hn1 = str(r.get("Human Notes", "")).strip()
                hv2 = hn2 = ""
            if not any((hv1, hn1, hv2, hn2)):
                continue
            cat = category if category is not None else str(r.get("Category", "")).strip()
            out.setdefault((cat, norm(r["cve_id"])), (hv1, hn1, hv2, hn2))

    ingest(os.path.join(diff_dir, "human_review_queue.csv"), category=None)
    for p in sorted(glob.glob(os.path.join(diff_dir, "*", "02_needs_human_review.csv"))):
        ingest(p, category=cat_of(p))
    return out


def verdicts_summary(row):
    parts = []
    for r, tag in zip(REVIEWERS, ("C", "X", "G")):
        j = str(row.get(f"{r} Judgment", "")).strip() or "?"
        c = str(row.get(f"{r} Confidence", "")).strip() or "?"
        parts.append(f"{tag}:{j}/{c}")
    return "  ".join(parts)


def build_queue(merged_path, existing):
    cat = cat_of(merged_path)
    df = pd.read_csv(merged_path, dtype=str).fillna("")
    incomplete = int((df.get("Review Status", "") == "incomplete").sum())
    flagged = df[df.get("Needs Human Review", "") == "Yes"].copy()
    if flagged.empty:
        return flagged, 0, incomplete
    flagged["Verdicts"] = flagged.apply(verdicts_summary, axis=1)
    carried = flagged["cve_id"].map(lambda c: existing.get((cat, norm(c)), ("", "", "", "")))
    flagged["Human Verdict 1"] = [v for v, _, _, _ in carried]
    flagged["Human Notes 1"] = [n for _, n, _, _ in carried]
    flagged["Human Verdict 2"] = [v for _, _, v, _ in carried]
    flagged["Human Notes 2"] = [n for _, _, _, n in carried]
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

    existing = load_existing_verdicts(args.diff_dir)
    if existing:
        print(f"Carrying forward {len(existing)} existing human verdict(s).\n")

    combined = []
    total_flagged = total_incomplete = 0
    for mp in merged_files:
        cat = cat_of(mp)
        q, n, inc = build_queue(mp, existing)
        out = os.path.join(os.path.dirname(mp), "02_needs_human_review.csv")
        q.to_csv(out, index=False)
        note = f" ({inc} still incomplete — queue partial)" if inc else ""
        print(f"  {cat:16} {n:4} flagged -> {out}{note}")
        if n:
            q_out = q.copy()
            # Add Direction alias from Difference Type for combined queue backward compat
            if "Difference Type" in q_out.columns:
                q_out.insert(0, "Direction", q_out["Difference Type"])
            q_out.insert(0, "Category", cat)
            combined.append(q_out)
        total_flagged += n
        total_incomplete += inc

    if not args.merged:
        combined_path = os.path.join(args.diff_dir, "human_review_queue.csv")
        if combined:
            out_df = pd.concat(combined, ignore_index=True)
            v1 = int((out_df["Human Verdict 1"].str.strip() != "").sum())
            v2 = int((out_df["Human Verdict 2"].str.strip() != "").sum())
            both = int(((out_df["Human Verdict 1"].str.strip() != "") &
                        (out_df["Human Verdict 2"].str.strip() != "")).sum())
            out_df.to_csv(combined_path, index=False)
            print(f"\nCombined: {total_flagged} rows "
                  f"(reviewer1={v1}, reviewer2={v2}, both={both}) -> {combined_path}")
        else:
            print("\nNo flagged rows in any category.")
    if total_incomplete:
        print(f"Note: {total_incomplete} rows still incomplete (an AI hasn't reviewed) — not yet queued.")


if __name__ == "__main__":
    main()
