#!/usr/bin/env python3
"""Fold human verdicts back in to produce one settled judgment per CVE.

Collapses each category's merged triple-AI file into a single `Final Judgment` using:

    not flagged (AIs agree, confident)      -> the AI consensus      (Final Source = ai-consensus)
    flagged + human filled Human Verdict     -> the human's verdict    (Final Source = human)
    flagged + Human Verdict still blank       -> pending                (Final Source = pending)
    a reviewer hasn't judged yet (incomplete) -> blank                  (Final Source = incomplete)

Human verdicts are read from the Human Verdict column of either the combined
data/difference/human_review_queue.csv or the per-category 02_needs_human_review.csv
(whichever you filled in), keyed by (category, cve_id).

Adds `Final Judgment` / `Final Source` columns — never overwrites the AI columns. Re-run
as humans fill more in; the `pending` count shrinks toward zero.

Outputs:
    per category : data/difference/<cat>/03_final.csv
    combined     : data/difference/final_resolved.csv   (adds a Category column)

Usage:
    python finalize_judgments.py
    python finalize_judgments.py --diff-dir data/difference
"""
import argparse
import glob
import os
import pandas as pd

VALID = {"Yes", "No", "Maybe"}


def load_human_verdicts(diff_dir):
    """Return {(category, CVE-ID): verdict} from filled Human Verdict cells, warning on
    invalid values or conflicts between the combined and per-category sheets."""
    verdicts = {}
    sources = {}  # (cat, cve) -> file it came from, for conflict messages

    def ingest(path, category):
        """category=None -> read it from the file's Category column (combined sheet)."""
        if not os.path.isfile(path):
            return
        df = pd.read_csv(path, dtype=str).fillna("")
        if "Human Verdict" not in df.columns or "cve_id" not in df.columns:
            return
        for _, r in df.iterrows():
            hv = str(r["Human Verdict"]).strip()
            if not hv:
                continue
            cat = category if category is not None else str(r.get("Category", "")).strip()
            cve = str(r["cve_id"]).strip().upper()
            key = (cat, cve)
            if hv not in VALID:
                print(f"  ! {cat}/{cve}: invalid Human Verdict '{hv}' (want Yes/No/Maybe) — skipped")
                continue
            if key in verdicts and verdicts[key] != hv:
                print(f"  ! conflict for {cat}/{cve}: '{verdicts[key]}' ({sources[key]}) "
                      f"vs '{hv}' ({os.path.basename(path)}) — keeping first")
                continue
            verdicts.setdefault(key, hv)
            sources.setdefault(key, os.path.basename(path))

    # combined sheet (category from its own column)
    ingest(os.path.join(diff_dir, "human_review_queue.csv"), category=None)
    # per-category sheets (category from the folder name)
    for p in sorted(glob.glob(os.path.join(diff_dir, "*", "02_needs_human_review.csv"))):
        ingest(p, category=os.path.basename(os.path.dirname(p)))
    return verdicts


def resolve_row(row, cat, human):
    status = str(row.get("Review Status", "")).strip()
    if status == "incomplete":
        return "", "incomplete"
    if str(row.get("Needs Human Review", "")).strip() == "Yes":
        hv = human.get((cat, str(row["cve_id"]).strip().upper()))
        return (hv, "human") if hv else ("", "pending")
    # not flagged + complete => the three judgments are unanimous; take any (Claude)
    return str(row.get("Claude Judgment", "")).strip(), "ai-consensus"


def finalize(merged_path, human):
    cat = os.path.basename(os.path.dirname(merged_path))
    df = pd.read_csv(merged_path, dtype=str).fillna("")
    res = df.apply(lambda r: resolve_row(r, cat, human), axis=1, result_type="expand")
    df["Final Judgment"] = res[0]
    df["Final Source"] = res[1]
    return cat, df


def main():
    ap = argparse.ArgumentParser(description="Fold human verdicts into one Final Judgment per CVE.")
    ap.add_argument("--diff-dir", default="data/difference",
                    help="Directory holding <category>/02_merged.csv (default: data/difference)")
    args = ap.parse_args()

    merged_files = sorted(glob.glob(os.path.join(args.diff_dir, "*", "02_merged.csv")))
    if not merged_files:
        raise SystemExit("No 02_merged.csv files found — run merge_judgments.py first.")

    print("Loading human verdicts ...")
    human = load_human_verdicts(args.diff_dir)
    print(f"  {len(human)} human verdict(s) found\n")

    combined = []
    from collections import Counter
    grand = Counter()
    for mp in merged_files:
        cat, df = finalize(mp, human)
        out = os.path.join(os.path.dirname(mp), "03_final.csv")
        df.to_csv(out, index=False)
        c = Counter(df["Final Source"])
        grand.update(c)
        pend = c.get("pending", 0)
        flag = f"  ({pend} pending human input)" if pend else ""
        print(f"  {cat:14} resolved={c.get('ai-consensus',0)+c.get('human',0):4} "
              f"[ai={c.get('ai-consensus',0)}, human={c.get('human',0)}], "
              f"incomplete={c.get('incomplete',0)}{flag}")
        df.insert(0, "Category", cat)
        combined.append(df)

    pd.concat(combined, ignore_index=True).to_csv(
        os.path.join(args.diff_dir, "final_resolved.csv"), index=False)
    print(f"\nTotals: {dict(grand)}")
    print(f"-> per-category 03_final.csv + {os.path.join(args.diff_dir, 'final_resolved.csv')}")
    if grand.get("pending"):
        print(f"\n{grand['pending']} rows still need a Human Verdict "
              f"(fill them in the review sheet and re-run).")


if __name__ == "__main__":
    main()
