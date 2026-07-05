#!/usr/bin/env python3
"""Fold human verdicts back in to produce one settled judgment per CVE.

Collapses each category's merged triple-AI file into a single `Final Judgment` using:

    not flagged (AIs agree, confident)         -> the AI consensus       (Final Source = ai-consensus)
    flagged + both humans agree (not Maybe)     -> the agreed verdict     (Final Source = human)
    flagged + humans disagree, or either blank  -> pending                (Final Source = pending)
    a reviewer hasn't judged yet (incomplete)   -> blank                  (Final Source = incomplete)

There are TWO independent human reviewer slots per row (Human Verdict 1/2, mirroring the
AI triple-review model with two humans). A row only settles once both reviewers agree —
same rule as the AI unanimity check. Disagreement leaves it `pending` for reconciliation
rather than picking a side.

Human verdicts are read from data/difference/human_review_queue.csv or per-category
02_needs_human_review.csv (whichever was filled in), keyed by (category, cve_id). Sheets
still on the old single-reviewer schema (Human Verdict) are read as Reviewer 1's answer.

Direction is encoded per-row in the Difference Type column (vendor_only / keyword_only).
Adds `Final Judgment` / `Final Source` columns — never overwrites the AI columns.
Re-run as humans fill more in; the `pending` count shrinks toward zero.

After each run, upserts settled AI judgments + Final Judgment into judgment_store.csv
(keyed by (category, cve_id)) so they survive 01_raw.csv regenerations.

Outputs:
    per category  : data/difference/<cat>/03_final.csv
    combined      : data/difference/final_resolved.csv  (adds Category + Direction columns)
    persistent    : data/difference/judgment_store.csv  (upserted, never rebuilt from scratch)

Usage:
    python finalize_judgments.py
    python finalize_judgments.py --diff-dir data/difference
"""
import argparse
import glob
import os
import pandas as pd
from collections import Counter

VALID = {"Yes", "No", "Maybe"}

STORE_COLS = [
    "category", "cve_id", "Difference Type",
    "Claude Judgment", "Claude Confidence", "Claude Reasoning",
    "Codex Judgment", "Codex Confidence", "Codex Reasoning",
    "Gemini Judgment", "Gemini Confidence", "Gemini Reasoning",
    "Final Judgment", "Final Source",
]


def cat_of(merged_path):
    return os.path.basename(os.path.dirname(merged_path))


def load_human_verdicts(diff_dir):
    """Return {(category, CVE-ID): (verdict1, verdict2)} from filled Human Verdict cells.

    Sheets on the old single-reviewer schema (Human Verdict) are read as Reviewer 1's
    answer; Reviewer 2 comes back blank for those rows.
    """
    verdicts = {}
    origin = {}  # key -> path last written from, for conflict messages

    def read_cell(r, col, cat, cve, path):
        hv = str(r.get(col, "")).strip()
        if hv and hv not in VALID:
            print(f"  ! {cat}/{cve}: invalid {col} '{hv}' (want Yes/No/Maybe) — skipped")
            return ""
        return hv

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
            cat = category if category is not None else str(r.get("Category", "")).strip()
            cve = str(r["cve_id"]).strip().upper()
            key = (cat, cve)
            if has_v2:
                hv1 = read_cell(r, "Human Verdict 1", cat, cve, path)
                hv2 = read_cell(r, "Human Verdict 2", cat, cve, path)
            else:
                hv1 = read_cell(r, "Human Verdict", cat, cve, path)
                hv2 = ""
            if not hv1 and not hv2:
                continue
            if key in verdicts and verdicts[key] != (hv1, hv2):
                print(f"  ! conflict for {cat}/{cve}: {verdicts[key]} ({origin[key]}) "
                      f"vs {(hv1, hv2)} ({os.path.basename(path)}) — keeping first")
                continue
            verdicts.setdefault(key, (hv1, hv2))
            origin.setdefault(key, os.path.basename(path))

    ingest(os.path.join(diff_dir, "human_review_queue.csv"), category=None)
    for p in sorted(glob.glob(os.path.join(diff_dir, "*", "02_needs_human_review.csv"))):
        cat = os.path.basename(os.path.dirname(p))
        ingest(p, category=cat)
    return verdicts


def resolve_row(row, cat, human):
    status = str(row.get("Review Status", "")).strip()
    if status == "incomplete":
        return "", "incomplete"
    if str(row.get("Needs Human Review", "")).strip() == "Yes":
        hv1, hv2 = human.get((cat, str(row["cve_id"]).strip().upper()), ("", ""))
        # Settles only when both reviewers have weighed in, agree, and it isn't "Maybe" —
        # same unanimity bar as the AI triple review. Disagreement or a still-blank slot
        # both fall through to pending rather than picking a side.
        if hv1 and hv2 and hv1 == hv2 and hv1 != "Maybe":
            return hv1, "human"
        return "", "pending"
    return str(row.get("Claude Judgment", "")).strip(), "ai-consensus"


def finalize(merged_path, human):
    cat = cat_of(merged_path)
    df = pd.read_csv(merged_path, dtype=str).fillna("")
    res = df.apply(lambda r: resolve_row(r, cat, human), axis=1, result_type="expand")
    df["Final Judgment"] = res[0]
    df["Final Source"] = res[1]
    return cat, df


def upsert_store(df, cat, store_path):
    """Replace all rows for this category in judgment_store.csv (upsert semantics)."""
    if os.path.isfile(store_path):
        store = pd.read_csv(store_path, dtype=str).fillna("")
    else:
        store = pd.DataFrame(columns=STORE_COLS)

    new_df = df.copy()
    new_df["category"] = cat
    keep = ["category", "cve_id"] + [c for c in STORE_COLS[2:] if c in new_df.columns]
    new_rows = new_df[keep]

    store = store[store["category"] != cat]
    store = pd.concat([store, new_rows], ignore_index=True)

    # Ensure all store columns exist (fill any absent ones with "")
    for col in STORE_COLS:
        if col not in store.columns:
            store[col] = ""
    store = store[STORE_COLS]
    store.to_csv(store_path, index=False)


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

    store_path = os.path.join(args.diff_dir, "judgment_store.csv")
    combined = []
    grand = Counter()

    for mp in merged_files:
        cat, df = finalize(mp, human)
        out = os.path.join(os.path.dirname(mp), "03_final.csv")
        df.to_csv(out, index=False)
        c = Counter(df["Final Source"])
        grand.update(c)
        pend = c.get("pending", 0)
        flag = f"  ({pend} pending human input)" if pend else ""
        print(f"  {cat:16} resolved={c.get('ai-consensus',0)+c.get('human',0):4} "
              f"[ai={c.get('ai-consensus',0)}, human={c.get('human',0)}], "
              f"incomplete={c.get('incomplete',0)}{flag}")
        upsert_store(df, cat, store_path)
        df_out = df.copy()
        # Direction is already encoded in Difference Type; add an alias column for compat
        if "Difference Type" in df_out.columns:
            df_out.insert(0, "Direction", df_out["Difference Type"])
        df_out.insert(0, "Category", cat)
        combined.append(df_out)

    pd.concat(combined, ignore_index=True).to_csv(
        os.path.join(args.diff_dir, "final_resolved.csv"), index=False)
    print(f"\nTotals: {dict(grand)}")
    print(f"-> per-category 03_final.csv + {os.path.join(args.diff_dir, 'final_resolved.csv')}")
    print(f"-> judgment store upserted: {store_path}")
    if grand.get("pending"):
        print(f"\n{grand['pending']} rows still need a Human Verdict "
              f"(fill them in the review sheet and re-run).")


if __name__ == "__main__":
    main()
