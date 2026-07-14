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

**Outstanding-only queue:** rows already settled by humans (both reviewers answered, agree,
not Maybe — the same bar finalize_judgments.py uses) are DROPPED from the queue. Their raw
verdicts live in judgment_store.csv (persisted by finalize_judgments.py), so the queue is
just the genuine to-do list: rows with no verdict, one verdict (awaiting the 2nd reviewer),
a disagreement, or a Maybe to reconcile. Run finalize BEFORE extract (pipeline.py settle
does) so a freshly filled verdict reaches the store before the queue is regenerated.

**Verdict-preserving:** existing Human Verdict 1/2 / Human Notes 1/2 are read from the store
first, then from the live sheets (which win), keyed by (category, cve_id), and carried
forward for any row that stays in the queue — earlier hand-filled verdicts are never lost.
Sheets still on the old single-reviewer schema (Human Verdict / Human Notes) are read as
Reviewer 1's answer, migrating them forward automatically.

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
    """{(category, CVE-ID): (HV1, HN1, HV2, HN2)} from the persistent store + any sheets.

    The judgment store is the durable home for human answers (finalize_judgments.py writes
    them there), so it is read first — this is what lets already-reviewed rows be dropped
    from the live queue yet still carried forward if they ever reappear. Live sheets are
    read after and win over the store (a human may have just edited them). Sheets on the
    old single-reviewer schema (Human Verdict / Human Notes) are read as Reviewer 1's
    answer; Reviewer 2's slot comes back blank for those rows.
    """
    out = {}

    def ingest(path, category, override):
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
            cat = (category if category is not None
                   else str(r.get("Category", "")).strip() or str(r.get("category", "")).strip())
            key = (cat, norm(r["cve_id"]))
            if override:
                out[key] = (hv1, hn1, hv2, hn2)
            else:
                out.setdefault(key, (hv1, hn1, hv2, hn2))

    ingest(os.path.join(diff_dir, "judgment_store.csv"), category=None, override=False)
    ingest(os.path.join(diff_dir, "human_review_queue.csv"), category=None, override=True)
    for p in sorted(glob.glob(os.path.join(diff_dir, "*", "02_needs_human_review.csv"))):
        ingest(p, category=cat_of(p), override=True)
    return out


def is_settled(verdict_tuple):
    """A row is settled by humans when both reviewers answered, agree, and it isn't Maybe
    — the same unanimity bar finalize_judgments.py uses. Such rows leave the live queue."""
    hv1, _hn1, hv2, _hn2 = verdict_tuple
    return bool(hv1) and hv1 == hv2 and hv1 != "Maybe"


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
        return flagged, 0, incomplete, 0
    # Drop rows already settled by humans — they live in the judgment store now, not the
    # live queue. What stays is genuine outstanding work: no verdict, one verdict (awaiting
    # the 2nd reviewer), a disagreement, or a Maybe to reconcile.
    settled_mask = flagged["cve_id"].map(
        lambda c: is_settled(existing.get((cat, norm(c)), ("", "", "", ""))))
    n_settled = int(settled_mask.sum())
    flagged = flagged[~settled_mask].copy()
    if flagged.empty:
        return flagged, 0, incomplete, n_settled
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
    return flagged[cols], len(flagged), incomplete, n_settled


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
    total_flagged = total_incomplete = total_settled = 0
    for mp in merged_files:
        cat = cat_of(mp)
        q, n, inc, settled = build_queue(mp, existing)
        out = os.path.join(os.path.dirname(mp), "02_needs_human_review.csv")
        q.to_csv(out, index=False)
        parts = []
        if settled:
            parts.append(f"{settled} settled -> store")
        if inc:
            parts.append(f"{inc} still incomplete — queue partial")
        note = f" ({'; '.join(parts)})" if parts else ""
        print(f"  {cat:16} {n:4} outstanding -> {out}{note}")
        total_settled += settled
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
            print(f"\nCombined: {total_flagged} outstanding rows "
                  f"(reviewer1={v1}, reviewer2={v2}, both={both}) -> {combined_path}")
        else:
            print("\nNo outstanding rows in any category.")
    if total_settled:
        print(f"Excluded {total_settled} already-settled human row(s) — persisted in "
              f"judgment_store.csv, not the live queue.")
    if total_incomplete:
        print(f"Note: {total_incomplete} rows still incomplete (an AI hasn't reviewed) — not yet queued.")


if __name__ == "__main__":
    main()
