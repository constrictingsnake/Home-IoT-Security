#!/usr/bin/env python3
"""Fold human verdicts back in to produce one settled judgment per CVE.

Collapses each category's merged triple-AI file into a single `Final Judgment` using
(first match wins):

    both humans agree (not Maybe)               -> the agreed verdict     (Final Source = human)
    settled `human` in judgment_store.csv       -> the stored verdict     (Final Source = human)
    flagged, no settled human verdict           -> pending                (Final Source = pending)
    not flagged, all 3 AIs unanimous            -> the AI consensus       (Final Source = ai-consensus)
    not flagged, lone Gemini dissent            -> Claude/Codex verdict   (Final Source = strong-consensus)
    a reviewer hasn't judged yet (incomplete)   -> blank                  (Final Source = incomplete)

Human verdicts are STICKY: once a row settled as `human` (in the store), it stays `human`
even if a flag-rule change later unflags it or the queue sheets are regenerated without it —
a fresh, different queue verdict is the only thing that supersedes it. `strong-consensus`
is the relaxed-rule class (see merge_judgments.py: Claude & Codex agree on Yes/No at High
confidence, Gemini sole dissenter — validated 99.7% against human verdicts).

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

After each run, upserts settled AI judgments + Final Judgment AND the raw human verdicts
(Human Verdict/Notes 1 & 2) into judgment_store.csv (keyed by (category, cve_id)) so they
survive 01_raw.csv regenerations. The store is the durable home for human answers: because
they live here, extract_human_review.py can drop already-reviewed rows from the live queue
without losing them. Run finalize BEFORE extract (pipeline.py settle does) so a freshly
filled verdict is persisted here before the queue is regenerated to exclude it.

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

HUMAN_COLS = ["Human Verdict 1", "Human Notes 1", "Human Verdict 2", "Human Notes 2"]

STORE_COLS = [
    "category", "cve_id", "Difference Type",
    "Claude Judgment", "Claude Confidence", "Claude Reasoning",
    "Codex Judgment", "Codex Confidence", "Codex Reasoning",
    "Gemini Judgment", "Gemini Confidence", "Gemini Reasoning",
    "Final Judgment", "Final Source",
] + HUMAN_COLS + ["Excluded"]


def cat_of(merged_path):
    return os.path.basename(os.path.dirname(merged_path))


def load_human_verdicts(diff_dir, store_path):
    """Return {(category, CVE-ID): (verdict1, notes1, verdict2, notes2)} from filled cells.

    Sources, lowest to highest priority: the persistent judgment store (so verdicts of
    rows that have already dropped out of the live queue are still folded in), then the
    combined queue and per-category sheets (fresher — a human just edited them, so they
    win over the store). Sheets on the old single-reviewer schema (Human Verdict) are read
    as Reviewer 1's answer; Reviewer 2 comes back blank for those rows.
    """
    store_v = {}    # from the persistent store (baseline)
    sheet_v = {}    # from the live sheets (authoritative)
    origin = {}     # key -> sheet path, for conflict messages

    def read_cell(r, col, cat, cve):
        hv = str(r.get(col, "")).strip()
        if hv and hv not in VALID:
            print(f"  ! {cat}/{cve}: invalid {col} '{hv}' (want Yes/No/Maybe) — skipped")
            return ""
        return hv

    def ingest(path, category, dest, warn):
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
            cat = (category if category is not None
                   else str(r.get("Category", "")).strip() or str(r.get("category", "")).strip())
            cve = str(r["cve_id"]).strip().upper()
            key = (cat, cve)
            if has_v2:
                hv1 = read_cell(r, "Human Verdict 1", cat, cve)
                hn1 = str(r.get("Human Notes 1", "")).strip()
                hv2 = read_cell(r, "Human Verdict 2", cat, cve)
                hn2 = str(r.get("Human Notes 2", "")).strip()
            else:
                hv1 = read_cell(r, "Human Verdict", cat, cve)
                hn1 = str(r.get("Human Notes", "")).strip()
                hv2 = hn2 = ""
            if not any((hv1, hn1, hv2, hn2)):
                continue
            tup = (hv1, hn1, hv2, hn2)
            if warn and key in dest and dest[key] != tup:
                print(f"  ! conflict for {cat}/{cve}: {dest[key]} ({origin[key]}) "
                      f"vs {tup} ({os.path.basename(path)}) — keeping first")
                continue
            dest.setdefault(key, tup)
            if warn:
                origin.setdefault(key, os.path.basename(path))

    ingest(store_path, category=None, dest=store_v, warn=False)
    ingest(os.path.join(diff_dir, "human_review_queue.csv"), category=None, dest=sheet_v, warn=True)
    for p in sorted(glob.glob(os.path.join(diff_dir, "*", "02_needs_human_review.csv"))):
        cat = os.path.basename(os.path.dirname(p))
        ingest(p, category=cat, dest=sheet_v, warn=True)
    return {**store_v, **sheet_v}


def resolve_row(row, cat, human, prior_human):
    status = str(row.get("Review Status", "")).strip()
    if status == "incomplete":
        return "", "incomplete"
    key = (cat, str(row["cve_id"]).strip().upper())
    hv1, _hn1, hv2, _hn2 = human.get(key, ("", "", "", ""))
    # A fresh queue verdict settles only when both reviewers have weighed in, agree, and it
    # isn't "Maybe" — same unanimity bar as the AI triple review. It wins over everything,
    # flagged or not (so a row that was human-settled before the flag rule relaxed keeps its
    # human verdict, and a human can still overrule an unflagged row via the queue sheet).
    if hv1 and hv2 and hv1 == hv2 and hv1 != "Maybe":
        return hv1, "human"
    # Sticky human verdicts: settled `human` rows in the store stay human even if the queue
    # sheets were regenerated without them or the flag rule no longer flags the row.
    if key in prior_human:
        return prior_human[key], "human"
    if str(row.get("Needs Human Review", "")).strip() == "Yes":
        return "", "pending"
    judgments = {
        str(row.get(f"{r} Judgment", "")).strip().lower() for r in ("Claude", "Codex", "Gemini")
    }
    # Unflagged + not unanimous = the relaxed-rule class (Claude & Codex agree at High,
    # Gemini sole dissenter) — resolve to the strong consensus, with a distinct source so
    # it stays measurable.
    source = "ai-consensus" if len(judgments) == 1 else "strong-consensus"
    return str(row.get("Claude Judgment", "")).strip(), source


def finalize(merged_path, human, prior_human):
    cat = cat_of(merged_path)
    df = pd.read_csv(merged_path, dtype=str).fillna("")
    if df.empty:
        df["Final Judgment"] = []
        df["Final Source"] = []
        return cat, df
    res = df.apply(lambda r: resolve_row(r, cat, human, prior_human), axis=1, result_type="expand")
    df["Final Judgment"] = res[0]
    df["Final Source"] = res[1]
    return cat, df


def upsert_store(df, cat, store_path, human):
    """True upsert into judgment_store.csv, keyed (category, cve_id): rows present in df
    update their store row (or insert); store rows ABSENT from df are retained. Retention
    is the point of the store (see the refresh invariant in CLAUDE.md) — 01_raw.csv files
    get pruned/regenerated, and settled judgments must outlive them. (Earlier versions
    replaced the whole category here, silently deleting settled rows whose CVE had been
    pruned from the raws.)

    The four Human Verdict/Notes columns are persisted here too, sourced from `human`
    (queue sheets + prior store). This is what lets the live queue drop already-reviewed
    rows without losing the raw per-reviewer answers — the store becomes their home.

    `Excluded` (scope-exclusion reason, e.g. scope:tvos-2026-07; blank = in scope) is set
    only by mark_excluded.py, never derived from df — so it must be read from the PRIOR
    store and stamped onto new_rows before the old rows are dropped, or a plain `settle`
    run would silently wipe every flag (see docs/plans/PLAN_scope_exclusion.md)."""
    if os.path.isfile(store_path):
        store = pd.read_csv(store_path, dtype=str).fillna("")
    else:
        store = pd.DataFrame(columns=STORE_COLS)

    prior_excluded = {}
    if len(store) and "Excluded" in store.columns:
        for _, r in store.iterrows():
            ex = str(r.get("Excluded", "")).strip()
            if ex:
                prior_excluded[(str(r["category"]).strip(), str(r["cve_id"]).strip().upper())] = ex

    new_df = df.copy()
    new_df["category"] = cat
    # Attach the raw human cells for each row from the resolved `human` map.
    for col in HUMAN_COLS:
        new_df[col] = ""
    new_df["Excluded"] = ""
    for idx, cve in new_df["cve_id"].items():
        hv1, hn1, hv2, hn2 = human.get((cat, str(cve).strip().upper()), ("", "", "", ""))
        new_df.at[idx, "Human Verdict 1"] = hv1
        new_df.at[idx, "Human Notes 1"] = hn1
        new_df.at[idx, "Human Verdict 2"] = hv2
        new_df.at[idx, "Human Notes 2"] = hn2
        new_df.at[idx, "Excluded"] = prior_excluded.get((cat, str(cve).strip().upper()), "")
    keep = ["category", "cve_id"] + [c for c in STORE_COLS[2:] if c in new_df.columns]
    new_rows = new_df[keep]

    def keys(frame):
        return frame["category"].str.strip() + "\x00" + frame["cve_id"].str.strip().str.upper()

    if len(store):
        store = store[~keys(store).isin(set(keys(new_rows)))]
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

    store_path = os.path.join(args.diff_dir, "judgment_store.csv")

    print("Loading human verdicts ...")
    human = load_human_verdicts(args.diff_dir, store_path)
    print(f"  {len(human)} human verdict(s) found\n")

    # Sticky human verdicts (see resolve_row): remember which rows the store already
    # settled as `human` BEFORE this run's upserts replace the category's rows.
    # Also collect prior `Excluded` reasons (set only by mark_excluded.py) so a scope
    # exclusion survives this run and can be dropped from 03_final.csv/final_resolved.csv —
    # see docs/plans/PLAN_scope_exclusion.md.
    prior_human = {}
    prior_excluded = {}
    if os.path.isfile(store_path):
        sdf = pd.read_csv(store_path, dtype=str).fillna("")
        for _, r in sdf.iterrows():
            cat_key = str(r.get("category", "")).strip()
            cve_key = str(r.get("cve_id", "")).strip().upper()
            fj = str(r.get("Final Judgment", "")).strip()
            if str(r.get("Final Source", "")).strip() == "human" and fj:
                prior_human[(cat_key, cve_key)] = fj
            ex = str(r.get("Excluded", "")).strip()
            if ex:
                prior_excluded[(cat_key, cve_key)] = ex

    combined = []
    grand = Counter()

    for mp in merged_files:
        cat, df = finalize(mp, human, prior_human)
        c = Counter(df["Final Source"])
        grand.update(c)
        excluded_mask = df["cve_id"].map(
            lambda cve: (cat, str(cve).strip().upper()) in prior_excluded)
        n_excluded = int(excluded_mask.sum())
        upsert_store(df, cat, store_path, human)
        df = df[~excluded_mask].copy()
        out = os.path.join(os.path.dirname(mp), "03_final.csv")
        df.to_csv(out, index=False)
        pend = c.get("pending", 0)
        flag = f"  ({pend} pending human input)" if pend else ""
        excl = f"  (excluded: {n_excluded})" if n_excluded else ""
        resolved = c.get("ai-consensus", 0) + c.get("strong-consensus", 0) + c.get("human", 0)
        print(f"  {cat:16} resolved={resolved:4} "
              f"[ai={c.get('ai-consensus',0)}, strong={c.get('strong-consensus',0)}, "
              f"human={c.get('human',0)}], "
              f"incomplete={c.get('incomplete',0)}{flag}{excl}")
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
