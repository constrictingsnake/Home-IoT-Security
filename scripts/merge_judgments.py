#!/usr/bin/env python3
"""Run the Gemini reviewer (optional) and merge the three per-AI review copies.

Reads claude.csv, codex.csv and gemini.csv (the blind copies produced by
make_review_copies.py and filled in by each reviewer), joins them on cve_id, and writes
a merged file carrying all nine AI columns plus a human-review flag.

With --run-gemini, the Gemini API reviewer is run first (filling gemini.csv in place via
gemini_classify.classify_file), then everything is merged — so one command does the
automated review and the merge together. Without it, this is a pure, dependency-light
merge you can run any time as a "show me current status" view.

Flag rule (set by the project):
    "Needs Human Review" = Yes  when
        BOTH strong reviewers (Claude & Codex) are Low confidence
        OR the 3 judgments are not unanimous (confident disagreement)
    Gemini's confidence is recorded but excluded from the flag (weaker model, skews Low);
    Gemini's judgment still counts toward the unanimity check.

Rows not yet fully reviewed (any of the 3 judgments still blank) are marked
"Review Status = incomplete" and left unflagged (pending), so partial progress is visible
without pretending the row is resolved.

Alongside the merge, a small spot-check sample is written (02_high_confidence_audit.csv):
a random N (default 10) of the "high-confidence" rows — complete, all 3 judgments unanimous,
and both strong reviewers High. These rows are never flagged for human review, so the sample
lets a human audit whether the AIs are confidently wrong. It carries empty Human Verdict /
Human Notes columns to fill in, and the seed keeps the draw reproducible.

Usage:
    # pure merge (status view) + audit sample
    python merge_judgments.py --reviews path/to/reviews
    # run Gemini, then merge, in one command
    GEMINI_API_KEY=... python merge_judgments.py --reviews path/to/reviews \
        --run-gemini --category "security camera"
    python merge_judgments.py --claude a.csv --codex b.csv --gemini c.csv --out merged.csv
"""
import argparse
import csv
import os
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIFF_DIR = os.path.join(ROOT, "data", "difference")
CATEGORIES = os.path.join(ROOT, "data", "categories.csv")

REVIEWERS = ["Claude", "Codex", "Gemini"]
JUDGMENT_FIELDS = ["Judgment", "Confidence", "Reasoning"]

# Confidence from these "strong" models drives the low-confidence flag. Gemini is a weaker
# third model whose self-reported confidence tends to skew Low, which would inflate the
# human-review queue — so its confidence is recorded but NOT counted here. Gemini's *judgment*
# still counts toward the unanimity check.
STRONG_REVIEWERS = ["Claude", "Codex"]


def review_columns(reviewer):
    return [f"{reviewer} {field}" for field in JUDGMENT_FIELDS]


def normalize_cve(value):
    return str(value).strip().upper()


def load_copy(path, reviewer):
    df = pd.read_csv(path, dtype=str).fillna("")
    if "cve_id" not in df.columns:
        raise SystemExit(f"{path}: missing 'cve_id' column")
    missing = [c for c in review_columns(reviewer) if c not in df.columns]
    if missing:
        raise SystemExit(
            f"{path}: missing reviewer columns {missing} — is this the {reviewer} copy?"
        )
    df["_key"] = df["cve_id"].map(normalize_cve)
    return df


def classify_row(row):
    """Return (status, needs_review, reason) for one merged row."""
    judgments = [str(row[f"{r} Judgment"]).strip() for r in REVIEWERS]

    if any(j == "" for j in judgments):
        return "incomplete", "", ""

    # Low-confidence flag uses only the strong reviewers (Gemini's confidence is excluded).
    low_count = sum(
        1 for r in STRONG_REVIEWERS if str(row[f"{r} Confidence"]).strip().lower() == "low"
    )
    distinct = {j.lower() for j in judgments}
    disagree = len(distinct) > 1

    reasons = []
    if low_count >= len(STRONG_REVIEWERS):  # all strong reviewers low (i.e. Claude & Codex)
        reasons.append("both strong reviewers low confidence")
    if disagree:
        reasons.append("judgments not unanimous")

    if reasons:
        return "complete", "Yes", "; ".join(reasons)
    return "complete", "No", ""


def is_high_confidence(row):
    """True when the row is complete, all 3 judgments agree, and both strong reviewers are
    High confidence. These rows are never flagged for human review, so a sample of them is
    drawn for spot-checking (catching confidently-wrong answers)."""
    judgments = [str(row[f"{r} Judgment"]).strip() for r in REVIEWERS]
    if any(j == "" for j in judgments):
        return False
    if len({j.lower() for j in judgments}) > 1:  # not unanimous
        return False
    return all(
        str(row[f"{r} Confidence"]).strip().lower() == "high" for r in STRONG_REVIEWERS
    )


def write_audit_sample(merged, n, seed, out_path):
    """Write a random sample of up to n high-confidence rows for human spot-checking."""
    pool = merged[merged.apply(is_high_confidence, axis=1)].copy()
    take = min(n, len(pool))
    sample = pool.sample(n=take, random_state=seed) if take else pool
    # Focus the sheet for a human: drop the flag columns (all No here), surface the agreed
    # verdict, and add blank columns for the human's answer.
    sample = sample.drop(
        columns=[c for c in ("Review Status", "Needs Human Review", "Review Reason") if c in sample.columns]
    )
    sample.insert(0, "AI Verdict (unanimous)", sample["Claude Judgment"].values)
    sample["Human Verdict"] = ""
    sample["Human Notes"] = ""
    sample.to_csv(out_path, index=False)
    return take, len(pool)


def resolve_paths(args):
    paths = {}
    if args.reviews:
        for r in REVIEWERS:
            paths[r] = os.path.join(args.reviews, f"{r.lower()}.csv")
    for r, override in (("Claude", args.claude), ("Codex", args.codex), ("Gemini", args.gemini)):
        if override:
            paths[r] = override
    return paths


def load_env(root=ROOT):
    """Populate os.environ from a .env file (KEY=VALUE lines) without overwriting existing
    vars — lets --run-gemini pick up GEMINI_API_KEY like the retired shell wrapper did."""
    path = os.path.join(root, ".env")
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


def read_gemini_categories(path=CATEGORIES):
    """Parse categories.csv -> [(slug, label)], preserving file order (deliberately
    smalls-first / cameras-last so a full pass straddles the daily Gemini quota reset)."""
    if not os.path.isfile(path):
        raise SystemExit(f"Categories file not found: {path}")
    out = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            slug = (row.get("slug") or "").strip()
            label = (row.get("label") or "").strip()
            if slug:
                out.append((slug, label or slug))
    return out


def run_gemini_pass(gemini_path, category, args):
    """Fill gemini.csv in place via the API reviewer (resumable; skips already-judged rows)."""
    try:
        # lazy: the Gemini reviewer (and its 'requests' dependency) is only needed here
        from gemini_classify import classify_file, DEFAULT_MODEL
    except ImportError as e:
        raise SystemExit(
            f"--run-gemini needs the Gemini reviewer's dependencies ({e}). Try: pip install requests"
        )
    classify_file(
        gemini_path, category,
        model=args.model or DEFAULT_MODEL,
        rps=args.rps, save_every=args.save_every,
        limit=args.limit, redo=args.redo, batch_size=args.batch_size,
    )


def merge_reviews(paths, out, args):
    """Merge the 3 review copies at `paths` into `out`, print the summary, write the audit sample."""
    # The raw columns are identical across copies; take them from the Claude copy.
    base = load_copy(paths["Claude"], "Claude")
    raw_cols = [c for c in base.columns if c not in review_columns("Claude") and c != "_key"]
    merged = base[["_key"] + raw_cols].copy()

    for r in REVIEWERS:
        df = load_copy(paths[r], r)
        merged = merged.merge(df[["_key"] + review_columns(r)], on="_key", how="left")

    merged = merged.fillna("")
    results = merged.apply(classify_row, axis=1, result_type="expand")
    merged["Review Status"] = results[0]
    merged["Needs Human Review"] = results[1]
    merged["Review Reason"] = results[2]
    merged = merged.drop(columns=["_key"])
    merged.to_csv(out, index=False)

    n = len(merged)
    complete = int((merged["Review Status"] == "complete").sum())
    incomplete = n - complete
    flagged = int((merged["Needs Human Review"] == "Yes").sum())
    print(f"Merged {n} rows -> {out}")
    print(f"  complete:           {complete}/{n}")
    print(f"  incomplete:         {incomplete}/{n}")
    print(f"  needs human review: {flagged} (of {complete} complete)")

    if args.audit_sample and args.audit_sample > 0:
        audit_out = args.audit_out or os.path.join(
            os.path.dirname(os.path.abspath(out)), "02_high_confidence_audit.csv"
        )
        take, pool = write_audit_sample(merged, args.audit_sample, args.seed, audit_out)
        print(f"  high-conf audit:    {take} of {pool} high-confidence rows -> {audit_out}")


def main():
    ap = argparse.ArgumentParser(
        description="Merge per-AI review copies into a triple-checked file."
    )
    ap.add_argument("--all", action="store_true",
                    help="Iterate every category in data/categories.csv (folds in the old "
                         "run_gemma_column.sh loop). With --run-gemini the per-category label from "
                         "that file is used, so --category is not needed.")
    ap.add_argument("--reviews", help="Directory holding claude.csv / codex.csv / gemini.csv")
    ap.add_argument("--claude", help="Path to the Claude copy (overrides --reviews)")
    ap.add_argument("--codex", help="Path to the Codex copy (overrides --reviews)")
    ap.add_argument("--gemini", help="Path to the Gemini copy (overrides --reviews)")
    ap.add_argument("--out", default=None, help="Output path (default: <reviews>/../02_merged.csv)")
    ap.add_argument("--audit-sample", type=int, default=10,
                    help="Write a random sample of N high-confidence rows for human spot-checking (0 to disable)")
    ap.add_argument("--audit-out", default=None,
                    help="Audit sample path (default: <merged dir>/02_high_confidence_audit.csv)")
    ap.add_argument("--seed", type=int, default=42, help="Random seed for the audit sample (reproducible)")
    # Run the Gemini API reviewer before merging (one command does both)
    gem = ap.add_argument_group("Gemini reviewer (use --run-gemini to enable)")
    gem.add_argument("--run-gemini", action="store_true", help="Classify the Gemini copy via the API, then merge")
    gem.add_argument("--category", help="Device category passed to Gemini, e.g. 'security camera' (required with --run-gemini)")
    gem.add_argument("--model", default=None, help="Gemini model id (default: gemini_classify.DEFAULT_MODEL)")
    gem.add_argument("--rps", type=float, default=1.0, help="Gemini max requests per second")
    gem.add_argument("--save-every", type=int, default=25, help="Gemini: flush progress every N rows")
    gem.add_argument("--limit", type=int, default=0, help="Gemini: classify only the first N pending rows")
    gem.add_argument("--redo", action="store_true", help="Gemini: re-classify rows that already have a judgment")
    gem.add_argument("--batch-size", type=int, default=1,
                     help="Gemini: rows per API call (try 20 to cut round-trips ~20x)")
    args = ap.parse_args()

    if args.all:
        # --all iterates the category map itself, so per-target overrides make no sense.
        for bad, name in ((args.reviews, "--reviews"), (args.claude, "--claude"),
                          (args.codex, "--codex"), (args.gemini, "--gemini"),
                          (args.out, "--out"), (args.audit_out, "--audit-out"),
                          (args.category, "--category")):
            if bad:
                ap.error(f"{name} cannot be combined with --all")
        if args.run_gemini:
            load_env()
        cats = read_gemini_categories()
        done = skipped = 0
        for slug, label in cats:
            reviews_dir = os.path.join(DIFF_DIR, slug, "reviews")
            paths = {r: os.path.join(reviews_dir, f"{r.lower()}.csv") for r in REVIEWERS}
            if not os.path.isdir(reviews_dir) or any(not os.path.isfile(p) for p in paths.values()):
                print(f"=== {slug} — SKIP (no review copies; run make_review_copies.py first)")
                skipped += 1
                continue
            print(f"\n=== {slug} ({label}) ===")
            if args.run_gemini:
                print("==> Gemini review")
                try:
                    run_gemini_pass(paths["Gemini"], label, args)
                except (RuntimeError, FileNotFoundError, ValueError, SystemExit) as e:
                    print(f"  Gemini FAILED for {slug}: {e} — merging what exists")
                print("==> Merge")
            merge_reviews(paths, os.path.join(DIFF_DIR, slug, "02_merged.csv"), args)
            done += 1
        print(f"\nDone. {done} merged, {skipped} skipped ({len(cats)} categories).")
        return

    paths = resolve_paths(args)
    for r in REVIEWERS:
        if not paths.get(r) or not os.path.isfile(paths[r]):
            ap.error(f"Missing {r} review copy (got: {paths.get(r)})")

    if args.run_gemini:
        if not args.category:
            ap.error("--category is required with --run-gemini")
        load_env()
        print("==> Gemini review")
        try:
            run_gemini_pass(paths["Gemini"], args.category, args)
        except (RuntimeError, FileNotFoundError, ValueError) as e:
            ap.error(str(e))
        print("==> Merge")

    out = args.out
    if not out:
        if args.reviews:
            parent = os.path.dirname(os.path.abspath(args.reviews.rstrip(os.sep)))
            out = os.path.join(parent, "02_merged.csv")
        else:
            out = "02_merged.csv"
    merge_reviews(paths, out, args)


if __name__ == "__main__":
    main()
