#!/usr/bin/env python3
"""Orchestrator for the two idempotent halves of the review pipeline.

    python3 scripts/pipeline.py refresh   # rebuild search -> review sets -> CPE expansion ->
                                          #   blind copies, then STOP for manual Claude/Codex review
    python3 scripts/pipeline.py settle    # Gemini + merge -> extract human queue -> finalize
    python3 scripts/pipeline.py status    # per-category term coverage (computed, not stored)
    python3 scripts/pipeline.py discover-vendors --all   # mine CPE vendors missing from
                                          #   vendor_terms.csv (candidate list only, manual, optional)

Every underlying step is idempotent and judgment-preserving (settled judgments are restored
from judgment_store.csv / carried human verdicts), so re-running is safe. The only points a
human is required are the two manual pauses this orchestrator brackets:
  * after `refresh`  — fill the blank Claude/Codex judgments (the two manual reviewers)
  * within `settle`  — adjudicate the flagged rows in human_review_queue.csv, then re-run settle

`refresh` chains: build_search.py -> build_review_sets.py --direction all --overwrite ->
cpe_expansion.py --all -> make_review_copies.py --all --refresh.
`settle` chains: merge_judgments.py --all [--run-gemini] -> extract_human_review.py ->
finalize_judgments.py.
`status` computes each category's term coverage (keyword_terms.csv / vendor_terms.csv) live —
replaces the old hand-maintained ①②③④ tags in CLAUDE.md's category table, which could drift
out of sync with the actual term files.
`discover-vendors` runs cpe_brand_mining.py — NOT chained into refresh/settle, since accepting
a candidate vendor is a human decision (it writes vendor_candidates.csv only, never edits
vendor_terms.csv). Run it whenever, then hand-add accepted terms and re-run `refresh`.
`mine-keywords` runs keyword_mining.py — same story, mirrored for Stage 1: it writes
keyword_candidates.csv (+ keyword_candidates_brands.csv) only, never edits keyword_terms.csv.
"""
import argparse
import glob
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DIFF_DIR = os.path.join(ROOT, "data", "difference")
CATEGORIES = os.path.join(ROOT, "data", "categories.csv")


def run(cmd):
    """Run one pipeline step (a script + args) with the repo root as CWD; stop on failure."""
    print("\n$ python3 " + " ".join(os.path.relpath(c, ROOT) if c.startswith(HERE) else c for c in cmd))
    result = subprocess.run([sys.executable] + cmd, cwd=ROOT)
    if result.returncode != 0:
        sys.exit(f"\n✗ step failed (exit {result.returncode}): {' '.join(cmd)}")


def script(name):
    return os.path.join(HERE, name)


def blank_row_summary():
    """Report, per category, how many review rows still lack a Claude / Codex judgment."""
    import pandas as pd
    print("\n--- Blank rows awaiting manual review (Claude / Codex) ---")
    grand = 0
    for reviews in sorted(glob.glob(os.path.join(DIFF_DIR, "*", "reviews"))):
        cat = os.path.basename(os.path.dirname(reviews))
        cl, cx = os.path.join(reviews, "claude.csv"), os.path.join(reviews, "codex.csv")
        if not (os.path.isfile(cl) and os.path.isfile(cx)):
            continue
        cldf = pd.read_csv(cl, dtype=str).fillna("")
        cxdf = pd.read_csv(cx, dtype=str).fillna("")
        cl_blank = int((cldf["Claude Judgment"] == "").sum()) if "Claude Judgment" in cldf.columns else len(cldf)
        cx_blank = int((cxdf["Codex Judgment"] == "").sum()) if "Codex Judgment" in cxdf.columns else len(cxdf)
        if cl_blank or cx_blank:
            print(f"  {cat:16s} claude={cl_blank:4d}  codex={cx_blank:4d}")
            grand += max(cl_blank, cx_blank)
    print(f"  -> ~{grand} rows still need a manual judgment.")


def cmd_refresh(args):
    search = [script("build_search.py")]
    if args.rebuild_search:
        search.append("--overwrite")
    run(search)
    run([script("build_review_sets.py"), CATEGORIES, "--direction", "all", "--overwrite"])
    run([script("cpe_expansion.py"), "--all"])
    run([script("make_review_copies.py"), "--all", "--refresh"])
    blank_row_summary()
    print("\n✓ refresh complete — fill the blank Claude/Codex judgments, then run: "
          "python3 scripts/pipeline.py settle")


def cmd_settle(args):
    merge = [script("merge_judgments.py"), "--all"]
    if not args.no_gemini:
        merge.append("--run-gemini")
        if args.model:
            merge += ["--model", args.model]
        if args.rps is not None:
            merge += ["--rps", str(args.rps)]
    run(merge)
    run([script("extract_human_review.py")])
    run([script("finalize_judgments.py")])
    print("\n✓ settle complete — adjudicate flagged rows in "
          "data/difference/human_review_queue.csv (fill Human Verdict), then re-run settle to finalize.")


STATUS_LABELS = {
    (True, True): "① in both searches",
    (True, False): "② keyword exists, needs vendor",
    (False, True): "③ vendor exists, needs keywords",
    (False, False): "④ needs both",
}


def cmd_status(args):
    """Per-category term coverage, computed live from keyword_terms.csv / vendor_terms.csv
    (no separately-maintained status field to go stale)."""
    from build_search import read_terms, METHODS
    from build_review_sets import read_categories

    keyword_terms = read_terms(METHODS["keyword"]["terms"])
    vendor_terms = read_terms(METHODS["vendor"]["terms"])
    categories = read_categories(CATEGORIES)

    print(f"{'slug':<16}status")
    for slug in categories:
        has_kw = bool(keyword_terms.get(slug))
        has_vn = bool(vendor_terms.get(slug))
        print(f"  {slug:<16}{STATUS_LABELS[(has_kw, has_vn)]}")


def cmd_discover_vendors(args):
    cmd = [script("cpe_brand_mining.py")]
    cmd += ["--all"] if args.all else args.categories
    if args.min_evidence != 1:
        cmd += ["--min-evidence", str(args.min_evidence)]
    run(cmd)
    print("\n✓ candidates written to data/vendor-search/vendor_candidates.csv — review, hand-add "
          "accepted vendors to data/vendor-search/vendor_terms.csv, then run: "
          "python3 scripts/pipeline.py refresh")


def cmd_mine_keywords(args):
    cmd = [script("keyword_mining.py")]
    cmd += ["--all"] if args.all else args.categories
    if args.top != 50:
        cmd += ["--top", str(args.top)]
    if args.min_yes != 3:
        cmd += ["--min-yes", str(args.min_yes)]
    run(cmd)
    print("\n✓ candidates written to data/keyword-search/keyword_candidates.csv — review, hand-add "
          "accepted phrases to data/keyword-search/keyword_terms.csv, then run: "
          "python3 scripts/pipeline.py refresh")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    r = sub.add_parser("refresh", help="Rebuild all inputs and blind review copies, then pause.")
    r.add_argument("--rebuild-search", action="store_true",
                   help="Force build_search to --overwrite (recompute searches; default: build only missing).")
    r.set_defaults(func=cmd_refresh)

    s = sub.add_parser("settle", help="Run Gemini + merge, extract the human queue, finalize.")
    s.add_argument("--no-gemini", action="store_true",
                   help="Skip the Gemini pass (merge existing judgments only).")
    s.add_argument("--model", default=None, help="Gemini model id passed through to merge_judgments.")
    s.add_argument("--rps", type=float, default=None, help="Gemini requests/sec passed through.")
    s.set_defaults(func=cmd_settle)

    st = sub.add_parser("status", help="Per-category term coverage, computed live.")
    st.set_defaults(func=cmd_status)

    dv = sub.add_parser("discover-vendors",
                        help="Mine CPE vendors missing from vendor_terms.csv (candidate list only).")
    dv.add_argument("categories", nargs="*", help="category slug(s); omit when using --all")
    dv.add_argument("--all", action="store_true", help="every category in categories.csv")
    dv.add_argument("--min-evidence", type=int, default=1,
                    help="min distinct evidence CVEs required (default: 1)")
    dv.set_defaults(func=cmd_discover_vendors)

    mk = sub.add_parser("mine-keywords",
                        help="Mine device-type phrases missing from keyword_terms.csv (candidate list only).")
    mk.add_argument("categories", nargs="*", help="category slug(s); omit when using --all")
    mk.add_argument("--all", action="store_true", help="every category in categories.csv")
    mk.add_argument("--top", type=int, default=50,
                    help="max candidates kept per category before yield scoring (default: 50)")
    mk.add_argument("--min-yes", type=int, default=3,
                    help="min Yes-doc frequency required for a candidate (default: 3)")
    mk.set_defaults(func=cmd_mine_keywords)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
