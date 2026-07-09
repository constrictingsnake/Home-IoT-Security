#!/usr/bin/env python3
"""Stage 8 (reverse) — per-term precision from settled judgments.

Turns the term attribution written by the two builders (the `matched_terms` column in
keyword_<cat>.csv / results_all_<cat>.csv) into a precision score for every search term,
so a noisy term shows up as a line item ("term with a 90%+ false-positive rate") instead
of requiring a manual disagreement autopsy.

How it works (Option B — attribution stays at the builder, join at report time):
  1. Read final_resolved.csv (settled Yes/No per CVE, with Category + Difference Type).
  2. For each judged row, look up which term(s) pulled that CVE in — from the matching
     builder output(s) chosen by direction:
        vendor_only  -> results_all_<cat>.csv                (vendor-term precision)
        keyword_only -> keyword_<cat>.csv                    (keyword-term precision)
        intersection -> BOTH of the above (matched by both methods, so it attributes to
                        its vendor term(s) AND its keyword term(s))
  3. Tally, per (method, category, term): how many judged CVEs it matched and how many
     were confirmed Yes. A CVE hit by two terms counts toward both (each term "owns" it).

precision = n_yes / n_judged. A term is flagged a *prune candidate* when it has been
judged on enough rows (--min-n, default 5) and its precision is at or below --threshold
(default 0.10) — i.e. it drags in mostly false positives.

Scope note. final_resolved.csv covers the difference set (vendor_only/keyword_only) plus
the intersection audit direction — cpe_expansion rows are excluded here since a CPE-expansion
candidate isn't attributable to a search term. So this is per-term precision on a term's
difference-set + intersection matches, not literally every CVE it ever matched — still a
prioritized prune list, not a global precision.

Usage:
    python scripts/term_precision.py
    python scripts/term_precision.py --min-n 3 --threshold 0.15
    python scripts/term_precision.py --diff-dir data/difference
"""
import argparse
import os
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR_DIR = os.path.join(ROOT, "data", "vendor-search")
KEYWORD_DIR = os.path.join(ROOT, "data", "keyword-search")
DEFAULT_DIFF_DIR = os.path.join(ROOT, "data", "difference")

MATCHED_TERMS_COL = "matched_terms"

# direction -> method(s) whose builder output(s) attribute its matched_terms.
# intersection rows were matched by BOTH methods, so they attribute to both.
DIRECTIONS = {
    "vendor_only": ("vendor",),
    "keyword_only": ("keyword",),
    "intersection": ("vendor", "keyword"),
}


def _norm(cve):
    return str(cve).strip().upper()


def _builder_path(method, category):
    if method == "vendor":
        return os.path.join(VENDOR_DIR, f"results_all_{category}.csv")
    return os.path.join(KEYWORD_DIR, f"keyword_{category}.csv")


def load_term_map(method, category, cache):
    """Return {CVE-ID -> [terms]} for one category's builder output, or {} if the file
    or the matched_terms column is missing (warned once). Results are cached."""
    key = (method, category)
    if key in cache:
        return cache[key]

    path = _builder_path(method, category)
    term_map = {}
    if not os.path.isfile(path):
        print(f"  ! {method}/{category}: builder output not found ({os.path.relpath(path, ROOT)}) "
              "— terms unattributable, skipping")
    else:
        df = pd.read_excel(path) if path.endswith(".xlsx") else pd.read_csv(path)
        if MATCHED_TERMS_COL not in df.columns:
            print(f"  ! {method}/{category}: no '{MATCHED_TERMS_COL}' column in "
                  f"{os.path.basename(path)} — rebuild with the updated builder to attribute terms")
        else:
            for _, r in df.iterrows():
                cid = _norm(r.get("cve_id", ""))
                raw = str(r.get(MATCHED_TERMS_COL, "") or "")
                terms = [t for t in raw.split("|") if t]
                if cid and terms:
                    term_map[cid] = terms
    cache[key] = term_map
    return term_map


def main():
    ap = argparse.ArgumentParser(description="Per-term precision from settled judgments.")
    ap.add_argument("--diff-dir", default=DEFAULT_DIFF_DIR,
                    help=f"Difference dir holding final_resolved.csv (default: {os.path.relpath(DEFAULT_DIFF_DIR, ROOT)})")
    ap.add_argument("--out", default=None,
                    help="Output CSV (default: <diff-dir>/term_precision.csv)")
    ap.add_argument("--min-n", type=int, default=5,
                    help="Min judged rows before a term can be a prune candidate (default: 5)")
    ap.add_argument("--threshold", type=float, default=0.10,
                    help="Precision at or below this flags a prune candidate (default: 0.10)")
    args = ap.parse_args()

    final_path = os.path.join(args.diff_dir, "final_resolved.csv")
    if not os.path.isfile(final_path):
        raise SystemExit(f"final_resolved.csv not found at {final_path} — run finalize_judgments.py first.")

    final = pd.read_csv(final_path, dtype=str).fillna("")
    for col in ("Category", "Difference Type", "cve_id", "Final Judgment"):
        if col not in final.columns:
            raise SystemExit(f"{final_path}: missing expected column '{col}'")

    # tally[(method, category, term)] = [n_yes, n_judged]
    tally = {}
    cache = {}
    unattributed = 0
    for _, row in final.iterrows():
        verdict = str(row["Final Judgment"]).strip()
        if verdict not in ("Yes", "No"):      # skip Maybe / pending / incomplete / blank
            continue
        direction = str(row["Difference Type"]).strip()
        methods = DIRECTIONS.get(direction)
        if methods is None:
            continue
        category = str(row["Category"]).strip()
        cid = _norm(row["cve_id"])
        row_attributed = False
        for method in methods:
            terms = load_term_map(method, category, cache).get(cid)
            if not terms:
                continue
            row_attributed = True
            for term in terms:
                key = (method, category, term)
                slot = tally.setdefault(key, [0, 0])
                slot[1] += 1                     # n_judged
                if verdict == "Yes":
                    slot[0] += 1                 # n_yes
        if not row_attributed:
            unattributed += 1

    if not tally:
        print("\nNo attributable judged rows found. Rebuild the builder outputs with "
              "build_search.py (so keyword_<cat>.csv "
              "and results_all_<cat>.csv carry the matched_terms column), then re-run the "
              "Stage-4 pipeline and this report.")
        return

    records = []
    for (method, category, term), (n_yes, n_judged) in tally.items():
        precision = n_yes / n_judged if n_judged else 0.0
        prune = n_judged >= args.min_n and precision <= args.threshold
        records.append({
            "method": method,
            "category": category,
            "term": term,
            "n_judged": n_judged,
            "n_yes": n_yes,
            "n_no": n_judged - n_yes,
            "precision": round(precision, 3),
            "prune_candidate": "Yes" if prune else "",
        })

    out_df = pd.DataFrame(records).sort_values(
        ["prune_candidate", "precision", "n_judged"],
        ascending=[False, True, False],
    ).reset_index(drop=True)

    out = args.out or os.path.join(args.diff_dir, "term_precision.csv")
    out_df.to_csv(out, index=False)

    prunes = out_df[out_df["prune_candidate"] == "Yes"]
    print(f"\nScored {len(out_df)} term(s) across "
          f"{out_df['category'].nunique()} categor(y/ies) -> {out}")
    if unattributed:
        print(f"  ({unattributed} judged row(s) had no attributable term — likely built "
              "before the matched_terms column existed)")
    if len(prunes):
        print(f"\n{len(prunes)} prune candidate(s) "
              f"(n_judged >= {args.min_n}, precision <= {args.threshold:.0%}):")
        for _, r in prunes.iterrows():
            print(f"  {r['method']:7} {r['category']:14} {r['term']:24} "
                  f"precision={r['precision']:.0%}  ({r['n_yes']}/{r['n_judged']} Yes)")
    else:
        print("  No prune candidates at the current thresholds.")


if __name__ == "__main__":
    main()
