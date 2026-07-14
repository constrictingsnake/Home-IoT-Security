#!/usr/bin/env python3
"""CVSS score analysis over confirmed-Yes CVEs.

Replicates RQ2 of the transportation IoT device study (Yih, Goseva-Popstojanova
& Cukier — Onboarding-Docs/transportation_device_study.pdf, Section V): per-
category CVSS score distributions and severity buckets, plus a Kruskal-Wallis
omnibus test with Dunn's post-hoc pairwise comparisons.

Method (paper-faithful):
  1. Take every (category, cve_id) with Final Judgment = Yes in
     judgment_store.csv — the same confirmed-Yes population cwe888_analysis.py
     uses, so RQ1/RQ2 stay comparable. Unlike a CWE attribution, a CVSS score
     is a property of the CVE itself, not attribution-weighted: a CVE
     confirmed in several categories counts once per category (same
     convention the CWE script uses).
  2. Look up cvss_score / cvss_version for each CVE in the fixed NVD snapshot.
  3. Per category: n confirmed, n with a score, mean/median/std/min/max/
     quartiles, and the NVD v3 qualitative severity buckets (None/Low/Medium/
     High/Critical/Unscored — same thresholds as nvd_stats.py's
     severity_bucket, so the two reports agree).
  4. Kruskal-Wallis across every category with >= --min-n scored CVEs
     (default 5 — the paper's smallest category had 24); if the omnibus test
     is significant, Dunn's post-hoc test (rank-based, tie-corrected,
     two-sided, Bonferroni-adjusted across all pairs) on every pair of
     qualifying categories.

Outputs (default under data/difference/):
  cvss_distribution.csv   — category, n_cves, n_scored, mean, median, std,
                            min, q1, median, q3, max
  cvss_severity.csv        — long form: category, severity, n, pct
  cvss_dunn_pairwise.csv   — cat_a, cat_b, n_a, n_b, z, p, p_bonferroni, sig
                            (only written if the omnibus test is significant)
  cvss_matrix.md           — summary table (paper's Fig 6/7 as numbers) +
                            Kruskal-Wallis result + significant Dunn's pairs

Usage:
    python3 scripts/cvss_analysis.py
    python3 scripts/cvss_analysis.py --category cameras --category thermostat
    python3 scripts/cvss_analysis.py --min-n 10
"""
import argparse
import csv
import os
import statistics
import sys
from collections import Counter, defaultdict

import scipy.stats as st

csv.field_size_limit(sys.maxsize)     # snapshot cpe_strings fields exceed the default

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_STORE = os.path.join(ROOT, "data", "difference", "judgment_store.csv")
DEFAULT_SNAPSHOT = os.path.join(ROOT, "data", "nvd-snapshot", "nvd_all.csv")
DEFAULT_CATEGORIES = os.path.join(ROOT, "data", "categories.csv")
DEFAULT_OUT_DIR = os.path.join(ROOT, "data", "difference")

# NVD v3 qualitative severity ranges — matches scripts/nvd_stats.py exactly
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "None", "Unscored"]


def severity_bucket(score):
    if score is None:
        return "Unscored"
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


# ------------------------------------------------------------- Dunn's test

def dunn_pairwise(groups):
    """Dunn's post-hoc test (tie-corrected, two-sided) on {name: [scores]}.

    Standard rank-based Dunn's test: pool all scores, rank with average ranks
    for ties, compare mean ranks pairwise against a normal approximation,
    Bonferroni-adjust across all pairs. Returns rows sorted by ascending
    Bonferroni-adjusted p-value.
    """
    names = sorted(groups)
    pooled = []
    offsets = {}
    idx = 0
    for name in names:
        vals = groups[name]
        offsets[name] = (idx, idx + len(vals))
        pooled.extend(vals)
        idx += len(vals)

    N = len(pooled)
    ranks = st.rankdata(pooled)
    mean_rank = {name: sum(ranks[lo:hi]) / (hi - lo) for name, (lo, hi) in offsets.items()}

    tie_counts = Counter(pooled).values()
    tie_term = sum(c ** 3 - c for c in tie_counts)
    sigma_correction = 1 - tie_term / (N ** 3 - N) if N > 1 else 1.0

    pairs = []
    n_pairs = len(names) * (len(names) - 1) // 2
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            n_a, n_b = len(groups[a]), len(groups[b])
            se = ((N * (N + 1) / 12) * sigma_correction * (1 / n_a + 1 / n_b)) ** 0.5
            z = (mean_rank[a] - mean_rank[b]) / se if se else 0.0
            p = 2 * st.norm.sf(abs(z))
            p_bonf = min(1.0, p * n_pairs)
            pairs.append({
                "cat_a": a, "cat_b": b, "n_a": n_a, "n_b": n_b,
                "z": round(z, 3), "p": p, "p_bonferroni": p_bonf,
                "sig": p_bonf < 0.05,
            })
    pairs.sort(key=lambda r: r["p_bonferroni"])
    return pairs


# ------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(
        description="CVSS score distribution + Kruskal-Wallis/Dunn's test over confirmed-Yes CVEs.")
    ap.add_argument("--store", default=DEFAULT_STORE,
                    help="Judgment store CSV (default: data/difference/judgment_store.csv)")
    ap.add_argument("--snapshot", default=DEFAULT_SNAPSHOT,
                    help="NVD snapshot CSV with cvss_score (default: data/nvd-snapshot/nvd_all.csv)")
    ap.add_argument("--categories", default=DEFAULT_CATEGORIES,
                    help="categories.csv for ordering/labels (default: data/categories.csv)")
    ap.add_argument("--category", action="append", default=None,
                    help="Restrict to one category slug (repeatable; default: all)")
    ap.add_argument("--min-n", type=int, default=5,
                    help="Minimum scored CVEs for a category to enter the Kruskal-Wallis/Dunn's "
                         "test (default: 5; paper's smallest category had 24)")
    ap.add_argument("--out-dir", default=DEFAULT_OUT_DIR,
                    help="Output directory (default: data/difference)")
    args = ap.parse_args()

    # confirmed-Yes rows, deduped per (category, cve)
    yes_pairs = set()
    with open(args.store, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            if str(row.get("Final Judgment", "")).strip() == "Yes":
                cat = row["category"].strip()
                if args.category and cat not in args.category:
                    continue
                yes_pairs.add((cat, row["cve_id"].strip().upper()))
    if not yes_pairs:
        raise SystemExit("No Final Judgment = Yes rows matched — nothing to analyze.")
    needed = {cve for _, cve in yes_pairs}
    print(f"Confirmed-Yes rows: {len(yes_pairs)} "
          f"({len(needed)} distinct CVEs, {len({c for c, _ in yes_pairs})} categories)")

    # cvss_score lookup from the fixed snapshot, only for needed CVEs
    score_of = {}
    version_of = {}
    with open(args.snapshot, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            cid = row["cve_id"].strip().upper()
            if cid in needed:
                raw = (row.get("cvss_score") or "").strip()
                score_of[cid] = float(raw) if raw else None
                version_of[cid] = (row.get("cvss_version") or "").strip()
    missing = needed - set(score_of)
    if missing:
        print(f"  ! {len(missing)} confirmed CVE(s) not in the snapshot "
              f"(e.g. {sorted(missing)[:3]}) — skipped")

    cat_order = []
    if os.path.isfile(args.categories):
        with open(args.categories, newline="", encoding="utf-8-sig") as f:
            cat_order = [r["slug"].strip() for r in csv.DictReader(f)]

    groups = defaultdict(list)         # category -> [cvss_score, ...] (scored only)
    n_cves = Counter()                 # category -> confirmed-Yes CVEs found in snapshot
    sev_counts = defaultdict(Counter)  # category -> Counter(severity -> n)
    ver_counts = defaultdict(Counter)  # category -> Counter(cvss_version -> n)

    for cat, cve in yes_pairs:
        if cve not in score_of:
            continue
        n_cves[cat] += 1
        score = score_of[cve]
        sev_counts[cat][severity_bucket(score)] += 1
        if score is not None:
            groups[cat].append(score)
            ver_counts[cat][version_of[cve] or "unknown"] += 1

    cats = [c for c in cat_order if c in n_cves] + sorted(set(n_cves) - set(cat_order))
    os.makedirs(args.out_dir, exist_ok=True)

    # ---- distribution CSV
    dist_path = os.path.join(args.out_dir, "cvss_distribution.csv")
    dist_rows = []
    with open(dist_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["category", "n_cves", "n_scored", "mean", "median", "std",
                    "min", "q1", "q3", "max"])
        for cat in cats:
            vals = sorted(groups[cat])
            if vals:
                q1, med, q3 = st.scoreatpercentile(vals, [25, 50, 75])
                mean = statistics.mean(vals)
                std = statistics.stdev(vals) if len(vals) > 1 else 0.0
                row = [cat, n_cves[cat], len(vals), round(mean, 2), round(med, 2),
                       round(std, 2), round(vals[0], 2), round(q1, 2), round(q3, 2),
                       round(vals[-1], 2)]
            else:
                row = [cat, n_cves[cat], 0, "", "", "", "", "", "", ""]
            w.writerow(row)
            dist_rows.append(row)

    # ---- severity CSV (long form)
    sev_path = os.path.join(args.out_dir, "cvss_severity.csv")
    with open(sev_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["category", "severity", "n", "pct"])
        for cat in cats:
            total = sum(sev_counts[cat].values())
            for sev in SEVERITY_ORDER:
                if sev_counts[cat][sev]:
                    w.writerow([cat, sev, sev_counts[cat][sev],
                               round(100 * sev_counts[cat][sev] / total, 1)])

    # ---- Kruskal-Wallis + Dunn's post-hoc
    qualifying = [c for c in cats if len(groups[c]) >= args.min_n]
    excluded = [c for c in cats if c not in qualifying]
    kw_result = None
    dunn_rows = []
    if len(qualifying) >= 2:
        H, p_kw = st.kruskal(*[groups[c] for c in qualifying])
        kw_result = {"H": H, "p": p_kw, "df": len(qualifying) - 1, "n_groups": len(qualifying)}
        if p_kw < 0.05:
            dunn_rows = dunn_pairwise({c: groups[c] for c in qualifying})
            dunn_path = os.path.join(args.out_dir, "cvss_dunn_pairwise.csv")
            with open(dunn_path, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=["cat_a", "cat_b", "n_a", "n_b",
                                                  "z", "p", "p_bonferroni", "sig"])
                w.writeheader()
                w.writerows(dunn_rows)

    # ---- markdown report
    md_path = os.path.join(args.out_dir, "cvss_matrix.md")
    L = ["# CVSS score distribution — confirmed-Yes CVEs", ""]
    L.append("Mirrors RQ2 of the transportation IoT study (Section V): per-category CVSS score "
             "distribution (numeric stand-in for its Fig. 6 box plots) and severity-bucket shares "
             "(its Fig. 7), plus the same Kruskal-Wallis omnibus test with Dunn's post-hoc pairwise "
             "comparisons. A CVE confirmed in several categories counts once per category, not "
             "attribution-weighted (a CVSS score is a property of the CVE, unlike a CWE).")
    L.append("")
    L.append("| Category | N (Yes) | N Scored | Mean | Median | Std | Min | Q1 | Q3 | Max | "
             "Critical% | High% | Medium% | Low% | None% |")
    L.append("|" + "---|" * 15)
    for cat, row in zip(cats, dist_rows):
        _, ncve, nsc, mean, med, std, mn, q1, q3, mx = row
        total = sum(sev_counts[cat].values())

        def sp(sev):
            n = sev_counts[cat][sev]
            return f"{100 * n / total:.0f}%" if n else ""

        L.append("| " + " | ".join(str(x) for x in [
            cat, ncve, nsc, mean, med, std, mn, q1, q3, mx,
            sp("Critical"), sp("High"), sp("Medium"), sp("Low"), sp("None")]) + " |")

    L += ["", "## Kruskal-Wallis omnibus test", ""]
    if kw_result:
        L.append(f"Categories with >= {args.min_n} scored CVEs (n={kw_result['n_groups']}): "
                 + ", ".join(qualifying))
        L.append("")
        sig = "significant" if kw_result["p"] < 0.05 else "not significant"
        L.append(f"H = {kw_result['H']:.3f}, df = {kw_result['df']}, "
                 f"p = {kw_result['p']:.6g} — **{sig}** at alpha=0.05.")
        if excluded:
            L.append("")
            L.append(f"Excluded ({len(excluded)}, below --min-n {args.min_n} scored CVEs): "
                     + ", ".join(excluded))
        if kw_result["p"] < 0.05:
            L += ["", "## Dunn's post-hoc pairwise comparisons (Bonferroni-adjusted)", ""]
            sig_pairs = [r for r in dunn_rows if r["sig"]]
            if sig_pairs:
                L.append(f"{len(sig_pairs)} of {len(dunn_rows)} pairs significant "
                         f"(p_bonferroni < 0.05), most significant first:")
                L.append("")
                for r in sig_pairs:
                    L.append(f"- **{r['cat_a']}** vs **{r['cat_b']}** "
                             f"(n={r['n_a']} vs {r['n_b']}): z={r['z']}, "
                             f"p_bonferroni={r['p_bonferroni']:.4g}")
            else:
                L.append("No pairs significant after Bonferroni correction "
                         f"(full pairwise table: {len(dunn_rows)} pairs in "
                         "`cvss_dunn_pairwise.csv`).")
    else:
        L.append(f"Fewer than 2 categories have >= {args.min_n} scored CVEs — omnibus test skipped.")

    with open(md_path, "w") as f:
        f.write("\n".join(L) + "\n")

    # ---- console summary
    print(f"\n{len(cats)} categories, {sum(n_cves.values())} confirmed-Yes CVEs found in snapshot "
          f"({sum(len(v) for v in groups.values())} with a CVSS score).")
    if kw_result:
        print(f"Kruskal-Wallis: H={kw_result['H']:.3f}, p={kw_result['p']:.6g} "
              f"({kw_result['n_groups']} categories, min-n={args.min_n})")
    print(f"\nWrote {os.path.relpath(dist_path, ROOT)}, {os.path.relpath(sev_path, ROOT)}, "
          f"{os.path.relpath(md_path, ROOT)}"
          + (f", {os.path.relpath(os.path.join(args.out_dir, 'cvss_dunn_pairwise.csv'), ROOT)}"
             if dunn_rows else ""))


if __name__ == "__main__":
    main()
