#!/usr/bin/env python3
"""CVSS score + vector analysis over confirmed-Yes CVEs.

Replicates RQ2 of the transportation IoT device study (Yih, Goseva-Popstojanova
& Cukier — Onboarding-Docs/transportation_device_study.pdf, Section V): per-
category CVSS score distributions and severity buckets, plus a Kruskal-Wallis
omnibus test with Dunn's post-hoc pairwise comparisons.

It also implements **RQ3** of the 2025 extension (Onboarding-Docs/
2025_Paper_Extension (1).pdf, Section VI): the distribution of CVSS *vector*
components — Attack Vector, Scope, and the Confidentiality/Integrity/
Availability impact combination — per category, mirroring its Figs. 8-10. That
half reads the snapshot's `vector_string` column, which only exists in snapshots
downloaded after docs/plans/PLAN_nvd_update.md landed.

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
  5. RQ3: parse each CVE's `vector_string` into the CVSS 3.x metric set. The
     extension pins its vector analysis to 3.x and converts 4.0 vectors back
     (VC/VI/VA are the 3.x C/I/A; 4.0 dropped Scope, so any non-None
     SC/SI/SA subsequent-system impact becomes Scope: Changed) — we do the
     same. CVSS 2.0 vectors are NOT converted: v2 has no Scope metric at all
     and its impact values (None/Partial/Complete) are not the 3.x
     None/Low/High, so a v2-only CVE is reported as unconvertible rather
     than silently reshaped.

Outputs (default under data/difference/):
  cvss_distribution.csv   — category, n_cves, n_scored, mean, median, std,
                            min, q1, median, q3, max
  cvss_severity.csv        — long form: category, severity, n, pct
  cvss_dunn_pairwise.csv   — cat_a, cat_b, n_a, n_b, z, p, p_bonferroni, sig
                            (only written if the omnibus test is significant)
  cvss_matrix.md           — summary table (paper's Fig 6/7 as numbers) +
                            Kruskal-Wallis result + significant Dunn's pairs
  cvss_vectors.csv         — RQ3 long form: category, metric, value, n, pct
  cvss_vector_matrix.md    — RQ3 tables for Attack Vector, Scope and CIA
                            impact combination (the extension's Figs. 8-10)

`--group family` folds the 24 categories into the ontology's folding categories
and writes `*_family.*` alongside, leaving the per-category files untouched —
the tail fix for leaf categories too small to carry a percentage.

Usage:
    python3 scripts/cvss_analysis.py
    python3 scripts/cvss_analysis.py --category cameras --category thermostat
    python3 scripts/cvss_analysis.py --min-n 10
    python3 scripts/cvss_analysis.py --group family
    python3 scripts/cvss_analysis.py --score-versions 3      # drop v2-only from the stats test
"""
import argparse
import csv
import os
import statistics
import sys
from collections import Counter, defaultdict

import scipy.stats as st

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cvss_vector import (AV_NAMES, AC_NAMES, PR_NAMES, UI_NAMES, S_NAMES,   # noqa: E402
                         CIA_NAMES, METRIC_ORDER, impact_combination, parse_vector)

csv.field_size_limit(sys.maxsize)     # snapshot cpe_strings fields exceed the default

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_STORE = os.path.join(ROOT, "data", "difference", "judgment_store.csv")
DEFAULT_SNAPSHOT = os.path.join(ROOT, "data", "nvd-snapshot", "nvd_all.csv")
DEFAULT_CATEGORIES = os.path.join(ROOT, "data", "categories.csv")
DEFAULT_FAMILIES = os.path.join(ROOT, "data", "ontology", "families.csv")
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


def load_families(path):
    """slug -> family_label, plus family order (first appearance). Same loader
    contract as cwe888_analysis.py — generated by ontology_build.py --write."""
    fam, order = {}, []
    with open(path, newline="", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            label = r["family_label"].strip()
            fam[r["slug"].strip()] = label
            if label not in order:
                order.append(label)
    return fam, order


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
    ap.add_argument("--group", choices=("category", "family"), default="category",
                    help="Unit of analysis. 'family' folds the 24 categories into the "
                         "supervisor-agreed folding categories from data/ontology/families.csv "
                         "and writes *_family.* outputs, leaving the per-category files "
                         "untouched (default: category)")
    ap.add_argument("--families", default=DEFAULT_FAMILIES,
                    help="families.csv from the ontology (default: data/ontology/families.csv)")
    ap.add_argument("--score-versions", choices=("all", "3"), default="all",
                    help="Which CVSS base-score versions enter the distribution and the "
                         "Kruskal-Wallis/Dunn's test. 'all' pools every version (default, "
                         "preserves published numbers); '3' keeps only v3.0/v3.1/v4.0-scored "
                         "CVEs, dropping v2.0 — v2 uses a different formula and skews low, so "
                         "pooling it is a confound the paper avoids. Does not affect RQ3, "
                         "which is pinned to 3.x-convertible vectors either way.")
    ap.add_argument("--include-excluded", action="store_true",
                    help="Keep rows a scope ruling took out of the analysis population "
                         "(judgment_store.csv `Excluded`). Off by default — mark_excluded.py's "
                         "rulings are meant to apply.")
    args = ap.parse_args()

    # confirmed-Yes rows, deduped per (category, cve)
    yes_pairs = set()
    n_excluded = 0
    with open(args.store, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            if str(row.get("Final Judgment", "")).strip() == "Yes":
                cat = row["category"].strip()
                if args.category and cat not in args.category:
                    continue
                # See cwe888_analysis.py: a scope ruling takes a settled row out of the
                # analysis population without touching its judgment, and this script reads
                # the store directly rather than final_resolved.csv.
                if str(row.get("Excluded", "")).strip() and not args.include_excluded:
                    n_excluded += 1
                    continue
                yes_pairs.add((cat, row["cve_id"].strip().upper()))
    if not yes_pairs:
        raise SystemExit("No Final Judgment = Yes rows matched — nothing to analyze.")
    needed = {cve for _, cve in yes_pairs}
    print(f"Confirmed-Yes rows: {len(yes_pairs)} "
          f"({len(needed)} distinct CVEs, {len({c for c, _ in yes_pairs})} categories)")
    if n_excluded:
        print(f"  excluded by scope ruling: {n_excluded} "
              f"(use --include-excluded to keep them)")
    elif args.include_excluded:
        print("  --include-excluded: scope-excluded rows KEPT in the population")

    # cvss_score lookup from the fixed snapshot, only for needed CVEs
    score_of = {}
    version_of = {}
    vector_of = {}
    has_vector_col = False
    with open(args.snapshot, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        has_vector_col = "vector_string" in (reader.fieldnames or [])
        for row in reader:
            cid = row["cve_id"].strip().upper()
            if cid in needed:
                raw = (row.get("cvss_score") or "").strip()
                score_of[cid] = float(raw) if raw else None
                version_of[cid] = (row.get("cvss_version") or "").strip()
                vector_of[cid] = (row.get("vector_string") or "").strip()
    missing = needed - set(score_of)
    if missing:
        print(f"  ! {len(missing)} confirmed CVE(s) not in the snapshot "
              f"(e.g. {sorted(missing)[:3]}) — skipped")
    if not has_vector_col:
        print("  ! snapshot has no `vector_string` column — RQ3 vector analysis skipped. "
              "Re-download with scripts/download_nvd.py (see docs/plans/PLAN_nvd_update.md).")

    # ---- fold categories into families, if asked. Folding is a view over the same
    # judgments: a CVE confirmed in two categories of the SAME family contributes one
    # score to that family, not two — unlike cwe888_analysis.py, where the unit is a
    # CWE attribution and repeats are meaningful.
    suffix = ""
    if args.group == "family":
        fam_of, fam_order = load_families(args.families)
        cats_seen = {c for c, _ in yes_pairs}
        missing_fam = sorted(cats_seen - set(fam_of))
        if missing_fam:
            raise SystemExit(f"No family for: {', '.join(missing_fam)} — "
                             f"rerun scripts/ontology_build.py --write")
        yes_pairs = {(fam_of[c], cve) for c, cve in yes_pairs}
        cat_order, suffix = fam_order, "_family"
        print(f"  --group family: folded into {len({c for c, _ in yes_pairs})} folding "
              f"categories ({len(yes_pairs)} rows after de-duplication)")
    else:
        cat_order = []
        if os.path.isfile(args.categories):
            with open(args.categories, newline="", encoding="utf-8-sig") as f:
                cat_order = [r["slug"].strip() for r in csv.DictReader(f)]

    groups = defaultdict(list)         # category -> [cvss_score, ...] (scored only)
    n_cves = Counter()                 # category -> confirmed-Yes CVEs found in snapshot
    sev_counts = defaultdict(Counter)  # category -> Counter(severity -> n)
    ver_counts = defaultdict(Counter)  # category -> Counter(cvss_version -> n)
    vec_counts = defaultdict(lambda: defaultdict(Counter))  # category -> metric -> Counter(value)
    n_vec = Counter()                  # category -> CVEs with a 3.x-equivalent vector
    n_unconvertible = Counter()        # category -> scored CVEs whose vector isn't 3.x-convertible

    n_dropped_v2 = 0
    for cat, cve in yes_pairs:
        if cve not in score_of:
            continue
        score = score_of[cve]
        version = version_of[cve] or "unknown"
        # --score-versions 3 drops v2-only records from the score distribution and the
        # stats test. They stay counted in n_cves nowhere — they leave the population
        # entirely, so percentages have a consistent denominator.
        if args.score_versions == "3" and score is not None and version.startswith("2"):
            n_dropped_v2 += 1
            continue
        n_cves[cat] += 1
        sev_counts[cat][severity_bucket(score)] += 1
        if score is not None:
            groups[cat].append(score)
            ver_counts[cat][version] += 1

        # ---- RQ3: vector components
        metrics = parse_vector(vector_of.get(cve)) if has_vector_col else None
        if metrics:
            n_vec[cat] += 1
            for metric, _ in METRIC_ORDER[:-1]:
                vec_counts[cat][metric][metrics[metric]] += 1
            vec_counts[cat]["impact_combination"][impact_combination(metrics)] += 1
        elif score is not None:
            n_unconvertible[cat] += 1

    if n_dropped_v2:
        print(f"  --score-versions 3: dropped {n_dropped_v2} v2.0-scored row(s) from the "
              f"distribution and the stats test")

    cats = [c for c in cat_order if c in n_cves] + sorted(set(n_cves) - set(cat_order))
    unit_label = "folding category" if args.group == "family" else "category"
    unit_plural = "folding categories" if args.group == "family" else "categories"
    os.makedirs(args.out_dir, exist_ok=True)

    def out(name):
        """Insert the --group suffix before the extension: cvss_matrix.md ->
        cvss_matrix_family.md, so a family run never overwrites the per-category files."""
        stem, ext = os.path.splitext(name)
        return os.path.join(args.out_dir, f"{stem}{suffix}{ext}")

    # ---- distribution CSV
    dist_path = out("cvss_distribution.csv")
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
    sev_path = out("cvss_severity.csv")
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
            dunn_path = out("cvss_dunn_pairwise.csv")
            with open(dunn_path, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=["cat_a", "cat_b", "n_a", "n_b",
                                                  "z", "p", "p_bonferroni", "sig"])
                w.writeheader()
                w.writerows(dunn_rows)

    # ---- RQ3: vector CSV (long form) + its own matrix
    vec_paths = []
    if has_vector_col and sum(n_vec.values()):
        vec_path = out("cvss_vectors.csv")
        with open(vec_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["category", "metric", "value", "n", "pct"])
            for cat in cats:
                total = n_vec[cat]
                if not total:
                    continue
                for metric, order in METRIC_ORDER:
                    counts = vec_counts[cat][metric]
                    # spec order first, then anything unexpected (a new CVSS value)
                    values = [v for v in order if counts[v]] + \
                             [v for v in sorted(counts) if v not in order]
                    for value in values:
                        w.writerow([cat, metric, value, counts[value],
                                    round(100 * counts[value] / total, 1)])
        vec_paths.append(vec_path)

        vm_path = out("cvss_vector_matrix.md")
        V = ["# CVSS vector components — confirmed-Yes CVEs (RQ3)", ""]
        V.append("Mirrors Section VI of the 2025 paper extension (its Figs. 8-10): the "
                 "distribution of Attack Vector, Scope, and the Confidentiality/Integrity/"
                 "Availability impact combination per category. Pinned to CVSS 3.x; 4.0 "
                 "vectors are converted back (VC/VI/VA -> C/I/A, any non-None subsequent-"
                 "system impact SC/SI/SA -> Scope: Changed). CVSS 2.0 has no Scope metric and "
                 "a different impact scale, so v2-only CVEs are counted as unconvertible "
                 "rather than reshaped.")
        V.append("")
        V.append(f"Population: **{sum(n_vec.values())}** ({unit_label}, CVE) rows with a "
                 f"3.x-equivalent vector; **{sum(n_unconvertible.values())}** scored rows "
                 f"without one (v2.0-only).")

        def vec_table(metric, order, title, note=None):
            counts_by_cat = {c: vec_counts[c][metric] for c in cats if n_vec[c]}
            values = [v for v in order
                      if any(counts_by_cat[c][v] for c in counts_by_cat)]
            V.extend(["", f"## {title}", ""])
            if note:
                V.extend([note, ""])
            V.append("| Category | N | " + " | ".join(values) + " |")
            V.append("|" + "---|" * (len(values) + 2))
            for cat in counts_by_cat:
                total = n_vec[cat]
                cells = [f"{100 * counts_by_cat[cat][v] / total:.0f}% ({counts_by_cat[cat][v]})"
                         if counts_by_cat[cat][v] else "—" for v in values]
                V.append(f"| {cat} | {total} | " + " | ".join(cells) + " |")
            # pooled row — the one number safe to quote for a small category
            pooled = Counter()
            for c in counts_by_cat:
                pooled.update(counts_by_cat[c])
            ptotal = sum(n_vec[c] for c in counts_by_cat)
            cells = [f"**{100 * pooled[v] / ptotal:.0f}%** ({pooled[v]})" if pooled[v] else "—"
                     for v in values]
            V.append(f"| **All** | **{ptotal}** | " + " | ".join(cells) + " |")

        vec_table("attack_vector", ["Network", "Adjacent", "Local", "Physical"],
                  "Attack Vector (Fig. 8)")
        vec_table("scope", ["Unchanged", "Changed"], "Scope (Fig. 9)",
                  "`Changed` means the exploit can affect resources beyond the vulnerable "
                  "component's own security scope.")
        vec_table("impact_combination", ["C+I+A", "C+I", "C+A", "I+A", "C", "I", "A", "none"],
                  "CIA impact combination (Fig. 10)",
                  "Which security attributes a CVE affects at all (metric value != None).")
        V.extend(["", "## Supporting metrics", ""])
        for metric, order in METRIC_ORDER:
            if metric in ("attack_vector", "scope", "impact_combination"):
                continue
            vec_table(metric, order, metric.replace("_", " ").title())
        V.extend(["", f"Long form: `{os.path.relpath(vec_path, ROOT)}`.", ""])
        with open(vm_path, "w") as f:
            f.write("\n".join(V) + "\n")
        vec_paths.append(vm_path)

    # ---- markdown report
    md_path = out("cvss_matrix.md")
    L = ["# CVSS score distribution — confirmed-Yes CVEs", ""]
    L.append("Mirrors RQ2 of the transportation IoT study (Section V): per-category CVSS score "
             "distribution (numeric stand-in for its Fig. 6 box plots) and severity-bucket shares "
             "(its Fig. 7), plus the same Kruskal-Wallis omnibus test with Dunn's post-hoc pairwise "
             "comparisons. A CVE confirmed in several categories counts once per category, not "
             "attribution-weighted (a CVSS score is a property of the CVE, unlike a CWE).")
    L.append("")
    if args.group == "family":
        L.append("Reported at the **folding-category** tier (`--group family`): the 24 leaf "
                 "categories folded per `data/ontology/families.csv`, de-duplicated so a CVE "
                 "confirmed in two categories of one family contributes one score. Per-category "
                 "numbers in `cvss_matrix.md` remain the primary reporting unit.")
        L.append("")
    ver_mix = Counter()
    for c in cats:
        ver_mix.update(ver_counts[c])
    if ver_mix:
        L.append("Base-score metric versions in this population: "
                 + ", ".join(f"v{v} ({n})" for v, n in sorted(ver_mix.items())) + ".")
        if args.score_versions == "all" and any(v.startswith("2") for v in ver_mix):
            L.append("")
            L.append("> **Caveat:** v2.0 and v3.x base scores are pooled here. v2 uses a "
                     "different formula and skews low, so it is a confound in the "
                     "Kruskal-Wallis below, not just noise. `--score-versions 3` reruns "
                     "without the v2-only records.")
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
    print(f"\n{len(cats)} {unit_plural}, {sum(n_cves.values())} confirmed-Yes CVEs found in "
          f"snapshot ({sum(len(v) for v in groups.values())} with a CVSS score).")
    if kw_result:
        print(f"Kruskal-Wallis: H={kw_result['H']:.3f}, p={kw_result['p']:.6g} "
              f"({kw_result['n_groups']} {unit_plural}, min-n={args.min_n})")
    if has_vector_col:
        print(f"RQ3 vectors: {sum(n_vec.values())} rows with a 3.x-equivalent vector, "
              f"{sum(n_unconvertible.values())} scored rows without one (v2.0-only).")
    written = [dist_path, sev_path, md_path]
    if dunn_rows:
        written.append(out("cvss_dunn_pairwise.csv"))
    written += vec_paths
    print("\nWrote " + ", ".join(os.path.relpath(p, ROOT) for p in written))


if __name__ == "__main__":
    main()
