#!/usr/bin/env python3
"""Generate the LaTeX version of the CWE-888 x category matrix, with the
transportation IoT study's Table III cell-shading convention (top-6 dominant
classes per row highlighted).

Reads the already-computed cwe888_analysis.py output (data/difference/
cwe888_distribution.csv) rather than recomputing from the judgment store, so
this script has no CWE-catalog dependency and always matches cwe888_matrix.md
exactly.

Layout differs from the paper's Table III on purpose: the paper has 4 device
categories as columns (classes as rows), which fits a conference page; this
project has 20 categories, so the matrix is transposed here (categories as
rows, CWE-888 classes as columns, one row per category plus a final "All"
row) to reuse the same row-based layout as the CVSS summary table already in
the report. Top-6 selection uses the identical method as cwe888_matrix.md's
"Top-6 share" row: Counter.most_common(6) per row (ties broken by class
insertion order, i.e. the canonical CWE-888 order below).

Cells show only the row-percentage (integer, rounded) rather than "n (pct%)"
as in the paper — with 22 class columns there isn't room for both, and the
per-category N is already carried in its own column here (and in the
existing CVSS summary table). Exact counts remain in cwe888_matrix.md.

Output:
  data/difference/cwe888_table.tex — \\input-able from the report via
  \\input{../data/difference/cwe888_table.tex} (relative to docs/, where the
  report is built from). Requires \\usepackage[table]{xcolor} in the
  preamble (colortbl's \\cellcolor, loaded automatically by xcolor's `table`
  option, used for in-cell shading; \\colorbox — plain xcolor, works outside
  a tabular too — is used for the caption's color-key swatch).

Usage:
    python3 scripts/generate_cwe888_table.py
    python3 scripts/generate_cwe888_table.py --highlight-color "yellow!70"
"""
import argparse
import csv
import os
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Canonical CWE-888 primary-class order, matching cwe888_matrix.md exactly
# (Unused Entities is omitted: it has zero attributions in every category).
CLASS_ORDER = [
    "API", "Access Control", "Authentication", "Channel", "Cryptography",
    "Entry Points", "Exception Management", "Failure to Release Memory",
    "Faulty Resource Release", "Information Leak", "Malware", "Memory Access",
    "Memory Management", "Other", "Path Resolution", "Predictability",
    "Privilege", "Resource Management", "Risky Values", "Synchronization",
    "Tainted Input", "UI",
]

# Short column headers, rotated 90 degrees in the table.
CLASS_ABBREV = {
    "API": "API",
    "Access Control": "AccCtrl",
    "Authentication": "Auth",
    "Channel": "Channel",
    "Cryptography": "Crypto",
    "Entry Points": "EntryPt",
    "Exception Management": "ExcMgmt",
    "Failure to Release Memory": "FailRelMem",
    "Faulty Resource Release": "FaultResRel",
    "Information Leak": "InfoLeak",
    "Malware": "Malware",
    "Memory Access": "MemAccess",
    "Memory Management": "MemMgmt",
    "Other": "Other",
    "Path Resolution": "PathRes",
    "Predictability": "Predict",
    "Privilege": "Privilege",
    "Resource Management": "ResMgmt",
    "Risky Values": "RiskyVal",
    "Synchronization": "Sync",
    "Tainted Input": "TaintIn",
    "UI": "UI",
}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--distribution",
                     default=os.path.join(ROOT, "data/difference/cwe888_distribution.csv"))
    ap.add_argument("--categories", default=os.path.join(ROOT, "data/categories.csv"))
    ap.add_argument("--out", default=os.path.join(ROOT, "data/difference/cwe888_table.tex"))
    ap.add_argument("--highlight-color", default="yellow",
                     help="xcolor spec used for \\cellcolor on each row's top-6 classes")
    ap.add_argument("--label", default="tab:cwe888-matrix",
                     help="LaTeX \\label for the emitted table")
    ap.add_argument("--unit-label", default="category",
                     help="noun for the unit of analysis, used in the caption and row header "
                          "(e.g. 'folding category' for a --group family distribution)")
    ap.add_argument("--order-by-n", action="store_true",
                     help="order rows by descending N instead of by --categories file order; "
                          "use for family rollups, whose labels are not in categories.csv")
    args = ap.parse_args()

    # cwe888_analysis.py emits two pseudo-rows alongside the real categories:
    # "ALL" (micro totals, which this script recomputes by summing anyway) and
    # "ALL-MACRO" (each category weighted equally, so it carries percentages
    # only and its n_cwes cell is empty by construction).
    counts = {}
    macro_pcts = {}
    with open(args.distribution, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            cat, cls = row["category"], row["cwe888_class"]
            if cat == "ALL-MACRO":
                macro_pcts[cls] = float(row["pct"] or 0)
                continue
            n = row["n_cwes"].strip()
            counts.setdefault(cat, Counter())[cls] = int(n) if n else 0

    if args.order_by_n:
        cats = sorted((c for c in counts if c != "ALL"),
                       key=lambda c: -sum(counts[c].values()))
    else:
        cat_order = []
        with open(args.categories, newline="", encoding="utf-8-sig") as f:
            cat_order = [r["slug"].strip() for r in csv.DictReader(f)]
        cats = [c for c in cat_order if c in counts and c != "ALL"]
        cats += sorted(c for c in counts if c not in cat_order and c != "ALL")

    def tex_escape(s):
        # Family labels are prose ("Alarms & Sensors"), not slugs, so they can
        # carry characters that are LaTeX-active. An unescaped "&" silently
        # adds a column and breaks the whole tabular.
        for ch in ("&", "%", "$", "#", "_"):
            s = s.replace(ch, "\\" + ch)
        return s

    def row_cells(c):
        total = sum(c.values())
        top6 = {cls for cls, _ in c.most_common(6)}
        cells = []
        for cls in CLASS_ORDER:
            n = c[cls]
            if not n:
                cells.append("")
                continue
            pct = round(100 * n / total)
            text = f"{pct}"
            if cls in top6:
                text = f"\\cellcolor{{{args.highlight_color}}}{text}"
            cells.append(text)
        top6_n = sum(n for _, n in c.most_common(6))
        top6_pct = round(100 * top6_n / total) if total else 0
        return cells, total, top6_pct

    lines = []
    lines.append("% Auto-generated by scripts/generate_cwe888_table.py — do not edit by hand.")
    lines.append("\\begin{table*}[t]")
    lines.append("\\centering")
    lines.append("\\caption{Distribution of confirmed home IoT CVE CWE attributions across "
                  f"CWE-888 primary classes, by {args.unit_label}. Each cell is the row's "
                  f"percentage of its {args.unit_label}'s total CWE attributions ($N$); shaded cells "
                  "(\\colorbox{" + args.highlight_color + "}{\\phantom{0}}) mark that row's "
                  "6 most common classes, mirroring Table~III of the transportation IoT study. "
                  "The two overall rows differ in weighting: \\emph{micro} pools every "
                  "attribution, so the largest rows dominate, while \\emph{macro} averages the "
                  "individual row profiles with equal weight and therefore has no attribution "
                  "count of its own. "
                  "Exact counts are in \\texttt{data/difference/cwe888\\_matrix.md}.}")
    lines.append(f"\\label{{{args.label}}}")
    lines.append("\\resizebox{\\textwidth}{!}{%")
    col_spec = "l" + "r" * len(CLASS_ORDER) + "rr"
    lines.append(f"\\begin{{tabular}}{{{col_spec}}}")
    lines.append("\\toprule")
    header = [args.unit_label.title()] + [f"\\rotatebox{{90}}{{{CLASS_ABBREV[c]}}}" for c in CLASS_ORDER] \
        + ["\\rotatebox{90}{$N$}", "\\rotatebox{90}{Top-6\\%}"]
    lines.append(" & ".join(header) + " \\\\")
    lines.append("\\midrule")

    all_counts = Counter()
    for cat in cats:
        all_counts.update(counts[cat])
        cells, total, top6_pct = row_cells(counts[cat])
        lines.append(" & ".join([tex_escape(cat)] + cells + [str(total), str(top6_pct)]) + " \\\\")

    lines.append("\\midrule")
    cells, total, top6_pct = row_cells(all_counts)
    lines.append(" & ".join(["\\textbf{All} (micro)"] + cells + [str(total), str(top6_pct)]) + " \\\\")

    # Macro row: every category weighted equally regardless of its N, so the
    # profile is not dominated by the largest category. Percentages come
    # straight from cwe888_analysis.py rather than being re-derived here, so
    # the two stay consistent; there is no attribution count to report.
    if macro_pcts:
        top6_macro = {cls for cls, _ in Counter(macro_pcts).most_common(6)}
        macro_cells = []
        for cls in CLASS_ORDER:
            pct = macro_pcts.get(cls, 0)
            if not round(pct):
                macro_cells.append("")
                continue
            text = f"{round(pct)}"
            if cls in top6_macro:
                text = f"\\cellcolor{{{args.highlight_color}}}{text}"
            macro_cells.append(text)
        top6_macro_pct = round(sum(p for _, p in Counter(macro_pcts).most_common(6)))
        lines.append(" & ".join(["\\textbf{All} (macro)"] + macro_cells
                                 + ["---", str(top6_macro_pct)]) + " \\\\")
    lines.append("\\bottomrule")
    lines.append("\\end{tabular}}")
    lines.append("\\end{table*}")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {args.out} ({len(cats)} categories x {len(CLASS_ORDER)} classes)")


if __name__ == "__main__":
    main()
