#!/usr/bin/env python3
"""Reusable SPARQL queries over the home IoT vulnerability knowledge graph.

Loads ontology/homeiot.ttl (device-type classes + facets) and
data/ontology/homeiot-kg.ttl (the generated instance graph: confirmed CVEs,
products, vendors, weaknesses, reified category assignments — see
scripts/ontology_build.py --export-kg) into one rdflib.Graph and runs SPARQL
against it. This is an exploration tool, not a pipeline stage: it never
writes back to the ontology or the judgment store, and isn't chained into
pipeline.py refresh/settle.

Three ways to use it:

    python3 scripts/kg_queries.py list                 # what canned queries exist
    python3 scripts/kg_queries.py run <name>            # run one (or 'all')
    python3 scripts/kg_queries.py sparql "SELECT ..."   # run an ad hoc query

Plus two heavier analyses that don't fit a single canned SPARQL query:

    python3 scripts/kg_queries.py weakness-fingerprint
    python3 scripts/kg_queries.py cves-by-year

--- weakness-fingerprint -----------------------------------------------------
Question: NVD overall is dominated by web-style bugs (injection/XSS land in
the CWE-888 "Tainted Input" cluster) — is the CWE-888 fingerprint different
for home IoT, in general or per category?

The per-category/overall CWE-888 histogram over *confirmed* CVEs comes
straight from the KG via SPARQL (hkg:hasWeakness -> hkg:hasCwe888Class).
The "software at large" baseline CANNOT be a SPARQL query against this graph:
the KG deliberately holds only CVEs confirmed in scope for a device category
(homeiot-kg.ttl's "circularity boundary" note) — it does not carry the ~360k
irrelevant CVEs in the full NVD snapshot just to make this one comparison
self-contained. So the baseline is computed the same way cwe888_analysis.py
computes the real one, reusing its CWE->CWE-888 mapping (load_cwe_catalog /
map_cwe / parse_cwe_ids, imported directly, not copied) but run over every
row of data/nvd-snapshot/nvd_all.csv instead of just confirmed-Yes rows.
Each home-IoT histogram is then compared to that baseline with a chi-square
goodness-of-fit test (classes with expected count < --min-expected are
pooled into "Other (pooled, low expected)" first, standard chi-square
practice for sparse cells).

--- cves-by-year --------------------------------------------------------------
Question: which device categories are seeing accelerating disclosure, and
since when? Per-category, per-year confirmed-CVE counts come from the KG via
SPARQL (hkg:published, grouped with BIND(YEAR(?pub) AS ?yr) — rdflib's SPARQL
engine requires the BIND form; grouping directly by a `SELECT (YEAR(?pub) AS
?yr)` alias silently collapses to one group). NVD's CPE/CWE enrichment lags
after ~2024, so year counts from --cutoff-year+1 onward understate true
disclosure volume — they're shown but excluded from the trend fit. The trend
itself is an ordinary least-squares slope (scipy.stats.linregress) of annual
count vs year, per category, over years <= the cutoff; "accelerating" means
slope > 0 at p < 0.05. This flags *whether* a category trends up, not a
change-point "since exactly year X" — the printed per-year table is there so
a human can eyeball the inflection point directly.
"""
import argparse
import csv
import os
import sys
from collections import Counter, defaultdict

import rdflib
import scipy.stats as st

csv.field_size_limit(sys.maxsize)     # nvd_all.csv description fields can be huge

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ONTOLOGY_TTL = os.path.join(ROOT, "ontology", "homeiot.ttl")
KG_TTL = os.path.join(ROOT, "data", "ontology", "homeiot-kg.ttl")
NVD_SNAPSHOT = os.path.join(ROOT, "data", "nvd-snapshot", "nvd_all.csv")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cwe888_analysis as cwe888      # reuse its CWE -> CWE-888 mapping, don't reimplement it

PREFIXES = """
PREFIX hkg:  <https://w3id.org/homeiot/kg#>
PREFIX hiot: <https://w3id.org/homeiot/ontology#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
"""

# name -> (SPARQL body, one-line description). PREFIXES is prepended at run time.
QUERIES = {
    "class-counts": ("""
        SELECT ?class (COUNT(?x) AS ?n) WHERE {
          VALUES ?class { hkg:Vulnerability hkg:Product hkg:Vendor hkg:Weakness
                           hkg:Cwe888Class hkg:CategoryAssignment }
          ?x a ?class .
        } GROUP BY ?class ORDER BY DESC(?n)
    """, "Instance counts per KG class"),

    "category-counts": ("""
        SELECT ?slug (COUNT(?a) AS ?n) WHERE {
          ?a a hkg:CategoryAssignment ; hkg:assignedCategory ?cat .
          ?cat hiot:slug ?slug .
        } GROUP BY ?slug ORDER BY DESC(?n)
    """, "Confirmed CVEs per device category"),

    "empty-categories": ("""
        SELECT ?slug WHERE {
          ?cat a hiot:DeviceType ; hiot:slug ?slug .
          FILTER NOT EXISTS { ?cat hiot:failsCriteria ?fc }
          FILTER NOT EXISTS { ?a hkg:assignedCategory ?cat }
        }
    """, "In-scope (24-category) slugs with zero confirmed CVEs"),

    "judgment-source": ("""
        SELECT ?src (COUNT(?a) AS ?n) WHERE {
          ?a a hkg:CategoryAssignment ; hkg:judgmentSource ?src .
        } GROUP BY ?src ORDER BY DESC(?n)
    """, "How assignments settled: ai-consensus / strong-consensus / human"),

    "judgment-source-by-category": ("""
        SELECT ?slug ?src (COUNT(?a) AS ?n) WHERE {
          ?a a hkg:CategoryAssignment ; hkg:assignedCategory ?cat ; hkg:judgmentSource ?src .
          ?cat hiot:slug ?slug .
        } GROUP BY ?slug ?src ORDER BY ?slug DESC(?n)
    """, "Judgment-source crosstab per category"),

    "discovery-direction": ("""
        SELECT ?dir (COUNT(?a) AS ?n) WHERE {
          ?a a hkg:CategoryAssignment ; hkg:discoveryDirection ?dir .
        } GROUP BY ?dir ORDER BY DESC(?n)
    """, "vendor_only / keyword_only / intersection / cpe_expansion breakdown"),

    "human-settled": ("""
        SELECT ?human (COUNT(?a) AS ?n) WHERE {
          ?a a hkg:CategoryAssignment ; hkg:humanSettled ?human .
        } GROUP BY ?human
    """, "Human-settled vs AI-settled assignment counts"),

    "top-vendors": ("""
        SELECT ?vname (COUNT(DISTINCT ?v) AS ?n) WHERE {
          ?v hkg:affectsProduct ?p . ?p hkg:vendor ?vend . ?vend hkg:vendorName ?vname .
        } GROUP BY ?vname ORDER BY DESC(?n) LIMIT 15
    """, "Top 15 vendors by confirmed CVE count"),

    "top-weaknesses": ("""
        SELECT ?clabel (COUNT(*) AS ?n) WHERE {
          ?v hkg:hasWeakness ?w . ?w hkg:hasCwe888Class ?c . ?c rdfs:label ?clabel .
        } GROUP BY ?clabel ORDER BY DESC(?n) LIMIT 10
    """, "Top 10 CWE-888 classes overall (see weakness-fingerprint for per-category + baseline)"),

    "cvss-stats": ("""
        SELECT (AVG(?s) AS ?avg) (MIN(?s) AS ?min) (MAX(?s) AS ?max) (COUNT(?s) AS ?n) WHERE {
          ?v hkg:cvssScore ?s .
        }
    """, "CVSS base score summary, all confirmed CVEs"),

    "cvss-by-category": ("""
        SELECT ?slug (AVG(?s) AS ?avgcvss) (COUNT(?v) AS ?n) WHERE {
          ?a a hkg:CategoryAssignment ; hkg:assignedCategory ?cat ; hkg:assignedVulnerability ?v .
          ?cat hiot:slug ?slug . ?v hkg:cvssScore ?s .
        } GROUP BY ?slug ORDER BY DESC(?n)
    """, "Average CVSS base score per category"),

    "physical-consequence": ("""
        SELECT ?slug (COUNT(?a) AS ?n) WHERE {
          ?a a hkg:CategoryAssignment ; hkg:assignedCategory ?cat .
          ?cat hiot:actuatesPhysical true ; hiot:slug ?slug .
        } GROUP BY ?slug ORDER BY DESC(?n)
    """, "Confirmed CVEs on devices that can cause a physical-world consequence"),

    "av-capture": ("""
        SELECT ?slug (COUNT(?a) AS ?n) WHERE {
          ?a a hkg:CategoryAssignment ; hkg:assignedCategory ?cat .
          ?cat hiot:capturesAV true ; hiot:slug ?slug .
        } GROUP BY ?slug ORDER BY DESC(?n)
    """, "Confirmed CVEs on devices that capture audio/video"),
}


def load_graph(kg_path=KG_TTL, ontology_path=ONTOLOGY_TTL):
    g = rdflib.Graph()
    g.parse(ontology_path, format="turtle")
    g.parse(kg_path, format="turtle")
    return g


def print_rows(query):
    def run(g):
        for row in g.query(query):
            print(" | ".join(str(x) for x in row))
    return run


# ------------------------------------------------------------- list / run / sparql

def cmd_list(args):
    width = max(len(n) for n in QUERIES)
    for name, (_, desc) in QUERIES.items():
        print(f"{name:{width}s}  {desc}")


def cmd_run(args):
    g = load_graph()
    names = list(QUERIES) if args.name == "all" else [args.name]
    for name in names:
        if name not in QUERIES:
            raise SystemExit(f"Unknown query '{name}'. Run 'list' to see valid names.")
        body, desc = QUERIES[name]
        print(f"\n=== {name} — {desc} ===")
        for row in g.query(PREFIXES + body):
            print(" | ".join(str(x) for x in row))


def cmd_sparql(args):
    g = load_graph()
    q = args.query
    if "PREFIX" not in q.upper():
        q = PREFIXES + q
    for row in g.query(q):
        print(" | ".join(str(x) for x in row))


# ------------------------------------------------------- weakness-fingerprint

def home_iot_cwe888_histogram(g):
    """Returns (per_category: slug -> Counter(class -> n), overall: Counter)."""
    q = """
        SELECT ?slug ?clabel (COUNT(*) AS ?n) WHERE {
          ?a a hkg:CategoryAssignment ; hkg:assignedCategory ?cat ; hkg:assignedVulnerability ?v .
          ?cat hiot:slug ?slug .
          ?v hkg:hasWeakness ?w . ?w hkg:hasCwe888Class ?c . ?c rdfs:label ?clabel .
        } GROUP BY ?slug ?clabel
    """
    per_cat, overall = defaultdict(Counter), Counter()
    for slug, clabel, n in g.query(PREFIXES + q):
        n = int(n)
        per_cat[str(slug)][str(clabel)] += n
        overall[str(clabel)] += n
    return per_cat, overall


def nvd_wide_cwe888_baseline(cwe_xml=cwe888.DEFAULT_CWE_XML, snapshot=NVD_SNAPSHOT):
    """CWE-888 class histogram over EVERY CVE in the full NVD snapshot — the
    'software at large' comparison population. See module docstring for why
    this has to be a plain scan rather than a SPARQL query."""
    cwe_to_classes, parents, _ = cwe888.load_cwe_catalog(cwe_xml)
    memo, baseline = {}, Counter()
    with open(snapshot, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            for num in cwe888.parse_cwe_ids(row.get("cwe_ids", "")):
                if num not in memo:
                    memo[num] = cwe888.map_cwe(num, cwe_to_classes, parents)[0]
                for cls in memo[num]:
                    baseline[cls] += 1
    return baseline


def chi_square_vs_baseline(observed, baseline_props, min_expected=5.0):
    """observed: Counter(class -> n). baseline_props: class -> proportion (sums
    to ~1). Classes with expected count < min_expected are pooled into one
    'Other (pooled)' bin on both sides before scipy.stats.chisquare, standard
    practice for sparse chi-square cells. Returns (chi2, p, dof, table) or
    None if too few classes survive to run a meaningful test."""
    total = sum(observed.values())
    if total == 0:
        return None
    obs_final, exp_final, table = [], [], []
    pooled_obs = pooled_exp = 0.0
    for c in sorted(baseline_props):
        o, e = observed.get(c, 0), total * baseline_props[c]
        if e < min_expected:
            pooled_obs += o
            pooled_exp += e
        else:
            obs_final.append(o); exp_final.append(e); table.append((c, o, e))
    if pooled_exp > 0:
        obs_final.append(pooled_obs); exp_final.append(pooled_exp)
        table.append(("Other (pooled, low expected)", pooled_obs, pooled_exp))
    if len(obs_final) < 2:
        return None
    chi2, p = st.chisquare(obs_final, f_exp=exp_final)
    return chi2, p, len(obs_final) - 1, table


def cmd_weakness_fingerprint(args):
    g = load_graph()
    per_cat, overall = home_iot_cwe888_histogram(g)
    print(f"Scanning {os.path.relpath(NVD_SNAPSHOT, ROOT)} for the NVD-wide "
          f"CWE-888 baseline (~360k CVEs, a few seconds)...")
    baseline = nvd_wide_cwe888_baseline()
    baseline_total = sum(baseline.values())
    baseline_props = {c: n / baseline_total for c, n in baseline.items()}
    print(f"Baseline: {baseline_total} CWE attributions across the full snapshot.\n")

    rows_out = []

    def report(label, counter):
        total = sum(counter.values())
        print(f"--- {label} (n={total} CWE attributions) ---")
        print(f"{'class':28s} {'home-IoT %':>10s} {'NVD-wide %':>10s} {'ratio':>7s}")
        for c in sorted(counter, key=lambda c: -counter[c]):
            hp = counter[c] / total
            bp = baseline_props.get(c, 0.0)
            ratio = hp / bp if bp else float("inf")
            print(f"{c:28s} {hp*100:9.1f}% {bp*100:9.1f}% {ratio:6.2f}x")
            rows_out.append({"scope": label, "cwe888_class": c, "n": counter[c],
                              "home_iot_pct": round(hp * 100, 2),
                              "nvd_wide_pct": round(bp * 100, 2),
                              "ratio": round(ratio, 3) if bp else ""})
        result = chi_square_vs_baseline(counter, baseline_props, args.min_expected)
        if result:
            chi2, p, dof, _ = result
            sig = "YES" if p < 0.05 else "no"
            print(f"chi-square vs NVD-wide baseline: chi2={chi2:.1f}  dof={dof}  "
                  f"p={p:.2e}  significantly different: {sig}")
        else:
            print("chi-square: skipped (too few CVEs/classes for a valid test)")
        print()

    report("Home IoT overall", overall)
    cats = args.category or sorted(per_cat, key=lambda s: -sum(per_cat[s].values()))
    for slug in cats:
        counter = per_cat.get(slug)
        if not counter:
            print(f"--- {slug}: no confirmed CVEs with a mapped CWE — skipped ---\n")
            continue
        report(slug, counter)

    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)
        out = os.path.join(args.out_dir, "kg_weakness_fingerprint.csv")
        with open(out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["scope", "cwe888_class", "n",
                                               "home_iot_pct", "nvd_wide_pct", "ratio"])
            w.writeheader(); w.writerows(rows_out)
        print(f"Wrote {os.path.relpath(out, ROOT)}")


# ------------------------------------------------------------- cves-by-year

def cves_by_year(g):
    q = """
        SELECT ?slug ?yr (COUNT(DISTINCT ?v) AS ?n) WHERE {
          ?a a hkg:CategoryAssignment ; hkg:assignedCategory ?cat ; hkg:assignedVulnerability ?v .
          ?cat hiot:slug ?slug .
          ?v hkg:published ?pub .
          BIND(YEAR(?pub) AS ?yr)
        } GROUP BY ?slug ?yr ORDER BY ?slug ?yr
    """
    per_cat_year = defaultdict(dict)
    for slug, yr, n in g.query(PREFIXES + q):
        per_cat_year[str(slug)][int(yr)] = int(n)
    return per_cat_year


def cmd_cves_by_year(args):
    g = load_graph()
    per_cat_year = cves_by_year(g)
    cutoff = args.cutoff_year

    print(f"NVD CPE/CWE enrichment lags after ~2024, so counts for {cutoff + 1}+ "
          f"understate true disclosure volume. Per-year counts below include them; "
          f"the trend fit uses only years <= {cutoff}.\n")

    trend_rows = []
    for slug in sorted(per_cat_year, key=lambda s: -sum(per_cat_year[s].values())):
        by_year = per_cat_year[slug]
        years_all = sorted(by_year)
        total = sum(by_year.values())
        series = " ".join(f"{y}:{by_year[y]}" for y in years_all)
        print(f"{slug:16s} n={total:4d}  {series}")

        lo = years_all[0]
        fit_years = list(range(lo, cutoff + 1))
        fit_counts = [by_year.get(y, 0) for y in fit_years]
        if len(fit_years) >= 4 and sum(fit_counts) >= 5:
            slope, _, _, p, _ = st.linregress(fit_years, fit_counts)
            trend_rows.append((slug, total, slope, p))

    print(f"\nLinear trend, annual count ~ year (years <= {cutoff}, categories with "
          f">=4 years of data and >=5 CVEs in that window):")
    print(f"{'category':16s} {'n':>5s} {'slope/yr':>10s} {'p':>10s} {'accelerating?':>14s}")
    for slug, total, slope, p in sorted(trend_rows, key=lambda r: -r[2]):
        flag = "YES" if (slope > 0 and p < 0.05) else "no"
        print(f"{slug:16s} {total:5d} {slope:10.2f} {p:10.3f} {flag:>14s}")

    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)
        out = os.path.join(args.out_dir, "kg_cves_by_year.csv")
        with open(out, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["category", "year", "n", "post_cutoff"])
            for slug, by_year in per_cat_year.items():
                for y, n in sorted(by_year.items()):
                    w.writerow([slug, y, n, y > cutoff])
        print(f"Wrote {os.path.relpath(out, ROOT)}")


# ------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list", help="List all canned SPARQL queries")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("run", help="Run one canned query by name (or 'all')")
    p.add_argument("name")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("sparql", help="Run an ad hoc SPARQL query string")
    p.add_argument("query")
    p.set_defaults(func=cmd_sparql)

    p = sub.add_parser(
        "weakness-fingerprint",
        help="Per-category CWE-888 histogram vs NVD-at-large baseline (chi-square)")
    p.add_argument("--category", action="append", default=None,
                    help="Restrict to one category slug (repeatable; default: all with data)")
    p.add_argument("--min-expected", type=float, default=5.0,
                    help="Chi-square pooling threshold for sparse cells (default: 5.0)")
    p.add_argument("--out-dir", default=None,
                    help="If set, also write kg_weakness_fingerprint.csv here")
    p.set_defaults(func=cmd_weakness_fingerprint)

    p = sub.add_parser(
        "cves-by-year",
        help="Confirmed CVEs per category per year, plus a linear trend up to --cutoff-year")
    p.add_argument("--cutoff-year", type=int, default=2024,
                    help="Last year treated as complete for the trend fit (default: 2024)")
    p.add_argument("--out-dir", default=None,
                    help="If set, also write kg_cves_by_year.csv here")
    p.set_defaults(func=cmd_cves_by_year)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
