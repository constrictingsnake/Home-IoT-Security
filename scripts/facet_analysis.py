#!/usr/bin/env python3
"""Report the confirmed-Yes CVE population sliced by ontology facet.

The descriptive sub-facets in ontology/homeiot.ttl are inert until something reads
them. This is that something: it joins each category's facet values to the confirmed
population in judgment_store.csv and reports the cells, so a facet can be argued
about with numbers instead of intuition.

    python3 scripts/facet_analysis.py                    # every facet, with dominance
    python3 scripts/facet_analysis.py --facet computeTier
    python3 scripts/facet_analysis.py --group family     # roll up to the 13 folds
    python3 scripts/facet_analysis.py --cross cwe888     # facet x CWE-888 class
    python3 scripts/facet_analysis.py --cross attack_vector   # facet x CVSS AV (RQ3)

THE DOMINANCE COLUMN IS THE POINT. Facets here are asserted per CATEGORY, and one
category — cameras — is 51% of the confirmed population. So a facet cell can look
like an independent grouping while actually being a rename of `cameras`, and any
finding stated over it is really a finding about cameras wearing a disguise.

Measured, and the reason this script exists: hiot:capturesAV=true is 1,120 rows of
which cameras alone is 881 (79%). hiot:actuatesPhysical=true is 388 rows over 13
categories, top share 23%. Same file, same kind of facet, completely different
evidentiary value. `top_share` makes that difference visible before anything is
published; cells above --dominance-threshold are flagged, never dropped (the same
convention the discovery miners use for risk flags — flags triage, they never
filter).

WHAT THIS CANNOT FIX. A per-category facet can never resolve below 24 buckets, so
the majority cell of almost every facet inherits cameras' mass no matter how the
vocabulary is designed. Contrast the MINORITY cells, report at --group family where
n allows, and treat a dominated cell as a hypothesis needing a product-level facet
rather than as a result.
"""
import argparse
import collections
import csv
import os
import sys

from rdflib import Graph, Namespace

HIOT = Namespace("https://w3id.org/homeiot/ontology#")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TTL = os.path.join(ROOT, "ontology", "homeiot.ttl")
FAMILIES = os.path.join(ROOT, "data", "ontology", "families.csv")
STORE = os.path.join(ROOT, "data", "difference", "judgment_store.csv")
SNAPSHOT = os.path.join(ROOT, "data", "nvd-snapshot", "nvd_all.csv")
CWE888_MAP = os.path.join(ROOT, "data", "difference", "cwe888_cve_map.csv")

# Every descriptive sub-facet, in criterion order. hiot:hasConnectivity and the four
# axiom-bearing properties are deliberately absent: they are membership tests, and
# slicing the population by a constant (hasDeployment is Residential on all 24)
# produces one cell and no information.
FACETS = [
    "cloudDependence", "topology", "pairingModel",                      # criterion 1
    "computeTier", "hasWebAdminUI", "firmwareUpdateModel",              # criterion 2
    "alsoDeployedIn", "consumerAvailability",                           # criterion 3
    "hasRole", "actuationConsequence", "dataSensitivity",               # criterion 4
    "adminModel", "credentialModel", "patchResponsibility",             # criterion 5
    "supportLifetime",
    "actuatesPhysical", "capturesAV", "formFactor", "placement",        # pre-existing
]


def load_facets(ttl=TTL):
    """{slug: {facet: {value, ...}}} straight from the hand-authored ontology."""
    g = Graph()
    g.parse(ttl, format="turtle")
    slug = {s: str(o) for s, o in g.subject_objects(HIOT.slug)}
    out = collections.defaultdict(lambda: collections.defaultdict(set))
    for f in FACETS:
        for s, o in g.subject_objects(HIOT[f]):
            if s in slug:
                v = str(o)
                out[slug[s]][f].add(v.split("#")[-1] if v.startswith(str(HIOT)) else v)
    return out


def load_population(store=STORE):
    """Confirmed-Yes (category, cve_id). Same population and same Excluded test as
    cwe888_analysis.py and the KG export, so these numbers reconcile with RQ1/RQ2."""
    out = []
    with open(store, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if r.get("Final Judgment") != "Yes":
                continue
            if str(r.get("Excluded", "")).strip():
                continue
            out.append((r["category"], r["cve_id"]))
    return out


def load_families(path=FAMILIES):
    with open(path, newline="", encoding="utf-8") as fh:
        return {r["slug"]: r["family_label"] for r in csv.DictReader(fh)}


def load_cross(kind):
    """{cve_id: {value, ...}} for a cross-tabulation axis."""
    if kind == "cwe888":
        m = collections.defaultdict(set)
        with open(CWE888_MAP, newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                for c in r["cwe888_classes"].split("|"):
                    if c.strip():
                        m[r["cve_id"]].add(c.strip())
        return m
    # Otherwise a CVSS vector metric, parsed by the same module cvss_analysis.py uses
    # so RQ3 numbers reported here cannot drift from RQ3 numbers reported there.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from cvss_vector import parse_vector
    csv.field_size_limit(10 ** 9)
    m = collections.defaultdict(set)
    with open(SNAPSHOT, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            vec = (r.get("vector_string") or "").strip()
            if not vec:
                continue
            metrics = parse_vector(vec)
            if metrics and kind in metrics:
                m[r["cve_id"]].add(metrics[kind])
    return m


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--facet", action="append",
                    help="restrict to one facet (repeatable); default is all")
    ap.add_argument("--group", choices=["category", "family"], default="category",
                    help="attribute the top-share column to a leaf category (default) "
                         "or to its family fold — a cell dominated by one CATEGORY may "
                         "still be well spread across FAMILIES, and vice versa")
    ap.add_argument("--cross",
                    help="cross-tabulate against cwe888 or a CVSS vector metric "
                         "(attack_vector, scope, confidentiality, ...)")
    ap.add_argument("--dominance-threshold", type=float, default=0.55,
                    help="flag cells where one group exceeds this share (default 0.55)")
    ap.add_argument("--min-n", type=int, default=0,
                    help="hide cells below this CVE count")
    args = ap.parse_args()

    facets = load_facets()
    pop = load_population()
    fam = load_families()
    wanted = args.facet or FACETS

    per_cat = collections.Counter(c for c, _v in pop)
    total = len(pop)
    key = (lambda c: fam.get(c, c)) if args.group == "family" else (lambda c: c)

    cross = load_cross(args.cross) if args.cross else None

    print(f"confirmed-Yes population: {total} CVE-category pairs over "
          f"{len(per_cat)} categories")
    print(f"dominance attributed by {args.group}; flagged above "
          f"{args.dominance_threshold:.0%}\n")

    for f in wanted:
        cells = collections.defaultdict(collections.Counter)
        for cat, cve in pop:
            for v in facets.get(cat, {}).get(f, ()):
                cells[v][key(cat)] += 1
        if not cells:
            continue
        print(f"### {f}")
        if cross:
            print(f"{'value':26} {'n':>6} {'top ' + args.group:>22}   {args.cross}")
        else:
            print(f"{'value':26} {'n':>6} {'%':>7}  {'top ' + args.group:>22}")
        for v, by in sorted(cells.items(), key=lambda kv: -sum(kv[1].values())):
            n = sum(by.values())
            if n < args.min_n:
                continue
            top, tn = by.most_common(1)[0]
            share = tn / n
            flag = "  DOMINATED" if share > args.dominance_threshold else ""
            head = f"{v:26} {n:6d}"
            if cross:
                cc = collections.Counter()
                for cat, cve in pop:
                    if v in facets.get(cat, {}).get(f, ()):
                        for x in cross.get(cve, ()):
                            cc[x] += 1
                tot = sum(cc.values()) or 1
                brk = "  ".join(f"{k} {100*n2/tot:.0f}%" for k, n2 in cc.most_common(4))
                print(f"{head} {top[:20]:>22} {share:5.0%}{flag}   {brk}")
            else:
                print(f"{head} {100*n/total:6.1f}%  {top[:20]:>22} {share:5.0%}{flag}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
