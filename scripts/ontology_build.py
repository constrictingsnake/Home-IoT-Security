#!/usr/bin/env python3
"""Build derived CSVs from the Home IoT device ontology, and validate it.

The ontology (`ontology/homeiot.ttl`) is the hand-authored source of truth for the
24 analysis categories, their 7-family hierarchy, and the five definitional criteria.
This script is the only thing that reads it and writes anything.

    python3 scripts/ontology_build.py --check     # validate + prove CSVs unchanged (no writes)
    python3 scripts/ontology_build.py --write     # emit categories.csv + families.csv
    python3 scripts/ontology_build.py --reason    # 27-class in/out ruling table

Two invariants (docs/plans/PLAN_ontology.md):

  1. `data/categories.csv` must regenerate BYTE-IDENTICALLY, row order included.
     11 scripts + run_gemini.sh read it; cwe888_analysis.py reads its order into
     `cat_order` and uses that for table row ordering. `hiot:sortOrder` carries the
     order. NO COMMENT LINES: unlike keyword_terms.csv / vendor_terms.csv (custom
     parser, '#' ignored), this file is read by csv.DictReader, which would consume
     a leading '#' line as the header row.

  2. `skos:scopeNote` text is MOVED from the old hand-authored categories.csv
     verbatim, never synthesized. It reaches the AI reviewers through
     gemini_classify.py --scope, so editing it changes reviewer behaviour. The
     ontology must not become a classification input beyond this pass-through
     (see PLAN_ontology.md "Circularity boundary").

Requires: rdflib, pyshacl, owlrl.
"""
import argparse
import csv
import io
import os
import sys

from rdflib import Graph, Namespace, RDF, RDFS
from rdflib.namespace import SKOS

HIOT = Namespace("https://w3id.org/homeiot/ontology#")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TTL = os.path.join(ROOT, "ontology", "homeiot.ttl")
SHAPES = os.path.join(ROOT, "ontology", "shapes.ttl")
CATEGORIES = os.path.join(ROOT, "data", "categories.csv")
FAMILIES = os.path.join(ROOT, "data", "ontology", "families.csv")


# ---------------------------------------------------------------- load


def load(path=TTL):
    g = Graph()
    g.parse(path, format="turtle")
    return g


def device_types(g, excluded=False):
    """Return [(sortOrder, slug, label, scope_note, family_id, uri)] for the analysis
    set (or, with excluded=True, for the defined-but-excluded types)."""
    q = """
    SELECT ?d ?slug ?label ?note ?order ?fam WHERE {
      ?d hiot:slug ?slug ; rdfs:label ?label ; rdfs:subClassOf ?parent .
      OPTIONAL { ?d skos:scopeNote ?note }
      OPTIONAL { ?d hiot:sortOrder ?order }
      OPTIONAL { ?parent hiot:familyId ?fam }
      %s
    }
    """ % ("?d rdfs:subClassOf hiot:ExcludedDeviceType ."
           if excluded else
           "?parent hiot:familyId ?fam .")
    rows = []
    for d, slug, label, note, order, fam in g.query(q, initNs={"hiot": HIOT, "skos": SKOS}):
        rows.append((
            int(order) if order is not None else 10_000,
            str(slug), str(label),
            str(note) if note is not None else "",
            str(fam) if fam is not None else "",
            d,
        ))
    rows.sort(key=lambda r: (r[0], r[1]))
    return rows


def families(g):
    q = """
    SELECT ?f ?fid ?flabel WHERE { ?f hiot:familyId ?fid ; rdfs:label ?flabel . }
    """
    return {str(fid): str(flabel) for _, fid, flabel in g.query(q, initNs={"hiot": HIOT})}


# ---------------------------------------------------------------- render


def render_categories(g):
    """Serialize categories.csv exactly as the committed file is written:
    csv.writer defaults (QUOTE_MINIMAL, '\\r\\n' suppressed to '\\n')."""
    buf = io.StringIO(newline="")
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["slug", "label", "scope_note"])
    for _order, slug, label, note, _fam, _uri in device_types(g):
        w.writerow([slug, label, note])
    return buf.getvalue()


def render_families(g):
    fams = families(g)
    buf = io.StringIO(newline="")
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["slug", "family", "family_label"])
    for _order, slug, _label, _note, fam, _uri in device_types(g):
        w.writerow([slug, fam, fams.get(fam, "")])
    return buf.getvalue()


# ---------------------------------------------------------------- validate


def shacl_validate(g):
    """Returns (status, text) where status is True / False / None (= not run).
    None is distinct from True on purpose: a missing shapes file must never read as
    a clean validation."""
    if not os.path.isfile(SHAPES):
        return None, f"shapes.ttl not found at {SHAPES}"
    from pyshacl import validate as shacl
    ok, _graph, text = shacl(g, shacl_graph=Graph().parse(SHAPES, format="turtle"),
                             advanced=True, inference="none")
    return ok, text


CRITERIA = [
    ("1 connectivity",  "?d hiot:hasConnectivity ?v ."),
    ("2 device class",  "?d hiot:hasDeviceClass ?v . "
                        "VALUES ?v { hiot:EmbeddedSensor hiot:EmbeddedAppliance hiot:EmbeddedController }"),
    ("3 deployment",    "?d hiot:hasDeployment hiot:Residential . BIND(1 AS ?v)"),
    ("4 function/role", "{ ?d hiot:hasFunction ?v . VALUES ?v { hiot:Monitor hiot:Automate hiot:Control } } "
                        "UNION { ?d hiot:hasRole hiot:HomeControlSurface . BIND(1 AS ?v) }"),
    ("5 security ctx",  "?d hiot:hasSecurityContext hiot:ConsumerManaged . BIND(1 AS ?v)"),
]


def criteria_report(g, uri):
    """Which of the five criteria this device type satisfies, evaluated directly
    against the asserted facets."""
    out = []
    for name, pattern in CRITERIA:
        q = "ASK { VALUES ?d { <%s> } %s }" % (uri, pattern)
        out.append((name, bool(g.query(q, initNs={"hiot": HIOT}))))
    return out


def reason(g, verbose=True):
    """Run OWL-RL closure and check each device type's inferred membership in
    hiot:InScopeDeviceType against its asserted placement in the taxonomy.

    Device types are punned (owl:Class AND hiot:DeviceType individual) precisely so
    the equivalence axiom can classify them. A mismatch means the asserted facets and
    the published ruling disagree — which is the point of running this."""
    import owlrl
    closed = Graph()
    for t in g:
        closed.add(t)
    owlrl.DeductiveClosure(owlrl.OWLRL_Semantics).expand(closed)

    expected_in = {uri for *_r, uri in device_types(g)}
    expected_out = {uri for *_r, uri in device_types(g, excluded=True)}

    rows, mismatches = [], []
    for uri in sorted(expected_in | expected_out, key=str):
        inferred = (uri, RDF.type, HIOT.InScopeDeviceType) in closed
        expect = uri in expected_in
        slug = str(next(g.objects(uri, HIOT.slug)))
        ok = inferred == expect
        rows.append((slug, expect, inferred, ok))
        if not ok:
            mismatches.append((slug, expect, inferred, criteria_report(g, uri)))

    if verbose:
        print(f"\n{'category':24} {'published':>10} {'reasoner':>9}   ")
        print("-" * 50)
        for slug, expect, inferred, ok in rows:
            mark = "ok" if ok else "MISMATCH"
            print(f"{slug:24} {'in' if expect else 'out':>10} "
                  f"{'in' if inferred else 'out':>9}   {mark}")
        print("-" * 50)
        print(f"{len(rows)} device types, {len(rows) - len(mismatches)} agree, "
              f"{len(mismatches)} mismatch")
        for slug, expect, inferred, crit in mismatches:
            print(f"\n  {slug}: published={'in' if expect else 'out'}, "
                  f"reasoner={'in' if inferred else 'out'}")
            for name, sat in crit:
                print(f"    criterion {name:18} {'satisfied' if sat else 'FAILED'}")
    return mismatches


# ---------------------------------------------------------------- commands


def read_if_exists(path):
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def cmd_check(g):
    failures = []

    ok, text = shacl_validate(g)
    print("SHACL: " + {True: "clean", False: "FAILED", None: "NOT RUN"}[ok])
    if ok is not True:
        print(text)
        failures.append("shacl")

    cats = device_types(g)
    print(f"parsed: {len(cats)} analysis categories, "
          f"{len(device_types(g, excluded=True))} excluded, {len(families(g))} families")

    for path, rendered, label in ((CATEGORIES, render_categories(g), "categories.csv"),
                                  (FAMILIES, render_families(g), "families.csv")):
        current = read_if_exists(path)
        if current is None:
            print(f"{label}: absent — would create ({len(rendered.splitlines())} lines)")
        elif current == rendered:
            print(f"{label}: byte-identical ✓")
        else:
            print(f"{label}: DRIFT — regenerating would change this file")
            import difflib
            diff = list(difflib.unified_diff(current.splitlines(True), rendered.splitlines(True),
                                             "committed", "generated", n=1))
            sys.stdout.writelines(diff[:40])
            failures.append(label)

    mismatches = reason(g, verbose=False)
    print(f"reasoner: {27 - len(mismatches)}/27 rulings reproduced"
          if not mismatches else
          f"reasoner: {len(mismatches)} MISMATCH — run --reason")
    if mismatches:
        failures.append("reasoner")

    return 1 if failures else 0


def cmd_write(g):
    for path, rendered, label in ((CATEGORIES, render_categories(g), "categories.csv"),
                                  (FAMILIES, render_families(g), "families.csv")):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        current = read_if_exists(path)
        if current == rendered:
            print(f"{label}: unchanged")
            continue
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(rendered)
        print(f"{label}: written ({len(rendered.splitlines())} lines)")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="validate + prove the derived CSVs are unchanged; exit 1 on drift")
    ap.add_argument("--write", action="store_true",
                    help="regenerate data/categories.csv and data/ontology/families.csv")
    ap.add_argument("--reason", action="store_true",
                    help="print the 27-class in/out ruling table")
    ap.add_argument("--ttl", default=TTL, help="ontology file (default: ontology/homeiot.ttl)")
    args = ap.parse_args()

    if not (args.check or args.write or args.reason):
        ap.error("pick one of --check / --write / --reason")

    g = load(args.ttl)
    rc = 0
    if args.reason:
        rc |= 1 if reason(g) else 0
    if args.check:
        rc |= cmd_check(g)
    if args.write:
        rc |= cmd_write(g)
    return rc


if __name__ == "__main__":
    sys.exit(main())
