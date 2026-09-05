#!/usr/bin/env python3
"""Build derived CSVs from the Home IoT device ontology, and validate it.

The ontology (`ontology/homeiot.ttl`) is the hand-authored source of truth for the
24 analysis categories, their 7-family hierarchy, and the five definitional criteria.
This script is the only thing that reads it and writes anything.

    python3 scripts/ontology_build.py --check     # validate + prove CSVs unchanged (no writes)
    python3 scripts/ontology_build.py --write     # emit categories.csv + families.csv
    python3 scripts/ontology_build.py --reason    # 31-class in/out ruling table
    python3 scripts/ontology_build.py --export-kg # emit the instance graph (Phase 4)

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

from collections import Counter

from rdflib import Graph, Namespace, RDF, RDFS
from rdflib.namespace import SKOS

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cvss_vector import impact_combination, parse_vector   # noqa: E402

HIOT = Namespace("https://w3id.org/homeiot/ontology#")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TTL = os.path.join(ROOT, "ontology", "homeiot.ttl")
SHAPES = os.path.join(ROOT, "ontology", "shapes.ttl")
ALIGN = os.path.join(ROOT, "ontology", "homeiot-align.ttl")
EXTERNAL = os.path.join(ROOT, "ontology", "external_classes.tsv")
SOURCES = os.path.join(ROOT, "ontology", "homeiot-sources.ttl")
STUDY_MANIFEST = os.path.join(ROOT, "ontology", "study_sources.tsv")
CATEGORIES = os.path.join(ROOT, "data", "categories.csv")
FAMILIES = os.path.join(ROOT, "data", "ontology", "families.csv")

FACET_DISTRIBUTION = os.path.join(ROOT, "data", "facets", "facet_distribution.csv")

KG_SCHEMA = os.path.join(ROOT, "ontology", "homeiot-kg.ttl")
KG_OUT = os.path.join(ROOT, "data", "ontology", "homeiot-kg.ttl")
STORE = os.path.join(ROOT, "data", "difference", "judgment_store.csv")
SNAPSHOT = os.path.join(ROOT, "data", "nvd-snapshot", "nvd_all.csv")
CWE888_MAP = os.path.join(ROOT, "data", "difference", "cwe888_cve_map.csv")


def snapshot_date(path):
    """The vintage a snapshot CSV was downloaded at, for hkg:snapshotDate.

    Read from the provenance markdown download_nvd.py writes beside it
    (SNAPSHOT.md for nvd_all.csv, SNAPSHOT_<stem>.md otherwise) and fall back to
    the file's mtime. Hardcoding this is how a graph ends up claiming a vintage
    it was not built from."""
    import datetime, re
    base = os.path.basename(path)
    md = os.path.join(os.path.dirname(path),
                      "SNAPSHOT.md" if base == "nvd_all.csv"
                      else "SNAPSHOT_%s.md" % os.path.splitext(base)[0])
    if os.path.isfile(md):
        with open(md, encoding="utf-8") as fh:
            m = re.search(r"\*\*Snapshot date:\*\*\s*(\d{4}-\d{2}-\d{2})", fh.read())
        if m:
            return m.group(1)
    if os.path.isfile(path):
        return datetime.date.fromtimestamp(os.path.getmtime(path)).isoformat()
    return "unknown"


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
    # 4(b) is the four named control-surface mechanisms, not the single
    # hiot:HomeControlSurface individual it used to be. Kept in sync with the
    # owl:oneOf in hiot:HomeControlSurfaceRole — this report is what a reviewer
    # reads when the reasoner and a published ruling disagree, so it must test
    # the same thing the axiom does.
    ("4 function/role", "{ ?d hiot:hasFunction ?v . VALUES ?v { hiot:Monitor hiot:Automate hiot:Control } } "
                        "UNION { ?d hiot:hasRole ?v . VALUES ?v { hiot:ControllerRole hiot:AssistantRole "
                        "hiot:FeedSurfaceRole hiot:AutomationEngineRole } }"),
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


ALIGN_PREDS = (RDFS.subClassOf, SKOS.closeMatch, SKOS.broadMatch, SKOS.relatedMatch)


def phase_a_line(path=FACET_DISTRIBUTION):
    """One-line Phase A heterogeneity summary for --check.

    Reports how many measured (category, facet) cells support a single value. The
    numbers come from facet_sample.py --aggregate and are NOT written into the
    ontology: 120 measured values hand-copied into a hand-authored TTL is exactly the
    drift the byte-identical-CSV design exists to prevent, so the CSV stays the source
    and this is the visibility surface.
    """
    if not os.path.exists(path):
        return ("facet heterogeneity: NOT MEASURED — no data/facets/"
                "facet_distribution.csv (run facet_sample.py; until then every "
                "category-level value is unvalidated)")
    counts = Counter()
    worst = None
    with open(path, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            counts[r.get("verdict", "").strip()] += 1
            share = r.get("modal_share_cve", "").strip()
            if share and (worst is None or float(share) < worst[0]):
                worst = (float(share), r["category"], r["facet"])
    total = sum(counts.values())
    bad = counts.get("NOT-USABLE-report-distribution", 0)
    line = (f"facet heterogeneity (Phase A): "
            f"{counts.get('summary-defensible', 0)} defensible / "
            f"{counts.get('grouping-only', 0)} grouping-only / {bad} NOT-USABLE "
            f"of {total} measured cells")
    if worst:
        line += f"; worst {worst[1]}/{worst[2]} at {worst[0]:.3f}"
    if bad:
        line += " — facet_analysis.py withholds those cells"
    return line


def check_alignment(verbose=True):
    """Verify every external IRI in homeiot-align.ttl exists in the pinned manifest,
    and report alignment coverage.

    The failure mode this exists to catch is inventing a plausible external class.
    SAREF core has no `Multimedia`, no `WashingMachine`, no `Generator`; `sosa:System`
    is not a class (it is `ssn:System`). All four were caught here. The manifest
    (ontology/external_classes.tsv) is extracted from the published vocabularies with
    versions and source hashes recorded, so this check runs offline."""
    if not os.path.isfile(ALIGN):
        return None, "homeiot-align.ttl not found", {}
    if not os.path.isfile(EXTERNAL):
        return None, "external_classes.tsv not found — cannot verify alignment IRIs", {}

    known = {}
    with open(EXTERNAL, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh, delimiter="\t"):
            known[r["iri"]] = r["vocabulary"]

    ag = Graph()
    ag.parse(ALIGN, format="turtle")

    bad, used = [], Counter()
    for s, p, o in ag:
        if p in ALIGN_PREDS and str(o).startswith("http") \
                and not str(o).startswith(str(HIOT)):
            if str(o) in known:
                used[known[str(o)]] += 1
            else:
                bad.append((str(s).split("#")[-1], str(p).split("#")[-1], str(o)))

    prec = {str(s).split("#")[-1]: str(o)
            for s, o in ag.subject_objects(HIOT.alignmentPrecision)
            if not str(s).endswith("alignmentPrecision")}

    if verbose:
        print(f"\nalignment: {sum(used.values())} external references, "
              f"{len(known)} IRIs in manifest")
        for v, n in used.most_common():
            print(f"  {v:14} {n:4} references")
        if bad:
            print("\n  UNVERIFIED IRIs (not in manifest — likely fabricated):")
            for s, p, o in bad:
                print(f"    {s} {p} {o}")

        # Coverage is a claim about the 24 ANALYSIS categories. The 3 excluded types
        # carry alignments too (hiot:vrar -> s4wear:OnBodyWearable is exact), and
        # counting them here would inflate the "exact" figure.
        g = load()
        analysis = {slug for _o, slug, *_r in device_types(g)}
        exact = sorted(k for k, v in prec.items()
                       if v == "exact" and k.replace("_", "-") in analysis)
        coarse = sorted(k for k, v in prec.items()
                        if v == "coarse" and k.replace("_", "-") in analysis)
        other = sorted(k for k in prec if k.replace("_", "-") not in analysis)
        n = len(analysis)
        print(f"\n  coverage over the {n} analysis categories: "
              f"{len(exact)} exact ({100*len(exact)/n:.0f}%), "
              f"{len(coarse)} coarse ({100*len(coarse)/n:.0f}%)")
        # Deliberately NOT "no external class exists for" — that is what this line used to
        # say, and it was wrong. Coarse means no class at the RIGHT GRANULARITY; every one
        # of these categories does have a denoting class (usually a generic superclass).
        # The 2026-08-10 pass found s4bldg:AudioVisualAppliance, s4bldg:Alarm and
        # s4bldg:Controller already sitting in the manifest, uncited, because the original
        # searches stopped at SAREF core. Overstating absence is how that survived.
        print(f"    coarse (denoted only by a generic or over-broad class): "
              f"{', '.join(coarse)}")
        if other:
            print(f"    (excluded types, not counted: {', '.join(other)})")
        if len(exact) + len(coarse) != n:
            print(f"    WARNING: {n - len(exact) - len(coarse)} categories carry no "
                  f"alignmentPrecision annotation")

        # Every precision label must carry its search trail. Without this, "coarse" is
        # indistinguishable from "nobody looked" — which is exactly the state the
        # 2026-08-10 pass found, and the reason a published figure had to be retracted.
        ag_comments = {str(s).split("#")[-1]: str(o)
                       for s, o in ag.subject_objects(RDFS.comment)}
        unevidenced = sorted(k for k in prec
                             if k.replace("_", "-") in analysis
                             and "Searched:" not in ag_comments.get(k, ""))
        if unevidenced:
            print(f"    UNEVIDENCED precision labels (no 'Searched:' trail): "
                  f"{', '.join(unevidenced)}")
            bad.append(("alignment", "unevidenced-precision", ", ".join(unevidenced)))
    return (not bad), bad, prec


def check_sources(verbose=True):
    """Verify every study cited in homeiot-sources.ttl exists in the pinned manifest,
    and report how much of the confirmed CVE mass rests on categories no study has
    examined.

    Same mechanism as check_alignment, one level weaker on purpose: it can prove a
    citation KEY is one we registered, never that its bibliographic detail is correct.
    That is what study_sources.tsv's verified= column is for, and why entries marked
    `no` must be confirmed against the actual paper before they reach the report."""
    if not os.path.isfile(SOURCES):
        return None, "homeiot-sources.ttl not found", {}
    if not os.path.isfile(STUDY_MANIFEST):
        return None, "study_sources.tsv not found — cannot verify citations", {}

    known, unverified = {}, set()
    with open(STUDY_MANIFEST, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader((ln for ln in fh if not ln.startswith("#")),
                                delimiter="\t"):
            known[r["iri"]] = r["title"]
            if r["verified"].strip() != "yes":
                unverified.add(r["iri"])

    sg = Graph()
    sg.parse(SOURCES, format="turtle")

    DCT = Namespace("http://purl.org/dc/terms/")
    bad, cited = [], Counter()
    direct, methodological = {}, {}
    for pred, bucket in ((DCT.source, direct), (HIOT.methodologicalSource, methodological)):
        for s, o in sg.subject_objects(pred):
            if not str(s).startswith(str(HIOT)):
                continue
            bucket.setdefault(str(s).split("#")[-1], set()).add(str(o))
            if str(o) in known:
                cited[str(o)] += 1
            else:
                bad.append((str(s).split("#")[-1], str(pred).split("/")[-1], str(o)))

    no_study = {str(s).split("#")[-1]
                for s, _o in sg.subject_objects(HIOT.noDirectStudy)}

    if verbose:
        # The sources file keys on IRI local names (hiot:home_power), the judgment
        # store keys on slugs (home-power). They differ wherever a slug contains a
        # hyphen, so the two must be mapped, not assumed equal.
        g = load()
        slug_of = {str(uri).split("#")[-1]: slug
                   for _o, slug, _l, _n, _f, uri in device_types(g)}
        analysis = set(slug_of)                    # local names of the 24 categories
        print(f"\nsources: {sum(cited.values())} citations over "
              f"{len(known)} registered studies")
        if unverified:
            print(f"  {len(unverified)} of {len(known)} studies are verified=no — "
                  f"titles are real, bibliographic detail is NOT confirmed")
        if bad:
            print("\n  UNREGISTERED citations (not in manifest — likely fabricated):")
            for s, p, o in bad:
                print(f"    {s} {p} {o}")

        n = len(analysis)
        d = sorted(k for k in direct if k in analysis)
        m = sorted(k for k in analysis if k not in direct and k in methodological)
        none_ = sorted(k for k in analysis if k not in direct and k not in methodological)
        print(f"\n  over the {n} analysis categories: {len(d)} with a direct study "
              f"({100*len(d)/n:.0f}%), {len(m)} methodological only, {len(none_)} with none")
        if m:
            print(f"    methodological only: {', '.join(m)}")
        if none_:
            print(f"    no study at all:     {', '.join(none_)}")

        # Weight the gap by confirmed CVEs — a gap over empty categories would not
        # matter. This is the literature-side twin of the SAREF coverage figure.
        try:
            direct_slugs = {slug_of[k] for k in direct if k in slug_of}
            pop = Counter(c for c, _v, _r in load_population())
            total = sum(pop.values())
            if total:
                by_direct = sum(v for k, v in pop.items() if k in direct_slugs)
                print(f"\n  weighted by confirmed CVEs (n={total}): "
                      f"{100*by_direct/total:.1f}% sit on categories a study evaluates "
                      f"directly, {100*(total-by_direct)/total:.1f}% do not")
                gap = sorted(((v, k) for k, v in pop.items() if k not in direct_slugs),
                             reverse=True)[:5]
                if gap:
                    print("    largest unexamined categories: "
                          + ", ".join(f"{k} ({v})" for v, k in gap))
        except (OSError, KeyError):
            pass
    return (not bad), bad, {"direct": direct, "methodological": methodological,
                            "noDirectStudy": no_study, "unverified": unverified}


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


# ---------------------------------------------------------------- KG export (Phase 4)


KG_PREFIXES = {
    "hkg": "https://w3id.org/homeiot/kg#",
    "hiot": str(HIOT),
    "kgv": "https://w3id.org/homeiot/kg/cve/",
    "kgp": "https://w3id.org/homeiot/kg/product/",
    "kgn": "https://w3id.org/homeiot/kg/vendor/",
    "kgw": "https://w3id.org/homeiot/kg/cwe/",
    "kgc": "https://w3id.org/homeiot/kg/cwe888/",
    "kga": "https://w3id.org/homeiot/kg/assignment/",
    "owl": "http://www.w3.org/2002/07/owl#",
    "rdf": str(RDF),
    "rdfs": str(RDFS),
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "dcterms": "http://purl.org/dc/terms/",
}


def _iri_segment(text):
    """Percent-encode a CPE vendor/product token for use in an IRI path segment.

    CPE names legitimately contain characters that are not IRI-safe (escaped dots,
    backslashes, and in a few real vendors a literal '%'), so this cannot be a
    passthrough. `safe=''` deliberately encodes '/' too — a product name containing
    a slash must not silently create a new path level."""
    from urllib.parse import quote
    return quote(text, safe="")


def _uri(prefix, *segments):
    """A full <IRI> for a minted instance.

    Minted resources are NOT written as prefixed names. A Turtle local name may not
    contain '/', and CPE product tokens routinely do once vendor and product are joined
    — writing kgp:tp-link/tapo_p100 produces a file that will not parse. The kgv:/kgp:/…
    prefixes are still declared in the output because they are what a SPARQL author
    wants to type; they are simply not used as an abbreviation mechanism here."""
    return "<%s%s>" % (KG_PREFIXES[prefix], "/".join(segments))


def _lit(value):
    """A Turtle string literal with the five escapes the grammar requires."""
    s = str(value)
    for old, new in (("\\", "\\\\"), ('"', '\\"'), ("\n", "\\n"),
                     ("\r", "\\r"), ("\t", "\\t")):
        s = s.replace(old, new)
    return '"%s"' % s


def load_population(store_path=STORE, include_excluded=False):
    """The confirmed-Yes analysis population, as [(category, cve_id, row)].

    Reads judgment_store.csv rather than final_resolved.csv on purpose. The store is
    the durable home for judgments (CLAUDE.md "Refresh invariant"); final_resolved.csv
    is rebuilt from the per-category review directories and currently lacks 5 confirmed
    rows that are in the store. cwe888_analysis.py and cvss_analysis.py already read the
    store, so this keeps the KG on the same population as RQ1 and RQ2.

    `Excluded` is a non-empty REASON string, not a boolean — mark_excluded.py writes e.g.
    'scope:tvos-2026-07'. Same test as cwe888_analysis.py: any non-empty value excludes."""
    out = []
    with open(store_path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row.get("Final Judgment") != "Yes":
                continue
            if str(row.get("Excluded", "")).strip() and not include_excluded:
                continue
            out.append((row["category"], row["cve_id"], row))
    return out


def hydrate(cve_ids, snapshot=SNAPSHOT):
    """One streaming pass over the fixed NVD snapshot for the CVEs we need."""
    csv.field_size_limit(10 ** 9)
    want, found = set(cve_ids), {}
    with open(snapshot, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row["cve_id"] in want:
                found[row["cve_id"]] = row
    return found


def load_cwe888(path=CWE888_MAP):
    """{cwe_id: (sorted CWE-888 classes, map_depth)} from the derived map, plus any
    CWE that maps inconsistently.

    The map's key is (category, cve_id, cwe_id) — one row per CWE, so a CVE with two
    CWEs occupies two rows. But the CWE-888 assignment itself depends on nothing but the
    CWE: CWE-639 is Access Control wherever it appears. Verified over the real file, all
    155 distinct CWEs map consistently, so this collapses to a per-CWE function and the
    classes are attached to the Weakness instance rather than to each CVE.

    That placement is what lets the graph reproduce RQ1's counting unit. cwe888_analysis.py
    counts a CWE ATTRIBUTION — 'a CVE with two CWEs counts twice, a CWE mapping to two
    classes counts twice'. Hanging a deduplicated set of classes off the CVE would silently
    undercount; walking assignment -> CVE -> weakness -> class reproduces 1,904 exactly."""
    per_cwe, conflicts = {}, []
    if not os.path.isfile(path):
        return per_cwe, conflicts
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            classes = tuple(sorted(c for c in row["cwe888_classes"].split("|") if c.strip()))
            entry = (classes, int(row["map_depth"]))
            prev = per_cwe.setdefault(row["cwe_id"], entry)
            if prev != entry:
                conflicts.append((row["cwe_id"], prev, entry))
    return per_cwe, conflicts


def expected_attributions(path=CWE888_MAP, population=None):
    """RQ1's attribution total, recomputed from the map restricted to the KG population.
    The gate compares this against a SPARQL count over the emitted graph."""
    if not os.path.isfile(path):
        return None
    keys = {(c, v) for c, v, _r in (population or load_population())}
    total = 0
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if (row["category"], row["cve_id"]) in keys:
                total += len([c for c in row["cwe888_classes"].split("|") if c.strip()])
    return total


VECTOR_PREDICATES = {
    "attack_vector": "hkg:attackVector",
    "attack_complexity": "hkg:attackComplexity",
    "privileges_required": "hkg:privilegesRequired",
    "user_interaction": "hkg:userInteraction",
    "scope": "hkg:scope",
    "confidentiality": "hkg:confidentialityImpact",
    "integrity": "hkg:integrityImpact",
    "availability": "hkg:availabilityImpact",
}


def build_kg(g, include_excluded=False, snapshot=SNAPSHOT):
    """Assemble the instance graph as {subject: [(predicate, object)]} with everything
    already rendered as Turtle terms. Returns (triples_by_subject, stats)."""
    pop = load_population(include_excluded=include_excluded)
    slug_to_uri = {slug: uri for _o, slug, *_r, uri in device_types(g)}

    unknown = sorted({c for c, _v, _r in pop} - set(slug_to_uri))
    if unknown:
        raise SystemExit(f"population references slugs absent from the ontology: {unknown}")

    nvd = hydrate({cve for _c, cve, _r in pop}, snapshot=snapshot)
    missing = sorted({cve for _c, cve, _r in pop} - set(nvd))
    cwe888, cwe_conflicts = load_cwe888()

    subj = {}

    def add(s, p, o):
        subj.setdefault(s, set()).add((p, o))

    products, vendors, weaknesses, classes = {}, set(), set(), set()
    n_vectors = [0]                     # CVEs carrying a 3.x-normalised vector

    for cve_id, row in sorted(nvd.items()):
        v = _uri("kgv", cve_id)
        add(v, "rdf:type", "hkg:Vulnerability")
        add(v, "rdfs:label", _lit(cve_id))
        if row.get("description", "").strip():
            add(v, "dcterms:description", _lit(row["description"].strip()))
        if row.get("published", "").strip():
            add(v, "hkg:published", '%s^^xsd:date' % _lit(row["published"].strip()))
        if row.get("cvss_score", "").strip():
            add(v, "hkg:cvssScore", '%s^^xsd:decimal' % _lit(row["cvss_score"].strip()))
        if row.get("cvss_version", "").strip():
            add(v, "hkg:cvssVersion", _lit(row["cvss_version"].strip()))
        # RQ3 vector metrics. Emitted only when the vector normalises to CVSS 3.x —
        # a 2.0-only CVE gets none of them rather than a converted approximation
        # (see ontology/homeiot-kg.ttl for why absence is meaningful here).
        vector = row.get("vector_string", "").strip()
        if vector:
            add(v, "hkg:cvssVector", _lit(vector))
            metrics = parse_vector(vector)
            if metrics:
                n_vectors[0] += 1
                for key, pred in VECTOR_PREDICATES.items():
                    add(v, pred, _lit(metrics[key]))
                add(v, "hkg:impactCombination", _lit(impact_combination(metrics)))

        for cwe in sorted({c.strip() for c in row.get("cwe_ids", "").split("|") if c.strip()}):
            # NVD uses NVD-CWE-noinfo / NVD-CWE-Other as non-CWE placeholders; they are
            # real values in the data and are kept as Weakness instances so a query can
            # distinguish "no weakness assigned" from "weakness assigned but unmapped".
            w = _uri("kgw", _iri_segment(cwe))
            add(v, "hkg:hasWeakness", w)
            add(w, "rdf:type", "hkg:Weakness")
            add(w, "rdfs:label", _lit(cwe))
            weaknesses.add(cwe)

            klasses, depth = cwe888.get(cwe, ((), None))
            for k in klasses:
                c = _uri("kgc", _iri_segment(k.replace(" ", "")))
                add(w, "hkg:hasCwe888Class", c)
                add(c, "rdf:type", "hkg:Cwe888Class")
                add(c, "rdfs:label", _lit(k))
                classes.add(k)
            if depth is not None:
                add(w, "hkg:cwe888MapDepth", '%s^^xsd:integer' % _lit(depth))

        for cpe in sorted({c.strip() for c in row.get("cpe_strings", "").split("|") if c.strip()}):
            parts = cpe.split(":")
            if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
                continue
            part, vend, prod = parts[2], parts[3], parts[4]
            pid = _uri("kgp", _iri_segment(vend), _iri_segment(prod))
            nid = _uri("kgn", _iri_segment(vend))
            add(v, "hkg:affectsProduct", pid)
            if pid not in products:
                products[pid] = (vend, prod)
                add(pid, "rdf:type", "hkg:Product")
                add(pid, "rdfs:label", _lit("%s:%s" % (vend, prod)))
                add(pid, "hkg:cpeName", _lit("%s:%s" % (vend, prod)))
                add(pid, "hkg:vendor", nid)
            # part is per-CPE, not per-product: the same vendor:product can appear as
            # both 'o' and 'h'. Recorded as a multi-valued property rather than collapsed.
            add(pid, "hkg:cpePart", _lit(part))
            if vend not in vendors:
                vendors.add(vend)
                add(nid, "rdf:type", "hkg:Vendor")
                add(nid, "rdfs:label", _lit(vend))
                add(nid, "hkg:vendorName", _lit(vend))

    for category, cve_id, row in sorted(pop, key=lambda r: (r[1], r[0])):
        if cve_id not in nvd:
            continue
        v, dev = _uri("kgv", cve_id), slug_to_uri[category]
        dev_t = "hiot:" + str(dev).split("#")[-1]
        a = _uri("kga", "%s_%s" % (_iri_segment(cve_id), _iri_segment(category)))
        add(v, "hkg:affectsCategory", dev_t)
        add(v, "hkg:assignment", a)
        add(a, "rdf:type", "hkg:CategoryAssignment")
        add(a, "hkg:assignedVulnerability", v)
        add(a, "hkg:assignedCategory", dev_t)
        add(a, "rdfs:label", _lit("%s / %s" % (cve_id, category)))
        if row.get("Final Source", "").strip():
            add(a, "hkg:judgmentSource", _lit(row["Final Source"].strip()))
        human = row.get("Final Source", "").strip() == "human"
        add(a, "hkg:humanSettled", "true" if human else "false")
        if row.get("Difference Type", "").strip():
            add(a, "hkg:discoveryDirection", _lit(row["Difference Type"].strip()))

    stats = {
        "pairs": len(pop),
        "cves": len(nvd),
        "missing_from_snapshot": missing,
        "products": len(products),
        "vendors": len(vendors),
        "weaknesses": len(weaknesses),
        "cwe888_classes": len(classes),
        "cwe888_conflicts": cwe_conflicts,
        "attributions": expected_attributions(population=pop),
        "vectors": n_vectors[0],
        "snapshot": snapshot,
        "triples": sum(len(v) for v in subj.values()),
    }
    return subj, stats


def render_kg(subj, stats):
    """Deterministic Turtle: subjects sorted, predicate/object pairs sorted within a
    subject. PLAN_ontology.md's risk table requires this — an unsorted machine-written
    TTL churns the diff on every regeneration and makes review impossible."""
    import datetime
    out = io.StringIO()
    for pfx, uri in sorted(KG_PREFIXES.items()):
        out.write("@prefix %-8s <%s> .\n" % (pfx + ":", uri))
    out.write("""
################################################################################
# Home IoT Vulnerability Knowledge Graph — INSTANCE DATA
#
# GENERATED. Do not hand-edit; regenerate with
#     python3 scripts/ontology_build.py --export-kg
#
# Schema: ontology/homeiot-kg.ttl. Device types resolve against
# ontology/homeiot.ttl — load all three together to query family rollups.
################################################################################

""")
    out.write("<https://w3id.org/homeiot/kg/graph> rdf:type owl:Ontology ;\n")
    out.write('  dcterms:title "Home IoT Vulnerability Knowledge Graph" ;\n')
    out.write("  owl:imports <https://w3id.org/homeiot/kg>, <https://w3id.org/homeiot/ontology> ;\n")
    out.write('  hkg:snapshotDate "%s"^^xsd:date ;\n' % snapshot_date(stats["snapshot"]))
    out.write('  dcterms:created "%s"^^xsd:date ;\n' % datetime.date.today().isoformat())
    for line in (
        "judgment_store.csv: %d confirmed-Yes (category, cve) pairs, Excluded applied" % stats["pairs"],
        "nvd-snapshot/%s: %d distinct CVEs hydrated, %d with a CVSS 3.x vector"
        % (os.path.basename(stats["snapshot"]), stats["cves"], stats["vectors"]),
        "cwe888_cve_map.csv: %d CWE-888 classes" % stats["cwe888_classes"],
    ):
        out.write('  hkg:generatedFrom %s ;\n' % _lit(line))
    out.write('  owl:versionInfo "0.1.0" .\n\n')

    for s in sorted(subj):
        pairs = sorted(subj[s])
        out.write(s + "\n")
        for i, (p, o) in enumerate(pairs):
            out.write("  %s %s%s\n" % (p, o, " ;" if i < len(pairs) - 1 else " ."))
        out.write("\n")
    return out.getvalue()


def cmd_export_kg(g, include_excluded=False, write=True, snapshot=SNAPSHOT):
    subj, stats = build_kg(g, include_excluded=include_excluded, snapshot=snapshot)
    text = render_kg(subj, stats)

    if stats["missing_from_snapshot"]:
        print("WARNING: %d confirmed CVEs are absent from the NVD snapshot and were "
              "skipped:" % len(stats["missing_from_snapshot"]))
        for cve in stats["missing_from_snapshot"][:10]:
            print("   ", cve)
    if stats["cwe888_conflicts"]:
        print("WARNING: %d CWEs map to different CWE-888 classes on different rows — the "
              "per-CWE collapse in load_cwe888() is unsafe:" % len(stats["cwe888_conflicts"]))
        for cwe, a, b in stats["cwe888_conflicts"][:5]:
            print("    %s: %s vs %s" % (cwe, a, b))

    if write:
        os.makedirs(os.path.dirname(KG_OUT), exist_ok=True)
        with open(KG_OUT, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        print("wrote %s (%.1f MB)" % (os.path.relpath(KG_OUT, ROOT), len(text) / 1e6))

    return verify_kg(text, stats, g)


def verify_kg(text, stats, g):
    """Phase 4 gate: the emitted graph must reparse in rdflib, its instance counts must
    reconcile against the source CSVs, and a family rollup answered purely by the class
    hierarchy in homeiot.ttl must match one computed from families.csv."""
    print("\n--- Phase 4 gate ---")
    failures = []

    kg = Graph()
    kg.parse(data=text, format="turtle")
    print("reparse: %d triples load in rdflib ✓" % len(kg))

    HKG = Namespace("https://w3id.org/homeiot/kg#")
    counts = {
        "Vulnerability": (len(set(kg.subjects(RDF.type, HKG.Vulnerability))), stats["cves"]),
        "CategoryAssignment": (len(set(kg.subjects(RDF.type, HKG.CategoryAssignment))),
                               stats["pairs"]),
        "Product": (len(set(kg.subjects(RDF.type, HKG.Product))), stats["products"]),
        "Vendor": (len(set(kg.subjects(RDF.type, HKG.Vendor))), stats["vendors"]),
        "Cwe888Class": (len(set(kg.subjects(RDF.type, HKG.Cwe888Class))),
                        stats["cwe888_classes"]),
    }
    print("\n%-20s %10s %10s" % ("instance class", "in graph", "expected"))
    for name, (got, want) in counts.items():
        ok = got == want
        print("%-20s %10d %10d   %s" % (name, got, want, "ok" if ok else "MISMATCH"))
        if not ok:
            failures.append(name)

    n_edges = len(list(kg.subject_objects(HKG.affectsCategory)))
    if n_edges != stats["pairs"]:
        print("affectsCategory edges %d != %d pairs   MISMATCH" % (n_edges, stats["pairs"]))
        failures.append("affectsCategory")
    else:
        print("\naffectsCategory edges: %d = confirmed pairs ✓" % n_edges)

    # Per-category reconciliation against the store, straight from the graph.
    per_cat = Counter()
    for _a, dev in kg.subject_objects(HKG.assignedCategory):
        per_cat[str(next(g.objects(dev, HIOT.slug)))] += 1
    store = Counter(c for c, _v, _r in load_population())
    bad = {k for k in set(per_cat) | set(store) if per_cat[k] != store[k]}
    n_defined = len(device_types(g))
    print("per-category counts vs judgment_store: %s"
          % ("all %d categories agree ✓ (%d of the %d defined carry no confirmed CVE)"
             % (len(per_cat), n_defined - len(per_cat), n_defined) if not bad
             else "MISMATCH on %s" % sorted(bad)))
    if bad:
        failures.append("per-category")

    # RQ1 reconciliation. The counting unit is a CWE ATTRIBUTION, which is why the
    # CWE-888 classes hang off the Weakness rather than the CVE: this walk yields
    # (category, cve, cwe, class) tuples, exactly cwe888_analysis.py's unit.
    q = """
    SELECT (COUNT(*) AS ?n) WHERE {
      ?a hkg:assignedVulnerability ?v .
      ?v hkg:hasWeakness ?w .
      ?w hkg:hasCwe888Class ?c .
    }"""
    got = int(next(iter(kg.query(q, initNs={"hkg": HKG})))[0])
    want = stats["attributions"]
    ok = want is not None and got == want
    print("CWE-888 attributions (SPARQL over the graph): %d vs %s from cwe888_cve_map.csv"
          " %s" % (got, want, "✓" if ok else "MISMATCH"))
    if not ok:
        failures.append("attributions")

    # The point of shipping the KG with the ontology rather than a CSV: family
    # membership is not re-encoded here, it is inferred from rdfs:subClassOf in
    # homeiot.ttl. This must reproduce the families.csv rollup exactly.
    fam_from_graph = Counter()
    for _a, dev in kg.subject_objects(HKG.assignedCategory):
        for parent in g.objects(dev, RDFS.subClassOf):
            fid = next(g.objects(parent, HIOT.familyId), None)
            if fid is not None:
                fam_from_graph[str(fid)] += 1
    fam_expected = Counter()
    slug_fam = {slug: fam for _o, slug, _l, _n, fam, _u in device_types(g)}
    for cat, _cve, _row in load_population():
        fam_expected[slug_fam[cat]] += 1
    fam_bad = {k for k in set(fam_from_graph) | set(fam_expected)
               if fam_from_graph[k] != fam_expected[k]}
    print("family rollup via rdfs:subClassOf: %s"
          % ("all %d families match families.csv ✓ (%d of %d carry no confirmed CVE)"
             % (len(fam_from_graph), len(families(g)) - len(fam_from_graph), len(families(g)))
             if not fam_bad else "MISMATCH on %s" % sorted(fam_bad)))
    if fam_bad:
        failures.append("family-rollup")

    print("\n%s" % ("gate: PASS" if not failures else "gate: FAIL — %s" % ", ".join(failures)))
    return 1 if failures else 0


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

    ok_align, bad_align, _prec = check_alignment(verbose=False)
    if ok_align is None:
        print(f"alignment: NOT RUN — {bad_align}")
    elif ok_align:
        print("alignment: all external IRIs verified against manifest ✓")
    else:
        print(f"alignment: {len(bad_align)} UNVERIFIED external IRI(s)")
        for sbj, pred, obj in bad_align:
            print(f"  {sbj} {pred} {obj}")
        failures.append("alignment")

    # Facet provenance. Not a failure condition — Estimated facets are legitimate for
    # organising the analysis. It is printed on every --check so that the share of
    # unevidenced facets stays visible instead of becoming invisible through habit.
    tiers = Counter()
    assertions = Counter()
    slugs = {uri for *_r, uri in cats}
    for prop, tier in g.subject_objects(HIOT.evidenceTier):
        name = str(tier).split("#")[-1]
        tiers[name] += 1
        assertions[name] += sum(1 for s, _o in g.subject_objects(prop) if s in slugs)
    if tiers:
        summary = ", ".join(f"{n} {k.lower()}" for k, n in sorted(tiers.items()))
        print(f"facet provenance: {summary} "
              f"({assertions['Estimated']} of {sum(assertions.values())} assertions "
              f"unevidenced — organising structure, not citable)")

    # Phase A heterogeneity, printed for the same reason as provenance above: a
    # category-level value that is false for most of the devices it lands on is a
    # validity problem, and validity problems fade from view faster than schema ones.
    # Also not a failure condition — the CSV is the machine-readable source and
    # facet_analysis.py is what enforces it; this is the visibility surface, so the
    # hand-authored TTL never has to carry 120 measured numbers it would drift from.
    print(phase_a_line())

    ok_src, bad_src, _info = check_sources(verbose=False)
    if ok_src is None:
        print(f"sources: NOT RUN — {bad_src}")
    elif ok_src:
        print("sources: all cited studies verified against manifest ✓")
    else:
        print(f"sources: {len(bad_src)} UNREGISTERED citation(s)")
        for sbj, pred, obj in bad_src:
            print(f"  {sbj} {pred} {obj}")
        failures.append("sources")

    # Never hardcode the ruling count. It was literally "27" here, so adding a
    # negative case would have printed "28/27 rulings reproduced".
    n_rulings = len(cats) + len(device_types(g, excluded=True))
    mismatches = reason(g, verbose=False)
    print(f"reasoner: {n_rulings - len(mismatches)}/{n_rulings} rulings reproduced"
          if not mismatches else
          f"reasoner: {len(mismatches)} MISMATCH — run --reason")
    if mismatches:
        failures.append("reasoner")

    return 1 if failures else 0


# The five conjuncts of hiot:InScopeDeviceType, as they appear verbatim in the TTL.
# --self-test deletes each in turn and requires the reasoner to notice.
AXIOM_CONJUNCTS = {
    "1 connectivity": "      [ a owl:Restriction ; owl:onProperty hiot:hasConnectivity ; "
                      "owl:someValuesFrom hiot:Protocol ]\n",
    "2 device class": "      [ a owl:Restriction ; owl:onProperty hiot:hasDeviceClass ; "
                      "owl:someValuesFrom hiot:SpecialPurposeEmbedded ]\n",
    "3 deployment":   "      [ a owl:Restriction ; owl:onProperty hiot:hasDeployment ; "
                      "owl:hasValue hiot:Residential ]\n",
    "4 function/role": """      [ a owl:Class ; owl:unionOf (
          [ a owl:Restriction ; owl:onProperty hiot:hasFunction ; owl:someValuesFrom hiot:HomeControlFunction ]
          [ a owl:Restriction ; owl:onProperty hiot:hasRole ; owl:someValuesFrom hiot:HomeControlSurfaceRole ] ) ]\n""",
    "5 security ctx": "      [ a owl:Restriction ; owl:onProperty hiot:hasSecurityContext ; "
                      "owl:hasValue hiot:ConsumerManaged ]\n",
}


def cmd_self_test(ttl=TTL):
    """Prove every criterion in the membership axiom is load-bearing.

    Deletes each conjunct in turn and requires --reason to report a mismatch. A
    criterion that can be removed while the build stays green is not being enforced,
    and the 'the reasoner reproduces every published ruling' claim is worth exactly
    as much as the negative cases behind it.

    Measured before the single-criterion boundary cases were added: only criterion 4
    was caught (by transport-networking, the sole type failing one criterion alone);
    1, 2, 3 and 5 were all silently deletable. gameconsoles and vrar caught nothing,
    because each fails 2 AND 4 and so isolates neither."""
    with open(ttl, encoding="utf-8") as fh:
        src = fh.read()

    print("axiom self-test: deleting each criterion, expecting the reasoner to object\n")
    print(f"{'deleted conjunct':20} {'detected by':>34}   result")
    print("-" * 72)
    failures = []
    for name, conjunct in AXIOM_CONJUNCTS.items():
        if conjunct not in src:
            print(f"{name:20} {'':>34}   ANCHOR NOT FOUND — axiom text changed")
            failures.append(name)
            continue
        g2 = Graph()
        g2.parse(data=src.replace(conjunct, "", 1), format="turtle")
        caught = reason(g2, verbose=False)
        who = ", ".join(sorted(slug for slug, *_r in caught)) if caught else "nothing"
        ok = bool(caught)
        print(f"{name:20} {who[:34]:>34}   {'ok' if ok else 'NOT ENFORCED'}")
        if not ok:
            failures.append(name)

    print("-" * 72)
    if failures:
        print(f"self-test: FAIL — {len(failures)} criterion/criteria not enforced by any "
              f"negative case: {', '.join(failures)}")
        print("  Fix by adding a defined-but-excluded type that fails ONLY that criterion.")
    else:
        print(f"self-test: PASS — all {len(AXIOM_CONJUNCTS)} criteria are load-bearing")
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
                    help="print the 31-class in/out ruling table")
    ap.add_argument("--align", action="store_true",
                    help="verify external alignment IRIs and report coverage")
    ap.add_argument("--self-test", action="store_true",
                    help="delete each criterion from the membership axiom in turn and "
                         "require the reasoner to catch it; proves the criteria are "
                         "load-bearing rather than decorative")
    ap.add_argument("--sources", action="store_true",
                    help="verify study citations against the pinned manifest and report "
                         "how much confirmed-CVE mass rests on categories no study "
                         "examines directly")
    ap.add_argument("--export-kg", action="store_true",
                    help="emit the instance graph to data/ontology/homeiot-kg.ttl and run "
                         "the Phase 4 gate")
    ap.add_argument("--verify-kg", action="store_true",
                    help="rebuild the graph in memory and run the gate without writing")
    ap.add_argument("--include-excluded", action="store_true",
                    help="KG export only: keep rows carrying a judgment_store Excluded "
                         "reason (default drops them, matching cwe888_analysis.py)")
    ap.add_argument("--ttl", default=TTL, help="ontology file (default: ontology/homeiot.ttl)")
    ap.add_argument("--snapshot", default=SNAPSHOT,
                    help="KG export only: NVD snapshot to hydrate CVEs from (default: "
                         "data/nvd-snapshot/nvd_all.csv). cwe888_analysis.py and "
                         "cvss_analysis.py take the same flag — point all three at one "
                         "vintage, or the graph reconciles against a CWE map built from "
                         "different data.")
    args = ap.parse_args()

    if not (args.check or args.write or args.reason or args.align or args.sources
            or args.self_test or args.export_kg or args.verify_kg):
        ap.error("pick one of --check / --write / --reason / --align / --sources "
                 "/ --self-test / --export-kg / --verify-kg")

    g = load(args.ttl)
    rc = 0
    if args.align:
        ok, bad, _ = check_alignment()
        rc |= 0 if ok else 1
    if args.sources:
        ok, bad, _ = check_sources()
        rc |= 0 if ok else 1
    if args.reason:
        rc |= 1 if reason(g) else 0
    if args.self_test:
        rc |= cmd_self_test(args.ttl)
    if args.check:
        rc |= cmd_check(g)
    if args.write:
        rc |= cmd_write(g)
    if args.export_kg or args.verify_kg:
        rc |= cmd_export_kg(g, include_excluded=args.include_excluded,
                            write=args.export_kg, snapshot=args.snapshot)
    return rc


if __name__ == "__main__":
    sys.exit(main())
