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

PHASE A VERDICTS ARE ENFORCED HERE, NOT REMEMBERED. Dominance asks whether a facet
cell is really one category in disguise. Phase A (facet_sample.py) asks something
upstream of that: whether the category-level value is even TRUE of the devices it is
stamped onto. It sampled devices per category and measured the modal value's share,
and 12 of 120 measured cells came back below 0.60 — cameras/capturesAV at 0.591
(~43% of sampled camera devices are recorders, which have no lens), doorlock/
cloudDependence at 0.389. For those cells a single value is a fiction, and no
amount of annotator agreement repairs it.

So this script REFUSES to print one. Every category carries its Phase A verdict and
modal share into the output; a NOT-USABLE category is withheld from the value's
category breakdown and reported as a distribution instead, and an UNMEASURED one
(Phase A could not sample it — too few CVEs, mega-CPE-bound, or empty) is labelled
as such rather than silently counted as fine. --ignore-phase-a reproduces the old
unguarded behaviour for A/B, the same convention every other guardrail here follows
(cpe_expansion.py --no-part-filter, facet_sample.py --keep-shared).

Note the asymmetry that makes this worth doing in code: a NOT-USABLE cell still
contributes its CVEs to the population total, because those CVEs are real and
confirmed. What is unsafe is attributing them to a single facet VALUE. Withholding
the attribution while keeping the count is exactly the distinction a human reading a
policy note forgets, and the reason this is a join rather than a docstring.

THERE ARE TWO WITHHOLDING SOURCES, AND THEY ARE DIFFERENT INSTRUMENTS. Phase A finds
heterogeneity by SAMPLING DEVICES, so it can only speak about the 10 categories it had
the CVE mass to sample. F5's sourced category pass finds it a second way: when the two
reviewers of a cell split along a subfamily line, each right about a different half,
that is the NOT-USABLE condition reached through disagreement rather than sampling.
`garden` is the worked case — Ecovacs robot mowers (42% of the category's CVEs) against
RainMachine irrigation controllers (32%), where capturesAV is true of the mowers and
false of the controllers. Phase A never tested `garden` at all (n=19, below its CVE
floor), so the reviewer split is the ONLY instrument that could have caught it, and
before this join those 5 cells printed as `[unmeasured]` — the label that means "nobody
looked", on cells somebody had looked at and ruled unusable.

So facet_store.csv is read as a second withholding source, and the two are kept
distinguishable in the output rather than merged into one count: a Phase A withholding
carries a measured modal share and n_devices, a reviewer-split withholding carries
neither and must never be rendered as though it did. Each guard has its own A/B switch
(--ignore-phase-a, --ignore-f5-exclusions), the same convention every other guardrail
in this pipeline follows.
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
DISTRIBUTION = os.path.join(ROOT, "data", "facets", "facet_distribution.csv")
FACET_STORE = os.path.join(ROOT, "data", "facets", "facet_store.csv")

# Phase A verdict -> how a (category, facet) may be used. The thresholds are
# facet_sample.py's, restated here only as labels; the numbers live in that script so
# the two cannot drift.
USABLE = "summary-defensible"      # >= 0.80 — a value is a defensible summary
GROUPING = "grouping-only"         # 0.60-0.80 — group by it, do not report it
NOT_USABLE = "NOT-USABLE-report-distribution"   # < 0.60 — no single value is true
UNMEASURED = "UNMEASURED"          # Phase A could not sample this category at all

# F5's verdict for the same condition reached by a different instrument: the two
# reviewers of a cell split along a subfamily line, so the category holds two device
# types and no single value is true of both. Recorded in facet_store.csv, never in
# facet_distribution.csv — that file is facet_sample.py's machine-written output and
# hand-adding a row with no n_devices and no modal_share would misrepresent a reviewer
# split as a sampled measurement.
NOT_USABLE_SPLIT = "NOT-USABLE-reviewer-split"

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


def load_phase_a(path=DISTRIBUTION):
    """{(category, facet): {verdict, share, modal, n}} from facet_sample.py --aggregate.

    Absent file is not an error — Phase A is a separate study and this script predates
    it — but it IS reported, because silently treating unmeasured cells as sound is the
    failure mode the whole join exists to prevent.
    """
    if not os.path.exists(path):
        return None
    out = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            share = r.get("modal_share_cve", "").strip()
            out[(r["category"], r["facet"])] = {
                "verdict": r.get("verdict", "").strip() or UNMEASURED,
                # CVE-weighted is the right weighting here: this script counts CVE rows,
                # so the question is what the CVE population looks like, not what the
                # typical product looks like (plan decision 9B).
                "share": float(share) if share else None,
                "modal": r.get("modal_value_cve", "").strip(),
                "n": r.get("n_devices", "").strip(),
                "divergent": bool(r.get("weighting_divergence", "").strip()),
            }
    return out


def load_f5_exclusions(path=FACET_STORE):
    """{(category, facet): notes} for cells F5 excluded on a reviewer split.

    Only NOT_USABLE_SPLIT is read. The store also carries the 12 Phase A
    NOT-USABLE cells, but those come from facet_distribution.csv already and that
    file is the machine-written source of truth for them — reading them twice would
    let a hand-edited copy silently outvote the measurement it was copied from.

    Absent file is not an error (F5 is a separate pass), but it IS reported, for the
    same reason load_phase_a reports a missing distribution file.
    """
    if not os.path.exists(path):
        return None
    out = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if (r.get("Phase A Verdict", "") or "").strip() != NOT_USABLE_SPLIT:
                continue
            note = (r.get("Notes 1", "") or r.get("Notes 2", "") or "").strip()
            out[(r["slug"], r["facet"])] = note
    return out


def verdict_for(phase_a, cat, facet):
    """Phase A's ruling on one (category, facet), or UNMEASURED."""
    if phase_a is None:
        return None
    return phase_a.get((cat, facet), {"verdict": UNMEASURED, "share": None,
                                      "modal": "", "n": "", "divergent": False})


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
    ap.add_argument("--ignore-phase-a", action="store_true",
                    help="report every category-level value regardless of its Phase A "
                         "heterogeneity verdict — the pre-enforcement behaviour, kept "
                         "for A/B only. A cell Phase A marked NOT-USABLE has a modal "
                         "value that is false for >40%% of the devices it lands on")
    ap.add_argument("--ignore-f5-exclusions", action="store_true",
                    help="report cells F5 excluded on a reviewer split as though no "
                         "one had looked at them. Separate switch from --ignore-phase-a "
                         "because it is a separate instrument: a split is evidence of "
                         "heterogeneity in a category Phase A could not sample at all")
    args = ap.parse_args()

    facets = load_facets()
    pop = load_population()
    fam = load_families()
    wanted = args.facet or FACETS

    phase_a = None if args.ignore_phase_a else load_phase_a()
    f5_excluded = {} if args.ignore_f5_exclusions else load_f5_exclusions()

    per_cat = collections.Counter(c for c, _v in pop)
    total = len(pop)
    key = (lambda c: fam.get(c, c)) if args.group == "family" else (lambda c: c)

    cross = load_cross(args.cross) if args.cross else None

    print(f"confirmed-Yes population: {total} CVE-category pairs over "
          f"{len(per_cat)} categories")
    print(f"dominance attributed by {args.group}; flagged above "
          f"{args.dominance_threshold:.0%}")
    if args.ignore_phase_a:
        print("Phase A: DISABLED (--ignore-phase-a) — values below the 0.60 modal-share "
              "gate are being reported as if sound")
    elif phase_a is None:
        print(f"Phase A: no {os.path.relpath(DISTRIBUTION, ROOT)} — heterogeneity "
              "UNMEASURED for every cell; treat every value as unvalidated")
    else:
        vc = collections.Counter(v["verdict"] for v in phase_a.values())
        print(f"Phase A: {vc[USABLE]} defensible / {vc[GROUPING]} grouping-only / "
              f"{vc[NOT_USABLE]} NOT-USABLE over {len(phase_a)} measured cells; "
              "unmeasured categories are marked [unmeasured]")
    if args.ignore_f5_exclusions:
        print("F5 exclusions: DISABLED (--ignore-f5-exclusions) — cells a reviewer "
              "split ruled unusable are being reported as if unexamined")
    elif f5_excluded is None:
        print(f"F5 exclusions: no {os.path.relpath(FACET_STORE, ROOT)} — reviewer-split "
              "heterogeneity unchecked; only Phase A's sampled verdicts are enforced")
        f5_excluded = {}
    else:
        cats = sorted({c for c, _f in f5_excluded})
        print(f"F5 exclusions: {len(f5_excluded)} cells withheld on a reviewer split "
              f"({', '.join(cats) if cats else 'none'}) — heterogeneity found by "
              "disagreement, in categories Phase A could not sample")
    print()

    for f in wanted:
        # Partition the contributing categories by Phase A verdict BEFORE counting.
        # NOT-USABLE categories are withheld from every value cell of this facet: their
        # CVEs are real, but attributing them to one facet value is what Phase A
        # measured to be false. Unmeasured categories are counted and labelled, never
        # silently promoted to sound (plan decision 12A).
        # Two withholding sources, checked in that order. Phase A wins a tie because
        # it carries a measured modal share, which is the stronger statement; the F5
        # split is what catches the categories Phase A could not sample, so it is
        # checked against the UNMEASURED cells rather than competing for the sampled
        # ones.
        withheld, split_withheld, unmeasured = {}, {}, []
        for cat in {c for c, _v in pop}:
            if not facets.get(cat, {}).get(f):
                continue
            va = verdict_for(phase_a, cat, f)
            if va is not None and va["verdict"] == NOT_USABLE:
                withheld[cat] = va
                continue
            if (cat, f) in f5_excluded:
                split_withheld[cat] = f5_excluded[(cat, f)]
                continue
            if va is not None and va["verdict"] == UNMEASURED:
                unmeasured.append(cat)

        cells = collections.defaultdict(collections.Counter)
        withheld_n = collections.Counter()
        for cat, cve in pop:
            for v in facets.get(cat, {}).get(f, ()):
                if cat in withheld or cat in split_withheld:
                    withheld_n[cat] += 1
                    continue
                cells[v][key(cat)] += 1
        if not cells and not withheld_n:
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

        # The withheld block is the enforcement made visible. A reader who wants the
        # old number has to see why it is not being printed, which is the whole point
        # of doing this in code rather than in a policy note.
        for cat, va in sorted(withheld.items(), key=lambda kv: -withheld_n[kv[0]]):
            asserted = "/".join(sorted(facets.get(cat, {}).get(f, ())))
            share = va["share"]
            print(f"  WITHHELD {cat}: {withheld_n[cat]} CVEs, asserted {asserted} — "
                  f"Phase A modal share {share:.3f} (n={va['n']} devices) is below the "
                  f"0.60 gate, so no single value is reportable for this category")
        # Deliberately a separate line with no share and no n: a reviewer split has
        # neither, and printing it in the Phase A format would dress a disagreement up
        # as a measurement.
        for cat, note in sorted(split_withheld.items(),
                                key=lambda kv: -withheld_n[kv[0]]):
            asserted = "/".join(sorted(facets.get(cat, {}).get(f, ())))
            print(f"  WITHHELD {cat}: {withheld_n[cat]} CVEs, asserted {asserted} — "
                  f"F5 reviewer split (no sampled share; the category holds two device "
                  f"subfamilies and each reviewer was right about one)"
                  + (f": {note[:110]}" if note else ""))
        if unmeasured:
            un_n = sum(1 for c, _v in pop
                       if c in set(unmeasured) and facets.get(c, {}).get(f))
            print(f"  [unmeasured] {len(unmeasured)} categories / {un_n} CVEs not "
                  f"sampled by Phase A: {', '.join(sorted(unmeasured)[:6])}"
                  + (" …" if len(unmeasured) > 6 else ""))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
