#!/usr/bin/env python3
"""Phase A — measure within-category facet heterogeneity from a product sample.

WHY THIS EXISTS. Facets are asserted per *category* but every analysis joins them onto
*CVE rows*. If a category is internally varied, a single facet value is not an
approximation of that category — it is a fiction stamped onto every CVE in it. No amount
of annotator agreement repairs that: three annotators can agree perfectly on a value that
is wrong for half the rows it lands on. Agreement is reliability; this is validity, and it
sits upstream of the whole annotation study (see docs/plans/PLAN_facet_annotation.md
Phase A, which gates Phase 0 on this script's output).

The concern is not hypothetical. The confirmed-Yes set resolves to thousands of distinct
devices, most of them in `cameras`, which is ~51% of the population. `--frame` prints the
real numbers.

WHAT IT DOES. Builds a sampling frame of distinct devices from confirmed-Yes CVEs, draws a
per-category sample, and emits an annotation sheet. A second pass (`--aggregate`) reads the
filled sheet back and reports, per (category, facet), the modal value and its share under
BOTH weightings.

THE HARD CONSTRAINT — product identity only, never CVE text.
    The emitted sheet carries vendor, product, and category. It carries NO CVE
    description, NO CWE, NO CVSS vector, and this is enforced in code (see SHEET_COLS and
    the assertion in write_sample). If a facet were assigned from CVE text, then any
    later facet-vs-weakness contrast would be correlating that text with itself — which is
    exactly how facet_derive.py became circular and why two of its contrasts stand
    retracted in CLAUDE.md. Keeping the annotator away from the description is what makes
    facet and weakness independent, and it is the difference between a citable contrast
    and a circular one. `cve_count` is carried because it is a WEIGHT, not evidence about
    the device; it must not inform the facet judgment.

SAMPLING. Uniform per category, with each device's confirmed-Yes CVE count recorded, so a
single pass yields both estimates (plan decision 9B):
    - product-weighted  — "what is a typical camera product like"
    - CVE-weighted      — "what does the camera CVE population look like"
The second is what the analysis actually needs; the gap between them is itself a result,
since a large divergence means the CVE-heavy devices are atypical of their category and
the dominance problem is worse than category counts suggest.

n defaults to 40, sized for the DECISION (is this category ~90/10 or ~55/45?) and not for
precision: at the worst case p=0.5, n=40 gives roughly +/-15pp. Pinning a value precisely
is not what this phase is for. Categories with fewer devices than n are taken whole.

FACETS. The 12 single-valued facets only — derived from shapes.ttl (sh:maxCount 1), never
hardcoded, so the list cannot drift from the ontology. The 7 multi-valued facets already
express within-category spread by construction and are not at risk.

GUARDRAILS. Reuses cpe_expansion's device-CPE granularity exactly (part in {o,h},
vendor:product only, GENERIC_PLATFORM_CPES denied) and its Excluded-aware Yes loader, so
the frame is held to the same bar as every other CPE-derived artifact here. Firmware and
hardware twins collapse to one device via device_str.

Usage:
    python3 scripts/facet_sample.py --frame              # frame stats only, no draw
    python3 scripts/facet_sample.py --draw               # draw + write annotation sheet
    python3 scripts/facet_sample.py --draw -n 60 --seed 7
    python3 scripts/facet_sample.py --aggregate          # read filled sheet -> distribution

Writes  data/facets/product_frame.csv        (every device, with its CVE weight)
        data/facets/product_sample.csv       (the annotation sheet — identity only)
        data/facets/facet_distribution.csv   (--aggregate output)
"""
import argparse
import csv
import os
import random
import sys
from collections import Counter, defaultdict

from rdflib import Graph, RDF, RDFS, Namespace

from cpe_expansion import (
    DEVICE_PARTS,
    GENERIC_PLATFORM_CPES,
    device_str,
    load_raw_rows,
    load_snapshot_cpe_fallback,
    load_yes_cve_ids,
    parse_cpe,
)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
ONTO = os.path.join(ROOT, "ontology")
OUTDIR = os.path.join(DATA, "facets")

HIOT = Namespace("https://w3id.org/homeiot/ontology#")
SH = Namespace("http://www.w3.org/ns/shacl#")

csv.field_size_limit(1 << 24)

DEFAULT_N = 40
DEFAULT_SEED = 20260807

# The annotation sheet's columns. CVE-derived text is absent BY CONSTRUCTION, not by
# convention — write_sample asserts this set is exactly what gets written.
SHEET_COLS = [
    "category", "device", "vendor", "product", "cve_count",
    "facet", "allowed_values",
    "Value", "Confidence", "Reasoning",
]
FORBIDDEN_IN_SHEET = {"description", "cwe_ids", "cvss_score", "vector_string", "cve_id"}


# ---------------------------------------------------------------- ontology introspection

def load_facet_spec():
    """The 12 single-valued facets and their allowed values, read from the ontology.

    Single-valued is decided by shapes.ttl (sh:maxCount 1) rather than a hardcoded list, so
    this cannot drift from the ontology the way a copied list would. Booleans get
    true/false; object properties get the individuals of their rdfs:range class.
    """
    g = Graph()
    g.parse(os.path.join(ONTO, "homeiot.ttl"), format="turtle")
    shapes = Graph()
    shapes.parse(os.path.join(ONTO, "shapes.ttl"), format="turtle")

    # Facet properties are exactly those carrying an evidenceTier annotation.
    tiered = {p for p in g.subjects(HIOT.evidenceTier, None)}

    single = set()
    for pshape in shapes.subjects(SH.maxCount, None):
        path = shapes.value(pshape, SH.path)
        maxc = shapes.value(pshape, SH.maxCount)
        if path in tiered and int(maxc) == 1:
            single.add(path)

    spec = {}
    for prop in sorted(single, key=str):
        name = str(prop).split("#")[1]
        rng = g.value(prop, RDFS.range)
        if rng is not None and str(rng).endswith("#boolean"):
            values = ["true", "false"]
        else:
            values = sorted(
                str(i).split("#")[1] for i in g.subjects(RDF.type, rng)
            )
        if not values:
            continue
        spec[name] = values
    return spec


def load_categories():
    """slug -> label, from the generated categories.csv (the frozen 24)."""
    path = os.path.join(DATA, "categories.csv")
    with open(path, newline="") as f:
        return {r["slug"]: r["label"] for r in csv.DictReader(f)}


# --------------------------------------------------------------------- frame construction

def build_frame(slugs):
    """(category, device) -> confirmed-Yes CVE count, plus per-category coverage stats.

    Mirrors cpe_expansion.build_seeds' guardrails so a device enters this frame on exactly
    the terms it would enter a Stage-5 seed set.
    """
    frame = defaultdict(Counter)
    stats = {}
    for slug in slugs:
        yes = load_yes_cve_ids(slug)
        if not yes:
            stats[slug] = {"yes": 0, "no_device_cpe": 0, "devices": 0}
            continue
        raw = load_raw_rows(slug)
        missing = {c for c in yes if c not in raw}
        raw.update(load_snapshot_cpe_fallback(missing))

        no_cpe = 0
        dev_cves = defaultdict(set)   # device -> the CVEs it came from (for n_eff)
        for cve in yes:
            row = raw.get(cve) or {}
            devices = set()
            for cpe in (row.get("cpe_strings") or "").split("|"):
                cpe = cpe.strip()
                if not cpe:
                    continue
                part, vp = parse_cpe(cpe)
                if vp is None or part not in DEVICE_PARTS:
                    continue
                if vp in GENERIC_PLATFORM_CPES:
                    continue
                devices.add(device_str(vp))
            if not devices:
                no_cpe += 1
            for d in devices:
                frame[slug][d] += 1
                dev_cves[d].add(cve)
        # Largest single CVE's device list. A CVE listing 178 devices is ONE piece of
        # evidence, not 178 — see report_frame's warning.
        per_cve = Counter()
        for d, cs in dev_cves.items():
            for c in cs:
                per_cve[c] += 1
        stats[slug] = {
            "yes": len(yes),
            "no_device_cpe": no_cpe,
            "devices": len(frame[slug]),
            "widest_cve": per_cve.most_common(1)[0][1] if per_cve else 0,
            "dev_cves": dev_cves,
        }
    return frame, stats


MIN_CVES = 20          # below this a category cannot support a distribution estimate
MIN_DEVICES = 10       # below this there is nothing to sample — take the population whole


def regime(s):
    """Which sampling regime a category falls in.

    Device count and CVE count are badly decoupled here, and the decoupling is not noise —
    it is NVD listing one vulnerability against a whole product catalogue. `airpurifier`
    has 2 confirmed CVEs whose CPE lists name 178 and 119 devices; `fridge` and
    `airconditioner` inherit the same two. Drawing 40 devices there yields 40 annotation
    rows that collectively describe TWO CVEs, and — worse — the output would look like a
    well-sampled category unless the regime is stated. A CVE listing 178 devices is one
    piece of evidence, not 178.

    Flags triage, they never filter (same convention as the discovery miners): this labels
    every category and drops none. Deciding what to do with `mega-cpe-bound` is a judgement
    call for a human, not this script.
    """
    if s["devices"] == 0:
        return "empty"
    if s["yes"] < MIN_CVES:
        return "too-few-cves"
    if s["devices"] < MIN_DEVICES:
        return "take-whole"
    if s["widest_cve"] >= s["devices"] * 0.5:
        return "mega-cpe-bound"
    return "samplable"


def report_frame(frame, stats, labels):
    tot_yes = sum(s["yes"] for s in stats.values())
    tot_nocpe = sum(s["no_device_cpe"] for s in stats.values())
    all_devices = set()
    for slug, ctr in frame.items():
        all_devices |= set(ctr)

    print(f"{'category':18s} {'yes':>6s} {'devices':>8s} {'no-CPE':>7s} {'widest CVE':>11s} {'regime':>12s}")
    print("-" * 72)
    for slug in sorted(stats, key=lambda s: -stats[s]["devices"]):
        s = stats[slug]
        print(f"{slug:18s} {s['yes']:6d} {s['devices']:8d} {s['no_device_cpe']:7d} "
              f"{s.get('widest_cve', 0):11d} {regime(s):>12s}")
    print("-" * 72)
    print(f"{'TOTAL':18s} {tot_yes:6d} {len(all_devices):8d} {tot_nocpe:7d}")
    if tot_yes:
        pct = tot_nocpe / tot_yes * 100
        print(f"\n{tot_nocpe} of {tot_yes} confirmed-Yes rows ({pct:.1f}%) carry no device CPE and")
        print("cannot be product-sampled at any budget. They keep a category-level facet by")
        print("necessity; report this share next to any Phase A result.")


# ------------------------------------------------------------------------------- sampling

def draw(frame, stats, n, seed):
    """Uniform draw of n devices per SAMPLABLE category (whole population if fewer).

    Uniform rather than probability-proportional-to-size because recording each device's
    cve_count lets BOTH estimates come out of one pass (plan decision 9B). A PPS draw would
    give the CVE-weighted estimate directly but foreclose the product-weighted one.

    Only `samplable` categories are drawn (plan decision 12A). The other regimes are not
    sampled at all rather than sampled-and-caveated: a `too-few-cves` or `mega-cpe-bound`
    row would appear downstream as a confident modal share resting on two CVEs, and a
    caveat attached to a number does not survive being quoted second-hand. Those categories
    keep their category-level facet and are reported as UNMEASURED, which is honest and
    costs little — the 11 samplable categories carry 93% of the confirmed CVE population.
    """
    rng = random.Random(seed)
    sample = {}
    for slug in sorted(frame):
        if regime(stats[slug]) != "samplable":
            continue
        devices = sorted(frame[slug])          # sorted first => draw is seed-reproducible
        if len(devices) <= n:
            picked = devices
        else:
            picked = sorted(rng.sample(devices, n))
        sample[slug] = [(d, frame[slug][d]) for d in picked]
    return sample


def write_frame(frame, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["category", "device", "vendor", "product", "cve_count"])
        for slug in sorted(frame):
            for dev, cnt in sorted(frame[slug].items(), key=lambda x: (-x[1], x[0])):
                vendor, _, product = dev.partition(":")
                w.writerow([slug, dev, vendor, product, cnt])


def write_sample(sample, spec, path):
    """Emit the annotation sheet, long format: one row per (device, facet).

    The column set is asserted against FORBIDDEN_IN_SHEET because this is the constraint the
    whole design rests on — a future edit that adds `description` here to 'help the
    annotator' would silently make every downstream contrast circular, and would look like
    a helpful change in review.
    """
    leaked = FORBIDDEN_IN_SHEET & set(SHEET_COLS)
    assert not leaked, f"annotation sheet must not carry CVE-derived fields: {leaked}"

    os.makedirs(os.path.dirname(path), exist_ok=True)
    rows = 0
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=SHEET_COLS)
        w.writeheader()
        for slug in sorted(sample):
            for dev, cnt in sample[slug]:
                vendor, _, product = dev.partition(":")
                for facet, values in spec.items():
                    w.writerow({
                        "category": slug, "device": dev,
                        "vendor": vendor, "product": product, "cve_count": cnt,
                        "facet": facet, "allowed_values": "|".join(values + ["unsure"]),
                        "Value": "", "Confidence": "", "Reasoning": "",
                    })
                    rows += 1
    return rows


# ------------------------------------------------------------------------------ aggregate

def aggregate(path_in, path_out):
    """Modal value and share per (category, facet), under both weightings.

    The share is the admission test (Phase A): >=0.80 the category-level value is a
    defensible summary; 0.60-0.80 usable for grouping only; <0.60 the category-level facet
    is NOT usable and the distribution must be reported instead of a value.
    """
    if not os.path.exists(path_in):
        sys.exit(f"no annotation sheet at {path_in} — run --draw and fill it first")

    prod = defaultdict(Counter)   # (slug, facet) -> Counter over values, 1 per device
    cvew = defaultdict(Counter)   # (slug, facet) -> Counter weighted by cve_count
    unsure = defaultdict(int)
    seen = defaultdict(int)

    with open(path_in, newline="") as f:
        for r in csv.DictReader(f):
            val = (r.get("Value") or "").strip()
            key = (r["category"], r["facet"])
            seen[key] += 1
            if not val:
                continue
            if val.lower() == "unsure":
                unsure[key] += 1
                continue
            prod[key][val] += 1
            cvew[key][val] += int(r["cve_count"] or 0)

    os.makedirs(os.path.dirname(path_out), exist_ok=True)
    with open(path_out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "category", "facet", "n_devices", "n_answered", "n_unsure",
            "modal_value_product", "modal_share_product",
            "modal_value_cve", "modal_share_cve",
            "weighting_divergence", "verdict",
        ])
        for key in sorted(seen):
            slug, facet = key
            pc, cc = prod[key], cvew[key]
            if not pc:
                w.writerow([slug, facet, seen[key], 0, unsure[key],
                            "", "", "", "", "", "unannotated"])
                continue
            pv, pn = pc.most_common(1)[0]
            ps = pn / sum(pc.values())
            cv, cn = cc.most_common(1)[0]
            cs = cn / sum(cc.values()) if sum(cc.values()) else 0.0
            verdict = ("summary-defensible" if cs >= 0.80
                       else "grouping-only" if cs >= 0.60
                       else "NOT-USABLE-report-distribution")
            w.writerow([
                slug, facet, seen[key], sum(pc.values()), unsure[key],
                pv, f"{ps:.3f}", cv, f"{cs:.3f}",
                "differs" if pv != cv else "", verdict,
            ])
    print(f"wrote {path_out}")


# ----------------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--frame", action="store_true", help="frame stats only, no draw")
    ap.add_argument("--draw", action="store_true", help="draw sample + write annotation sheet")
    ap.add_argument("--aggregate", action="store_true", help="filled sheet -> distribution")
    ap.add_argument("-n", type=int, default=DEFAULT_N, help=f"devices per category (default {DEFAULT_N})")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED, help="RNG seed (draw is reproducible)")
    args = ap.parse_args()

    if not (args.frame or args.draw or args.aggregate):
        ap.error("pick one of --frame / --draw / --aggregate")

    if args.aggregate:
        aggregate(os.path.join(OUTDIR, "product_sample.csv"),
                  os.path.join(OUTDIR, "facet_distribution.csv"))
        return

    labels = load_categories()
    spec = load_facet_spec()
    print(f"single-valued facets from shapes.ttl: {len(spec)}")
    for k, v in spec.items():
        print(f"  {k:24s} {len(v)} values")
    print()

    frame, stats = build_frame(list(labels))
    report_frame(frame, stats, labels)

    if args.draw:
        write_frame(frame, os.path.join(OUTDIR, "product_frame.csv"))
        sample = draw(frame, stats, args.n, args.seed)
        rows = write_sample(sample, spec, os.path.join(OUTDIR, "product_sample.csv"))
        drawn = sum(len(v) for v in sample.values())
        skipped = [s for s in stats if regime(stats[s]) != "samplable" and stats[s]["devices"]]
        in_cves = sum(stats[s]["yes"] for s in sample)
        all_cves = sum(s["yes"] for s in stats.values())
        print(f"\ndrew {drawn} devices across {len(sample)} samplable categories "
              f"(n={args.n}, seed={args.seed})")
        print(f"annotation sheet: {rows} rows ({len(spec)} facets x {drawn} devices)")
        print(f"CVE coverage: {in_cves}/{all_cves} confirmed-Yes rows "
              f"({in_cves / all_cves * 100:.1f}%) sit in a sampled category")
        print(f"NOT sampled ({len(skipped)}): {', '.join(sorted(skipped))}")
        print("  -> these keep a category-level facet and must be reported as UNMEASURED")


if __name__ == "__main__":
    main()
