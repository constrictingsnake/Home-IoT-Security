#!/usr/bin/env python3
"""Measure whether a facet cell's citations are representative of the category they assert.

WHY THIS EXISTS
---------------
F5's tier vocabulary distinguishes `Documented` (a source covering the whole category) from
`HumanSourced` (per-product citations, generalised by a human). What it could not distinguish
is a per-product citation drawn from the population the facet describes and one drawn from
whatever brand happens to be famous. Measured on the first sourced pass, the median cell cited
vendors accounting for **3%** of its category's confirmed-Yes CVEs: `hub` was sourced on
Hubitat, which has no CVEs in the corpus at all, while Insteon carried 45% of the category.

Citing a brand the corpus does not contain is not evidence about the corpus. So coverage is
measured, and a cell that fails the floor drops to `HumanJudged` with its source RETAINED and
labelled - which says more than a blank source would.

THE FLOOR RULE (relative, with an absolute backstop)
----------------------------------------------------
A cell is `representative` when the cited vendors' share EXCEEDS the largest single uncited
vendor's share, and is at least 10%. The relative half adapts to how concentrated a category
is - a 16% citation is weak in `hub` (Insteon holds 45%) and would be strong in a category
where no vendor exceeds 5%. The absolute backstop stops a fragmented category passing on crumbs.

Shares are CVE-level: the fraction of the category's confirmed-Yes CVEs having at least one
device CPE from the cited vendor set. A CVE can count toward several vendors, so shares do not
sum to 1 - deliberately, since a CVE genuinely attributed to two vendors is evidence about both.

EXEMPTIONS, both recorded rather than silent
--------------------------------------------
- `regulation` - the cell's evidence is a standard or certification requirement binding the
  product CLASS (ETSI EN 303 645, Matter). Vendor coverage is the wrong test for these: a
  device conforming to the standard carries the property wherever it is sold, so the
  requirement reaches the corpus by definition and does not need a market share.
- `unmeasurable` - fewer than 10 confirmed-Yes CVEs in the category, so any share is noise.
  These keep whatever tier they had, flagged, never silently promoted - the same convention
  `facet_analysis.py` uses for Phase A's `[unmeasured]` categories.

WHY A LAW IS NOT AUTOMATICALLY AN EXEMPTION (corrected 2026-09-01)
------------------------------------------------------------------
The exemption above originally read "regulation, standard or certification requirement" and
listed UK PSTI and grid codes alongside ETSI and Matter, on the reasoning that "a law does not
need a market share". That conflates two different kinds of instrument, and the difference is
exactly a coverage question:

  - A STANDARD binds a product class. Any Matter-commissioned device has a printed onboarding
    code; any device conforming to EN 303 645 has no universal default password. Membership of
    the class is the only precondition, so the instrument reaches every vendor in the corpus.
  - A REGULATION binds a MARKET. UK PSTI requires a declared support period for consumer
    connectable products placed on the UK market. It says nothing whatsoever about a vendor
    that does not sell there - and the corpus is full of them.

Measured when this was caught: all 11 `supportLifetime` cells came back `DeclaredLifetime`
sourced on UK PSTI, 10 of them claiming category-wide, and in 7 of those the cited vendor held
0% of the category's confirmed-Yes CVEs. `babymonitor` was sourced on Nanit while dlink carries
44%; `doorbell` on Ring while akuvox carries 36%; `thermostat` on Google/Bosch while ecobee
carries 22%. The white-label brands holding the CVE mass are precisely the ones that publish no
support declaration, so the exemption was converting an absence of evidence into the highest
tier - and a facet that comes out identical on all 11 categories discriminates nothing anyway.

So jurisdiction-bound instruments now face the coverage test like any vendor citation and are
recorded as `jurisdiction-bound` rather than silently exempted. They are NOT rejected: the
verdict is informational, and it is the SHARE that decides, so a PSTI citation backed by a
vendor that does hold the corpus still passes as `representative`.
"""
import argparse
import collections
import csv
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JUDGMENTS = os.path.join(ROOT, "data", "difference", "judgment_store.csv")
SNAPSHOT = os.path.join(ROOT, "data", "nvd-snapshot", "nvd_all.csv")
VENDOR_MAP = os.path.join(ROOT, "data", "facets", "source_vendors.csv")
OUT = os.path.join(ROOT, "data", "facets", "source_coverage.csv")

MIN_CVES = 10
ABSOLUTE_FLOOR = 0.10

# A cell whose evidence is one of these is class-binding, not product-level: conformance is the
# only precondition, so the requirement reaches every vendor in the corpus by definition.
# NOTE a CISA ICS advisory is deliberately NOT here: it is coordinated vulnerability disclosure
# about named products, so it is per-product evidence and must face the coverage test like any
# other vendor citation. Only instruments that bind the product class qualify.
CLASS_BINDING = ("etsi.org", "csa-iot.org", "docs.silabs.com/matter")

# Instruments that bind a MARKET rather than a product class - they reach only the vendors who
# sell into that jurisdiction, which is a coverage question and therefore measured, not assumed.
# See the module docstring for the `supportLifetime` case that produced this split.
JURISDICTION_BOUND = ("legislation.gov.uk", "gov.uk/guidance", "surgepv.com/solar-compliance")

FIELDS = ["slug", "facet", "n_cves", "cited_vendors", "cited_share",
          "top_uncited_vendor", "top_uncited_share", "verdict"]


def confirmed_yes():
    """category -> set of confirmed-Yes CVE ids, excluding scope-excluded rows."""
    out = collections.defaultdict(set)
    with open(JUDGMENTS) as fh:
        for r in csv.DictReader(fh):
            if r.get("Final Judgment") == "Yes" and not (r.get("Excluded") or "").strip():
                out[r["category"]].add(r["cve_id"])
    return out


def cve_vendors():
    """cve_id -> set of CPE vendor tokens."""
    csv.field_size_limit(10 ** 8)
    out = {}
    with open(SNAPSHOT) as fh:
        for r in csv.DictReader(fh):
            vs = set()
            for c in (r.get("cpe_strings") or "").split("|"):
                p = c.split(":")
                if len(p) > 4 and p[1] == "2.3":
                    vs.add(p[3].lower())
            out[r["cve_id"]] = vs
    return out


def sheet_sources():
    """(slug, facet) -> both reviewers' source text, for the instrument test.

    Both columns are read, not just column 1: a cell can be re-sourced in column 2 (the 19
    `below-floor` cells were re-sourced onto the corpus vendors by design), and the instrument
    a cell rests on is whatever either reviewer actually cited.
    """
    path = os.path.join(ROOT, "data", "facets", "tagging-kit", "category_tags.csv")
    csv.field_size_limit(10 ** 8)
    with open(path) as fh:
        return {(r["slug"], r["facet"]): f"{r.get('Source 1') or ''} {r.get('Source 2') or ''}"
                for r in csv.DictReader(fh) if r["status"] == "ask"}


def compute():
    yes = confirmed_yes()
    vend = cve_vendors()
    sources = sheet_sources()
    per_cve = {cat: {c: vend.get(c, set()) for c in s} for cat, s in yes.items()}

    rows = []
    with open(VENDOR_MAP) as fh:
        for r in csv.DictReader(fh):
            slug, facet = r["slug"], r["facet"]
            cited = {v for v in (r["cpe_vendors"] or "").split("|") if v}
            n = len(yes.get(slug, ()))
            src = sources.get((slug, facet), "").lower()
            class_binding = any(k in src for k in CLASS_BINDING)
            jurisdictional = any(k in src for k in JURISDICTION_BOUND)

            if n < MIN_CVES:
                rows.append(dict(slug=slug, facet=facet, n_cves=n,
                                 cited_vendors="|".join(sorted(cited)), cited_share="",
                                 top_uncited_vendor="", top_uncited_share="",
                                 verdict="unmeasurable"))
                continue

            hits = sum(1 for vs in per_cve[slug].values() if vs & cited)
            share = hits / n
            counts = collections.Counter()
            for vs in per_cve[slug].values():
                for v in vs - cited:
                    counts[v] += 1
            top_v, top_n = (counts.most_common(1) or [("", 0)])[0]
            top_share = top_n / n

            if class_binding:
                verdict = "regulation"
            elif share > top_share and share >= ABSOLUTE_FLOOR:
                # A jurisdiction-bound citation can still pass on the merits: the vendors
                # behind it do hold the corpus. The label records the instrument; the share
                # decides the verdict.
                verdict = "jurisdiction-bound" if jurisdictional else "representative"
            else:
                verdict = "below-floor"

            rows.append(dict(slug=slug, facet=facet, n_cves=n,
                             cited_vendors="|".join(sorted(cited)),
                             cited_share=f"{share:.3f}", top_uncited_vendor=top_v,
                             top_uncited_share=f"{top_share:.3f}", verdict=verdict))
    return sorted(rows, key=lambda r: (r["slug"], r["facet"]))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true", help=f"write {os.path.relpath(OUT, ROOT)}")
    args = ap.parse_args()

    rows = compute()
    tally = collections.Counter(r["verdict"] for r in rows)
    print(f"{'category':14} {'facet':21} {'n':>5} {'cited':>7} {'top-uncited':>22}  verdict")
    for r in rows:
        cs = f"{float(r['cited_share']):.0%}" if r["cited_share"] else "n/a"
        tu = (f"{r['top_uncited_vendor']} {float(r['top_uncited_share']):.0%}"
              if r["top_uncited_share"] else "")
        print(f"{r['slug']:14} {r['facet']:21} {r['n_cves']:>5} {cs:>7} {tu:>22}  {r['verdict']}")
    print("\n" + "  ".join(f"{k}={v}" for k, v in sorted(tally.items())))

    if args.write:
        with open(OUT, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=FIELDS)
            w.writeheader()
            w.writerows(rows)
        print(f"\nwrote {os.path.relpath(OUT, ROOT)} ({len(rows)} cells)")
    else:
        print("\n(dry run - pass --write to record it)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
