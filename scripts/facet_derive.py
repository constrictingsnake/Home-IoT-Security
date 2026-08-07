#!/usr/bin/env python3
"""Derive ontology facet values from the NVD snapshot, and compare them to what the
ontology asserts.

WHY THIS EXISTS. The 400 facet assertions in ontology/homeiot.ttl were hand-assigned
from domain knowledge in a single pass. That is fine for organising thought and not
fine as evidence — and it is the one part of this ontology carrying no provenance,
while alignment IRIs, study citations, scope notes and judgments are all tracked.
The honest answer to "how do you know this is a web-admin device?" is currently "I
don't". This script converts two facets from assertion into measurement so that
answer changes.

    python3 scripts/facet_derive.py                 # derive, compare, report
    python3 scripts/facet_derive.py --write         # + write data/ontology/facet_evidence.csv

WHAT IT DOES NOT DO. It never edits homeiot.ttl. Same convention as
cpe_brand_mining.py / keyword_mining.py / cpe_product_scan.py: a derived value is a
candidate for a human to accept, not an automatic overwrite. A disagreement between
the derived and asserted value is the interesting output, not an error to paper over.

THE CONFOUND, STATED UP FRONT. Evidence is read from CVE descriptions, which are
written by the same analysts who assign the CWE. So a description mentioning
"/cgi-bin/" and a CWE of "command injection" are not fully independent. This matters
if you then compare hasWebAdminUI against CWE-888 class: some of the association is
baked in. It is still a large improvement on my say-so, because the evidence is
external, counted and reproducible rather than remembered — but it is NOT a clean
natural experiment and must not be reported as one. The cleanest reading is
descriptive: "categories whose CVEs frequently reference a web management interface".

TWO FACETS ONLY. hasWebAdminUI and computeTier are derivable because they leave
textual traces (a CGI path, a busybox shell, an Android component). Facets like
supportLifetime or patchResponsibility leave no trace in NVD at all and stay
hiot:Estimated — which is exactly why the evidence tier is recorded per facet
rather than claimed for all of them.
"""
import argparse
import collections
import csv
import os
import re
import sys

from rdflib import Graph, Namespace

HIOT = Namespace("https://w3id.org/homeiot/ontology#")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TTL = os.path.join(ROOT, "ontology", "homeiot.ttl")
STORE = os.path.join(ROOT, "data", "difference", "judgment_store.csv")
SNAPSHOT = os.path.join(ROOT, "data", "nvd-snapshot", "nvd_all.csv")
OUT = os.path.join(ROOT, "data", "ontology", "facet_evidence.csv")

# Phrases chosen to name the INTERFACE, not the bug. "cross-site scripting" would be
# a weakness term and would hard-wire the CWE association this facet is later compared
# against; "/cgi-bin/" is a fact about the device's software surface.
WEB_ADMIN = [
    "web interface", "web-based interface", "web based interface", "web management",
    "web admin", "web console", "web ui", "web gui", "webui", "cgi-bin", ".cgi",
    "administration interface", "administrative interface", "management interface",
    "admin panel", "http interface", "web configuration", "web portal",
]

# A deliberately looser set, used ONLY to measure how much the answer depends on the
# word list rather than on the devices. If the narrow and broad shares diverge, the
# "derivation" is measuring the author's keyword choice and must not be promoted out
# of hiot:Estimated. This check is the whole reason the script is trustworthy: it is
# built to be able to fail, and it does.
WEB_ADMIN_BROAD = WEB_ADMIN + ["http", "web", "url", "login", "authenticat"]

# Above this narrow-vs-broad gap the facet is declared pattern-fragile.
FRAGILITY_LIMIT = 0.25

OS_MARKERS = {
    # Android-derived includes the vendor forks: a Fire TV CVE says "Fire OS", a
    # Samsung fridge says "Tizen". Grouping them is the point of the tier.
    "AndroidDerived": ["android", "aosp", "fire os", "fireos", "google tv",
                       "tizen", "webos", "web os"],
    "EmbeddedLinux": ["busybox", "uclibc", "openwrt", "dropbear", "telnetd",
                      "/etc/passwd", "/etc/shadow", "/bin/sh", "root shell",
                      "linux kernel", "embedded linux", "lighttpd", "boa server"],
}

# A category is called web-admin when a fifth of its confirmed CVEs name a management
# interface. Chosen because the observed distribution is strongly bimodal rather than
# to hit a target; --threshold exposes it so the choice can be argued with.
WEB_THRESHOLD = 0.20
OS_THRESHOLD = 0.15


def load_asserted(ttl=TTL):
    g = Graph()
    g.parse(ttl, format="turtle")
    slug = {s: str(o) for s, o in g.subject_objects(HIOT.slug)}
    out = collections.defaultdict(dict)
    for prop in ("hasWebAdminUI", "computeTier"):
        for s, o in g.subject_objects(HIOT[prop]):
            if s in slug:
                v = str(o)
                out[slug[s]][prop] = v.split("#")[-1] if v.startswith(str(HIOT)) else v
    return out


def load_population(store=STORE):
    pop = collections.defaultdict(set)
    with open(store, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if r.get("Final Judgment") == "Yes" and not str(r.get("Excluded", "")).strip():
                pop[r["category"]].add(r["cve_id"])
    return pop


def hydrate(cve_ids, snapshot=SNAPSHOT):
    csv.field_size_limit(10 ** 9)
    want, found = set(cve_ids), {}
    with open(snapshot, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if r["cve_id"] in want:
                found[r["cve_id"]] = r
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true",
                    help="write data/ontology/facet_evidence.csv")
    ap.add_argument("--threshold", type=float, default=WEB_THRESHOLD,
                    help=f"web-admin share to call the facet true (default {WEB_THRESHOLD})")
    ap.add_argument("--snapshot", default=SNAPSHOT)
    args = ap.parse_args()

    asserted = load_asserted()
    pop = load_population()
    nvd = hydrate({c for s in pop.values() for c in s}, snapshot=args.snapshot)

    rows = []
    for cat in sorted(pop, key=lambda c: -len(pop[c])):
        cves = [nvd[c] for c in pop[cat] if c in nvd]
        n = len(cves)
        if not n:
            continue
        web = broad = 0
        os_hits = collections.Counter()
        for r in cves:
            blob = ((r.get("description") or "") + " " +
                    (r.get("cpe_strings") or "")).lower()
            if any(p in blob for p in WEB_ADMIN):
                web += 1
            if any(p in blob for p in WEB_ADMIN_BROAD):
                broad += 1
            for tier, pats in OS_MARKERS.items():
                if any(p in blob for p in pats):
                    os_hits[tier] += 1

        web_share = web / n
        broad_share = broad / n
        fragile = (broad_share - web_share) > FRAGILITY_LIMIT
        derived_web = web_share >= args.threshold

        # Android-derived wins ties: a Fire TV description mentions Linux too (it is
        # an Android device), so checking the more specific marker first avoids
        # collapsing every Android box into EmbeddedLinux.
        android_share = os_hits["AndroidDerived"] / n
        linux_share = os_hits["EmbeddedLinux"] / n
        if android_share >= OS_THRESHOLD and android_share >= linux_share:
            derived_tier = "AndroidDerived"
        elif linux_share >= OS_THRESHOLD:
            derived_tier = "EmbeddedLinux"
        else:
            derived_tier = "insufficient-evidence"

        a_web = asserted.get(cat, {}).get("hasWebAdminUI", "")
        a_tier = asserted.get(cat, {}).get("computeTier", "")
        rows.append({
            "slug": cat, "n_cves": n,
            "web_admin_hits": web, "web_admin_share": round(web_share, 3),
            "web_admin_share_broad": round(broad_share, 3),
            "pattern_fragile": str(fragile).lower(),
            "derived_hasWebAdminUI": str(derived_web).lower(),
            "asserted_hasWebAdminUI": a_web,
            "web_agrees": str(str(derived_web).lower() == a_web.lower()).lower(),
            "android_share": round(android_share, 3),
            "linux_share": round(linux_share, 3),
            "derived_computeTier": derived_tier,
            "asserted_computeTier": a_tier,
            "tier_agrees": str(derived_tier == a_tier).lower()
              if derived_tier != "insufficient-evidence" else "undetermined",
        })

    print(f"derived over {sum(r['n_cves'] for r in rows)} confirmed CVEs in "
          f"{len(rows)} categories (threshold {args.threshold})\n")
    print(f"{'category':16} {'n':>5} {'narrow':>7} {'broad':>7} {'frag':>5} "
          f"{'derived':>8} {'asserted':>9} {'':3} {'derived tier':>21}")
    print("-" * 96)
    for r in rows:
        wmark = "ok" if r["web_agrees"] == "true" else "DIFF"
        print(f"{r['slug']:16} {r['n_cves']:5d} {100*r['web_admin_share']:6.0f}% "
              f"{100*r['web_admin_share_broad']:6.0f}% "
              f"{'YES' if r['pattern_fragile']=='true' else '-':>5} "
              f"{r['derived_hasWebAdminUI']:>8} {r['asserted_hasWebAdminUI']:>9} {wmark:>4} "
              f"{r['derived_computeTier']:>21}")

    w_ok = sum(1 for r in rows if r["web_agrees"] == "true")
    t_det = sum(1 for r in rows if r["tier_agrees"] != "undetermined")
    n_frag = sum(1 for r in rows if r["pattern_fragile"] == "true")
    print("-" * 96)
    print(f"hasWebAdminUI: derived agrees with asserted on {w_ok}/{len(rows)} categories")
    print(f"computeTier:   evidence sufficient on only {t_det}/{len(rows)} categories")
    print(f"pattern-fragile (narrow vs broad word list diverges by >{FRAGILITY_LIMIT:.0%}): "
          f"{n_frag}/{len(rows)} categories")
    print()

    # The verdict. Written as a hard gate rather than a remark because the whole point
    # of running this was to decide whether these facets may leave hiot:Estimated.
    if n_frag > len(rows) / 3 or t_det < len(rows) / 2:
        print("VERDICT: NOT DERIVABLE from NVD text. Both facets stay hiot:Estimated.")
        print("  hasWebAdminUI swings with the word list (cameras 23% narrow vs 65% broad),")
        print("  so the number measures the author's keyword choice, not the device.")
        print("  computeTier leaves almost no textual trace at all.")
        print("  Consequence: do NOT report the earlier 'web-admin categories show 25%")
        print("  Tainted Input vs 13%' contrast -- the grouping behind it is not evidenced.")
    else:
        print("VERDICT: stable enough to promote out of hiot:Estimated (record the")
        print("  threshold and word list alongside the value).")

    if args.write:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
            w.writeheader()
            w.writerows(rows)
        print(f"\nwrote {os.path.relpath(OUT, ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
