#!/usr/bin/env python3
"""CPE product-token scan — automated discovery from NVD product names.

The third text surface no current method searches. Vendor search (Stage 2) only knows
brands someone already listed; keyword search (Stage 1) can't use single device nouns
(`camera`, `hub`, `alarm`) in a description — too generic, they'd match half of NVD. But
inside a CPE **product** field the same noun is high-precision: a product literally named
`..._camera_firmware` is a camera. This scans product-name tokens (split on `[_\\-.]`,
matched exactly) to find CVEs whose description names no device phrase and whose vendor is
on no list — structurally unreachable by both text searches today.

Distinct from its two siblings:
  - cpe_expansion.py (Stage 5) densifies confirmed vendor:product seeds — never a new brand.
  - cpe_brand_mining.py finds new vendors, but only ones already co-occurring with a
    keyword-matched or confirmed-Yes CVE — it needs an evidence trail into the category.
  - This scan needs no evidence trail at all: the product name itself is the evidence.

This script never edits any term file — it is read-only outside its one output file. See
docs/plans/PLAN_cpe_product_scan.md for the full algorithm, prototype yield numbers, and
guardrails, and CLAUDE.md Stage 5 for the device-CPE-granularity convention this reuses.

Algorithm:
  1. Per-category known set: cve_ids in keyword_<cat>.csv U results_all_<cat>.csv U the
     judgment store (any verdict — a settled No must not resurface).
  2. One snapshot pass: for each CVE's cpe_strings, keep part in {o,h}, deny
     GENERIC_PLATFORM_CPES; split each product name on [_\\-.]; an exact token hit for a
     slug whose token list contains it, on a CVE unknown to that category, is a hit.
  3. Aggregate per (slug, vendor:product) — a human vets *products*, one decision settles
     all its CVEs.
  4. Risk flags (never filter, only triage): broad-token, non-consumer-vendor,
     pro-surveillance (cameras only, sourced from term_precision.csv prune rows).

Usage:
    python3 scripts/cpe_product_scan.py --all
    python3 scripts/cpe_product_scan.py hub cameras            # subset
    python3 scripts/cpe_product_scan.py --all --min-cves 2     # drop 1-CVE products (default 1)

Writes data/cpe-product-scan/product_candidates.csv (only file this script writes) plus a
console summary (per-category totals, top 10 products each).
"""
import argparse
import csv
import os
import re
from collections import defaultdict

from cpe_expansion import DEVICE_PARTS, GENERIC_PLATFORM_CPES, parse_cpe, load_known_cve_ids
from cpe_brand_mining import (
    normalize, _related, load_judgment_store, build_coverage_index, covered_elsewhere,
)
from build_search import read_terms
from build_review_sets import read_categories

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
SNAPSHOT = os.path.join(DATA, "nvd-snapshot", "nvd_all.csv")
CATEGORIES_PATH = os.path.join(DATA, "categories.csv")
TOKENS_PATH = os.path.join(DATA, "cpe-product-tokens.csv")
VENDOR_TERMS_PATH = os.path.join(DATA, "vendor-search", "vendor_terms.csv")
TERM_PRECISION = os.path.join(DATA, "difference", "term_precision.csv")
OUT_PATH = os.path.join(DATA, "cpe-product-scan", "product_candidates.csv")

csv.field_size_limit(1 << 24)

TOKEN_SPLIT_RE = re.compile(r"[_\-.]+")

# Risk-flag guardrail (plan Step 4): tokens the prototype measured as noise magnets
# (Citrix NetScaler "gateway", Dell Edge "gateway", Cisco IPS "sensor", GE feeder
# protection relay, IBM chassis "fan", Nissan blind-spot ECU "blind"...). Flags triage,
# never filter — same rule as cpe_brand_mining.py's mega-vendor/known-fp-bomb flags.
BROAD_TOKENS = {
    "gateway", "bridge", "sensor", "feeder", "fan", "blind", "lock", "switch", "controller",
}

# Safety-net fallback for vendors the dynamic snapshot-footprint ratio (below) might miss
# for a token combination too rare to trip the >200-CPE threshold. Supplements, never
# replaces, the dynamic check.
HARDCODED_NON_CONSUMER_VENDORS = [
    "citrix", "dell", "cisco", "ibm", "ge", "hewlett packard", "hp", "oracle", "huawei",
    "juniper", "fortinet", "vmware", "microsoft", "sap", "siemens", "schneider electric",
]

MEGA_VENDOR_SNAPSHOT_MIN = 200
MEGA_VENDOR_RATIO = 0.10


def load_tokens_by_slug():
    """slug -> set of lowercased tokens (order doesn't matter for exact matching)."""
    raw = read_terms(TOKENS_PATH)
    return {slug: {t.strip().lower() for t in toks if t.strip()} for slug, toks in raw.items()}


def build_token_index(tokens_by_slug, wanted_slugs):
    """token -> [slug, ...], restricted to the requested categories."""
    idx = defaultdict(list)
    for slug in wanted_slugs:
        for tok in tokens_by_slug.get(slug, ()):
            idx[tok].append(slug)
    return idx


def build_known_sets(categories, store):
    """category -> set of cve_ids already surfaced by keyword search, vendor search, or
    carrying any judgment (settled or not) in the store — Step 1 of the plan."""
    known = {}
    for cat in categories:
        s = load_known_cve_ids(cat)  # keyword_<cat>.csv U results_all_<cat>.csv
        s.update(store.get(cat, {}).keys())
        known[cat] = s
    return known


def load_pro_surveillance_terms():
    """Normalized cameras-only prune_candidate=Yes terms from term_precision.csv — the
    pro/enterprise-surveillance brands (Geutebrück, Digital Watchdog, i-PRO, Synology
    Surveillance Station...) CLAUDE.md's `cameras` scope note calls out by name."""
    terms = set()
    if os.path.exists(TERM_PRECISION):
        with open(TERM_PRECISION, newline="") as f:
            for r in csv.DictReader(f):
                if r.get("category") == "cameras" and (r.get("prune_candidate") or "").strip().lower() == "yes":
                    terms.add(normalize(r.get("term", "")))
    terms.discard("")
    return terms


def risk_flags_for(vendor, slug, matched_tokens, snapshot_total_vendor, n_new_cves,
                    pro_surveillance_terms):
    flags = []
    if matched_tokens & BROAD_TOKENS:
        flags.append("broad-token")
    nv = normalize(vendor)
    is_mega = (snapshot_total_vendor > MEGA_VENDOR_SNAPSHOT_MIN
               and n_new_cves < MEGA_VENDOR_RATIO * snapshot_total_vendor)
    is_hardcoded = any(_related(nv, normalize(v)) for v in HARDCODED_NON_CONSUMER_VENDORS)
    if is_mega or is_hardcoded:
        flags.append("non-consumer-vendor")
    if slug == "cameras" and any(_related(nv, t) for t in pro_surveillance_terms):
        flags.append("pro-surveillance")
    return "|".join(flags)


def scan_snapshot(token_index, known_by_cat):
    """One pass over the snapshot (plan Step 2).

    Returns:
      agg: {(slug, vendor:product): {"cve_ids": set, "matched_tokens": set,
                                      "samples": [(cve_id, description[:150]), ...]}}
      vendor_snapshot_total: {vendor: count} — whole CPE footprint (any part, any CVE),
        counted per CPE entry like cpe_brand_mining.py's snapshot_total, for the
        non-consumer-vendor ratio check.
    """
    agg = defaultdict(lambda: {"cve_ids": set(), "matched_tokens": set(), "samples": []})
    vendor_snapshot_total = defaultdict(int)

    with open(SNAPSHOT, newline="") as f:
        for r in csv.DictReader(f):
            cpes = (r.get("cpe_strings") or "").split("|")
            if not cpes:
                continue
            cve_id = r["cve_id"]
            row_hits = defaultdict(lambda: defaultdict(set))  # slug -> vp -> matched tokens
            for c in cpes:
                c = c.strip()
                if not c:
                    continue
                parts = c.split(":")
                if len(parts) >= 5:
                    v = parts[3].strip().lower()
                    if v and v not in ("*", "-"):
                        vendor_snapshot_total[v] += 1
                part, vp = parse_cpe(c)
                if vp is None or part not in DEVICE_PARTS or vp in GENERIC_PLATFORM_CPES:
                    continue
                vendor, product = vp.split(":", 1)
                for tok in TOKEN_SPLIT_RE.split(product):
                    if not tok:
                        continue
                    for slug in token_index.get(tok, ()):
                        if cve_id in known_by_cat[slug]:
                            continue
                        row_hits[slug][vp].add(tok)

            if not row_hits:
                continue
            desc = (r.get("description") or "")[:150]
            for slug, vp_map in row_hits.items():
                for vp, toks in vp_map.items():
                    entry = agg[(slug, vp)]
                    entry["cve_ids"].add(cve_id)
                    entry["matched_tokens"] |= toks
                    if len(entry["samples"]) < 3:
                        entry["samples"].append((cve_id, desc))

    return agg, vendor_snapshot_total


CANDIDATE_COLS = [
    "category", "vendor_product", "matched_tokens", "n_new_cves",
    "covered_elsewhere_slug", "risk_flags", "sample_cves", "sample_descriptions",
]


def write_candidates(rows):
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CANDIDATE_COLS)
        w.writeheader()
        w.writerows(rows)
    return OUT_PATH


def print_summary(rows, categories):
    by_cat = defaultdict(list)
    for r in rows:
        by_cat[r["category"]].append(r)
    grand_new = 0
    for cat in categories:
        crows = by_cat.get(cat)
        if not crows:
            continue
        crows.sort(key=lambda r: -r["n_new_cves"])
        total_new = sum(r["n_new_cves"] for r in crows)
        grand_new += total_new
        print(f"\n=== {cat}: {len(crows)} candidate product(s), {total_new} total new CVE(s) ===")
        for r in crows[:10]:
            flags = f"  [{r['risk_flags']}]" if r["risk_flags"] else ""
            print(f"  {r['vendor_product']:<40} tokens={r['matched_tokens']:<20} "
                  f"new={r['n_new_cves']:<5}{flags}")
    print(f"\n=== TOTAL: {len(rows)} candidate (category, product) pair(s), {grand_new} new CVE(s) "
          f"across {len(by_cat)} categor(y/ies) ===")
    print(f"-> {os.path.relpath(OUT_PATH, ROOT)}")


def run(categories, min_cves):
    print("Loading judgment store, cpe-product-tokens.csv, vendor_terms.csv, term_precision.csv...")
    store = load_judgment_store()
    tokens_by_slug = load_tokens_by_slug()
    wanted = [c for c in categories if tokens_by_slug.get(c)]
    skipped = sorted(set(categories) - set(wanted))
    if skipped:
        print(f"  (no tokens for: {', '.join(skipped)} — skipping)")
    if not wanted:
        print("No categories with tokens to scan.")
        return []

    vendor_terms = read_terms(VENDOR_TERMS_PATH)
    coverage_idx = build_coverage_index(vendor_terms)
    pro_surveillance_terms = load_pro_surveillance_terms()

    print(f"Building known sets for {len(wanted)} categor(y/ies) "
          "(keyword U vendor U judgment store, any verdict)...")
    known_by_cat = build_known_sets(wanted, store)
    token_index = build_token_index(tokens_by_slug, wanted)

    print(f"Scanning snapshot once for {len(token_index)} distinct token(s)...")
    agg, vendor_snapshot_total = scan_snapshot(token_index, known_by_cat)

    rows = []
    for (slug, vp), entry in agg.items():
        n_new = len(entry["cve_ids"])
        if n_new < min_cves:
            continue
        vendor, _product = vp.split(":", 1)
        snap_total = vendor_snapshot_total.get(vendor, 0)
        flags = risk_flags_for(vendor, slug, entry["matched_tokens"], snap_total, n_new,
                                pro_surveillance_terms)
        samp = entry["samples"]
        rows.append({
            "category": slug, "vendor_product": vp,
            "matched_tokens": "|".join(sorted(entry["matched_tokens"])),
            "n_new_cves": n_new,
            "covered_elsewhere_slug": "|".join(covered_elsewhere(vendor, slug, coverage_idx)),
            "risk_flags": flags,
            "sample_cves": "|".join(c for c, _d in samp),
            "sample_descriptions": "|".join(d for _c, d in samp),
        })

    if not rows:
        print("No candidates survived the known-set filter and --min-cves threshold.")
        return []

    rows.sort(key=lambda r: (r["category"], -r["n_new_cves"]))
    write_candidates(rows)
    print_summary(rows, wanted)
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("categories", nargs="*", help="category slug(s); omit when using --all")
    ap.add_argument("--all", action="store_true", help="every category in categories.csv")
    ap.add_argument("--min-cves", type=int, default=1,
                    help="min new CVEs required for a product to be listed (default: 1)")
    args = ap.parse_args()

    if args.all:
        cats = read_categories(CATEGORIES_PATH)
    elif args.categories:
        cats = args.categories
    else:
        ap.error("give one or more category slugs, or --all")

    run(cats, args.min_cves)


if __name__ == "__main__":
    main()
