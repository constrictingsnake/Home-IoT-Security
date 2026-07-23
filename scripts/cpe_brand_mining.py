#!/usr/bin/env python3
"""Automated vendor discovery — surface CPE brands missing from vendor_terms.csv.

Both text-based methods (vendor search, keyword search) can only find a vendor whose
name (or a device phrase) appears in a CVE's *description*. But every CVE also carries
`cpe_strings` — NVD's own structured vendor:product attribution — so a vendor that shows
up on a handful of Yes-confirmed or keyword-matched CVEs for a category is evidence that
vendor makes devices of that type, even though most of its *other* CVEs have terse
descriptions neither method's terms would ever match. Mining the vendor name out of the
CPE and proposing it as a new `vendor_terms.csv` term makes that vendor's whole catalogue
searchable — this is the automated-discovery counterpart to Stage 5 (`cpe_expansion.py`),
which densifies *products* already confirmed rather than discovering new *brands*.

This script never edits vendor_terms.csv — it is read-only outside its one output file.
See docs/plans/PLAN_cpe_brand_mining.md and CLAUDE.md Stage 5 for the guardrails this
reuses (device-CPE granularity, GENERIC_PLATFORM_CPES) and docs/SCRIPTS_REFERENCE.md for
the full flag table.

Algorithm (see the plan doc for the full rationale):
  1. Per-category evidence: Tier A = confirmed-Yes CPEs (judgment_store.csv), Tier B =
     keyword-matched CPEs not judged No. Both filtered to device-level (part in {o,h},
     non-platform) vendor:product CPEs.
  2. Drop vendors already covered by an existing vendor_terms.csv term for that slug
     (cross-slug coverage is reported, not dropped).
  3. One snapshot pass scores new_yield (CVEs the vendor would add that neither text
     method already found) and snapshot_total (the vendor's whole CPE footprint, in or
     out of scope) for every surviving candidate.
  4. Risk flags (mega-vendor / known-fp-bomb / dictionary-word) so a human reviewer can
     triage the candidate list fast.

Usage:
    python3 scripts/cpe_brand_mining.py --all                 # every category
    python3 scripts/cpe_brand_mining.py hub streaming alarms  # subset
    python3 scripts/cpe_brand_mining.py --all --min-evidence 2   # require >=2 evidence CVEs (default 1)

Writes data/vendor-search/vendor_candidates.csv (only file this script writes) plus a
console summary (top 10 candidates per category, totals per category).
"""
import argparse
import csv
import os
import re
from collections import defaultdict

from cpe_expansion import DEVICE_PARTS, GENERIC_PLATFORM_CPES, parse_cpe, load_known_cve_ids
from build_search import read_terms
from build_review_sets import read_categories

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
SNAPSHOT = os.path.join(DATA, "nvd-snapshot", "nvd_all.csv")
CATEGORIES_PATH = os.path.join(DATA, "categories.csv")
VENDOR_TERMS_PATH = os.path.join(DATA, "vendor-search", "vendor_terms.csv")
JUDGMENT_STORE = os.path.join(DATA, "difference", "judgment_store.csv")
TERM_PRECISION = os.path.join(DATA, "difference", "term_precision.csv")
OUT_PATH = os.path.join(DATA, "vendor-search", "vendor_candidates.csv")

csv.field_size_limit(1 << 24)

# The four Stage-4 review directions carry cpe_strings for their rows; falling back to
# the snapshot covers Yes rows absent from all four (common — see the plan doc).
DIRECTIONS = ("vendor_only", "keyword_only", "cpe_expansion", "intersection")

# Guardrail source (plan Step 4): measured experiments where a bare vendor term dragged
# in an unrelated-industry mega-catalogue. Supplements (never replaces) the dynamic
# term_precision.csv prune list — kept for vendors never run through the text searches,
# so term_precision.csv has no row to flag them from.
HARDCODED_FP_BOMBS = [
    "worx", "haier", "hisense", "fujitsu", "moxa", "mitsubishi electric",
    "cerberus", "pelco", "geovision", "verint", "anviz",
]

# Small embedded fallback if /usr/share/dict/words isn't present (non-macOS/Linux boxes).
DICT_WORD_FALLBACK = {
    "carrier", "august", "wink", "hue", "nest", "ring", "echo", "orbit", "genie",
    "sense", "tag", "link", "board", "home", "smart", "view", "guard", "shield",
    "pulse", "spark", "flow", "drift", "haven", "nook", "cove", "arc", "core",
}

MIN_MATCH_LEN = 3  # containment (non-equal) matches below this length are too noisy to trust


def normalize(s: str) -> str:
    """Squash to bare alnum lowercase — collapses casefold/underscore/hyphen/space
    differences AND the NVD inconsistency where some multi-word vendors get concatenated
    with no separator at all (e.g. CPE vendor 'mitsubishielectric' vs the term
    'mitsubishi electric')."""
    return re.sub(r"[^a-z0-9]", "", (s or "").strip().casefold())


def _related(a: str, b: str) -> bool:
    """True if normalized a/b are equal, or one contains the other (both >= MIN_MATCH_LEN
    to avoid short-token noise, e.g. a 2-char vendor spuriously 'contained' in anything)."""
    if not a or not b:
        return False
    if a == b:
        return True
    return len(a) >= MIN_MATCH_LEN and len(b) >= MIN_MATCH_LEN and (a in b or b in a)


def extract_vendor_sets(cpe_strings: str):
    """One CVE's pipe-separated CPE list -> (all_vendors, device_vendors).

    all_vendors: every vendor token appearing in any CPE (any part) — used for
    snapshot_total, a vendor's whole footprint regardless of scope.
    device_vendors: vendor tokens from device-level CPEs only (part in {o,h}, not a
    GENERIC_PLATFORM_CPES entry) — the same guardrail cpe_expansion.py enforces, so a
    candidate here is held to the identical device-CPE-granularity bar as Stage 5.
    """
    all_v, dev_v = set(), set()
    for c in (cpe_strings or "").split("|"):
        c = c.strip()
        if not c:
            continue
        parts = c.split(":")
        if len(parts) >= 5:
            vendor = parts[3].strip().lower()
            if vendor and vendor not in ("*", "-"):
                all_v.add(vendor)
        part, vp = parse_cpe(c)
        if vp is not None and part in DEVICE_PARTS and vp not in GENERIC_PLATFORM_CPES:
            dev_v.add(vp.split(":", 1)[0])
    return all_v, dev_v


def load_judgment_store():
    """category -> {cve_id: (Final Judgment, Excluded)}, one read for every category at once.

    Excluded (set only by mark_excluded.py; blank = in scope) rides alongside the judgment
    so callers can tell evidence-gathering (must skip excluded rows) apart from "known /
    already judged" suppression sets (must still treat excluded rows as known — see
    cpe_product_scan.py's build_known_sets, which only reads .keys() and is unaffected)."""
    store = defaultdict(dict)
    with open(JUDGMENT_STORE, newline="") as f:
        for r in csv.DictReader(f):
            store[r["category"]][r["cve_id"]] = (
                (r.get("Final Judgment") or "").strip(),
                (r.get("Excluded") or "").strip(),
            )
    return store


def load_direction_cpe_map(category):
    """cve_id -> cpe_strings across all four Stage-4 review directions for one category."""
    m = {}
    for direction in DIRECTIONS:
        p = os.path.join(DATA, "difference", category, direction, "01_raw.csv")
        if not os.path.exists(p):
            continue
        with open(p, newline="") as f:
            for r in csv.DictReader(f):
                m.setdefault(r["cve_id"], r.get("cpe_strings", ""))
    return m


def load_snapshot_cpe_fallback(missing_ids):
    """One pass over the snapshot filling cpe_strings for cve_ids absent from every
    direction file (2,136/3,085 Yes rows per the plan doc — the snapshot always has them)."""
    if not missing_ids:
        return {}
    found = {}
    with open(SNAPSHOT, newline="") as f:
        for r in csv.DictReader(f):
            cid = r["cve_id"]
            if cid in missing_ids:
                found[cid] = r.get("cpe_strings", "")
                if len(found) == len(missing_ids):
                    break
    return found


def gather_evidence(categories, store):
    """{category: {vendor: {"yes": {cve_id,...}, "kw": {cve_id,...}}}}

    Excluded rows (scope-out-of-population, see mark_excluded.py) contribute no evidence,
    Tier A or Tier B — a row's exclusion is treated the same as a settled No for the
    purposes of "don't resurface" (CLAUDE.md Stage-5-adjacent guardrail, see
    docs/plans/PLAN_scope_exclusion.md)."""
    yes_ids_by_cat, no_ids_by_cat = {}, {}
    for cat in categories:
        judgments = store.get(cat, {})
        yes_ids_by_cat[cat] = {
            c for c, (j, ex) in judgments.items() if j.lower() == "yes" and not ex
        }
        no_ids_by_cat[cat] = {
            c for c, (j, ex) in judgments.items() if j.lower() == "no" or ex
        }

    direction_map_by_cat = {cat: load_direction_cpe_map(cat) for cat in categories}

    missing = set()
    for cat in categories:
        dmap = direction_map_by_cat[cat]
        missing.update(cid for cid in yes_ids_by_cat[cat] if cid not in dmap)
    fallback = load_snapshot_cpe_fallback(missing)

    evidence = defaultdict(lambda: defaultdict(lambda: {"yes": set(), "kw": set()}))

    # Tier A — confirmed Yes.
    for cat in categories:
        dmap = direction_map_by_cat[cat]
        for cid in yes_ids_by_cat[cat]:
            cpes = dmap.get(cid)
            if cpes is None:
                cpes = fallback.get(cid, "")
            _, dev_vendors = extract_vendor_sets(cpes)
            for v in dev_vendors:
                evidence[cat][v]["yes"].add(cid)

    # Tier B — keyword-matched, not judged No.
    for cat in categories:
        kp = os.path.join(DATA, "keyword-search", f"keyword_{cat}.csv")
        if not os.path.exists(kp):
            continue
        no_ids = no_ids_by_cat[cat]
        with open(kp, newline="") as f:
            for r in csv.DictReader(f):
                cid = r["cve_id"]
                if cid in no_ids:
                    continue
                _, dev_vendors = extract_vendor_sets(r.get("cpe_strings", ""))
                for v in dev_vendors:
                    evidence[cat][v]["kw"].add(cid)

    return evidence


def build_coverage_index(vendor_terms):
    """slug -> [normalized term, ...] for the Step-2 already-covered check."""
    return {slug: [normalize(t) for t in terms] for slug, terms in vendor_terms.items()}


def is_covered(vendor, slug, coverage_idx):
    nv = normalize(vendor)
    return any(_related(nv, nt) for nt in coverage_idx.get(slug, []))


def covered_elsewhere(vendor, own_slug, coverage_idx):
    nv = normalize(vendor)
    return sorted(
        slug for slug, terms in coverage_idx.items()
        if slug != own_slug and any(_related(nv, nt) for nt in terms)
    )


def load_fp_bomb_terms():
    """Dynamic (term_precision.csv, method=vendor, prune_candidate=Yes) unioned with the
    hardcoded fallback list, both normalized — dynamic first per the plan's preference."""
    terms = set()
    if os.path.exists(TERM_PRECISION):
        with open(TERM_PRECISION, newline="") as f:
            for r in csv.DictReader(f):
                if r.get("method") == "vendor" and (r.get("prune_candidate") or "").strip().lower() == "yes":
                    terms.add(normalize(r.get("term", "")))
    terms.update(normalize(t) for t in HARDCODED_FP_BOMBS)
    terms.discard("")
    return terms


def load_dictionary_words():
    path = "/usr/share/dict/words"
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                return {w.strip().lower() for w in f if w.strip()}
        except OSError:
            pass
    return set(DICT_WORD_FALLBACK)


def risk_flags_for(vendor, snapshot_total, n_evidence_distinct, fp_terms, dict_words):
    flags = []
    if snapshot_total > 200 and n_evidence_distinct < 0.10 * snapshot_total:
        flags.append("mega-vendor")
    nv = normalize(vendor)
    if any(_related(nv, nt) for nt in fp_terms):
        flags.append("known-fp-bomb")
    token = vendor.strip().casefold()
    if token.isalpha() and len(token) >= MIN_MATCH_LEN and token in dict_words:
        flags.append("dictionary-word")
    return "|".join(flags)


def scan_snapshot_for_candidates(vendor_to_cats, known_ids_by_cat):
    """One pass over the snapshot. Returns (snapshot_total, new_yield, samples):
    snapshot_total: {vendor: count}                      — whole footprint, any part.
    new_yield:      {category: {vendor: count}}           — device-level hits not in
                     either text method's known set for that category.
    samples:        {(category, vendor): [(cve_id, description[:150]), ...]} up to 3.
    """
    candidate_vendors = set(vendor_to_cats)
    snapshot_total = defaultdict(int)
    new_yield = defaultdict(lambda: defaultdict(int))
    samples = defaultdict(list)
    with open(SNAPSHOT, newline="") as f:
        for r in csv.DictReader(f):
            cpes = r.get("cpe_strings", "")
            if not cpes:
                continue
            all_v, dev_v = extract_vendor_sets(cpes)
            for v in all_v & candidate_vendors:
                snapshot_total[v] += 1
            hit_dev = dev_v & candidate_vendors
            if not hit_dev:
                continue
            cid = r["cve_id"]
            for v in hit_dev:
                for cat in vendor_to_cats[v]:
                    if cid in known_ids_by_cat[cat]:
                        continue
                    new_yield[cat][v] += 1
                    key = (cat, v)
                    if len(samples[key]) < 3:
                        samples[key].append((cid, (r.get("description") or "")[:150]))
    return snapshot_total, new_yield, samples


CANDIDATE_COLS = [
    "category", "vendor", "n_yes_evidence", "n_keyword_evidence",
    "covered_elsewhere_slug", "snapshot_total", "new_yield", "risk_flags",
    "sample_cves", "sample_descriptions",
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
        crows.sort(key=lambda r: -r["new_yield"])
        total_new = sum(r["new_yield"] for r in crows)
        grand_new += total_new
        print(f"\n=== {cat}: {len(crows)} candidate vendor(s), {total_new} total new-yield CVE(s) ===")
        for r in crows[:10]:
            flags = f"  [{r['risk_flags']}]" if r["risk_flags"] else ""
            print(f"  {r['vendor']:<28} yes={r['n_yes_evidence']:<3} kw={r['n_keyword_evidence']:<3} "
                  f"snap_total={r['snapshot_total']:<5} new_yield={r['new_yield']:<5}{flags}")
    print(f"\n=== TOTAL: {len(rows)} candidate (category, vendor) pair(s), {grand_new} new-yield CVE(s) "
          f"across {len(by_cat)} categor(y/ies) ===")
    print(f"-> {os.path.relpath(OUT_PATH, ROOT)}")


def run(categories, min_evidence):
    print(f"Loading judgment store, vendor_terms.csv, term_precision.csv...")
    store = load_judgment_store()
    vendor_terms = read_terms(VENDOR_TERMS_PATH)
    coverage_idx = build_coverage_index(vendor_terms)
    fp_terms = load_fp_bomb_terms()
    dict_words = load_dictionary_words()

    print(f"Gathering evidence for {len(categories)} categor(y/ies) "
          "(Tier A confirmed-Yes CPEs, Tier B keyword-matched CPEs)...")
    evidence = gather_evidence(categories, store)

    candidates = {}
    for cat in categories:
        for vendor, tiers in evidence.get(cat, {}).items():
            if is_covered(vendor, cat, coverage_idx):
                continue
            n_distinct = len(tiers["yes"] | tiers["kw"])
            if n_distinct < min_evidence:
                continue
            candidates[(cat, vendor)] = dict(
                n_yes=len(tiers["yes"]), n_kw=len(tiers["kw"]),
                covered_elsewhere=covered_elsewhere(vendor, cat, coverage_idx),
            )

    if not candidates:
        print("No candidate vendors survived evidence + coverage filtering.")
        return []

    vendor_to_cats = defaultdict(set)
    for (cat, vendor) in candidates:
        vendor_to_cats[vendor].add(cat)

    print(f"Scanning snapshot once for {len(vendor_to_cats)} candidate vendor(s)...")
    known_ids_by_cat = {cat: load_known_cve_ids(cat) for cat in {c for c, _v in candidates}}
    snapshot_total, new_yield, samples = scan_snapshot_for_candidates(vendor_to_cats, known_ids_by_cat)

    rows = []
    for (cat, vendor), info in candidates.items():
        snap_total = snapshot_total.get(vendor, 0)
        n_new = new_yield.get(cat, {}).get(vendor, 0)
        n_distinct_evidence = info["n_yes"] + info["n_kw"]  # dominant driver, ok to approximate here
        flags = risk_flags_for(vendor, snap_total, n_distinct_evidence, fp_terms, dict_words)
        samp = samples.get((cat, vendor), [])
        rows.append({
            "category": cat, "vendor": vendor,
            "n_yes_evidence": info["n_yes"], "n_keyword_evidence": info["n_kw"],
            "covered_elsewhere_slug": "|".join(info["covered_elsewhere"]),
            "snapshot_total": snap_total, "new_yield": n_new,
            "risk_flags": flags,
            "sample_cves": "|".join(c for c, _d in samp),
            "sample_descriptions": "|".join(d for _c, d in samp),
        })

    rows.sort(key=lambda r: (r["category"], -r["new_yield"]))
    write_candidates(rows)
    print_summary(rows, categories)
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("categories", nargs="*", help="category slug(s); omit when using --all")
    ap.add_argument("--all", action="store_true", help="every category in categories.csv")
    ap.add_argument("--min-evidence", type=int, default=1,
                    help="min distinct evidence CVEs (Tier A + Tier B, deduped) required (default: 1)")
    args = ap.parse_args()

    if args.all:
        cats = read_categories(CATEGORIES_PATH)
    elif args.categories:
        cats = args.categories
    else:
        ap.error("give one or more category slugs, or --all")

    run(cats, args.min_evidence)


if __name__ == "__main__":
    main()
