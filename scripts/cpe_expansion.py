#!/usr/bin/env python3
"""Stage 5 — CPE expansion: the third discovery method.

Once a vendor:product CPE has been confirmed `Yes` (final judgment), scan the NVD
snapshot for *every* CVE that NVD itself attributes to that same vendor:product —
regardless of whether the CVE's description mentions a brand term or a device phrase.
This catches terse entries ("buffer overflow in the web server of X firmware") that
both text-based methods (vendor search, keyword search) structurally miss.

It is a *densification* method, not a discovery method: it can only find more CVEs for
products already confirmed, never a new brand. Its recall is bounded to "everything NVD
attributed to devices we already caught."

Guardrails (see CLAUDE.md Stage 5):
  1. Seed ONLY from Final Judgment == Yes rows (judgment_store.csv).
  2. Device-CPE granularity, two filters:
       (a) vendor:product only — never vendor-only. A CPE whose product field is
           empty / '*' / '-' is dropped (would drag in a whole vendor catalogue).
       (b) part in {o, h} only — firmware/hardware. A co-listed part=a CPE (a shared
           protocol library / SoC / app riding on a device's Yes row, e.g.
           openweave:openweave-core on a Nest camera CVE) is dropped. This is what
           keeps expansion pinned to the physical device, not its dependencies.
       (c) general-purpose computing platforms (GENERIC_PLATFORM_CPES) are dropped even
           though they are part=o. Apple/Google attribute one CVE across every OS at once,
           so a streaming Apple-TV Yes row co-lists apple:tvos WITH apple:mac_os_x /
           apple:iphone_os / apple:watchos; seeding those pulls the entire desktop/mobile
           corpus (~17k for `streaming` alone). Only shared platforms are denied — the
           device-specific OS/firmware CPEs (amazon:fire_os, per-model TVs) are kept.
           NOTE: apple:tvos itself is ALSO denied here (2026-07 scope ruling, see
           docs/plans/PLAN_scope_exclusion.md) — its ~1.9k yield turned out to be almost
           entirely shared-WebKit CVEs disproportionate to its device-specific share, so
           the `streaming` scope note now excludes tvOS CVEs wholesale. This stops new
           tvos seeds from entering; already-confirmed tvos rows are separately flagged
           `Excluded` in judgment_store.csv by mark_excluded.py (retroactive removal from
           analysis population without touching AI judgments).
  3. New candidates leave the pipeline as an UNREVIEWED candidate set — this script
     never auto-includes them. It tags Discovery Method = cpe_expansion and records
     the seed CPE that pulled each row in (attribution, like matched_terms), so
     per-seed precision stays measurable and a contaminating seed shows up as a
     lopsided single-seed yield in the report.

Usage:
    python3 scripts/cpe_expansion.py <category>        # one category
    python3 scripts/cpe_expansion.py --all             # every seeded category + summary
    python3 scripts/cpe_expansion.py <category> --no-part-filter   # A/B the guardrail

Writes per-category  data/difference/<cat>/09_cpe_expansion_candidates.csv
and (in --all)       data/difference/cpe_expansion_summary.csv
"""
import argparse
import csv
import os
import sys
from collections import Counter, defaultdict

from review_lib import write_raw  # shared Stage-4 01_raw.csv writer (canonical RAW_COLS)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
SNAPSHOT = os.path.join(DATA, "nvd-snapshot", "nvd_all.csv")

csv.field_size_limit(1 << 24)

# The four Stage-4 review directions carry cpe_strings for their rows; falling back to
# the snapshot covers Yes rows absent from all four (2,136/3,085 Yes rows per
# docs/plans/PLAN_cpe_brand_mining.md — the snapshot always has the row). Without this,
# build_seeds silently skips any Yes CVE whose row isn't in vendor_only/keyword_only,
# starving Stage-5 seeding for exactly the small/thin categories that need it most.
DIRECTIONS = ("vendor_only", "keyword_only", "cpe_expansion", "intersection")

DEVICE_PARTS = {"o", "h"}  # firmware / hardware — guardrail 2(b)

# Guardrail 2(c): general-purpose computing platforms are never a home-IoT *device* seed,
# even though they are part=o. They leak in because vendors (esp. Apple/Google) attribute a
# single CVE across every OS at once — a streaming Apple-TV CVE co-lists apple:tvos WITH
# apple:mac_os_x / apple:iphone_os / apple:watchos, and seeding those pulls the entire
# desktop/mobile CVE corpus (17k+ for `streaming` alone). The device-specific OS/firmware CPEs
# (amazon:fire_os, per-model sony:kd-* TVs) are NOT denied — only shared general-purpose
# platforms. nvidia:jetson_* are embedded dev/robotics boards (fail criteria 2 & 3), not home
# devices, so they are denied too. apple:tvos was denied 2026-07 by a separate scope ruling
# (see docs/plans/PLAN_scope_exclusion.md) — it is device-specific, not general-purpose, but
# its yield turned out to be almost entirely shared-WebKit CVEs, so it is excluded for volume.
GENERIC_PLATFORM_CPES = {
    "apple:mac_os_x", "apple:mac_os_x_server", "apple:macos", "apple:mac_os",
    "apple:iphone_os", "apple:ipados", "apple:ipad_os", "apple:watchos", "apple:tvos",
    "google:android", "google:android_things",
    "microsoft:windows", "microsoft:windows_10", "microsoft:windows_11",
    "linux:linux_kernel", "canonical:ubuntu_linux", "debian:debian_linux",
    "redhat:enterprise_linux", "fedoraproject:fedora", "opensuse:leap",
    "nvidia:jetson_tx1", "nvidia:jetson_tx2", "nvidia:jetson_nano",
    "nvidia:jetson_nano_2gb", "nvidia:jetson_xavier_nx", "nvidia:jetson_agx_xavier",
    "nvidia:linux_for_tegra",
}


def parse_cpe(cpe: str):
    """Return (part, 'vendor:product') from a CPE 2.3 URI, or (None, None) if unusable.

    Enforces guardrail 2(a): product must be a concrete token, not '' / '*' / '-'.
    """
    parts = cpe.split(":")
    if len(parts) < 5:
        return None, None
    part = parts[2].strip().lower()
    vendor, product = parts[3].strip().lower(), parts[4].strip().lower()
    if not vendor or vendor in ("*", "-"):
        return None, None
    if not product or product in ("*", "-"):
        return None, None
    return part, f"{vendor}:{product}"


def device_str(vp: str) -> str:
    """Collapse the firmware/hardware twins to one device label for counting."""
    return vp[: -len("_firmware")] if vp.endswith("_firmware") else vp


def load_yes_cve_ids(category: str):
    """Confirmed-Yes CVEs for a category, excluding rows flagged out-of-scope in the store
    (Excluded column, set by mark_excluded.py) — an excluded row must never seed Stage 5."""
    path = os.path.join(DATA, "difference", "judgment_store.csv")
    yes = set()
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            if (r["category"] == category
                    and (r.get("Final Judgment") or "").strip().lower() == "yes"
                    and not (r.get("Excluded") or "").strip()):
                yes.add(r["cve_id"])
    return yes


def load_raw_rows(category: str):
    """cve_id -> row dict across all four Stage-4 review directions (carries cpe_strings)."""
    rows = {}
    for direction in DIRECTIONS:
        p = os.path.join(DATA, "difference", category, direction, "01_raw.csv")
        if not os.path.exists(p):
            continue
        with open(p, newline="") as f:
            for r in csv.DictReader(f):
                rows.setdefault(r["cve_id"], r)
    return rows


def load_snapshot_cpe_fallback(missing_ids):
    """One pass over the snapshot filling cpe_strings for cve_ids absent from every
    direction file (see DIRECTIONS comment above — the snapshot always has them)."""
    if not missing_ids:
        return {}
    found = {}
    with open(SNAPSHOT, newline="") as f:
        for r in csv.DictReader(f):
            cid = r["cve_id"]
            if cid in missing_ids:
                found[cid] = {"cpe_strings": r.get("cpe_strings", "")}
                if len(found) == len(missing_ids):
                    break
    return found


def load_known_cve_ids(category: str):
    """Every CVE already surfaced for this category by either text method."""
    known = set()
    kp = os.path.join(DATA, "keyword-search", f"keyword_{category}.csv")
    if os.path.exists(kp):
        with open(kp, newline="") as f:
            for r in csv.DictReader(f):
                known.add(r["cve_id"])
    vp = os.path.join(DATA, "vendor-search", f"results_all_{category}.csv")
    if os.path.exists(vp):
        with open(vp, newline="") as f:
            for r in csv.DictReader(f):
                known.add(r["cve_id"])
    return known


def build_seeds(category: str, part_filter: bool, raw: dict | None = None):
    """Return (seeds set, seed_source, stats) for a category's confirmed-Yes CPEs.

    `raw` may be pre-supplied (already merged with the snapshot fallback) so callers
    iterating many categories — see `run()` — can do ONE combined fallback pass instead
    of one per category. If omitted (single-category CLI usage), falls back standalone.
    """
    yes_ids = load_yes_cve_ids(category)
    if raw is None:
        raw = load_raw_rows(category)
        missing = yes_ids - raw.keys()
        raw = {**raw, **load_snapshot_cpe_fallback(missing)}
    seeds = set()
    seed_source = defaultdict(set)
    yes_with_cpe = 0
    dropped_vendor_only = 0
    dropped_app = 0
    dropped_platform = 0
    for cid in yes_ids:
        row = raw.get(cid)
        if not row:
            continue
        cpes = [c for c in (row.get("cpe_strings") or "").split("|") if c.strip()]
        if cpes:
            yes_with_cpe += 1
        for c in cpes:
            part, vp = parse_cpe(c)
            if vp is None:
                if len(c.split(":")) >= 4:
                    dropped_vendor_only += 1
                continue
            if part_filter and part not in DEVICE_PARTS:
                dropped_app += 1
                continue
            if vp in GENERIC_PLATFORM_CPES:  # guardrail 2(c)
                dropped_platform += 1
                continue
            seeds.add(vp)
            seed_source[vp].add(cid)
    stats = dict(yes=len(yes_ids), yes_with_cpe=yes_with_cpe,
                 dropped_vendor_only=dropped_vendor_only, dropped_app=dropped_app,
                 dropped_platform=dropped_platform,
                 devices=len({device_str(vp) for vp in seeds}))
    return seeds, seed_source, stats


def scan_snapshot(all_seeds):
    """One pass over the snapshot. all_seeds: {category: seed_set}.

    Returns {category: [(row, hit_seeds), ...]} of matches (known + new both kept).
    """
    hits = {c: [] for c in all_seeds}
    with open(SNAPSHOT, newline="") as f:
        for r in csv.DictReader(f):
            cpes = [c for c in (r.get("cpe_strings") or "").split("|") if c.strip()]
            if not cpes:
                continue
            vps = set()
            for c in cpes:
                _, vp = parse_cpe(c)
                if vp:
                    vps.add(vp)
            if not vps:
                continue
            for cat, seeds in all_seeds.items():
                overlap = vps & seeds
                if overlap:
                    hits[cat].append((r, overlap))
    return hits


def write_candidates(category, new_rows):
    """Attribution file — carries seed_cpe (the CPE-expansion analogue of matched_terms)."""
    out = os.path.join(DATA, "difference", category, "09_cpe_expansion_candidates.csv")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    cols = ["cve_id", "published", "description", "cvss_score", "cvss_version",
            "cwe_ids", "cpe_strings", "seed_cpe", "Discovery Method"]
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r, hit_seeds in sorted(new_rows, key=lambda x: x[0]["cve_id"]):
            w.writerow({
                "cve_id": r["cve_id"], "published": r.get("published", ""),
                "description": r.get("description", ""), "cvss_score": r.get("cvss_score", ""),
                "cvss_version": r.get("cvss_version", ""), "cwe_ids": r.get("cwe_ids", ""),
                "cpe_strings": r.get("cpe_strings", ""),
                "seed_cpe": "|".join(sorted(hit_seeds)), "Discovery Method": "cpe_expansion",
            })
    return out


def write_stage4_raw(category, new_rows):
    """Emit <cat>/cpe_expansion/01_raw.csv so Stage 4 reviews the candidates.

    'cpe_expansion' is a third review DIRECTION alongside vendor_only / keyword_only —
    disjoint from both by construction (these CVEs are, by definition, in neither method's
    output), so the Stage-4 (category, cve_id) key stays unique and finalize/extract, which
    read Difference Type per row, need no changes. make_review_copies.py picks it up.
    Returns the path, or None when there are no candidates (no empty folder is created).
    """
    if not new_rows:
        return None
    out = os.path.join(DATA, "difference", category, "cpe_expansion", "01_raw.csv")
    records = [
        {
            "Difference Type": "cpe_expansion",
            "cve_id": r["cve_id"], "published": r.get("published", ""),
            "description": r.get("description", ""), "cvss_score": r.get("cvss_score", ""),
            "cvss_version": r.get("cvss_version", ""), "cwe_ids": r.get("cwe_ids", ""),
            "cpe_strings": r.get("cpe_strings", ""),
        }
        for r, _hit_seeds in sorted(new_rows, key=lambda x: x[0]["cve_id"])
    ]
    write_raw(records, out)
    return out


def seeded_categories():
    """Categories that have at least one non-excluded Final Judgment == Yes in the store."""
    cats = set()
    path = os.path.join(DATA, "difference", "judgment_store.csv")
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            if ((r.get("Final Judgment") or "").strip().lower() == "yes"
                    and not (r.get("Excluded") or "").strip()):
                cats.add(r["category"])
    return sorted(cats)


def run(categories, part_filter, to_stage4=True):
    # Gather each category's raw rows first, then do ONE combined snapshot pass to
    # fall back the Yes CVEs missing from all four direction files (rather than one
    # fallback pass per category) — same one-pass convention as scan_snapshot below.
    raw_by_cat = {cat: load_raw_rows(cat) for cat in categories}
    yes_by_cat = {cat: load_yes_cve_ids(cat) for cat in categories}
    all_missing = set()
    for cat in categories:
        all_missing.update(yes_by_cat[cat] - raw_by_cat[cat].keys())
    fallback = load_snapshot_cpe_fallback(all_missing)
    for cat in categories:
        raw_by_cat[cat] = {**raw_by_cat[cat], **fallback}

    all_seeds, all_src, all_stats = {}, {}, {}
    for cat in categories:
        seeds, src, stats = build_seeds(cat, part_filter, raw=raw_by_cat[cat])
        if not seeds:
            print(f"  {cat}: no usable confirmed-Yes device CPEs — skipping")
            continue
        all_seeds[cat], all_src[cat], all_stats[cat] = seeds, src, stats
    if not all_seeds:
        print("Nothing to expand.")
        return []

    hits = scan_snapshot(all_seeds)

    summary = []
    for cat in categories:
        if cat not in all_seeds:
            continue
        known = load_known_cve_ids(cat)
        matched = hits[cat]
        new_rows = [(r, s) for (r, s) in matched if r["cve_id"] not in known]
        per_seed_total, per_seed_new = Counter(), Counter()
        for r, s in matched:
            for vp in s:
                per_seed_total[vp] += 1
        for r, s in new_rows:
            for vp in s:
                per_seed_new[vp] += 1
        st = all_stats[cat]
        out = write_candidates(cat, new_rows)
        raw_out = write_stage4_raw(cat, new_rows) if to_stage4 else None

        print(f"\n=== CPE expansion — {cat} ===")
        print(f"confirmed-Yes seeds:            {st['yes']} ({st['yes_with_cpe']} carry a CPE)")
        print(f"distinct device seeds:          {st['devices']}  "
              f"(dropped {st['dropped_app']} app/lib CPE, {st['dropped_vendor_only']} vendor-only, "
              f"{st['dropped_platform']} general-purpose platform)")
        print(f"snapshot CVEs matching a seed:  {len(matched)}")
        print(f"  already known (either method): {len(matched) - len(new_rows)}")
        print(f"  NEW candidates:                {len(new_rows)}")
        if per_seed_new:
            print("  top seeds by NEW yield (a lopsided single seed = inspect for contamination):")
            for vp, n in per_seed_new.most_common(6):
                print(f"    {vp:<48}{n:>4} new /{per_seed_total[vp]:>4} total")
        print(f"  -> {os.path.relpath(out, ROOT)}")
        if raw_out:
            print(f"  -> {os.path.relpath(raw_out, ROOT)}  (Stage-4 direction: cpe_expansion)")

        summary.append(dict(
            category=cat, yes_seeds=st["yes"], device_seeds=st["devices"],
            app_cpe_dropped=st["dropped_app"], platform_cpe_dropped=st["dropped_platform"],
            matched=len(matched),
            already_known=len(matched) - len(new_rows), new_candidates=len(new_rows),
        ))
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("category", nargs="?", help="single category; omit with --all")
    ap.add_argument("--all", action="store_true", help="every seeded category + summary CSV")
    ap.add_argument("--no-part-filter", action="store_true",
                    help="disable the part in {o,h} guardrail (to A/B the leak filter)")
    ap.add_argument("--no-stage4", action="store_true",
                    help="report only; do NOT write cpe_expansion/01_raw.csv for Stage 4")
    args = ap.parse_args()

    part_filter = not args.no_part_filter
    to_stage4 = not args.no_stage4
    if args.all:
        cats = seeded_categories()
    elif args.category:
        cats = [args.category]
    else:
        ap.error("give a category or --all")

    summary = run(cats, part_filter, to_stage4)

    if to_stage4:
        staged = [s["category"] for s in summary if s["new_candidates"]]
        if staged:
            print("\nNext: route these into Stage-4 review (candidates are unreviewed):")
            print(f"  python3 scripts/make_review_copies.py {'--all' if args.all else staged[0]}")
            print("  # then Claude/Codex fill reviews/*.csv; Gemini via merge_judgments.py --run-gemini")
            print("  # then extract_human_review.py -> finalize_judgments.py, as usual")

    if args.all and summary:
        sp = os.path.join(DATA, "difference", "cpe_expansion_summary.csv")
        with open(sp, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(summary[0].keys()))
            w.writeheader()
            w.writerows(summary)
        tot_new = sum(s["new_candidates"] for s in summary)
        tot_drop = sum(s["app_cpe_dropped"] for s in summary)
        tot_plat = sum(s["platform_cpe_dropped"] for s in summary)
        print(f"\n=== TOTAL: {tot_new} new candidate CVEs across {len(summary)} categories "
              f"({tot_drop} app/lib CPEs dropped by the part filter, "
              f"{tot_plat} general-purpose platform CPEs dropped) ===")
        print(f"summary -> {os.path.relpath(sp, ROOT)}")


if __name__ == "__main__":
    main()
