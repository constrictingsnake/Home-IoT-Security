#!/usr/bin/env python3
"""CWE-888 vulnerability-class analysis over confirmed-Yes CVEs.

Replicates the CWE analysis of the transportation IoT device study (Yih,
Goseva-Popstojanova & Cukier — Onboarding-Docs/transportation_device_study.pdf,
Section III-C / Table III) on this project's judgment store: every CWE attached
to a confirmed-Yes CVE is grouped into one of the 23 *primary clusters* of the
CWE-888 Software Fault Patterns view, giving a per-category distribution of
vulnerability classes.

Method (paper-faithful):
  1. Take every (category, cve_id) with Final Judgment = Yes in judgment_store.csv.
  2. Look up its CWE ids in the fixed NVD snapshot (nvd_all.csv `cwe_ids`).
     NVD-CWE-noinfo / NVD-CWE-Other rows count as CVEs but contribute no CWEs.
  3. Map each CWE to CWE-888 primary class(es):
       - if the CWE is a member of the 888 view, use its primary cluster(s);
       - otherwise climb its ChildOf parents (Research Concepts view 1000),
         level by level, stopping at the first level where any ancestor is in
         the 888 view — all mapped ancestors at that level count (so CWE-798
         maps to both Predictability via CWE-344 and Other via CWE-671,
         exactly the paper's worked example).
  4. Tally per (category, primary class). The unit is a CWE attribution — a
     CVE with two CWEs counts twice; a CWE mapping to two classes counts in
     both (same counting as the paper's Table III).

The CWE catalog is pinned to v4.12 (June 29, 2023) — the same CWE-888 version
the paper used. If data/cwe/cwec_v4.12.xml[.zip] is missing:
    curl -L -o data/cwe/cwec_v4.12.xml.zip https://cwe.mitre.org/data/xml/cwec_v4.12.xml.zip

Caveat: unlike the paper's four disjoint device categories, one CVE can be a
confirmed Yes in several of our categories; it then counts once per category,
so the All column is attribution-weighted, not a distinct-CVE count.

Outputs (default under data/difference/):
  cwe888_distribution.csv  — long form: category, cwe888_class, n_cwes, pct
  cwe888_cve_map.csv       — audit trail: one row per (category, cve_id, cwe_id)
                             with the class(es) it mapped to and the map depth
                             (0 = in the 888 view itself, 1 = via parents, ...)
  cwe888_matrix.md         — Table-III-style matrix (classes x categories,
                             "n (pct%)" cells, Total and Top-6-share rows)
                             plus per-category CWE-coverage notes

Usage:
    python3 scripts/cwe888_analysis.py
    python3 scripts/cwe888_analysis.py --category cameras --category thermostat
    python3 scripts/cwe888_analysis.py --store data/difference/judgment_store.csv
"""
import argparse
import csv
import io
import os
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict

csv.field_size_limit(sys.maxsize)     # snapshot cpe_strings fields exceed the default

ROOT =os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_STORE = os.path.join(ROOT, "data", "difference", "judgment_store.csv")
DEFAULT_SNAPSHOT = os.path.join(ROOT, "data", "nvd-snapshot", "nvd_all.csv")
DEFAULT_CATEGORIES = os.path.join(ROOT, "data", "categories.csv")
DEFAULT_FAMILIES = os.path.join(ROOT, "data", "ontology", "families.csv")


def load_families(path):
    """slug -> family_label, plus the family order (first appearance). Generated from
    ontology/homeiot.ttl by scripts/ontology_build.py --write."""
    fam, order = {}, []
    with open(path, newline="", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            label = r["family_label"].strip()
            fam[r["slug"].strip()] = label
            if label not in order:
                order.append(label)
    return fam, order


def macro_profile(counters, class_names):
    """Unweighted mean of each unit's percentage profile — the macro-average.

    The `ALL` row is a micro-average: it pools attributions, so a unit with 20x the
    CVEs contributes 20x the weight and the overall shape is whatever the largest
    unit's shape is. The macro-average gives every unit with data an equal vote,
    answering 'what does a typical home IoT device category look like' rather than
    'what does the corpus look like'. Report both; the gap between them measures how
    concentrated the corpus is."""
    profiles = []
    for c in counters:
        total = sum(c.values())
        if total:
            profiles.append({cls: 100 * c[cls] / total for cls in class_names})
    if not profiles:
        return {cls: 0.0 for cls in class_names}
    return {cls: sum(p[cls] for p in profiles) / len(profiles) for cls in class_names}
DEFAULT_CWE_XML = os.path.join(ROOT, "data", "cwe", "cwec_v4.12.xml")
DEFAULT_OUT_DIR = os.path.join(ROOT, "data", "difference")

CWE_NS = {"c": "http://cwe.mitre.org/cwe-7"}
SFP_VIEW_ID = "888"
PARENT_VIEW_ID = "1000"          # Research Concepts — the full ChildOf hierarchy
PRIMARY_PREFIX = "SFP Primary Cluster: "
# NVD placeholders — count as CVEs, contribute no CWEs (paper Section III-B)
NON_CWE = {"NVD-CWE-NOINFO", "NVD-CWE-OTHER"}


# ---------------------------------------------------------------- CWE catalog

def load_cwe_catalog(xml_path):
    """Parse the CWE catalog and return (cwe_to_classes, parents, class_names):
       cwe_to_classes: weakness id -> set of primary-class display names
       parents:        weakness id -> [ChildOf ids in view 1000]
       class_names:    the 23 primary-class display names, sorted
    """
    if os.path.isfile(xml_path):
        root = ET.parse(xml_path).getroot()
    elif os.path.isfile(xml_path + ".zip"):
        with zipfile.ZipFile(xml_path + ".zip") as zf:
            with zf.open(os.path.basename(xml_path)) as fh:
                root = ET.parse(io.BytesIO(fh.read())).getroot()
    else:
        raise SystemExit(
            f"CWE catalog not found at {xml_path}[.zip] — download it with:\n"
            "  curl -L -o data/cwe/cwec_v4.12.xml.zip "
            "https://cwe.mitre.org/data/xml/cwec_v4.12.xml.zip")

    categories = {}          # category id -> (name, [member CWE ids in view 888])
    for cat in root.find("c:Categories", CWE_NS):
        rel = cat.find("c:Relationships", CWE_NS)
        members = [m.get("CWE_ID") for m in rel.findall("c:Has_Member", CWE_NS)
                   if m.get("View_ID") == SFP_VIEW_ID] if rel is not None else []
        categories[cat.get("ID")] = (cat.get("Name"), members)

    view888 = next(v for v in root.find("c:Views", CWE_NS)
                   if v.get("ID") == SFP_VIEW_ID)
    primary_ids = [m.get("CWE_ID")
                   for m in view888.find("c:Members", CWE_NS).findall("c:Has_Member", CWE_NS)]

    cwe_to_classes = defaultdict(set)
    for pid in primary_ids:
        name = categories[pid][0].removeprefix(PRIMARY_PREFIX)
        # members are secondary-cluster categories and/or weaknesses; walk
        # nested categories, collect weakness ids
        stack = list(categories[pid][1])
        while stack:
            mid = stack.pop()
            if mid in categories:
                stack.extend(categories[mid][1])
            else:
                cwe_to_classes[mid].add(name)

    parents = {}
    for weak in root.find("c:Weaknesses", CWE_NS):
        rel = weak.find("c:Related_Weaknesses", CWE_NS)
        if rel is None:
            continue
        ps = [r.get("CWE_ID") for r in rel.findall("c:Related_Weakness", CWE_NS)
              if r.get("Nature") == "ChildOf" and r.get("View_ID") == PARENT_VIEW_ID]
        if ps:
            parents[weak.get("ID")] = ps

    class_names = sorted(categories[pid][0].removeprefix(PRIMARY_PREFIX)
                         for pid in primary_ids)
    return dict(cwe_to_classes), parents, class_names


def map_cwe(cwe_num, cwe_to_classes, parents):
    """Map one CWE number to its CWE-888 primary class(es).

    Level-by-level ascent: if the CWE itself is in the 888 view use it,
    otherwise replace the frontier with all view-1000 parents and take every
    888-mapped CWE at the first level that has any. Returns (classes, depth);
    (set(), -1) if the ancestry never reaches the 888 view.
    """
    frontier, seen, depth = {cwe_num}, {cwe_num}, 0
    while frontier:
        mapped = set()
        for c in frontier:
            mapped |= cwe_to_classes.get(c, set())
        if mapped:
            return mapped, depth
        nxt = set()
        for c in frontier:
            nxt.update(p for p in parents.get(c, []) if p not in seen)
        seen |= nxt
        frontier, depth = nxt, depth + 1
    return set(), -1


# ------------------------------------------------------------------- tallying

def parse_cwe_ids(raw):
    """'CWE-59|CWE-281' -> ['59', '281'] (deduped, order kept); placeholders dropped."""
    out, seen = [], set()
    for tok in (raw or "").split("|"):
        tok = tok.strip()
        if not tok or tok.upper() in NON_CWE:
            continue
        m = re.fullmatch(r"CWE-(\d+)", tok, re.IGNORECASE)
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            out.append(m.group(1))
    return out


def main():
    ap = argparse.ArgumentParser(
        description="CWE-888 primary-class distribution over confirmed-Yes CVEs.")
    ap.add_argument("--store", default=DEFAULT_STORE,
                    help="Judgment store CSV (default: data/difference/judgment_store.csv)")
    ap.add_argument("--snapshot", default=DEFAULT_SNAPSHOT,
                    help="NVD snapshot CSV with cwe_ids (default: data/nvd-snapshot/nvd_all.csv)")
    ap.add_argument("--cwe-xml", default=DEFAULT_CWE_XML,
                    help="CWE catalog XML (or .zip alongside) pinned to v4.12")
    ap.add_argument("--categories", default=DEFAULT_CATEGORIES,
                    help="categories.csv for ordering/labels (default: data/categories.csv)")
    ap.add_argument("--category", action="append", default=None,
                    help="Restrict to one category slug (repeatable; default: all)")
    ap.add_argument("--out-dir", default=DEFAULT_OUT_DIR,
                    help="Output directory (default: data/difference)")
    ap.add_argument("--include-excluded", action="store_true",
                    help="Keep rows a scope ruling took out of the analysis population "
                         "(judgment_store.csv `Excluded`). Off by default — mark_excluded.py's "
                         "rulings are meant to apply.")
    ap.add_argument("--group", choices=("category", "family"), default="category",
                    help="Unit of analysis. 'family' folds the 24 categories into the "
                         "supervisor-agreed folding categories from data/ontology/families.csv "
                         "and writes *_family.* outputs, leaving the per-category files "
                         "untouched.")
    ap.add_argument("--families", default=DEFAULT_FAMILIES,
                    help="families.csv from the ontology (default: data/ontology/families.csv)")
    args = ap.parse_args()

    cwe_to_classes, parents, class_names = load_cwe_catalog(args.cwe_xml)
    print(f"CWE-888 view: {len(class_names)} primary classes, "
          f"{len(cwe_to_classes)} member CWEs (catalog: {os.path.relpath(args.cwe_xml, ROOT)})")

    # confirmed-Yes rows, grouped cve -> categories
    yes_rows = []                     # (category, cve_id)
    n_excluded = 0
    with open(args.store, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            if str(row.get("Final Judgment", "")).strip() == "Yes":
                cat = row["category"].strip()
                if args.category and cat not in args.category:
                    continue
                # A scope ruling (mark_excluded.py) takes a settled row OUT of the
                # analysis population without touching its judgment. finalize_judgments.py
                # already drops these from final_resolved.csv; this script reads the store
                # directly, so it must apply the same filter or the ruling silently does
                # not reach RQ1.
                if str(row.get("Excluded", "")).strip() and not args.include_excluded:
                    n_excluded += 1
                    continue
                yes_rows.append((cat, row["cve_id"].strip().upper()))
    if not yes_rows:
        raise SystemExit("No Final Judgment = Yes rows matched — nothing to analyze.")
    needed = {cve for _, cve in yes_rows}
    print(f"Confirmed-Yes rows: {len(yes_rows)} "
          f"({len(needed)} distinct CVEs, {len({c for c, _ in yes_rows})} categories)")
    if n_excluded:
        print(f"  excluded by scope ruling: {n_excluded} "
              f"(use --include-excluded to keep them)")
    elif args.include_excluded:
        print("  --include-excluded: scope-excluded rows KEPT in the population")

    # cwe_ids lookup from the fixed snapshot, only for needed CVEs
    cwe_of = {}
    with open(args.snapshot, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            cid = row["cve_id"].strip().upper()
            if cid in needed:
                cwe_of[cid] = parse_cwe_ids(row.get("cwe_ids", ""))
    missing = needed - set(cwe_of)
    if missing:
        print(f"  ! {len(missing)} confirmed CVE(s) not in the snapshot "
              f"(e.g. {sorted(missing)[:3]}) — skipped")

    # tally
    counts = defaultdict(Counter)     # category -> Counter(class -> n)
    stats = defaultdict(Counter)      # category -> cves / cves_with_cwe / attributions / unmapped
    map_rows = []
    unmapped_cwes = Counter()
    for cat, cve in yes_rows:
        if cve not in cwe_of:
            continue
        stats[cat]["cves"] += 1
        cwes = cwe_of[cve]
        if cwes:
            stats[cat]["cves_with_cwe"] += 1
        for num in cwes:
            classes, depth = map_cwe(num, cwe_to_classes, parents)
            map_rows.append({
                "category": cat, "cve_id": cve, "cwe_id": f"CWE-{num}",
                "cwe888_classes": "|".join(sorted(classes)), "map_depth": depth,
            })
            if not classes:
                stats[cat]["unmapped"] += 1
                unmapped_cwes[f"CWE-{num}"] += 1
                continue
            stats[cat]["attributions"] += len(classes)
            for cls in classes:
                counts[cat][cls] += 1

    # ---- fold categories into families, if asked
    suffix = ""
    if args.group == "family":
        fam_of, fam_order = load_families(args.families)
        missing = sorted(set(counts) - set(fam_of))
        if missing:
            raise SystemExit(f"No family for: {', '.join(missing)} — "
                             f"rerun scripts/ontology_build.py --write")
        folded, folded_stats = defaultdict(Counter), defaultdict(Counter)
        for cat, c in counts.items():
            folded[fam_of[cat]].update(c)
            folded_stats[fam_of[cat]].update(stats[cat])
        counts, stats = folded, folded_stats
        cat_order, suffix = fam_order, "_family"
        for row in map_rows:
            row["category"] = fam_of[row["category"]]
    else:
        cat_order = []
        if os.path.isfile(args.categories):
            with open(args.categories, newline="", encoding="utf-8-sig") as f:
                cat_order = [r["slug"].strip() for r in csv.DictReader(f)]

    cats = [c for c in cat_order if c in counts] + sorted(set(counts) - set(cat_order))
    all_counts = Counter()
    for cat in cats:
        all_counts.update(counts[cat])
    macro = macro_profile([counts[c] for c in cats], class_names)

    os.makedirs(args.out_dir, exist_ok=True)

    # ---- long-form distribution CSV
    dist_path = os.path.join(args.out_dir, f"cwe888_distribution{suffix}.csv")
    with open(dist_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["category", "cwe888_class", "n_cwes", "pct"])
        for cat in cats + ["ALL"]:
            c = all_counts if cat == "ALL" else counts[cat]
            total = sum(c.values())
            for cls in class_names:
                if c[cls]:
                    w.writerow([cat, cls, c[cls], round(100 * c[cls] / total, 1)])
        # ALL-MACRO carries no counts — it is a mean of percentages, so n_cwes is blank.
        for cls in class_names:
            if macro[cls]:
                w.writerow(["ALL-MACRO", cls, "", round(macro[cls], 1)])

    # ---- per-attribution audit CSV
    map_path = os.path.join(args.out_dir, f"cwe888_cve_map{suffix}.csv")
    with open(map_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["category", "cve_id", "cwe_id",
                                          "cwe888_classes", "map_depth"])
        w.writeheader()
        w.writerows(map_rows)

    # ---- Table-III-style markdown matrix
    def cell(c, cls):
        total = sum(c.values())
        return f"{c[cls]} ({100 * c[cls] / total:.0f}%)" if c[cls] else ""

    md_path = os.path.join(args.out_dir, f"cwe888_matrix{suffix}.md")
    unit = "folding category" if args.group == "family" else "category"
    L = [f"# CWE-888 primary-class distribution — confirmed-Yes CVEs (by {unit})", ""]
    L.append("Counting matches Table III of the transportation IoT study: unit = CWE "
             "attribution; a CVE with two CWEs counts twice, a CWE mapping to two "
             "primary classes counts in both. `All` sums the category columns "
             "(a CVE confirmed in several categories counts once per category).")
    L.append("")
    L.append("")
    L.append("`All` is a **micro**-average (pooled attributions, so the largest unit "
             "dominates the shape); `All-macro` is a **macro**-average (unweighted mean "
             "of each unit's percentage profile, so every unit with data gets an equal "
             "vote). Read them together — the gap between the two is how concentrated "
             "the corpus is.")
    L.append("")
    header = ["Primary CWE-888 Class"] + cats + ["All", "All-macro"]
    L.append("| " + " | ".join(header) + " |")
    L.append("|" + "---|" * len(header))
    for cls in class_names:
        L.append("| " + " | ".join(
            [cls] + [cell(counts[c], cls) for c in cats] + [cell(all_counts, cls)]
            + [f"{macro[cls]:.0f}%" if macro[cls] else ""]) + " |")
    top6 = ["**Top-6 share**"]
    for c in [counts[c] for c in cats] + [all_counts]:
        total = sum(c.values())
        t6 = sum(n for _, n in c.most_common(6))
        top6.append(f"{t6} ({100 * t6 / total:.0f}%)" if total else "")
    top6.append(f"{sum(sorted(macro.values(), reverse=True)[:6]):.0f}%")
    L.append("| " + " | ".join(top6) + " |")
    L.append("| " + " | ".join(
        ["**Total CWEs**"] + [str(sum(counts[c].values())) for c in cats]
        + [str(sum(all_counts.values())), "—"]) + " |")
    L += ["", "## Coverage", "",
          f"| {unit.title()} | Yes CVEs | with CWE | CWE attributions | unmapped CWEs |",
          "|---|---|---|---|---|"]
    for cat in cats:
        s = stats[cat]
        L.append(f"| {cat} | {s['cves']} | {s['cves_with_cwe']} "
                 f"| {s['attributions']} | {s['unmapped']} |")
    tot = Counter()
    for s in stats.values():
        tot.update(s)
    L.append(f"| **All** | {tot['cves']} | {tot['cves_with_cwe']} "
             f"| {tot['attributions']} | {tot['unmapped']} |")
    if unmapped_cwes:
        L += ["", "Unmapped CWEs (no ancestry into the 888 view): "
              + ", ".join(f"{k} ×{n}" for k, n in unmapped_cwes.most_common())]
    with open(md_path, "w") as f:
        f.write("\n".join(L) + "\n")

    # ---- console summary
    total_all = sum(all_counts.values())
    print(f"\nAll categories — {tot['cves']} Yes CVEs, {total_all} mapped CWE attributions "
          f"({tot['cves_with_cwe']}/{tot['cves']} CVEs have a CWE; "
          f"{tot['unmapped']} attributions unmapped):")
    for cls, n in all_counts.most_common():
        print(f"  {cls:28} {n:5}  ({100 * n / total_all:.0f}%)")
    print(f"\nWrote {os.path.relpath(dist_path, ROOT)}, "
          f"{os.path.relpath(map_path, ROOT)}, {os.path.relpath(md_path, ROOT)}")


if __name__ == "__main__":
    main()
