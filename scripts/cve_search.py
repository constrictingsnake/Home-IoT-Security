#!/usr/bin/env python3
"""
CVE Search — keyword search against a local NVD dataset.
=========================================================================
Searches a local NVD CSV (or JSON) for keywords and outputs a list of
matching CVEs with their description, CVSS score, CWE IDs, and CPE strings.

Also supports one-time JSON → CSV conversion for fast repeated searches.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1 — Download the NVD dataset (one-time setup)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Per-year NVD 1.1 feeds (recommended — manageable file sizes):
  https://nvd.nist.gov/feeds/json/cve/1.1/
  e.g. nvdcve-1.1-2024.json.gz  →  gunzip  →  nvdcve-1.1-2024.json

Full combined NVD 2.0 bulk export:
  https://github.com/fkie-fau/nvd-json-data-feeds/releases
  → CVE-all.json.zip  →  unzip  →  CVE-all.json  (~2 GB, needs lots of RAM)

STEP 2 — Convert JSON → CSV (one-time, do once per year-file)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  python cve_search.py --convert nvdcve-1.1-2024.json --csv-out nvd_2024.csv

STEP 3 — Search
━━━━━━━━━━━━━━━
  python cve_search.py --input nvd_2024.csv --keywords "ecobee" "nest thermostat"

  # Merge multiple year CSVs first (Linux/Mac):
  python cve_search.py --merge nvd_2022.csv nvd_2023.csv nvd_2024.csv \
                       --merged-out nvd_all.csv
  python cve_search.py --input nvd_all.csv --keywords "midea" "sensibo"

Requirements:
  pip install tqdm          (optional, for progress bars)
"""

import argparse
import csv
import json
import os
import re
import sys
import textwrap
from typing import Optional

# Raise CSV field size limit — NVD entries can exceed the default 128 KB cap
csv.field_size_limit(sys.maxsize)

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


# ──────────────────────────────────────────────────────────
# CSV column names
# ──────────────────────────────────────────────────────────
CSV_COLS = [
    "cve_id", "published", "description",
    "cvss_score", "cvss_version",
    "cwe_ids",     # pipe-separated  e.g.  CWE-79|CWE-89
    "cpe_strings", # pipe-separated
]


# ──────────────────────────────────────────────────────────
# NVD JSON parsing
# ──────────────────────────────────────────────────────────

def _en_description(descriptions: list) -> Optional[str]:
    return next((d["value"] for d in descriptions if d.get("lang") == "en"), None)


def _parse_nvd_11(item: dict) -> Optional[dict]:
    cve_node    = item.get("cve", {})
    cve_id      = cve_node.get("CVE_data_meta", {}).get("ID", "")
    published   = item.get("publishedDate", "")[:10]
    descs       = cve_node.get("description", {}).get("description_data", [])
    description = next((d["value"] for d in descs if d.get("lang") == "en"), None)
    if not description:
        return None

    impact = item.get("impact", {})
    cvss_score, cvss_version = None, None
    for key, ver in (("baseMetricV3", "3.x"), ("baseMetricV2", "2.0")):
        node = impact.get(key)
        if node:
            cvss_data    = node.get("cvssV3", node.get("cvssV2", {}))
            cvss_score   = cvss_data.get("baseScore")
            cvss_version = cvss_data.get("version", ver)
            break

    cwe_ids: list[str] = []
    for pd in cve_node.get("problemtype", {}).get("problemtype_data", []):
        for d in pd.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)

    cpe_strings: list[str] = []
    for node in item.get("configurations", {}).get("nodes", []):
        for cpe in node.get("cpe_match", []):
            uri = cpe.get("cpe23Uri", "")
            if uri:
                cpe_strings.append(uri)

    return {
        "cve_id": cve_id, "published": published, "description": description,
        "cvss_score": cvss_score, "cvss_version": cvss_version,
        "cwe_ids": list(dict.fromkeys(cwe_ids)),
        "cpe_strings": list(dict.fromkeys(cpe_strings)),
    }


def _parse_nvd_20(item: dict) -> Optional[dict]:
    cve         = item.get("cve", item)
    cve_id      = cve.get("id", "")
    published   = cve.get("published", "")[:10]
    description = _en_description(cve.get("descriptions", []))
    if not description:
        return None

    metrics = cve.get("metrics", {})
    cvss_score, cvss_version = None, None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            primary      = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            cvss_data    = primary.get("cvssData", {})
            cvss_score   = cvss_data.get("baseScore")
            cvss_version = cvss_data.get("version")
            break

    cwe_ids: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for d in weakness.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)

    cpe_strings: list[str] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for m in node.get("cpeMatch", []):
                uri = m.get("criteria", "")
                if uri:
                    cpe_strings.append(uri)

    return {
        "cve_id": cve_id, "published": published, "description": description,
        "cvss_score": cvss_score, "cvss_version": cvss_version,
        "cwe_ids": list(dict.fromkeys(cwe_ids)),
        "cpe_strings": list(dict.fromkeys(cpe_strings)),
    }


def load_nvd_json(path: str) -> list[dict]:
    print(f"  📂  Loading JSON: {path}  ({os.path.getsize(path) / 1e6:.1f} MB) ...")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if "CVE_Items" in data:
        raw_items, parse_func, fmt = data["CVE_Items"], _parse_nvd_11, "NVD 1.1"
    elif "vulnerabilities" in data:
        raw_items, parse_func, fmt = data["vulnerabilities"], _parse_nvd_20, "NVD 2.0"
    elif isinstance(data, list):
        raw_items, parse_func, fmt = data, _parse_nvd_20, "NVD 2.0 (list)"
    else:
        print("  ❌  Unrecognised JSON structure.")
        sys.exit(1)

    print(f"  ✅  Format: {fmt}  |  {len(raw_items):,} raw entries")
    results: list[dict] = []
    iterator = tqdm(raw_items, desc="  Parsing", unit="CVE") if HAS_TQDM else raw_items
    for item in iterator:
        parsed = parse_func(item)
        if parsed:
            results.append(parsed)

    print(f"  ✅  {len(results):,} CVEs parsed")
    return results


# ──────────────────────────────────────────────────────────
# CSV helpers
# ──────────────────────────────────────────────────────────

def _row_to_cve(row: dict) -> dict:
    score = row.get("cvss_score", "")
    return {
        "cve_id":       row["cve_id"],
        "published":    row.get("published", ""),
        "description":  row["description"],
        "cvss_score":   float(score) if score else None,
        "cvss_version": row.get("cvss_version") or None,
        "cwe_ids":      [x for x in row.get("cwe_ids", "").split("|") if x],
        "cpe_strings":  [x for x in row.get("cpe_strings", "").split("|") if x],
    }


def _cve_to_row(cve: dict) -> dict:
    return {
        "cve_id":       cve["cve_id"],
        "published":    cve["published"],
        "description":  cve["description"],
        "cvss_score":   cve["cvss_score"] if cve["cvss_score"] is not None else "",
        "cvss_version": cve["cvss_version"] or "",
        "cwe_ids":      "|".join(cve["cwe_ids"]),
        "cpe_strings":  "|".join(cve["cpe_strings"]),
    }


def load_csv(path: str) -> list[dict]:
    print(f"  📂  Loading CSV: {path}  ({os.path.getsize(path) / 1e6:.1f} MB) ...")
    results: list[dict] = []
    with open(path, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            results.append(_row_to_cve(row))
    print(f"  ✅  {len(results):,} CVEs loaded")
    return results


def save_as_csv(cves: list[dict], path: str) -> None:
    print(f"\n  💾  Writing {len(cves):,} CVEs → {path} ...")
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLS)
        writer.writeheader()
        for cve in cves:
            writer.writerow(_cve_to_row(cve))
    print(f"  ✅  Done.  Future runs: --input {path}")


def load_dataset(path: str) -> list[dict]:
    return load_csv(path) if path.endswith(".csv") else load_nvd_json(path)


def merge_csvs(paths: list[str], out_path: str) -> None:
    """
    Merge multiple NVD CSVs into one, deduplicating by cve_id.
    Skips duplicate header rows automatically.
    """
    print(f"\n🔗  Merging {len(paths)} CSV files → {out_path} ...")
    seen: set[str] = set()
    total = 0
    with open(out_path, "w", newline="", encoding="utf-8") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=CSV_COLS)
        writer.writeheader()
        for path in paths:
            count = 0
            print(f"  ← {path}")
            with open(path, "r", encoding="utf-8") as f_in:
                for row in csv.DictReader(f_in):
                    cve_id = row.get("cve_id", "")
                    if cve_id and cve_id not in seen:
                        writer.writerow({col: row.get(col, "") for col in CSV_COLS})
                        seen.add(cve_id)
                        count += 1
                        total += 1
            print(f"     {count:,} unique CVEs added")
    print(f"  ✅  {total:,} total unique CVEs written to {out_path}")


# ──────────────────────────────────────────────────────────
# Keyword filtering
# ──────────────────────────────────────────────────────────

def filter_by_keywords(
    cves: list[dict],
    keywords: list[str],
    case_sensitive: bool = False,
    whole_word: bool = False,
) -> tuple[list[dict], dict[str, int]]:
    """Match `keywords` against each CVE's description + CPE strings.

    Two matching modes:
      - substring (default): `kw in haystack`. Fast, but a short token can match
        INSIDE an unrelated word (e.g. "nvr" → "nvram", "trv" → "iccattrval",
        "landroid" → "...bailandroid"), inflating a category with junk.
      - whole_word=True: the token must start on an alphanumeric boundary and end on
        one too, except a trailing plural suffix ("s"/"es") is allowed. So "nvr"
        matches "nvr"/"nvrs" but NOT "nvram"; "ip camera" matches "ip camera" and the
        plural "ip cameras" but not "...equipcamerax". Blocks the substring bombs
        ("nvr"→"nvram", "trv"→"iccattrval", "evse"→"prevsell", "landroid"→"bailandroid")
        while preserving plurals. This is what the per-category keyword/vendor builders
        use, since both rely on short device/brand tokens. Non-alphanumeric chars
        (":" "_" "-" in CPE) act as boundaries, so CPE matching is unaffected.
    """
    matches: list[dict] = []
    seen: set[str] = set()
    counts: dict[str, int] = {kw: 0 for kw in keywords}

    if whole_word:
        flags = 0 if case_sensitive else re.IGNORECASE
        # Precompile once; \b is unreliable next to ":" "_" so use explicit
        # alphanumeric-boundary look-arounds (with IGNORECASE the class covers A-Z).
        matchers = [
            (kw, re.compile(r"(?<![a-z0-9])" + re.escape(kw) + r"(?:es|s)?(?![a-z0-9])", flags))
            for kw in keywords
        ]
        for cve in cves:
            haystack = cve["description"] + " " + " ".join(cve["cpe_strings"])
            for orig_kw, pat in matchers:
                if pat.search(haystack):
                    counts[orig_kw] += 1
                    if cve["cve_id"] not in seen:
                        matches.append(cve)
                        seen.add(cve["cve_id"])
        return matches, counts

    search_keywords = keywords if case_sensitive else [kw.lower() for kw in keywords]
    for cve in cves:
        haystack = cve["description"] + " " + " ".join(cve["cpe_strings"])
        if not case_sensitive:
            haystack = haystack.lower()
        for orig_kw, search_kw in zip(keywords, search_keywords):
            if search_kw in haystack:
                counts[orig_kw] += 1
                if cve["cve_id"] not in seen:
                    matches.append(cve)
                    seen.add(cve["cve_id"])

    return matches, counts


# ──────────────────────────────────────────────────────────
# Output
# ──────────────────────────────────────────────────────────

def print_keyword_breakdown(counts: dict[str, int], total: int) -> None:
    print()
    print("  ┌─────────────────────────────────────────────────────┐")
    print("  │            KEYWORD MATCH BREAKDOWN                  │")
    print("  ├─────────────────────────────────────────────────────┤")
    col = max((len(kw) for kw in counts), default=10)
    col = max(col, 30)
    max_count = max(counts.values()) if counts else 1
    for kw, count in counts.items():
        bar = "█" * int((count / max(max_count, 1)) * 20)
        print(f"  │  {kw:<{col}}  {count:>6,} CVEs  {bar}")
    print("  ├─────────────────────────────────────────────────────┤")
    print(f"  │  {'TOTAL (deduplicated)':<{col}}  {total:>6,} CVEs")
    print("  └─────────────────────────────────────────────────────┘")
    print()


def print_cve_list(cves: list[dict], max_display: int = 50) -> None:
    """Print a human-readable summary of matched CVEs to the terminal."""
    display = cves[:max_display]
    print(f"\n{'─' * 72}")
    print(f"  MATCHED CVEs  (showing {len(display)} of {len(cves):,})")
    print(f"{'─' * 72}\n")

    for cve in display:
        score_str = f"CVSS {cve['cvss_score']} (v{cve['cvss_version']})" \
                    if cve["cvss_score"] else "no CVSS score"
        cwe_str   = ", ".join(cve["cwe_ids"][:4]) if cve["cwe_ids"] else "—"
        cpe_str   = cve["cpe_strings"][0] if cve["cpe_strings"] else "—"

        print(f"  {cve['cve_id']}   {score_str}   pub: {cve['published']}")
        print(f"  CWE : {cwe_str}")
        print(f"  CPE : {cpe_str}")
        if len(cve["cpe_strings"]) > 1:
            print(f"        (+{len(cve['cpe_strings']) - 1} more CPE strings)")
        # Wrap description to 68 chars
        wrapped = textwrap.fill(cve["description"], width=68,
                                initial_indent="  Desc: ",
                                subsequent_indent="        ")
        print(wrapped)
        print()

    if len(cves) > max_display:
        print(f"  ... and {len(cves) - max_display:,} more — see output files for full list.\n")


def save_results_csv(cves: list[dict], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLS)
        writer.writeheader()
        for cve in cves:
            writer.writerow(_cve_to_row(cve))
    print(f"  💾  CSV  → {path}")


def save_results_json(cves: list[dict], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cves, f, indent=2)
    print(f"  💾  JSON → {path}")


# ──────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Search a local NVD dataset by keyword. No AI required.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            ─────────────────────────────────────────────────────────────
            EXAMPLES
            ─────────────────────────────────────────────────────────────
            # Convert a year's JSON feed to CSV (one-time):
            python cve_search.py --convert nvdcve-1.1-2024.json --csv-out nvd_2024.csv

            # Merge multiple year CSVs into one (handles duplicate headers):
            python cve_search.py --merge nvd_2022.csv nvd_2023.csv nvd_2024.csv \\
                                 --merged-out nvd_all.csv

            # Search a single year:
            python cve_search.py --input nvd_2024.csv \\
                                 --keywords "ecobee" "nest thermostat" "midea"

            # Search merged file, show all results in terminal, save both formats:
            python cve_search.py --input nvd_all.csv \\
                                 --keywords "sensibo" "tado" "cielo breez" \\
                                 --output results.csv --output-json results.json \\
                                 --show-all

            # Case-sensitive search, sort by CVSS score descending:
            python cve_search.py --input nvd_all.csv \\
                                 --keywords "SmartLife" "TuyaSmart" \\
                                 --case-sensitive --sort-by cvss
            ─────────────────────────────────────────────────────────────
        """),
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--convert", metavar="NVD_JSON",
                      help="Convert NVD JSON → flat CSV (no search performed).")
    mode.add_argument("--merge", nargs="+", metavar="CSV",
                      help="Merge multiple NVD CSVs into one deduplicated file.")
    mode.add_argument("--input", metavar="FILE",
                      help="Local .csv or .json dataset to search.")

    # Convert options
    parser.add_argument("--csv-out", default="nvd_flat.csv", metavar="FILE",
                        help="Output path for --convert (default: nvd_flat.csv).")

    # Merge options
    parser.add_argument("--merged-out", default="nvd_merged.csv", metavar="FILE",
                        help="Output path for --merge (default: nvd_merged.csv).")

    # Search options
    parser.add_argument("--keywords", nargs="+", metavar="KW",
                        help="Keywords to search (required for --input mode).")
    parser.add_argument("--case-sensitive", action="store_true",
                        help="Case-sensitive keyword matching (default: case-insensitive).")
    parser.add_argument("--sort-by",
                        choices=["cvss", "date", "cve_id"],
                        default="date",
                        help="Sort results by: cvss (desc), date (desc), or cve_id (default: date).")
    parser.add_argument("--min-cvss", type=float, default=None, metavar="SCORE",
                        help="Only include CVEs with CVSS score ≥ this value.")
    parser.add_argument("--max-results", type=int, default=None, metavar="N",
                        help="Cap total results returned.")

    # Output options
    parser.add_argument("--output", default="cve_search_results.csv", metavar="FILE",
                        help="Output CSV file (default: cve_search_results.csv).")
    parser.add_argument("--output-json", default=None, metavar="FILE",
                        help="Also save results as JSON (optional).")
    parser.add_argument("--show-all", action="store_true",
                        help="Print all matched CVEs to terminal (default: first 50).")
    parser.add_argument("--no-preview", action="store_true",
                        help="Skip terminal preview entirely, just save files.")

    args = parser.parse_args()

    # ── CONVERT mode ─────────────────────────────────────
    if args.convert:
        print(f"\n🔄  Convert: {args.convert} → {args.csv_out}\n")
        cves = load_nvd_json(args.convert)
        save_as_csv(cves, args.csv_out)
        print("\n✨  Done!\n")
        return

    # ── MERGE mode ───────────────────────────────────────
    if args.merge:
        merge_csvs(args.merge, args.merged_out)
        print("\n✨  Done!\n")
        return

    # ── SEARCH mode ──────────────────────────────────────
    if not args.keywords:
        parser.error("--keywords is required with --input")

    # 1. Load
    print(f"\n📦  Loading dataset ...")
    all_cves = load_dataset(args.input)

    # 2. Filter by keywords
    print(f"\n🔍  Searching for: {args.keywords} ...")
    matched, kw_counts = filter_by_keywords(all_cves, args.keywords, args.case_sensitive)
    print_keyword_breakdown(kw_counts, len(matched))

    if not matched:
        print("  ℹ️   No CVEs matched. Try broader or different keywords.\n")
        sys.exit(0)

    # 3. Optional CVSS filter
    if args.min_cvss is not None:
        before  = len(matched)
        matched = [c for c in matched if c["cvss_score"] is not None
                   and c["cvss_score"] >= args.min_cvss]
        print(f"  🔽  CVSS filter (≥ {args.min_cvss}): {len(matched):,} kept from {before:,}")

    # 4. Sort
    if args.sort_by == "cvss":
        matched.sort(key=lambda c: c["cvss_score"] or 0.0, reverse=True)
    elif args.sort_by == "date":
        matched.sort(key=lambda c: c["published"], reverse=True)
    elif args.sort_by == "cve_id":
        matched.sort(key=lambda c: c["cve_id"])

    # 5. Cap
    if args.max_results and len(matched) > args.max_results:
        print(f"  ✂️   Capping at {args.max_results:,} results (--max-results).")
        matched = matched[: args.max_results]

    # 6. Terminal preview
    if not args.no_preview:
        limit = len(matched) if args.show_all else 50
        print_cve_list(matched, max_display=limit)

    # 7. Save
    print(f"  Saving {len(matched):,} results ...")
    save_results_csv(matched, args.output)
    if args.output_json:
        save_results_json(matched, args.output_json)

    print(f"\n✨  Done!  {len(matched):,} CVEs saved.\n")


if __name__ == "__main__":
    main()