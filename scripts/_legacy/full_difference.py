"""RETIRED — interactive whole-corpus vendor-vs-keyword difference tool.

Superseded by `build_review_sets.py --direction vendor_only` (per-category, batch,
non-interactive, and the actual Stage-4 input). Kept for reference only; the shared
helpers it used to define (load_cves, difference_rows, RAW_COLS, write_raw, ...) now
live in scripts/review_lib.py, which this file still imports so it remains runnable
if dug back up.

This interactive tool built the WHOLE-CORPUS union of every per-category keyword file
(e.g. for unmatched_cves.xlsx) and diffed one vendor file against it.

Usage (if resurrected):
    python _legacy/full_difference.py
"""
import os
import sys
import glob

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from review_lib import load_cves, difference_rows  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KEYWORD_DIR = os.path.join(ROOT, "data", "keyword-search")


def keyword_files():
    """Every per-category keyword search output (absolute paths)."""
    return sorted(glob.glob(os.path.join(KEYWORD_DIR, "keyword_*.csv")))


# Prompt for file path, assumes file is in the cwd, checks if .xlsx
def get_single_sheet_file():
    while True:
        filepath = input(
            "Enter path to the single-sheet Excel file: "
        ).strip().strip('"')

        if not os.path.isfile(filepath):
            print("File not found. Please try again.\n")
            continue

        if not filepath.lower().endswith((".xlsx", ".xls")):
            print("Please provide a valid Excel file.\n")
            continue

        return filepath


# Collects every CVE ID present in a per-category keyword file (keyword_<cat>.csv).
def collect_keyword_cves(csv_path):
    import pandas as pd

    if not os.path.isfile(csv_path):
        print(f"Skipping missing file: {csv_path}")
        return set()

    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"Could not open {csv_path}: {e}")
        return set()

    if 'cve_id' not in df.columns:
        print(f"  {os.path.basename(csv_path)}: no 'cve_id' column — skipped")
        return set()

    found = set(
        df['cve_id']
        .dropna()
        .astype(str)
        .str.strip()
        .str.upper()
    )
    print(f"  {os.path.basename(csv_path)}: {len(found)} CVEs")
    return found


# Compute the difference and prompt the user to save it
# Unmatched = CVEs in the vendor file that appear in NONE of the workbooks
def save_results(df, vendor_cves, keyword_cves):
    unmatched = vendor_cves - keyword_cves

    print(f"\nVendor CVEs:             {len(vendor_cves)}")
    print(f"Keyword CVEs (union):    {len(keyword_cves)}")
    print(f"Unmatched (vendor-only): {len(unmatched)}")

    if not unmatched:  # nothing left after removing the intersection
        print(
            "\nNo unmatched CVEs found "
            "— every vendor CVE appears in a keyword workbook."
        )
        return

    result = difference_rows(df, vendor_cves, keyword_cves)

    choice = input(
        "\nSave all unmatched rows to CSV? (y/n): "
    ).strip().lower()

    if choice == 'y':
        filename = input(
            "Output filename "
            "(default: unmatched_cves.csv): "
        ).strip()

        if not filename:
            filename = "unmatched_cves.csv"

        if not filename.lower().endswith(".csv"):
            filename += ".csv"

        result.to_csv(filename, index=False)
        print(f"Results saved to: {filename}")


def main():
    print("------ CVE Multi-Spreadsheet Difference ------\n")

    single_sheet_file = get_single_sheet_file()  # prompt for user input
    try:
        df, cves = load_cves(single_sheet_file)
    except ValueError as e:
        print(e)
        exit(1)

    files = keyword_files()
    if not files:
        print(f"\nNo keyword files found in {os.path.relpath(KEYWORD_DIR, ROOT)} "
              "(run build_search.py --method keyword first).")
        exit(1)

    keyword_cves = set()
    # build the whole-corpus union of every CVE across the per-category keyword files
    print(f"\nBuilding keyword union from {len(files)} keyword file(s):")
    for csv_file in files:
        keyword_cves |= collect_keyword_cves(csv_file)

    save_results(df, cves, keyword_cves)


if __name__ == "__main__":
    main()
