import pandas as pd
import glob
import os

# Keyword search outputs to difference against. Since the overhaul, the keyword search
# is per-category (data/keyword-search/keyword_<cat>.csv, from build_keyword_search.py)
# instead of the legacy grouped Category*.xlsx workbooks (now under _legacy/).
#
# This interactive tool builds the WHOLE-CORPUS union of every per-category keyword file
# (e.g. for unmatched_cves.xlsx). For the per-category difference used by the Stage-4
# pipeline (vendor_<cat> − keyword_<cat>), use build_difference_sets.py instead.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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

# Loading the CVEs from a single-sheet file (.xlsx vendor file OR .csv keyword file).
# Returns the dataframe (so the difference rows can be written out) and the
# set of normalized CVE IDs used for comparison.
def load_cves(filepath):
    try:
        if filepath.lower().endswith(".csv"):
            df = pd.read_csv(filepath)
        else:
            df = pd.read_excel(filepath)

        if 'cve_id' not in df.columns:
            raise ValueError("Column 'cve_id' not found.")

        # Drop rows with no CVE id, then keep a normalized column for matching
        df = df.dropna(subset=['cve_id']).copy()
        df['_cve_norm'] = (
            df['cve_id']
            .astype(str)
            .str.strip()
            .str.upper()
        )

        cves = set(df['_cve_norm'])

        print(f"Loaded {len(cves)} CVEs.\n")
        return df, cves

    except Exception as e:
        # Raise (instead of exit) so batch callers can skip one bad file and continue.
        raise ValueError(f"Could not read CVEs from {filepath}: {e}")

# Collects every CVE ID present in a per-category keyword file (keyword_<cat>.csv).
def collect_keyword_cves(csv_path):
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

# Columns dropped from the output (helper column + reviewer judgment columns,
# spelled both ways across files). `matched_terms` is dropped too: it is search-term
# attribution that must NOT reach the blind reviewers (it would anchor their judgment).
# Attribution stays on the builder outputs (keyword_<cat>.csv / results_all_<cat>.xlsx),
# where term_precision.py re-reads it and joins to the settled judgments by cve_id.
DROP_COLS = [
    '_cve_norm',
    'matched_terms',
    'Lizzie Judgment', 'Lizzie Judgement',
    'Cukier Judgment', 'Cukier Judgement',
]

# Build the difference rows: the CVEs in source_cves that appear in NONE of other_cves,
# pulled from source_df and tagged with `label` (the Difference Type). Direction-agnostic:
#   vendor_only  = difference_rows(vendor_df, vendor_cves, keyword_cves, "vendor_only")
#   keyword_only = difference_rows(keyword_df, keyword_cves, vendor_cves, "keyword_only")
# Reusable by batch callers (build_difference_sets.py) and by save_results below.
def difference_rows(source_df, source_cves, other_cves, label="vendor_only"):
    only = source_cves - other_cves
    result = source_df[source_df['_cve_norm'].isin(only)].copy()
    result = result.drop(columns=DROP_COLS, errors='ignore')
    result.insert(0, "Difference Type", label)
    return result


# Build the intersection rows: the CVEs present in BOTH source_cves and other_cves,
# pulled from source_df and tagged with `label` (the Difference Type = "intersection").
# The intersection (V ∩ K) is disjoint from vendor_only (V − K) and keyword_only (K − V);
# together the three partition V ∪ K exactly, so a CVE never lands in two directions.
# Rows are pulled from source_df (pass the vendor df — its schema matches the keyword df).
# Used by build_intersection_sets.py to route the intersection through the same Stage-4
# review as the difference set (it is NOT assumed clean — see CLAUDE.md Stage 3/4).
def intersection_rows(source_df, source_cves, other_cves, label="intersection"):
    both = source_cves & other_cves
    result = source_df[source_df['_cve_norm'].isin(both)].copy()
    result = result.drop(columns=DROP_COLS, errors='ignore')
    result.insert(0, "Difference Type", label)
    return result


# Compute the difference and prompt the user to save it
# Unmatched = CVEs in the vendor file that appear in NONE of the workbooks
def save_results(df, vendor_cves, keyword_cves):
    unmatched = vendor_cves - keyword_cves

    print(f"\nVendor CVEs:             {len(vendor_cves)}")
    print(f"Keyword CVEs (union):    {len(keyword_cves)}")
    print(f"Unmatched (vendor-only): {len(unmatched)}")

    if not unmatched: # nothing left after removing the intersection
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

    single_sheet_file = get_single_sheet_file() # prompt for user input
    try:
        df, cves = load_cves(single_sheet_file)
    except ValueError as e:
        print(e)
        exit(1)

    files = keyword_files()
    if not files:
        print(f"\nNo keyword files found in {os.path.relpath(KEYWORD_DIR, ROOT)} "
              "(run build_keyword_search.py first).")
        exit(1)

    keyword_cves = set()
    # build the whole-corpus union of every CVE across the per-category keyword files
    print(f"\nBuilding keyword union from {len(files)} keyword file(s):")
    for csv_file in files:
        keyword_cves |= collect_keyword_cves(csv_file)

    save_results(df, cves, keyword_cves)


if __name__ == "__main__":
    main()
