import pandas as pd
import glob
import os

# Keyword search outputs to intersect against. Since the overhaul, the keyword search is
# per-category (data/keyword-search/keyword_<cat>.csv, from build_keyword_search.py) instead
# of the legacy grouped Category*.xlsx workbooks (now under _legacy/).
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

# Loading the CVEs from a single sheet file
def load_cves(filepath):
    try:
        df = pd.read_excel(filepath)

        if 'cve_id' not in df.columns:
            raise ValueError("Column 'cve_id' not found.")

        cves = set(
            df['cve_id']
            .dropna()
            .astype(str)
            .str.strip()
            .str.upper()
        )

        print(f"Loaded {len(cves)} CVEs.\n")
        return cves

    except Exception as e:
        print(f"File read error: {e}")
        exit(1)

# Searches a per-category keyword file (keyword_<cat>.csv) for matching CVEs
def search_file(cves, csv_path):
    if not os.path.isfile(csv_path):
        print(f"Skipping missing file: {csv_path}")
        return []

    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"Could not open {csv_path}: {e}")
        return []

    if 'cve_id' not in df.columns:
        return []

    matches = []
    # category slug = keyword_<slug>.csv -> <slug>
    slug = os.path.basename(csv_path)[len("keyword_"):-len(".csv")]

    df['cve_id'] = (
        df['cve_id']
        .astype(str)
        .str.strip()
        .str.upper()
    )

    matched_rows = df[df['cve_id'].isin(cves)]

    if not matched_rows.empty:
        print(f"\nMatches found in {os.path.basename(csv_path)} ({len(matched_rows)})")

        matched_rows = matched_rows.copy()
        matched_rows.insert(0, "Source File", os.path.basename(csv_path))
        matched_rows.insert(1, "Source Sheet", slug)
        matches.append(matched_rows)

    return matches

# Prompt user to save matches to a file
def save_results(all_matches):
    if not all_matches: # if matches is empty 
        print("\nNo matching CVEs found in any file.")
        return

    combined = pd.concat(all_matches, ignore_index=True)
    print(f"\nTotal matches found: {len(combined)}")

    choice = input(
        "\nSave all matching rows to CSV? (y/n): "
    ).strip().lower()

    if choice == 'y':
        filename = input(
            "Output filename "
            "(default: matched_cves.csv): "
        ).strip()

        if not filename:
            filename = "matched_cves.csv"

        if not filename.lower().endswith(".csv"):
            filename += ".csv"

        combined.to_csv(filename, index=False)
        print(f"Results saved to: {filename}")


def main():
    print("------ CVE Multi-Spreadsheet Intersection ------\n")

    single_sheet_file = get_single_sheet_file() # prompt for user input
    cves = load_cves(single_sheet_file) 

    files = keyword_files()
    if not files:
        print(f"\nNo keyword files found in {os.path.relpath(KEYWORD_DIR, ROOT)} "
              "(run build_keyword_search.py first).")
        return

    all_matches = []
    # compile a list of matched CVEs across every per-category keyword file
    for csv_file in files:
        matches = search_file(cves, csv_file)
        all_matches.extend(matches)

    save_results(all_matches)


if __name__ == "__main__":
    main()