import pandas as pd
import os

# List of multi-sheet xlsx files to check against
# These are hardcoded for now, but can be changed later
# (kept identical to full_intersect.py so both scripts cover the same workbooks)

MULTI_SHEET_FILES = [
    "CategoryIII_CameraDoorbellDeviceTypes.xlsx",
    "CategoryII_NetworkGatewayDeviceTypes.xlsx",
    "CategoryIV_AccessControlDeviceTypes.xlsx",
    "CategoryIX_IoTDeviceTypes.xlsx",
    "CategoryI_SmartHomeDeviceTypes.xlsx",
    "CategoryVIII_ProtocolDeviceTypes.xlsx",
    "CategoryVII_HubDeviceTypes.xlsx",
    "CategoryVI_ApplianceDeviceTypes.xlsx",
    "CategoryVI_SwitchDeviceTypes.xlsx",
    "CategoryV_SensorDeviceTypes.xlsx"
    # Can add or remove files to check as needed
]

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
# Returns the dataframe (so unmatched rows can be written out) and the
# set of normalized CVE IDs used for comparison
def load_cves(filepath):
    try:
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
        print(f"File read error: {e}")
        exit(1)

# Collects every CVE ID present in a multi-sheet workbook (across all sheets)
def collect_workbook_cves(excel_path):
    if not os.path.isfile(excel_path):
        print(f"Skipping missing file: {excel_path}")
        return set()

    try:
        workbook = pd.ExcelFile(excel_path)
    except Exception as e:
        print(f"Could not open {excel_path}: {e}")
        return set()

    found = set()

    print(f"\nSearching: {excel_path}")

    for sheet_name in workbook.sheet_names:
        try:
            df = pd.read_excel(excel_path, sheet_name=sheet_name)

            if 'CVE' not in df.columns:
                continue

            sheet_cves = set(
                df['CVE']
                .dropna()
                .astype(str)
                .str.strip()
                .str.upper()
            )

            if sheet_cves:
                print(
                    f"  {sheet_name}: {len(sheet_cves)} CVEs"
                )

            found |= sheet_cves

        except Exception as e:
            print(
                f"Error processing "
                f"{excel_path} [{sheet_name}]: {e}"
            )

    return found

# Columns dropped from the output (helper column + reviewer judgment columns,
# spelled both ways across files)
DROP_COLS = [
    '_cve_norm',
    'Lizzie Judgment', 'Lizzie Judgement',
    'Cukier Judgment', 'Cukier Judgement',
]

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

    result = df[df['_cve_norm'].isin(unmatched)].copy()
    result = result.drop(columns=DROP_COLS, errors='ignore')
    result.insert(0, "Difference Type", "vendor_only")

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
    df, cves = load_cves(single_sheet_file)

    keyword_cves = set()
    # build the union of every CVE found across the keyword workbooks
    for excel_file in MULTI_SHEET_FILES:
        keyword_cves |= collect_workbook_cves(excel_file)

    save_results(df, cves, keyword_cves)


if __name__ == "__main__":
    main()
