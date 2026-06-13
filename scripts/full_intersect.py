import pandas as pd
import os

# List of multi-sheet xlsx files to search for a match on
# These are hardcoded for now, but can be changed later

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

# Searches file for matching CVEs
def search_file(cves, excel_path):
    if not os.path.isfile(excel_path):
        print(f"Skipping missing file: {excel_path}")
        return []

    try:
        workbook = pd.ExcelFile(excel_path)
    except Exception as e:
        print(f"Could not open {excel_path}: {e}")
        return []

    matches = []

    print(f"\nSearching: {excel_path}")

    for sheet_name in workbook.sheet_names:
        try:
            df = pd.read_excel(excel_path, sheet_name=sheet_name)

            if 'CVE' not in df.columns:
                continue

            df['CVE'] = (
                df['CVE']
                .astype(str)
                .str.strip()
                .str.upper()
            )

            matched_rows = df[df['CVE'].isin(cves)]

            if not matched_rows.empty:
                print(
                    f"\nMatches found in "
                    f"{excel_path} -> Sheet: {sheet_name}"
                )

                for _, row in matched_rows.iterrows():
                    print(row.to_dict())

                matched_rows = matched_rows.copy()
                matched_rows.insert(0, "Source File", excel_path)
                matched_rows.insert(1, "Source Sheet", sheet_name)
                matches.append(matched_rows)

        except Exception as e:
            print(
                f"Error processing "
                f"{excel_path} [{sheet_name}]: {e}"
            )

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

    all_matches = [] 
    # compile a list of matched CVEs
    for excel_file in MULTI_SHEET_FILES:
        matches = search_file(cves, excel_file)
        all_matches.extend(matches)

    save_results(all_matches)


if __name__ == "__main__":
    main()