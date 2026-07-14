"""Shared Stage-3/4 review-set helpers: load CVEs from a per-category file, compute
difference/intersection rows, and write them in the canonical RAW_COLS schema.

Extracted from the former full_difference.py (now scripts/_legacy/full_difference.py,
the retired interactive whole-corpus CLI) so the still-live batch drivers
(build_review_sets.py, cpe_expansion.py) don't depend on a retired script.
"""
import csv
import os

import pandas as pd

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


# Columns dropped from the output (helper column + reviewer judgment columns,
# spelled both ways across files). `matched_terms` is dropped too: it is search-term
# attribution that must NOT reach the blind reviewers (it would anchor their judgment).
# Attribution stays on the builder outputs (keyword_<cat>.csv / results_all_<cat>.csv),
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
# Reusable by batch callers (build_review_sets.py) and by save_results below.
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
# Used by build_review_sets.py to route the intersection through the same Stage-4
# review as the difference set (it is NOT assumed clean — see CLAUDE.md Stage 3/4).
def intersection_rows(source_df, source_cves, other_cves, label="intersection"):
    both = source_cves & other_cves
    result = source_df[source_df['_cve_norm'].isin(both)].copy()
    result = result.drop(columns=DROP_COLS, errors='ignore')
    result.insert(0, "Difference Type", label)
    return result


# Canonical Stage-4 review-set schema. Every direction's 01_raw.csv uses these 8 columns
# in this order — difference_rows/intersection_rows produce exactly this (after DROP_COLS),
# and cpe_expansion.py emits the same via write_raw so all directions stay comparable.
RAW_COLS = ["Difference Type", "cve_id", "published", "description",
            "cvss_score", "cvss_version", "cwe_ids", "cpe_strings"]


def write_raw(records, out_path):
    """Write review-set rows to a Stage-4 01_raw.csv in the canonical RAW_COLS schema.

    `records` is any iterable of dicts keyed by (a superset of) RAW_COLS — extra keys are
    ignored, missing keys blank. Callers with a DataFrame from difference_rows /
    intersection_rows should pass `df.reindex(columns=RAW_COLS).fillna("").to_dict("records")`;
    cpe_expansion passes plain string dicts. Creates the parent dir; always overwrites."""
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=RAW_COLS, extrasaction="ignore")
        w.writeheader()
        for r in records:
            w.writerow({c: r.get(c, "") for c in RAW_COLS})
