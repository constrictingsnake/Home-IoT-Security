# NVD Snapshot — `nvd_all.csv`

This directory holds the **fixed, offline NVD dataset** that Stage 1 (keyword search) and
Stage 2 (vendor/brand search) — both `scripts/build_search.py` — run against. Pinning one
snapshot is what makes the two search methods **comparable** (same data, same engine) and the
study **reproducible / citeable** ("dataset as of <date>").

The dataset file itself (`nvd_all.csv`) is **gitignored** (large, reproducible bulk data).
Only this provenance file is tracked.

## How to build the snapshot

Either the API route (this file's generator) or the per-year-feed route — see the header of
`scripts/cve_search.py` (STEP 1-2) for the latter's full detail.

```
set -a && source .env && set +a
python3 scripts/download_nvd.py            # -> data/nvd-snapshot/nvd_all.csv (+ this file)
```

Then run the searches:
```
python3 scripts/build_search.py
```

## Provenance

- **Snapshot date:** 2026-08-05
- **Source:** NVD 2.0 API (`https://services.nvd.nist.gov/rest/json/cves/2.0`), downloaded via `scripts/download_nvd.py` with NVD API key (2000 CVEs/page, 3 threads)
- **Years included:** all CVEs in NVD as of download date
- **Total CVEs:** 373,518
- **Columns:** `cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings, vector_string`
- **Notes:** Count is the number of unique CVE records (the `written` value in `nvd_all.csv.progress.json`), **not** `wc -l nvd_all.csv` — the latter over-counts because CVE descriptions contain embedded newlines, so one CVE can span several physical lines.

_This file is written automatically by `scripts/download_nvd.py` on a clean (no-failed-pages) run — do not hand-edit the Provenance section, it will be overwritten on the next run._
