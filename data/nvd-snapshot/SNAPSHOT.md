# NVD Snapshot

This directory holds the **fixed, offline NVD dataset** that Stage 1 (keyword search,
`scripts/build_keyword_search.py`) and — eventually — the vendor brand search run against.
Pinning one snapshot is what makes the two search methods **comparable** (same data, same
engine) and the study **reproducible / citeable** ("dataset as of <date>").

The dataset file itself (`nvd_all.csv`) is **gitignored** (large, reproducible bulk data).
Only this provenance file is tracked.

## How to build the snapshot (one-time)

See the header of `scripts/cve_search.py` (STEP 1–2) for full detail.

1. **Download** per-year NVD 1.1 feeds for 2002–2026 from
   <https://nvd.nist.gov/feeds/json/cve/1.1/> (`nvdcve-1.1-<year>.json.gz`) and gunzip them.
2. **Convert** each year JSON → CSV:
   ```
   python3 scripts/cve_search.py --convert nvdcve-1.1-<year>.json --csv-out nvd_<year>.csv
   ```
3. **Merge** all years into one deduplicated snapshot here:
   ```
   python3 scripts/cve_search.py --merge nvd_2002.csv ... nvd_2026.csv \
       --merged-out data/nvd-snapshot/nvd_all.csv
   ```

Then run the keyword search:
```
python3 scripts/build_keyword_search.py
```

## Provenance

- **Snapshot date:** 2026-06-25
- **Source:** NVD 2.0 API (`https://services.nvd.nist.gov/rest/json/cves/2.0`), downloaded via `scripts/download_nvd.py` with NVD API key (2000 CVEs/page, 3 threads)
- **Years included:** all CVEs in NVD as of download date (2000–2026)
- **Total CVEs:** 360,981
- **Notes:** Count is the number of unique CVE records (the `written` value in `nvd_all.csv.progress.json`), **not** `wc -l nvd_all.csv` — the latter over-counts (~748k) because CVE descriptions contain embedded newlines, so one CVE can span several physical lines.
