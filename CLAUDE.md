# Home IoT Security — Project Guide

## What This Project Is

A security research pipeline that systematically maps real-world home IoT device brands to known CVEs from NIST's National Vulnerability Database (NVD), organized by device category. The goal is to build a comprehensive dataset of vulnerability exposure across 15 consumer IoT device types, with manual review to eliminate false positives.

---

## Three-Stage Pipeline

### Stage 1 — `nvd_keyword_query.py` (Live API queries)
- Hits the **NVD REST API v2.0** (`services.nvd.nist.gov`)
- Takes comma-separated keywords interactively, shows CVE counts, fetches full detail for approved keywords
- Enriches each CVE with: CVSS score + severity, CWE ID, description
- Outputs a multi-sheet `.xlsx` — one tab per keyword
- Requires an NVD API key (currently blank in the file — fill in `API_KEY`)
- Rate-limited at 0.6s between requests

### Stage 2 — `cve_search.py` (Offline bulk search)
- Designed for local NVD JSON year-feeds (2002–2026)
- Three modes: `--convert` (JSON→CSV), `--merge` (deduplicate multiple CSVs), `--input` (keyword search)
- Searches both description text and CPE strings
- Supports NVD 1.1 and NVD 2.0 JSON formats
- Output columns: `cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings`
- `run_all_years.sh` automates Stage 2 across all years, then merges into a single CSV

### Stage 3 — `full_intersect.py` (Cross-file matching)
- Takes a single-sheet Excel of CVE IDs (from Stage 2 output) and cross-references against all 10 NVD Keyword Query workbooks
- Finds CVEs that appear in both the device-specific result set and a generic category query
- Adds `Source File` and `Source Sheet` columns to matched rows
- Saves output to CSV interactively

---

## File Structure

```
Home IoT Security/
├── cve_search.py                    # Stage 2 — offline bulk NVD searcher
├── nvd_keyword_query.py             # Stage 1 — live NVD API querier
├── full_intersect.py                # Stage 3 — CVE cross-file matcher
├── run_all_years.sh                 # Automates Stage 2 across 2002–2026
├── Devices List.docx                # Master keyword reference: categories, source URLs,
│                                    # and exact --keywords strings per device type
│
├── NVD Keyword Queries/             # Stage 1 outputs — 10 multi-sheet workbooks
│   ├── CategoryI_SmartHomeDeviceTypes.xlsx       (smart home, smart speaker, smart TV...)
│   ├── CategoryII_NetworkGatewayDeviceTypes.xlsx (routers, modems, NVR, mesh wifi...)
│   ├── CategoryIII_CameraDoorbellDeviceTypes.xlsx (IP cam, baby monitor, doorbell...)
│   ├── CategoryIV_AccessControlDeviceTypes.xlsx  (smart lock, garage door...)
│   ├── CategoryV_SensorDeviceTypes.xlsx          (motion, CO, flood, thermostat...)
│   ├── CategoryVI_ApplianceDeviceTypes.xlsx      (fridge, robot vacuum, smart AC...)
│   ├── CategoryVI_SwitchDeviceTypes.xlsx         (smart plug, bulb, switch...)
│   ├── CategoryVII_HubDeviceTypes.xlsx           (smart hub, zigbee hub, matter hub...)
│   ├── CategoryVIII_ProtocolDeviceTypes.xlsx     (zigbee, z-wave, MQTT, CoAP...)
│   └── CategoryIX_IoTDeviceTypes.xlsx            (brand names: Ring, Arlo, Hikvision, Tuya...)
│
├── results_all_<device>.xlsx        # Stage 2 outputs — one per device type (15 files)
│   ├── results_all_cameras.xlsx          (~2,161 CVEs — largest)
│   ├── results_all_airconditioner.xlsx   (~187 CVEs)
│   ├── results_all_gameconsoles.xlsx     (~246 CVEs)
│   ├── results_all_streaming_tvs.xlsx    (~232 CVEs)
│   ├── results_all_thermostat.xlsx       (~61 CVEs)
│   ├── results_all_robotvacuum.xlsx      (~80 CVEs)
│   ├── results_all_smartplugs.xlsx       (~99 CVEs)
│   ├── results_all_alarms.xlsx           (~117 CVEs)
│   ├── results_all_doorbell.xlsx         (~60 CVEs)
│   ├── results_all_babymonitor.xlsx      (~74 CVEs)
│   ├── results_all_doorlock.xlsx         (~18 CVEs)
│   ├── results_all_fridge.xlsx           (~3 CVEs)
│   ├── results_all_fans.xlsx             (~1 CVE)
│   ├── results_all_smartspeakers.xlsx    (~33 CVEs)
│   └── results_all_sleeptracker.xlsx     (~27 CVEs)
│
├── Matched CVEs/                    # Stage 3 outputs — intersection results per device
│   ├── matched_camera_cves.csv           (~1,048 rows — largest)
│   ├── matched_alarms_cves.csv           (~175 rows)
│   ├── matched_smartplug_cves.csv        (~88 rows)
│   └── matched_<device>_cves.csv         (10 more device types)
│
└── unmatched_cves.xlsx              # CVEs in Stage 2 results NOT matched in any
                                     # category workbook (64,327 rows total)
```

---

## Data Schemas

| File type | Columns |
|-----------|---------|
| `NVD Keyword Queries/*.xlsx` | CVE, CVSS, CVSS Severity, CWE, CWE Name, Description |
| `results_all_*.xlsx` | cve_id, published, description, cvss_score, cvss_version, cwe_ids (pipe-sep), cpe_strings (pipe-sep), Lizzie Judgment/Judgement, Cukier Judgment |
| `Matched CVEs/*.csv` | Source File, Source Sheet, CVE, CVSS, CVSS Severity, CWE, CWE Name, Description |
| `unmatched_cves.xlsx` | Difference Type, Origin File, cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings, Lizzie Judgment, Cukier Judgment, Lizzie Judgement |

**Note:** There is a spelling inconsistency — some files use `Lizzie Judgment`, others use `Lizzie Judgement`. Treat them as the same column.

---

## Definition of a Home IoT Device

A Home IoT device is an embedded computing system, typically resource-constrained in aspects like processing power, memory, and storage, that has 3 key aspects:

1. Designed for permanent (or semi-permanent) deployment within a private residential network **without dedicated security oversight**
2. Communicates through one or more standard internet protocols (TCP/IP, MQTT, CoAP, Zigbee)
3. Exposes a hardware or software attack surface identifiable by a Common Platform Enumeration (CPE) string in the NIST National Vulnerability Database. As such, its firmware or software is subject to CVE disclosure when vulnerabilities are discovered

---

## Manual Review — False Positive Classification

### What the judgment columns are
`Lizzie Judgment` and `Cukier Judgment` are independent manual review columns where two researchers determine whether each CVE is a true match for the device category or a false positive from the keyword search.

**Values:**
- `Yes` — true match, CVE genuinely affects this device type
- `No` — false positive, keyword matched but CVE is unrelated
- `Maybe` — ambiguous, needs further discussion

### Guidance for AI-assisted classification (Claude Judgment column)

#### Column schema
Each `results_all_*.xlsx` file gets three columns added:

| Column | Values | When to populate |
|--------|--------|-----------------|
| `Claude Judgment` | Yes / No / Maybe | Always |
| `Claude Confidence` | High / Low | Always |
| `Claude Judgment Reasoning` | Short explanation | Low confidence and Maybe rows only |

#### Judgment values
- `Yes` — CVE genuinely affects a home IoT device of this category
- `No` — false positive, keyword matched but CVE is unrelated
- `Maybe` — ambiguous, needs human review. Always paired with Low confidence.

#### Confidence values
- `High` — classification is clear from the description and/or CPE strings. Reasoning column left empty.
- `Low` — some uncertainty exists. Reasoning column must be populated.

Use `Low` confidence when:
- The device could theoretically appear in a home but is primarily a commercial/industrial product
- The description mentions the device category but CPE strings point to enterprise hardware
- The CVE affects a software platform or protocol layer shared between home and non-home contexts
- No CPE string is available on a borderline row

#### Reasoning must be self-contained
Reasoning should explain the classification based solely on the description and CPE strings. Never reference other reviewers' judgments (e.g. "Lizzie marked this Maybe") — the reasoning must stand on its own and work consistently across all files, including those with no prior human review.

#### Maybe is always Low confidence
`Maybe` means the device is genuinely ambiguous. There is no `Maybe (High)` — if you are confident something is ambiguous, it is still `Low` confidence because the classification itself is unresolved.

#### A Maybe or Low confidence No is more useful than a confident wrong answer
Reviewers only check rows with reasoning populated. A High confidence mistake will never be caught. When in doubt, use Low confidence.

### CPE absence does not automatically mean Maybe
A missing CPE string should not downgrade a classification to `Maybe` if the description is unambiguous. CPE data on recent CVEs (especially 2024–2026) is frequently absent due to NIST data lag. If the description explicitly names a home device and describes a residential attack vector (e.g. "accessible via LAN or home router port forwarding"), treat the spirit of criterion 3 as satisfied and classify based on the content.

**Example:** CVE-2025-6260 has no CPE string but its description reads *"the embedded web server on the thermostat... allows unauthenticated attackers, either on the local area network or from the Internet via a router with port forwarding"* — this is unambiguously a home thermostat and should be classified `Yes (High)`.

### Why false positives exist
The keyword search is purely text-based, so generic brand names and terms produce noise. For example:
- Keyword `"cerberus"` (Siemens Cerberus thermostat) also matches Cerberus FTP Server CVEs
- Keyword `"honeywell"` matches industrial controls, security panels, non-IoT products
- Keyword `"smart home"` appears in marketing copy for unrelated software

The thermostat file (the only fully reviewed file) shows a ~65% false positive rate: 14 Yes / 7 Maybe / 40 No out of 61 rows.

### Review decision rule
For each row, read the `description` and `cpe_strings` and ask:
> "Does this CVE describe a vulnerability in a device that a typical home user would have in their home for this category?"

### Current review status

| File | Rows | Lizzie | Cukier |
|------|------|--------|--------|
| `results_all_thermostat.xlsx` | 61 | **Complete** (14 Yes / 7 Maybe / 40 No) | 1/61 |
| `results_all_airconditioner.xlsx` | 187 | 1/187 | 1/187 |
| `results_all_cameras.xlsx` | 2,161 | 1/2161 | 1/2161 |
| All other 12 `results_all_*.xlsx` | varies | No judgment columns yet | — |
| `unmatched_cves.xlsx` | 64,327 | ~47/64327 | 3/64327 |

**Next task:** Eliminate false positives across all `results_all_*.xlsx` files by filling in the judgment columns. Files missing the columns need them added first.

---

## Environment

- Python 3.14 (at `/Library/Frameworks/Python.framework/Versions/3.14/bin/python3`)
- Dependencies installed: `pandas`, `openpyxl`, `numpy`, `requests`
- `tqdm` optional (for progress bars in `cve_search.py`)
- NVD API key required for `nvd_keyword_query.py` — get one at https://nvd.nist.gov/developers/request-an-api-key

## Preferred file formats (for importing from Google Docs/Sheets)
- Google Docs → `.txt` (plain text, directly readable)
- Google Sheets (single sheet) → `.csv`
- Google Sheets (multi-sheet) → `.xlsx` (pandas + openpyxl required, now installed)
