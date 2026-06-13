# Home IoT Security — Project Guide

## What This Project Is

A security research pipeline that systematically maps real-world home IoT device brands to known CVEs from NIST's National Vulnerability Database (NVD), organized by device category. The goal is to build a comprehensive dataset of vulnerability exposure across 13 in-scope consumer IoT device types (see *Definition of a Home IoT Device* for the scoping criteria; game consoles and streaming TVs were excluded as entertainment devices), with manual review to eliminate false positives.

---

## Three-Stage Pipeline

### Two search methods (researcher attribution)
The project combines two complementary CVE-discovery methods, each owned by a different researcher:

- **Vendor-based search — Jason.** Compiles a list of manufacturers/brands per device type, then searches NVD for those vendor/brand names. Produces the `results_all_*.xlsx` files (Stage 2, via `cve_search.py` / `run_all_years.sh`; the `--keywords` in `Devices List.docx` are Jason's vendor/brand strings). More prone to false positives, since brand names overlap with unrelated products.
- **Keyword-based search — Lizzie.** Searches NVD for generic device-type keywords (e.g. "security camera", "ip camera"). Produces the `data/keyword-search/*.xlsx` workbooks (Stage 1, via `nvd_keyword_query.py`). `full_intersect.py` (Stage 3) is also Lizzie's — it intersects the two methods' outputs.

Combining both methods yields the most comprehensive per-device CVE list.

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
- Takes a single-sheet Excel of CVE IDs (from Stage 2 output) and cross-references against all 10 keyword-search workbooks (`data/keyword-search/`)
- Finds CVEs that appear in both the device-specific result set and a generic category query
- Adds `Source File` and `Source Sheet` columns to matched rows
- Saves output to CSV interactively

**Companion script — `full_difference.py`** (the complement of `full_intersect.py`):
- Same inputs and workbook list as `full_intersect.py`
- Outputs the vendor CVEs that appear in **none** of the keyword workbooks (i.e. `vendor − keyword_union`) — the set difference behind `unmatched_cves.xlsx`
- Adds a `Difference Type` (= `vendor_only`) column and drops reviewer judgment columns; default output `unmatched_cves.csv`
- Prints vendor / keyword-union / unmatched counts so the set math is visible
- Note: like `full_intersect.py`, the workbook filenames are bare, so run it from inside `data/keyword-search/` (passing the vendor file via a relative path), or with the workbooks in the cwd

### Stage 4 — Triple-AI review of the difference set (per device category)

The difference set (a category's `vendor − keyword_union`) is the list of vendor CVEs the
keyword search **missed**. Classifying which are true matches both (a) cleans the dataset and
(b) surfaces keywords the keyword search is missing — mining the true-positive descriptions
feeds new terms back into the keyword list to raise recall. To keep this trustworthy, every
row is judged **independently by three AI reviewers**, mirroring the two-human reviewer model:

| Reviewer | Columns it owns | How it runs |
|----------|-----------------|-------------|
| **Claude Code** | `Claude Judgment / Confidence / Reasoning` | manual (in-session) |
| **ChatGPT Codex** | `Codex Judgment / Confidence / Reasoning` | manual (run by a person) |
| **Gemini** | `Gemini Judgment / Confidence / Reasoning` | automated via `gemini_classify.py` |

**Blind judgment is a hard rule.** No reviewer may see or be influenced by another reviewer's
answer. This is guaranteed structurally: each reviewer works on its **own copy** that contains
only the raw data + its own empty columns, so other AIs' judgments are physically absent from
the file it reads. All three judge by the same rubric: `data/difference/CLASSIFICATION_PROMPT.md`.

**Per-category workflow** (run from the repo root; `<device>` e.g. `cameras`):
0. (Optional, batch) `python scripts/init_categories.py categories.txt` — scaffold `data/difference/<device>/reviews/` for every category in a newline-separated list. Idempotent: existing folders are left untouched, only missing ones are created.
1. Generate the raw difference set(s) as `data/difference/<device>/01_raw.csv`:
   - **Batch (all categories):** `python scripts/build_difference_sets.py data/device_lst.txt` — maps each list entry to `data/vendor-search/results_all_<device>.xlsx`, builds the keyword union once, and writes every category's `01_raw.csv`. Skips categories that already have one (use `--overwrite` to regenerate).
   - **Single, interactive:** `python scripts/full_difference.py` (run from `data/keyword-search/`; see Stage 3 note), then save to the category's `01_raw.csv`.
2. `python scripts/make_review_copies.py data/difference/<device>/01_raw.csv` → writes blind `reviews/{claude,codex,gemini}.csv`.
3. The two **manual** reviewers each fill **only their own** copy, following the rubric:
   - Claude Code edits `reviews/claude.csv`
   - Codex edits `reviews/codex.csv`
4. Run the **Gemini reviewer + merge in one command**:
   `GEMINI_API_KEY=… python scripts/merge_judgments.py --reviews data/difference/<device>/reviews --run-gemini --category "<keyword>"`
   → fills `reviews/gemini.csv` (resumable; skips already-filled rows), then writes `02_merged.csv` with all 9 AI columns plus the flag.
   - Plain `python scripts/merge_judgments.py --reviews data/difference/<device>/reviews` (no `--run-gemini`) just re-merges — a quick status view, no API/`requests` needed.
   - Standalone `python scripts/gemini_classify.py reviews/gemini.csv --category "<keyword>"` still works if you want the Gemini pass without merging.
5. Mine the unanimous-`Yes` rows for missing keywords → `03_keyword_additions.md`.

**Human-review flag** (set in `merge_judgments.py`): `Needs Human Review = Yes` when **both strong
reviewers (Claude & Codex) are Low confidence OR the 3 judgments are not unanimous**. Gemini is a
weaker third model, so its self-reported confidence is **recorded but excluded** from the flag (it
skews Low and would inflate the queue); Gemini's *judgment* still counts toward unanimity. Rows
where any AI hasn't reviewed yet are `Review Status = incomplete` (pending, unflagged). Humans only
adjudicate flagged rows.

---

## File Structure

```
Home IoT Security/
├── CLAUDE.md                        # This project guide
├── AGENTS.md                        # Codex reviewer instructions (auto-loaded by Codex)
├── Devices List.docx                # Master keyword reference: categories, source URLs,
│                                    # and exact --keywords strings per device type
│
├── scripts/                         # All pipeline scripts live here
│   ├── nvd_keyword_query.py             # Stage 1 — live NVD API querier
│   ├── cve_search.py                    # Stage 2 — offline bulk NVD searcher
│   ├── run_all_years.sh                 # Automates Stage 2 across 2002–2026
│   ├── full_intersect.py                # Stage 3 — CVE cross-file matcher (intersection)
│   ├── full_difference.py               # Stage 3 — CVE cross-file matcher (difference / complement)
│   ├── build_difference_sets.py         # Stage 4 — batch-generate 01_raw.csv for many categories at once
│   ├── init_categories.py               # Stage 4 — scaffold per-category folders from a list (idempotent)
│   ├── make_review_copies.py            # Stage 4 — split a raw difference set into 3 blind AI copies
│   ├── gemini_classify.py               # Stage 4 — Gemini API reviewer (standalone, or imported by merge)
│   └── merge_judgments.py               # Stage 4 — (optionally run Gemini, then) merge the 3 AI copies + flag
│
├── Onboarding-Docs/                 # Onboarding doc + reference papers (unchanged)
│
└── data/                            # All datasets, grouped by search method
    │
    ├── keyword-search/              # Stage 1 outputs (Lizzie) — 10 multi-sheet workbooks
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
    ├── vendor-search/               # Stage 2 outputs (Jason) — 13 in-scope device types (+2 excluded)
    │   ├── results_all_cameras.xlsx          (~2,161 CVEs — largest)
    │   ├── results_all_airconditioner.xlsx   (~187 CVEs)
    │   ├── results_all_gameconsoles.xlsx     (~246 CVEs — OUT OF SCOPE: entertainment, fails criterion 4)
    │   ├── results_all_streaming_tvs.xlsx    (~232 CVEs — OUT OF SCOPE: entertainment, fails criterion 4)
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
    ├── intersection/                # Stage 3 — vendor ∩ keyword (full_intersect.py output)
    │   ├── matched_camera_cves.csv       (~1,048 rows — largest)
    │   ├── matched_alarms_cves.csv       (~175 rows)
    │   ├── matched_smartplug_cves.csv    (~88 rows)
    │   └── matched_<device>_cves.csv     (10 more device types)
    │
    └── difference/                  # Stage 3 + Stage 4 — vendor − keyword, plus its triple-AI review
        ├── CLASSIFICATION_PROMPT.md     # shared rubric all 3 AI reviewers judge by (single source of truth)
        ├── unmatched_cves.xlsx          # vendor CVEs in NO category workbook (whole-corpus difference)
        │
        └── <device>/                    # per-category triple-AI review (e.g. cameras/)
            ├── 01_raw.csv                   # full_difference.py output (vendor − keyword_union)
            ├── reviews/
            │   ├── claude.csv               # raw + Claude columns   (Claude Code fills, manual)
            │   ├── codex.csv                # raw + Codex columns    (Codex fills, manual)
            │   └── gemini.csv               # raw + Gemini columns   (gemini_classify.py fills, API)
            ├── 02_merged.csv                # merge_judgments.py → all 9 AI cols + human-review flag
            └── 03_keyword_additions.md      # keywords mined from unanimous-Yes rows (feeds keyword search)
```

> **Note — running the scripts.** Scripts now live in `scripts/`. `full_intersect.py` and
> `full_difference.py` still reference the keyword workbooks by **bare filename**, so run them
> from inside `data/keyword-search/` (e.g. `python ../../scripts/full_intersect.py`). `cve_search.py`
> and `run_all_years.sh` operate on the cwd; run them from wherever the year-feeds / outputs live.

---

## Data Schemas

| File type | Columns |
|-----------|---------|
| `data/keyword-search/*.xlsx` | CVE, CVSS, CVSS Severity, CWE, CWE Name, Description |
| `data/vendor-search/results_all_*.xlsx` | cve_id, published, description, cvss_score, cvss_version, cwe_ids (pipe-sep), cpe_strings (pipe-sep), Lizzie Judgment/Judgement, Cukier Judgment |
| `data/intersection/*.csv` | Source File, Source Sheet, CVE, CVSS, CVSS Severity, CWE, CWE Name, Description |
| `data/difference/<device>/01_raw.csv` | Difference Type, cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings |
| `data/difference/<device>/reviews/{ai}.csv` | …raw columns + `<AI> Judgment`, `<AI> Confidence`, `<AI> Reasoning` (one AI's triple only) |
| `data/difference/<device>/02_merged.csv` | …raw columns + all 3 AI triples (Claude/Codex/Gemini) + `Review Status`, `Needs Human Review`, `Review Reason` |
| `data/difference/unmatched_cves.xlsx` | Difference Type, Origin File, cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings, Lizzie Judgment, Cukier Judgment, Lizzie Judgement |

**Note:** There is a spelling inconsistency — some files use `Lizzie Judgment`, others use `Lizzie Judgement`. Treat them as the same column.

---

## Definition of a Home IoT Device

**Definition.** Home IoT devices are internet-connected sensors, appliances, and embedded systems deployed within residential environments for the purpose of monitoring, automation, or control, without dedicated IT security oversight (Balta-Ozkan et al., 2013; Alrawi et al., 2019).

The criteria below are derived directly from this definition — one per clause. A device must satisfy **all five** definitional criteria.

**Definitional criteria:**
1. **Connectivity** — communicates over a network via standard protocols (TCP/IP, MQTT, CoAP, Zigbee, BLE). *(from "internet-connected")*
2. **Device class** — a special-purpose sensor, appliance, or embedded system; **not** general-purpose IT (PC, phone, tablet, game console). *(from "sensors, appliances, and embedded systems")*
3. **Deployment context** — intended for a private residence, not primarily enterprise/industrial. *(from "deployed within residential environments")*
4. **Function** — primary purpose is to **monitor, automate, or control the home environment or its systems** (climate, security, access, lighting, appliances, presence). Media/entertainment, general computing, and communication are **not** qualifying functions. *(from "for the purpose of monitoring, automation, or control")*
5. **Security context** — owned and maintained by non-expert consumers, with no professional security administration. *(from "without dedicated IT security oversight")*

**Study-inclusion criterion** (operational, *not* definitional — it scopes what can be analyzed, not what qualifies as home IoT):
- Has a Common Platform Enumeration (CPE)-identifiable footprint in NVD and is subject to CVE disclosure.

**Guiding principle — connectivity is not membership.** Being networked alongside, or interoperating with, home IoT does not make a device home IoT. Criterion 1 (connectivity) is satisfied by virtually every IT device, so it cannot be the discriminator; the device's own **function** (criterion 4) and **class** (criterion 2) are what qualify it. A game console that controls smart lights through an app is still not a home IoT device.

**Out of scope (excluded by criterion 4).** Game consoles and streaming devices / smart TVs are **entertainment** devices — their primary function is media consumption, not monitoring/automation/control of the home — and are therefore excluded. (Alrawi et al. include a "media" category because they score *deployment attack surface*; this project is a *function-defined category study*, a different goal, so their scope is not inherited.) The `results_all_gameconsoles.xlsx` and `results_all_streaming_tvs.xlsx` files remain on disk but are **out of the analysis set**.

**Open scoping note — sleep trackers.** This category currently mixes bedside/in-bed monitors (in scope) with wearables like Fitbit/Apple Watch/Garmin/Whoop, which fail criterion 3 (personal/mobile, not deployed within the residence). Recommended resolution: scope the category to bedside sleep monitors and treat wearables as out of scope.

**Recommended additions** (already keyword-prepped in `Devices List.docx` / `data/keyword-search/` but never given a `results_all_*.xlsx`): **routers/gateways, smart hubs, smart lighting** — all pass the five criteria cleanly.

---

## Manual Review — False Positive Classification

### What the judgment columns are
`Lizzie Judgment` and `Cukier Judgment` are independent manual review columns where two researchers determine whether each CVE is a true match for the device category or a false positive from the keyword search.

**Values:**
- `Yes` — true match, CVE genuinely affects this device type
- `No` — false positive, keyword matched but CVE is unrelated
- `Maybe` — ambiguous, needs further discussion

### Guidance for AI-assisted classification (AI Judgment column)

#### Column schema
Each `results_all_*.xlsx` file gets three columns added:

| Column | Values | When to populate |
|--------|--------|-----------------|
| `AI Judgment` | Yes / No / Maybe | Always |
| `AI Confidence` | High / Low | Always |
| `AI Judgment Reasoning` | Short explanation | Low confidence and Maybe rows only |

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
| All other 10 in-scope `results_all_*.xlsx` | varies | No judgment columns yet | — |
| `results_all_gameconsoles.xlsx`, `results_all_streaming_tvs.xlsx` | — | **Out of scope** (entertainment) | — |
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
