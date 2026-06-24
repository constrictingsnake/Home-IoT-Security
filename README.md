# Home IoT Security — CVE Research Pipeline

A research pipeline that systematically maps real-world home IoT device brands to known CVEs from NIST's National Vulnerability Database (NVD), organized by device category. The dataset is built using two complementary CVE-discovery methods and audited with a triple-AI review system.

---

## Table of Contents

- [What This Project Does](#what-this-project-does)
- [Prerequisites](#prerequisites)
- [One-Time Setup: Build the NVD Snapshot](#one-time-setup-build-the-nvd-snapshot)
- [Stage 1 — Keyword Search](#stage-1--keyword-search)
- [Stage 2 — Vendor Search](#stage-2--vendor-search)
- [Stage 3 — Intersection and Difference](#stage-3--intersection-and-difference)
- [Stage 4 — Triple-AI Review](#stage-4--triple-ai-review)
- [Device Categories](#device-categories)
- [Scripts](#scripts)
- [Data Schemas](#data-schemas)
- [Key Design Decisions](#key-design-decisions)

---

## What This Project Does

The pipeline has two CVE discovery methods that are cross-referenced against each other:

- **Vendor search (Jason):** searches NVD for manufacturer/brand names (e.g. "Nest", "Ring", "Ecobee") → produces `data/vendor-search/results_all_<category>.xlsx`
- **Keyword search (Lizzie):** searches NVD for generic device-type phrases (e.g. "video doorbell", "ip camera") → produces `data/keyword-search/keyword_<category>.csv`

Both methods run against the same fixed offline NVD snapshot to ensure the results are directly comparable and the study is reproducible.

The set difference (CVEs found by one method but not the other) is then reviewed by three independent AI reviewers (Claude Code, Codex, and Gemini) to classify each CVE as a true match or false positive.

---

## Prerequisites

- **Python 3.14** at `/Library/Frameworks/Python.framework/Versions/3.14/bin/python3` — invoke as `python3`
- Dependencies: `pandas`, `openpyxl`, `numpy`, `requests` (install with `pip install pandas openpyxl numpy requests`)
- `tqdm` optional — adds progress bars to `cve_search.py` (`pip install tqdm`)
- **API keys** in a gitignored `.env` file (never hardcode):
  - `GEMINI_API_KEY` — for the Gemini/Gemma reviewer
  - `NVD_API_KEY` — for the legacy live-API querier (not needed for the offline pipeline)
  - Load with: `set -a; source .env; set +a`

---

## One-Time Setup: Build the NVD Snapshot

The entire pipeline runs against a single fixed offline snapshot (`data/nvd-snapshot/nvd_all.csv`). This file is gitignored because it is large, but it is fully reproducible.

**Step 1 — Download the per-year NVD 1.1 feeds (2002–2026)**

From <https://nvd.nist.gov/feeds/json/cve/1.1/>, download `nvdcve-1.1-<year>.json.gz` for each year you want, then gunzip them:

```bash
gunzip nvdcve-1.1-2024.json.gz
# repeat for each year
```

**Step 2 — Convert each year JSON to CSV**

```bash
python3 scripts/cve_search.py --convert nvdcve-1.1-2002.json --csv-out nvd_2002.csv
python3 scripts/cve_search.py --convert nvdcve-1.1-2003.json --csv-out nvd_2003.csv
# ... repeat for each year through 2026
```

**Step 3 — Merge all years into one deduplicated snapshot**

```bash
python3 scripts/cve_search.py --merge nvd_2002.csv nvd_2003.csv ... nvd_2026.csv \
    --merged-out data/nvd-snapshot/nvd_all.csv
```

After this, fill in the provenance fields in `data/nvd-snapshot/SNAPSHOT.md` (date, total CVE count from `wc -l data/nvd-snapshot/nvd_all.csv`).

---

## Stage 1 — Keyword Search

**Script:** `scripts/build_keyword_search.py`
**Output:** `data/keyword-search/keyword_<category>.csv` (one per category)

This stage searches the NVD snapshot for device-type phrases (not brand names). It uses the same engine as the vendor search so results are directly comparable.

**Step 1 — Author your search terms**

Edit `data/keyword-search/keyword_terms.csv`. The file already exists with a `slug,term` header row and commented-out placeholder lines for every category — uncomment the lines you want or add new ones below them. Both files share the same `slug,term` column format.

```
# Already in the file — just uncomment or add lines like these:
# cameras,ip camera        ← remove the leading "# " to activate
cameras,network camera     ← a newly added line
doorbell,video doorbell
thermostat,smart thermostat
```

For starter ideas, copy rows from `data/keyword-search/keyword_terms.suggested.csv` into `keyword_terms.csv`. The suggested file is never read by the script — it is a reference-only copy-from menu with the same `slug,term` format.

**Rules for terms:**
- Device-type phrases only (e.g. `ip camera`, `video doorbell`)
- No brand names — that is the vendor search's job
- No protocols, firmware names, or umbrella terms

**Step 2 — Run the keyword search**

```bash
# All categories that have active terms
python3 scripts/build_keyword_search.py

# Specific categories only
python3 scripts/build_keyword_search.py --categories cameras thermostat doorbell

# Custom snapshot or terms file
python3 scripts/build_keyword_search.py --snapshot path/to/nvd_all.csv --terms path/to/terms.csv

# Rebuild existing output files
python3 scripts/build_keyword_search.py --overwrite
```

Categories with no active terms are **skipped with a message** — not an error.

**Output columns:** `cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings`

---

## Stage 2 — Vendor Search

**Script:** `scripts/cve_search.py` + `scripts/run_all_years.sh`
**Output:** CSV (e.g. `results_all.csv`)

This stage searches NVD for manufacturer and brand names. It is owned by Jason. The vendor/brand keyword strings per device type are in `Devices List.docx`.

Both scripts output **CSV only** — `cve_search.py` has no Excel output mode, and `run_all_years.sh` merges its per-year outputs into a single `results_all.csv`. The `results_all_<category>.xlsx` files currently in `data/vendor-search/` are **externally produced** (manually saved as Excel by Jason outside the pipeline) and serve as pre-existing inputs to Stages 3 and 4.

Note: `run_all_years.sh` is currently hardcoded to a specific keyword set (sleeptracker). To run a different category, edit the `KEYWORDS` variable at the top of the script.

**Run a single vendor search**

```bash
python3 scripts/cve_search.py --input data/nvd-snapshot/nvd_all.csv \
    --keywords "ring" "nest" "arlo" "wyze" "blink"
```

**Run across all years for one category (automated)**

```bash
bash scripts/run_all_years.sh
# Edit KEYWORDS at the top of the script before running
```

Run from the directory where your year-feed CSVs live. Output lands in `Results/` and is merged into `results_all.csv`.

---

## Stage 3 — Intersection and Difference

### Intersection — CVEs found by both methods

**Script:** `scripts/full_intersect.py`
**Output:** `data/intersection/matched_<device>_cves.csv`

Takes a vendor search Excel file and cross-references it against all keyword CSV files. Finds CVEs that appear in both. Run it interactively — it will prompt for the input file and output path.

```bash
python3 scripts/full_intersect.py
```

### Difference — CVEs found by only one method

**Script:** `scripts/full_difference.py` (whole-corpus) or `scripts/build_difference_sets.py` (per-category batch)

For Stage 4 review, use `build_difference_sets.py`. It generates both directions per category:

- `vendor_only` — CVEs in the vendor search that the keyword search missed
- `keyword_only` — CVEs in the keyword search that the vendor list missed (surfaces brand-list gaps)

**Run for all categories (both directions)**

```bash
python3 scripts/build_difference_sets.py data/device_lst.txt
```

**Run for specific categories or direction**

```bash
python3 scripts/build_difference_sets.py data/device_lst.txt --direction vendor_only
python3 scripts/build_difference_sets.py --categories cameras thermostat --direction keyword_only
```

By default, existing `01_raw.csv` files are **skipped** (so in-progress reviews are never overwritten). Add `--overwrite` to regenerate.

**Output:** `data/difference/<category>/<direction>/01_raw.csv`

---

## Stage 4 — Triple-AI Review

Each `01_raw.csv` difference set is reviewed independently by three AI reviewers (Claude Code, Codex, Gemini) using the shared rubric in `data/difference/CLASSIFICATION_PROMPT.md`. No reviewer sees another's judgment — each works from a blind copy containing only the raw data and its own empty columns.

### Full workflow (run from repo root)

Replace `<device>` with the category slug (e.g. `cameras`) and `<dir>` with `vendor_only` or `keyword_only`.

**Step 0 — (Optional) Scaffold folders for all categories**

```bash
python3 scripts/init_categories.py data/device_lst.txt
# One direction only:
python3 scripts/init_categories.py data/device_lst.txt --direction vendor_only
```

This creates `data/difference/<category>/<direction>/reviews/` for every category. Existing folders are untouched (idempotent).

**Step 1 — Generate the raw difference set**

```bash
python3 scripts/build_difference_sets.py data/device_lst.txt
# Output: data/difference/<device>/<dir>/01_raw.csv
```

**Step 2 — Create blind review copies**

```bash
python3 scripts/make_review_copies.py data/difference/<device>/<dir>/01_raw.csv
# Output: data/difference/<device>/<dir>/reviews/{claude,codex,gemini}.csv
```

Each file has the raw columns plus three empty judgment columns for that reviewer only.

**Step 3 — Manual AI reviews (Claude and Codex)**

- Claude Code opens and fills `reviews/claude.csv` — columns: `Claude Judgment`, `Claude Confidence`, `Claude Reasoning`
- Codex opens and fills `reviews/codex.csv` — columns: `Codex Judgment`, `Codex Confidence`, `Codex Reasoning`

Judgment values: `Yes` / `No` / `Maybe`. Confidence: `High` / `Low`. See the rubric in `data/difference/CLASSIFICATION_PROMPT.md`.

**Step 4 — Run Gemini reviewer + merge all three**

```bash
# Load API key first
set -a; source .env; set +a

# Run Gemini and merge in one command
python3 scripts/merge_judgments.py \
    --reviews data/difference/<device>/<dir>/reviews \
    --run-gemini \
    --category "<device type phrase>" \
    --model gemma-4-31b-it

# Pure merge only (no Gemini API call) — useful as a status check
python3 scripts/merge_judgments.py --reviews data/difference/<device>/<dir>/reviews
```

Gemini is resumable — rows already filled are skipped. The merge writes:

- `02_merged.csv` — all 9 AI columns plus `Needs Human Review` flag and `Review Status`
- `02_high_confidence_audit.csv` — a random sample of unanimous high-confidence rows for spot-checking

**Flag rule:** `Needs Human Review = Yes` when both Claude and Codex are Low confidence, or the three judgments are not unanimous. Gemini's confidence is excluded from the flag (it skews Low) but its judgment counts toward unanimity.

**Run Gemini over all categories at once**

```bash
DIRECTION=vendor_only bash scripts/run_gemma_column.sh
# Backs up the prior model's results, blanks the Gemini column, then fills it
```

Rate limits for `gemma-4-31b-it`: 15 RPM / 1,500 req/day. Quota resets at midnight Pacific (~03:00 ET).

**Step 5 — Extract the human-review queue**

```bash
python3 scripts/extract_human_review.py
# Or for a specific file:
python3 scripts/extract_human_review.py --merged data/difference/<device>/<dir>/02_merged.csv
```

Writes:

- `data/difference/<device>/<dir>/02_needs_human_review.csv` — flagged rows for this category/direction
- `data/difference/human_review_queue.csv` — all flagged rows across all categories (one combined sheet)

Re-running is safe — any `Human Verdict` / `Human Notes` already filled in are carried forward automatically.

**Step 6 — Human adjudication**

Open `human_review_queue.csv` and fill in the `Human Verdict` column (`Yes` / `No` / `Maybe`) for each flagged row. Add notes in `Human Notes` where useful.

**Step 7 — Finalize judgments**

```bash
python3 scripts/finalize_judgments.py
```

Writes:

- `data/difference/<device>/<dir>/03_final.csv` — per category/direction with `Final Judgment` + `Final Source`
- `data/difference/final_resolved.csv` — all categories combined

`Final Source` is `ai-consensus` for unflagged rows, `human` for adjudicated rows, `pending` for rows still awaiting a human verdict.

Re-run as humans fill more rows in — it never overwrites AI columns.

**Step 8 — Mine resolved-Yes rows for missing keywords**

Inspect the resolved-Yes rows in `03_final.csv` for keyword phrases not yet in `keyword_terms.csv`. Add them to close the recall gap, then re-run `build_keyword_search.py`. Document the additions in `03_keyword_additions.md`.

---

## Device Categories

The frozen analysis scope has ~22 categories defined in `data/device_lst.txt`. Vendor Excel files are at `data/vendor-search/results_all_<slug>.xlsx`.

| Family | Category slugs |
|--------|---------------|
| Cameras & monitors | `cameras`, `doorbell`, `babymonitor` |
| Access control | `doorlock` |
| Alarms & sensors | `alarms`, `sensors` |
| Climate & air | `thermostat`, `airconditioner`, `fans`, `airpurifier` |
| Electrical & lighting | `smartplugs`, `lighting` |
| Appliances | `fridge`, `robotvacuum`, `appliances` |
| Hubs & controllers | `hub` |
| Audio | `smartspeakers` |
| Sleep | `sleeptracker` |
| Shades | `shades` |
| Energy | `ev-charging`, `home-power` |
| Outdoor & pet | `garden`, `pet` |
| Entertainment (hybrid) | `streaming` |

**Out of scope:** `gameconsoles`, VR headsets, plain routers/modems/switches.

---

## Scripts

### `cve_search.py` — Stage 1 & 2
Core NVD search engine and the shared filter used by `build_keyword_search.py`. Operates in one of three mutually exclusive modes.

| Flag | Description |
|------|-------------|
| `--convert NVD_JSON` | Convert a NVD JSON year-feed to a flat CSV (no search performed) |
| `--merge CSV [CSV …]` | Merge and deduplicate multiple year CSVs into one file |
| `--input FILE` | Search a local `.csv` or `.json` dataset for keywords |
| `--csv-out FILE` | Output path for `--convert` (default: `nvd_flat.csv`) |
| `--merged-out FILE` | Output path for `--merge` (default: `nvd_merged.csv`) |
| `--keywords KW [KW …]` | Keywords to search — required with `--input` |
| `--output FILE` | Output CSV for search results (default: `cve_search_results.csv`) |
| `--output-json FILE` | Also save results as JSON (optional) |
| `--sort-by cvss\|date\|cve_id` | Sort order for results (default: `date`) |
| `--min-cvss SCORE` | Only include CVEs with CVSS score ≥ this value |
| `--max-results N` | Cap total results returned |
| `--case-sensitive` | Case-sensitive keyword matching (default: case-insensitive) |
| `--show-all` | Print all matched CVEs to terminal (default: first 50) |
| `--no-preview` | Skip terminal preview entirely, just save files |

---

### `build_keyword_search.py` — Stage 1
Runs device-phrase keywords from `keyword_terms.csv` through the `cve_search` engine against the fixed NVD snapshot. Writes one `keyword_<slug>.csv` per category.

| Flag | Description |
|------|-------------|
| `--categories SLUG [SLUG …]` | Only build these slugs (default: every slug with active terms) |
| `--snapshot FILE` | NVD snapshot CSV to search (default: `data/nvd-snapshot/nvd_all.csv`) |
| `--terms FILE` | Keyword terms CSV to read (default: `data/keyword-search/keyword_terms.csv`) |
| `--outdir DIR` | Where to write `keyword_<slug>.csv` files (default: `data/keyword-search/`) |
| `--overwrite` | Rebuild even if `keyword_<slug>.csv` already exists (default: skip) |

---

### `run_all_years.sh` — Stage 2
Shell wrapper that runs `cve_search.py` over all NVD year feeds (2002–2026) and merges the per-year outputs into a single `results_all.csv`. Outputs CSV only — no Excel. Currently hardcoded to a specific keyword set (sleeptracker); edit the `KEYWORDS` variable at the top of the script before running a different category. No CLI flags.

---

### `full_intersect.py` — Stage 3
Fully interactive. Prompts for a vendor Excel file, cross-references it against all `keyword_<cat>.csv` files, and saves matched CVEs to a file of your choice. No CLI flags.

---

### `full_difference.py` — Stage 3
Fully interactive. Finds vendor CVEs that appear in none of the keyword files (whole-corpus `vendor − keyword_union`). For per-category differences use `build_difference_sets.py` instead. No CLI flags.

---

### `build_difference_sets.py` — Stage 4
Batch-generates `01_raw.csv` for every category, in both directions (`vendor_only` and `keyword_only`). Skips existing files by default so in-progress reviews are never overwritten.

| Flag | Description |
|------|-------------|
| `categories_file` | (positional) Text file with one category slug per line (e.g. `data/device_lst.txt`) |
| `--categories SLUG [SLUG …]` | Category slugs directly, instead of a file |
| `--direction vendor_only\|keyword_only\|both` | Which direction(s) to build (default: `both`) |
| `--overwrite` | Regenerate even if `01_raw.csv` already exists |

---

### `init_categories.py` — Stage 4
Scaffolds `data/difference/<cat>/<dir>/reviews/` folders from a category list. Idempotent — existing folders are untouched.

| Flag | Description |
|------|-------------|
| `categories_file` | (positional) Text file with one category slug per line |
| `--direction vendor_only\|keyword_only\|both` | Which direction(s) to scaffold (default: `both`) |
| `--base DIR` | Base directory for category folders (default: `data/difference`) |

---

### `make_review_copies.py` — Stage 4
Splits a `01_raw.csv` into three blind per-AI copies (`claude.csv`, `codex.csv`, `gemini.csv`), each containing only the raw columns and that reviewer's empty judgment columns.

| Flag | Description |
|------|-------------|
| `raw_csv` | (positional) Path to the raw difference CSV (e.g. `01_raw.csv`) |
| `--outdir DIR` | Where to write the review copies (default: `<raw_dir>/reviews/`) |
| `--overwrite` | Overwrite existing review copies instead of skipping them |

---

### `gemini_classify.py` — Stage 4 (lowest level)
**Core Gemini API caller.** Sends each row's description + CPE to the Gemini/Gemma API and fills `gemini.csv` in place. Resumable — already-filled rows are skipped. Use standalone when you want fine-grained control without immediately merging. Imported and called by `merge_judgments.py`.

| Flag | Description |
|------|-------------|
| `csv` | (positional) Path to the Gemini review copy (`gemini.csv`) |
| `--category TEXT` | Device category label sent to the model, e.g. `"security camera"` **(required)** |
| `--model MODEL_ID` | Gemini/Gemma model to use (default: `gemini-2.5-flash`; can also set via `GEMINI_MODEL` env var) |
| `--rubric FILE` | Path to the shared rubric markdown (default: `data/difference/CLASSIFICATION_PROMPT.md`) |
| `--rps FLOAT` | Max requests per second (default: `1.0`) |
| `--save-every N` | Flush progress to disk every N rows (default: `25`) |
| `--limit N` | Classify only the first N pending rows — useful for testing (default: `0` = all) |
| `--redo` | Re-classify rows that already have a Gemini judgment |

---

### `merge_judgments.py` — Stage 4 (mid level)
**Single-category orchestrator.** Merges the three per-AI review copies into `02_merged.csv` and writes a `02_high_confidence_audit.csv` spot-check sample. With `--run-gemini`, calls `gemini_classify.py` first — one command does both the automated review and the merge. Without it, just re-merges existing copies (no API call needed).

| Flag | Description |
|------|-------------|
| `--reviews DIR` | Directory holding `claude.csv`, `codex.csv`, `gemini.csv` |
| `--claude FILE` | Path to the Claude copy (overrides `--reviews`) |
| `--codex FILE` | Path to the Codex copy (overrides `--reviews`) |
| `--gemini FILE` | Path to the Gemini copy (overrides `--reviews`) |
| `--out FILE` | Output path for the merged file (default: `<reviews>/../02_merged.csv`) |
| `--audit-sample N` | Size of the high-confidence spot-check sample (default: `10`; `0` to disable) |
| `--audit-out FILE` | Audit sample output path (default: `<merged dir>/02_high_confidence_audit.csv`) |
| `--seed N` | Random seed for the audit sample draw (default: `42`) |
| `--run-gemini` | Call the Gemini API to fill `gemini.csv` before merging |
| `--category TEXT` | Device category passed to Gemini — required with `--run-gemini` |
| `--model MODEL_ID` | Gemini model to use (default: `gemini_classify.DEFAULT_MODEL`) |
| `--rps FLOAT` | Gemini max requests per second (default: `1.0`) |
| `--save-every N` | Gemini: flush progress every N rows (default: `25`) |
| `--limit N` | Gemini: classify only the first N pending rows (default: `0` = all) |
| `--redo` | Gemini: re-classify rows that already have a judgment |

---

### `run_gemma_column.sh` — Stage 4 (top level)
**All-categories batch runner.** Loops over every category and calls `merge_judgments.py --run-gemini` for each. Does one-time prep (backs up the prior model's results as `gemini_3.1_baseline.csv`, blanks the Gemini columns) guarded by a flag file so the run is fully resumable. Tuned to straddle the daily API quota reset at 0.30 RPS.

Configured via environment variables at the top of the script rather than CLI flags:

| Variable | Description |
|----------|-------------|
| `DIRECTION` | Which difference direction to fill: `vendor_only` or `keyword_only` (default: `vendor_only`) |
| `MODEL` | Gemini/Gemma model ID (hardcoded to `gemma-4-31b-it` — edit the script to change) |
| `RPS` | Requests per second (hardcoded to `0.30` — edit to change) |

---

### `extract_human_review.py` — Stage 4
Pulls all `Needs Human Review = Yes` rows from every `02_merged.csv` into per-category `02_needs_human_review.csv` files and a combined `human_review_queue.csv`. Verdict-preserving — re-runs carry forward any `Human Verdict` / `Human Notes` already filled in, keyed by `(category, cve_id)`.

| Flag | Description |
|------|-------------|
| `--diff-dir DIR` | Directory holding `<cat>/<dir>/02_merged.csv` files (default: `data/difference`) |
| `--merged FILE` | Run on a single `02_merged.csv` instead of scanning the whole directory |

---

### `finalize_judgments.py` — Stage 4
Folds human verdicts back into one settled judgment per CVE. Writes `03_final.csv` per category and a combined `final_resolved.csv`. Never overwrites AI columns — safe to re-run as humans fill more rows in.

| Flag | Description |
|------|-------------|
| `--diff-dir DIR` | Directory holding `<cat>/<dir>/02_merged.csv` files (default: `data/difference`) |

---

### `nvd_keyword_query.py` — Legacy
Old live-NVD-API querier. Retired and no longer part of the pipeline. Kept on disk for reference only. Use `build_keyword_search.py` instead.

---

## Data Schemas

| File | Key columns |
|------|-------------|
| `keyword_terms.csv` | `slug, term` |
| `keyword_<cat>.csv` | `cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings` |
| `results_all_*.xlsx` | `cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings` |
| `01_raw.csv` | `Difference Type, cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings` |
| `reviews/{ai}.csv` | raw columns + `<AI> Judgment, <AI> Confidence, <AI> Reasoning` |
| `02_merged.csv` | raw columns + all 9 AI columns + `Review Status, Needs Human Review, Review Reason` |
| `02_needs_human_review.csv` | `Verdicts, Review Reason` + raw + AI reasoning + `Human Verdict, Human Notes` |
| `03_final.csv` | merged columns + `Final Judgment, Final Source` |
| `human_review_queue.csv` | same as `02_needs_human_review.csv` + leading `Category, Direction` |
| `final_resolved.csv` | same as `03_final.csv` + leading `Category, Direction` |

---

## Key Design Decisions

**Why one fixed snapshot?** Running both searches against the same `nvd_all.csv` eliminates data-lag noise — a "gap" between vendor and keyword results reflects a genuine difference in search terms, not a difference in data freshness. The snapshot date is recorded in `data/nvd-snapshot/SNAPSHOT.md` to make the study citable.

**Why three AI reviewers?** It mirrors the two-human reviewer model. Claude and Codex are the permanent reviewers; Gemini is the swappable third vote. Known biases: Codex over-excludes unfamiliar security brands; Gemini over-includes on function-overlap. Claude is the reliable anchor. The 2-of-3 unanimity check plus human flagging catches both biases.

**Why bidirectional difference?** `vendor_only` cleans false negatives in the keyword search. `keyword_only` surfaces gaps in the vendor brand list. Together they close both sides of the recall gap.

**What counts as a home IoT device?** A device must be internet-connected, be a special-purpose sensor/appliance/embedded system (not general-purpose IT), be intended for a private residence, have a monitoring/automation/control function (or serve as a home-control hub for other IoT devices), and be maintained by a non-expert consumer. Game consoles fail on device class and function. Streaming TVs qualify because their platforms act as Matter/Thread controllers. Plain routers are excluded — they are threat-model context, not study subjects.
