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
- [Refreshing Difference Sets Without Losing Review Work](#refreshing-difference-sets-without-losing-review-work)
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
  - `NVD_API_KEY` — for downloading the NVD snapshot (`download_nvd.py`). Get one free at <https://nvd.nist.gov/developers/request-an-api-key>; it raises the API rate limit dramatically and is strongly recommended.
  - Load with: `set -a; source .env; set +a`

---

## One-Time Setup: Build the NVD Snapshot

The entire pipeline runs against a single fixed offline snapshot (`data/nvd-snapshot/nvd_all.csv`) — pinning one download is what makes the keyword and vendor searches comparable and the study reproducible/citeable ("dataset as of `<date>`"). The file is gitignored because it is large (~290 MB / ~360k CVEs), but it is fully reproducible.

There are two ways to build it. The **API downloader is the recommended path** — one command pulls the entire database. The per-year-feed route is kept below as a manual fallback.

### Recommended — download the whole database via the NVD API

**Script:** `scripts/download_nvd.py`

This pulls every CVE from the NVD 2.0 REST API and writes them directly to `data/nvd-snapshot/nvd_all.csv` in the project's exact schema (`cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings`).

```bash
cd /path/to/Home-IoT-Security         # the repo root
set -a && source .env && set +a       # loads $NVD_API_KEY
python3 scripts/download_nvd.py        # → data/nvd-snapshot/nvd_all.csv
```

That's the whole thing. The script reads the API key from `$NVD_API_KEY`, defaults its output to the snapshot path, and prints progress per page.

**It is resumable.** The corpus is fetched in pages of 2000 CVEs across a few threads. After every completed page, the set of finished pages is saved to `data/nvd-snapshot/nvd_all.csv.progress.json` and rows are appended immediately, so:

- **To pause** — `Ctrl-C`, or `pkill -f download_nvd.py`.
- **To resume** — run the exact same command again. It reads the progress file and the existing CSV, skips finished pages, and de-duplicates by CVE ID — so you never lose more than the single page in flight (~2000 CVEs), and a resume can't create duplicates.

A full run from scratch is ~360k CVEs / ~181 pages and takes **~2–3 hours** (the NVD API is flaky; retries with exponential backoff are normal and expected). Re-running later only fetches pages NVD has added since.

**Options:**

| Flag | Description |
|------|-------------|
| `--api-key KEY` | NVD API key (default: `$NVD_API_KEY`). Strongly recommended — anonymous requests are heavily rate-limited. |
| `--out FILE` | Output CSV (default: `data/nvd-snapshot/nvd_all.csv`). |
| `--threads N` | Concurrent download threads (default: `3`). |

When it finishes it prints **"All pages complete."** Then update the provenance fields in `data/nvd-snapshot/SNAPSHOT.md` (snapshot date + total CVE count — read the count from the progress file's `written` value, which is the true CVE count; note that `wc -l nvd_all.csv` over-counts because CVE descriptions contain embedded newlines).

### Fallback — build from per-year NVD 1.1 feeds

If you prefer the static year-feeds (or the API is down), build the snapshot manually:

**Step 1 — Download the per-year NVD 1.1 feeds (2002–2026)**

From <https://nvd.nist.gov/feeds/json/cve/1.1/>, download `nvdcve-1.1-<year>.json.gz` for each year, then gunzip them:

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

Then fill in the provenance fields in `data/nvd-snapshot/SNAPSHOT.md` as above.

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

**Script:** `scripts/build_vendor_search.py`
**Output:** `data/vendor-search/results_all_<category>.xlsx` (one per category)

This stage searches the NVD snapshot for manufacturer/brand names (e.g. "Nest", "Ring", "Ecobee"). It is owned by Jason. As of the 2026-06 overhaul it runs **offline, per-category, through the same engine as the keyword search** (`cve_search.filter_by_keywords`, matching description **+ CPE** with whole-word boundaries) against the same fixed snapshot — so the only difference between the two methods is now the search *terms* (brands vs. device-phrases), making the results directly comparable.

**Step 1 — Author your brand terms**

Brand terms live in `data/vendor-search/vendor_terms.csv`, same `slug,term` format and parser as `keyword_terms.csv` (`#`-comment / blank-line aware). Qualify a brand with a product word wherever the bare name overlaps unrelated products — e.g. `carrier infinity`, not `carrier` — to suppress false positives.

```
slug,term
thermostat,ecobee
thermostat,nest thermostat
cameras,hikvision
doorbell,ring video doorbell
```

This file is the **complete, reproducible source for all 25 categories**:

- The **15 original** categories' terms were recovered from the exact `--keywords` strings in `Devices List.docx` (Jason's brand strings). Verified: rebuilding through `build_vendor_search.py` reproduces the committed `results_all_<cat>.xlsx` CVE sets **exactly** for all 14 in-scope categories.
- The **10 new** categories' terms are Claude-drafted (companion doc: `data/vendor-search/PROPOSED_brand_lists.md`).

**Step 2 — Run the vendor search**

```bash
# All categories that have active terms
python3 scripts/build_vendor_search.py

# Specific categories only
python3 scripts/build_vendor_search.py --categories cameras thermostat doorbell

# Custom snapshot or terms file
python3 scripts/build_vendor_search.py --snapshot path/to/nvd_all.csv --terms path/to/terms.csv

# Rebuild existing output files
python3 scripts/build_vendor_search.py --overwrite
```

Categories with no active terms are **skipped with a message** — not an error.

**Output columns:** `cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings` — identical to the keyword files and `01_raw.csv`.

> **Legacy path:** before the overhaul the vendor search was a per-year run via `cve_search.py --input` / `run_all_years.sh`, with results manually saved to Excel. That path still works (see [`cve_search.py`](#cve_searchpy--stage-1--2) / [`run_all_years.sh`](#run_all_yearssh--snapshot--legacy)) and is what builds the snapshot, but it is no longer the vendor-search route. The pre-overhaul workbooks are archived under `data/vendor-search/_backup_pre_rebuild_2026-06-28/`.

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
# One category
python3 scripts/make_review_copies.py <device>
# All categories at once
python3 scripts/make_review_copies.py --all
```

Output: `data/difference/<device>/reviews/{claude,codex,gemini}.csv` — each containing the combined rows from both `vendor_only` and `keyword_only` (the `Difference Type` column sorts them back). Prior AI judgments are **automatically restored from `judgment_store.csv`** by `(category, cve_id)` — no `--preserve` flag needed. Only CVEs new to the current `01_raw.csv` are left blank.

To blank-rebuild and ignore the store: add `--overwrite`. See [Refreshing difference sets without losing review work](#refreshing-difference-sets-without-losing-review-work).

**Step 3 — Manual AI reviews (Claude and Codex)**

- Claude Code opens and fills `data/difference/<device>/reviews/claude.csv` — columns: `Claude Judgment`, `Claude Confidence`, `Claude Reasoning`
- Codex opens and fills `data/difference/<device>/reviews/codex.csv` — columns: `Codex Judgment`, `Codex Confidence`, `Codex Reasoning`

Judgment values: `Yes` / `No` / `Maybe`. Confidence: `High` / `Low`. See the rubric in `data/difference/CLASSIFICATION_PROMPT.md`.

**Step 4 — Run Gemini reviewer + merge all three**

```bash
# Load API key first
set -a; source .env; set +a

# Run Gemini and merge in one command
python3 scripts/merge_judgments.py \
    --reviews data/difference/<device>/reviews \
    --run-gemini \
    --category "<device type phrase>" \
    --model gemma-4-31b-it

# Pure merge only (no Gemini API call) — useful as a status check
python3 scripts/merge_judgments.py --reviews data/difference/<device>/reviews
```

Gemini is resumable — rows already filled are skipped. The merge writes:

- `data/difference/<device>/02_merged.csv` — all 9 AI columns plus `Needs Human Review` flag and `Review Status`
- `data/difference/<device>/02_high_confidence_audit.csv` — a random sample of unanimous high-confidence rows for spot-checking

**Speeding up the Gemini pass — `--batch-size`.** By default each row is one API call. Pass `--batch-size N` (e.g. `20`) to pack N CVEs into a single prompt; the model returns a JSON array and results are mapped back by `cve_id`, cutting round-trips ~Nx and easing the daily-quota load. Rows the model omits or returns with an unrecognized `cve_id` are left blank and retried on the next run, so batching stays safe and resumable.

```bash
python3 scripts/merge_judgments.py \
    --reviews data/difference/<device>/reviews \
    --run-gemini --category "<device type phrase>" \
    --model gemma-4-31b-it --batch-size 20
```

> **Note:** very large batches risk truncating the model's JSON output on long-description categories (the whole chunk is then dropped and retried). Start at `--batch-size 10` for verbose categories (cameras, hub) and go up to `20` for short-description ones. `--batch-size 1` is the default and reproduces the exact prior one-row-at-a-time behavior.

**Flag rule:** `Needs Human Review = Yes` when both Claude and Codex are Low confidence, or the three judgments are not unanimous. Gemini's confidence is excluded from the flag (it skews Low) but its judgment counts toward unanimity.

**Run Gemini over all categories at once**

```bash
bash scripts/run_gemma_column.sh
# Backs up the prior model's results (per-category), blanks the Gemini column, then fills it
```

Each category gets its own flag file (`.gemma_prepped`) so the run is resumable. Rate limits for `gemma-4-31b-it`: 15 RPM / 1,500 req/day. Quota resets at midnight Pacific (~03:00 ET).

**Step 5 — Extract the human-review queue**

```bash
python3 scripts/extract_human_review.py
# Or for a specific file:
python3 scripts/extract_human_review.py --merged data/difference/<device>/02_merged.csv
```

Writes:

- `data/difference/<device>/02_needs_human_review.csv` — flagged rows for this category (both directions)
- `data/difference/human_review_queue.csv` — all flagged rows across all categories (one combined sheet)

Re-running is safe — any `Human Verdict` / `Human Notes` already filled in are carried forward automatically.

**Step 6 — Human adjudication**

Open `human_review_queue.csv` and fill in the `Human Verdict` column (`Yes` / `No` / `Maybe`) for each flagged row. Add notes in `Human Notes` where useful.

**Step 7 — Finalize judgments**

```bash
python3 scripts/finalize_judgments.py
```

Writes:

- `data/difference/<device>/03_final.csv` — per category with `Final Judgment` + `Final Source`
- `data/difference/final_resolved.csv` — all categories combined (derived; rebuilt each run)
- `data/difference/judgment_store.csv` — **upserted** (never rebuilt from scratch); the persistent backing store that survives any `01_raw.csv` regeneration

`Final Source` is `ai-consensus` for unflagged rows, `human` for adjudicated rows, `pending` for rows still awaiting a human verdict.

Re-run as humans fill more rows in — it never overwrites AI columns.

**Step 8 — Mine resolved-Yes rows for missing keywords**

Inspect the resolved-Yes rows in `03_final.csv` for keyword phrases not yet in `keyword_terms.csv`. Add them to close the recall gap, then re-run `build_keyword_search.py`. Document the additions in `03_keyword_additions.md`.

---

## Refreshing difference sets without losing review work

When the vendor or keyword terms change (e.g. a snapshot rebuild or scope freeze), the `01_raw` difference sets must be regenerated — which desyncs the review artifacts built on top of them. Prior work is **not lost** if you refresh in this order: both human verdicts and AI judgments are preserved by `(category, cve_id)`, so only *genuinely new* rows need review.

1. **Regenerate the raw sets** — `build_difference_sets.py --direction both --overwrite`.
2. **Rebuild review copies** — `make_review_copies.py --all`. Prior AI judgments are **automatically restored from `judgment_store.csv`** by `(category, cve_id)` — no `--preserve` flag needed. Only CVEs new to the regenerated `01_raw.csv` are left blank.
3. **Re-judge only the new (blank) rows** — Claude/Codex manually; Gemini via `merge_judgments.py --run-gemini` (resumable — it skips filled rows, so it only spends quota on the blanks).
4. **Re-merge and re-settle** — `merge_judgments.py` (re-flag) → `extract_human_review.py` (re-applies existing `Human Verdict`s by key) → `finalize_judgments.py` (re-finalizes and upserts the store).

> Worked example (2026-06-28 refresh after the vendor reproducibility fix + keyword overhaul): regenerating the `vendor_only` sets preserved **1,175** Claude/Codex judgments per reviewer and left **2,178** new rows (mostly cameras, whose set grew 1,709 → 2,798) for fresh review. All **334** human verdicts were retained — **268** still map to current rows; the **66** orphans (CVEs the keyword search now also matches) drop out harmlessly.

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

### `download_nvd.py` — Setup
Downloads the entire NVD database from the NVD 2.0 REST API into the snapshot CSV. Resumable (saves per-page progress to `<out>.progress.json`, de-dupes by CVE ID), multi-threaded, reads the API key from `$NVD_API_KEY`. See [One-Time Setup](#one-time-setup-build-the-nvd-snapshot).

| Flag | Description |
|------|-------------|
| `--api-key KEY` | NVD API key (default: `$NVD_API_KEY`). Strongly recommended. |
| `--out FILE` | Output CSV (default: `data/nvd-snapshot/nvd_all.csv`). |
| `--threads N` | Concurrent download threads (default: `3`). |

---

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

### `build_vendor_search.py` — Stage 2
Runs brand terms from `vendor_terms.csv` through the `cve_search` engine against the fixed NVD snapshot. Writes one `results_all_<slug>.xlsx` per category, in the same schema as the keyword files. Same flags and behaviour as `build_keyword_search.py`.

| Flag | Description |
|------|-------------|
| `--categories SLUG [SLUG …]` | Only build these slugs (default: every slug with active terms) |
| `--snapshot FILE` | NVD snapshot CSV to search (default: `data/nvd-snapshot/nvd_all.csv`) |
| `--terms FILE` | Brand terms CSV to read (default: `data/vendor-search/vendor_terms.csv`) |
| `--outdir DIR` | Where to write `results_all_<slug>.xlsx` files (default: `data/vendor-search/`) |
| `--overwrite` | Rebuild even if `results_all_<slug>.xlsx` already exists (default: skip) |

---

### `run_all_years.sh` — Snapshot / Legacy
Shell wrapper that runs `cve_search.py` over all NVD year feeds (2002–2026) and merges the per-year outputs into a single CSV. Used to **build the snapshot**, and is the legacy per-year vendor-search path (superseded by `build_vendor_search.py`). Outputs CSV only — no Excel. Currently hardcoded to a specific keyword set (sleeptracker); edit the `KEYWORDS` variable at the top of the script before running a different category. No CLI flags.

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
Scaffolds `data/difference/<cat>/vendor_only/` and `data/difference/<cat>/keyword_only/` direction subfolders from a category list. Idempotent — existing folders are untouched. (The `reviews/` folder at the category level is created by `make_review_copies.py` when needed.)

| Flag | Description |
|------|-------------|
| `categories_file` | (positional) Text file with one category slug per line |
| `--direction vendor_only\|keyword_only\|both` | Which direction(s) to scaffold (default: `both`) |
| `--base DIR` | Base directory for category folders (default: `data/difference`) |

---

### `seed_judgment_store.py` — Stage 4 (one-time migration)
Bootstraps `data/difference/judgment_store.csv` from the existing `final_resolved.csv`. Run once when migrating to the current pipeline structure. After that, `finalize_judgments.py` keeps the store up to date automatically.

| Flag | Description |
|------|-------------|
| `--diff-dir DIR` | Difference directory (default: `data/difference`) |
| `--overwrite` | Overwrite if `judgment_store.csv` already exists |

---

### `make_review_copies.py` — Stage 4
Builds combined blind review copies for a category, concatenating both `vendor_only` and `keyword_only` `01_raw.csv` files. Pre-fills known AI judgments from `judgment_store.csv` automatically — no `--preserve` flag needed. Writes to `data/difference/<category>/reviews/{claude,codex,gemini}.csv`. Existing copies are skipped by default.

| Flag | Description |
|------|-------------|
| `category` | (positional) Category slug (e.g. `cameras`) |
| `--all` | Process every category listed in `device_lst.txt` |
| `--diff-dir DIR` | Difference directory root (default: `data/difference`) |
| `--store FILE` | Path to `judgment_store.csv` (default: `<diff-dir>/judgment_store.csv`) |
| `--overwrite` | Blank-rebuild existing copies (ignore judgment store) |

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
| `--batch-size N` | Rows per API call (default: `1` = one row at a time). Values >1 pack N CVEs into a single prompt and map results back by `cve_id`, cutting round-trips ~Nx. See the batching note below. |

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
| `--batch-size N` | Gemini: rows per API call (default: `1`). Try `20` to cut round-trips ~20x. See the batching note below. |

---

### `run_gemma_column.sh` — Stage 4 (top level)
**All-categories batch runner.** Loops over every category and calls `merge_judgments.py --run-gemini` for each. Reviews are now combined per category (`data/difference/<cat>/reviews/`) so both directions are filled in one pass. Does one-time prep per category (backs up the prior model's results as `gemini_3.1_baseline.csv`, blanks the Gemini columns) guarded by a per-category flag file (`.gemma_prepped`) so the run is fully resumable. Tuned to straddle the daily API quota reset at 0.30 RPS.

No CLI flags — edit `MODEL` and `RPS` at the top of the script if needed.

---

### `extract_human_review.py` — Stage 4
Pulls all `Needs Human Review = Yes` rows from every `<cat>/02_merged.csv` into per-category `02_needs_human_review.csv` files and a combined `human_review_queue.csv`. Verdict-preserving — re-runs carry forward any `Human Verdict` / `Human Notes` already filled in, keyed by `(category, cve_id)`. The `Direction` column in the combined queue is derived from the `Difference Type` column on each row.

| Flag | Description |
|------|-------------|
| `--diff-dir DIR` | Directory holding `<cat>/02_merged.csv` files (default: `data/difference`) |
| `--merged FILE` | Run on a single `02_merged.csv` instead of scanning the whole directory |

---

### `finalize_judgments.py` — Stage 4
Folds human verdicts back into one settled judgment per CVE. Writes `03_final.csv` per category, a combined `final_resolved.csv` (rebuilt each run), and **upserts `judgment_store.csv`** (append-only — never rebuilt from scratch, survives any `01_raw` regeneration). Never overwrites AI columns — safe to re-run as humans fill more rows in.

| Flag | Description |
|------|-------------|
| `--diff-dir DIR` | Directory holding `<cat>/02_merged.csv` files (default: `data/difference`) |

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
| `<cat>/<dir>/01_raw.csv` | `Difference Type, cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings` |
| `<cat>/reviews/{ai}.csv` | raw columns (both directions combined) + `<AI> Judgment, <AI> Confidence, <AI> Reasoning` |
| `<cat>/02_merged.csv` | raw columns + all 9 AI columns + `Review Status, Needs Human Review, Review Reason` |
| `<cat>/02_needs_human_review.csv` | `Verdicts, Review Reason` + raw + AI reasoning + `Human Verdict, Human Notes` |
| `<cat>/03_final.csv` | merged columns + `Final Judgment, Final Source` |
| `human_review_queue.csv` | same as `02_needs_human_review.csv` + leading `Category, Direction` |
| `final_resolved.csv` | same as `03_final.csv` + leading `Category, Direction` (derived; rebuilt each run) |
| `judgment_store.csv` | `category, cve_id, Difference Type` + all 9 AI columns + `Final Judgment, Final Source` (persistent; upserted by `finalize_judgments.py`) |

---

## Key Design Decisions

**Why one fixed snapshot?** Running both searches against the same `nvd_all.csv` eliminates data-lag noise — a "gap" between vendor and keyword results reflects a genuine difference in search terms, not a difference in data freshness. The snapshot date is recorded in `data/nvd-snapshot/SNAPSHOT.md` to make the study citable.

**Why three AI reviewers?** It mirrors the two-human reviewer model. Claude and Codex are the permanent reviewers; Gemini is the swappable third vote. Known biases: Codex over-excludes unfamiliar security brands; Gemini over-includes on function-overlap. Claude is the reliable anchor. The 2-of-3 unanimity check plus human flagging catches both biases.

**Why bidirectional difference?** `vendor_only` cleans false negatives in the keyword search. `keyword_only` surfaces gaps in the vendor brand list. Together they close both sides of the recall gap.

**What counts as a home IoT device?** A device must be internet-connected, be a special-purpose sensor/appliance/embedded system (not general-purpose IT), be intended for a private residence, have a monitoring/automation/control function (or serve as a home-control hub for other IoT devices), and be maintained by a non-expert consumer. Game consoles fail on device class and function. Streaming TVs qualify because their platforms act as Matter/Thread controllers. Plain routers are excluded — they are threat-model context, not study subjects.
