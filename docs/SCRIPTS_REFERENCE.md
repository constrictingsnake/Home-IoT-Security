# Scripts Reference — full flag tables

Full per-script flag reference. For the day-to-day path use `scripts/pipeline.py refresh` /
`settle` (see `README.md` Quick Start) — this doc is for manual/fine-grained runs of an individual
stage script. Every script also answers `--help`.

---

### `download_nvd.py` — Setup
Downloads the entire NVD database from the NVD 2.0 REST API into the snapshot CSV. Resumable (saves per-page progress to `<out>.progress.json`, de-dupes by CVE ID), multi-threaded, reads the API key from `$NVD_API_KEY`.

| Flag | Description |
|------|-------------|
| `--api-key KEY` | NVD API key (default: `$NVD_API_KEY`). Strongly recommended. |
| `--out FILE` | Output CSV (default: `data/nvd-snapshot/nvd_all.csv`). |
| `--threads N` | Concurrent download threads (default: `3`). |

---

### `cve_search.py` — Stage 1 & 2 engine
Core NVD search engine and the shared filter used by `build_search.py`. Operates in one of three mutually exclusive modes.

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

### `build_search.py` — Stage 1 & 2
Runs both discovery methods through the `cve_search` engine against the fixed NVD snapshot, writing one CSV per category per method in the identical 8-column schema (`keyword_<slug>.csv` / `results_all_<slug>.csv`). `--method both` (default) loads the snapshot once and runs both.

| Flag | Description |
|------|-------------|
| `--method keyword\|vendor\|both` | Which search method(s) to run (default: `both`) |
| `--categories SLUG [SLUG …]` | Only build these slugs (default: every slug with active terms) |
| `--snapshot FILE` | NVD snapshot CSV to search (default: `data/nvd-snapshot/nvd_all.csv`) |
| `--terms FILE` | Terms CSV override — requires a single `--method` (default: the per-method file) |
| `--outdir DIR` | Output dir override — requires a single `--method` (default: the per-method dir) |
| `--overwrite` | Rebuild even if the output already exists (default: skip) |

---

### `build_review_sets.py` — Stage 3/4
Batch-generates `01_raw.csv` for every category and every review direction (`vendor_only`, `keyword_only`, `intersection`). Skips existing files by default.

| Flag | Description |
|------|-------------|
| `categories_file` | (positional) `data/categories.csv` (header row with a `slug` column) or a plain one-slug-per-line list |
| `--categories SLUG [SLUG …]` | Category slugs directly, instead of a file |
| `--direction vendor_only\|keyword_only\|intersection\|all` | Which direction(s) to build (default: `all`) |
| `--overwrite` | Regenerate even if `01_raw.csv` already exists |

---

### `make_review_copies.py` — Stage 4
Builds combined blind review copies for a category, concatenating every direction's `01_raw.csv`. Pre-fills known AI judgments from `judgment_store.csv` automatically.

| Flag | Description |
|------|-------------|
| `category` | (positional) Category slug (e.g. `cameras`) |
| `--all` | Process every category listed in `data/categories.csv` |
| `--refresh` | Rebuild existing copies to fold in **new** rows, carrying prior judgments forward from the store — only genuinely new CVEs are left blank |
| `--diff-dir DIR` | Difference directory root (default: `data/difference`) |
| `--store FILE` | Path to `judgment_store.csv` (default: `<diff-dir>/judgment_store.csv`) |
| `--overwrite` | Blank-rebuild existing copies (ignore judgment store; re-reviews everything) |

---

### `gemini_classify.py` — Stage 4 (lowest level)
Core Gemini API caller. Sends each row's description + CPE to the Gemini/Gemma API and fills `gemini.csv` in place. Resumable — already-filled rows are skipped. Imported and called by `merge_judgments.py`.

| Flag | Description |
|------|-------------|
| `csv` | (positional) Path to the Gemini review copy (`gemini.csv`) |
| `--category TEXT` | Device category label sent to the model, e.g. `"security camera"` **(required)** |
| `--model MODEL_ID` | Gemini/Gemma model to use (default: `gemini-2.5-flash`; can also set via `GEMINI_MODEL` env var) |
| `--rubric FILE` | Path to the shared rubric markdown (default: `data/difference/CLASSIFICATION_PROMPT.md`) |
| `--scope FILE` | Path to `categories.csv`, the per-category in/out scope notes injected into the prompt (default: `data/categories.csv`) |
| `--slug SLUG` | Category slug used to look up the scope note (default: derived from the `csv` path). A missing note is non-fatal |
| `--rps FLOAT` | Max requests per second (default: `1.0`) |
| `--save-every N` | Flush progress to disk every N rows (default: `25`) |
| `--limit N` | Classify only the first N pending rows — useful for testing (default: `0` = all) |
| `--redo` | Re-classify rows that already have a Gemini judgment |
| `--batch-size N` | Rows per API call (default: `1`). Values >1 pack N CVEs into a single prompt and map results back by `cve_id`, cutting round-trips ~Nx. Start at `10` for verbose categories (cameras, hub), up to `20` for short-description ones — very large batches risk truncating the model's JSON output. |

---

### `merge_judgments.py` — Stage 4 (mid level)
Merges the three per-AI review copies into `02_merged.csv` and writes a `02_high_confidence_audit.csv` spot-check sample. With `--run-gemini`, calls `gemini_classify.py` first. **`--all`** iterates every category in `data/categories.csv`.

| Flag | Description |
|------|-------------|
| `--all` | Iterate every category in `data/categories.csv`; cannot combine with `--reviews`/`--category`/`--out`/etc. |
| `--reviews DIR` | Directory holding `claude.csv`, `codex.csv`, `gemini.csv` |
| `--claude FILE` / `--codex FILE` / `--gemini FILE` | Path overrides for each copy |
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
| `--batch-size N` | Gemini: rows per API call (default: `1`) |

---

### `pipeline.py` — orchestrator
Chains the idempotent pipeline steps into three subcommands, pausing only at the two human touchpoints.

| Subcommand / flag | Description |
|-------------------|-------------|
| `refresh` | Rebuild search → review sets → CPE expansion → blind copies, then pause |
| `refresh --rebuild-search` | Also force `build_search --overwrite` (default builds only missing search outputs) |
| `settle` | Gemini + merge → extract human queue → finalize |
| `settle --no-gemini` | Skip the Gemini pass (merge existing judgments only) |
| `settle --model ID` / `--rps FLOAT` | Passed through to `merge_judgments --all --run-gemini` |
| `status` | Per-category `keyword_terms.csv`/`vendor_terms.csv` coverage, computed live from `data/categories.csv` |

---

### `extract_human_review.py` — Stage 4
Pulls all `Needs Human Review = Yes` rows into per-category `02_needs_human_review.csv` files and a combined `human_review_queue.csv`. Verdict-preserving.

| Flag | Description |
|------|-------------|
| `--diff-dir DIR` | Directory holding `<cat>/02_merged.csv` files (default: `data/difference`) |
| `--merged FILE` | Run on a single `02_merged.csv` instead of scanning the whole directory |

---

### `finalize_judgments.py` — Stage 4
Folds human verdicts back into one settled judgment per CVE. Writes `03_final.csv` per category, `final_resolved.csv`, and upserts `judgment_store.csv`.

| Flag | Description |
|------|-------------|
| `--diff-dir DIR` | Directory holding `<cat>/02_merged.csv` files (default: `data/difference`) |

---

### `term_precision.py` — Stage 8 (pruning)
Scores every search term's precision from the settled judgments, joining `matched_terms` attribution back to `final_resolved.csv`. Writes `data/difference/term_precision.csv`.

| Flag | Description |
|------|-------------|
| `--diff-dir DIR` | Directory holding `final_resolved.csv` (default: `data/difference`) |
| `--out FILE` | Output CSV (default: `<diff-dir>/term_precision.csv`) |
| `--min-n N` | Min judged rows before a term can be a prune candidate (default: `5`) |
| `--threshold FLOAT` | Precision at or below this flags a prune candidate (default: `0.10`) |

---

### `cpe_expansion.py` — Stage 5
Seeds from confirmed-`Yes` rows, extracts device `vendor:product` CPEs, and scans the snapshot for every other CVE NVD attributes to the same CPE minus what the two text methods already found.

| Flag | Description |
|------|-------------|
| `<category>` | Run one category (omit when using `--all`) |
| `--all` | Run every category with a confirmed-Yes seed, and write the summary CSV |
| `--no-part-filter` | Disable the `part ∈ {o, h}` guardrail — for A/B'ing how many app/library CPEs it filters out |
| `--no-stage4` | Report-only run — writes `09_*_candidates.csv` but no `cpe_expansion/01_raw.csv` |

---

### `cpe_brand_mining.py` — Stage 2 (automated vendor discovery)
Mines CPE vendors on confirmed-Yes and keyword-matched CVEs that `vendor_terms.csv` is missing, ranked by `new_yield` (CVEs neither text method already found). Read-only outside its one output file: `data/vendor-search/vendor_candidates.csv`. Never edits `vendor_terms.csv` — candidates are for a human to vet.

| Flag | Description |
|------|-------------|
| `<category> [<category> ...]` | One or more category slugs (omit when using `--all`) |
| `--all` | Every category in `categories.csv` |
| `--min-evidence N` | Min distinct evidence CVEs (Tier A confirmed-Yes + Tier B keyword-matched, deduped) required before a vendor becomes a candidate (default: `1`) |

---

### `keyword_mining.py` — Stage 1 (automated keyword discovery)
Mines device-type n-grams (1-3 words) from confirmed-Yes CVE descriptions that `keyword_terms.csv` is missing, ranked by `new_yield` (CVEs neither text method already found). Read-only outside its two output files: `data/keyword-search/keyword_candidates.csv` and `keyword_candidates_brands.csv` (brand-like candidates routed to the vendor-mining side). Never edits `keyword_terms.csv` — candidates are for a human to vet.

| Flag | Description |
|------|-------------|
| `<category> [<category> ...]` | One or more category slugs (omit when using `--all`) |
| `--all` | Every category in `categories.csv` |
| `--top N` | Max candidates kept per category before yield scoring (default: `50`) |
| `--min-yes N` | Min Yes-doc frequency required for a candidate (default: `3`) |

---

### `cpe_product_scan.py` — Stage 1/2 (automated product-token discovery)
Mines CPE **product**-name tokens (`insteon:hub_firmware` → `hub`) that `cpe-product-tokens.csv` is missing, ranked by `n_new_cves` (CVEs in neither text method's known set nor the judgment store, any verdict). The third text surface after vendor mining (CPE vendor field) and keyword mining (description) — needs no evidence trail, the product name itself is the evidence. Read-only outside its one output file: `data/cpe-product-scan/product_candidates.csv`. Never edits `cpe-product-tokens.csv` or `vendor_terms.csv` — candidates are for a human to vet.

| Flag | Description |
|------|-------------|
| `<category> [<category> ...]` | One or more category slugs (omit when using `--all`) |
| `--all` | Every category in `categories.csv` |
| `--min-cves N` | Min new CVEs required for a product to be listed (default: `1`) |

---

### `recall_estimate.py` — Stage 6
Capture–recapture recall estimation over the vendor/keyword searches (+ optional CPE capture set).

| Flag | Description |
|------|-------------|
| `--three` | Add the three-source log-linear estimate for categories with a confirmed-Yes CPE seed (needs the snapshot) |
| `--population {raw,yes}` | `raw` (default) = candidate-CVE population; `yes` = true-positive population, scaling each cell by its review Yes-rate |
| `--isect-precision P` | Assumed Yes-rate of the unreviewed `V∩K` cell under `--population yes` (default 1.0) |
| `--categories …` | Restrict to a subset of category slugs |

---

### `cwe888_analysis.py` — Stage 7 (analysis)
Groups the CWEs of every confirmed-Yes CVE in the judgment store into the 23 primary clusters of the CWE-888 Software Fault Patterns view (method of the transportation IoT device study, Table III). CWEs not in the view are mapped via their view-1000 `ChildOf` parents, level by level, stopping at the first level with an 888 member — a CWE whose parents land in two clusters counts in both (e.g. CWE-798 → Predictability + Other). Legacy NVD category CWEs (CWE-399, CWE-264, …) have no ancestry into the view and are reported as unmapped. Needs `data/cwe/cwec_v4.12.xml[.zip]` (pinned to the paper's CWE-888 version). Writes `data/difference/cwe888_distribution.csv`, `cwe888_cve_map.csv`, `cwe888_matrix.md`.

| Flag | Description |
|------|-------------|
| `--store FILE` | Judgment store CSV (default: `data/difference/judgment_store.csv`) |
| `--snapshot FILE` | NVD snapshot with `cwe_ids` (default: `data/nvd-snapshot/nvd_all.csv`) |
| `--cwe-xml FILE` | CWE catalog XML, or `.zip` alongside (default: `data/cwe/cwec_v4.12.xml`) |
| `--categories FILE` | `categories.csv` for column ordering (default: `data/categories.csv`) |
| `--category SLUG` | Restrict to one category slug (repeatable; default: all) |
| `--out-dir DIR` | Output directory (default: `data/difference`) |

---

### Retired scripts — `scripts/_legacy/`
Superseded by the current pipeline; kept on disk for reference only, not part of any live workflow.

| Script | Superseded by |
|--------|---------------|
| `full_intersect.py` | `build_review_sets.py --direction intersection` |
| `full_difference.py` | `build_review_sets.py --direction vendor_only`; shared helpers moved to `review_lib.py` |
| `init_categories.py` | Self-scaffolding — `write_raw()` and every live builder create their own output directories on demand |
| `seed_judgment_store.py` | `finalize_judgments.py` now upserts the store on every run |
| `nvd_keyword_query.py` | `download_nvd.py` + `build_search.py` |
| `run_all_years.sh` | `build_search.py`; still useful as a per-year-feed template for building the snapshot itself |
