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
- [Stage 9 — CPE Expansion](#stage-9--cpe-expansion)
- [Stage 10 — Recall Estimation (Capture–Recapture)](#stage-10--recall-estimation-capturerecapture)
- [Refreshing Difference Sets Without Losing Review Work](#refreshing-difference-sets-without-losing-review-work)
- [Device Categories](#device-categories)
- [Scripts](#scripts)
- [Data Schemas](#data-schemas)
- [Key Design Decisions](#key-design-decisions)

---

## What This Project Does

The pipeline has two text-based CVE discovery methods that are cross-referenced against each other:

- **Vendor search (Jason):** searches NVD for manufacturer/brand names (e.g. "Nest", "Ring", "Ecobee") → produces `data/vendor-search/results_all_<category>.xlsx`
- **Keyword search (Lizzie):** searches NVD for generic device-type phrases (e.g. "video doorbell", "ip camera") → produces `data/keyword-search/keyword_<category>.csv`

Both methods run against the same fixed offline NVD snapshot to ensure the results are directly comparable and the study is reproducible.

A third, structural method — **CPE expansion (Stage 9)** — runs *after* review: once a device's `vendor:product` CPE has been confirmed a true match, it pulls in every other CVE that NVD itself attributes to that same CPE, catching terse entries whose text neither search could match.

The set difference (CVEs found by one method but not the other) is reviewed by three independent AI reviewers (Claude Code, Codex, and Gemini) to classify each CVE as a true match or false positive.

Because the two searches are near-independent capture lists of the same underlying CVE population, **Stage 10 (recall estimation)** turns their overlap into a capture–recapture estimate of *how many in-scope CVEs exist per category and what fraction the pipeline found* — the recall counterpart to the precision that review measures.

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

**Output columns:** `cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings, matched_terms`

The trailing **`matched_terms`** column (pipe-separated, like `cwe_ids`) records which of the category's terms pulled each row in — a CVE hit by two terms lists both. It is what lets `term_precision.py` (Step 8) score every term's false-positive rate from the settled judgments. The fixed NVD snapshot itself does **not** carry this column — it is added only on the search outputs.

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

**Output columns:** `cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings, matched_terms` — identical to the keyword files. The trailing `matched_terms` column records which brand term(s) matched each row (pipe-separated), feeding `term_precision.py` (Step 8).

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

**Step 8 — Mine resolved-Yes rows and score term precision**

Two complementary loops close the quality gap in opposite directions:

- **Recall (mining).** Inspect the resolved-Yes rows in `03_final.csv` for keyword phrases not yet in `keyword_terms.csv`. Add them, re-run `build_keyword_search.py`, and document the additions in `03_keyword_additions.md`.
- **Precision (pruning).** Run the term-precision report to find terms that drag in mostly false positives:

  ```bash
  python3 scripts/term_precision.py
  # Tune the prune threshold:
  python3 scripts/term_precision.py --min-n 3 --threshold 0.15
  ```

  It joins the settled `Final Judgment`s in `final_resolved.csv` back to the `matched_terms` attribution written by the builders, and writes `data/difference/term_precision.csv` — one row per `(method, category, term)` with `n_judged`, `n_yes`, `precision`, and a `prune_candidate` flag (default: ≥5 judged rows at ≤10% precision). A noisy term (e.g. a brand that collides with unrelated software, or an over-broad vendor entry pulling in generic hardware) shows up as a line item to prune from `keyword_terms.csv` / `vendor_terms.csv` instead of requiring a manual disagreement autopsy.

  > **Scope caveat:** `final_resolved.csv` only contains the **difference set** (CVEs unique to one method). The intersection (matched by both) is never reviewed, so this is per-term precision *on the difference set*, not on all of a term's matches — read it as a prioritized prune list, not a global precision. A term must have been re-attributed by a builder rebuilt with the `matched_terms` column, and the Stage-4 pipeline re-run, before it can be scored.

---

## Stage 9 — CPE Expansion

Both text methods key off *language* — brand strings and device phrases matched against a CVE's description and CPE text. Terse entries evade them: *"An OS command injection vulnerability exists in the XCMD setAlexa functionality of Abode Systems, Inc. iota…"* names the device only in passing, and `abode` is too collision-prone to keyword on. But NVD's structured **CPE** attributes that CVE cleanly to `goabode:iota_all-in-one_security_kit`. CPE expansion mines that structured signal.

**How it works.** For each category, seed from the rows already settled `Final Judgment = Yes`, take the `vendor:product` CPEs on those confirmed rows, and scan the snapshot for *every* CVE NVD attributes to the same `vendor:product` — then subtract everything the two text methods already found. What remains is new.

It is a **densification** method, not a discovery method: it can only find more CVEs for products already confirmed, never a new brand. Recall is bounded to "everything NVD attributed to devices we already caught."

```bash
python3 scripts/cpe_expansion.py alarms        # one category
python3 scripts/cpe_expansion.py --all         # every seeded category + summary CSV
python3 scripts/cpe_expansion.py cameras --no-part-filter   # A/B the leak guardrail
```

Per-category output → `data/difference/<cat>/09_cpe_expansion_candidates.csv` (tagged `Discovery Method = cpe_expansion`, with the `seed_cpe` that pulled each row in). The `--all` run also writes `data/difference/cpe_expansion_summary.csv`.

**Routing into Stage 4.** By default the script *also* writes `data/difference/<cat>/cpe_expansion/01_raw.csv` — a third review **direction** alongside `vendor_only` / `keyword_only`, in the exact Stage-4 raw schema. It is disjoint from both by construction (these CVEs are, by definition, in neither text method's output), so the `(category, cve_id)` key stays unique and `finalize_judgments.py` / `extract_human_review.py` — which read `Difference Type` per row — need no changes. `make_review_copies.py` concatenates all three directions automatically. So the candidates flow through the *same* review loop as everything else:

```bash
python3 scripts/cpe_expansion.py --all           # writes candidates + cpe_expansion/01_raw.csv
python3 scripts/make_review_copies.py alarms     # pulls all 3 directions into blind copies
# Claude/Codex fill reviews/*.csv; then:
python3 scripts/merge_judgments.py --reviews data/difference/alarms/reviews --run-gemini --category alarm
python3 scripts/extract_human_review.py          # flagged rows -> human queue
python3 scripts/finalize_judgments.py            # settle + upsert judgment_store.csv
```

Pass `--no-stage4` to `cpe_expansion.py` for a report-only run that writes no `01_raw.csv`. The `09_*_candidates.csv` file is retained separately as the `seed_cpe` attribution source (the CPE-expansion analogue of the builders' `matched_terms`).

**Three guardrails** keep it honest:

1. **Seed only from confirmed `Yes`** rows (`judgment_store.csv`) — never an unreviewed CVE.
2. **Device-CPE granularity.** (a) `vendor:product` only, never vendor-only — `tp-link:tapo_p100`, not all of `tp-link` (which would drag in every Archer router). (b) `part ∈ {o, h}` only — firmware/hardware. A co-listed `part=a` application/library CPE riding on a device's Yes row (e.g. `openweave:openweave-core`, Nest's protocol library, sitting on a camera CVE) is dropped, so expansion stays pinned to the physical device, not its dependencies.
3. **Candidates are never auto-included.** They leave as an unreviewed set that still goes through Stage 4 (or an audit sample). High CPE precision ≠ zero false positives — see the smartplugs miss below.

**First-run results (2026-07-02, 8 seeded categories).** 52 new candidate CVEs the two text methods never found:

| Category | Confirmed-Yes seeds | New candidates | Note |
|----------|--------------------:|---------------:|------|
| **alarms** | 12 | **38** | Abode iota security kit — a 2022 researcher CVE dump, brand buried in terse text |
| cameras | 255 | 11 | Momentum Axel, TP-Link NC-series, Owlet Cam |
| babymonitor | 8 | 2 | D-Link EyeOn baby cameras |
| smartplugs | 7 | 1 | seed-inheritance miss (see below) |
| doorbell / robotvacuum / smartspeakers / thermostat | — | 0 | text search already had complete coverage of their confirmed products |
| **Total** | | **52** | |

- **Yield is spiky and is *not* predicted by a category's false-positive rate.** robotvacuum (a deliberate cameras-FP-rate match) returned **0** — its confirmed products' CVEs all name the brand in text, so the vendor search already had them. alarms returned 38 because one prolific product (Abode iota) had a wall of tersely-described CVEs. The predictor is "confirmed products with prolific, terse CVE families," not difference-set noise.
- **Precision (Claude single-review spot-check, `cpe_expansion_precision_spotcheck.csv`): 51/52 = 98% category-correct.** The one miss — `CVE-2024-10523`, the TP-Link Tapo **H100** — is a genuine home IoT device but a *hub*, not a plug; it traces to a mis-confirmed seed (`tp-link:tapo_h100` wrongly settled `Yes` under `smartplugs`). The method faithfully propagated a *seed* error, not a method fault — and Stage-4 review of the candidate would catch it.
- **The part filter earns its place.** It drops 70 app/lib seed CPEs and prevents 4 library-leak candidates (openweave ×2 in cameras, a Tapo app CPE ×2 in smartplugs). Run `--no-part-filter` to see the 56-candidate unfiltered set for comparison.

> **Open item for review:** the 52 candidates are still unreviewed by the full triple-AI + human pipeline. The 98% is a Claude-only first pass. The routing is now wired (each category's candidates sit in a `cpe_expansion/01_raw.csv` ready for `make_review_copies.py`) — running the triple-AI + human loop over them (starting with the 38 alarms rows) is the next step to get a defensible precision number and fold the true matches into the dataset.

---

## Stage 10 — Recall Estimation (Capture–Recapture)

Review measures **precision** (how many matched CVEs are real). It says nothing about **recall** — *what fraction of the real in-scope CVEs did the pipeline find?* Stage 10 answers that without any new labelling, by treating the vendor and keyword searches as two independent **capture occasions** of the same underlying CVE population (Lincoln–Petersen mark-recapture). If the two methods overlap a lot relative to their sizes, they have jointly covered most of the population; if they barely overlap, a large unseen remainder is implied.

```bash
python3 scripts/recall_estimate.py                       # two-source, all categories, raw population
python3 scripts/recall_estimate.py --three               # + three-source log-linear where a CPE set exists
python3 scripts/recall_estimate.py --population yes       # true-positive population (needs review labels)
python3 scripts/recall_estimate.py --population yes --isect-precision 0.9   # sensitivity on the unreviewed V∩K cell
```

Output → printed table + `data/difference/recall_estimate.csv`.

**Two-source (Chapman).** For each category with sizes `V`, `K` and overlap `m = |V∩K|`, the population is estimated by the Chapman estimator (the bias-corrected Lincoln–Petersen, stable at small overlap), `N̂ = (V+1)(K+1)/(m+1) − 1`, with a **log-normal 95% CI (Chao)** that never falls below the observed count. Combined recall = `|V∪K| / N̂`.

**Three-source (`--three`).** Adds `C` = every CVE NVD attributes to a confirmed-Yes device CPE — the **full** Stage-9 capture set, reconstructed here from the snapshot *with its overlaps against V and K intact*. (The stored `09_*_candidates.csv` keeps only `C∖(V∪K)`, which discards exactly the overlap cells this needs.) A hierarchical Poisson **log-linear model** is fit over the 7 observable inclusion cells, selected by AIC, and the unobserved "missed by all three" cell is extrapolated. Three sources let the data *estimate* pairwise dependence instead of assuming it away — the main weakness of naive two-source LP, since V and K share an engine, snapshot, and text fields and are positively correlated. CIs come from an **800-replicate nonparametric bootstrap** that re-selects the model each replicate (so the interval absorbs model-selection uncertainty, not just sampling).

**First-run results (2026-07-02, raw candidate population).**

| Category | V | K | ∩ | Observed | N̂ (2-src) | 95% CI | Recall | 3-src N̂ |
|----------|--:|--:|--:|---------:|----------:|--------|-------:|--------:|
| cameras | 3153 | 715 | 355 | 3513 | **6342** | 5936–6817 | **0.55** | 6325 |
| streaming | 199 | 277 | 17 | 459 | 3088 | 2086–4708 | 0.15 | — |
| hub | 92 | 43 | 5 | 130 | 681 | 380–1345 | 0.19 | — |
| thermostat | 71 | 15 | 11 | 75 | 95 | 82–135 | 0.79 | 93 |
| alarms | 103 | 69 | 11 | 161 | 606 | 400–987 | 0.27 | 574 |
| doorbell | 58 | 47 | 21 | 84 | 128 | 106–170 | 0.66 | 110 |
| **POOLED** | | | | **4967** | **12141** | 10801–13789 | **0.41** | — |

- **The estimator validates itself where data is rich.** On `cameras` the independent two-source (6342) and three-source (6325) estimates land **0.3 % apart** — a convergence worth citing.
- **Low-recall categories are exactly the known-thin brand lists** (`streaming` 0.15, `hub` 0.19, `lighting`/`ev-charging` ~0.28). The estimator independently rediscovers where the vendor lists need work, and gives a prioritized recall-improvement queue.
- **`recall = 1.0` rows are flagged `degenerate`, not real** (babymonitor, pet, fans, sensors). There one list is a strict subset of the other (`m = min(V,K)`), so recapture carries no information and `N̂` collapses to the larger list. These are **excluded from the POOLED total.**

**Estimands (`--population`).** `raw` (default) estimates the population of *candidate* CVEs the searches could match (true + false positives) — recall of the **search stage**, available now for every category. `yes` estimates the population of *true* in-scope CVEs by scaling each cell by its review Yes-rate — the scientifically interesting number, but it needs labels. Only `alarms` is currently labelled (and only its `vendor_only` direction), so `yes` proxies the unlabelled side and marks the row `assumed-rate`; the `V∩K` cell is **never reviewed** by the pipeline, so its precision is a supplied assumption (`--isect-precision`, default 1.0) with a printed sensitivity band.

**Honest caveats (printed with every run):**

1. **Two-source N̂ is biased *down* by V–K positive dependence** → its recall is an **upper bound**. Prefer the three-source figure where present; it is the one built to handle the dependence.
2. **`C` is not a clean third capture.** It is seeded from already-confirmed products, so it cannot reach a true CVE whose product never appeared in V/K. Read its `N̂` as "population reachable through confirmed products," and the three-source estimate as relaxing the V–K independence assumption, not as a fully independent third list.
3. **The `yes` population is not yet paper-grade** — it needs a labelled `keyword_only` direction and a small labelled `V∩K` sample for 2–3 rich categories (cameras, doorbell, thermostat) before it yields a defensible true-positive recall. The `raw` (search-stage) recall is defensible today.
4. **Pooled CI** sums per-category Chapman variances (categories are disjoint CVE populations, so their estimates are treated as independent) and inverts a log-normal band on the pooled unseen count.

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
| `--scope FILE` | Path to `category_scope.csv`, the per-category in/out scope notes injected into the prompt (default: `data/difference/category_scope.csv`) |
| `--slug SLUG` | Category slug used to look up the scope note (default: derived from the `csv` path, i.e. the `<slug>` in `…/<slug>/reviews/gemini.csv`). A missing note is non-fatal — the pass runs without it |
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

### `term_precision.py` — Stage 8 (reverse: pruning)
Scores every search term's precision from the settled judgments. Reads `final_resolved.csv`, and for each judged `Yes`/`No` row looks up which term(s) matched that CVE — from the builder output chosen by direction (`vendor_only` → `results_all_<cat>.xlsx`, `keyword_only` → `keyword_<cat>.csv`, both via the `matched_terms` column). Writes `data/difference/term_precision.csv` (one row per `method, category, term` with `n_judged, n_yes, n_no, precision, prune_candidate`) and prints the prune candidates. Handles builder outputs that predate the `matched_terms` column gracefully (warns and counts them unattributed).

| Flag | Description |
|------|-------------|
| `--diff-dir DIR` | Directory holding `final_resolved.csv` (default: `data/difference`) |
| `--out FILE` | Output CSV (default: `<diff-dir>/term_precision.csv`) |
| `--min-n N` | Min judged rows before a term can be a prune candidate (default: `5`) |
| `--threshold FLOAT` | Precision at or below this flags a prune candidate (default: `0.10`) |

---

### `cpe_expansion.py` — Stage 9
The third discovery method. Seeds from the confirmed-`Yes` rows in `judgment_store.csv`, extracts their device `vendor:product` CPEs, and scans the snapshot for every other CVE NVD attributes to the same CPE — minus everything the two text methods already found. Writes `data/difference/<cat>/09_cpe_expansion_candidates.csv` per category and (with `--all`) `data/difference/cpe_expansion_summary.csv`. Candidates are unreviewed and feed Stage 4, never the dataset directly.

| Flag | Description |
|------|-------------|
| `<category>` | Run one category (omit when using `--all`) |
| `--all` | Run every category with a confirmed-Yes seed, and write the summary CSV |
| `--no-part-filter` | Disable the `part ∈ {o, h}` guardrail — for A/B'ing how many app/library CPEs it filters out |

---

### `recall_estimate.py` — Stage 10
Capture–recapture recall estimation. Treats the vendor and keyword searches as two capture occasions and computes, per category, the Chapman population estimate `N̂` with a log-normal 95% CI and the implied combined recall. With `--three` it reconstructs the full Stage-9 CPE capture set from the snapshot (reusing `cpe_expansion.py`'s scan) and fits an AIC-selected Poisson log-linear model with a bootstrap CI. Writes `data/difference/recall_estimate.csv` and prints a table with a `POOLED` cross-category total. Read-only over the pipeline outputs — computes nothing that changes the dataset.

| Flag | Description |
|------|-------------|
| `--three` | Add the three-source log-linear estimate for categories with a confirmed-Yes CPE seed (needs the snapshot) |
| `--population {raw,yes}` | `raw` (default) = candidate-CVE population (search-stage recall); `yes` = true-positive population, scaling each cell by its review Yes-rate |
| `--isect-precision P` | Assumed Yes-rate of the unreviewed `V∩K` cell under `--population yes` (default 1.0); re-run to test sensitivity |
| `--categories …` | Restrict to a subset of category slugs |

---

### `nvd_keyword_query.py` — Legacy
Old live-NVD-API querier. Retired and no longer part of the pipeline. Kept on disk for reference only. Use `build_keyword_search.py` instead.

---

## Data Schemas

| File | Key columns |
|------|-------------|
| `keyword_terms.csv` | `slug, term` |
| `keyword_<cat>.csv` | `cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings, matched_terms` |
| `results_all_*.xlsx` | `cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings, matched_terms` |
| `term_precision.csv` | `method, category, term, n_judged, n_yes, n_no, precision, prune_candidate` |
| `<cat>/09_cpe_expansion_candidates.csv` | `cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings, seed_cpe, Discovery Method` |
| `cpe_expansion_summary.csv` | `category, yes_seeds, device_seeds, app_cpe_dropped, matched, already_known, new_candidates` |
| `recall_estimate.csv` | `category, method, n_vendor, n_keyword, n_both, n_observed, N_hat, N_lo, N_hi, recall, recall_lo, recall_hi, confidence` (`POOLED` row = cross-category total; `confidence` ∈ ok/low/degenerate/assumed-rate/pooled) |
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

**Why does CPE expansion run *after* review, not as a third search up front?** It trades breadth for precision. Seeding only from confirmed-`Yes` CPEs means it can never invent a new brand — but every CVE it returns is already attributed by NVD to a device a human/consensus signed off on, so it is far higher-precision than a third text search would be. It is the natural completion of the two-method design: vendor terms find brands, keyword terms find device language, CPE expansion finds everything NVD itself already attributed to a confirmed device. Because it depends on settled judgments, it slots in at Stage 9, after the review loop, and feeds its output back through that same loop.

**What counts as a home IoT device?** A device must be internet-connected, be a special-purpose sensor/appliance/embedded system (not general-purpose IT), be intended for a private residence, have a monitoring/automation/control function (or serve as a home-control hub for other IoT devices), and be maintained by a non-expert consumer. Game consoles fail on device class and function. Streaming TVs qualify because their platforms act as Matter/Thread controllers. Plain routers are excluded — they are threat-model context, not study subjects.
