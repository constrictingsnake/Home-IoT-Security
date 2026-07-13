# Home IoT Security — CVE Research Pipeline

A research pipeline that maps real-world home IoT device brands to known CVEs from NIST's NVD,
organized by device category, using two complementary search methods audited by a triple-AI
review system. **This doc is how to run it.** For reviewer rules, the classification rubric, and
the design rationale behind each stage, see `CLAUDE.md`. For first-run result tables and worked
examples, see `docs/FIRST_RUN_RESULTS.md`. For the full per-script flag reference, see
`docs/SCRIPTS_REFERENCE.md`.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [One-Time Setup: Build the NVD Snapshot](#one-time-setup-build-the-nvd-snapshot)
- [Quick Start (orchestrator)](#quick-start-orchestrator)
- [Manual Stage-by-Stage Commands](#manual-stage-by-stage-commands)
- [Device Categories](#device-categories)
- [Scripts](#scripts)
- [Data Schemas](#data-schemas)

---

## Prerequisites

- **Python 3.14** at `/Library/Frameworks/Python.framework/Versions/3.14/bin/python3` — invoke as `python3`
- Dependencies: `pandas`, `openpyxl`, `numpy`, `requests`, `scipy` (install with `pip install pandas openpyxl numpy requests scipy`)
- `matplotlib`, `squarify` — only for `generate_cwe888_treemaps.py` (`pip install matplotlib squarify`)
- `tqdm` optional — adds progress bars to `cve_search.py` (`pip install tqdm`)
- **API keys** in a gitignored `.env` file (never hardcode):
  - `GEMINI_API_KEY` — for the Gemini/Gemma reviewer
  - `NVD_API_KEY` — for downloading the NVD snapshot (`download_nvd.py`). Get one free at <https://nvd.nist.gov/developers/request-an-api-key>; it raises the API rate limit dramatically and is strongly recommended.
  - Load with: `set -a; source .env; set +a`

---

## One-Time Setup: Build the NVD Snapshot

The entire pipeline runs against a single fixed offline snapshot (`data/nvd-snapshot/nvd_all.csv`) — pinning one download is what makes the keyword and vendor searches comparable and the study reproducible/citeable ("dataset as of `<date>`"). The file is gitignored (~290 MB / ~360k CVEs) but fully reproducible.

**Recommended — download the whole database via the NVD API:**

```bash
cd /path/to/Home-IoT-Security
set -a && source .env && set +a       # loads $NVD_API_KEY
python3 scripts/download_nvd.py        # → data/nvd-snapshot/nvd_all.csv
```

Resumable — after every completed page (2000 CVEs), progress is saved to
`data/nvd-snapshot/nvd_all.csv.progress.json` and rows are appended immediately. `Ctrl-C` to pause;
re-run the same command to resume (skips finished pages, de-dupes by CVE ID). A full run is
~360k CVEs / ~181 pages, ~2–3 hours. On a clean finish it writes `data/nvd-snapshot/SNAPSHOT.md`
itself (snapshot date + true CVE count).

**Fallback — build from per-year NVD 1.1 feeds** (if you prefer static feeds or the API is down):

```bash
# 1. Download nvdcve-1.1-<year>.json.gz for 2002-2026 from https://nvd.nist.gov/feeds/json/cve/1.1/ and gunzip
# 2. Convert each year to CSV
python3 scripts/cve_search.py --convert nvdcve-1.1-2024.json --csv-out nvd_2024.csv   # repeat per year
# 3. Merge into one deduplicated snapshot
python3 scripts/cve_search.py --merge nvd_2002.csv nvd_2003.csv ... nvd_2026.csv \
    --merged-out data/nvd-snapshot/nvd_all.csv
```

This route doesn't auto-write `SNAPSHOT.md` — fill in the provenance fields (snapshot date + total CVE count) by hand.

---

## Quick Start (orchestrator)

`scripts/pipeline.py` chains the idempotent steps and pauses only where a human is needed. This is
the recommended day-to-day path — use the [manual commands](#manual-stage-by-stage-commands) below
only when you need finer-grained control over a single stage.

```bash
# 1. Rebuild search -> review sets -> CPE expansion -> blind copies, then STOP for manual review.
python3 scripts/pipeline.py refresh
#   (add --rebuild-search to also recompute the searches; default builds only missing ones)

# 2. ... fill the blank Claude/Codex judgments (refresh prints the per-category blank counts) ...

# 3. Run Gemini + merge -> finalize (upserts judgment_store.csv) -> extract outstanding queue.
python3 scripts/pipeline.py settle --model gemma-4-31b-it --rps 0.30
#   (add --no-gemini to merge existing judgments only)

# Check term coverage / status at any time:
python3 scripts/pipeline.py status

# Optional, manual, run any time: mine CPE vendors missing from vendor_terms.csv.
# Writes a candidate list only (never edits vendor_terms.csv) — not chained into
# refresh/settle since accepting a candidate is a human decision.
python3 scripts/pipeline.py discover-vendors --all

# Optional, manual, run any time: mine CPE product-name tokens missing from
# cpe-product-tokens.csv. Same story — candidate list only, human decides.
python3 scripts/pipeline.py scan-products --all
```

Every step is judgment-preserving (see `CLAUDE.md` § Methodology Notes for the invariant), so
re-running `refresh`/`settle` is always safe.

---

## Manual Stage-by-Stage Commands

Full flag tables for every script are in `docs/SCRIPTS_REFERENCE.md`. Stage rationale and design
decisions are in `CLAUDE.md`.

### Stage 1 & 2 — Search (keyword + vendor)

Author terms in `data/keyword-search/keyword_terms.csv` and `data/vendor-search/vendor_terms.csv` (`slug,term`), then:

```bash
python3 scripts/build_search.py                        # both methods, all categories w/ active terms
python3 scripts/build_search.py --method keyword        # one method only
python3 scripts/build_search.py --categories cameras thermostat doorbell
```

Output: `data/keyword-search/keyword_<category>.csv`, `data/vendor-search/results_all_<category>.csv`.

### Stage 3 — Intersection and Difference

```bash
python3 scripts/build_review_sets.py data/categories.csv                       # all directions, all categories
python3 scripts/build_review_sets.py data/categories.csv --direction intersection
python3 scripts/make_review_copies.py --all --refresh    # fold new rows into the blind copies
```

Output: `data/difference/<category>/<direction>/01_raw.csv` for `vendor_only`, `keyword_only`, `intersection`.

### Stage 4 — Triple-AI Review

```bash
# 1. Raw sets (see Stage 3), then blind copies:
python3 scripts/make_review_copies.py <device>          # or --all

# 2. Claude fills data/difference/<device>/reviews/claude.csv
#    Codex fills  data/difference/<device>/reviews/codex.csv
#    (Judgment: Yes/No/Maybe. Confidence: High/Low. Rubric: data/difference/CLASSIFICATION_PROMPT.md)

# 3. Gemini + merge in one command:
set -a; source .env; set +a
python3 scripts/merge_judgments.py --reviews data/difference/<device>/reviews \
    --run-gemini --category "<device type phrase>" --model gemma-4-31b-it
# Or all categories at once:
python3 scripts/merge_judgments.py --all --run-gemini --model gemma-4-31b-it --rps 0.30

# 4. Human queue -> adjudicate -> finalize -> refresh outstanding queue:
python3 scripts/extract_human_review.py                  # outstanding-only queue
#   ... fill Human Verdict 1 & 2 in human_review_queue.csv ...
python3 scripts/finalize_judgments.py                    # persists verdicts into judgment_store.csv
python3 scripts/extract_human_review.py                  # drops the now-settled rows

# 5. Mine + prune:
python3 scripts/term_precision.py
```

Writes (per category): `reviews/{claude,codex,gemini}.csv` → `02_merged.csv` +
`02_high_confidence_audit.csv` → `02_needs_human_review.csv` → `03_final.csv`; combined:
`human_review_queue.csv`, `final_resolved.csv`, `judgment_store.csv`, `term_precision.csv`.

### Stage 5 — CPE Expansion

```bash
python3 scripts/cpe_expansion.py --all                     # writes candidates + cpe_expansion/01_raw.csv
python3 scripts/make_review_copies.py --all --refresh       # fold new rows into review copies
python3 scripts/merge_judgments.py --reviews data/difference/<cat>/reviews --run-gemini --category "<keyword>"
python3 scripts/extract_human_review.py
python3 scripts/finalize_judgments.py
```

Output: `data/difference/<cat>/09_cpe_expansion_candidates.csv`, `cpe_expansion/01_raw.csv`,
`data/difference/cpe_expansion_summary.csv`. See `CLAUDE.md` for the three guardrails and
`docs/FIRST_RUN_RESULTS.md` for first-run yield/precision numbers.

### Vendor Discovery — CPE Brand Mining (feeds back into Stage 2)

Automated counterpart to Stage 2's hand-compiled vendor list: mines `cpe_strings` on
confirmed-Yes and keyword-matched CVEs for vendors NVD already knows about that
`vendor_terms.csv` is missing, ranked by how many new CVEs adding them would pull.

```bash
python3 scripts/cpe_brand_mining.py --all                 # every category
python3 scripts/cpe_brand_mining.py hub streaming alarms  # subset
python3 scripts/cpe_brand_mining.py --all --min-evidence 2   # require >=2 evidence CVEs (default 1)
# or via the orchestrator:
python3 scripts/pipeline.py discover-vendors --all
```

Output: `data/vendor-search/vendor_candidates.csv` — a candidate list only, sorted by
`new_yield` desc within category. **It never edits `vendor_terms.csv`.** Review it, hand-add
accepted vendors to `vendor_terms.csv` (qualify with a product word if flagged
`mega-vendor`/`dictionary-word`, per the existing vendor-term convention), then re-run
`python3 scripts/pipeline.py refresh` to pull their CVEs into review. See `CLAUDE.md` and
`docs/plans/PLAN_cpe_brand_mining.md` for the algorithm and guardrails.

### Keyword Discovery — Keyword Mining (feeds back into Stage 1)

Automated counterpart to Stage 1's hand-compiled keyword list: mines confirmed-Yes CVE
descriptions for device-type n-grams that `keyword_terms.csv` is missing, ranked by how many
new CVEs adding them would pull.

```bash
python3 scripts/keyword_mining.py --all                   # every category
python3 scripts/keyword_mining.py hub streaming alarms    # subset
python3 scripts/keyword_mining.py --all --top 50 --min-yes 3   # plan defaults
# or via the orchestrator:
python3 scripts/pipeline.py mine-keywords --all
```

Output: `data/keyword-search/keyword_candidates.csv` — a candidate list only, sorted by
`new_yield` desc within category — plus `keyword_candidates_brands.csv` (brand-like n-grams
routed to the vendor-mining side instead). **It never edits `keyword_terms.csv`.** Review it,
hand-add accepted phrases to `keyword_terms.csv`, then re-run `python3 scripts/pipeline.py
refresh` to pull their CVEs into review. See `CLAUDE.md` and
`docs/plans/PLAN_keyword_mining.md` for the algorithm and guardrails.

### Product-Token Discovery — CPE Product Scan (the third text surface)

The last of three text surfaces: where vendor mining reads CPE **vendor** fields and keyword
mining reads **descriptions**, this reads CPE **product** fields — device nouns (`camera`,
`hub`, `alarm`) too generic for a description keyword but high-precision inside a product name
(`insteon:hub_firmware`, `yitechnology:yi_home_camera_firmware`). Needs no evidence trail at
all: the product name itself is the evidence.

```bash
python3 scripts/cpe_product_scan.py --all                  # every category with tokens
python3 scripts/cpe_product_scan.py hub cameras            # subset
python3 scripts/cpe_product_scan.py --all --min-cves 2     # drop 1-CVE products (default 1)
# or via the orchestrator:
python3 scripts/pipeline.py scan-products --all
```

Output: `data/cpe-product-scan/product_candidates.csv` — a candidate list only, sorted by
`n_new_cves` desc within category. **It never edits `cpe-product-tokens.csv` or
`vendor_terms.csv`.** Review it; an accepted product becomes an ordinary `vendor_terms.csv`
line (`hub,insteon`), then re-run `python3 scripts/pipeline.py refresh` to pull its CVEs into
review. See `CLAUDE.md` and `docs/plans/PLAN_cpe_product_scan.md` for the algorithm and guardrails.

### Stage 6 — Recall Estimation (Capture–Recapture)

```bash
python3 scripts/recall_estimate.py                        # two-source, all categories, raw population
python3 scripts/recall_estimate.py --three                # + three-source log-linear where a CPE set exists
python3 scripts/recall_estimate.py --population yes --isect-precision 0.9
```

Output → printed table + `data/difference/recall_estimate.csv`. See `CLAUDE.md` for the method and
`docs/FIRST_RUN_RESULTS.md` for first-run numbers.

### Stage 7 — CWE-888 Vulnerability-Class Analysis

```bash
python3 scripts/cwe888_analysis.py                        # all confirmed-Yes rows in the judgment store
python3 scripts/cwe888_analysis.py --category cameras     # restrict to one category (repeatable)
```

Groups every CWE on a confirmed-Yes CVE into the 23 primary clusters of the CWE-888
Software Fault Patterns view, per category — the same analysis as Table III of the
transportation IoT device study (`Onboarding-Docs/transportation_device_study.pdf`).
Requires the pinned CWE catalog: `curl -L -o data/cwe/cwec_v4.12.xml.zip
https://cwe.mitre.org/data/xml/cwec_v4.12.xml.zip` (v4.12 = the CWE-888 version the paper used).
Output → printed summary + `data/difference/cwe888_distribution.csv`,
`cwe888_cve_map.csv` (per-CWE audit trail), `cwe888_matrix.md` (Table-III-style matrix).

```bash
python3 scripts/generate_cwe888_table.py       # data/difference/cwe888_table.tex (Table III equivalent)
python3 scripts/generate_cwe888_treemaps.py    # docs/figures/cwe888_treemap_*.pdf (Figs. 2-4 equivalent)
```

Both read `cwe888_distribution.csv`, so they always agree with each other and with
`cwe888_matrix.md`. The table script needs its output pasted manually into
`docs/home_iot_security_report.tex` (see the comment above the inlined table — Overleaf
can't resolve a path outside its project root); the treemap script writes straight into
`docs/figures/`, which the report already `\includegraphics`-references, so no copy step
is needed there. Requires `matplotlib` and `squarify` (see Prerequisites).

### Stage 8 — CVSS Score Analysis

```bash
python3 scripts/cvss_analysis.py                          # all confirmed-Yes rows in the judgment store
python3 scripts/cvss_analysis.py --category cameras       # restrict to one category (repeatable)
python3 scripts/cvss_analysis.py --min-n 10                # raise the group-size floor for the stats test
```

Per-category CVSS score distribution and severity buckets (None/Low/Medium/High/Critical),
plus a Kruskal-Wallis omnibus test with Dunn's post-hoc pairwise comparisons
(Bonferroni-adjusted) — the same analysis as RQ2 of the transportation IoT device study
(`Onboarding-Docs/transportation_device_study.pdf`, Section V). Requires `scipy`
(`pip install scipy`). Categories with fewer than `--min-n` scored CVEs (default 5) are
excluded from the statistical test but still reported descriptively.
Output → printed summary + `data/difference/cvss_distribution.csv`, `cvss_severity.csv`,
`cvss_dunn_pairwise.csv` (only if the omnibus test is significant), `cvss_matrix.md`.

### Refreshing difference sets without losing review work

When vendor/keyword terms change, use the [Quick Start](#quick-start-orchestrator) orchestrator, or by hand:

```bash
python3 scripts/build_review_sets.py data/categories.csv --direction all --overwrite
python3 scripts/make_review_copies.py --all --refresh    # restores prior judgments from judgment_store.csv
# ... re-judge only the new (blank) rows ...
python3 scripts/merge_judgments.py --all
python3 scripts/finalize_judgments.py                    # persist verdicts -> judgment_store.csv
python3 scripts/extract_human_review.py                  # regenerate outstanding-only queue
```

See `CLAUDE.md` for why this preserves prior work and `docs/FIRST_RUN_RESULTS.md` for a worked example.

---

## Device Categories

The frozen analysis scope has 24 categories defined in `data/categories.csv` (`slug, label, scope_note`). Vendor search files are at `data/vendor-search/results_all_<slug>.csv`. Run `python3 scripts/pipeline.py status` for live per-category term coverage.

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

**Out of scope:** `gameconsoles`, VR headsets, plain routers/modems/switches. See `CLAUDE.md` for the scoping criteria.

---

## Scripts

One line per script — full flag tables in `docs/SCRIPTS_REFERENCE.md`.

| Script | Stage | Purpose |
|--------|-------|---------|
| `download_nvd.py` | Setup | Bulk-download the NVD snapshot via the API (resumable) |
| `cve_search.py` | 1 & 2 (engine) | Core NVD search engine: `--convert`, `--merge`, `--input` modes |
| `build_search.py` | 1 & 2 | Per-category keyword + vendor search against the fixed snapshot |
| `review_lib.py` | 3/4 (shared lib) | Shared helpers: `load_cves`, `difference_rows`, `intersection_rows`, `write_raw` |
| `build_review_sets.py` | 3/4 | Batch-generates `01_raw.csv` for `vendor_only` / `keyword_only` / `intersection` |
| `make_review_copies.py` | 4 | Builds blind `reviews/{claude,codex,gemini}.csv`, pre-filled from the judgment store |
| `gemini_classify.py` | 4 (lowest level) | Core Gemini API caller; fills `gemini.csv` |
| `merge_judgments.py` | 4 (mid level) | Runs Gemini (optional) + merges all 3 copies into `02_merged.csv` |
| `pipeline.py` | orchestrator | `refresh` / `settle` / `status` / `discover-vendors` / `mine-keywords` / `scan-products` — chains the idempotent steps |
| `extract_human_review.py` | 4 | Regenerates the **outstanding-only** human-review queue (drops rows already settled in the store) |
| `finalize_judgments.py` | 4 | Folds human verdicts into `Final Judgment`; upserts AI + raw human verdicts into `judgment_store.csv` |
| `term_precision.py` | 8 (pruning) | Per-term precision from settled judgments |
| `cpe_expansion.py` | 5 | Third discovery method: CPE-based densification of confirmed products |
| `cpe_brand_mining.py` | 2 (discovery) | Mines CPE vendors missing from `vendor_terms.csv`; writes a candidate list, never auto-adds |
| `keyword_mining.py` | 1 (discovery) | Mines device-type n-grams missing from `keyword_terms.csv`; writes a candidate list, never auto-adds |
| `cpe_product_scan.py` | 1/2 (discovery) | Mines CPE product-name tokens missing from `cpe-product-tokens.csv`; writes a candidate list, never auto-adds |
| `recall_estimate.py` | 6 | Capture–recapture recall estimate (Chapman + 3-source log-linear) |
| `cwe888_analysis.py` | 7 (analysis) | CWE-888 primary-class distribution over confirmed-Yes CVEs |
| `generate_cwe888_table.py` | 7 (report) | LaTeX Table III equivalent, shaded top-6 classes per category |
| `generate_cwe888_treemaps.py` | 7 (report) | LaTeX Figs. 2-4 equivalent — area-proportional CWE-888 treemaps |
| `cvss_analysis.py` | 8 (analysis) | CVSS score distribution + Kruskal-Wallis/Dunn's test over confirmed-Yes CVEs |

Retired scripts live in `scripts/_legacy/` (superseded-by table in `docs/SCRIPTS_REFERENCE.md`).

---

## Data Schemas

| File | Key columns |
|------|-------------|
| `categories.csv` | `slug, label, scope_note` |
| `keyword_terms.csv`, `vendor_terms.csv` | `slug, term` |
| `keyword_<cat>.csv`, `results_all_<cat>.csv` | `cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings, matched_terms` |
| `term_precision.csv` | `method, category, term, n_judged, n_yes, n_no, precision, prune_candidate` |
| `<cat>/09_cpe_expansion_candidates.csv` | `cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings, seed_cpe, Discovery Method` |
| `cpe_expansion_summary.csv` | `category, yes_seeds, device_seeds, app_cpe_dropped, matched, already_known, new_candidates` |
| `vendor_candidates.csv` | `category, vendor, n_yes_evidence, n_keyword_evidence, covered_elsewhere_slug, snapshot_total, new_yield, risk_flags, sample_cves, sample_descriptions` |
| `cpe-product-tokens.csv` | `slug, token` |
| `product_candidates.csv` | `category, vendor_product, matched_tokens, n_new_cves, covered_elsewhere_slug, risk_flags, sample_cves, sample_descriptions` |
| `recall_estimate.csv` | `category, method, n_vendor, n_keyword, n_both, n_observed, N_hat, N_lo, N_hi, recall, recall_lo, recall_hi, confidence` |
| `cwe888_distribution.csv` | `category, cwe888_class, n_cwes, pct` (plus an `ALL` pseudo-category) |
| `cwe888_cve_map.csv` | `category, cve_id, cwe_id, cwe888_classes, map_depth` (classes pipe-separated; depth 0 = in the 888 view, ≥1 = via parents, −1 = unmappable) |
| `<cat>/<dir>/01_raw.csv` | `Difference Type, cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings` |
| `<cat>/reviews/{ai}.csv` | raw columns + `<AI> Judgment, <AI> Confidence, <AI> Reasoning` |
| `<cat>/02_merged.csv` | raw columns + all 9 AI columns + `Review Status, Needs Human Review, Review Reason` |
| `<cat>/02_needs_human_review.csv` | `Verdicts, Review Reason` + raw + AI reasoning + `Human Verdict 1, Human Notes 1, Human Verdict 2, Human Notes 2` (outstanding rows only) |
| `<cat>/03_final.csv` | merged columns + `Final Judgment, Final Source` |
| `human_review_queue.csv` | same as `02_needs_human_review.csv` + leading `Category, Direction` |
| `final_resolved.csv` | same as `03_final.csv` + leading `Category, Direction` |
| `judgment_store.csv` | `category, cve_id, Difference Type` + all 9 AI columns + `Final Judgment, Final Source` + `Human Verdict 1, Human Notes 1, Human Verdict 2, Human Notes 2` |
