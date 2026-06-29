# Home IoT Security — Project Guide

## What This Project Is

A security research pipeline that systematically maps real-world home IoT device brands to known CVEs from NIST's National Vulnerability Database (NVD), organized by device category. The goal is to build a comprehensive dataset of vulnerability exposure across consumer IoT device types (see *Definition of a Home IoT Device* for the scoping criteria; game consoles remain excluded as entertainment, while streaming TVs/sticks were re-admitted as **home-control surfaces** — see criterion 4), with manual review to eliminate false positives. The original 13 vendor categories have since been **expanded and frozen to ~22 analysis categories** — see *Finalized Category Scope*.

---

## Three-Stage Pipeline

### Two search methods (researcher attribution)
The project combines two complementary CVE-discovery methods, each owned by a different researcher:

- **Vendor-based search — Jason.** Compiles a list of manufacturers/brands per device type, then searches NVD for those vendor/brand names. Produces the `results_all_*.xlsx` files. **As of the vendor overhaul (2026-06)** this runs the same way as the keyword search — **offline, per-category, through the same engine** (`build_vendor_search.py` → `cve_search.py`'s `filter_by_keywords` against the one fixed NVD snapshot, matching description **+ CPE**) — see Stage 2. Brand terms live in `data/vendor-search/vendor_terms.csv` (`slug,term`). More prone to false positives, since brand names overlap with unrelated products. *(Legacy path: the old `cve_search.py --input` / `run_all_years.sh` per-year run; the prior `results_all_*.xlsx` are backed up under `data/vendor-search/_backup_pre_rebuild_2026-06-28/`, and the `--keywords` strings in `Devices List.docx` are Jason's original vendor/brand strings — now recovered into `vendor_terms.csv` and verified to reproduce the committed results, see Stage 2.)*
- **Keyword-based search — Lizzie.** Searches NVD for generic device-type keywords (e.g. "security camera", "ip camera"). **As of the keyword overhaul (2026-06)** this runs **offline, per-category, through the same engine as the vendor search** (`cve_search.py` against one fixed NVD snapshot, matching description **+ CPE**) — see Stage 1. Produces `data/keyword-search/keyword_<category>.csv`, one file per analysis category. `full_intersect.py` (Stage 3) is also Lizzie's — it intersects the two methods' outputs. *(The legacy live-API workbooks and groupings are retired under `data/keyword-search/_legacy/`.)*

Combining both methods yields the most comprehensive per-device CVE list.

### Stage 1 — `build_keyword_search.py` (Offline per-category keyword search)
The keyword search was **overhauled (2026-06)** to fix the vendor↔keyword comparability gap: it
now runs **offline** through the **same engine** as the vendor search (`cve_search.py`'s
`filter_by_keywords`) against **one fixed NVD snapshot**, matching **description + CPE**, and emits
**one file per analysis category** in the common schema.

- **User-authored keywords.** Terms live in `data/keyword-search/keyword_terms.csv` (`slug,term`,
  `#`-comment aware). This file ships **empty** — every category present but commented out, with an
  example line showing where to add terms. **You fill in your own** device-phrase terms per category.
  Suggested starter terms are in `data/keyword-search/keyword_terms.suggested.csv` (a copy-from menu
  the driver **never** reads).
- **Scope:** device-type **phrases only** (e.g. `ip camera`, `video doorbell`). No brands, protocols,
  firmware, or umbrella terms — brand discovery is the vendor search's job.
- **Whole-word matching.** Both builders pass `whole_word=True` to `filter_by_keywords`, so a short
  token must sit on alphanumeric boundaries (a trailing plural `s`/`es` is allowed). This blocks the
  substring bombs that inflated categories (`nvr`→`nvram`, `trv`→`iccattrval`, `evse`→`prevsell`,
  `landroid`→`bailandroid`) while still matching plurals; non-alphanumerics (`:` `_` `-` in CPE) act
  as boundaries, so CPE matching is unaffected.
- **Snapshot:** build once from per-year NVD feeds — see `data/nvd-snapshot/SNAPSHOT.md` and the
  `cve_search.py` header (STEP 1–2). The snapshot makes the dataset reproducible/citeable ("as of <date>").
- **Run:** `python3 scripts/build_keyword_search.py` (loads the snapshot once, filters per category).
  Categories with no terms are **skipped with a message**, not an error. Use `--categories <slug…>`
  for a subset, `--snapshot`/`--terms` to override paths, `--overwrite` to rebuild existing outputs.
- **Output:** `data/keyword-search/keyword_<category>.csv` with columns `cve_id, published,
  description, cvss_score, cvss_version, cwe_ids, cpe_strings` — **identical to the vendor files and
  to `01_raw.csv`**, now *with CPE*, so the two methods are directly comparable and the classification
  rubric (which leans on CPE) works on keyword rows too.

*(Legacy: the old live-API querier `nvd_keyword_query.py` and its grouped `Category*.xlsx` workbooks
are retired under `data/keyword-search/_legacy/`. The script remains for reference but is no longer
the keyword-search path.)*

### Stage 2 — `build_vendor_search.py` (Offline per-category vendor/brand search)
The vendor search was **overhauled (2026-06)** to match the keyword side: it now runs **offline**
through the **same engine** as the keyword search (`cve_search.py`'s `filter_by_keywords`,
description **+ CPE**, `whole_word=True`) against the **same fixed NVD snapshot**, and emits one
`results_all_<category>.xlsx` per analysis category in the common schema. This is the change that
**closes the vendor↔keyword comparability gap** — the only remaining difference between the two
methods is now the search *terms* (brands vs. device-phrases).

- **Brand terms.** Authored in `data/vendor-search/vendor_terms.csv` (`slug,term`, same format and
  parser as `keyword_terms.csv` — `#`-comment / blank-line aware). Brands are **qualified** with a
  product word where the bare name overlaps unrelated products (e.g. `carrier infinity`, not
  `carrier`) to suppress false positives. A category with no active terms is skipped with a message.
  **This file is now the complete, reproducible source for *all* 25 categories.** The **15 original**
  categories' terms were recovered from the exact `--keywords` strings in `Devices List.docx`
  (Jason's brand strings; `Omitted:` terms excluded) and **verified (2026-06-28)**: rebuilding each
  through `build_vendor_search.py` reproduces the committed `results_all_<cat>.xlsx` CVE sets
  **exactly** for all 14 in-scope categories (gameconsoles is out of scope; its xlsx was regenerated
  on the snapshot so it too derives reproducibly from these terms — its old file was a stale
  pre-`whole_word` build). The **10 new** categories' terms are Claude-drafted
  (`vendor_terms_proposed.csv` + `PROPOSED_brand_lists.md` are the original draft + companion doc).
- **Run:** `python3 scripts/build_vendor_search.py` (loads the snapshot once, filters per category).
  Same flags as the keyword builder: `--categories <slug…>`, `--snapshot`/`--terms`, `--overwrite`,
  `--outdir`.
- **Output:** `data/vendor-search/results_all_<category>.xlsx`, columns `cve_id, published,
  description, cvss_score, cvss_version, cwe_ids, cpe_strings` — **identical to the keyword files and
  to `01_raw.csv`**.

**Engine — `cve_search.py`** (the shared offline searcher behind Stage 1 and Stage 2):
- Designed for local NVD JSON year-feeds (2002–2026); builds the snapshot both builders read.
- Three modes: `--convert` (JSON→CSV), `--merge` (deduplicate multiple CSVs), `--input` (keyword search).
- `filter_by_keywords` searches description **+ CPE**; `whole_word=True` enables boundary-aware matching (see Stage 1).
- Supports NVD 1.1 and NVD 2.0 JSON formats; output columns as above.
- `run_all_years.sh` automates the per-year run across 2002–2026, then merges into a single CSV (used to build the snapshot; the legacy direct vendor-search path).

### Stage 3 — `full_intersect.py` (Cross-file matching)
- Takes a single-sheet Excel of CVE IDs (from Stage 2 output) and cross-references against all per-category keyword files (`data/keyword-search/keyword_*.csv`, globbed automatically)
- Finds CVEs that appear in both the device-specific result set and a keyword search
- Adds `Source File` and `Source Sheet` (= the category slug) columns to matched rows
- Saves output to CSV interactively

**Companion script — `full_difference.py`** (the complement of `full_intersect.py`):
- Same inputs and keyword files as `full_intersect.py`
- Outputs the vendor CVEs that appear in **none** of the keyword files (i.e. `vendor − keyword_union`, whole-corpus) — the set difference behind `unmatched_cves.xlsx`
- Adds a `Difference Type` (= `vendor_only`) column and drops reviewer judgment columns; default output `unmatched_cves.csv`
- Prints vendor / keyword-union / unmatched counts so the set math is visible
- Note: both scripts now resolve `data/keyword-search/` **relative to the script**, so they can be run from anywhere (no more cwd/bare-filename requirement). For the **per-category** difference used by Stage 4, use `build_difference_sets.py` instead (this tool is the whole-corpus union).

### Stage 4 — Triple-AI review of the difference set (per device category)

The difference set is built **bidirectionally** per category: `vendor_only` (`vendor_<cat> −
keyword_<cat>`, vendor CVEs the keyword search **missed**) and `keyword_only` (`keyword_<cat> −
vendor_<cat>`, keyword CVEs the brand/vendor list **missed** → surfaces vendor/brand-list gaps).
The two are disjoint and reviewed independently by the same pipeline. Classifying which are true matches both (a) cleans the dataset and
(b) surfaces keywords the keyword search is missing — mining the true-positive descriptions
feeds new terms back into the keyword list to raise recall. To keep this trustworthy, every
row is judged **independently by three AI reviewers**, mirroring the two-human reviewer model:

| Reviewer | Columns it owns | How it runs |
|----------|-----------------|-------------|
| **Claude Code** | `Claude Judgment / Confidence / Reasoning` | manual (in-session) |
| **ChatGPT Codex** | `Codex Judgment / Confidence / Reasoning` | manual (run by a person) |
| **Gemini** | `Gemini Judgment / Confidence / Reasoning` | automated via `gemini_classify.py` (current model `gemma-4-31b-it` — see *Gemini reviewer model & limits*) |

**Blind judgment is a hard rule.** No reviewer may see or be influenced by another reviewer's
answer. This is guaranteed structurally: each reviewer works on its **own copy** that contains
only the raw data + its own empty columns, so other AIs' judgments are physically absent from
the file it reads. All three judge by the same rubric: `data/difference/CLASSIFICATION_PROMPT.md`.

**Per-category workflow** (run from the repo root; `<device>` e.g. `cameras`, `<dir>` =
`vendor_only` or `keyword_only`). The review is **bidirectional**: every category has two disjoint
review units, `<device>/vendor_only/` and `<device>/keyword_only/`, both run through the *same*
pipeline below (just swap `<dir>`).
0. (Optional, batch) `python scripts/init_categories.py categories.txt` — scaffold `data/difference/<device>/<dir>/reviews/` for every category × direction (`--direction vendor_only|keyword_only|both`, default both). Idempotent: existing folders untouched.
1. Generate the raw difference set(s) as `data/difference/<device>/<dir>/01_raw.csv`:
   - **Batch (all categories, both directions):** `python scripts/build_difference_sets.py data/device_lst.txt` — for each category builds **both** `vendor_only` (vendor_<cat> − keyword_<cat>) and `keyword_only` (keyword_<cat> − vendor_<cat>), differencing `results_all_<device>.xlsx` against `keyword_<device>.csv`. Use `--direction` to pick one. Warns if the keyword file is missing (run `build_keyword_search.py` first); a missing *other* side is treated as empty. Skips a direction that already has `01_raw.csv` (use `--overwrite`). **Note:** regenerating existing sets invalidates in-progress review/human verdicts, so it is gated (skip-if-exists) and should only be re-run after scope freeze (verdicts are preserved by `extract_human_review.py`).
   - **Single, interactive (whole-corpus vendor_only only):** `python scripts/full_difference.py` (runnable from anywhere), then save to the direction's `01_raw.csv`.
2. `python scripts/make_review_copies.py data/difference/<device>/<dir>/01_raw.csv` → writes blind `reviews/{claude,codex,gemini}.csv`.
3. The two **manual** reviewers each fill **only their own** copy, following the rubric:
   - Claude Code edits `reviews/claude.csv`
   - Codex edits `reviews/codex.csv`
4. Run the **Gemini reviewer + merge in one command**:
   `GEMINI_API_KEY=… python scripts/merge_judgments.py --reviews data/difference/<device>/<dir>/reviews --run-gemini --category "<keyword>" --model gemma-4-31b-it`
   → fills `reviews/gemini.csv` (resumable; skips already-filled rows), then writes `02_merged.csv` (all 9 AI columns + flag) **and** `02_high_confidence_audit.csv` (a seeded random sample of unanimous-high-confidence rows, so a human can spot-check the calls that otherwise never get reviewed).
   - Plain `python scripts/merge_judgments.py --reviews …` (no `--run-gemini`) just re-merges — a quick status view, no API/`requests` needed.
   - Standalone `python scripts/gemini_classify.py reviews/gemini.csv --category "<keyword>"` still works for the Gemini pass without merging.
   - `bash scripts/run_gemma_column.sh` runs the Gemini pass over **all** categories at once (set `DIRECTION=vendor_only|keyword_only`; backs up the prior model's results, blanks the column, fills on Gemma) — see *Gemini reviewer model & limits* for the rate/quota timing.
5. **Extract the human-review queue:** `python scripts/extract_human_review.py` → pulls every `Needs Human Review = Yes` row (both directions) into `<dir>/02_needs_human_review.csv` (per cat+direction) and `human_review_queue.csv` (combined, with `Category` + `Direction` columns). **Verdict-preserving:** already-filled `Human Verdict` / `Human Notes` are carried forward by `(category, cve_id)` on every re-run, so nothing hand-filled is lost.
6. A **human adjudicates** only those flagged rows — fills `Human Verdict` (Yes/No/Maybe) in the queue sheet.
7. **Fold verdicts back to one settled answer:** `python scripts/finalize_judgments.py` → `<dir>/03_final.csv` (per cat+direction) + `final_resolved.csv` (combined, with `Category` + `Direction`), adding `Final Judgment` / `Final Source` (`ai-consensus` for unflagged rows, `human` for adjudicated rows, `pending`/`incomplete` otherwise). Verdicts are keyed `(category, cve_id)` — directions are disjoint so the key stays unique. Re-run as humans fill more in; never overwrites AI columns.
8. Mine the **resolved-`Yes`** rows (AI-unanimous + human-confirmed) for missing keywords → `03_keyword_additions.md`.

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
│   ├── build_keyword_search.py          # Stage 1 — offline per-category keyword search (uses cve_search engine)
│   ├── build_vendor_search.py           # Stage 2 — offline per-category vendor/brand search (same engine)
│   ├── nvd_keyword_query.py             # Stage 1 — LEGACY live NVD API querier (retired; kept for reference)
│   ├── cve_search.py                    # Shared engine — offline bulk NVD searcher (Stage 1 & 2)
│   ├── run_all_years.sh                 # Builds the snapshot / legacy per-year vendor run across 2002–2026
│   ├── full_intersect.py                # Stage 3 — CVE cross-file matcher (intersection)
│   ├── full_difference.py               # Stage 3 — CVE cross-file matcher (difference / complement)
│   ├── build_difference_sets.py         # Stage 4 — batch-generate 01_raw.csv, both directions (--direction)
│   ├── init_categories.py               # Stage 4 — scaffold per-category/direction folders from a list (idempotent)
│   ├── make_review_copies.py            # Stage 4 — split a raw difference set into 3 blind AI copies
│   ├── gemini_classify.py               # Stage 4 — Gemini/Gemma API reviewer (standalone, or imported by merge)
│   ├── merge_judgments.py               # Stage 4 — (optionally run Gemini, then) merge 3 AI copies + flag + audit sample
│   ├── extract_human_review.py          # Stage 4 — pull flagged rows into the human-review queue
│   ├── finalize_judgments.py            # Stage 4 — fold human verdicts into one Final Judgment per CVE
│   └── run_gemma_column.sh              # Stage 4 — run the Gemini/Gemma pass over ALL categories (backup+blank+fill)
│
├── Onboarding-Docs/                 # Onboarding doc + reference papers (unchanged)
│
└── data/                            # All datasets, grouped by search method
    │
    ├── nvd-snapshot/                # Fixed offline NVD dataset (one snapshot, reproducible/citeable)
    │   ├── SNAPSHOT.md                  # provenance: download date, source, how to (re)build  [tracked]
    │   └── nvd_all.csv                  # merged year-feeds searched by Stage 1/2  [gitignored — large]
    │
    ├── keyword-search/              # Stage 1 — per-category keyword search (offline, device-phrases only)
    │   ├── keyword_terms.csv            # USER-AUTHORED terms (slug,term) — now populated for all ~24 categories
    │   ├── keyword_terms.suggested.csv  # Claude's suggested terms per category (copy-from; driver never reads)
    │   ├── keyword_<category>.csv       # build_keyword_search.py output, one per analysis category (all built)
    │   └── _legacy/                     # retired live-API grouped workbooks + CATEGORY_GROUPING.md
    │       ├── CategoryI_SmartHomeDeviceTypes.xlsx … CategoryIX_IoTDeviceTypes.xlsx (10 workbooks)
    │       └── CATEGORY_GROUPING.md     # original keyword→category groupings (term source for the suggestions)
    │
    ├── vendor-search/               # Stage 2 — build_vendor_search.py outputs (Jason), rebuilt on the snapshot
    │   ├── vendor_terms.csv                  # brand terms (slug,term) — driver input; ALL 25 cats (15 originals recovered from Devices List.docx + verified reproducible, 10 new Claude-drafted)
    │   ├── vendor_terms_proposed.csv         # original Claude draft of the 10 new categories' lists (now also folded into vendor_terms.csv)
    │   ├── PROPOSED_brand_lists.md           # human-review doc behind vendor_terms_proposed.csv
    │   ├── _backup_pre_rebuild_2026-06-28/   # the pre-overhaul results_all_*.xlsx (legacy per-year run)
    │   ├── results_all_cameras.xlsx          (~2,161 CVEs — largest)
    │   ├── results_all_airconditioner.xlsx   (~187 CVEs)
    │   ├── results_all_gameconsoles.xlsx     (~246 CVEs — OUT OF SCOPE: entertainment, fails criteria 2 & 4)
    │   ├── results_all_streaming.xlsx        (~232 CVEs — IN SCOPE: `streaming` category, home-control surface — criterion 4(b))
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
    │   ├── results_all_sleeptracker.xlsx     (~27 CVEs)
    │   └── results_all_<10 new cats>.xlsx    # airpurifier, appliances, ev-charging, garden, home-power,
    │                                         #   hub, lighting, pet, sensors, shades (built from vendor_terms.csv)
    │   # (CVE counts above are pre-rebuild approximations; all 14 originals were re-run on the snapshot)
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
        ├── human_review_queue.csv       # extract_human_review.py → all flagged rows, all categories (one sheet)
        ├── final_resolved.csv           # finalize_judgments.py → Final Judgment per CVE, all categories
        │
        └── <device>/                    # per-category review, split by difference DIRECTION
            ├── vendor_only/                 # vendor_<cat> − keyword_<cat> (vendor CVEs keyword missed)
            │   ├── 01_raw.csv                   # build_difference_sets.py output (Difference Type=vendor_only)
            │   ├── reviews/
            │   │   ├── claude.csv               # raw + Claude columns   (Claude Code fills, manual)
            │   │   ├── codex.csv                # raw + Codex columns    (Codex fills, manual)
            │   │   └── gemini.csv               # raw + Gemini columns   (gemini_classify.py / Gemma fills, API)
            │   ├── 02_merged.csv                # merge_judgments.py → all 9 AI cols + human-review flag
            │   ├── 02_high_confidence_audit.csv # seeded sample of unanimous-high-confidence rows to spot-check
            │   ├── 02_needs_human_review.csv    # this direction's flagged rows (Human Verdict to fill)
            │   ├── 03_final.csv                 # finalize_judgments.py → Final Judgment / Final Source
            │   └── 03_keyword_additions.md      # keywords mined from resolved-Yes rows (feeds keyword search)
            └── keyword_only/                # keyword_<cat> − vendor_<cat> (keyword CVEs the brand list missed)
                └── …                            # same file set as vendor_only/ (disjoint review unit)
```
> Both directions are **disjoint** (a CVE can't be in both) and run through the *same*
> direction-agnostic Stage-4 pipeline. `keyword_only` surfaces **vendor/brand-list gaps**.

> **Note — running the scripts.** Scripts live in `scripts/`. `full_intersect.py`,
> `full_difference.py`, `build_keyword_search.py`, `build_vendor_search.py`, and
> `build_difference_sets.py` resolve their data dirs **relative to the script**, so they can be run
> from the repo root (or anywhere). `cve_search.py` and `run_all_years.sh` operate on the cwd; run
> them from wherever the year-feeds / outputs live.

---

## Data Schemas

| File type | Columns |
|-----------|---------|
| `data/keyword-search/keyword_terms.csv`, `keyword_terms.suggested.csv` | `slug, term` (`#`-comment + blank-line aware) |
| `data/vendor-search/vendor_terms.csv`, `vendor_terms_proposed.csv` | `slug, term` (brand strings; same parser as keyword_terms.csv) |
| `data/vendor-search/results_all_<category>.xlsx` (Stage 2 output) | cve_id, published, description, cvss_score, cvss_version, cwe_ids (pipe-sep), cpe_strings (pipe-sep) — same schema as keyword files / `01_raw.csv` (rebuilt files; legacy reviewed files also carry Lizzie/Cukier columns) |
| `data/keyword-search/keyword_<category>.csv` (Stage 1 output) | cve_id, published, description, cvss_score, cvss_version, cwe_ids (pipe-sep), cpe_strings (pipe-sep) — same schema as vendor files / `01_raw.csv` |
| `data/keyword-search/_legacy/*.xlsx` (retired) | CVE, CVSS, CVSS Severity, CWE, CWE Name, Description |
| `data/vendor-search/results_all_*.xlsx` | cve_id, published, description, cvss_score, cvss_version, cwe_ids (pipe-sep), cpe_strings (pipe-sep), Lizzie Judgment/Judgement, Cukier Judgment |
| `data/intersection/*.csv` | Source File, Source Sheet, CVE, CVSS, CVSS Severity, CWE, CWE Name, Description |
| `data/difference/<device>/<dir>/01_raw.csv` (`<dir>` = `vendor_only` \| `keyword_only`) | Difference Type, cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings |
| `data/difference/<device>/<dir>/reviews/{ai}.csv` | …raw columns + `<AI> Judgment`, `<AI> Confidence`, `<AI> Reasoning` (one AI's triple only) |
| `data/difference/<device>/<dir>/02_merged.csv` | …raw columns + all 3 AI triples (Claude/Codex/Gemini) + `Review Status`, `Needs Human Review`, `Review Reason` |
| `…/<dir>/02_high_confidence_audit.csv` | `AI Verdict (unanimous)` + raw columns + all 3 AI triples + `Human Verdict`, `Human Notes` |
| `…/<dir>/02_needs_human_review.csv`, `difference/human_review_queue.csv` | `Verdicts`, `Review Reason` + raw + all 3 AI triples + `Human Verdict`, `Human Notes` (combined file adds leading `Category`, `Direction`) |
| `…/<dir>/03_final.csv`, `difference/final_resolved.csv` | …merged columns + `Final Judgment`, `Final Source` (combined file adds leading `Category`, `Direction`) |
| `data/difference/unmatched_cves.xlsx` | Difference Type, Origin File, cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings, Lizzie Judgment, Cukier Judgment, Lizzie Judgement |

**Note:** There is a spelling inconsistency — some files use `Lizzie Judgment`, others use `Lizzie Judgement`. Treat them as the same column.

---

## Definition of a Home IoT Device

**Definition.** Home IoT devices are internet-connected sensors, appliances, and embedded systems deployed within residential environments for the purpose of monitoring, automation, or control, without dedicated IT security oversight (Balta-Ozkan et al., 2013; Alrawi et al., 2019).

The criteria below are derived directly from this definition — one per clause. A device must satisfy **all five** definitional criteria.

**Definitional criteria:**
1. **Connectivity** — communicates over a network via standard protocols (TCP/IP, MQTT, CoAP, Zigbee, BLE). *(from "internet-connected")*
2. **Device class** — a special-purpose sensor, appliance, or embedded system; **not** general-purpose IT (PC, phone, tablet, game console). *(from "sensors, appliances, and embedded systems")*
3. **Deployment context** — intended for a private residence (see *Definition of "home"* below), not primarily enterprise/industrial. *(from "deployed within residential environments")*
4. **Function** — qualifies if **either** (a) its primary purpose is to **monitor, automate, or control the home environment or its systems** (climate, security, access, lighting, appliances, presence), **or** (b) it serves as a **home-control surface/hub** for *other* home IoT devices — i.e. it can discover, control, or display the state of other home IoT devices (acts as a Matter/Thread controller or border router, runs a voice assistant, or surfaces camera/sensor feeds). **General-purpose computing and pure media playback with no such control role do not qualify.** *(from "for the purpose of monitoring, automation, or control"; clause (b) generalizes the precedent that admitted smart speakers — media hardware whose qualifying function is home control)*
5. **Security context** — owned and maintained by non-expert consumers, with no professional security administration. *(from "without dedicated IT security oversight")*

**Study-inclusion criterion** (operational, *not* definitional — it scopes what can be analyzed, not what qualifies as home IoT):
- Has a Common Platform Enumeration (CPE)-identifiable footprint in NVD and is subject to CVE disclosure.

**Guiding principle — connectivity is not membership.** Being networked alongside, or interoperating with, home IoT does not make a device home IoT. Criterion 1 (connectivity) is satisfied by virtually every IT device, so it cannot be the discriminator; the device's own **function** (criterion 4) and **class** (criterion 2) are what qualify it. A game console that controls smart lights through an app is still not a home IoT device — it is general-purpose compute (fails criterion 2), and an *app* is not the device acting as a control surface. (Contrast a streaming TV whose *platform* is a Matter/Thread controller — there the device itself is the home-control surface, satisfying criterion 4(b).)

**Entertainment — the hybrid line (criterion 4(b)).** Entertainment hardware qualifies *only* when it doubles as a home-control surface. The discriminator is **control of other home IoT devices**, not connectivity:
- **In scope:** streaming TVs / sticks / boxes (Google TV, Fire TV, Apple TV) — their platforms act as Matter/Thread controllers or border routers, run assistants, and surface camera/doorbell feeds. Smart speakers (already in) and smart soundbars/displays qualify the same way. These form the `streaming` category and the `smartspeakers` absorptions.
- **Out of scope:** game consoles and VR/AR headsets are **general-purpose compute + media** with no home-control role — they fail criterion 2 (device class) *and* criterion 4. Dumb media players / assistant-less TV-companion soundbars also fail 4(b).

(Alrawi et al. include a "media" category because they score *deployment attack surface*; this project stays a *function-defined category study*, so clause 4(b) admits media hardware on its **control function**, not on exposure.) `results_all_streaming.xlsx` is now **in the analysis set**; `results_all_gameconsoles.xlsx` remains on disk but **out of the analysis set**.

**Networking — hub-in / router-out (criterion 4 / 4(b)).** The same control-vs-connectivity test that governs entertainment governs networking: the discriminator is **whether the device controls other home IoT devices**, not whether it carries their traffic. This is the exact line drawn by the project's anchor paper, **Alrawi et al. (2019)** — they *"consider the exploitation of a hub device (communication bridge between low-energy and IP) to be equivalent to exploiting all the connected low-energy devices"* and *"exclude direct evaluation of low-energy devices but consider their hubs for evaluation,"* while the router appears only in the threat-model boundary: *"we consider the home network to be an untrusted network and we make no assumptions about the security state of mobile applications, modems/routers, or web browsers."* The hub is a study subject; the modem/router is untrusted **context** (sitting alongside browsers and mobile apps), and their evaluation table (Table III) has a *Hub* column but **no router/modem device category**.
- **In scope:** IoT **hubs / bridges / controllers** (SmartThings, Hubitat, Hue Bridge, Matter/Zigbee/Z-Wave controllers) — home control *is* their primary function (criterion 4(a)). Mesh/gateways that **also** act as a Matter/Thread/Zigbee controller are carved in via **criterion 4(b)**, identical to the streaming-TV logic, and are reviewed under `hub`.
- **Out of scope (as a category):** pure **transport** gear — plain routers, cable/DSL modems, ONT, unmanaged switches — whose only function is moving packets. By the guiding principle *connectivity is not membership* this fails criterion 4. The network layer is acknowledged as **threat-model context** (the untrusted home network devices sit on, per the standard 3-layer perception/network/application IoT architecture) but is **not** an enumerated category. The generic `router` category is therefore dropped; `CategoryII_NetworkGatewayDeviceTypes.xlsx` stays on disk, but only its hub / mesh-controller terms are in the analysis set.
- **Why not "networking as a base layer":** admitting routers as a network base layer is an *attack-surface-completeness* rationale — the same scope philosophy this project already declined for entertainment (it stays a *function-defined* study, not an attack-surface study). Including them would be internally inconsistent.

**Open scoping note — sleep trackers.** Confirmed by inspection: the current `sleeptracker` set is **~88% wearables** (Fitbit/Apple Watch/Garmin — out by criterion 3) and contains **0** actual bedside monitors. This is a near-total rebuild (bedside-only brands + new keyword sheets), and the category may not clear the NVD-footprint study-inclusion bar — so it could be dropped or folded. See *Finalized Category Scope* and *Methodology Notes → known data issues*.

**Recommended additions** (already keyword-prepped in `Devices List.docx` / `data/keyword-search/` but never given a `results_all_*.xlsx`): **smart hubs, smart lighting** — pass the five criteria cleanly and are folded into the frozen scope below. (Generic **routers/gateways** were keyword-prepped too but are **excluded as a category** — see *Networking — hub-in / router-out* above.)

---

## Finalized Category Scope (frozen 2026-06)

Scope is defined at **two levels**: broad **families** (for narrative / keyword organization) and the
granular **analysis categories** that are the actual unit of search, review, and reporting.

**Granularity rule:** two device types are *separate* analysis categories if a consumer would call
them different products **and** they have a meaningfully different brand set; *merge* only when
they're the same product with a different label. (e.g. cameras / doorbell / baby monitor stay
separate — different brands; blinds / curtains / shutters merge into one `shades` — same product.)

The frozen list is **~22 analysis categories** (hybrid entertainment re-admitted via criterion 4(b); pure-transport networking excluded — hub-in/router-out per Alrawi 2019). Status tags vs. current
coverage: **①** in both searches already · **②** keyword exists, needs a vendor list · **③** vendor
exists, needs keywords · **④** needs both (new build).

> **Status update (2026-06-28):** the build work below is now **provisionally complete** — every
> category has both a keyword set (`keyword_<cat>.csv`) and a vendor build
> (`results_all_<cat>.xlsx`). The 10 newly-added vendor lists were built from Claude-drafted brand
> terms (`vendor_terms_proposed.csv` / `PROPOSED_brand_lists.md`) and are **pending Jason's review**,
> so the **②/③/④** tags below reflect the *original* gap, not the current on-disk state.

| Family | Analysis categories (status) |
|--------|------------------------------|
| Cameras & monitors | `cameras` ①, `doorbell` ①, `babymonitor` ① *(vendor list needs tightening)* |
| Access control | `doorlock` ① *(incl. garage-door openers)* |
| Alarms & sensors | `alarms` ①, `sensors` ② |
| Climate & air | `thermostat` ①, `airconditioner` ①, `fans` ①, `airpurifier` ② |
| Electrical & lighting | `smartplugs` ①, `lighting` ② *(bulbs + switches + dimmers)* |
| Appliances | `fridge` ①, `robotvacuum` ①, `appliances` ④ *(oven/range/cooker/microwave/dishwasher/washer/dryer/water heater)* |
| Hubs & controllers | `hub` ② *(IoT hubs/bridges/controllers; absorbs mesh/gateways that **also** act as Matter/Thread/Zigbee controllers via 4(b))* — pure-transport routers/modems/ONT/switches are **out as a category** (Alrawi 2019: untrusted context, not a study subject) |
| Audio | `smartspeakers` ① *(absorbs smart displays **and smart soundbars** — same brands/platform/CVEs)* |
| Sleep | `sleeptracker` ③ *(rebuild — bedside only)* |
| Shades | `shades` ④ *(blinds/curtains/coverings — one category)* |
| Energy | `ev-charging` ④ *(home EVSE/wallbox only — excludes the vehicle and public/commercial EVCS; criteria 2 & 3)*, `home-power` ④ *(solar + batteries + meters)* |
| Outdoor & pet | `garden` ④ *(irrigation + mowers)*, `pet` ④ *(feeders/cameras/litter)* |
| Entertainment (hybrid) | `streaming` ① *(streaming TVs + sticks/boxes — one category; qualifies via criterion 4(b) as home-control surface)* — game consoles & VR stay **dropped** (fail criteria 2 & 4) |

Build work implied: **4 new vendor lists** (②), **1 new keyword set** (③), **4 full new builds** (④),
plus **2 fixes** (babymonitor tighten, sleeptracker rebuild). The ① categories are ready as-is.
**Done provisionally (2026-06-28):** all keyword sets and all 10 missing vendor lists are built (the
vendor lists from Claude-drafted brand terms, pending Jason's review); babymonitor tighten and
sleeptracker rebuild remain.

**Open scope calls still to confirm** (all on criterion ③/④): `ev-charging`/`home-power`,
`shades`, `garden`/`pet`, and whether `smart display` stays merged into `smartspeakers` or splits out. (`streaming` confirmed in via criterion 4(b); networking confirmed **hub-in/router-out** per Alrawi 2019; smart soundbars confirmed merged into `smartspeakers`.)

**Dependency rule.** Categories sit upstream of everything: lists → collection (NVD/Shodan/Censys)
→ set-ops → review → mining. Changing one category only forces a re-run of *that* category's chain;
the others are untouched. **Freeze scope before running collection at scale**, or you re-do the
(expensive) AI review on categories you were going to change anyway.

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
| `results_all_streaming.xlsx` | ~232 | In scope (`streaming`) — no judgment columns yet | — |
| `results_all_gameconsoles.xlsx` | ~246 | **Out of scope** (entertainment, fails criteria 2 & 4) | — |
| `unmatched_cves.xlsx` | 64,327 | ~47/64327 | 3/64327 |

**Next task:** Eliminate false positives across all `results_all_*.xlsx` files by filling in the judgment columns. Files missing the columns need them added first.

---

## Methodology Notes & Findings (2026-06)

### Vendor ↔ keyword comparability — **BOTH sides FIXED (2026-06 overhaul)**
Historically the two searches were **not directly comparable**, which quietly polluted the difference sets:
- **Different data source:** keyword = live NVD API (current); vendor = offline year-feed snapshot (can be stale) → some "gaps" are just data lag.
- **Different match surface:** vendor matches description **+ CPE**; keyword (`keywordSearch`) matched **description only** → many "vendor-only" CVEs were just *brand-in-CPE* artifacts.
- **Different columns:** keyword output had **no CPE** (and the classification rubric leans on CPE).

**Fix (keyword side):** the keyword search now runs through the **same engine** (`cve_search.py`'s `filter_by_keywords`, description **+ CPE**) against **one fixed NVD snapshot** (`data/nvd-snapshot/nvd_all.csv`) — see Stage 1 / `build_keyword_search.py`.

**Fix (vendor side) — DONE:** the vendor brand lists were **re-run on the *same* snapshot through the same engine** via `build_vendor_search.py` (description **+ CPE**, `whole_word=True`) — see Stage 2. The pre-overhaul `results_all_*.xlsx` are preserved under `data/vendor-search/_backup_pre_rebuild_2026-06-28/`. So **both** methods now read one snapshot through one engine, and the only difference between them is the search *terms* (brands vs device-phrases); both carry CPE in the common schema. Both builders use `whole_word=True` to stop short brand/device tokens matching inside unrelated words.

**Ideal end-state (remaining):** one per-category run over the shared snapshot tags each CVE with `match_method` (vendor / keyword / both) → intersection and both differences become column filters. The fixed snapshot already makes the study **reproducible / citeable** ("dataset as of <date>", recorded in `SNAPSHOT.md`).

### Symmetric (bidirectional) difference — BUILT (2026-06)
Both directions now exist per category: `vendor_only` (`vendor_<cat> − keyword_<cat>`) and
`keyword_only` (`keyword_<cat> − vendor_<cat>`, surfaces **vendor/brand-list gaps**), under
`data/difference/<cat>/{vendor_only,keyword_only}/`. The keyword overhaul made this direct — the
per-category `keyword_<cat>.csv` files are differenced straight against the vendor files, so the
old plan's **keyword-sheet → device-slug bridge mapping** is **obsolete** (not needed).
`build_difference_sets.py --direction {vendor_only,keyword_only,both}` generates both; the entire
Stage-4 pipeline (`init_categories` → `make_review_copies` → `merge_judgments` →
`extract_human_review` → `finalize_judgments`) is **direction-agnostic** (globs `*/*/`), and
`extract_human_review.py` is **verdict-preserving** so the migration kept all 334 human verdicts
(finalize parity: ai-consensus 1758 / human 328 / pending 6). The existing review data was
migrated under `vendor_only/`. *(`keyword_only` review work itself begins once `keyword_<cat>.csv`
files are generated from a snapshot — see Stage 1.)* See `data/difference/SYMMETRIC_DIFFERENCE_PLAN.md`.

### Reviewer behaviour & known data issues (from the baseline review)
Claude & Codex are the **permanent** reviewers; Gemini is the **swappable third vote**.
- **Systematic model biases:** Claude is the reliable anchor; **Codex over-excludes** (rejects unfamiliar security brands — e.g. Akuvox video doorbells, Qolsys/Abode/Eufy alarm hardware); **Gemini over-includes** (accepts function-overlap, e.g. IP-camera → baby monitor). The 2-of-3 + human flag catches both; Claude–Codex agree ~86%, Gemini is the outlier.
- **babymonitor contamination:** ~95% of its difference set are **generic IP cameras** (D-Link DCS…) dragged in by an over-broad vendor list — *the fix is tightening the vendor list, not the reviewer.*
- **sleeptracker:** ~88% wearables, 0 bedside monitors, no keyword sheet — needs a rebuild and may be dropped (see scope section).

### Gemini reviewer model & limits
The automated third reviewer evolved `gemini-2.5-flash` → `gemini-3.1-flash-lite` → **`gemma-4-31b-it`** (current; chosen for higher daily quota, supports the structured-output request with no code change). Free-tier caps: 3.1-flash-lite ≈ **500 req/day**; **Gemma 4 31B = 15 RPM / 1,500 req/day**. **Daily quota resets at midnight *Pacific*** (≈03:00 ET — confirmed via a live 429, *not* local midnight). For a clean one-pass run, straddle the reset at `--rps 0.30`. Keep **one model across the whole Gemini column** for consistency (re-run with `--redo` if switching mid-stream; `run_gemma_column.sh` backs up the prior model's results first).

### Future dimension — Shodan / Censys (not yet in the pipeline)
A second axis: NVD = *known vulnerabilities*; Shodan/Censys = *real-world deployment / exposure* (internet scanning). Join to NVD via **CPE / vendor-product**, used mainly at the **brand/category level** (which doesn't need per-CVE CPE, so it survives NVD's 2024+ CPE backlog). Uses: scope validation, brand discovery, exposure-weighting CVEs. **Caveat:** they see only internet-exposed devices (most home IoT is behind NAT) → it measures *exposure, not ownership*.

---

## Environment

- Python 3.14 (at `/Library/Frameworks/Python.framework/Versions/3.14/bin/python3`); invoke as `python3` (no `python` shim on PATH)
- Dependencies installed: `pandas`, `openpyxl`, `numpy`, `requests`
- `tqdm` optional (for progress bars in `cve_search.py`)
- **API keys live in a gitignored `.env`** (never hardcoded): `GEMINI_API_KEY` (Gemini/Gemma reviewer) and `NVD_API_KEY` (read from `os.environ` by `nvd_keyword_query.py`). Load with `set -a; source .env; set +a` before running. NVD key: https://nvd.nist.gov/developers/request-an-api-key · Gemini/Gemma key: https://aistudio.google.com/apikey

## Preferred file formats (for importing from Google Docs/Sheets)
- Google Docs → `.txt` (plain text, directly readable)
- Google Sheets (single sheet) → `.csv`
- Google Sheets (multi-sheet) → `.xlsx` (pandas + openpyxl required, now installed)
