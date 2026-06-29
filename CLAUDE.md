# Home IoT Security — Project Guide

## What This Project Is

A security research pipeline that systematically maps real-world home IoT device brands to known CVEs from NIST's National Vulnerability Database (NVD), organized by device category. The goal is to build a comprehensive dataset of vulnerability exposure across consumer IoT device types (see *Definition of a Home IoT Device* for the scoping criteria; game consoles remain excluded as entertainment, while streaming TVs/sticks were re-admitted as **home-control surfaces** — see criterion 4), with manual review to eliminate false positives. The scope is **frozen to ~22 analysis categories** — see *Finalized Category Scope*.

---

## Three-Stage Pipeline

### Two search methods (researcher attribution)
The project combines two complementary CVE-discovery methods, each owned by a different researcher:

- **Vendor-based search — Jason.** Compiles a list of manufacturers/brands per device type, then searches NVD for those vendor/brand names. Produces the `results_all_*.xlsx` files. Runs **offline, per-category, through the same engine** (`build_vendor_search.py` → `cve_search.py`'s `filter_by_keywords` against the one fixed NVD snapshot, matching description **+ CPE**) — see Stage 2. Brand terms live in `data/vendor-search/vendor_terms.csv` (`slug,term`). More prone to false positives, since brand names overlap with unrelated products.
- **Keyword-based search — Lizzie.** Searches NVD for generic device-type keywords (e.g. "security camera", "ip camera"). Runs **offline, per-category, through the same engine as the vendor search** (`cve_search.py` against one fixed NVD snapshot, matching description **+ CPE**) — see Stage 1. Produces `data/keyword-search/keyword_<category>.csv`, one file per analysis category. `full_intersect.py` (Stage 3) is also Lizzie's — it intersects the two methods' outputs.

Combining both methods yields the most comprehensive per-device CVE list.

### Stage 1 — `build_keyword_search.py` (Offline per-category keyword search)
Runs **offline** through the **same engine** as the vendor search (`cve_search.py`'s
`filter_by_keywords`) against **one fixed NVD snapshot**, matching **description + CPE**, and emits
**one file per analysis category** in the common schema.

- **User-authored keywords.** Terms live in `data/keyword-search/keyword_terms.csv` (`slug,term`,
  `#`-comment aware). This file ships **empty** — every category present but commented out, with an
  example line showing where to add terms. **You fill in your own** device-phrase terms per category.
  Suggested starter terms are in `data/keyword-search/keyword_terms.suggested.csv` (a copy-from menu
  the driver **never** reads).
- **Scope:** device-type **phrases only** (e.g. `ip camera`, `video doorbell`). No brands, protocols,
  firmware, or umbrella terms — brand discovery is the vendor search's job.
- **Whole-word matching.** Both builders pass `whole_word=True` so tokens sit on alphanumeric boundaries (trailing `s`/`es` allowed). Blocks substring bombs (e.g. `nvr`→`nvram`, `evse`→`prevsell`) while leaving CPE matching unaffected (non-alphanumerics act as boundaries).
- **Snapshot:** build once from per-year NVD feeds — see `data/nvd-snapshot/SNAPSHOT.md` and the
  `cve_search.py` header (STEP 1–2). The snapshot makes the dataset reproducible/citeable ("as of <date>").
- **Run:** `python3 scripts/build_keyword_search.py` (loads the snapshot once, filters per category).
  Categories with no terms are **skipped with a message**, not an error. Use `--categories <slug…>`
  for a subset, `--snapshot`/`--terms` to override paths, `--overwrite` to rebuild existing outputs.
- **Output:** `data/keyword-search/keyword_<category>.csv` with columns `cve_id, published,
  description, cvss_score, cvss_version, cwe_ids, cpe_strings` — **identical to the vendor files and
  to `01_raw.csv`**, so the two methods are directly comparable and the classification rubric (which
  leans on CPE) works on keyword rows too.

### Stage 2 — `build_vendor_search.py` (Offline per-category vendor/brand search)
Runs **offline** through the **same engine** as the keyword search (`cve_search.py`'s
`filter_by_keywords`, description **+ CPE**, `whole_word=True`) against the **same fixed NVD
snapshot**, emitting one `results_all_<category>.xlsx` per analysis category in the common schema.
The only difference between the two methods is the search *terms* (brands vs. device-phrases).

- **Brand terms.** Authored in `data/vendor-search/vendor_terms.csv` (`slug,term`, same format and
  parser as `keyword_terms.csv` — `#`-comment / blank-line aware). Brands are **qualified** with a
  product word where the bare name overlaps unrelated products (e.g. `carrier infinity`, not
  `carrier`) to suppress false positives. A category with no active terms is skipped with a message.
  **This file is the complete, reproducible source for *all* 25 categories.**
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
- `run_all_years.sh` automates the per-year run across 2002–2026, then merges into a single CSV (used to build the snapshot).

### Stage 3 — `full_intersect.py` (Cross-file matching)
- Takes a single-sheet Excel of CVE IDs (from Stage 2 output) and cross-references against all per-category keyword files (`data/keyword-search/keyword_*.csv`, globbed automatically)
- Finds CVEs that appear in both the device-specific result set and a keyword search
- Adds `Source File` and `Source Sheet` (= the category slug) columns to matched rows
- Saves output to CSV interactively

**Companion script — `full_difference.py`** (complement of `full_intersect.py`): outputs vendor CVEs in **none** of the keyword files (`vendor − keyword_union`, whole-corpus) → `unmatched_cves.csv`; adds `Difference Type = vendor_only`. Both scripts resolve `data/keyword-search/` relative to the script, so they run from anywhere. For the **per-category** difference used by Stage 4, use `build_difference_sets.py` instead.

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

**Per-category workflow** (run from the repo root; `<device>` e.g. `cameras`). The review is
**bidirectional** — both directions (`vendor_only` and `keyword_only`) are combined into one review
unit per category. The `Difference Type` column on every row (`vendor_only` / `keyword_only`) is
the sort-back key when you need to separate them.

0. (Optional) `python scripts/init_categories.py categories.txt` — scaffold `data/difference/<device>/vendor_only/` and `keyword_only/` for every category. Idempotent: existing folders untouched.
1. Generate the raw difference set(s) as `data/difference/<device>/<dir>/01_raw.csv`:
   - **Batch (all categories, both directions):** `python scripts/build_difference_sets.py data/device_lst.txt` — for each category builds **both** `vendor_only` (vendor_<cat> − keyword_<cat>) and `keyword_only` (keyword_<cat> − vendor_<cat>), differencing `results_all_<device>.xlsx` against `keyword_<device>.csv`. Use `--direction` to pick one. Warns if the keyword file is missing (run `build_keyword_search.py` first); a missing *other* side is treated as empty. Skips a direction that already has `01_raw.csv` (use `--overwrite`). **Note:** regenerating existing sets is gated (skip-if-exists) and should only be re-run after scope freeze. Prior work is **not lost on a deliberate `--overwrite` refresh** — see *Refreshing difference sets without losing review work*.
   - **Single, interactive (whole-corpus vendor_only only):** `python scripts/full_difference.py` (runnable from anywhere), then save to the direction's `01_raw.csv`.
2. `python scripts/make_review_copies.py <device>` → concatenates both directions' `01_raw.csv`, pre-fills known AI judgments from `judgment_store.csv` (keyed by `(category, cve_id)`), and writes blind `<device>/reviews/{claude,codex,gemini}.csv`. **Carry-forward is automatic** — no `--preserve` flag needed; the store restores prior judgments for any CVE still in the current raw set. Only genuinely new CVEs are left blank.
   - For all categories at once: `python scripts/make_review_copies.py --all`
   - To blank-rebuild (ignore the store): add `--overwrite`
3. The two **manual** reviewers each fill **only their own** copy, following the rubric:
   - Claude Code edits `data/difference/<device>/reviews/claude.csv`
   - Codex edits `data/difference/<device>/reviews/codex.csv`
4. Run the **Gemini reviewer + merge in one command**:
   `GEMINI_API_KEY=… python scripts/merge_judgments.py --reviews data/difference/<device>/reviews --run-gemini --category "<keyword>" --model gemma-4-31b-it`
   → fills `reviews/gemini.csv` (resumable; skips already-filled rows), then writes `data/difference/<device>/02_merged.csv` (all 9 AI columns + flag) **and** `02_high_confidence_audit.csv` (a seeded random sample of unanimous-high-confidence rows, so a human can spot-check the calls that otherwise never get reviewed).
   - Plain `python scripts/merge_judgments.py --reviews …` (no `--run-gemini`) just re-merges — a quick status view, no API/`requests` needed.
   - Standalone `python scripts/gemini_classify.py reviews/gemini.csv --category "<keyword>"` still works for the Gemini pass without merging.
   - `bash scripts/run_gemma_column.sh` runs the Gemini pass over **all** categories at once (one combined pass per category; backs up the prior model's results, blanks the column, fills on Gemma) — see *Gemini reviewer model & limits* for the rate/quota timing.
5. **Extract the human-review queue:** `python scripts/extract_human_review.py` → pulls every `Needs Human Review = Yes` row into `<device>/02_needs_human_review.csv` (per category) and `human_review_queue.csv` (combined, with `Category` + `Direction` columns). **Verdict-preserving:** already-filled `Human Verdict` / `Human Notes` are carried forward by `(category, cve_id)` on every re-run, so nothing hand-filled is lost.
6. A **human adjudicates** only those flagged rows — fills `Human Verdict` (Yes/No/Maybe) in the queue sheet.
7. **Fold verdicts back to one settled answer:** `python scripts/finalize_judgments.py` → `<device>/03_final.csv` (per category) + `final_resolved.csv` (combined, with `Category` + `Direction`), adding `Final Judgment` / `Final Source` (`ai-consensus` for unflagged rows, `human` for adjudicated rows, `pending`/`incomplete` otherwise). **Also upserts into `judgment_store.csv`** — the persistent backing store that survives any `01_raw.csv` regeneration. Verdicts are keyed `(category, cve_id)` — directions are disjoint so the key stays unique. Re-run as humans fill more in; never overwrites AI columns.
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
│   ├── nvd_keyword_query.py             # LEGACY live NVD API querier (retired; kept for reference)
│   ├── cve_search.py                    # Shared engine — offline bulk NVD searcher (Stage 1 & 2)
│   ├── run_all_years.sh                 # Builds the NVD snapshot by running per-year across 2002–2026
│   ├── full_intersect.py                # Stage 3 — CVE cross-file matcher (intersection)
│   ├── full_difference.py               # Stage 3 — CVE cross-file matcher (difference / complement)
│   ├── build_difference_sets.py         # Stage 4 — batch-generate 01_raw.csv, both directions (--direction)
│   ├── init_categories.py               # Stage 4 — scaffold per-category direction subfolders from a list (idempotent)
│   ├── seed_judgment_store.py           # Stage 4 — one-time bootstrap: seed judgment_store.csv from final_resolved.csv
│   ├── make_review_copies.py            # Stage 4 — build combined blind review copies for a category (auto-fills from judgment store)
│   ├── gemini_classify.py               # Stage 4 — Gemini/Gemma API reviewer (standalone, or imported by merge)
│   ├── merge_judgments.py               # Stage 4 — (optionally run Gemini, then) merge 3 AI copies + flag + audit sample
│   ├── extract_human_review.py          # Stage 4 — pull flagged rows into the human-review queue
│   ├── finalize_judgments.py            # Stage 4 — fold human verdicts into one Final Judgment per CVE; upserts judgment_store.csv
│   └── run_gemma_column.sh              # Stage 4 — run the Gemini/Gemma pass over ALL categories (backup+blank+fill)
│
├── Onboarding-Docs/                 # Onboarding doc + reference papers
│
└── data/                            # All datasets, grouped by search method
    │
    ├── nvd-snapshot/                # Fixed offline NVD dataset (one snapshot, reproducible/citeable)
    │   ├── SNAPSHOT.md                  # provenance: download date, source, how to (re)build  [tracked]
    │   └── nvd_all.csv                  # merged year-feeds searched by Stage 1/2  [gitignored — large]
    │
    ├── keyword-search/              # Stage 1 — per-category keyword search (offline, device-phrases only)
    │   ├── keyword_terms.csv            # USER-AUTHORED terms (slug,term)
    │   ├── keyword_terms.suggested.csv  # suggested terms per category (copy-from; driver never reads)
    │   ├── keyword_<category>.csv       # build_keyword_search.py output, one per analysis category
    │   └── _legacy/                     # retired live-API grouped workbooks (CategoryI–IX.xlsx)
    │
    ├── vendor-search/               # Stage 2 — build_vendor_search.py outputs (Jason)
    │   ├── vendor_terms.csv                  # brand terms (slug,term) — driver input; all 25 categories
    │   ├── vendor_terms_proposed.csv         # original draft of the 10 new categories' brand lists
    │   ├── PROPOSED_brand_lists.md           # human-review doc behind vendor_terms_proposed.csv
    │   ├── _backup_pre_rebuild_2026-06-28/   # pre-overhaul results_all_*.xlsx (legacy per-year run)
    │   └── results_all_<category>.xlsx       # one file per category
    │
    ├── intersection/                # Stage 3 — vendor ∩ keyword (full_intersect.py output)
    │   └── matched_<device>_cves.csv
    │
    └── difference/                  # Stage 3 + Stage 4 — vendor − keyword, plus its triple-AI review
        ├── CLASSIFICATION_PROMPT.md     # shared rubric all 3 AI reviewers judge by (single source of truth)
        ├── unmatched_cves.xlsx          # vendor CVEs in NO category workbook (whole-corpus difference)
        ├── human_review_queue.csv       # extract_human_review.py → all flagged rows, all categories (one sheet)
        ├── final_resolved.csv           # finalize_judgments.py → Final Judgment per CVE, all categories (derived)
        ├── judgment_store.csv           # persistent AI judgment store — keyed (category, cve_id); upserted by
        │                               #   finalize_judgments.py; read by make_review_copies.py to auto-restore
        │                               #   prior judgments on any 01_raw regeneration
        │
        └── <device>/                    # per-category review — both directions combined in one reviews/ folder
            ├── vendor_only/
            │   └── 01_raw.csv               # build_difference_sets.py output (Difference Type=vendor_only)
            ├── keyword_only/
            │   └── 01_raw.csv               # build_difference_sets.py output (Difference Type=keyword_only)
            ├── reviews/                     # combined blind copies (both directions; Difference Type sorts back)
            │   ├── claude.csv               # raw + Claude columns   (Claude Code fills, manual)
            │   ├── codex.csv                # raw + Codex columns    (Codex fills, manual)
            │   └── gemini.csv               # raw + Gemini columns   (gemini_classify.py / Gemma fills, API)
            ├── 02_merged.csv                # merge_judgments.py → all 9 AI cols + human-review flag
            ├── 02_high_confidence_audit.csv # seeded sample of unanimous-high-confidence rows to spot-check
            ├── 02_needs_human_review.csv    # flagged rows for this category (Human Verdict to fill)
            ├── 03_final.csv                 # finalize_judgments.py → Final Judgment / Final Source
            └── 03_keyword_additions.md      # keywords mined from resolved-Yes rows (feeds keyword search)
```
> Both directions are **disjoint** (a CVE can't be in both). `keyword_only` surfaces
> **vendor/brand-list gaps**. The `Difference Type` column on every row carries `vendor_only` or
> `keyword_only` so reviewers can filter/sort by direction at any time within the combined files.

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
| `data/vendor-search/results_all_<category>.xlsx` | cve_id, published, description, cvss_score, cvss_version, cwe_ids (pipe-sep), cpe_strings (pipe-sep), Lizzie Judgment, Cukier Judgment |
| `data/keyword-search/keyword_<category>.csv` | cve_id, published, description, cvss_score, cvss_version, cwe_ids (pipe-sep), cpe_strings (pipe-sep) |
| `data/intersection/*.csv` | Source File, Source Sheet, CVE, CVSS, CVSS Severity, CWE, CWE Name, Description |
| `data/difference/<device>/vendor_only/01_raw.csv`, `…/keyword_only/01_raw.csv` | Difference Type, cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings |
| `data/difference/<device>/reviews/{ai}.csv` | …raw columns (both directions combined) + `<AI> Judgment`, `<AI> Confidence`, `<AI> Reasoning` (one AI's triple only) |
| `data/difference/<device>/02_merged.csv` | …raw columns + all 3 AI triples (Claude/Codex/Gemini) + `Review Status`, `Needs Human Review`, `Review Reason` |
| `…/02_high_confidence_audit.csv` | `AI Verdict (unanimous)` + raw columns + all 3 AI triples + `Human Verdict`, `Human Notes` |
| `…/02_needs_human_review.csv`, `difference/human_review_queue.csv` | `Verdicts`, `Review Reason` + raw + all 3 AI triples + `Human Verdict`, `Human Notes` (combined file adds leading `Category`, `Direction`) |
| `…/03_final.csv`, `difference/final_resolved.csv` | …merged columns + `Final Judgment`, `Final Source` (combined file adds leading `Category`, `Direction`) |
| `data/difference/judgment_store.csv` | category, cve_id, Difference Type, all 9 AI judgment columns, Final Judgment, Final Source — persistent store, keyed `(category, cve_id)` |
| `data/difference/unmatched_cves.xlsx` | Difference Type, Origin File, cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings, Lizzie Judgment, Cukier Judgment |

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

**Guiding principle — connectivity is not membership.** Being networked alongside home IoT does not make a device home IoT. The discriminator is the device's **function** (criterion 4) and **class** (criterion 2). A game console controlling smart lights via an app fails criterion 2, and the app is not the device acting as a control surface — contrast a streaming TV whose *platform* is a Matter/Thread controller, where the device itself is the home-control surface (satisfying criterion 4(b)).

**Entertainment — the hybrid line (criterion 4(b)).** Entertainment hardware qualifies *only* when it doubles as a home-control surface (control of other home IoT devices, not just connectivity):
- **In scope:** streaming TVs / sticks / boxes (Google TV, Fire TV, Apple TV) — platforms act as Matter/Thread controllers, run assistants, surface camera/doorbell feeds. Form the `streaming` category. Smart speakers, soundbars, and displays qualify the same way (`smartspeakers`). `results_all_streaming.xlsx` is **in the analysis set**.
- **Out of scope:** game consoles and VR/AR headsets (general-purpose compute, fail criteria 2 & 4). `results_all_gameconsoles.xlsx` stays on disk but is **out of the analysis set**.

**Networking — hub-in / router-out (criterion 4 / 4(b)).** The discriminator is **whether the device controls other home IoT devices**, not whether it carries their traffic. Per Alrawi et al. (2019), hubs are study subjects; routers/modems appear only as untrusted threat-model context (no router/modem category in their evaluation table).
- **In scope:** IoT **hubs / bridges / controllers** (SmartThings, Hubitat, Hue Bridge, Matter/Zigbee/Z-Wave controllers) — home control is their primary function (4(a)). Mesh/gateways that **also** act as Matter/Thread/Zigbee controllers are reviewed under `hub` via 4(b).
- **Out of scope:** pure **transport** gear — plain routers, modems, ONT, unmanaged switches. The generic `router` category is dropped; `CategoryII_NetworkGatewayDeviceTypes.xlsx` stays on disk but only its hub/mesh-controller terms are in the analysis set.

**Open scoping note — sleep trackers.** The current set is ~88% wearables (Fitbit/Apple Watch/Garmin — out by criterion 3), 0 actual bedside monitors. Near-total rebuild needed; may be dropped if it doesn't clear the NVD-footprint bar.

---

## Finalized Category Scope (frozen 2026-06)

Scope is defined at **two levels**: broad **families** (for narrative / keyword organization) and the
granular **analysis categories** that are the actual unit of search, review, and reporting.

**Granularity rule:** two device types are *separate* analysis categories if a consumer would call
them different products **and** they have a meaningfully different brand set; *merge* only when
they're the same product with a different label. (e.g. cameras / doorbell / baby monitor stay
separate — different brands; blinds / curtains / shutters merge into one `shades` — same product.)

The frozen list is **~22 analysis categories** (hybrid entertainment re-admitted via criterion 4(b); pure-transport networking excluded — hub-in/router-out per Alrawi 2019). Status tags: **①** in both searches · **②** keyword exists, needs vendor · **③** vendor exists, needs keywords · **④** needs both.

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

All categories have both a keyword set (`keyword_<cat>.csv`) and a vendor build (`results_all_<cat>.xlsx`). The 10 newly-added vendor lists are built from Claude-drafted brand terms and are **pending Jason's review**. Remaining work: babymonitor vendor list tightening, sleeptracker rebuild.

**Open scope calls still to confirm:** `ev-charging`/`home-power`, `shades`, `garden`/`pet`, and whether `smart display` stays merged into `smartspeakers` or splits out.

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
The keyword search is text-based, so generic brand names produce noise (e.g. `"cerberus"` matches Cerberus FTP Server CVEs; `"honeywell"` matches industrial controls). The thermostat file shows a ~65% false positive rate (14 Yes / 7 Maybe / 40 No out of 61 rows).

### Review decision rule
For each row, read the `description` and `cpe_strings` and ask:
> "Does this CVE describe a vulnerability in a device that a typical home user would have in their home for this category?"

---

## Methodology Notes

### Refreshing difference sets without losing review work
When `01_raw` sets need regeneration (e.g. after a keyword or vendor change), the **refresh order** is:

1. `build_difference_sets.py --direction both --overwrite` — rebuild `01_raw` (both directions).
2. `make_review_copies.py <device>` (or `--all`) — **automatically restores prior AI judgments from
   `judgment_store.csv`** by `(category, cve_id)`; only genuinely new CVEs are left blank. No
   `--preserve` flag needed — the store is always checked first.
3. Re-judge **only the new (blank) rows** — Claude/Codex manually, Gemini via `merge_judgments.py
   --run-gemini` (resumable; skips already-filled rows, so it only spends quota on the blanks).
4. `merge_judgments.py` → re-merge + re-flag; `extract_human_review.py` → re-extract (carries the
   existing human verdicts forward by `(category, cve_id)`); `finalize_judgments.py` → re-finalize
   (upserts the store with any newly resolved rows).

**Key invariant:** human verdicts (`extract_human_review.py`) and AI judgments (`judgment_store.csv`,
read by `make_review_copies.py`) are both preserved by `(category, cve_id)`, so a deliberate
`01_raw` regeneration never repeats settled work — it only creates review load for *genuinely new*
rows. The store also survives folder restructures and pipeline changes, since it is a flat CSV
independent of the review directory layout.

### Reviewer behaviour & known data issues
Claude & Codex are the **permanent** reviewers; Gemini is the **swappable third vote**.
- **Systematic model biases:** Claude is the reliable anchor; **Codex over-excludes** (rejects unfamiliar security brands — e.g. Akuvox video doorbells, Qolsys/Abode/Eufy alarm hardware); **Gemini over-includes** (accepts function-overlap, e.g. IP-camera → baby monitor). The 2-of-3 + human flag catches both; Claude–Codex agree ~86%, Gemini is the outlier.
- **babymonitor contamination:** ~95% of its difference set are **generic IP cameras** (D-Link DCS…) dragged in by an over-broad vendor list — *the fix is tightening the vendor list, not the reviewer.*
- **sleeptracker:** ~88% wearables, 0 bedside monitors, no keyword sheet — needs a rebuild and may be dropped (see scope section).

### Gemini reviewer model & limits
The automated third reviewer uses **`gemma-4-31b-it`** (current; chosen for higher daily quota). Free-tier caps: **15 RPM / 1,500 req/day**. **Daily quota resets at midnight *Pacific*** (≈03:00 ET). For a clean one-pass run, straddle the reset at `--rps 0.30`. Keep **one model across the whole Gemini column** for consistency (re-run with `--redo` if switching mid-stream; `run_gemma_column.sh` backs up the prior model's results first).

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
