# Plan — Implement the vendor_only / keyword_only difference layout

> Status: **not yet executed.** This is the agreed implementation plan for the bidirectional
> (symmetric) difference, ready to execute. See CLAUDE.md §"Symmetric (bidirectional)
> difference — planned".

## Context

Today the Stage-4 difference review only runs **one direction**: `vendor − keyword`
(vendor CVEs the keyword search missed), stored flat in `data/difference/<cat>/`. The
planned counterpart is `keyword − vendor` (keyword CVEs the brand/vendor search missed —
surfaces vendor/brand-list gaps). Agreed layout: `data/difference/<cat>/{vendor_only,
keyword_only}/`, each a full review unit, both normalized to the common `01_raw.csv` schema
so the AI-review pipeline stays direction-agnostic.

Two facts make this buildable now:
1. The keyword-search workbooks (`data/keyword-search/Category*.xlsx`) are **populated
   executed searches** — one tab per term, filled with CVE results (`ip camera`=281 rows,
   `mqtt`=214, etc.). So `keyword_only` builds from existing data, no new NVD runs.
2. `data/keyword-search/CATEGORY_GROUPING.md` already groups every keyword per-category and
   isolates the generic/protocol terms — it validates the tab→category split.

Locked-in decisions:
- **Generics dropped**: cross-cutting tabs (`smart home`, `internet of things`, `zigbee`,
  `mqtt`, …) and the brand-only `CategoryIX` tabs are NOT assigned to any category.
- Per-category keyword precision comes from vendor-Yes mining (`03_keyword_additions.md`),
  not from generic family terms.

Outcome: both difference directions exist per category, the whole Stage-4 pipeline runs on
either, and the 334 already-hand-filled human verdicts are preserved.

## Approach (two sequenced parts)

Land **Part A** first (structural, reversible, no new review data), then **Part B** (new
keyword_only data). Keeps the risky data-migration isolated from new-data generation.

---

## Part A — Direction-aware layout + script refactor

### A1. Migrate existing data into `vendor_only/` (git mv, preserves history)
For every `data/difference/<cat>/`, move contents down one level into `vendor_only/`:
`01_raw.csv`, `02_*.csv`, `03_*.csv`, `03_keyword_additions.md`, `reviews/` →
`<cat>/vendor_only/`. Applies to all 13 scaffolded categories (10 reviewed + airconditioner
/fans/fridge which have only `01_raw.csv`). Combined files (`human_review_queue.csv`,
`final_resolved.csv`, `CLASSIFICATION_PROMPT.md`, `unmatched_cves.xlsx`) stay at the
`data/difference/` root.

### A2. Make the cross-category glob scripts direction-aware
Pattern change everywhere: glob `…/*/02_merged.csv` → `…/*/*/02_merged.csv`, then derive
`direction = basename(dirname(path))`, `category = basename(dirname(dirname(path)))`,
filtering `direction ∈ {vendor_only, keyword_only}`. (`*/*/02_merged.csv` is safe — that
file only exists at the direction level, never under `reviews/`.) Files:
- `scripts/build_difference_sets.py` — write to `<cat>/vendor_only/01_raw.csv` (line ~76).
- `scripts/extract_human_review.py` — glob `*/*/02_merged.csv`; add `Direction` to the
  combined queue; verdict preservation per A4.
- `scripts/finalize_judgments.py` — glob `*/*/02_merged.csv` and `*/*/02_needs_human_review.csv`;
  write `03_final.csv` next to each merged file; key human verdicts on
  `(category, direction, cve_id)`; add `Direction` to `final_resolved.csv`.
- `scripts/init_categories.py` — scaffold `<cat>/<direction>/reviews/` (default both
  directions, or accept a `--direction` arg).
- `scripts/run_gemma_column.sh` — glob `*/*/reviews/gemini.csv`; derive cat+direction.

Already direction-agnostic, **no change** (take explicit paths): `make_review_copies.py`,
`merge_judgments.py`, `gemini_classify.py`, `full_difference.py`.

### A3. `Direction` column in the combined files only
Per-category files live under `<cat>/<direction>/` so direction is implicit there. Add a
`Direction` column only to the concatenated outputs (`human_review_queue.csv`,
`final_resolved.csv`), next to the existing `Category` column.

### A4. Protect the 334 hand-filled verdicts (the data-loss risk)
- Backfill `Direction = vendor_only` into the **existing** `human_review_queue.csv` and each
  `<cat>/vendor_only/02_needs_human_review.csv` in place — do NOT regenerate them (regen
  blanks `Human Verdict`).
- In `finalize_judgments.load_human_verdicts`: when a queue row has no `Direction` column,
  default it to `vendor_only`, so old + new keys both resolve.
- Harden `extract_human_review.py` to be **verdict-preserving**: before overwriting a queue,
  read the old one and carry forward `Human Verdict`/`Human Notes` by
  `(category, direction, cve_id)`. Fixes the existing overwrite footgun; makes re-runs after
  keyword_only safe.
- Re-run `finalize_judgments.py` only (read-only w.r.t. verdicts) to confirm parity with the
  current `final_resolved.csv` (still 341 Yes / 1745 No / 6 pending).

---

## Part B — Build the `keyword_only` direction

### B1. Bridge mapping — `data/keyword-search/keyword_category_map.csv`
Small reviewable CSV (`sheet,slug` rows), derived from `CATEGORY_GROUPING.md`, product tabs
only, restricted to tabs that exist in the workbooks. Proposed assignment:
- cameras ← ip/network/security/surveillance/cctv/wifi camera, nvr, network video recorder
- doorbell ← video doorbell, smart doorbell · babymonitor ← baby monitor
- doorlock ← smart lock, door lock, electronic lock, keyless lock, garage door opener, smart garage door
- alarms ← smart alarm, home alarm, siren · sensors ← motion/door/window sensor, co detector, gas detector, flood sensor
- thermostat ← thermostat, hvac controller · airconditioner ← smart ac · fans ← smart fan · airpurifier ← smart air purifier
- smartplugs ← smart plug, smart outlet, smart socket, power plug
- lighting ← smart switch, light switch, dimmer switch, smart light, smart bulb, smart lamp, led bulb, wifi bulb
- fridge ← smart fridge, smart refrigerator · appliances ← smart range, smart cooker · robotvacuum ← robot vacuum, robot cleaner
- hub ← smart hub, home hub, home automation hub, smart bridge, zigbee hub, matter hub, home controller, home automation controller
- smartspeakers ← smart speaker, voice assistant, smart display · streaming ← smart TV, set-top box, streaming box, media player
- **Dropped (generic/protocol):** smart home, smart device, smart appliance, internet of things,
  home automation, zigbee, z-wave, homekit, google home, alexa, mqtt, coap, 6lowpan
- **Dropped (brand-only, CategoryIX):** all of it — brands belong to vendor search
- **Dropped (pure transport, networking out-of-scope):** home/wifi/wireless/broadband router,
  cable/dsl modem, residential/home gateway, access points, mesh wifi, home firewall
- Confirm on review: nvr/network video recorder→cameras; smart switch→lighting.

### B2. Generator — `scripts/build_keyword_difference_sets.py`
Mirror of `build_difference_sets.py`, reverse direction. For each slug in the map:
- `keyword_cves` = union of CVE IDs across that slug's mapped tabs (dedup across workbooks).
- `vendor_cves` = CVE IDs from `data/vendor-search/results_all_<slug>.xlsx` (reuse
  `full_difference.load_cves`); empty set if no vendor file yet.
- `keyword_only = keyword_cves − vendor_cves`.
- Normalize to the common schema: `Difference Type=keyword_only, cve_id, published='',
  description, cvss_score=CVSS, cvss_version='', cwe_ids=CWE, cpe_strings=''`. (Keyword tabs
  carry no CPE — expected; rubric handles CPE-absent rows by description.) Write
  `<cat>/keyword_only/01_raw.csv`.

### B3. Run keyword_only rows through the existing Stage-4 pipeline
Per category: `make_review_copies.py …/keyword_only/01_raw.csv` → fill claude/codex (manual)
+ gemini (`merge_judgments --run-gemini`) → `extract_human_review` (appends keyword_only
flagged rows to the combined queue, preserving vendor verdicts) → human adjudication →
`finalize_judgments`. Normal flow; no new review tooling.

---

## Critical files
- Refactor: `scripts/{build_difference_sets,extract_human_review,finalize_judgments,init_categories}.py`, `scripts/run_gemma_column.sh`
- New: `scripts/build_keyword_difference_sets.py`, `data/keyword-search/keyword_category_map.csv`
- Data migration: `data/difference/<cat>/` → `data/difference/<cat>/vendor_only/` (git mv)
- Docs: update CLAUDE.md File-Structure tree + Symmetric-difference note to "built"
- Reuse as-is: `make_review_copies.py`, `merge_judgments.py`, `gemini_classify.py`, `full_difference.py`

## Verification
1. After A1–A4: `python3 scripts/finalize_judgments.py` → still `ai-consensus 1758 / human
   328 / pending 6`; `final_resolved.csv` = 341 Yes / 1745 No / 6 pending with a new
   `Direction=vendor_only` column on every row. Confirms zero verdict loss.
2. `git status` shows per-category files moved under `vendor_only/` as renames (not delete+add).
3. After B2: spot-check `cameras/keyword_only/01_raw.csv` — every cve_id is in the camera
   keyword tabs and absent from `results_all_cameras.xlsx`; printed counts (keyword_union /
   vendor / keyword_only) make the set math visible.
4. End-to-end on one small category (doorbell keyword_only): make_review_copies → merge →
   extract → finalize yields `<cat>/keyword_only/03_final.csv`, and the combined queue carries
   both directions with vendor verdicts intact.

## Risks / notes
- **Verdict loss** is the main risk — mitigated by A4 (in-place backfill, no regen of the
  vendor queue, verdict-preserving extract). Verify via step 1 before anything else.
- keyword_only rows have **no CPE** — inherent to the keyword search; expect more
  Low-confidence/Maybe than vendor_only.
- `CategoryIX` brand tabs and networking tabs intentionally dropped; brand-found CVEs surface
  via the vendor side. Documented in the map.
- Part B is independent per category (CLAUDE.md dependency rule) — build/review one
  category's keyword_only without touching others.
