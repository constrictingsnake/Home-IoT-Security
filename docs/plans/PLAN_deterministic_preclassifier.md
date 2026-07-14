# Plan — Deterministic Pre-Classifier (Stage 3.5)

**Goal:** stop sending rows to triple-AI review (and from there to the human queue) when the
judgment store already settles the answer at the *product* or *term* level. Extends the refresh
invariant from "never re-judge the same `(category, cve_id)`" to "never re-judge the same
evidence."

Measured motivation: `moxa` alone consumed 309 triple-AI judgments (0 Yes), `fujitsu` 96
(0 Yes); 19 zero-precision terms with `n_judged ≥ 10` account for **742 judged rows** (see
`data/difference/term_precision.csv`). Forward-looking: every snapshot refresh, term addition,
or Stage-5 round re-surfaces the same vendors and the same bombs.

## Rules (conservative by design)

**R1 — auto-Yes by confirmed device CPE.** A raw row is auto-Yes for category `c` if its
`cpe_strings` contain at least one CPE that (a) parses to a concrete `vendor:product` with
`part ∈ {o,h}`, (b) is not in `GENERIC_PLATFORM_CPES`, and (c) matches a *seed* — a
`vendor:product` extracted the same way from a `Final Judgment == Yes` row of the same
category in `judgment_store.csv`. Treat `vendor:product` and `vendor:product_firmware` as the
same device (see `cpe_expansion.device_str`).
Rationale: identical logic to Stage-5 seeding — NVD itself attributes the CVE to a device
already signed off. Note this is deliberately *stronger* than Stage-5 guardrail 3 ("candidates
are never auto-included"): the difference is that guardrail 3 governs *newly discovered* CVEs,
while R1 only fires on product-level identity to an already-confirmed device. The audit sample
(below) is the safety valve. Reuse `cpe_expansion.build_seeds` — but note its
`load_raw_rows` currently reads only `vendor_only`/`keyword_only`; the seed builder here must
find Yes-row CPEs via all four direction raws **with snapshot fallback by cve_id** (2,136 of
3,085 Yes rows are absent from those two raws today).

**R2 — auto-No by settled zero-precision terms.** A raw row is auto-No if **every** term in its
`matched_terms` attribution is a *bomb*: per `term_precision.csv`, same method+category,
`n_judged ≥ --min-term-judged` (default **20**) and `n_yes == 0`. Rows with any non-bomb term
are untouched. R1 beats R2 (a device-CPE hit vetoes auto-No).
`01_raw.csv` has no `matched_terms` column — recover it the way `scripts/term_precision.py`
does (join cve_id to `keyword_<cat>.csv` / `results_all_<cat>.csv`, direction→method mapping;
read that script first and reuse its `load_term_map`). Rows whose direction has no term
attribution (`cpe_expansion`, `intersection`) are R1-only.

**R3 (flag-gated, off by default, `--enable-product-no`) — auto-No by product bomb:** all of a
row's device CPEs are `vendor:product`s with ≥ 10 store judgments and 0 Yes in the same
category. Ship R1+R2 first; enable R3 only after inspecting a dry run.

## New script: `scripts/preclassify.py`

Runs **after** `01_raw.csv` generation, **before** `make_review_copies.py`.

For each category: load the four direction raws; skip rows already settled in the store
(non-empty `Final Judgment`); apply R1 then R2; **upsert** hits into
`data/difference/judgment_store.csv` keyed `(category, cve_id)` with:
- `Final Judgment` = Yes/No, `Final Source` = `rule:cpe-seed-yes` / `rule:term-bomb-no`
  (/ `rule:product-bomb-no`), `Difference Type` from the row, all nine AI columns **left
  blank** — rule verdicts must never masquerade as model judgments.
Follow `finalize_judgments.py`'s store-upsert idiom (`STORE_COLS`, never rebuild the store).
Idempotent: re-running produces no changes. Never overwrite an existing non-empty
`Final Judgment`, whatever its source.

**Audit valve:** each run appends a random sample (`--audit-sample`, default 15 per rule, seeded)
of newly rule-settled rows to `data/difference/preclassify_audit.csv` with empty
`Human Verdict`/`Human Notes` columns, mirroring `02_high_confidence_audit.csv`.

### CLI

```
python3 scripts/preclassify.py --all --dry-run     # counts per rule per category, no writes
python3 scripts/preclassify.py cameras             # one category, writes store + audit sample
python3 scripts/preclassify.py --all --min-term-judged 20 --audit-sample 15 --seed 42
```

Dry-run output per category: rows scanned / already settled / R1 Yes / R2 No / untouched, plus
top 5 seeds and top 5 bomb terms by hit count (a lopsided single seed = inspect, same
convention as Stage 5's per-seed report).

## Required changes in existing scripts

1. **`scripts/make_review_copies.py`** — in `process_category`, after building `combined`,
   **drop rows whose store entry has `Final Source` starting with `rule:`** so they never enter
   the blind copies (they'd show blank AI columns and get re-reviewed). Rows settled by
   `ai-consensus`/`human` keep current behavior (included, judgments pre-filled).
2. **`scripts/finalize_judgments.py`** — rule-settled rows won't appear in `02_merged.csv`
   (excluded from copies), so: when building `03_final.csv` / `final_resolved.csv`, append the
   category's rule-settled store rows, pulling raw fields (`published`, `description`,
   `cvss_score`, `cvss_version`, `cwe_ids`, `cpe_strings`) from the direction `01_raw.csv`.
   Their AI columns stay blank; `Review Status` = `complete`; `Needs Human Review` = `No`.
   Guard the upsert so it never blanks a `rule:*` row it didn't see in a merged file.
3. **`scripts/term_precision.py`** — **exclude `Final Source` `rule:*` rows from the
   precision computation.** Otherwise R2 becomes self-confirming (rule-No rows would push
   `n_yes=0` terms further down) and R1 self-inflates seeds. Only human/AI-consensus judgments
   may feed the rule tables.
4. **`scripts/recall_estimate.py`** — check how the `yes` population is selected; rule-Yes rows
   should count as Yes (they are settled), no code change expected unless it filters on
   `Final Source`.

`merge_judgments.py` and `gemini_classify.py` need no changes (rule rows never reach copies).

## Order of operations (documentation note for README)

`build_review_sets.py` / `cpe_expansion.py` → **`preclassify.py`** → `make_review_copies.py
--refresh` → AI reviews → `merge_judgments.py` → `extract_human_review.py` →
`finalize_judgments.py`.

## Acceptance checks

- Dry-run on `cameras`: R2 fires on `moxa`-attributed rows (if any unsettled remain);
  reported counts match a manual grep.
- No rule row has any non-empty AI judgment column in the store; store keys stay unique
  (`(category, cve_id)` — assert before writing).
- `make_review_copies.py --refresh` after preclassify: copies shrink by exactly the rule-settled
  row count; no settled row reappears blank.
- `finalize_judgments.py`: `final_resolved.csv` includes rule rows with their `rule:*` source;
  total row count = ai-consensus + human + rule; re-running is idempotent.
- `term_precision.py` output unchanged before vs. after adding only rule rows (proves the
  exclusion works).
- R1 sanity: every rule-Yes row shares a `vendor:product` (or `_firmware` twin) with a
  confirmed-Yes row of the same category — assert this invariant in the script.
