# Plan — Scope-exclusion column (`Excluded`) + tvOS removal

> **RECOVERED AND EXECUTED — read this before the status block below.**
>
> This file was referenced by 8 tracked files (`data/categories.csv`, `ontology/homeiot.ttl`,
> `mark_excluded.py`, `cpe_expansion.py`, `cpe_brand_mining.py`, `finalize_judgments.py`,
> `extract_human_review.py`, `docs/RESULTS.md`) while existing only on the unmerged branch
> `docs/tvos-scope-exclusion`. Restored to `ontology` on **2026-08-07** so those references
> resolve.
>
> **The "PARKED / ready to execute" status below is stale — the exclusion has been applied.**
> Verified in `data/difference/judgment_store.csv`: **2,015 rows** carry
> `Excluded = scope:tvos-2026-07`. The downstream consequence is recorded in
> `PLAN_ontology.md` § *The exclusion bug*: `cwe888_analysis.py` and `cvss_analysis.py` were
> reading the store without testing `Excluded`, so those 2,015 rows were silently back in RQ1/RQ2
> until 2026-08-04. Both now filter by default, with `--include-excluded` to reproduce the old
> numbers. The sections below are kept as the design record of how and why, not as a to-do list.

## Current status (2026-07-22) — PARKED, code done, ready to execute

**Where we are:** the *code* (sections §2–§5 below) is fully implemented. It was extracted
from branch `vulnrichment-test` — **cleanly separated from the vulnrichment work**, which is
deliberately left behind — onto branch **`tvos-scope-exclusion`** (this branch). The tvOS
slice is exactly these files, and none of them touch/import vulnrichment:
`scripts/mark_excluded.py` (new), `scripts/finalize_judgments.py`,
`scripts/extract_human_review.py`, `scripts/cpe_expansion.py`, `scripts/cpe_brand_mining.py`,
`data/categories.csv` (streaming scope note), and this plan doc.

Safety verified: merge-base with main is `923aac9`; main made **zero** changes to any of these
script files after that point, so bringing the branch versions reverts nothing. Main's newer
`judgment_store.csv` (the 154 Claude reviews) is deliberately NOT taken — we run
`mark_excluded.py` fresh against main's current store instead.

**Dry-run result (store still UNTOUCHED — nothing written yet):**
```
python3 scripts/mark_excluded.py --category streaming --cpe-vp apple:tvos \
    --reason scope:tvos-2026-07 --dry-run
→ 2,015 streaming store rows would be flagged
  by Difference Type: {vendor_only: 118, cpe_expansion: 1897}
  by Final Source:    {human: 120, ai-consensus: 1895}   (all currently Yes)
```

**To resume (start here):**
1. `git checkout tvos-scope-exclusion` (the code is already committed on it).
2. Real flag: drop `--dry-run` from the command above. Back up the store first
   (`cp data/difference/judgment_store.csv /tmp/store.bak`) for the §8 integrity diff.
3. Follow §7 execution order from step 3 (scope note is already edited; do docs §6 for
   CLAUDE.md/README/SCRIPTS_REFERENCE — those were left out to avoid dragging in vulnrichment
   doc text), then `pipeline.py refresh` → `settle`, then rerun `term_precision.py`,
   `recall_estimate.py`, and `cwe888_analysis.py` + the table/treemap generators.
4. Verify against §8 acceptance checks.

**Downstream cascade to expect (this is the big one):** `streaming` drops from ~2,090
confirmed Yes to ~75. Corpus total 3,413 → ~1,400. This forces a FULL regeneration and a
one-pass re-sync of every number in `docs/home_iot_security_report.tex` — the CWE-888 "All"
row (currently 42% Memory Access, streaming-driven), the entire RQ2 CVSS section (streaming is
the Kruskal–Wallis anchor at n=2,081), and the recall POOLED total. The paper's prose numbers
(3,413 / 2,780 / 2,879) are already one generation stale vs committed data even before this —
so do the tvOS regeneration and the number re-sync together, once. See memory
`tvos-scope-exclusion`. The CWE over-counting figures at ~line 363 of the .tex are flagged
PROVISIONAL in a LaTeX comment for exactly this reason.

*(Original plan below. Target: one sitting. No new dependencies.)*

**Goal:** remove the ~1,900 `apple:tvos` CVEs from the `streaming` analysis population
**without** touching any AI judgment cell, flipping any `Final Judgment`, or creating new
review load — via a new store-level exclusion column that every analysis surface respects.

**Why this design (context for the implementer):**
- All 1,897 tvos rows in `streaming/cpe_expansion` are already settled `Yes / ai-consensus`;
  ~147 more sit in `streaming/vendor_only` (138 of them sticky human Yes via the `apple tv`
  vendor term). They are *true* matches under the current scope note — flipping them to `No`
  would poison the labelled Yes/No corpus (`term_precision`, `keyword_mining`) with false
  negatives, and hand-edits to `Final Judgment` on `ai-consensus` rows get recomputed away by
  the next `settle` anyway. Deleting the rows breaks the refresh invariant (the vendor_only
  ones re-enter `01_raw` every refresh and become fresh triple-AI review load).
- So: a third state. `Final Judgment` stays what the reviewers said; a new `Excluded` column
  says "true, but out of the analysis population". AI-accuracy stats, human-overrule stats,
  and the labelled corpus all stay honest.

**Scope ruling being implemented (default; confirm with Aarav if in doubt):** *wholesale* —
any `streaming` store row whose CVE carries an `apple:tvos` CPE in the NVD snapshot is
excluded, reason `scope:tvos-2026-07`. (Alternative, NOT the default: keep Apple-TV
device-specific rows and exclude only shared-codebase OS CVEs — same mechanics, different
selection filter.)

---

## 1. The column

- Name: `Excluded`. Value: a reason slug, e.g. `scope:tvos-2026-07`; **blank = in scope**.
  A reason string, not a boolean, so the next scope removal reuses the column.
- Lives in `data/difference/judgment_store.csv` only. It is **not** added to `01_raw`,
  review copies, or `02_merged` — reviewers never see it (blind-judgment rule untouched).

## 2. `scripts/finalize_judgments.py` — the critical file (do this first)

Without these changes the very next `pipeline.py settle` silently wipes every flag.

1. Append `"Excluded"` to `STORE_COLS` (after the human cols).
2. **`upsert_store` must carry the flag forward.** Rows present in the incoming `df` replace
   their store row wholesale, built only from `df`'s columns — so before dropping matching
   keys, read the prior store's `Excluded` into a `{(category, cve_id): reason}` map and
   stamp it onto `new_rows` (mirror how the four Human Verdict/Notes cells are attached from
   the `human` map). The existing "fill absent columns with ''" loop then covers first-run
   migration of the store file itself.
3. **Drop excluded rows from the final outputs.** After resolution, filter rows whose store
   `Excluded` is non-blank out of both `03_final.csv` and `final_resolved.csv` (they remain
   in the store — retention is the point). This one change makes `term_precision.py`,
   `keyword_mining.py`, and `recall_estimate.py` (`yes_rates`) correct **with zero edits** —
   all three read `final_resolved.csv` only. Do not add per-script filters there.
4. Print an `excluded: N` line per category in the summary so the drop is visible.

## 3. Direct store readers — who filters and who must NOT

| Reader | Change |
|---|---|
| `cpe_expansion.py` `load_yes_cve_ids` (:112) | Skip rows with non-blank `Excluded` — excluded rows must never seed Stage 5. |
| `cpe_expansion.py` `seeded_categories` (:285) | Same filter. |
| `cpe_brand_mining.py` `load_judgment_store` (:127) | Return the `Excluded` value alongside the judgment (dict of tuples, or a parallel excluded-set). **Tier A / Tier B evidence** must skip excluded rows. |
| `cpe_product_scan.py` known set (:238, via `load_judgment_store`) | **No filter** — excluded rows must stay "known" so a removed CVE can never resurface as a product-scan candidate. Same for any other "already judged / don't resurface" suppression set (e.g. Tier-B's not-judged-No check treats excluded as judged). |
| `make_review_copies.py` `load_store` (:53) | No filter — excluded rows are settled; carry-forward keeps pre-filling their AI columns so they never become review load. |
| `extract_human_review.py` | Skip excluded rows when building the queue (an excluded row must not be queued even if it would otherwise be pending/flagged). |

Invariant to preserve everywhere: **evidence/analysis uses only non-excluded rows;
known/suppression sets use all rows.**

## 4. Stop the inflow — `GENERIC_PLATFORM_CPES`

`scripts/cpe_expansion.py:77`: add `"apple:tvos"` to the set, and rewrite the comment block
at :69–76, which currently documents tvos as *deliberately kept*. `cpe_brand_mining.py` and
`cpe_product_scan.py` import the same set — all three surfaces get the denial at once. On the
next refresh, `streaming/cpe_expansion/01_raw.csv` drops from 1,907 rows to ~10.

## 5. One-off bulk flag — new script `scripts/mark_excluded.py`

Small reusable CLI, same conventions as siblings (repo-relative paths,
`csv.field_size_limit(1 << 24)`):

```
python3 scripts/mark_excluded.py --category streaming --cpe-vp apple:tvos \
    --reason scope:tvos-2026-07 [--dry-run] [--clear]
```

- Selection: store rows for `--category` whose CVE's `cpe_strings` (from
  `data/nvd-snapshot/nvd_all.csv`; match `vendor:product` via `cpe_expansion.parse_cpe`)
  include `--cpe-vp`. Also accept `--cve-file` (one CVE id per line) as an alternative
  selector. `--clear` blanks the flag for the selection (reversibility).
- Writes `judgment_store.csv` in place; prints counts by `Difference Type`/`Final Source`.
  `--dry-run` prints only.
- **Not** chained into `pipeline.py refresh`/`settle` — excluding a scope is a human
  judgment call, same rationale as the three discovery miners.

## 6. Scope note + docs

1. `data/categories.csv`, `streaming` row: delete *"Apple TV named in a shared-codebase
   iOS/tvOS CVE counts"*; add to OUT: *"tvOS CVEs (scope ruling 2026-07: excluded for volume —
   see judgment_store `Excluded`)"*. This is what keeps the three AI reviewers consistent with
   the store going forward.
2. `CLAUDE.md`: Stage-5 guardrail 2(c) — replace the "`apple:tvos` itself is deliberately
   kept" sentence; add a short `Excluded` paragraph to the *Refresh invariant* section
   (semantics: judgment preserved, row out of the population; evidence-vs-suppression
   invariant from §3).
3. `README.md` § Data Schemas: add `Excluded` to the store schema. `docs/SCRIPTS_REFERENCE.md`:
   flag table for `mark_excluded.py`.

## 7. Execution order

1. Code: §2, §3, §4, §5.
2. Run the bulk flag (§5) — expect ~1,900+ streaming rows flagged (1,897 cpe_expansion +
   the vendor_only/intersection tvos rows).
3. Edit scope note + docs (§6).
4. `python3 scripts/pipeline.py refresh` then `settle` (regenerates raws → merged → final;
   see README for the exact chain).
5. Rerun `term_precision.py` and `recall_estimate.py`.

## 8. Acceptance checks

- [ ] Store row count unchanged before vs after the bulk flag; flagged rows keep their
      `Final Judgment`/`Final Source` and every AI column byte-identical (diff the CSV).
- [ ] Run `settle` **twice**; the `Excluded` column survives both (upsert carry-forward works).
- [ ] `final_resolved.csv` contains zero rows with a non-blank store `Excluded`.
- [ ] `cpe_expansion.py` run for `streaming`: no seed derived from an excluded row; no
      `apple:tvos` seed; `cpe_expansion/01_raw.csv` ≈ 10 rows.
- [ ] `make_review_copies.py` refresh creates **no** new unjudged rows for `streaming`
      (excluded vendor_only rows still pre-fill from the store).
- [ ] `extract_human_review.py`: no excluded row in `human_review_queue.csv`.
- [ ] `cpe_product_scan.py`: excluded CVEs still suppressed from candidates.
- [ ] `mark_excluded.py --clear --dry-run` selects exactly the rows it flagged (reversible).

## Known caveat (documented, not fixed here)

`recall_estimate.py`'s **raw** capture sets still count tvos rows on the vendor side, because
`results_all_streaming.csv` is a search-stage artifact and the `apple tv` term still matches
them. Expect `term_precision.py` to surface `apple tv` as a prune candidate after the rerun
(~70% of its vendor_only yield was tvos) — pruning/qualifying that term is a separate human
call on `vendor_terms.csv`, out of scope for this plan.
