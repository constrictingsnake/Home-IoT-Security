# Overall Results & Worked Examples

Measured numbers and point-in-time evidence from specific pipeline runs — first-run yields, current
snapshots, and worked examples. Not needed to operate the pipeline day to day. See `README.md` for
how to run each stage and `CLAUDE.md` for the design rationale behind these methods. Each section is
dated; treat older sections as historical (superseded by later snapshots where they overlap).

---

## Stage 5 — CPE expansion first-run (2026-07-02, 8 seeded categories)

52 new candidate CVEs the two text methods never found:

| Category | Confirmed-Yes seeds | New candidates | Note |
|----------|--------------------:|---------------:|------|
| **alarms** | 12 | **38** | Abode iota security kit — a 2022 researcher CVE dump, brand buried in terse text |
| cameras | 255 | 11 | Momentum Axel, TP-Link NC-series, Owlet Cam |
| babymonitor | 8 | 2 | D-Link EyeOn baby cameras |
| smartplugs | 7 | 1 | seed-inheritance miss (see below) |
| doorbell / robotvacuum / smartspeakers / thermostat | — | 0 | text search already had complete coverage of their confirmed products |
| **Total** | | **52** | |

- **Yield is spiky and is *not* predicted by a category's false-positive rate.** robotvacuum (a deliberate cameras-FP-rate match) returned **0** — its confirmed products' CVEs all name the brand in text, so the vendor search already had them. alarms returned 38 because one prolific product (Abode iota) had a wall of tersely-described CVEs. The predictor is "confirmed products with prolific, terse CVE families," not difference-set noise.
- **Precision (Claude single-review spot-check, `cpe_expansion_precision_spotcheck.csv` — since
  deleted, superseded by the full Stage-4 review; recover via git history): 51/52 = 98% category-correct.** The one miss — `CVE-2024-10523`, the TP-Link Tapo **H100** — is a genuine home IoT device but a *hub*, not a plug; it traces to a mis-confirmed seed (`tp-link:tapo_h100` wrongly settled `Yes` under `smartplugs`). The method faithfully propagated a *seed* error, not a method fault — and Stage-4 review of the candidate would catch it.
- **The part filter earns its place.** It drops 70 app/lib seed CPEs and prevents 4 library-leak candidates (openweave ×2 in cameras, a Tapo app CPE ×2 in smartplugs). Run `--no-part-filter` to see the 56-candidate unfiltered set for comparison.

> **Open item for review (as of 2026-07-02):** the 52 candidates were still unreviewed by the full triple-AI + human pipeline. The 98% is a Claude-only first pass.
> **Closed (2026-07-09):** the `cpe_expansion` direction has since gone through the full triple-AI
> review (judgments in `judgment_store.csv`, resolved rows in `final_resolved.csv`), which
> supersedes the spot-check; the spot-check CSV was deleted.

---

## Stage 6 — Recall estimation first-run (2026-07-02, raw candidate population)

> **Historical — superseded by "Recall estimate — full 24-category coverage" above** (2026-07-23
> post-rebuild). The pooled 0.41 / cameras 0.55 below are the *first-ever* run on a smaller term
> set; do not cite them as current. Kept for the self-validation and degenerate-row narrative.

| Category | V | K | ∩ | Observed | N̂ (2-src) | 95% CI | Recall | 3-src N̂ |
|----------|--:|--:|--:|---------:|----------:|--------|-------:|--------:|
| cameras | 3153 | 715 | 355 | 3513 | **6342** | 5936–6817 | **0.55** | 6325 |
| streaming | 199 | 277 | 17 | 459 | 3088 | 2086–4708 | 0.15 | — |
| hub | 92 | 43 | 5 | 130 | 681 | 380–1345 | 0.19 | — |
| thermostat | 71 | 15 | 11 | 75 | 95 | 82–135 | 0.79 | 93 |
| alarms | 103 | 69 | 11 | 161 | 606 | 400–987 | 0.27 | 574 |
| doorbell | 58 | 47 | 21 | 84 | 128 | 106–170 | 0.66 | 110 |
| **POOLED** | | | | **4967** | **12141** | 10801–13789 | **0.41** | — |

- **The estimator validates itself where data is rich.** On `cameras` the independent two-source (6342) and three-source (6325) estimates land **0.3% apart** — a convergence worth citing.
- **Low-recall categories are exactly the known-thin brand lists** (`streaming` 0.15, `hub` 0.19, `lighting`/`ev-charging` ~0.28). The estimator independently rediscovers where the vendor lists need work, and gives a prioritized recall-improvement queue.
- **`recall = 1.0` rows are flagged `degenerate`, not real** (babymonitor, pet, fans, sensors). There one list is a strict subset of the other (`m = min(V,K)`), so recapture carries no information and `N̂` collapses to the larger list. These are **excluded from the POOLED total.**

---

## Refresh worked example (2026-06-28)

After the vendor reproducibility fix + keyword overhaul, regenerating the `vendor_only` sets
preserved **1,175** Claude/Codex judgments per reviewer and left **2,178** new rows (mostly
cameras, whose set grew 1,709 → 2,798) for fresh review. All **334** human verdicts were
retained — **268** still map to current rows; the **66** orphans (CVEs the keyword search now
also matches) drop out harmlessly.

This is the concrete evidence behind the refresh invariant documented in `CLAUDE.md` — regenerating
`01_raw` never repeats settled work, it only creates review load for genuinely new rows.

---

## Judgment-store snapshot (2026-07-23)

Current state of `data/difference/judgment_store.csv` — **7,577 stored rows**. Taken right after
the `build_search.py --overwrite` rebuild + `pipeline.py refresh`, so it is **pre-review of the
rebuild's new candidates** (~701 blank Claude/Codex cells + 154 `incomplete` rows are not yet
counted as Yes/No here).

| Metric | Count |
|--------|------:|
| **Confirmed in-scope Yes** (`Final=yes`, not excluded) | **1,403** |
| Final = No | 4,005 |
| Yes but **tvOS-excluded** (`Excluded = scope:tvos-2026-07`) | 2,015 |
| Unsettled / `incomplete` | 154 |
| Final = yes (raw, before exclusion) | 3,418 |

- **Settle path:** ai-consensus 6,003 · human 1,414 · strong-consensus 6 · incomplete 154.
- **Reviewer coverage:** Claude 7,577/7,577 · Codex 7,423 (154 blank) · Gemini 7,463 (114 blank).
- **The tvOS exclusion dominates the Yes population.** Of 3,418 raw Yes, **2,015 are excluded**,
  almost all from `streaming` (2,403 stored → only 75 count in-scope). See `CLAUDE.md` criterion 4
  and `docs/plans/PLAN_scope_exclusion.md` — judgments are never flipped; the `Excluded` tag gates them.

**Confirmed in-scope Yes per category:**

| Category | Yes | Category | Yes | Category | Yes |
|----------|----:|----------|----:|----------|----:|
| cameras | 778 | smartplugs | 36 | thermostat | 17 |
| hub | 98 | pet | 35 | babymonitor | 11 |
| alarms | 88 | lighting | 34 | fridge | 3 |
| streaming | 75 | home-power | 33 | sensors | 3 |
| doorbell | 44 | doorlock | 31 | appliances | 3 |
| smartspeakers | 37 | ev-charging | 27 | airpurifier | 2 |
| | | robotvacuum | 27 | airconditioner | 2 |
| | | garden | 18 | fans | 1 |

> `sleeptracker` and `shades` have **0** confirmed in-scope Yes (not shown). Low counts in the
> low-recall categories (`hub`, `ev-charging`, `alarms`) are expected to rise once the rebuild's
> new candidates are reviewed — see the next section.

---

## Recall estimate — full 24-category coverage (`recall_estimate.csv`, 2026-07-26)

All 24 analysis categories below (`python3 scripts/recall_estimate.py --three`). The **2-source**
columns (V, K, ∩, Obs, N̂ 2-src, Recall 2-src) read V/K directly from the **2026-07-23** search
outputs and are **unchanged since that rebuild**. The **3-source** column (Recall 3-src) was
**recomputed 2026-07-26** against the current `judgment_store.csv` — the third capture set `C` is
reseeded from confirmed-Yes device CPEs, so it shifts whenever judgments settle, and the 220 human
verdicts landed between the two dates. This is the `raw` (search-stage) population; the
`yes`-population recall (which needs the reviews) is not recomputed here. Two things are **not yet
folded in**: the 7 pending Claude judgments (uncommitted) and the hubble vendor terms (added
2026-07-24, never rebuilt into the vendor search), so V and the C set will both move again on the
next full refresh. 3-src N̂ is volatile with wide CIs (see the log-linear caveats in `CLAUDE.md`
§ Stage 6) — read the 3-src column as indicative, not precise. Rows ordered by 2-src recall within
each confidence tier.

| Category | V | K | ∩ | Obs | N̂ (2-src) | Recall 2-src | Recall 3-src | Note |
|----------|--:|--:|--:|----:|----------:|-------------:|-------------:|------|
| doorbell | 60 | 22 | 21 | 61 | 63 | 0.972 | 0.970 | ok |
| smartspeakers | 83 | 67 | 57 | 93 | 98 | **0.954** | 0.992 | ok — near-complete |
| thermostat | 51 | 15 | 13 | 53 | 58 | 0.907 | 0.914 | ok |
| alarms | 103 | 112 | 65 | 150 | 177 | **0.847** ⬆ | 0.500 | ok — rose from 0.638 (new captures overlap) |
| babymonitor | 79 | 10 | 8 | 81 | 97 | 0.837 | 0.874 | ok — **no longer degenerate** (K grew 7→10) |
| doorlock | 35 | 37 | 20 | 52 | 64 | 0.811 | 0.247 | ok (3-src CI very wide) |
| lighting | 32 | 15 | 10 | 37 | 47 | 0.787 | 0.988 | ok |
| streaming | 218 | 35 | 25 | 228 | 302 | 0.754 | 0.640 | ok (unchanged — no new streaming terms) |
| smartplugs | 68 | 13 | 9 | 72 | 96 | 0.753 | 0.862 | ok |
| cameras | 2914 | 823 | 491 | 3246 | 4881 | **0.665** | 0.655 | ok — 2-src/3-src converge |
| **ev-charging** | 93 | 175 | 48 | 220 | 337 | **0.654** ⬆ | 0.344 | ok — 2-src rose from 0.502 (was low-recall target) |
| **hub** | 282 | 79 | 17 | 344 | 1257 | **0.274** ⬇ | 0.794 | ok — captured 2× more, but N̂ ballooned (see note) |
| garden | 12 | 13 | 1 | 24 | 90 | 0.267 | 0.914 | low — thin overlap |
| airconditioner | 15 | 10 | 1 | 24 | 87 | 0.276 | 0.160 | low; 3-src now formed (C=3, unstable) |
| home-power | 38 | 16 | 2 | 52 | 220 | 0.236 | 0.967 | low 2-src — thin overlap; 3-src wide CI |
| sleeptracker | 3 | 1 | 0 | 4 | 7 | 0.571 | — | low; **no 3-src** (see below) |
| appliances | 2 | 2 | 0 | 4 | 8 | 0.500 | 1.000 | low — tiny n |
| pet | 35 | 6 | 6 | 35 | 35 | 1.000 | 1.000 | **degenerate** (K ⊆ V) |
| robotvacuum | 36 | 5 | 5 | 36 | 36 | 1.000 | 1.000 | **degenerate** (K ⊆ V) |
| sensors | 1 | 13 | 1 | 13 | 13 | 1.000 | 1.000 | **degenerate** (V ⊆ K) |
| fridge | 3 | 3 | 3 | 3 | 3 | 1.000 | 1.000 | **degenerate** (V = K) |
| fans | 1 | 1 | 1 | 1 | 1 | 1.000 | 1.000 | **degenerate** (V = K, n=1) |
| **shades** | 5 | 0 | — | — | — | — | — | **absent** — no keyword terms (see below) |
| **airpurifier** | 0 | 8 | — | — | — | — | — | **absent** — no vendor terms (see below) |
| **POOLED** | | | | 4745 | 7888 | **0.602** | — | sum over informative (non-degenerate) categories; CI 0.556–0.646 |

**Reading the rebuild's effect on recall (this is capture-recapture behaving correctly, not a regression):**
The rebuild moved recall in *both* directions, and the direction tells you *why*:
- **`alarms` (0.638 → 0.847) and `ev-charging` (0.502 → 0.654) rose** because their new captures
  landed heavily in the V∩K overlap (∩ jumped 25→65 and 12→48), which *tightens* N̂ — the two
  searches now agree more, so the estimated true population shrinks relative to what's observed.
- **`hub` (0.332 → 0.274), `home-power` (0.424 → 0.236), `garden`, `airconditioner` fell** even though
  each captured *more* CVEs — because the new captures were mostly **non-overlapping** (`hub` ∩ barely
  moved 16→17 while V more than doubled 110→282), which is the signature of a still-incomplete list:
  finding lots of CVEs neither search's counterpart knows about reveals the true population is *larger*
  than previously estimated. A falling recall here means "we now know how much we were missing," not
  "coverage got worse." `hub` is still the #1 recall target.
- **`babymonitor` left the degenerate set** — its keyword list grew (7→10) enough that K is no longer a
  strict subset of V, so it now yields a real estimate (0.837) instead of an uninformative 1.000.

**Why a category is missing a value (all three cases are structural, not bugs):**

1. **Absent entirely — `shades`, `airpurifier`.** Capture-recapture needs *two* independent capture
   occasions, so the estimator skips any category where the vendor **or** the keyword list is empty
   (`if not V or not K: continue`). `shades` has 5 vendor CVEs but **0 keyword terms**; `airpurifier`
   has 8 keyword CVEs but **0 vendor terms**. Populate the missing side (add a keyword sheet for
   `shades`, vendor terms for `airpurifier`) and both get estimates on the next run.
2. **No 3-source row — `sleeptracker`.** The third capture set `C` is seeded from
   confirmed-Yes device CPEs (`part ∈ {o,h}`, generic platforms denied). `sleeptracker` has 0
   in-scope confirmed-Yes seeds, so no `C` set forms and only the 2-source Chapman estimate is
   produced. (`airconditioner`, which had no `C` set on the 2026-07-23 run, now forms a minimal
   `C=3` from newly settled Yes rows and so gained a 3-source row this run — but with only 3 seeds
   its 3-src N̂ is highly unstable, hence the 0.160 with a CI running to 1.0.)
3. **`recall = 1.000` flagged `degenerate` — `pet`, `robotvacuum`, `sensors`, `fridge`, `fans`.**
   One capture list is a strict subset of the other (`∩ = min(V,K)`), so recapture carries no
   information and N̂ collapses to the larger list. These are **excluded from the POOLED total** —
   the 1.000 is an artifact, not real completeness.

---

## NVD snapshot refresh — 2026-06-25 → 2026-08-05 (`PLAN_nvd_update.md`)

New pinned snapshot: **373,518 CVEs** (from 360,981 — **+12,537** in six weeks), downloaded in
1.2 min over 187 pages. Schema gained a `vector_string` column; `cvssMetricV40` is now read. The
June vintage is retained as `data/nvd-snapshot/nvd_all_2026-06.csv` (gitignored), so anything
published off the old numbers stays reproducible.

### What the refresh fixed (parser, not data)

All **57** confirmed-Yes CVEs that were silently `Unscored` now carry a base score — **54** were
scored only under CVSS 4.0 and were being dropped by a metric loop that never looked at
`cvssMetricV40`; the other 3 were genuinely new NVD analysis. Every category now reports
`n_scored == n_cves` in `cvss_distribution.csv` (previously `doorlock` 32/36, `hub` 244/247,
`fridge` 2/3, `sensors` 3/4, `robotvacuum` 26/27). **Vector coverage is 1,676 / 1,676 — 100%**,
so RQ3 carries no missing-data caveat.

### What it did NOT fix — NVD reanalysis churn is ~zero

`PLAN_nvd_update.md` §2.4 argued the strongest reason to refresh was NVD's CWE/CPE backlog. Over
the 1,676 confirmed-Yes CVEs (`snapshot_churn.md`), that did not happen:

| condition | predicted | measured |
|---|---|---|
| no usable CWE (118) | would enter the CWE-888 distribution | **0 gained a CWE** |
| no CPE string (196) | would unblock Stage 5 / the `C` capture set | **3 gained CPEs** |
| v2.0-only (81) | some re-scored under v3.x | **0 re-scored** |
| base score changed | — | **0** |
| newly REJECTED | — | **0** |

All 3 real changes are 2026 CVEs NVD was still analysing for the *first* time — first analysis,
not re-analysis. **A fixed confirmed-CVE set is far more stable across NVD vintages than the
"NVD reanalyses records" caveat implies.** The 7.0% of the confirmed set with no usable CWE and
the 11.5% with no CPE are limitations to report, not backlog to wait out; a future refresh will
not clear them.

### Re-run cost, and the refresh invariant again

Both searches rebuilt against the new snapshot (`build_search.py --overwrite`, 49 files, ~2 h —
each category is a full scan of 373k CVEs). Downstream:

| Step | Result |
|---|---|
| review sets | 68 regenerated, 4 skipped |
| CPE expansion | **140** new candidate CVEs across 22 categories |
| blind copies | **5,122** rows total — **5,011 restored from the store, 111 genuinely new** |

111 new rows across 10 categories (`cameras` 63, `hub` 14, `ev-charging` 14, `babymonitor` 9,
rest ≤3) is the entire manual review cost of a full snapshot refresh plus re-search — more
evidence for the refresh invariant.

Pooled 2-source recall moved **0.602 → 0.603** (N̂ 7,888 → 8,046 over 4,849 found): the corpus grew
and the searches found proportionally more, so coverage is flat.

### RQ3 — CVSS vector distributions (first run)

1,657 of 1,738 (category, CVE) rows normalise to CVSS 3.x; the other 81 are v2.0-only and are
reported as unconvertible rather than reshaped (v2 has no Scope metric).

| Metric | Pooled result |
|---|---|
| Attack Vector | **73% Network**, 16% Adjacent, 6% Local, 5% Physical |
| Scope | 83% Unchanged, **17% Changed** |
| CIA impact | **56% C+I+A**, 17% C-only, 13% A-only, 6% I-only, rest mixed pairs |
| Attack Complexity | 90% Low |

Two figures that need care before citing:

- **`hub` reports 54% Changed scope** against the 17% pooled rate — but `hub` is 45% single-vendor
  (insteon). This is exactly the concentration sensitivity check `PLAN_nvd_update.md` §9 proposes;
  do not cite it as a category property until that runs.
- **v2.0/v3.x pooling persists** in the Kruskal-Wallis (81 v2 scores among 1,657 v3.x). The refresh
  cannot fix it — 0 were re-scored — so it is now purely an analysis decision.
  `cvss_analysis.py --score-versions 3` implements the exclusion; the default remains `all` so no
  published number moved silently.

Both ontology gates stayed green throughout (`--check`: SHACL clean, both CSVs byte-identical,
27/27 rulings; `--verify-kg`: 1,676 / 1,738 / 1,904 all reconciling), confirming §4.3 — the T-Box
cannot move when CVE data changes.
