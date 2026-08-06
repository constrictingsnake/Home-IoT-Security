# Plan — NVD Snapshot Update (vector capture + backlog backfill)

*Status: **Implemented** (2026-08-05) — Steps 1-6 done; see § 11 for what the refresh actually
measured, including the one finding that contradicts § 2.4. Refresh the fixed NVD snapshot from 2026-06-25 to a current
vintage, capturing two fields the current snapshot never recorded (`vectorString`, CVSS 4.0
metrics) and picking up NVD's CWE/CPE backfill on records we already confirmed. Triggered by
`Onboarding-Docs/2025_Paper_Extension (1).pdf`, whose RQ3 (CVSS vector analysis) is not
implementable against the current snapshot. Supersedes the **CVSS vector-string** half of
`PLAN_analysis_improvements.md` § Data enrichment — cvelistV5 was proposed as the vector source,
but a full NVD re-download is cheaper in requests and also delivers CPE backfill, which
cvelistV5 structurally cannot (it has no CPE layer). KEV and EPSS remain separate joins,
unaffected by this plan.*

---

## 1. Why

The 2025 paper extension adds one substantive research question over the 2024 study this
project replicates:

- **RQ3 — CVSS vector analysis.** Attack Vector, Scope, and CIA impact combinations per
  category. RQ1 (CWE-888) and RQ2 (CVSS scores + Kruskal-Wallis/Dunn's) are already implemented
  here in `cwe888_analysis.py` and `cvss_analysis.py`; RQ3 is the gap.

It also handles CVSS 4.0 explicitly, converting v4.0 vectors back to 3.x (VC/VI/VA → C/I/A;
any non-None SC/SI/SA → `Scope: Changed`) so one metric version covers the whole corpus.

Checking our own data against that method surfaced two defects in what this project already
publishes, both rooted in the snapshot rather than the analysis code.

---

## 2. What is broken today (measured, 2026-08-05)

Population: **1,676 unique confirmed-Yes CVEs** (`Final Judgment = Yes`, `Excluded` empty),
covering **1,738 (category, CVE) pairs** across 22 categories.

### 2.1 CVSS 4.0 is never read

`download_nvd.py:118` iterates `cvssMetricV31, cvssMetricV30, cvssMetricV2` — **`cvssMetricV40`
is absent**. Any CVE scored only under v4.0 is written with an empty `cvss_score` and silently
becomes `Unscored` in `cvss_analysis.py`.

| CVSS version among confirmed-Yes | n |
|---|---|
| 3.1 | 1,208 |
| 3.0 | 330 |
| 2.0 | 81 |
| **none (unscored)** | **57** |

All 57 unscored CVEs are recent — **11 from 2024, 29 from 2025, 17 from 2026** — so the loss is
concentrated exactly where a severity-over-time claim is most sensitive.

### 2.2 CVSS v2 and v3 base scores are pooled

`cvss_analysis.py:198-206` feeds every scored CVE into the same Kruskal-Wallis regardless of
version, mixing 81 v2.0 scores with 1,538 v3.x scores. The paper deliberately pins to one
version. v2 skews low and is concentrated in older CVEs, so this is a confound, not noise.

**Note:** the refresh only *partly* addresses this. It reveals how many of the 81 NVD has since
re-scored under v3.x; any genuine v2-only remainder is an analysis decision (report separately,
or exclude from the pooled test). v2 cannot be converted to v3.

### 2.3 No vector strings at all

`download_nvd.py:142-150` writes `cve_id, published, description, cvss_score, cvss_version,
cwe_ids, cpe_strings`. `vectorString` is available in the same `cvssData` object already being
read and is simply not captured. RQ3 is blocked on this and nothing else.

### 2.4 Stale records on confirmed CVEs

NVD reanalyses records after publication, and the 2024+ CPE backlog is actively being worked
through. Among our 1,676 confirmed-Yes CVEs, as of the 2026-06-25 snapshot:

| condition | n | effect of backfill |
|---|---|---|
| no usable CWE (`NVD-CWE-noinfo` / `NVD-CWE-Other`) | **118** (7.0%) | contribute nothing to RQ1 today; would enter the CWE-888 distribution |
| no CPE string at all | **196** (11.7%) | dead ends for Stage 5 CPE expansion and for the `C` capture set in three-source recall |
| already REJECTED | 3 | the entire non-additive population |

This is the strongest argument for the refresh, and it is independent of the paper extension:
**7% of the confirmed set is invisible to RQ1 purely because NVD had not yet assigned a CWE.**

---

## 3. Why a full re-download, not a targeted fetch

The intuitive move — re-fetch only the confirmed-Yes CVEs — is the expensive one. The NVD 2.0
API has no batch-by-ID endpoint, so targeted fetches cost one request per CVE, while
`download_nvd.py:73` already pages at 2,000 per request.

| target | requests | wall time (with API key) |
|---|---|---|
| 1,676 confirmed-Yes | 1,676 | ~17 min |
| 5,700 non-excluded reviewed | 5,700 | ~57 min |
| **full corpus (181 pages)** | **~181** | **~15–30 min** |

A full re-download is ~30× fewer requests than the reviewed subset, no slower in wall time, and
yields a single consistent vintage rather than a sidecar that leaves two vintages coexisting in
one analysis.

---

## 4. What the refresh does *not* put at risk

### 4.1 Judgments

Judgments are keyed `(category, cve_id)` in `judgment_store.csv` and CVE IDs are stable. No NVD
update makes a Yes row stop being a Yes row. This is the refresh invariant the store was built
for: a deliberate `01_raw` regeneration creates review load only for genuinely new rows.

### 4.2 The pinning invariant

Pinning means *both search methods see the same snapshot*, so a vendor/keyword gap reflects
search terms rather than data freshness. It does **not** mean the snapshot never moves.
Re-downloading and re-running both searches preserves the invariant at a new date.

### 4.3 The ontology T-Box

`ontology/homeiot.ttl`, `shapes.ttl`, `homeiot-align.ttl`, `external_classes.tsv`, and the
generated `data/categories.csv` / `data/ontology/families.csv` all derive from hand-authored
facets. None of `render_categories`, `render_families`, `shacl_validate`, `check_alignment`, or
`reason` reads the store or the snapshot. The 27 published in/out rulings, the 24 leaf / 13 fold
structure, and the SAREF alignment gap cannot move when CVE data changes — the circularity
boundary guarantees it. **`ontology_build.py --check` stays green throughout.**

The one ontology-adjacent figure that *does* move is prose: "15 of 24 categories have no
external class, and those carry **91.5% of the confirmed CVEs**." The 15/24 is structural; the
91.5% is CVE-derived and gets restated.

---

## 5. The mechanical hazard — `download_nvd.py` cannot refresh in place

The script is built for **resume**, which makes it an append-and-dedupe tool, not a refresh tool:

- `download_nvd.py:349` — `file_mode = "a"` when the target exists and is non-empty
- `download_nvd.py:311-316` — preloads every existing `cve_id` into `seen_ids`
- `download_nvd.py:186` — skips any fetched CVE already in `seen_ids`

Pointing it at the existing `nvd_all.csv` therefore gives one of two wrong results:

1. **Progress file intact** — all 181 pages are marked complete; nothing is fetched.
2. **Progress file deleted** — all 181 pages are re-fetched, but every CVE already present is
   discarded. Only ~6 weeks of new CVEs are appended. All 360,981 existing rows keep their June
   vintage, the 118 CWE-less and 196 CPE-less rows stay empty, and `vector_string` is populated
   on new rows only — a file that looks complete while being silently half-stale.

**A real refresh requires writing to a fresh path**, or deleting both `nvd_all.csv` and
`nvd_all.csv.progress.json` first.

### Keep the old snapshot until cutover is done

The 2026-06-25 vintage is **irreproducible** — NVD serves only current state, so once that CSV
is deleted the data behind every number currently in `docs/RESULTS.md` and the report draft can
never be regenerated. It is 288 MB and gitignored, so retaining it through the cutover costs
nothing and preserves the ability to answer "reproduce this table." Delete it only after the new
snapshot is downloaded, the searches re-run, `RESULTS.md` restated, and the churn diff recorded.

---

## 6. Implementation

### Step 1 — parser fields (`scripts/download_nvd.py`)

- Add `cvssMetricV40` to the metric-preference loop at `:118`. Order matters: prefer v3.1 → v3.0
  → v4.0 → v2.0, so the majority of the corpus stays on v3.x and v4.0 is used only where no v3
  metric exists (this is what recovers the 57 unscored CVEs without re-versioning the corpus).
- Capture `cvssData.vectorString` alongside `baseScore` and emit it as a new `vector_string`
  column in the row dict at `:142-150` and the header at `:70`.
- Both fields come from the `cvssData` object already being read — no extra requests.

### Step 2 — download to a fresh path

Write to a new file (e.g. `data/nvd-snapshot/nvd_all_2026-08.csv`) with its own progress file.
Do **not** target the existing path. ~181 requests, ~15–30 min with an API key.

### Step 3 — churn diff (before cutover)

Compare old vs new over the 1,676 confirmed-Yes CVEs and record:

- base scores changed, and by how much
- of the 118 CWE-less, how many gained a CWE
- of the 196 CPE-less, how many gained CPE strings
- newly REJECTED records
- v2.0 records re-scored under v3.x (feeds the §2.2 decision)

This is a genuine data-quality finding for the threats-to-validity section — NVD reanalysis
churn over a six-week window on a fixed confirmed set — not just bookkeeping.

### Step 4 — cutover and re-run

1. Move the new file into `data/nvd-snapshot/nvd_all.csv`; update `SNAPSHOT.md` provenance
   (date, total CVEs, note the two added columns).
2. Re-run **both** searches against it. `build_search.py` skips categories that already have
   outputs, so this needs a force/rebuild path. Per the standing recall finding, that rebuild is
   pending work regardless — it is not extra cost attributable to this plan.
3. Let new rows flow into Stage 4 review; the store absorbs everything already settled.
4. Regenerate derived artifacts: `term_precision.csv`, `recall_estimate.csv`, `cwe888_*`,
   `cvss_*`.

### Step 5 — RQ3 implementation (the payoff)

- Parse `vector_string` into AV / AC / PR / UI / S / C / I / A.
- Implement the v4.0 → 3.x back-conversion for v4.0-only records: VC/VI/VA → C/I/A, and any
  non-None SC/SI/SA → `Scope: Changed`.
- Per-category distributions of Attack Vector, Scope, and CIA impact combinations, mirroring the
  extension's Figs. 8–10.

### Step 6 — ontology

- **Add a `--snapshot` flag to `ontology_build.py`.** `SNAPSHOT` is a module constant at `:54`
  and the arg list parameterizes only `--ttl`, so the KG will read
  `data/nvd-snapshot/nvd_all.csv` regardless of where anything else is pointed.
  `cvss_analysis.py` and `cwe888_analysis.py` both already take `--snapshot`. Without the flag,
  the KG can silently be built from a different vintage than the CWE map it is verified against.
- **Re-export the instance KG.** `build_kg` (`ontology_build.py:401`) reads all three moving
  inputs — population from `judgment_store.csv`, `hydrate()` from the snapshot at `:349`, and
  `load_cwe888()` from `cwe888_cve_map.csv`. After the refresh the 118 CWE-less CVEs gain
  `hkg:Weakness` nodes, the 57 v4.0-only ones gain `hkg:cvssScore`, the 196 CPE-less ones gain
  `hkg:Product`/`hkg:Vendor` links, `missing_from_snapshot` shrinks, and `hkg:snapshotDate`
  updates.
- **Add vector predicates to `ontology/homeiot-kg.ttl`.** It declares `hkg:cvssScore` and
  `hkg:cvssVersion` but nothing for vectors. Adding `hkg:attackVector`, `hkg:scope`, and the CIA
  impact predicates makes RQ3 queryable in SPARQL alongside CWE class and category — the
  `kg-research` skill picks it up with no further work. The KG is regenerated wholesale on each
  export, so there is no migration.

---

## 7. Ordering constraints

Two gates must stay green, and one of them is order-sensitive:

1. `ontology_build.py --check` — unaffected by the refresh (§4.3), but re-run to confirm.
2. `--verify-kg` — reconciles the instance graph against `judgment_store.csv` **and**
   `cwe888_cve_map.csv`. Regenerating the CWE map off the new snapshot without re-exporting the
   KG makes this fail, correctly.

**Required sequence:** `cwe888_analysis.py` → `ontology_build.py --export-kg` →
`ontology_build.py --verify-kg`.

Never reserialize the hand-authored `.ttl` files; `--write` emits CSVs only.

---

## 8. What gets restated

Everything below is computed against the snapshot and must be re-derived and re-dated together,
so no artifact cites a mix of vintages:

- `data/nvd-snapshot/SNAPSHOT.md` — date, total CVEs, added columns
- `docs/RESULTS.md` — all result tables
- `docs/home_iot_security_report.tex` and `docs/figures/` — every figure and cited number
- the SAREF-gap "91.5% of confirmed CVEs" figure (§4.3)
- `data/difference/` derived CSVs: `term_precision`, `recall_estimate`, `cwe888_*`, `cvss_*`
- `data/ontology/homeiot-kg.ttl`

---

## 9. Out of scope for this plan

These came out of the same review of the paper extension but need no snapshot change:

- **Vendor concentration reporting.** Pure analysis over CPE data already in hand. The
  extension publishes its CWE table both with and without Qualcomm (75%+ of one category).
  Our tvOS exclusion already handled the worst case, but concentration persists: `pet` 51%
  furbo, `hub` 45% insteon, `alarms` 45% goabode, `robotvacuum` 44% ecovacs, `doorbell` 36%
  akuvox. `hub` has both the highest median CVSS of any category (9.8, 53% Critical) *and* 45%
  single-vendor concentration — that number is not safe to cite as a category property without
  a sensitivity check. Proposal: a `--exclude-vendor` flag on both analysis scripts plus a
  Table II-style concentration report.
- **CVEs-by-year for the confirmed set.** `nvd_stats.py` does this for the whole snapshot only.
  The confirmed set spans 2001–2026 with a distinct 2018 spike (256).
- **MITRE Top-25 / OWASP Top-10 cross-reference** in the lessons-learned framing — cheap, and
  citable.
- **CWE-888 catalog version.** The extension moved to the 2025-09-09 version; we pin v4.12
  (2023-06-29) to match the original paper. Bumping breaks comparability with our own published
  RQ1 numbers. Recommend leaving pinned unless deliberately chasing the extension's figures.
  This is a MITRE catalog question, unrelated to NVD.
- **"Vulnerable components" axis** (their infotainment / RKE / TCU analysis). The home-IoT
  analogue — web UI / mobile app / firmware update / cloud API / local protocol — is a whole new
  labelling pass, not an extension of this one.

---

## 10. Open decisions

1. **v2-only remainder (§2.2).** ~~After the churn diff shows how many of the 81 were re-scored~~
   — **measured: zero of the 81 were re-scored** (§11.2). The refresh does not shrink this at all,
   so it is now purely an analysis decision. `cvss_analysis.py --score-versions 3` implements the
   exclusion; the default stays `all` so published numbers do not move silently, and
   `cvss_matrix.md` now prints the version mix plus an explicit confound caveat. **Recommend
   switching the published figure to `--score-versions 3`** and reporting the 81 v2-only CVEs
   separately — they are 5% of the population and the extension pins to one version. Not done here:
   it changes a published number, which is the supervisor's call.
2. **Metric preference order (Step 1).** ~~Proposed~~ **implemented** as v3.1 → v3.0 → v4.0 → v2.0.
   Confirmed correct in practice: of the 57 previously unscored CVEs, 54 are v4.0-only and now
   carry a score, while no CVE already scored under v3.x was re-versioned (§11.1).
3. **When to delete the old snapshot.** Not deleted. The 2026-06-25 vintage is retained as
   `data/nvd-snapshot/nvd_all_2026-06.csv` (+ its progress file and
   `SNAPSHOT_nvd_all_2026-06.md`), all gitignored. Retaining it costs nothing and is what makes
   "reproduce this table" answerable for anything published off the June numbers.

---

## 11. What the refresh actually measured (2026-08-05)

New snapshot: **373,518 CVEs** (from 360,981 — **+12,537** in six weeks). Download took 1.2 min
over 187 pages, not the estimated 15-30 min. Churn recorded in
`data/nvd-snapshot/snapshot_churn.md` / `.csv` before cutover.

### 11.1 The parser fix delivered in full

All **57** unscored confirmed-Yes CVEs now carry a base score: **54** were v4.0-only (recovered by
adding `cvssMetricV40`) and **3** were genuinely new NVD analysis. `vector_string` coverage is
**1,676 / 1,676 — 100%**, so RQ3 has no missing-data caveat at all. 1,657 of those normalise to
CVSS 3.x; the other 81 are the v2.0-only records, which are reported as unconvertible.

### 11.2 §2.4's backfill argument does not survive contact with the data

The plan's strongest stated argument for refreshing — 118 CWE-less and 196 CPE-less confirmed CVEs
waiting on NVD's backlog — **did not materialise**:

| condition | predicted effect | measured over six weeks |
|---|---|---|
| no usable CWE (118) | would enter the CWE-888 distribution | **0 gained a CWE** (still 118) |
| no CPE string (196) | would unblock Stage 5 / the `C` capture set | **3 gained CPEs** (now 193) |
| v2.0-only (81) | some re-scored under v3.x | **0 re-scored** (still 81) |
| base score changed | unknown | **0** |
| newly REJECTED | unknown | **0** |

Every one of the 3 real changes is a 2026 CVE that was still mid-analysis at the June download —
i.e. NVD finishing *first* analysis, not *re*-analysis. **NVD reanalysis churn on already-analysed
records is effectively nil at this timescale.** Two consequences:

- The 7.0% of the confirmed set invisible to RQ1 for want of a CWE is **not** a backlog artefact
  that waiting will fix. If those 118 matter, they need a different remedy (manual CWE
  attribution, or reporting the coverage gap as a limitation) — a future refresh will not do it.
- Refreshing again for backfill alone is not worth the re-review cost. The justification for
  *this* refresh reduces to the two parser fixes (§11.1), which were real and complete.

This is a citable threats-to-validity finding in its own right: a fixed confirmed-CVE set is far
more stable across NVD vintages than the "NVD reanalyses records" caveat implies, and the churn
that does occur is concentrated entirely in CVEs published within the last few months.

### 11.3 The ontology held, exactly as §4.3 predicted

`ontology_build.py --check` stayed green throughout (SHACL clean, both CSVs byte-identical,
27/27 rulings reproduced), and `--verify-kg` passes against the new vintage with every count
reconciling (1,676 Vulnerability / 1,738 CategoryAssignment / 1,904 CWE-888 attributions). The
KG grew to ~80k triples with the vector predicates added.
