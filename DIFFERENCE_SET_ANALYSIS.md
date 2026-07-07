# Difference-Set Analysis — Snapshot Numbers

**Date generated:** 2026-07-06
**Source data:** `data/difference/final_resolved.csv` + `data/difference/human_review_queue.csv`
**Scenario modeled:** `Human Verdict 1` treated as the finalized judgment for every flagged row (i.e. skipping the real pipeline's requirement that both human reviewers agree before a row settles).

> **Caveat — read before citing these numbers elsewhere.** The actual pipeline (`finalize_judgments.py`) only finalizes a flagged row when **both** `Human Verdict 1` and `Human Verdict 2` agree and neither is "Maybe." As of this snapshot, `Human Verdict 1` is 100% filled (1,011/1,011 flagged rows) but `Human Verdict 2` is only ~1/3 filled (329/1,011). So of the numbers below, only 3,662 rows (`ai-consensus` + `human`) are the pipeline's *official* settled state — the other 991 rows are provisional single-reviewer calls used here to get a fuller picture, not yet reconciled against Reviewer 2. Re-run this analysis once `Human Verdict 2` is more complete.

---

## 1. Headline numbers (4,653 difference-set CVEs, 22 categories)

| Judgment | Count | % |
|---|---|---|
| No (false positive) | 3,514 | 75.5% |
| Yes (true positive) | 1,131 | 24.3% |
| Maybe (still ambiguous even to Reviewer 1) | 8 | 0.2% |

**Resolution source:**

| Source | Count |
|---|---|
| `ai-consensus` (AIs unanimous & confident) | 3,642 |
| `human_verdict1` (flagged, resolved via Reviewer 1 only) | 991 |
| `human` (both reviewers agreed — official pipeline settle) | 20 |

---

## 2. Vendor search vs. keyword search — false-positive rate

| Direction | Rows | FP rate | Yes rate |
|---|---|---|---|
| `vendor_only` | 3,738 | **78.1%** | 21.7% |
| `keyword_only` | 915 | **64.9%** | 34.9% |

Vendor/brand-name search is meaningfully noisier than device-phrase (keyword) search — consistent with CLAUDE.md's general note that brand names collide with unrelated products more often than device phrases do.

---

## 3. By category (all directions combined), sorted by volume

| Category | Total | No | Yes | Maybe | FP rate |
|---|---|---|---|---|---|
| cameras | 3,158 | 2,597 | 554 | 7 | 82.2% |
| streaming | 442 | 291 | 151 | 0 | 65.8% |
| alarms | 150 | 113 | 37 | 0 | 75.3% |
| hub | 125 | 34 | 90 | 1 | 27.2% |
| airconditioner | 124 | 118 | 6 | 0 | 95.2% |
| lighting | 80 | 52 | 28 | 0 | 65.0% |
| smartplugs | 73 | 47 | 26 | 0 | 64.4% |
| babymonitor | 68 | 62 | 6 | 0 | 91.2% |
| thermostat | 64 | 56 | 8 | 0 | 87.5% |
| doorbell | 63 | 32 | 31 | 0 | 50.8% |
| ev-charging | 56 | 9 | 47 | 0 | 16.1% |
| robotvacuum | 51 | 29 | 22 | 0 | 56.9% |
| smartspeakers | 37 | 7 | 30 | 0 | 18.9% |
| home-power | 36 | 4 | 32 | 0 | 11.1% |
| doorlock | 31 | 16 | 15 | 0 | 51.6% |
| pet | 29 | 0 | 29 | 0 | 0.0% |
| sleeptracker | 28 | 28 | 0 | 0 | 100.0% |
| garden | 16 | 5 | 11 | 0 | 31.2% |
| sensors | 10 | 7 | 3 | 0 | 70.0% |
| shades | 5 | 5 | 0 | 0 | 100.0% |
| appliances | 4 | 1 | 3 | 0 | 25.0% |
| fridge | 3 | 1 | 2 | 0 | 33.3% |

**Cameras dominates the whole dataset:** 68% of all rows, and its 2,597 "No" verdicts are 74% of *every* "No" in the dataset. Its FP rate alone (82.2%) pulls the overall average up significantly.

**Cleanest categories:** `pet` (0% FP), `home-power` (11.1%), `ev-charging` (16.1%), `smartspeakers` (18.9%), `hub` (27.2%).

**Worst categories:** `sleeptracker` and `shades` are **100% false positive** (entire difference sets are noise — matches the known "~88% wearables, 0 bedside monitors" sleeptracker problem in CLAUDE.md), `airconditioner` 95.2%, `babymonitor` 91.2%, `thermostat` 87.5%.

---

## 4. Human review load

- **1,011 / 4,653 rows (21.7%)** were flagged for human review (AI judgments not unanimous, or both strong reviewers Low confidence + not unanimous).

Flag rate by category (highest → lowest):

| Category | Flag rate | Category | Flag rate |
|---|---|---|---|
| garden | 93.8% | streaming | 37.1% |
| babymonitor | 92.6% | hub | 22.4% |
| shades | 80.0% | smartspeakers | 21.6% |
| appliances | 75.0% | smartplugs | 20.5% |
| sensors | 70.0% | robotvacuum | 15.7% |
| fridge | 66.7% | cameras | 14.7% |
| ev-charging | 66.1% | sleeptracker | 14.3% |
| home-power | 58.3% | airconditioner | 10.5% |
| doorlock | 58.1% | pet | 6.9% |
| alarms | 49.3% | thermostat | 3.1% |
| lighting | 45.0% | doorbell | 38.1% |

Interesting inversion: the categories that are almost pure noise (`thermostat`, `airconditioner`) have the *lowest* flag rates — the AIs agree confidently that most of it is junk. The categories with the highest flag rates (`garden`, `babymonitor`, `shades`) are small-volume and genuinely ambiguous.

---

## 5. AI reviewer accuracy (vs. Human Verdict 1 as ground truth)

| Reviewer | Agreement on the 1,011 *hard/flagged* rows | Agreement across *all* 4,653 rows |
|---|---|---|
| **Claude** | **79.6%** | **95.6%** |
| Codex | 55.5% | 90.3% |
| Gemini | 47.8% | 88.7% |

- Claude–Codex pairwise agreement (all rows): **87.6%** (refines the ~86% figure in CLAUDE.md with the fuller dataset).
- 3-way AI unanimity rate: **78.3%** of all rows.
- Where Claude called a flagged row "No," the human overturned it to "Yes" in **102 / 574 cases (17.8%)** — Claude's main error mode on ambiguous rows is under-calling (false negative), not over-calling.

This is consistent with CLAUDE.md's documented model biases: Claude is the reliable anchor, Codex over-excludes, Gemini over-includes.

---

## 6. Term precision — biggest noise sources (from `term_precision.csv`)

34 terms flagged as prune candidates (≥5 judged rows, ≤10% precision). The single biggest offender:

| Term | Method | Category | Judged | Yes | Precision |
|---|---|---|---|---|---|
| **d-link** | vendor | cameras | **1,769** | 61 | **3.4%** |

`d-link` alone accounts for 38% of the *entire* 4,653-row difference set — this is the dominant noise source in the whole project (D-Link's generic DCS-series cameras dragging in unrelated CVEs).

Other zero-precision terms worth pruning:

| Term | Method | Category | Judged | Precision |
|---|---|---|---|---|
| moxa | vendor | cameras | 302 | 0.0% |
| media player | keyword | streaming | 240 | 0.0% |
| fujitsu | vendor | airconditioner | 96 | 0.0% |
| milesight | vendor | cameras | 79 | 0.0% |
| cerberus | vendor | thermostat | 36 | 0.0% |
| pelco | vendor | cameras | 21 | 0.0% |
| intercom | keyword | doorbell | 20 | 0.0% |
| anviz | vendor | cameras | 20 | 0.0% |
| verint | vendor | cameras | 17 | 0.0% |
| garmin | vendor | sleeptracker | 16 | 0.0% |
| eufy homebase | vendor | alarms | 13 | 0.0% |
| eufy | vendor | robotvacuum | 13 | 0.0% |
| honeywell security | vendor | cameras | 12 | 0.0% |
| homey | vendor | hub | 12 | 0.0% |
| geovision | vendor | cameras | 11 | 0.0% |
| anker eufy | vendor | smartplugs | 11 | 0.0% |
| allwinner | vendor | streaming | 11 | 0.0% |
| smart switch | keyword | lighting | 24 | 8.3% |
| tp-link tapo | vendor | smartplugs | 24 | 8.3% |

---

## 7. Recall estimate (capture–recapture, from `recall_estimate.csv`)

- **Pooled 2-source Chapman estimate: 52.9% recall** (95% CI 48.9–56.8%), `n_observed` = 3,674, `N̂` ≈ 6,948.
  - i.e. the vendor + keyword searches together are estimated to have found only about half of the true CVE population.
- **Worst-covered category: `alarms`** — 26.6% recall (2-source) / 34.7% (3-source, log-linear w/ CPE expansion) — the most under-searched category by a wide margin.
- `cameras` sits close to the pooled average (~55.4–55.7% recall).

---

## How to refresh this file

1. Re-run the pandas queries against `data/difference/final_resolved.csv` and `data/difference/human_review_queue.csv` (join on `Category, cve_id`, prefer `Final Judgment`/`Final Source` where already `ai-consensus`/`human`, else fall back to `Human Verdict 1`).
2. Re-check `data/difference/term_precision.csv` (`prune_candidate == 'Yes'`) and `data/difference/recall_estimate.csv` (`POOLED` row) for the term-precision and recall sections.
3. Update the "Date generated" line and the `Human Verdict 2` fill count in the caveat above.
