# First-Run Results & Worked Examples

Point-in-time evidence from specific pipeline runs — not needed to operate the pipeline day to
day. See `README.md` for how to run each stage and `CLAUDE.md` for the design rationale behind
these methods.

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
- **Precision (Claude single-review spot-check, `cpe_expansion_precision_spotcheck.csv`): 51/52 = 98% category-correct.** The one miss — `CVE-2024-10523`, the TP-Link Tapo **H100** — is a genuine home IoT device but a *hub*, not a plug; it traces to a mis-confirmed seed (`tp-link:tapo_h100` wrongly settled `Yes` under `smartplugs`). The method faithfully propagated a *seed* error, not a method fault — and Stage-4 review of the candidate would catch it.
- **The part filter earns its place.** It drops 70 app/lib seed CPEs and prevents 4 library-leak candidates (openweave ×2 in cameras, a Tapo app CPE ×2 in smartplugs). Run `--no-part-filter` to see the 56-candidate unfiltered set for comparison.

> **Open item for review (as of 2026-07-02):** the 52 candidates were still unreviewed by the full triple-AI + human pipeline. The 98% is a Claude-only first pass.

---

## Stage 6 — Recall estimation first-run (2026-07-02, raw candidate population)

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
