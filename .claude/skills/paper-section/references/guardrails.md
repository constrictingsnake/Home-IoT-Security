# Guardrails — figures and citations that must not reach the paper unmarked

Checked on every section map (SKILL.md Step 2). `CLAUDE.md` is authoritative; when it moves,
update this file. Last synced: 2026-09-05.

---

## 1. Retracted figures — never cite, in any section

| figure | why it died | what to say instead |
|---|---|---|
| **"15 of 24 categories (62%) have no corresponding external class, carrying 91.5% of confirmed CVEs"** | Rested on a hand-typed `hiot:alignmentPrecision` label; the original searches stopped at SAREF core. Three denoting classes were already sitting uncited in the manifest. Nine labels were wrong in *both* directions. | The three replacement claims: (a) only a generic superclass denotes **6 of 24 (25%)**, carrying **10.0%** of confirmed CVEs; (b) **the strong one** — `s4bldg:AudioVisualAppliance` covers **five** categories carrying **61.1%** of confirmed CVEs, so granularity, not absence, is the gap; (c) precision after correction is **7 exact (29%) / 17 coarse (71%)**. |
| **`capturesAV` at 79% dominance** | Under correction, and now fails *both* gates: Phase A rules it NOT-USABLE for `cameras` (modal share 0.591 — ~43% of sampled camera devices are DVR/NVR/XVR with no lens) and for `alarms` (0.574); the κ subsample puts it at **0.386**, `stays-Estimated`. Waits on the F4 cameras subtype pass. | Use `actuatesPhysical` / `actuationConsequence` — the only two facets clearing both gates (8 of 10 measured cells, **85.6%** of CVE mass). |
| **"web-admin categories show 25% Tainted Input vs 13%"** and **"AV:Network 77% vs 52%"** (commit `6e9617d`) | `facet_derive.py` found `hasWebAdminUI` pattern-fragile — 19 of 22 categories swing >25 points on keyword choice — and the hand assignment wrong for 7 of 22, all in the same direction. The grouping variable is unevidenced and largely a proxy for `cameras`. | Report the failed derivation as a result. It is why `hiot:evidenceTier` exists. |
| **"our reasoner reproduces all 31 published in/out rulings"** | Not retracted, but forbidden as a headline: most rulings are in-scope categories confirming they are in scope — true by construction, verifying nothing. | "Every criterion is enforced by a negative boundary case" (`--self-test`): `non-networked-detector` (1), `tablet-control-panel` (2), `commercial-hvac-controller` (3), `transport-networking` (4), `monitored-alarm-service` (5). |
| **Historical 2-rater π values 0.358 / 0.131 / 0.283** | Superseded. Claude authored both the prior assignment and the value definitions both raters annotated against, so they were flattered. | Quote the 3-rater Fleiss' κ from `data/facets/facet_agreement.csv` everywhere. |

## 2. Standing qualifications — cite only with the caveat attached

- **Recall ≈ 0.60 pooled** (`recall_estimate.csv`) — 2-source Chapman, biased *down* by V–K positive dependence, so it is an **upper bound**. `raw` (search-stage) recall is defensible today; the `yes`-population recall is **not paper-grade**. `recall = 1.0` rows are `degenerate` and excluded from the pool.
- **`hub` severity dominance** — `hub` is ~45% single-vendor (Insteon). Hedge wherever it appears.
- **All 496 TTL facet assertions are `hiot:Estimated`.** Legitimate for organising an analysis; never evidence. Never present a contrast whose grouping variable is Estimated without saying so.
- **Facet dominance** — `cameras` is 51% of the confirmed population, so a facet cell can look like an independent grouping while being a rename of `cameras`. Check the one-category share first. Contrast the *minority* cells.
- **A citation is evidence only if it covers the corpus** — `facet_source_coverage.py`; the first F5 pass had a median cited-vendor share of **3%**. A regulation binding a *market* is not the same as a standard binding the product *class*.
- **Two standing data gaps that no refresh will clear** (`snapshot_churn.md`): 7.0% of the confirmed set has no usable CWE, 11.5% no CPE. Report as limitations; do not blame the NVD backlog.
- **21.6% of confirmed-Yes rows carry no device CPE** and cannot be product-sampled at any budget.
- **Only 10 of 24 categories were samplable** in Phase A; the rest stay UNMEASURED, never silently sound.

## 3. Bibliography — FULL PASS COMPLETED 2026-09-08

All 48 `\bibitem` entries were verified against Crossref, the arXiv API, USENIX proceedings
pages, and publisher records. **Every correction below is already applied in the tex** (keys
renamed, prose author names fixed, `\cite` keys rewritten; 48 cited = 48 defined, no dangling
refs). Do not re-flag these as defects — they are fixed. Kept as the record of what was wrong,
because the failure mode recurs.

**Fabricated first authors — 9 entries (key renamed in each case):**

| old key | → new key | the fabrication |
|---|---|---|
| `alsubaei2018` | `ali2018` | authors invented → **B. Ali, A. I. Awad**, *Sensors* 18(3):817 |
| `kumar2019` | *(kept)* | Sorber/Lau/Snoeren/Feamster invented → **Kumar, Shen, Case, Garg, Alperovich, Kuznetsov, Gupta, Durumeric** |
| `sanders2017` | `dahmen2017` | authors **and** venue wrong → **Dahmen, Cook, Wang, Honglei**, *J. Reliable Intell. Env.* 3(2):83–98 |
| `apthorpe2019` | `valente2019` | → **Valente, Koneru, Cardenas**, ICIOT 2019, 173–180 |
| `jacobsson2018` | `bugeja2018cameras` | → **Bugeja, Jonsson, Jacobsson**, PerCom Wksh 2018, 537–542 |
| `brooks2022` | `johnson2022` | "C. Brooks" invented → **Johnson, Berg, Anderson, Wright**, *Energies* 15(11):3931 |
| `fernandez2023` | `builgil2023` | "M. Fernandez" invented → **Buil-Gil, Kemp, Kuenzel, Coventry, Zakhary, Tilley, Nicholson**; article no. 107885 → **107770** |
| `zheng2022` | `yang2022` | "Y. Zheng" invented → **J. Yang, L. Sun**, *IEEE Access* 10:124167–124192 |
| `georgiadou2024` | `vardakis2024` | "A. Georgiadou" invented → **Vardakis, Hatzivasilis, Koutsaki, Papadakis** |
| `sivaraman2019` | `mauro2019` | "V. Sivaraman" invented → **Mauro Junior, Melo, Lu, d'Amorim, Prakash** |

**Wrong initials / wrong year:** `hammi2022` (M. T. → **B.** Hammi) · `chen2024`→`chen2025`
(Y. Yang→**C.** Yang, Y. Zheng→**Z.** Zheng, year 2024→**2025**) · `singla2023` (A.→**R.**
Singla, S.→**N.** Reddy) · `xenofontos2021`→`xenofontos2022` (arXiv preprint → published
*IEEE IoT J.* 9(1):199–221).

**Previously author-less, now resolved:** `taxonomyci2023`→`alahmadi2023` ·
`voicecontrol2022`→`hewitt2022` (Hewitt & Cunningham) · `iotflow2023`→`schmidt2023` ·
`firmrec2024`→`xiao2024` (real title is "Accurate and Efficient Recurring Vulnerability
Detection for IoT Firmware"; *FirmRec* is the tool, not the title).

**`sandia2020` — RESOLVED 2026-09-09.** The unconfirmable report number (SAND2020-11401) is gone.
The key is now `johnson2022sandia` = J. Johnson, B. Anderson, B. Wright, J. Quiroz, T. Berg,
R. Graves, J. Daley, K. Phan, M. Kunz *et al.*, "Cybersecurity for electric vehicle charging
infrastructure," Sandia National Laboratories, **SAND2022-9315**, 2022,
`https://www.osti.gov/biblio/1877784` (tex 1577). The `\stub` is gone with it, and no
bibliography blocker remains: 48 cited = 48 defined, no dangling refs.

`ontology/study_sources.tsv` is now **10/10 `verified=yes`** with authors/venue/year filled;
all four ontology gates re-run green afterwards. Note `nistir8267` is a **draft** NISTIR
(labelled as such in the tex) — it was never finalized.

**Missing entirely:** SAREF / SMARTM2M TS 103 264 and S4BLDG TS 103 410-3 have no `\bibitem`,
so any standards-gap claim currently cites nothing. The extensions added 2026-08-10 are v2.1.1;
the manifest records `iri` and `vocabulary` only, so SAREF **versions** behind the other entries
are undocumented.

## 4. Known stale strings in the tex

`PLAN_paper_submission_fixes.md` §5.2 keeps the authoritative grep. Any of these appearing in a
section under discussion is a defect, not a number:

```
6,535 · 3,413 · 3,121 · 360,981 · 2026-06-25 · 343 distinct · 976 were
2,081 · H=77.454 · df=15 · "22 non-empty" · "the only categories above N=75"
"five reviewers" · results_all_<category>.xlsx
```

Also structural: `\label{sec:conclusion:data-availability}` sits on a **starred** section, so the
`\ref` in RQ2 (~line 833) prints the previous numbered section's number.
