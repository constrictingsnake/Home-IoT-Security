# Plan — Analysis Improvements (what to do with the confirmed CVE set)

*Status: **Proposed** (2026-07-26). This is a roadmap for **analysis**, not collection. The
existing `PLAN_*` docs are about *finding* CVEs (discovery/mining); this one is about *what we
say* once they're confirmed. Input to every item below is the confirmed in-scope set in
`data/difference/final_resolved.csv` (`Final Judgment = yes`, tvOS-excluded rows dropped),
with the full 361k-CVE `data/nvd-snapshot/nvd_all.csv` as the **baseline control group**.*

## Why we can do more than the transportation-IoT study

- That study was **small-n** — it could only count.
- We have **~1,400 confirmed Yes CVEs across 24 device categories**, a labelled Yes/No corpus,
  and a full NVD baseline. That unlocks three things they couldn't do:
  - **Per-category analysis** — compare a *camera's* risk profile to a *lock's* or *thermostat's*.
    Most IoT-CVE papers treat "IoT" as one blob; splitting by device function is our novel angle.
  - **A baseline control** — every finding becomes "home IoT over-indexes on X *vs. the NVD
    corpus*," which is far stronger than a raw count.
  - **Statistical power** — real significance tests, confidence intervals, concentration indices.

---

## What data we already have (per confirmed CVE)

- `cve_id`, `published` date, `cvss_score`, `cvss_version`, `cwe_ids`, `cpe_strings`, `Category`.
- Full NVD baseline stats already computed in `data/nvd-snapshot/` (CWE, severity, by-year, top vendor).
- **Missing:** CVSS *vector* strings (AV/PR/UI), exploitation signals, patch/exploit references.
  → see *Data enrichment* section for how to get these.

---

## Tier 1 — free from columns we already have

### 1. Weakness fingerprint per category (CWE) — **the headline**
- For each category, CWE distribution vs the NVD baseline; report the **over-index ratio**.
- Prediction: NVD is dominated by web bugs (CWE-79 XSS, CWE-89 SQLi); home IoT should skew to
  **hardcoded credentials (CWE-798), missing auth (CWE-306), command injection (CWE-78),
  credential handling (CWE-259/522)**.
- Research questions:
  - *Which weakness types are over-represented in home IoT vs. software at large?*
  - *Do weakness profiles differ by device function (camera vs. lock vs. thermostat)?*
- Method: per-category CWE histogram + chi-square vs. baseline. Effort: low (data in hand).

### 2. Severity contrast per category
- Mean CVSS and %Critical/%High per category vs. the baseline (13.3% Critical / 34.6% High).
- Research question: *Are physical-safety devices (locks, alarms, garage) more severe than the corpus?*
- **Caveat:** CVSS v2/v3/v4 aren't directly comparable — normalize (use v3.1 subset, or severity bands).
- Effort: low.

### 3. Temporal trends per category
- CVEs/year by category — growth curves and disclosure velocity.
- Research question: *Which device categories are seeing accelerating disclosure, and since when?*
- **Caveat:** NVD's post-2024 CPE backlog truncates recent years — cut off at 2023 or annotate.
- Effort: low.

### 4. Vendor concentration / "monoculture"
- Per category, a concentration index (HHI or Gini) over `vendor:product` from CPE strings.
- Research question: *Are a category's vulnerabilities concentrated in a few vendors, or spread wide?*
- Motivates the supply-chain angle. Effort: low–medium.

### 5. Shared-firmware / ODM detection
- Same CPE product (or SoC vendor — realtek / hisilicon) appearing across many "brands."
- Research question: *How much of home-IoT risk traces to shared reference designs behind many labels?*
- Known-but-underquantified IoT story; our CPE data can surface it. Effort: medium.

---

## Tier 2 — join an external per-CVE dataset (biggest new capability)

Today we measure *known vulnerabilities* but have **no exploitation signal**. Two free,
CVE-ID-keyed datasets fix that with a join — turning "here are the bugs" into "here's the
**risk-weighted** exposure by device type."

### 6. CISA KEV (Known Exploited Vulnerabilities)
- Ground-truth "actually exploited in the wild." Covers all years.
- Research question: *What share of home-IoT CVEs are known-exploited, vs. baseline, and which
  categories carry the most?*

### 7. EPSS (FIRST, daily CSV)
- Probability-of-exploitation score per CVE. Covers all years.
- Research questions:
  - *Do home-IoT CVEs carry higher exploitation probability than the corpus?*
  - *Where does CVSS say "critical" but EPSS says "nobody exploits it"? (the severity–risk gap)*
- Effort for 6+7: low–medium (simple join on CVE ID).

---

## Tier 3 — needs an enrichment pull (fields NVD CSV dropped)

### 8. CVSS vector decomposition (Attack Vector / Privileges / User Interaction)
- The scary IoT combo is **AV:Network + PR:None + UI:None** (remote, unauthenticated).
- Research question: *What % of each category's CVEs are remotely exploitable with no auth?*
- Source: get vectors from **cvelistV5** (see below) — no NVD re-pull needed. Effort: medium.

### 9. Reference-tag signals (patch / exploit availability)
- cvelistV5 tags references as `exploit`, `patch`, `vendor-advisory`, etc.
- Research question: *How often is a public exploit available, and how does patch availability
  vary by category?*
- Effort: medium (parse from cvelistV5 records).

---

## Data enrichment sources (how Tiers 2–3 get their data)

- **cvelistV5** (`github.com/CVEProject/cvelistV5`) — the official CVE List, upstream of NVD.
  - **Use it for:** CVSS **vector strings** (item 8) and **reference tags** (item 9), corpus-wide.
  - Bonus: embeds CISA-ADP KEV/SSVC, but **only back to ~Feb 2024** — most of our corpus is older,
    so use standalone KEV/EPSS as the primary exploitation source.
  - **Do NOT** use it as a search corpus — it has **no CPE** (that's NVD's layer); our search
    engine needs the NVD snapshot. This is a **join onto confirmed CVE IDs only** (~1,400 files).
  - Practical: download the daily **baseline zip**, not a full clone; **pin the release date** for
    reproducibility (matches our fixed-snapshot ethos).
- **CISA KEV catalog** (standalone) — full-history exploitation ground truth (item 6).
- **EPSS** (FIRST daily CSV) — full-history exploitation probability (item 7).

---

## Related published work (align to / cite / fill the gap)

- **A Large-Scale Study of IoT Security Weaknesses and Vulnerabilities in the Wild** (ACM TOSEM,
  2024) — closest comparator; align our **CWE grouping** to it. *Their gap = our angle:* they're
  wild-traffic + weakness-centric, not device-function-centric.
- **EPSS** (Jacobs et al.) and **Measuring the Exploitation of Weaknesses in the Wild** (arXiv
  2405.01289) — motivate the KEV/EPSS join and CWE-level exploitation view.
- **Consumer IoT Device Vulnerability Quantification Frameworks** (MDPI, 2023) — for a "how we
  weight risk" methods section.
- **The gap most share** (and our opening): they analyze "IoT" as one class and rarely use a
  **matched NVD baseline as control**. We do both — per-device-function breakdown *against* a
  corpus baseline.

---

## Suggested order of attack

1. **Item 1 (CWE fingerprint vs. baseline)** — free, and it's the paper's headline table.
2. **Items 6+7 (KEV + EPSS join)** — cheap, and it adds the exploitation axis we completely lack.
3. **Item 8 (CVSS vectors via cvelistV5)** — strong third once the enrichment join exists.
4. Items 2–5 as supporting analyses; item 9 alongside item 8 (same data source).
