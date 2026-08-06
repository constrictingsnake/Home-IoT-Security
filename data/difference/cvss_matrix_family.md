# CVSS score distribution — confirmed-Yes CVEs

Mirrors RQ2 of the transportation IoT study (Section V): per-category CVSS score distribution (numeric stand-in for its Fig. 6 box plots) and severity-bucket shares (its Fig. 7), plus the same Kruskal-Wallis omnibus test with Dunn's post-hoc pairwise comparisons. A CVE confirmed in several categories counts once per category, not attribution-weighted (a CVSS score is a property of the CVE, unlike a CWE).

Reported at the **folding-category** tier (`--group family`): the 24 leaf categories folded per `data/ontology/families.csv`, de-duplicated so a CVE confirmed in two categories of one family contributes one score. Per-category numbers in `cvss_matrix.md` remain the primary reporting unit.

Base-score metric versions in this population: v2.0 (81), v3.0 (339), v3.1 (1244), v4.0 (55).

> **Caveat:** v2.0 and v3.x base scores are pooled here. v2 uses a different formula and skews low, so it is a confound in the Kruskal-Wallis below, not just noise. `--score-versions 3` reruns without the v2-only records.

| Category | N (Yes) | N Scored | Mean | Median | Std | Min | Q1 | Q3 | Max | Critical% | High% | Medium% | Low% | None% |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Access Control | 36 | 36 | 7.16 | 6.95 | 1.58 | 2.4 | 6.5 | 8.35 | 9.8 | 11% | 39% | 47% | 3% |  |
| Audio | 38 | 38 | 7.42 | 7.2 | 1.83 | 3.3 | 6.32 | 8.8 | 9.8 | 16% | 34% | 47% | 3% |  |
| Cameras and Monitors | 936 | 936 | 7.77 | 7.7 | 1.56 | 1.6 | 6.8 | 8.8 | 10.0 | 23% | 50% | 26% | 1% |  |
| Climate & Air | 24 | 24 | 7.39 | 7.45 | 1.68 | 3.5 | 6.25 | 8.43 | 9.8 | 21% | 38% | 38% | 4% |  |
| Electrical & Lighting | 66 | 66 | 7.61 | 7.5 | 1.45 | 4.3 | 6.5 | 8.8 | 10.0 | 17% | 52% | 32% |  |  |
| Alarms & Sensors | 93 | 93 | 8.03 | 8.8 | 1.86 | 2.4 | 6.5 | 9.8 | 10.0 | 41% | 30% | 28% | 1% |  |
| Appliances | 33 | 33 | 6.81 | 7.4 | 1.93 | 2.3 | 6.1 | 7.6 | 9.8 | 15% | 42% | 33% | 9% |  |
| Hubs and Controllers | 247 | 247 | 8.73 | 9.8 | 1.54 | 2.2 | 7.95 | 9.9 | 10.0 | 53% | 34% | 12% | 1% |  |
| Energy | 116 | 116 | 7.54 | 7.5 | 1.81 | 3.1 | 6.4 | 8.8 | 10.0 | 22% | 40% | 34% | 4% |  |
| Outdoor & Pet | 54 | 54 | 7.49 | 8.1 | 2.2 | 2.3 | 6.3 | 9.8 | 9.8 | 33% | 28% | 31% | 7% |  |
| Entertainment | 76 | 76 | 7.34 | 7.8 | 1.62 | 2.6 | 6.1 | 8.1 | 10.0 | 14% | 49% | 36% | 1% |  |

## Kruskal-Wallis omnibus test

Categories with >= 5 scored CVEs (n=11): Access Control, Audio, Cameras and Monitors, Climate & Air, Electrical & Lighting, Alarms & Sensors, Appliances, Hubs and Controllers, Energy, Outdoor & Pet, Entertainment

H = 155.980, df = 10, p = 2.18697e-28 — **significant** at alpha=0.05.

## Dunn's post-hoc pairwise comparisons (Bonferroni-adjusted)

11 of 55 pairs significant (p_bonferroni < 0.05), most significant first:

- **Cameras and Monitors** vs **Hubs and Controllers** (n=936 vs 247): z=-10.498, p_bonferroni=4.869e-24
- **Energy** vs **Hubs and Controllers** (n=116 vs 247): z=-7.549, p_bonferroni=2.416e-12
- **Entertainment** vs **Hubs and Controllers** (n=76 vs 247): z=-7.316, p_bonferroni=1.41e-11
- **Appliances** vs **Hubs and Controllers** (n=33 vs 247): z=-6.783, p_bonferroni=6.463e-10
- **Access Control** vs **Hubs and Controllers** (n=36 vs 247): z=-6.274, p_bonferroni=1.939e-08
- **Electrical & Lighting** vs **Hubs and Controllers** (n=66 vs 247): z=-6.1, p_bonferroni=5.843e-08
- **Hubs and Controllers** vs **Outdoor & Pet** (n=247 vs 54): z=5.383, p_bonferroni=4.032e-06
- **Audio** vs **Hubs and Controllers** (n=38 vs 247): z=-5.332, p_bonferroni=5.338e-06
- **Climate & Air** vs **Hubs and Controllers** (n=24 vs 247): z=-4.701, p_bonferroni=0.0001423
- **Alarms & Sensors** vs **Hubs and Controllers** (n=93 vs 247): z=-4.308, p_bonferroni=0.000908
- **Alarms & Sensors** vs **Appliances** (n=93 vs 33): z=3.618, p_bonferroni=0.0163
