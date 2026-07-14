# CVSS score distribution — confirmed-Yes CVEs

Mirrors RQ2 of the transportation IoT study (Section V): per-category CVSS score distribution (numeric stand-in for its Fig. 6 box plots) and severity-bucket shares (its Fig. 7), plus the same Kruskal-Wallis omnibus test with Dunn's post-hoc pairwise comparisons. A CVE confirmed in several categories counts once per category, not attribution-weighted (a CVSS score is a property of the CVE, unlike a CWE).

| Category | N (Yes) | N Scored | Mean | Median | Std | Min | Q1 | Q3 | Max | Critical% | High% | Medium% | Low% | None% |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| doorlock | 31 | 27 | 7.34 | 7.5 | 1.61 | 2.4 | 6.5 | 8.8 | 9.8 | 10% | 39% | 35% | 3% |  |
| smartspeakers | 37 | 37 | 7.43 | 7.6 | 1.85 | 3.3 | 6.3 | 8.8 | 9.8 | 16% | 35% | 46% | 3% |  |
| doorbell | 44 | 44 | 7.23 | 7.5 | 1.77 | 3.5 | 5.98 | 8.8 | 9.8 | 20% | 41% | 36% | 2% |  |
| thermostat | 17 | 17 | 7.54 | 7.5 | 1.81 | 3.5 | 6.5 | 8.8 | 9.8 | 24% | 41% | 29% | 6% |  |
| babymonitor | 11 | 11 | 7.38 | 7.3 | 1.14 | 5.5 | 6.8 | 7.5 | 9.8 | 9% | 64% | 27% |  |  |
| smartplugs | 36 | 36 | 7.55 | 7.5 | 1.7 | 4.3 | 6.5 | 8.93 | 10.0 | 25% | 33% | 42% |  |  |
| alarms | 88 | 88 | 8.09 | 8.8 | 1.87 | 2.4 | 6.57 | 9.8 | 10.0 | 42% | 31% | 26% | 1% |  |
| robotvacuum | 27 | 26 | 6.64 | 7.4 | 1.93 | 2.3 | 5.78 | 7.5 | 9.8 | 11% | 44% | 30% | 11% |  |
| fans | 1 | 1 | 7.4 | 7.4 | 0.0 | 7.4 | 7.4 | 7.4 | 7.4 |  | 100% |  |  |  |
| fridge | 3 | 2 | 7.95 | 7.95 | 2.62 | 6.1 | 7.02 | 8.88 | 9.8 | 33% |  | 33% |  |  |
| sensors | 3 | 2 | 7.8 | 7.8 | 1.84 | 6.5 | 7.15 | 8.45 | 9.1 | 33% |  | 33% |  |  |
| airpurifier | 2 | 2 | 7.95 | 7.95 | 2.62 | 6.1 | 7.02 | 8.88 | 9.8 | 50% |  | 50% |  |  |
| lighting | 34 | 34 | 7.58 | 7.5 | 1.1 | 4.6 | 6.75 | 8.1 | 9.8 | 6% | 68% | 26% |  |  |
| appliances | 3 | 3 | 8.13 | 8.1 | 1.65 | 6.5 | 7.3 | 8.95 | 9.8 | 33% | 33% | 33% |  |  |
| hub | 98 | 95 | 8.07 | 8.2 | 1.63 | 2.2 | 7.45 | 9.6 | 10.0 | 27% | 51% | 18% | 1% |  |
| ev-charging | 31 | 31 | 7.46 | 8.0 | 1.43 | 4.2 | 6.5 | 8.8 | 8.8 |  | 65% | 35% |  |  |
| home-power | 33 | 33 | 7.99 | 8.1 | 1.78 | 3.4 | 6.5 | 9.8 | 9.8 | 39% | 30% | 27% | 3% |  |
| garden | 18 | 18 | 7.8 | 8.1 | 2.25 | 2.3 | 6.72 | 9.8 | 9.8 | 39% | 33% | 17% | 11% |  |
| pet | 35 | 35 | 7.36 | 8.1 | 2.22 | 2.4 | 5.7 | 9.8 | 9.8 | 31% | 26% | 37% | 6% |  |
| streaming | 2090 | 2090 | 7.25 | 7.8 | 1.57 | 1.9 | 6.1 | 8.8 | 10.0 | 7% | 55% | 36% | 2% |  |
| airconditioner | 2 | 1 | 6.3 | 6.3 | 0.0 | 6.3 | 6.3 | 6.3 | 6.3 |  |  | 50% |  |  |
| cameras | 778 | 736 | 7.78 | 7.7 | 1.55 | 1.6 | 6.8 | 8.8 | 10.0 | 22% | 48% | 24% | 1% |  |

## Kruskal-Wallis omnibus test

Categories with >= 5 scored CVEs (n=16): doorlock, smartspeakers, doorbell, thermostat, babymonitor, smartplugs, alarms, robotvacuum, lighting, hub, ev-charging, home-power, garden, pet, streaming, cameras

H = 86.500, df = 15, p = 4.43919e-12 — **significant** at alpha=0.05.

Excluded (6, below --min-n 5 scored CVEs): fans, fridge, sensors, airpurifier, appliances, airconditioner

## Dunn's post-hoc pairwise comparisons (Bonferroni-adjusted)

5 of 120 pairs significant (p_bonferroni < 0.05), most significant first:

- **cameras** vs **streaming** (n=736 vs 2090): z=5.979, p_bonferroni=2.701e-07
- **hub** vs **streaming** (n=95 vs 2090): z=5.176, p_bonferroni=2.713e-05
- **alarms** vs **streaming** (n=88 vs 2090): z=4.892, p_bonferroni=0.0001196
- **hub** vs **robotvacuum** (n=95 vs 26): z=4.172, p_bonferroni=0.003628
- **alarms** vs **robotvacuum** (n=88 vs 26): z=4.089, p_bonferroni=0.005204
