# CVSS score distribution — confirmed-Yes CVEs

Mirrors RQ2 of the transportation IoT study (Section V): per-category CVSS score distribution (numeric stand-in for its Fig. 6 box plots) and severity-bucket shares (its Fig. 7), plus the same Kruskal-Wallis omnibus test with Dunn's post-hoc pairwise comparisons. A CVE confirmed in several categories counts once per category, not attribution-weighted (a CVSS score is a property of the CVE, unlike a CWE).

| Category | N (Yes) | N Scored | Mean | Median | Std | Min | Q1 | Q3 | Max | Critical% | High% | Medium% | Low% | None% |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| doorlock | 17 | 15 | 7.71 | 8.1 | 1.19 | 5.9 | 6.5 | 8.8 | 9.3 | 12% | 47% | 29% |  |  |
| smartspeakers | 31 | 31 | 7.46 | 7.6 | 1.88 | 3.3 | 6.2 | 8.8 | 9.8 | 19% | 32% | 45% | 3% |  |
| doorbell | 23 | 23 | 7.86 | 7.5 | 1.44 | 4.6 | 7.25 | 9.1 | 9.8 | 30% | 48% | 22% |  |  |
| thermostat | 8 | 8 | 7.94 | 7.85 | 1.82 | 5.4 | 7.0 | 9.8 | 9.8 | 38% | 38% | 25% |  |  |
| babymonitor | 7 | 7 | 6.94 | 7.2 | 0.71 | 5.5 | 6.8 | 7.4 | 7.5 |  | 71% | 29% |  |  |
| smartplugs | 32 | 32 | 7.46 | 7.5 | 1.68 | 4.3 | 6.5 | 8.8 | 10.0 | 22% | 38% | 41% |  |  |
| alarms | 77 | 77 | 8.21 | 8.8 | 1.91 | 2.4 | 6.6 | 9.8 | 10.0 | 47% | 27% | 25% | 1% |  |
| robotvacuum | 23 | 22 | 6.8 | 7.4 | 2.05 | 2.3 | 6.35 | 7.57 | 9.8 | 13% | 52% | 17% | 13% |  |
| fridge | 3 | 2 | 7.95 | 7.95 | 2.62 | 6.1 | 7.02 | 8.88 | 9.8 | 33% |  | 33% |  |  |
| sensors | 2 | 1 | 9.1 | 9.1 | 0.0 | 9.1 | 9.1 | 9.1 | 9.1 | 50% |  |  |  |  |
| lighting | 29 | 29 | 7.59 | 7.9 | 1.2 | 4.6 | 6.5 | 8.1 | 9.8 | 7% | 62% | 31% |  |  |
| appliances | 3 | 3 | 8.13 | 8.1 | 1.65 | 6.5 | 7.3 | 8.95 | 9.8 | 33% | 33% | 33% |  |  |
| hub | 92 | 90 | 8.09 | 8.2 | 1.64 | 2.2 | 7.5 | 9.7 | 10.0 | 27% | 51% | 18% | 1% |  |
| ev-charging | 24 | 24 | 7.32 | 7.65 | 1.5 | 4.2 | 6.3 | 8.8 | 8.8 |  | 58% | 42% |  |  |
| home-power | 31 | 31 | 7.98 | 8.1 | 1.79 | 3.4 | 6.65 | 9.8 | 9.8 | 39% | 32% | 26% | 3% |  |
| garden | 17 | 17 | 7.68 | 8.1 | 2.26 | 2.3 | 6.5 | 9.8 | 9.8 | 35% | 35% | 18% | 12% |  |
| pet | 29 | 29 | 7.12 | 7.4 | 2.25 | 2.4 | 5.5 | 9.8 | 9.8 | 28% | 24% | 41% | 7% |  |
| streaming | 2081 | 2081 | 7.25 | 7.8 | 1.56 | 1.9 | 6.1 | 8.8 | 10.0 | 6% | 55% | 36% | 2% |  |
| airconditioner | 1 | 1 | 6.3 | 6.3 | 0.0 | 6.3 | 6.3 | 6.3 | 6.3 |  |  | 100% |  |  |
| cameras | 555 | 531 | 7.72 | 7.7 | 1.48 | 3.3 | 6.8 | 8.8 | 10.0 | 19% | 51% | 24% | 1% |  |

## Kruskal-Wallis omnibus test

Categories with >= 5 scored CVEs (n=16): doorlock, smartspeakers, doorbell, thermostat, babymonitor, smartplugs, alarms, robotvacuum, lighting, hub, ev-charging, home-power, garden, pet, streaming, cameras

H = 77.454, df = 15, p = 2.03395e-10 — **significant** at alpha=0.05.

Excluded (4, below --min-n 5 scored CVEs): fridge, sensors, appliances, airconditioner

## Dunn's post-hoc pairwise comparisons (Bonferroni-adjusted)

5 of 120 pairs significant (p_bonferroni < 0.05), most significant first:

- **alarms** vs **streaming** (n=77 vs 2081): z=5.441, p_bonferroni=6.341e-06
- **hub** vs **streaming** (n=90 vs 2081): z=5.218, p_bonferroni=2.165e-05
- **cameras** vs **streaming** (n=531 vs 2081): z=4.123, p_bonferroni=0.004479
- **alarms** vs **robotvacuum** (n=77 vs 22): z=3.711, p_bonferroni=0.02474
- **alarms** vs **cameras** (n=77 vs 531): z=3.534, p_bonferroni=0.04904
