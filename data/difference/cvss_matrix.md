# CVSS score distribution — confirmed-Yes CVEs

Mirrors RQ2 of the transportation IoT study (Section V): per-category CVSS score distribution (numeric stand-in for its Fig. 6 box plots) and severity-bucket shares (its Fig. 7), plus the same Kruskal-Wallis omnibus test with Dunn's post-hoc pairwise comparisons. A CVE confirmed in several categories counts once per category, not attribution-weighted (a CVSS score is a property of the CVE, unlike a CWE).

Base-score metric versions in this population: v2.0 (81), v3.0 (343), v3.1 (1259), v4.0 (55).

> **Caveat:** v2.0 and v3.x base scores are pooled here. v2 uses a different formula and skews low, so it is a confound in the Kruskal-Wallis below, not just noise. `--score-versions 3` reruns without the v2-only records.

| Category | N (Yes) | N Scored | Mean | Median | Std | Min | Q1 | Q3 | Max | Critical% | High% | Medium% | Low% | None% |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| doorlock | 36 | 36 | 7.16 | 6.95 | 1.58 | 2.4 | 6.5 | 8.35 | 9.8 | 11% | 39% | 47% | 3% |  |
| smartspeakers | 38 | 38 | 7.42 | 7.2 | 1.83 | 3.3 | 6.32 | 8.8 | 9.8 | 16% | 34% | 47% | 3% |  |
| doorbell | 45 | 45 | 7.29 | 7.5 | 1.79 | 3.5 | 6.2 | 8.8 | 9.8 | 22% | 40% | 36% | 2% |  |
| thermostat | 18 | 18 | 7.43 | 7.5 | 1.81 | 3.5 | 6.05 | 8.68 | 9.8 | 22% | 39% | 33% | 6% |  |
| babymonitor | 18 | 18 | 7.71 | 7.5 | 1.35 | 5.3 | 7.05 | 8.8 | 9.8 | 17% | 61% | 22% |  |  |
| smartplugs | 37 | 37 | 7.55 | 7.5 | 1.67 | 4.3 | 6.5 | 8.8 | 10.0 | 24% | 35% | 41% |  |  |
| alarms | 89 | 89 | 8.06 | 8.8 | 1.88 | 2.4 | 6.5 | 9.8 | 10.0 | 42% | 30% | 27% | 1% |  |
| robotvacuum | 27 | 27 | 6.57 | 7.4 | 1.93 | 2.3 | 5.45 | 7.5 | 9.8 | 11% | 44% | 33% | 11% |  |
| fans | 1 | 1 | 7.4 | 7.4 | 0.0 | 7.4 | 7.4 | 7.4 | 7.4 |  | 100% |  |  |  |
| fridge | 3 | 3 | 7.7 | 7.2 | 1.9 | 6.1 | 6.65 | 8.5 | 9.8 | 33% | 33% | 33% |  |  |
| sensors | 4 | 4 | 7.42 | 7.05 | 1.23 | 6.5 | 6.5 | 7.98 | 9.1 | 25% | 25% | 50% |  |  |
| airpurifier | 2 | 2 | 7.95 | 7.95 | 2.62 | 6.1 | 7.02 | 8.88 | 9.8 | 50% |  | 50% |  |  |
| lighting | 34 | 34 | 7.58 | 7.5 | 1.1 | 4.6 | 6.75 | 8.1 | 9.8 | 6% | 68% | 26% |  |  |
| appliances | 3 | 3 | 8.13 | 8.1 | 1.65 | 6.5 | 7.3 | 8.95 | 9.8 | 33% | 33% | 33% |  |  |
| hub | 247 | 247 | 8.73 | 9.8 | 1.54 | 2.2 | 7.95 | 9.9 | 10.0 | 53% | 34% | 12% | 1% |  |
| ev-charging | 71 | 71 | 7.2 | 7.5 | 1.81 | 3.1 | 6.1 | 8.8 | 9.8 | 11% | 44% | 39% | 6% |  |
| home-power | 45 | 45 | 8.08 | 7.5 | 1.69 | 3.4 | 6.8 | 9.8 | 10.0 | 40% | 33% | 24% | 2% |  |
| garden | 19 | 19 | 7.73 | 8.1 | 2.21 | 2.3 | 6.5 | 9.8 | 9.8 | 37% | 32% | 21% | 11% |  |
| pet | 35 | 35 | 7.36 | 8.1 | 2.22 | 2.4 | 5.7 | 9.8 | 9.8 | 31% | 26% | 37% | 6% |  |
| streaming | 76 | 76 | 7.34 | 7.8 | 1.62 | 2.6 | 6.1 | 8.1 | 10.0 | 14% | 49% | 36% | 1% |  |
| airconditioner | 5 | 5 | 7.24 | 6.8 | 1.49 | 6.1 | 6.3 | 7.2 | 9.8 | 20% | 20% | 60% |  |  |
| cameras | 885 | 885 | 7.79 | 7.7 | 1.55 | 1.6 | 6.8 | 8.8 | 10.0 | 23% | 50% | 26% | 1% |  |

## Kruskal-Wallis omnibus test

Categories with >= 5 scored CVEs (n=17): doorlock, smartspeakers, doorbell, thermostat, babymonitor, smartplugs, alarms, robotvacuum, lighting, hub, ev-charging, home-power, garden, pet, streaming, airconditioner, cameras

H = 169.820, df = 16, p = 9.14412e-28 — **significant** at alpha=0.05.

Excluded (5, below --min-n 5 scored CVEs): fans, fridge, sensors, airpurifier, appliances

## Dunn's post-hoc pairwise comparisons (Bonferroni-adjusted)

13 of 136 pairs significant (p_bonferroni < 0.05), most significant first:

- **cameras** vs **hub** (n=885 vs 247): z=-10.257, p_bonferroni=1.49e-22
- **ev-charging** vs **hub** (n=71 vs 247): z=-7.645, p_bonferroni=2.848e-12
- **hub** vs **streaming** (n=247 vs 76): z=7.307, p_bonferroni=3.721e-11
- **hub** vs **robotvacuum** (n=247 vs 27): z=6.765, p_bonferroni=1.815e-09
- **doorlock** vs **hub** (n=36 vs 247): z=-6.273, p_bonferroni=4.816e-08
- **doorbell** vs **hub** (n=45 vs 247): z=-6.221, p_bonferroni=6.7e-08
- **hub** vs **smartspeakers** (n=247 vs 38): z=5.333, p_bonferroni=1.317e-05
- **hub** vs **smartplugs** (n=247 vs 37): z=4.949, p_bonferroni=0.0001014
- **hub** vs **lighting** (n=247 vs 34): z=4.921, p_bonferroni=0.0001171
- **hub** vs **pet** (n=247 vs 35): z=4.849, p_bonferroni=0.0001686
- **alarms** vs **hub** (n=89 vs 247): z=-4.059, p_bonferroni=0.006701
- **alarms** vs **robotvacuum** (n=89 vs 27): z=3.957, p_bonferroni=0.01032
- **hub** vs **thermostat** (n=247 vs 18): z=3.8, p_bonferroni=0.01969
