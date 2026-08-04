# CVSS score distribution — confirmed-Yes CVEs

Mirrors RQ2 of the transportation IoT study (Section V): per-category CVSS score distribution (numeric stand-in for its Fig. 6 box plots) and severity-bucket shares (its Fig. 7), plus the same Kruskal-Wallis omnibus test with Dunn's post-hoc pairwise comparisons. A CVE confirmed in several categories counts once per category, not attribution-weighted (a CVSS score is a property of the CVE, unlike a CWE).

| Category | N (Yes) | N Scored | Mean | Median | Std | Min | Q1 | Q3 | Max | Critical% | High% | Medium% | Low% | None% |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| doorlock | 36 | 32 | 7.31 | 7.3 | 1.6 | 2.4 | 6.5 | 8.8 | 9.8 | 11% | 36% | 39% | 3% |  |
| smartspeakers | 38 | 38 | 7.42 | 7.2 | 1.83 | 3.3 | 6.32 | 8.8 | 9.8 | 16% | 34% | 47% | 3% |  |
| doorbell | 45 | 45 | 7.29 | 7.5 | 1.79 | 3.5 | 6.2 | 8.8 | 9.8 | 22% | 40% | 36% | 2% |  |
| thermostat | 18 | 18 | 7.43 | 7.5 | 1.81 | 3.5 | 6.05 | 8.68 | 9.8 | 22% | 39% | 33% | 6% |  |
| babymonitor | 18 | 18 | 7.71 | 7.5 | 1.35 | 5.3 | 7.05 | 8.8 | 9.8 | 17% | 61% | 22% |  |  |
| smartplugs | 37 | 37 | 7.55 | 7.5 | 1.67 | 4.3 | 6.5 | 8.8 | 10.0 | 24% | 35% | 41% |  |  |
| alarms | 89 | 89 | 8.06 | 8.8 | 1.88 | 2.4 | 6.5 | 9.8 | 10.0 | 42% | 30% | 27% | 1% |  |
| robotvacuum | 27 | 26 | 6.64 | 7.4 | 1.93 | 2.3 | 5.78 | 7.5 | 9.8 | 11% | 44% | 30% | 11% |  |
| fans | 1 | 1 | 7.4 | 7.4 | 0.0 | 7.4 | 7.4 | 7.4 | 7.4 |  | 100% |  |  |  |
| fridge | 3 | 2 | 7.95 | 7.95 | 2.62 | 6.1 | 7.02 | 8.88 | 9.8 | 33% |  | 33% |  |  |
| sensors | 4 | 3 | 7.37 | 6.5 | 1.5 | 6.5 | 6.5 | 7.8 | 9.1 | 25% |  | 50% |  |  |
| airpurifier | 2 | 2 | 7.95 | 7.95 | 2.62 | 6.1 | 7.02 | 8.88 | 9.8 | 50% |  | 50% |  |  |
| lighting | 34 | 34 | 7.58 | 7.5 | 1.1 | 4.6 | 6.75 | 8.1 | 9.8 | 6% | 68% | 26% |  |  |
| appliances | 3 | 3 | 8.13 | 8.1 | 1.65 | 6.5 | 7.3 | 8.95 | 9.8 | 33% | 33% | 33% |  |  |
| hub | 247 | 244 | 8.75 | 9.8 | 1.52 | 2.2 | 7.98 | 9.9 | 10.0 | 53% | 34% | 12% | 1% |  |
| ev-charging | 71 | 71 | 7.2 | 7.5 | 1.81 | 3.1 | 6.1 | 8.8 | 9.8 | 11% | 44% | 39% | 6% |  |
| home-power | 45 | 45 | 8.08 | 7.5 | 1.69 | 3.4 | 6.8 | 9.8 | 10.0 | 40% | 33% | 24% | 2% |  |
| garden | 19 | 19 | 7.73 | 8.1 | 2.21 | 2.3 | 6.5 | 9.8 | 9.8 | 37% | 32% | 21% | 11% |  |
| pet | 35 | 35 | 7.36 | 8.1 | 2.22 | 2.4 | 5.7 | 9.8 | 9.8 | 31% | 26% | 37% | 6% |  |
| streaming | 76 | 76 | 7.34 | 7.8 | 1.62 | 2.6 | 6.1 | 8.1 | 10.0 | 14% | 49% | 36% | 1% |  |
| airconditioner | 5 | 4 | 7.25 | 6.55 | 1.73 | 6.1 | 6.25 | 7.55 | 9.8 | 20% |  | 60% |  |  |
| cameras | 885 | 838 | 7.81 | 7.7 | 1.54 | 1.6 | 6.8 | 8.8 | 10.0 | 22% | 48% | 24% | 1% |  |

## Kruskal-Wallis omnibus test

Categories with >= 5 scored CVEs (n=16): doorlock, smartspeakers, doorbell, thermostat, babymonitor, smartplugs, alarms, robotvacuum, lighting, hub, ev-charging, home-power, garden, pet, streaming, cameras

H = 165.510, df = 15, p = 1.94311e-27 — **significant** at alpha=0.05.

Excluded (6, below --min-n 5 scored CVEs): fans, fridge, sensors, airpurifier, appliances, airconditioner

## Dunn's post-hoc pairwise comparisons (Bonferroni-adjusted)

15 of 120 pairs significant (p_bonferroni < 0.05), most significant first:

- **cameras** vs **hub** (n=838 vs 244): z=-10.221, p_bonferroni=1.907e-22
- **ev-charging** vs **hub** (n=71 vs 244): z=-7.724, p_bonferroni=1.357e-12
- **hub** vs **streaming** (n=244 vs 76): z=7.385, p_bonferroni=1.833e-11
- **hub** vs **robotvacuum** (n=244 vs 26): z=6.56, p_bonferroni=6.455e-09
- **doorbell** vs **hub** (n=45 vs 244): z=-6.304, p_bonferroni=3.478e-08
- **doorlock** vs **hub** (n=32 vs 244): z=-5.537, p_bonferroni=3.698e-06
- **hub** vs **smartspeakers** (n=244 vs 38): z=5.398, p_bonferroni=8.069e-06
- **hub** vs **smartplugs** (n=244 vs 37): z=5.014, p_bonferroni=6.402e-05
- **hub** vs **lighting** (n=244 vs 34): z=4.992, p_bonferroni=7.173e-05
- **hub** vs **pet** (n=244 vs 35): z=4.899, p_bonferroni=0.0001158
- **alarms** vs **hub** (n=89 vs 244): z=-4.148, p_bonferroni=0.004029
- **hub** vs **thermostat** (n=244 vs 18): z=3.849, p_bonferroni=0.01421
- **alarms** vs **robotvacuum** (n=89 vs 26): z=3.767, p_bonferroni=0.01985
- **babymonitor** vs **hub** (n=18 vs 244): z=-3.629, p_bonferroni=0.03419
- **home-power** vs **hub** (n=45 vs 244): z=-3.576, p_bonferroni=0.04189
