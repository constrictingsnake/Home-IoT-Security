# CVSS vector components — confirmed-Yes CVEs (RQ3)

Mirrors Section VI of the 2025 paper extension (its Figs. 8-10): the distribution of Attack Vector, Scope, and the Confidentiality/Integrity/Availability impact combination per category. Pinned to CVSS 3.x; 4.0 vectors are converted back (VC/VI/VA -> C/I/A, any non-None subsequent-system impact SC/SI/SA -> Scope: Changed). CVSS 2.0 has no Scope metric and a different impact scale, so v2-only CVEs are counted as unconvertible rather than reshaped.

Population: **1657** (category, CVE) rows with a 3.x-equivalent vector; **81** scored rows without one (v2.0-only).

## Attack Vector (Fig. 8)

| Category | N | Network | Adjacent | Local | Physical |
|---|---|---|---|---|---|
| doorlock | 36 | 50% (18) | 28% (10) | 3% (1) | 19% (7) |
| smartspeakers | 38 | 32% (12) | 47% (18) | 3% (1) | 18% (7) |
| doorbell | 45 | 76% (34) | 9% (4) | 9% (4) | 7% (3) |
| thermostat | 17 | 65% (11) | 24% (4) | 6% (1) | 6% (1) |
| babymonitor | 18 | 67% (12) | 11% (2) | 17% (3) | 6% (1) |
| smartplugs | 31 | 65% (20) | 29% (9) | 6% (2) | — |
| alarms | 86 | 70% (60) | 19% (16) | 3% (3) | 8% (7) |
| robotvacuum | 27 | 52% (14) | 19% (5) | 19% (5) | 11% (3) |
| fans | 1 | — | 100% (1) | — | — |
| fridge | 3 | 67% (2) | 33% (1) | — | — |
| sensors | 4 | 50% (2) | 50% (2) | — | — |
| airpurifier | 2 | 100% (2) | — | — | — |
| lighting | 34 | 50% (17) | 47% (16) | — | 3% (1) |
| appliances | 3 | 100% (3) | — | — | — |
| hub | 243 | 84% (205) | 9% (23) | 4% (10) | 2% (5) |
| ev-charging | 71 | 51% (36) | 44% (31) | 1% (1) | 4% (3) |
| home-power | 41 | 90% (37) | 5% (2) | — | 5% (2) |
| garden | 19 | 74% (14) | 11% (2) | 11% (2) | 5% (1) |
| pet | 35 | 63% (22) | 14% (5) | 3% (1) | 20% (7) |
| streaming | 73 | 47% (34) | 12% (9) | 38% (28) | 3% (2) |
| airconditioner | 5 | 60% (3) | 20% (1) | — | 20% (1) |
| cameras | 825 | 78% (644) | 12% (102) | 5% (44) | 4% (35) |
| **All** | **1657** | **73%** (1202) | **16%** (263) | **6%** (106) | **5%** (86) |

## Scope (Fig. 9)

`Changed` means the exploit can affect resources beyond the vulnerable component's own security scope.

| Category | N | Unchanged | Changed |
|---|---|---|---|
| doorlock | 36 | 89% (32) | 11% (4) |
| smartspeakers | 38 | 92% (35) | 8% (3) |
| doorbell | 45 | 98% (44) | 2% (1) |
| thermostat | 17 | 94% (16) | 6% (1) |
| babymonitor | 18 | 100% (18) | — |
| smartplugs | 31 | 90% (28) | 10% (3) |
| alarms | 86 | 87% (75) | 13% (11) |
| robotvacuum | 27 | 89% (24) | 11% (3) |
| fans | 1 | — | 100% (1) |
| fridge | 3 | 67% (2) | 33% (1) |
| sensors | 4 | 100% (4) | — |
| airpurifier | 2 | 50% (1) | 50% (1) |
| lighting | 34 | 97% (33) | 3% (1) |
| appliances | 3 | 100% (3) | — |
| hub | 243 | 46% (111) | 54% (132) |
| ev-charging | 71 | 92% (65) | 8% (6) |
| home-power | 41 | 95% (39) | 5% (2) |
| garden | 19 | 84% (16) | 16% (3) |
| pet | 35 | 100% (35) | — |
| streaming | 73 | 95% (69) | 5% (4) |
| airconditioner | 5 | 80% (4) | 20% (1) |
| cameras | 825 | 87% (717) | 13% (108) |
| **All** | **1657** | **83%** (1371) | **17%** (286) |

## CIA impact combination (Fig. 10)

Which security attributes a CVE affects at all (metric value != None).

| Category | N | C+I+A | C+I | C+A | I+A | C | I | A |
|---|---|---|---|---|---|---|---|---|
| doorlock | 36 | 36% (13) | 11% (4) | — | 6% (2) | 17% (6) | 22% (8) | 8% (3) |
| smartspeakers | 38 | 66% (25) | 11% (4) | 3% (1) | — | 21% (8) | — | — |
| doorbell | 45 | 33% (15) | 13% (6) | — | 2% (1) | 36% (16) | 11% (5) | 4% (2) |
| thermostat | 17 | 41% (7) | 6% (1) | — | 6% (1) | 18% (3) | 18% (3) | 12% (2) |
| babymonitor | 18 | 56% (10) | — | — | — | 33% (6) | 6% (1) | 6% (1) |
| smartplugs | 31 | 42% (13) | 6% (2) | — | — | 29% (9) | 6% (2) | 16% (5) |
| alarms | 86 | 62% (53) | 6% (5) | — | 2% (2) | 6% (5) | 13% (11) | 12% (10) |
| robotvacuum | 27 | 52% (14) | 15% (4) | — | 4% (1) | 19% (5) | 11% (3) | — |
| fans | 1 | — | — | — | — | — | — | 100% (1) |
| fridge | 3 | 67% (2) | 33% (1) | — | — | — | — | — |
| sensors | 4 | 25% (1) | — | — | 25% (1) | 25% (1) | — | 25% (1) |
| airpurifier | 2 | 50% (1) | 50% (1) | — | — | — | — | — |
| lighting | 34 | 38% (13) | 9% (3) | — | 6% (2) | 18% (6) | 3% (1) | 26% (9) |
| appliances | 3 | 67% (2) | — | — | — | — | 33% (1) | — |
| hub | 243 | 75% (183) | 5% (11) | — | 3% (7) | 9% (21) | 3% (8) | 5% (13) |
| ev-charging | 71 | 49% (35) | 11% (8) | 1% (1) | 6% (4) | 20% (14) | 11% (8) | 1% (1) |
| home-power | 41 | 56% (23) | 7% (3) | — | — | 32% (13) | 5% (2) | — |
| garden | 19 | 63% (12) | 16% (3) | — | — | 11% (2) | 11% (2) | — |
| pet | 35 | 49% (17) | 9% (3) | 3% (1) | 3% (1) | 23% (8) | 3% (1) | 11% (4) |
| streaming | 73 | 53% (39) | 4% (3) | — | 4% (3) | 15% (11) | 10% (7) | 14% (10) |
| airconditioner | 5 | 80% (4) | 20% (1) | — | — | — | — | — |
| cameras | 825 | 53% (439) | 5% (41) | 1% (6) | 1% (12) | 17% (141) | 4% (37) | 18% (149) |
| **All** | **1657** | **56%** (921) | **6%** (104) | **1%** (9) | **2%** (37) | **17%** (275) | **6%** (100) | **13%** (211) |

## Supporting metrics


## Attack Complexity

| Category | N | Low | High |
|---|---|---|---|
| doorlock | 36 | 89% (32) | 11% (4) |
| smartspeakers | 38 | 92% (35) | 8% (3) |
| doorbell | 45 | 93% (42) | 7% (3) |
| thermostat | 17 | 88% (15) | 12% (2) |
| babymonitor | 18 | 89% (16) | 11% (2) |
| smartplugs | 31 | 100% (31) | — |
| alarms | 86 | 86% (74) | 14% (12) |
| robotvacuum | 27 | 59% (16) | 41% (11) |
| fans | 1 | 100% (1) | — |
| fridge | 3 | 100% (3) | — |
| sensors | 4 | 100% (4) | — |
| airpurifier | 2 | 100% (2) | — |
| lighting | 34 | 88% (30) | 12% (4) |
| appliances | 3 | 67% (2) | 33% (1) |
| hub | 243 | 93% (225) | 7% (18) |
| ev-charging | 71 | 87% (62) | 13% (9) |
| home-power | 41 | 93% (38) | 7% (3) |
| garden | 19 | 84% (16) | 16% (3) |
| pet | 35 | 63% (22) | 37% (13) |
| streaming | 73 | 92% (67) | 8% (6) |
| airconditioner | 5 | 100% (5) | — |
| cameras | 825 | 92% (758) | 8% (67) |
| **All** | **1657** | **90%** (1496) | **10%** (161) |

## Privileges Required

| Category | N | None | Low | High |
|---|---|---|---|---|
| doorlock | 36 | 86% (31) | 14% (5) | — |
| smartspeakers | 38 | 92% (35) | 8% (3) | — |
| doorbell | 45 | 80% (36) | 18% (8) | 2% (1) |
| thermostat | 17 | 82% (14) | 18% (3) | — |
| babymonitor | 18 | 56% (10) | 39% (7) | 6% (1) |
| smartplugs | 31 | 81% (25) | 16% (5) | 3% (1) |
| alarms | 86 | 79% (68) | 21% (18) | — |
| robotvacuum | 27 | 74% (20) | 19% (5) | 7% (2) |
| fans | 1 | 100% (1) | — | — |
| fridge | 3 | 100% (3) | — | — |
| sensors | 4 | 100% (4) | — | — |
| airpurifier | 2 | 100% (2) | — | — |
| lighting | 34 | 91% (31) | 9% (3) | — |
| appliances | 3 | 100% (3) | — | — |
| hub | 243 | 32% (78) | 65% (159) | 2% (6) |
| ev-charging | 71 | 75% (53) | 17% (12) | 8% (6) |
| home-power | 41 | 83% (34) | 12% (5) | 5% (2) |
| garden | 19 | 79% (15) | 16% (3) | 5% (1) |
| pet | 35 | 86% (30) | 14% (5) | — |
| streaming | 73 | 77% (56) | 23% (17) | — |
| airconditioner | 5 | 100% (5) | — | — |
| cameras | 825 | 68% (561) | 24% (202) | 8% (62) |
| **All** | **1657** | **67%** (1115) | **28%** (460) | **5%** (82) |

## User Interaction

| Category | N | None | Required |
|---|---|---|---|
| doorlock | 36 | 97% (35) | 3% (1) |
| smartspeakers | 38 | 84% (32) | 16% (6) |
| doorbell | 45 | 100% (45) | — |
| thermostat | 17 | 82% (14) | 18% (3) |
| babymonitor | 18 | 100% (18) | — |
| smartplugs | 31 | 81% (25) | 19% (6) |
| alarms | 86 | 94% (81) | 6% (5) |
| robotvacuum | 27 | 96% (26) | 4% (1) |
| fans | 1 | 100% (1) | — |
| fridge | 3 | 67% (2) | 33% (1) |
| sensors | 4 | 75% (3) | 25% (1) |
| airpurifier | 2 | 50% (1) | 50% (1) |
| lighting | 34 | 94% (32) | 6% (2) |
| appliances | 3 | 67% (2) | 33% (1) |
| hub | 243 | 93% (225) | 7% (18) |
| ev-charging | 71 | 87% (62) | 13% (9) |
| home-power | 41 | 93% (38) | 7% (3) |
| garden | 19 | 79% (15) | 21% (4) |
| pet | 35 | 100% (35) | — |
| streaming | 73 | 68% (50) | 32% (23) |
| airconditioner | 5 | 60% (3) | 40% (2) |
| cameras | 825 | 93% (767) | 7% (58) |
| **All** | **1657** | **91%** (1512) | **9%** (145) |

## Confidentiality

| Category | N | High | Low | None |
|---|---|---|---|---|
| doorlock | 36 | 58% (21) | 6% (2) | 36% (13) |
| smartspeakers | 38 | 76% (29) | 24% (9) | — |
| doorbell | 45 | 62% (28) | 20% (9) | 18% (8) |
| thermostat | 17 | 59% (10) | 6% (1) | 35% (6) |
| babymonitor | 18 | 89% (16) | — | 11% (2) |
| smartplugs | 31 | 65% (20) | 13% (4) | 23% (7) |
| alarms | 86 | 70% (60) | 3% (3) | 27% (23) |
| robotvacuum | 27 | 59% (16) | 26% (7) | 15% (4) |
| fans | 1 | — | — | 100% (1) |
| fridge | 3 | 67% (2) | 33% (1) | — |
| sensors | 4 | 50% (2) | — | 50% (2) |
| airpurifier | 2 | 50% (1) | 50% (1) | — |
| lighting | 34 | 62% (21) | 3% (1) | 35% (12) |
| appliances | 3 | 67% (2) | — | 33% (1) |
| hub | 243 | 85% (206) | 4% (9) | 12% (28) |
| ev-charging | 71 | 62% (44) | 20% (14) | 18% (13) |
| home-power | 41 | 78% (32) | 17% (7) | 5% (2) |
| garden | 19 | 74% (14) | 16% (3) | 11% (2) |
| pet | 35 | 77% (27) | 6% (2) | 17% (6) |
| streaming | 73 | 70% (51) | 3% (2) | 27% (20) |
| airconditioner | 5 | 60% (3) | 40% (2) | — |
| cameras | 825 | 67% (550) | 9% (77) | 24% (198) |
| **All** | **1657** | **70%** (1155) | **9%** (154) | **21%** (348) |

## Integrity

| Category | N | High | Low | None |
|---|---|---|---|---|
| doorlock | 36 | 58% (21) | 17% (6) | 25% (9) |
| smartspeakers | 38 | 63% (24) | 13% (5) | 24% (9) |
| doorbell | 45 | 51% (23) | 9% (4) | 40% (18) |
| thermostat | 17 | 53% (9) | 18% (3) | 29% (5) |
| babymonitor | 18 | 61% (11) | — | 39% (7) |
| smartplugs | 31 | 42% (13) | 13% (4) | 45% (14) |
| alarms | 86 | 77% (66) | 6% (5) | 17% (15) |
| robotvacuum | 27 | 56% (15) | 26% (7) | 19% (5) |
| fans | 1 | — | — | 100% (1) |
| fridge | 3 | 33% (1) | 67% (2) | — |
| sensors | 4 | 50% (2) | — | 50% (2) |
| airpurifier | 2 | 50% (1) | 50% (1) | — |
| lighting | 34 | 50% (17) | 6% (2) | 44% (15) |
| appliances | 3 | 100% (3) | — | — |
| hub | 243 | 84% (204) | 2% (5) | 14% (34) |
| ev-charging | 71 | 65% (46) | 13% (9) | 23% (16) |
| home-power | 41 | 63% (26) | 5% (2) | 32% (13) |
| garden | 19 | 74% (14) | 16% (3) | 11% (2) |
| pet | 35 | 57% (20) | 6% (2) | 37% (13) |
| streaming | 73 | 64% (47) | 7% (5) | 29% (21) |
| airconditioner | 5 | 40% (2) | 60% (3) | — |
| cameras | 825 | 57% (467) | 8% (62) | 36% (296) |
| **All** | **1657** | **62%** (1032) | **8%** (130) | **30%** (495) |

## Availability

| Category | N | High | Low | None |
|---|---|---|---|---|
| doorlock | 36 | 50% (18) | — | 50% (18) |
| smartspeakers | 38 | 66% (25) | 3% (1) | 32% (12) |
| doorbell | 45 | 36% (16) | 4% (2) | 60% (27) |
| thermostat | 17 | 59% (10) | — | 41% (7) |
| babymonitor | 18 | 56% (10) | 6% (1) | 39% (7) |
| smartplugs | 31 | 52% (16) | 6% (2) | 42% (13) |
| alarms | 86 | 74% (64) | 1% (1) | 24% (21) |
| robotvacuum | 27 | 33% (9) | 22% (6) | 44% (12) |
| fans | 1 | 100% (1) | — | — |
| fridge | 3 | 33% (1) | 33% (1) | 33% (1) |
| sensors | 4 | 50% (2) | 25% (1) | 25% (1) |
| airpurifier | 2 | 50% (1) | — | 50% (1) |
| lighting | 34 | 65% (22) | 6% (2) | 29% (10) |
| appliances | 3 | 67% (2) | — | 33% (1) |
| hub | 243 | 83% (201) | 1% (2) | 16% (40) |
| ev-charging | 71 | 56% (40) | 1% (1) | 42% (30) |
| home-power | 41 | 56% (23) | — | 44% (18) |
| garden | 19 | 58% (11) | 5% (1) | 37% (7) |
| pet | 35 | 63% (22) | 3% (1) | 34% (12) |
| streaming | 73 | 67% (49) | 4% (3) | 29% (21) |
| airconditioner | 5 | 40% (2) | 40% (2) | 20% (1) |
| cameras | 825 | 71% (584) | 3% (22) | 27% (219) |
| **All** | **1657** | **68%** (1129) | **3%** (49) | **29%** (479) |

Long form: `data/difference/cvss_vectors.csv`.

