# CVSS vector components — confirmed-Yes CVEs (RQ3)

Mirrors Section VI of the 2025 paper extension (its Figs. 8-10): the distribution of Attack Vector, Scope, and the Confidentiality/Integrity/Availability impact combination per category. Pinned to CVSS 3.x; 4.0 vectors are converted back (VC/VI/VA -> C/I/A, any non-None subsequent-system impact SC/SI/SA -> Scope: Changed). CVSS 2.0 has no Scope metric and a different impact scale, so v2-only CVEs are counted as unconvertible rather than reshaped.

Population: **1638** (folding category, CVE) rows with a 3.x-equivalent vector; **81** scored rows without one (v2.0-only).

## Attack Vector (Fig. 8)

| Category | N | Network | Adjacent | Local | Physical |
|---|---|---|---|---|---|
| Access Control | 36 | 50% (18) | 28% (10) | 3% (1) | 19% (7) |
| Audio | 38 | 32% (12) | 47% (18) | 3% (1) | 18% (7) |
| Cameras and Monitors | 876 | 78% (684) | 12% (107) | 5% (47) | 4% (38) |
| Climate & Air | 23 | 61% (14) | 26% (6) | 4% (1) | 9% (2) |
| Electrical & Lighting | 60 | 58% (35) | 37% (22) | 3% (2) | 2% (1) |
| Alarms & Sensors | 90 | 69% (62) | 20% (18) | 3% (3) | 8% (7) |
| Appliances | 33 | 58% (19) | 18% (6) | 15% (5) | 9% (3) |
| Hubs and Controllers | 243 | 84% (205) | 9% (23) | 4% (10) | 2% (5) |
| Energy | 112 | 65% (73) | 29% (33) | 1% (1) | 4% (5) |
| Outdoor & Pet | 54 | 67% (36) | 13% (7) | 6% (3) | 15% (8) |
| Entertainment | 73 | 47% (34) | 12% (9) | 38% (28) | 3% (2) |
| **All** | **1638** | **73%** (1192) | **16%** (259) | **6%** (102) | **5%** (85) |

## Scope (Fig. 9)

`Changed` means the exploit can affect resources beyond the vulnerable component's own security scope.

| Category | N | Unchanged | Changed |
|---|---|---|---|
| Access Control | 36 | 89% (32) | 11% (4) |
| Audio | 38 | 92% (35) | 8% (3) |
| Cameras and Monitors | 876 | 88% (767) | 12% (109) |
| Climate & Air | 23 | 87% (20) | 13% (3) |
| Electrical & Lighting | 60 | 93% (56) | 7% (4) |
| Alarms & Sensors | 90 | 88% (79) | 12% (11) |
| Appliances | 33 | 88% (29) | 12% (4) |
| Hubs and Controllers | 243 | 46% (111) | 54% (132) |
| Energy | 112 | 93% (104) | 7% (8) |
| Outdoor & Pet | 54 | 94% (51) | 6% (3) |
| Entertainment | 73 | 95% (69) | 5% (4) |
| **All** | **1638** | **83%** (1353) | **17%** (285) |

## CIA impact combination (Fig. 10)

Which security attributes a CVE affects at all (metric value != None).

| Category | N | C+I+A | C+I | C+A | I+A | C | I | A |
|---|---|---|---|---|---|---|---|---|
| Access Control | 36 | 36% (13) | 11% (4) | — | 6% (2) | 17% (6) | 22% (8) | 8% (3) |
| Audio | 38 | 66% (25) | 11% (4) | 3% (1) | — | 21% (8) | — | — |
| Cameras and Monitors | 876 | 52% (457) | 5% (47) | 1% (6) | 1% (13) | 18% (159) | 5% (43) | 17% (151) |
| Climate & Air | 23 | 48% (11) | 9% (2) | — | 4% (1) | 13% (3) | 13% (3) | 13% (3) |
| Electrical & Lighting | 60 | 43% (26) | 8% (5) | — | 3% (2) | 18% (11) | 5% (3) | 22% (13) |
| Alarms & Sensors | 90 | 60% (54) | 6% (5) | — | 3% (3) | 7% (6) | 12% (11) | 12% (11) |
| Appliances | 33 | 55% (18) | 15% (5) | — | 3% (1) | 15% (5) | 12% (4) | — |
| Hubs and Controllers | 243 | 75% (183) | 5% (11) | — | 3% (7) | 9% (21) | 3% (8) | 5% (13) |
| Energy | 112 | 52% (58) | 10% (11) | 1% (1) | 4% (4) | 24% (27) | 9% (10) | 1% (1) |
| Outdoor & Pet | 54 | 54% (29) | 11% (6) | 2% (1) | 2% (1) | 19% (10) | 6% (3) | 7% (4) |
| Entertainment | 73 | 53% (39) | 4% (3) | — | 4% (3) | 15% (11) | 10% (7) | 14% (10) |
| **All** | **1638** | **56%** (913) | **6%** (103) | **1%** (9) | **2%** (37) | **16%** (267) | **6%** (100) | **13%** (209) |

## Supporting metrics


## Attack Complexity

| Category | N | Low | High |
|---|---|---|---|
| Access Control | 36 | 89% (32) | 11% (4) |
| Audio | 38 | 92% (35) | 8% (3) |
| Cameras and Monitors | 876 | 92% (805) | 8% (71) |
| Climate & Air | 23 | 91% (21) | 9% (2) |
| Electrical & Lighting | 60 | 93% (56) | 7% (4) |
| Alarms & Sensors | 90 | 87% (78) | 13% (12) |
| Appliances | 33 | 64% (21) | 36% (12) |
| Hubs and Controllers | 243 | 93% (225) | 7% (18) |
| Energy | 112 | 89% (100) | 11% (12) |
| Outdoor & Pet | 54 | 70% (38) | 30% (16) |
| Entertainment | 73 | 92% (67) | 8% (6) |
| **All** | **1638** | **90%** (1478) | **10%** (160) |

## Privileges Required

| Category | N | None | Low | High |
|---|---|---|---|---|
| Access Control | 36 | 86% (31) | 14% (5) | — |
| Audio | 38 | 92% (35) | 8% (3) | — |
| Cameras and Monitors | 876 | 69% (601) | 24% (212) | 7% (63) |
| Climate & Air | 23 | 87% (20) | 13% (3) | — |
| Electrical & Lighting | 60 | 85% (51) | 13% (8) | 2% (1) |
| Alarms & Sensors | 90 | 80% (72) | 20% (18) | — |
| Appliances | 33 | 79% (26) | 15% (5) | 6% (2) |
| Hubs and Controllers | 243 | 32% (78) | 65% (159) | 2% (6) |
| Energy | 112 | 78% (87) | 15% (17) | 7% (8) |
| Outdoor & Pet | 54 | 83% (45) | 15% (8) | 2% (1) |
| Entertainment | 73 | 77% (56) | 23% (17) | — |
| **All** | **1638** | **67%** (1102) | **28%** (455) | **5%** (81) |

## User Interaction

| Category | N | None | Required |
|---|---|---|---|
| Access Control | 36 | 97% (35) | 3% (1) |
| Audio | 38 | 84% (32) | 16% (6) |
| Cameras and Monitors | 876 | 93% (818) | 7% (58) |
| Climate & Air | 23 | 78% (18) | 22% (5) |
| Electrical & Lighting | 60 | 87% (52) | 13% (8) |
| Alarms & Sensors | 90 | 93% (84) | 7% (6) |
| Appliances | 33 | 91% (30) | 9% (3) |
| Hubs and Controllers | 243 | 93% (225) | 7% (18) |
| Energy | 112 | 89% (100) | 11% (12) |
| Outdoor & Pet | 54 | 93% (50) | 7% (4) |
| Entertainment | 73 | 68% (50) | 32% (23) |
| **All** | **1638** | **91%** (1494) | **9%** (144) |

## Confidentiality

| Category | N | High | Low | None |
|---|---|---|---|---|
| Access Control | 36 | 58% (21) | 6% (2) | 36% (13) |
| Audio | 38 | 76% (29) | 24% (9) | — |
| Cameras and Monitors | 876 | 67% (583) | 10% (86) | 24% (207) |
| Climate & Air | 23 | 57% (13) | 13% (3) | 30% (7) |
| Electrical & Lighting | 60 | 62% (37) | 8% (5) | 30% (18) |
| Alarms & Sensors | 90 | 69% (62) | 3% (3) | 28% (25) |
| Appliances | 33 | 61% (20) | 24% (8) | 15% (5) |
| Hubs and Controllers | 243 | 85% (206) | 4% (9) | 12% (28) |
| Energy | 112 | 68% (76) | 19% (21) | 13% (15) |
| Outdoor & Pet | 54 | 76% (41) | 9% (5) | 15% (8) |
| Entertainment | 73 | 70% (51) | 3% (2) | 27% (20) |
| **All** | **1638** | **70%** (1139) | **9%** (153) | **21%** (346) |

## Integrity

| Category | N | High | Low | None |
|---|---|---|---|---|
| Access Control | 36 | 58% (21) | 17% (6) | 25% (9) |
| Audio | 38 | 63% (24) | 13% (5) | 24% (9) |
| Cameras and Monitors | 876 | 56% (494) | 8% (66) | 36% (316) |
| Climate & Air | 23 | 48% (11) | 26% (6) | 26% (6) |
| Electrical & Lighting | 60 | 50% (30) | 10% (6) | 40% (24) |
| Alarms & Sensors | 90 | 76% (68) | 6% (5) | 19% (17) |
| Appliances | 33 | 58% (19) | 27% (9) | 15% (5) |
| Hubs and Controllers | 243 | 84% (204) | 2% (5) | 14% (34) |
| Energy | 112 | 64% (72) | 10% (11) | 26% (29) |
| Outdoor & Pet | 54 | 63% (34) | 9% (5) | 28% (15) |
| Entertainment | 73 | 64% (47) | 7% (5) | 29% (21) |
| **All** | **1638** | **63%** (1024) | **8%** (129) | **30%** (485) |

## Availability

| Category | N | High | Low | None |
|---|---|---|---|---|
| Access Control | 36 | 50% (18) | — | 50% (18) |
| Audio | 38 | 66% (25) | 3% (1) | 32% (12) |
| Cameras and Monitors | 876 | 69% (603) | 3% (24) | 28% (249) |
| Climate & Air | 23 | 57% (13) | 9% (2) | 35% (8) |
| Electrical & Lighting | 60 | 62% (37) | 7% (4) | 32% (19) |
| Alarms & Sensors | 90 | 73% (66) | 2% (2) | 24% (22) |
| Appliances | 33 | 36% (12) | 21% (7) | 42% (14) |
| Hubs and Controllers | 243 | 83% (201) | 1% (2) | 16% (40) |
| Energy | 112 | 56% (63) | 1% (1) | 43% (48) |
| Outdoor & Pet | 54 | 61% (33) | 4% (2) | 35% (19) |
| Entertainment | 73 | 67% (49) | 4% (3) | 29% (21) |
| **All** | **1638** | **68%** (1120) | **3%** (48) | **29%** (470) |

Long form: `data/difference/cvss_vectors_family.csv`.

