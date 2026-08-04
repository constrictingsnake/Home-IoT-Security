# CWE-888 primary-class distribution — confirmed-Yes CVEs (by folding category)

Counting matches Table III of the transportation IoT study: unit = CWE attribution; a CVE with two CWEs counts twice, a CWE mapping to two primary classes counts in both. `All` sums the category columns (a CVE confirmed in several categories counts once per category).


`All` is a **micro**-average (pooled attributions, so the largest unit dominates the shape); `All-macro` is a **macro**-average (unweighted mean of each unit's percentage profile, so every unit with data gets an equal vote). Read them together — the gap between the two is how concentrated the corpus is.

| Primary CWE-888 Class | Access Control | Audio | Cameras and Monitors | Climate & Air | Electrical & Lighting | Alarms & Sensors | Appliances | Hubs and Controllers | Energy | Outdoor & Pet | Entertainment | All | All-macro |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| API |  |  | 5 (0%) |  |  |  | 1 (2%) |  |  | 1 (1%) |  | 7 (0%) | 0% |
| Access Control | 9 (21%) | 3 (9%) | 56 (5%) | 1 (3%) | 4 (7%) | 4 (4%) | 2 (5%) | 14 (5%) | 11 (8%) | 7 (9%) | 2 (3%) | 113 (6%) | 7% |
| Authentication | 8 (19%) | 3 (9%) | 163 (15%) | 4 (12%) | 12 (20%) | 9 (10%) | 7 (17%) | 22 (8%) | 22 (16%) | 15 (20%) | 7 (11%) | 272 (14%) | 14% |
| Channel | 3 (7%) |  | 9 (1%) | 3 (9%) | 1 (2%) | 14 (16%) | 1 (2%) | 5 (2%) | 5 (4%) | 3 (4%) | 1 (2%) | 45 (2%) | 4% |
| Cryptography | 1 (2%) |  | 17 (2%) | 2 (6%) | 4 (7%) |  | 3 (7%) | 6 (2%) | 4 (3%) | 4 (5%) |  | 41 (2%) | 3% |
| Entry Points |  |  | 3 (0%) |  |  | 2 (2%) |  |  |  |  |  | 5 (0%) | 0% |
| Exception Management |  |  | 6 (1%) |  |  |  |  | 1 (0%) |  |  |  | 7 (0%) | 0% |
| Failure to Release Memory |  |  | 1 (0%) |  |  |  |  |  |  |  |  | 1 (0%) | 0% |
| Faulty Resource Release |  |  |  |  |  | 1 (1%) |  |  |  |  |  | 1 (0%) | 0% |
| Information Leak | 7 (16%) | 1 (3%) | 104 (10%) | 7 (21%) | 8 (13%) | 14 (16%) | 4 (10%) | 14 (5%) | 17 (13%) | 11 (15%) | 11 (18%) | 198 (10%) | 13% |
| Malware |  |  |  |  |  |  |  |  |  |  |  |  |  |
| Memory Access | 4 (9%) | 13 (39%) | 170 (16%) | 3 (9%) | 12 (20%) | 1 (1%) | 3 (7%) | 172 (61%) | 16 (12%) | 3 (4%) | 22 (36%) | 419 (22%) | 20% |
| Memory Management |  |  |  |  |  | 1 (1%) |  |  |  |  |  | 1 (0%) | 0% |
| Other | 2 (5%) |  | 67 (6%) | 3 (9%) | 3 (5%) | 3 (3%) | 6 (15%) | 2 (1%) | 13 (10%) | 6 (8%) | 1 (2%) | 106 (6%) | 6% |
| Path Resolution | 1 (2%) | 1 (3%) | 33 (3%) |  |  |  |  | 6 (2%) | 6 (4%) |  | 1 (2%) | 48 (3%) | 2% |
| Predictability | 3 (7%) |  | 75 (7%) | 3 (9%) | 3 (5%) | 5 (6%) | 7 (17%) | 2 (1%) | 11 (8%) | 5 (7%) | 1 (2%) | 115 (6%) | 6% |
| Privilege |  | 1 (3%) | 15 (1%) |  | 1 (2%) |  |  | 6 (2%) | 1 (1%) | 2 (3%) |  | 26 (1%) | 1% |
| Resource Management | 4 (9%) | 3 (9%) | 21 (2%) |  | 6 (10%) |  |  | 1 (0%) |  | 7 (9%) | 3 (5%) | 45 (2%) | 4% |
| Risky Values |  | 3 (9%) | 8 (1%) |  |  | 1 (1%) |  | 2 (1%) | 1 (1%) |  | 1 (2%) | 16 (1%) | 1% |
| Synchronization |  |  | 2 (0%) |  |  |  |  |  |  | 1 (1%) | 1 (2%) | 4 (0%) | 0% |
| Tainted Input | 1 (2%) | 5 (15%) | 297 (28%) | 7 (21%) | 6 (10%) | 34 (38%) | 7 (17%) | 29 (10%) | 26 (19%) | 9 (12%) | 10 (16%) | 431 (23%) | 17% |
| UI |  |  |  |  |  |  |  |  | 2 (1%) | 1 (1%) |  | 3 (0%) | 0% |
| Unused entities |  |  |  |  |  |  |  |  |  |  |  |  |  |
| **Top-6 share** | 35 (81%) | 30 (91%) | 876 (83%) | 27 (82%) | 48 (80%) | 80 (90%) | 34 (83%) | 257 (91%) | 105 (78%) | 55 (73%) | 55 (90%) | 1548 (81%) | 77% |
| **Total CWEs** | 43 | 33 | 1052 | 33 | 60 | 89 | 41 | 282 | 135 | 75 | 61 | 1904 | — |

## Coverage

| Folding Category | Yes CVEs | with CWE | CWE attributions | unmapped CWEs |
|---|---|---|---|---|
| Access Control | 36 | 36 | 43 | 0 |
| Audio | 38 | 31 | 33 | 1 |
| Cameras and Monitors | 948 | 871 | 1052 | 27 |
| Climate & Air | 26 | 25 | 33 | 1 |
| Electrical & Lighting | 71 | 60 | 60 | 6 |
| Alarms & Sensors | 93 | 87 | 89 | 6 |
| Appliances | 33 | 30 | 41 | 0 |
| Hubs and Controllers | 247 | 244 | 282 | 1 |
| Energy | 116 | 113 | 135 | 3 |
| Outdoor & Pet | 54 | 54 | 75 | 2 |
| Entertainment | 76 | 62 | 61 | 3 |
| **All** | 1738 | 1613 | 1904 | 50 |

Unmapped CWEs (no ancestry into the 888 view): CWE-264 ×16, CWE-255 ×14, CWE-310 ×11, CWE-254 ×3, CWE-16 ×2, CWE-399 ×2, CWE-320 ×1, CWE-417 ×1
