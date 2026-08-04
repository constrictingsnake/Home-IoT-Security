# CWE-888 primary-class distribution — confirmed-Yes CVEs (by category)

Counting matches Table III of the transportation IoT study: unit = CWE attribution; a CVE with two CWEs counts twice, a CWE mapping to two primary classes counts in both. `All` sums the category columns (a CVE confirmed in several categories counts once per category).


`All` is a **micro**-average (pooled attributions, so the largest unit dominates the shape); `All-macro` is a **macro**-average (unweighted mean of each unit's percentage profile, so every unit with data gets an equal vote). Read them together — the gap between the two is how concentrated the corpus is.

| Primary CWE-888 Class | doorlock | smartspeakers | doorbell | thermostat | babymonitor | smartplugs | alarms | robotvacuum | fans | fridge | sensors | airpurifier | lighting | appliances | hub | ev-charging | home-power | garden | pet | streaming | airconditioner | cameras | All | All-macro |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| API |  |  |  |  |  |  |  |  |  |  |  |  |  | 1 (33%) |  |  |  | 1 (4%) |  |  |  | 5 (1%) | 7 (0%) | 2% |
| Access Control | 9 (21%) | 3 (9%) | 4 (12%) |  | 1 (5%) | 3 (10%) | 4 (5%) | 2 (6%) | 1 (25%) |  |  |  | 1 (3%) |  | 14 (5%) | 8 (9%) | 3 (6%) | 2 (8%) | 5 (10%) | 2 (3%) |  | 51 (5%) | 113 (6%) | 6% |
| Authentication | 8 (19%) | 3 (9%) | 7 (21%) | 2 (11%) | 5 (23%) | 5 (17%) | 9 (10%) | 7 (21%) | 1 (25%) |  |  |  | 7 (23%) |  | 22 (8%) | 13 (15%) | 9 (18%) | 8 (31%) | 7 (14%) | 7 (11%) | 1 (12%) | 151 (15%) | 272 (14%) | 14% |
| Channel | 3 (7%) |  | 1 (3%) | 2 (11%) |  | 1 (3%) | 12 (14%) | 1 (3%) | 1 (25%) |  | 2 (67%) |  |  |  | 5 (2%) | 5 (6%) |  | 1 (4%) | 2 (4%) | 1 (2%) |  | 8 (1%) | 45 (2%) | 7% |
| Cryptography | 1 (2%) |  | 1 (3%) | 1 (5%) | 2 (9%) | 1 (3%) |  | 3 (9%) |  |  |  |  | 3 (10%) |  | 6 (2%) | 2 (2%) | 2 (4%) | 1 (4%) | 3 (6%) |  | 1 (12%) | 14 (1%) | 41 (2%) | 3% |
| Entry Points |  |  | 1 (3%) |  |  |  | 2 (2%) |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 2 (0%) | 5 (0%) | 0% |
| Exception Management |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 1 (0%) |  |  |  |  |  |  | 6 (1%) | 7 (0%) | 0% |
| Failure to Release Memory |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 1 (0%) | 1 (0%) | 0% |
| Faulty Resource Release |  |  |  |  |  |  | 1 (1%) |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 1 (0%) | 0% |
| Information Leak | 7 (16%) | 1 (3%) | 5 (15%) | 3 (16%) | 3 (14%) | 5 (17%) | 13 (15%) | 3 (9%) | 1 (25%) | 1 (25%) | 1 (33%) | 1 (50%) | 3 (10%) |  | 14 (5%) | 8 (9%) | 9 (18%) | 1 (4%) | 10 (20%) | 11 (18%) | 2 (25%) | 96 (10%) | 198 (10%) | 16% |
| Malware |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
| Memory Access | 4 (9%) | 13 (39%) |  | 3 (16%) | 2 (9%) | 4 (14%) | 1 (1%) | 1 (3%) |  |  |  |  | 8 (26%) | 2 (67%) | 172 (61%) | 16 (19%) |  |  | 3 (6%) | 22 (36%) |  | 168 (17%) | 419 (22%) | 15% |
| Memory Management |  |  |  |  |  |  | 1 (1%) |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 1 (0%) | 0% |
| Other | 2 (5%) |  |  | 2 (11%) | 1 (5%) | 3 (10%) | 3 (3%) | 5 (15%) |  | 1 (25%) |  |  |  |  | 2 (1%) | 9 (11%) | 4 (8%) | 4 (15%) | 2 (4%) | 1 (2%) | 1 (12%) | 66 (7%) | 106 (6%) | 6% |
| Path Resolution | 1 (2%) | 1 (3%) |  |  | 1 (5%) |  |  |  |  |  |  |  |  |  | 6 (2%) | 1 (1%) | 5 (10%) |  |  | 1 (2%) |  | 32 (3%) | 48 (3%) | 1% |
| Predictability | 3 (7%) |  | 1 (3%) | 2 (11%) | 1 (5%) | 3 (10%) | 5 (6%) | 6 (18%) |  | 1 (25%) |  |  |  |  | 2 (1%) | 6 (7%) | 5 (10%) | 3 (12%) | 2 (4%) | 1 (2%) | 1 (12%) | 73 (7%) | 115 (6%) | 6% |
| Privilege |  | 1 (3%) | 3 (9%) |  | 2 (9%) | 1 (3%) |  |  |  |  |  |  |  |  | 6 (2%) | 1 (1%) |  |  | 2 (4%) |  |  | 10 (1%) | 26 (1%) | 1% |
| Resource Management | 4 (9%) | 3 (9%) | 3 (9%) |  |  | 1 (3%) |  |  |  |  |  |  | 5 (16%) |  | 1 (0%) |  |  |  | 7 (14%) | 3 (5%) |  | 18 (2%) | 45 (2%) | 3% |
| Risky Values |  | 3 (9%) |  |  |  |  | 1 (1%) |  |  |  |  |  |  |  | 2 (1%) | 1 (1%) |  |  |  | 1 (2%) |  | 8 (1%) | 16 (1%) | 1% |
| Synchronization |  |  | 1 (3%) |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 1 (2%) | 1 (2%) |  | 1 (0%) | 4 (0%) | 0% |
| Tainted Input | 1 (2%) | 5 (15%) | 7 (21%) | 4 (21%) | 4 (18%) | 2 (7%) | 34 (40%) | 6 (18%) |  | 1 (25%) |  | 1 (50%) | 4 (13%) |  | 29 (10%) | 13 (15%) | 13 (26%) | 4 (15%) | 5 (10%) | 10 (16%) | 2 (25%) | 286 (29%) | 431 (23%) | 17% |
| UI |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 2 (2%) |  | 1 (4%) |  |  |  |  | 3 (0%) | 0% |
| Unused entities |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
| **Top-6 share** | 35 (81%) | 30 (91%) | 29 (85%) | 16 (84%) | 18 (82%) | 23 (79%) | 77 (90%) | 30 (88%) | 4 (100%) | 4 (100%) | 3 (100%) | 2 (100%) | 30 (97%) | 3 (100%) | 257 (91%) | 67 (79%) | 45 (90%) | 22 (85%) | 37 (76%) | 55 (90%) | 8 (100%) | 840 (84%) | 1548 (81%) | 75% |
| **Total CWEs** | 43 | 33 | 34 | 19 | 22 | 29 | 86 | 34 | 4 | 4 | 3 | 2 | 31 | 3 | 282 | 85 | 50 | 26 | 49 | 61 | 8 | 996 | 1904 | — |

## Coverage

| Category | Yes CVEs | with CWE | CWE attributions | unmapped CWEs |
|---|---|---|---|---|
| doorlock | 36 | 36 | 43 | 0 |
| smartspeakers | 38 | 31 | 33 | 1 |
| doorbell | 45 | 34 | 34 | 1 |
| thermostat | 18 | 17 | 19 | 1 |
| babymonitor | 18 | 17 | 22 | 1 |
| smartplugs | 37 | 31 | 29 | 6 |
| alarms | 89 | 84 | 86 | 6 |
| robotvacuum | 27 | 25 | 34 | 0 |
| fans | 1 | 1 | 4 | 0 |
| fridge | 3 | 3 | 4 | 0 |
| sensors | 4 | 3 | 3 | 0 |
| airpurifier | 2 | 2 | 2 | 0 |
| lighting | 34 | 29 | 31 | 0 |
| appliances | 3 | 2 | 3 | 0 |
| hub | 247 | 244 | 282 | 1 |
| ev-charging | 71 | 71 | 85 | 0 |
| home-power | 45 | 42 | 50 | 3 |
| garden | 19 | 19 | 26 | 0 |
| pet | 35 | 35 | 49 | 2 |
| streaming | 76 | 62 | 61 | 3 |
| airconditioner | 5 | 5 | 8 | 0 |
| cameras | 885 | 820 | 996 | 25 |
| **All** | 1738 | 1613 | 1904 | 50 |

Unmapped CWEs (no ancestry into the 888 view): CWE-264 ×16, CWE-255 ×14, CWE-310 ×11, CWE-254 ×3, CWE-16 ×2, CWE-399 ×2, CWE-320 ×1, CWE-417 ×1
