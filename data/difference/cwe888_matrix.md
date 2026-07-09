# CWE-888 primary-class distribution — confirmed-Yes CVEs

Counting matches Table III of the transportation IoT study: unit = CWE attribution; a CVE with two CWEs counts twice, a CWE mapping to two primary classes counts in both. `All` sums the category columns (a CVE confirmed in several categories counts once per category).

| Primary CWE-888 Class | doorlock | smartspeakers | doorbell | thermostat | babymonitor | smartplugs | alarms | robotvacuum | fridge | sensors | lighting | appliances | hub | ev-charging | home-power | garden | pet | streaming | airconditioner | cameras | All |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| API |  |  |  |  |  |  |  |  |  |  |  | 1 (33%) |  |  |  | 1 (5%) |  | 1 (0%) |  | 3 (0%) | 6 (0%) |
| Access Control | 6 (33%) | 2 (7%) | 1 (8%) |  |  | 2 (8%) | 4 (5%) | 2 (8%) |  |  |  |  | 6 (6%) | 6 (23%) | 3 (9%) | 2 (9%) | 4 (9%) | 51 (3%) |  | 33 (5%) | 122 (4%) |
| Authentication | 2 (11%) | 3 (11%) | 4 (31%) |  | 1 (10%) | 5 (20%) | 8 (10%) | 5 (19%) |  |  | 6 (24%) |  | 11 (11%) | 2 (8%) | 5 (15%) | 7 (32%) | 5 (12%) | 35 (2%) | 1 (33%) | 83 (13%) | 183 (6%) |
| Channel | 2 (11%) |  |  |  |  | 1 (4%) | 10 (13%) | 1 (4%) |  | 2 (100%) |  |  | 2 (2%) |  |  | 1 (5%) | 2 (5%) | 5 (0%) |  | 4 (1%) | 30 (1%) |
| Cryptography | 1 (6%) |  | 1 (8%) | 1 (10%) | 1 (10%) |  |  | 3 (12%) |  |  | 3 (12%) |  | 6 (6%) |  | 2 (6%) | 1 (5%) | 3 (7%) | 3 (0%) |  | 5 (1%) | 30 (1%) |
| Entry Points |  |  |  |  |  |  | 2 (3%) |  |  |  |  |  |  |  |  |  |  |  |  | 2 (0%) | 4 (0%) |
| Exception Management |  |  |  |  |  |  |  |  |  |  |  |  | 1 (1%) |  |  |  |  | 19 (1%) |  | 5 (1%) | 25 (1%) |
| Failure to Release Memory |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 2 (0%) |  |  | 2 (0%) |
| Faulty Resource Release |  |  |  |  |  |  | 1 (1%) |  |  |  |  |  |  |  |  |  |  | 7 (0%) |  |  | 8 (0%) |
| Information Leak | 2 (11%) | 1 (4%) | 1 (8%) | 1 (10%) | 1 (10%) | 5 (20%) | 10 (13%) | 2 (8%) | 1 (25%) |  | 2 (8%) |  | 10 (10%) | 2 (8%) | 4 (12%) | 1 (5%) | 7 (16%) | 108 (6%) | 1 (33%) | 57 (9%) | 216 (8%) |
| Malware |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 1 (0%) |  |  | 1 (0%) |
| Memory Access | 2 (11%) | 11 (41%) |  | 3 (30%) |  | 2 (8%) | 1 (1%) | 1 (4%) |  |  | 8 (32%) | 2 (67%) | 42 (41%) | 3 (12%) |  |  | 3 (7%) | 1032 (58%) |  | 102 (16%) | 1212 (42%) |
| Memory Management |  |  |  |  |  |  | 1 (1%) |  |  |  |  |  |  |  |  |  |  | 7 (0%) |  |  | 8 (0%) |
| Other |  |  |  | 2 (20%) |  | 3 (12%) | 3 (4%) | 3 (12%) | 1 (25%) |  |  |  |  | 5 (19%) | 2 (6%) | 2 (9%) | 2 (5%) | 17 (1%) |  | 38 (6%) | 78 (3%) |
| Path Resolution |  | 1 (4%) |  |  | 1 (10%) |  |  |  |  |  |  |  | 1 (1%) |  | 4 (12%) |  |  | 28 (2%) |  | 19 (3%) | 54 (2%) |
| Predictability |  |  | 1 (8%) | 2 (20%) |  | 3 (12%) | 3 (4%) | 3 (12%) | 1 (25%) |  |  |  |  | 1 (4%) | 3 (9%) | 2 (9%) | 2 (5%) | 1 (0%) |  | 45 (7%) | 67 (2%) |
| Privilege |  | 1 (4%) | 1 (8%) |  | 2 (20%) | 1 (4%) |  |  |  |  |  |  | 6 (6%) |  |  |  | 2 (5%) | 19 (1%) |  | 6 (1%) | 38 (1%) |
| Resource Management | 2 (11%) | 2 (7%) |  |  |  | 1 (4%) |  |  |  |  | 3 (12%) |  |  |  |  |  | 7 (16%) | 161 (9%) |  | 11 (2%) | 187 (6%) |
| Risky Values |  | 2 (7%) |  |  |  |  | 1 (1%) |  |  |  |  |  | 2 (2%) | 1 (4%) |  |  |  | 58 (3%) |  | 5 (1%) | 69 (2%) |
| Synchronization |  |  | 1 (8%) |  |  |  |  |  |  |  |  |  |  |  |  |  | 1 (2%) | 49 (3%) |  |  | 51 (2%) |
| Tainted Input | 1 (6%) | 4 (15%) | 3 (23%) | 1 (10%) | 4 (40%) | 2 (8%) | 33 (43%) | 6 (23%) | 1 (25%) |  | 3 (12%) |  | 15 (15%) | 6 (23%) | 10 (30%) | 4 (18%) | 5 (12%) | 177 (10%) | 1 (33%) | 207 (33%) | 483 (17%) |
| UI |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 1 (5%) |  | 4 (0%) |  |  | 5 (0%) |
| Unused entities |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
| **Top-6 share** | 16 (89%) | 24 (89%) | 11 (85%) | 10 (100%) | 10 (100%) | 20 (80%) | 68 (88%) | 22 (85%) | 4 (100%) | 2 (100%) | 25 (100%) | 3 (100%) | 90 (88%) | 24 (92%) | 29 (88%) | 18 (82%) | 31 (72%) | 1587 (89%) | 3 (100%) | 532 (85%) | 2403 (83%) |
| **Total CWEs** | 18 | 27 | 13 | 10 | 10 | 25 | 77 | 26 | 4 | 2 | 25 | 3 | 102 | 26 | 33 | 22 | 43 | 1785 | 3 | 625 | 2879 |

## Coverage

| Category | Yes CVEs | with CWE | CWE attributions | unmapped CWEs |
|---|---|---|---|---|
| doorlock | 17 | 17 | 18 | 0 |
| smartspeakers | 31 | 25 | 27 | 1 |
| doorbell | 23 | 13 | 13 | 0 |
| thermostat | 8 | 8 | 10 | 0 |
| babymonitor | 7 | 6 | 10 | 0 |
| smartplugs | 32 | 26 | 25 | 5 |
| alarms | 77 | 73 | 77 | 3 |
| robotvacuum | 23 | 21 | 26 | 0 |
| fridge | 3 | 3 | 4 | 0 |
| sensors | 2 | 2 | 2 | 0 |
| lighting | 29 | 24 | 25 | 0 |
| appliances | 3 | 2 | 3 | 0 |
| hub | 92 | 90 | 102 | 0 |
| ev-charging | 24 | 24 | 26 | 0 |
| home-power | 31 | 28 | 33 | 0 |
| garden | 17 | 17 | 22 | 0 |
| pet | 29 | 29 | 43 | 2 |
| streaming | 2081 | 1778 | 1785 | 63 |
| airconditioner | 1 | 1 | 3 | 0 |
| cameras | 555 | 515 | 625 | 12 |
| **All** | 3085 | 2702 | 2879 | 86 |

Unmapped CWEs (no ancestry into the 888 view): CWE-399 ×32, CWE-264 ×21, CWE-310 ×9, CWE-255 ×8, CWE-189 ×5, CWE-19 ×5, CWE-254 ×3, CWE-16 ×1, CWE-417 ×1, CWE-17 ×1
