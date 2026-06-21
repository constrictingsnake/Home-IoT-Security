# Home IoT Security — Project Guide

## What This Project Is

A security research pipeline that systematically maps real-world home IoT device brands to known CVEs from NIST's National Vulnerability Database (NVD), organized by device category. The goal is to build a comprehensive dataset of vulnerability exposure across consumer IoT device types (see *Definition of a Home IoT Device* for the scoping criteria; game consoles remain excluded as entertainment, while streaming TVs/sticks were re-admitted as **home-control surfaces** — see criterion 4), with manual review to eliminate false positives. The original 13 vendor categories have since been **expanded and frozen to ~22 analysis categories** — see *Finalized Category Scope*.

---

## Three-Stage Pipeline

### Two search methods (researcher attribution)
The project combines two complementary CVE-discovery methods, each owned by a different researcher:

- **Vendor-based search — Jason.** Compiles a list of manufacturers/brands per device type, then searches NVD for those vendor/brand names. Produces the `results_all_*.xlsx` files (Stage 2, via `cve_search.py` / `run_all_years.sh`; the `--keywords` in `Devices List.docx` are Jason's vendor/brand strings). More prone to false positives, since brand names overlap with unrelated products.
- **Keyword-based search — Lizzie.** Searches NVD for generic device-type keywords (e.g. "security camera", "ip camera"). Produces the `data/keyword-search/*.xlsx` workbooks (Stage 1, via `nvd_keyword_query.py`). `full_intersect.py` (Stage 3) is also Lizzie's — it intersects the two methods' outputs.

Combining both methods yields the most comprehensive per-device CVE list.

### Stage 1 — `nvd_keyword_query.py` (Live API queries)
- Hits the **NVD REST API v2.0** (`services.nvd.nist.gov`)
- Takes comma-separated keywords interactively, shows CVE counts, fetches full detail for approved keywords
- Enriches each CVE with: CVSS score + severity, CWE ID, description
- Outputs a multi-sheet `.xlsx` — one tab per keyword
- Requires an NVD API key — set `NVD_API_KEY` in the gitignored `.env` (the script reads `os.environ["NVD_API_KEY"]`; run `set -a; source .env; set +a` first)
- Rate-limited at 0.6s between requests
- **Comparability caveat:** this hits the *live* API and `keywordSearch` matches the **description only** (no CPE) — which makes its output not directly comparable to the offline, description+CPE vendor search. See *Methodology Notes → Vendor ↔ keyword comparability*.

### Stage 2 — `cve_search.py` (Offline bulk search)
- Designed for local NVD JSON year-feeds (2002–2026)
- Three modes: `--convert` (JSON→CSV), `--merge` (deduplicate multiple CSVs), `--input` (keyword search)
- Searches both description text and CPE strings
- Supports NVD 1.1 and NVD 2.0 JSON formats
- Output columns: `cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings`
- `run_all_years.sh` automates Stage 2 across all years, then merges into a single CSV

### Stage 3 — `full_intersect.py` (Cross-file matching)
- Takes a single-sheet Excel of CVE IDs (from Stage 2 output) and cross-references against all 10 keyword-search workbooks (`data/keyword-search/`)
- Finds CVEs that appear in both the device-specific result set and a generic category query
- Adds `Source File` and `Source Sheet` columns to matched rows
- Saves output to CSV interactively

**Companion script — `full_difference.py`** (the complement of `full_intersect.py`):
- Same inputs and workbook list as `full_intersect.py`
- Outputs the vendor CVEs that appear in **none** of the keyword workbooks (i.e. `vendor − keyword_union`) — the set difference behind `unmatched_cves.xlsx`
- Adds a `Difference Type` (= `vendor_only`) column and drops reviewer judgment columns; default output `unmatched_cves.csv`
- Prints vendor / keyword-union / unmatched counts so the set math is visible
- Note: like `full_intersect.py`, the workbook filenames are bare, so run it from inside `data/keyword-search/` (passing the vendor file via a relative path), or with the workbooks in the cwd

### Stage 4 — Triple-AI review of the difference set (per device category)

The difference set (a category's `vendor − keyword_union`) is the list of vendor CVEs the
keyword search **missed**. Classifying which are true matches both (a) cleans the dataset and
(b) surfaces keywords the keyword search is missing — mining the true-positive descriptions
feeds new terms back into the keyword list to raise recall. To keep this trustworthy, every
row is judged **independently by three AI reviewers**, mirroring the two-human reviewer model:

| Reviewer | Columns it owns | How it runs |
|----------|-----------------|-------------|
| **Claude Code** | `Claude Judgment / Confidence / Reasoning` | manual (in-session) |
| **ChatGPT Codex** | `Codex Judgment / Confidence / Reasoning` | manual (run by a person) |
| **Gemini** | `Gemini Judgment / Confidence / Reasoning` | automated via `gemini_classify.py` (current model `gemma-4-31b-it` — see *Gemini reviewer model & limits*) |

**Blind judgment is a hard rule.** No reviewer may see or be influenced by another reviewer's
answer. This is guaranteed structurally: each reviewer works on its **own copy** that contains
only the raw data + its own empty columns, so other AIs' judgments are physically absent from
the file it reads. All three judge by the same rubric: `data/difference/CLASSIFICATION_PROMPT.md`.

**Per-category workflow** (run from the repo root; `<device>` e.g. `cameras`):
0. (Optional, batch) `python scripts/init_categories.py categories.txt` — scaffold `data/difference/<device>/reviews/` for every category in a newline-separated list. Idempotent: existing folders are left untouched, only missing ones are created.
1. Generate the raw difference set(s) as `data/difference/<device>/01_raw.csv`:
   - **Batch (all categories):** `python scripts/build_difference_sets.py data/device_lst.txt` — maps each list entry to `data/vendor-search/results_all_<device>.xlsx`, builds the keyword union once, and writes every category's `01_raw.csv`. Skips categories that already have one (use `--overwrite` to regenerate).
   - **Single, interactive:** `python scripts/full_difference.py` (run from `data/keyword-search/`; see Stage 3 note), then save to the category's `01_raw.csv`.
2. `python scripts/make_review_copies.py data/difference/<device>/01_raw.csv` → writes blind `reviews/{claude,codex,gemini}.csv`.
3. The two **manual** reviewers each fill **only their own** copy, following the rubric:
   - Claude Code edits `reviews/claude.csv`
   - Codex edits `reviews/codex.csv`
4. Run the **Gemini reviewer + merge in one command**:
   `GEMINI_API_KEY=… python scripts/merge_judgments.py --reviews data/difference/<device>/reviews --run-gemini --category "<keyword>" --model gemma-4-31b-it`
   → fills `reviews/gemini.csv` (resumable; skips already-filled rows), then writes `02_merged.csv` (all 9 AI columns + flag) **and** `02_high_confidence_audit.csv` (a seeded random sample of unanimous-high-confidence rows, so a human can spot-check the calls that otherwise never get reviewed).
   - Plain `python scripts/merge_judgments.py --reviews …` (no `--run-gemini`) just re-merges — a quick status view, no API/`requests` needed.
   - Standalone `python scripts/gemini_classify.py reviews/gemini.csv --category "<keyword>"` still works for the Gemini pass without merging.
   - `bash scripts/run_gemma_column.sh` runs the Gemini pass over **all** categories at once (backs up the prior model's results, blanks the column, fills on Gemma) — see *Gemini reviewer model & limits* for the rate/quota timing.
5. **Extract the human-review queue:** `python scripts/extract_human_review.py` → pulls every `Needs Human Review = Yes` row into `02_needs_human_review.csv` (per category) and `human_review_queue.csv` (combined), each leading with a `Verdicts` summary + reason and ending with blank `Human Verdict` / `Human Notes`.
6. A **human adjudicates** only those flagged rows — fills `Human Verdict` (Yes/No/Maybe) in the queue sheet.
7. **Fold verdicts back to one settled answer:** `python scripts/finalize_judgments.py` → `03_final.csv` (per category) + `final_resolved.csv`, adding `Final Judgment` / `Final Source` (`ai-consensus` for unflagged rows, `human` for adjudicated rows, `pending`/`incomplete` otherwise). Re-run as humans fill more in; never overwrites AI columns.
8. Mine the **resolved-`Yes`** rows (AI-unanimous + human-confirmed) for missing keywords → `03_keyword_additions.md`.

**Human-review flag** (set in `merge_judgments.py`): `Needs Human Review = Yes` when **both strong
reviewers (Claude & Codex) are Low confidence OR the 3 judgments are not unanimous**. Gemini is a
weaker third model, so its self-reported confidence is **recorded but excluded** from the flag (it
skews Low and would inflate the queue); Gemini's *judgment* still counts toward unanimity. Rows
where any AI hasn't reviewed yet are `Review Status = incomplete` (pending, unflagged). Humans only
adjudicate flagged rows.

---

## File Structure

```
Home IoT Security/
├── CLAUDE.md                        # This project guide
├── AGENTS.md                        # Codex reviewer instructions (auto-loaded by Codex)
├── Devices List.docx                # Master keyword reference: categories, source URLs,
│                                    # and exact --keywords strings per device type
│
├── scripts/                         # All pipeline scripts live here
│   ├── nvd_keyword_query.py             # Stage 1 — live NVD API querier
│   ├── cve_search.py                    # Stage 2 — offline bulk NVD searcher
│   ├── run_all_years.sh                 # Automates Stage 2 across 2002–2026
│   ├── full_intersect.py                # Stage 3 — CVE cross-file matcher (intersection)
│   ├── full_difference.py               # Stage 3 — CVE cross-file matcher (difference / complement)
│   ├── build_difference_sets.py         # Stage 4 — batch-generate 01_raw.csv for many categories at once
│   ├── init_categories.py               # Stage 4 — scaffold per-category folders from a list (idempotent)
│   ├── make_review_copies.py            # Stage 4 — split a raw difference set into 3 blind AI copies
│   ├── gemini_classify.py               # Stage 4 — Gemini/Gemma API reviewer (standalone, or imported by merge)
│   ├── merge_judgments.py               # Stage 4 — (optionally run Gemini, then) merge 3 AI copies + flag + audit sample
│   ├── extract_human_review.py          # Stage 4 — pull flagged rows into the human-review queue
│   ├── finalize_judgments.py            # Stage 4 — fold human verdicts into one Final Judgment per CVE
│   └── run_gemma_column.sh              # Stage 4 — run the Gemini/Gemma pass over ALL categories (backup+blank+fill)
│
├── Onboarding-Docs/                 # Onboarding doc + reference papers (unchanged)
│
└── data/                            # All datasets, grouped by search method
    │
    ├── keyword-search/              # Stage 1 outputs (Lizzie) — 10 multi-sheet workbooks
    │   ├── CategoryI_SmartHomeDeviceTypes.xlsx       (smart home, smart speaker, smart TV...)
    │   ├── CategoryII_NetworkGatewayDeviceTypes.xlsx (routers, modems, NVR, mesh wifi...)
    │   ├── CategoryIII_CameraDoorbellDeviceTypes.xlsx (IP cam, baby monitor, doorbell...)
    │   ├── CategoryIV_AccessControlDeviceTypes.xlsx  (smart lock, garage door...)
    │   ├── CategoryV_SensorDeviceTypes.xlsx          (motion, CO, flood, thermostat...)
    │   ├── CategoryVI_ApplianceDeviceTypes.xlsx      (fridge, robot vacuum, smart AC...)
    │   ├── CategoryVI_SwitchDeviceTypes.xlsx         (smart plug, bulb, switch...)
    │   ├── CategoryVII_HubDeviceTypes.xlsx           (smart hub, zigbee hub, matter hub...)
    │   ├── CategoryVIII_ProtocolDeviceTypes.xlsx     (zigbee, z-wave, MQTT, CoAP...)
    │   └── CategoryIX_IoTDeviceTypes.xlsx            (brand names: Ring, Arlo, Hikvision, Tuya...)
    │
    ├── vendor-search/               # Stage 2 outputs (Jason) — 14 in-scope device types (+1 excluded)
    │   ├── results_all_cameras.xlsx          (~2,161 CVEs — largest)
    │   ├── results_all_airconditioner.xlsx   (~187 CVEs)
    │   ├── results_all_gameconsoles.xlsx     (~246 CVEs — OUT OF SCOPE: entertainment, fails criteria 2 & 4)
    │   ├── results_all_streaming.xlsx        (~232 CVEs — IN SCOPE: `streaming` category, home-control surface — criterion 4(b))
    │   ├── results_all_thermostat.xlsx       (~61 CVEs)
    │   ├── results_all_robotvacuum.xlsx      (~80 CVEs)
    │   ├── results_all_smartplugs.xlsx       (~99 CVEs)
    │   ├── results_all_alarms.xlsx           (~117 CVEs)
    │   ├── results_all_doorbell.xlsx         (~60 CVEs)
    │   ├── results_all_babymonitor.xlsx      (~74 CVEs)
    │   ├── results_all_doorlock.xlsx         (~18 CVEs)
    │   ├── results_all_fridge.xlsx           (~3 CVEs)
    │   ├── results_all_fans.xlsx             (~1 CVE)
    │   ├── results_all_smartspeakers.xlsx    (~33 CVEs)
    │   └── results_all_sleeptracker.xlsx     (~27 CVEs)
    │
    ├── intersection/                # Stage 3 — vendor ∩ keyword (full_intersect.py output)
    │   ├── matched_camera_cves.csv       (~1,048 rows — largest)
    │   ├── matched_alarms_cves.csv       (~175 rows)
    │   ├── matched_smartplug_cves.csv    (~88 rows)
    │   └── matched_<device>_cves.csv     (10 more device types)
    │
    └── difference/                  # Stage 3 + Stage 4 — vendor − keyword, plus its triple-AI review
        ├── CLASSIFICATION_PROMPT.md     # shared rubric all 3 AI reviewers judge by (single source of truth)
        ├── unmatched_cves.xlsx          # vendor CVEs in NO category workbook (whole-corpus difference)
        ├── human_review_queue.csv       # extract_human_review.py → all flagged rows, all categories (one sheet)
        ├── final_resolved.csv           # finalize_judgments.py → Final Judgment per CVE, all categories
        │
        └── <device>/                    # per-category triple-AI review (e.g. cameras/)
            ├── 01_raw.csv                   # full_difference.py output (vendor − keyword_union)
            ├── reviews/
            │   ├── claude.csv               # raw + Claude columns   (Claude Code fills, manual)
            │   ├── codex.csv                # raw + Codex columns    (Codex fills, manual)
            │   └── gemini.csv               # raw + Gemini columns   (gemini_classify.py / Gemma fills, API)
            ├── 02_merged.csv                # merge_judgments.py → all 9 AI cols + human-review flag
            ├── 02_high_confidence_audit.csv # seeded sample of unanimous-high-confidence rows to spot-check
            ├── 02_needs_human_review.csv    # this category's flagged rows (Human Verdict to fill)
            ├── 03_final.csv                 # finalize_judgments.py → Final Judgment / Final Source
            └── 03_keyword_additions.md      # keywords mined from resolved-Yes rows (feeds keyword search)
```

> **Note — running the scripts.** Scripts now live in `scripts/`. `full_intersect.py` and
> `full_difference.py` still reference the keyword workbooks by **bare filename**, so run them
> from inside `data/keyword-search/` (e.g. `python ../../scripts/full_intersect.py`). `cve_search.py`
> and `run_all_years.sh` operate on the cwd; run them from wherever the year-feeds / outputs live.

---

## Data Schemas

| File type | Columns |
|-----------|---------|
| `data/keyword-search/*.xlsx` | CVE, CVSS, CVSS Severity, CWE, CWE Name, Description |
| `data/vendor-search/results_all_*.xlsx` | cve_id, published, description, cvss_score, cvss_version, cwe_ids (pipe-sep), cpe_strings (pipe-sep), Lizzie Judgment/Judgement, Cukier Judgment |
| `data/intersection/*.csv` | Source File, Source Sheet, CVE, CVSS, CVSS Severity, CWE, CWE Name, Description |
| `data/difference/<device>/01_raw.csv` | Difference Type, cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings |
| `data/difference/<device>/reviews/{ai}.csv` | …raw columns + `<AI> Judgment`, `<AI> Confidence`, `<AI> Reasoning` (one AI's triple only) |
| `data/difference/<device>/02_merged.csv` | …raw columns + all 3 AI triples (Claude/Codex/Gemini) + `Review Status`, `Needs Human Review`, `Review Reason` |
| `…/02_high_confidence_audit.csv` | `AI Verdict (unanimous)` + raw columns + all 3 AI triples + `Human Verdict`, `Human Notes` |
| `…/02_needs_human_review.csv`, `difference/human_review_queue.csv` | `Verdicts`, `Review Reason` + raw + all 3 AI triples + `Human Verdict`, `Human Notes` (combined file adds a leading `Category`) |
| `…/03_final.csv`, `difference/final_resolved.csv` | …merged columns + `Final Judgment`, `Final Source` (combined file adds a leading `Category`) |
| `data/difference/unmatched_cves.xlsx` | Difference Type, Origin File, cve_id, published, description, cvss_score, cvss_version, cwe_ids, cpe_strings, Lizzie Judgment, Cukier Judgment, Lizzie Judgement |

**Note:** There is a spelling inconsistency — some files use `Lizzie Judgment`, others use `Lizzie Judgement`. Treat them as the same column.

---

## Definition of a Home IoT Device

**Definition.** Home IoT devices are internet-connected sensors, appliances, and embedded systems deployed within residential environments for the purpose of monitoring, automation, or control, without dedicated IT security oversight (Balta-Ozkan et al., 2013; Alrawi et al., 2019).

The criteria below are derived directly from this definition — one per clause. A device must satisfy **all five** definitional criteria.

**Definitional criteria:**
1. **Connectivity** — communicates over a network via standard protocols (TCP/IP, MQTT, CoAP, Zigbee, BLE). *(from "internet-connected")*
2. **Device class** — a special-purpose sensor, appliance, or embedded system; **not** general-purpose IT (PC, phone, tablet, game console). *(from "sensors, appliances, and embedded systems")*
3. **Deployment context** — intended for a private residence (see *Definition of "home"* below), not primarily enterprise/industrial. *(from "deployed within residential environments")*
4. **Function** — qualifies if **either** (a) its primary purpose is to **monitor, automate, or control the home environment or its systems** (climate, security, access, lighting, appliances, presence), **or** (b) it serves as a **home-control surface/hub** for *other* home IoT devices — i.e. it can discover, control, or display the state of other home IoT devices (acts as a Matter/Thread controller or border router, runs a voice assistant, or surfaces camera/sensor feeds). **General-purpose computing and pure media playback with no such control role do not qualify.** *(from "for the purpose of monitoring, automation, or control"; clause (b) generalizes the precedent that admitted smart speakers — media hardware whose qualifying function is home control)*
5. **Security context** — owned and maintained by non-expert consumers, with no professional security administration. *(from "without dedicated IT security oversight")*

**Study-inclusion criterion** (operational, *not* definitional — it scopes what can be analyzed, not what qualifies as home IoT):
- Has a Common Platform Enumeration (CPE)-identifiable footprint in NVD and is subject to CVE disclosure.

**Guiding principle — connectivity is not membership.** Being networked alongside, or interoperating with, home IoT does not make a device home IoT. Criterion 1 (connectivity) is satisfied by virtually every IT device, so it cannot be the discriminator; the device's own **function** (criterion 4) and **class** (criterion 2) are what qualify it. A game console that controls smart lights through an app is still not a home IoT device — it is general-purpose compute (fails criterion 2), and an *app* is not the device acting as a control surface. (Contrast a streaming TV whose *platform* is a Matter/Thread controller — there the device itself is the home-control surface, satisfying criterion 4(b).)

**Entertainment — the hybrid line (criterion 4(b)).** Entertainment hardware qualifies *only* when it doubles as a home-control surface. The discriminator is **control of other home IoT devices**, not connectivity:
- **In scope:** streaming TVs / sticks / boxes (Google TV, Fire TV, Apple TV) — their platforms act as Matter/Thread controllers or border routers, run assistants, and surface camera/doorbell feeds. Smart speakers (already in) and smart soundbars/displays qualify the same way. These form the `streaming` category and the `smartspeakers` absorptions.
- **Out of scope:** game consoles and VR/AR headsets are **general-purpose compute + media** with no home-control role — they fail criterion 2 (device class) *and* criterion 4. Dumb media players / assistant-less TV-companion soundbars also fail 4(b).

(Alrawi et al. include a "media" category because they score *deployment attack surface*; this project stays a *function-defined category study*, so clause 4(b) admits media hardware on its **control function**, not on exposure.) `results_all_streaming.xlsx` is now **in the analysis set**; `results_all_gameconsoles.xlsx` remains on disk but **out of the analysis set**.

**Networking — hub-in / router-out (criterion 4 / 4(b)).** The same control-vs-connectivity test that governs entertainment governs networking: the discriminator is **whether the device controls other home IoT devices**, not whether it carries their traffic. This is the exact line drawn by the project's anchor paper, **Alrawi et al. (2019)** — they *"consider the exploitation of a hub device (communication bridge between low-energy and IP) to be equivalent to exploiting all the connected low-energy devices"* and *"exclude direct evaluation of low-energy devices but consider their hubs for evaluation,"* while the router appears only in the threat-model boundary: *"we consider the home network to be an untrusted network and we make no assumptions about the security state of mobile applications, modems/routers, or web browsers."* The hub is a study subject; the modem/router is untrusted **context** (sitting alongside browsers and mobile apps), and their evaluation table (Table III) has a *Hub* column but **no router/modem device category**.
- **In scope:** IoT **hubs / bridges / controllers** (SmartThings, Hubitat, Hue Bridge, Matter/Zigbee/Z-Wave controllers) — home control *is* their primary function (criterion 4(a)). Mesh/gateways that **also** act as a Matter/Thread/Zigbee controller are carved in via **criterion 4(b)**, identical to the streaming-TV logic, and are reviewed under `hub`.
- **Out of scope (as a category):** pure **transport** gear — plain routers, cable/DSL modems, ONT, unmanaged switches — whose only function is moving packets. By the guiding principle *connectivity is not membership* this fails criterion 4. The network layer is acknowledged as **threat-model context** (the untrusted home network devices sit on, per the standard 3-layer perception/network/application IoT architecture) but is **not** an enumerated category. The generic `router` category is therefore dropped; `CategoryII_NetworkGatewayDeviceTypes.xlsx` stays on disk, but only its hub / mesh-controller terms are in the analysis set.
- **Why not "networking as a base layer":** admitting routers as a network base layer is an *attack-surface-completeness* rationale — the same scope philosophy this project already declined for entertainment (it stays a *function-defined* study, not an attack-surface study). Including them would be internally inconsistent.

**Open scoping note — sleep trackers.** Confirmed by inspection: the current `sleeptracker` set is **~88% wearables** (Fitbit/Apple Watch/Garmin — out by criterion 3) and contains **0** actual bedside monitors. This is a near-total rebuild (bedside-only brands + new keyword sheets), and the category may not clear the NVD-footprint study-inclusion bar — so it could be dropped or folded. See *Finalized Category Scope* and *Methodology Notes → known data issues*.

**Recommended additions** (already keyword-prepped in `Devices List.docx` / `data/keyword-search/` but never given a `results_all_*.xlsx`): **smart hubs, smart lighting** — pass the five criteria cleanly and are folded into the frozen scope below. (Generic **routers/gateways** were keyword-prepped too but are **excluded as a category** — see *Networking — hub-in / router-out* above.)

---

## Finalized Category Scope (frozen 2026-06)

Scope is defined at **two levels**: broad **families** (for narrative / keyword organization) and the
granular **analysis categories** that are the actual unit of search, review, and reporting.

**Granularity rule:** two device types are *separate* analysis categories if a consumer would call
them different products **and** they have a meaningfully different brand set; *merge* only when
they're the same product with a different label. (e.g. cameras / doorbell / baby monitor stay
separate — different brands; blinds / curtains / shutters merge into one `shades` — same product.)

The frozen list is **~22 analysis categories** (hybrid entertainment re-admitted via criterion 4(b); pure-transport networking excluded — hub-in/router-out per Alrawi 2019). Status tags vs. current
coverage: **①** in both searches already · **②** keyword exists, needs a vendor list · **③** vendor
exists, needs keywords · **④** needs both (new build).

| Family | Analysis categories (status) |
|--------|------------------------------|
| Cameras & monitors | `cameras` ①, `doorbell` ①, `babymonitor` ① *(vendor list needs tightening)* |
| Access control | `doorlock` ① *(incl. garage-door openers)* |
| Alarms & sensors | `alarms` ①, `sensors` ② |
| Climate & air | `thermostat` ①, `airconditioner` ①, `fans` ①, `airpurifier` ② |
| Electrical & lighting | `smartplugs` ①, `lighting` ② *(bulbs + switches + dimmers)* |
| Appliances | `fridge` ①, `robotvacuum` ①, `appliances` ④ *(oven/range/cooker/microwave/dishwasher/washer/dryer/water heater)* |
| Hubs & controllers | `hub` ② *(IoT hubs/bridges/controllers; absorbs mesh/gateways that **also** act as Matter/Thread/Zigbee controllers via 4(b))* — pure-transport routers/modems/ONT/switches are **out as a category** (Alrawi 2019: untrusted context, not a study subject) |
| Audio | `smartspeakers` ① *(absorbs smart displays **and smart soundbars** — same brands/platform/CVEs)* |
| Sleep | `sleeptracker` ③ *(rebuild — bedside only)* |
| Shades | `shades` ④ *(blinds/curtains/coverings — one category)* |
| Energy | `ev-charging` ④ *(home EVSE/wallbox only — excludes the vehicle and public/commercial EVCS; criteria 2 & 3)*, `home-power` ④ *(solar + batteries + meters)* |
| Outdoor & pet | `garden` ④ *(irrigation + mowers)*, `pet` ④ *(feeders/cameras/litter)* |
| Entertainment (hybrid) | `streaming` ① *(streaming TVs + sticks/boxes — one category; qualifies via criterion 4(b) as home-control surface)* — game consoles & VR stay **dropped** (fail criteria 2 & 4) |

Build work implied: **4 new vendor lists** (②), **1 new keyword set** (③), **4 full new builds** (④),
plus **2 fixes** (babymonitor tighten, sleeptracker rebuild). The ① categories are ready as-is.

**Open scope calls still to confirm** (all on criterion ③/④): `ev-charging`/`home-power`,
`shades`, `garden`/`pet`, and whether `smart display` stays merged into `smartspeakers` or splits out. (`streaming` confirmed in via criterion 4(b); networking confirmed **hub-in/router-out** per Alrawi 2019; smart soundbars confirmed merged into `smartspeakers`.)

**Dependency rule.** Categories sit upstream of everything: lists → collection (NVD/Shodan/Censys)
→ set-ops → review → mining. Changing one category only forces a re-run of *that* category's chain;
the others are untouched. **Freeze scope before running collection at scale**, or you re-do the
(expensive) AI review on categories you were going to change anyway.

---

## Manual Review — False Positive Classification

### What the judgment columns are
`Lizzie Judgment` and `Cukier Judgment` are independent manual review columns where two researchers determine whether each CVE is a true match for the device category or a false positive from the keyword search.

**Values:**
- `Yes` — true match, CVE genuinely affects this device type
- `No` — false positive, keyword matched but CVE is unrelated
- `Maybe` — ambiguous, needs further discussion

### Guidance for AI-assisted classification (AI Judgment column)

#### Column schema
Each `results_all_*.xlsx` file gets three columns added:

| Column | Values | When to populate |
|--------|--------|-----------------|
| `AI Judgment` | Yes / No / Maybe | Always |
| `AI Confidence` | High / Low | Always |
| `AI Judgment Reasoning` | Short explanation | Low confidence and Maybe rows only |

#### Judgment values
- `Yes` — CVE genuinely affects a home IoT device of this category
- `No` — false positive, keyword matched but CVE is unrelated
- `Maybe` — ambiguous, needs human review. Always paired with Low confidence.

#### Confidence values
- `High` — classification is clear from the description and/or CPE strings. Reasoning column left empty.
- `Low` — some uncertainty exists. Reasoning column must be populated.

Use `Low` confidence when:
- The device could theoretically appear in a home but is primarily a commercial/industrial product
- The description mentions the device category but CPE strings point to enterprise hardware
- The CVE affects a software platform or protocol layer shared between home and non-home contexts
- No CPE string is available on a borderline row

#### Reasoning must be self-contained
Reasoning should explain the classification based solely on the description and CPE strings. Never reference other reviewers' judgments (e.g. "Lizzie marked this Maybe") — the reasoning must stand on its own and work consistently across all files, including those with no prior human review.

#### Maybe is always Low confidence
`Maybe` means the device is genuinely ambiguous. There is no `Maybe (High)` — if you are confident something is ambiguous, it is still `Low` confidence because the classification itself is unresolved.

#### A Maybe or Low confidence No is more useful than a confident wrong answer
Reviewers only check rows with reasoning populated. A High confidence mistake will never be caught. When in doubt, use Low confidence.

### CPE absence does not automatically mean Maybe
A missing CPE string should not downgrade a classification to `Maybe` if the description is unambiguous. CPE data on recent CVEs (especially 2024–2026) is frequently absent due to NIST data lag. If the description explicitly names a home device and describes a residential attack vector (e.g. "accessible via LAN or home router port forwarding"), treat the spirit of criterion 3 as satisfied and classify based on the content.

**Example:** CVE-2025-6260 has no CPE string but its description reads *"the embedded web server on the thermostat... allows unauthenticated attackers, either on the local area network or from the Internet via a router with port forwarding"* — this is unambiguously a home thermostat and should be classified `Yes (High)`.

### Why false positives exist
The keyword search is purely text-based, so generic brand names and terms produce noise. For example:
- Keyword `"cerberus"` (Siemens Cerberus thermostat) also matches Cerberus FTP Server CVEs
- Keyword `"honeywell"` matches industrial controls, security panels, non-IoT products
- Keyword `"smart home"` appears in marketing copy for unrelated software

The thermostat file (the only fully reviewed file) shows a ~65% false positive rate: 14 Yes / 7 Maybe / 40 No out of 61 rows.

### Review decision rule
For each row, read the `description` and `cpe_strings` and ask:
> "Does this CVE describe a vulnerability in a device that a typical home user would have in their home for this category?"

### Current review status

| File | Rows | Lizzie | Cukier |
|------|------|--------|--------|
| `results_all_thermostat.xlsx` | 61 | **Complete** (14 Yes / 7 Maybe / 40 No) | 1/61 |
| `results_all_airconditioner.xlsx` | 187 | 1/187 | 1/187 |
| `results_all_cameras.xlsx` | 2,161 | 1/2161 | 1/2161 |
| All other 10 in-scope `results_all_*.xlsx` | varies | No judgment columns yet | — |
| `results_all_streaming.xlsx` | ~232 | In scope (`streaming`) — no judgment columns yet | — |
| `results_all_gameconsoles.xlsx` | ~246 | **Out of scope** (entertainment, fails criteria 2 & 4) | — |
| `unmatched_cves.xlsx` | 64,327 | ~47/64327 | 3/64327 |

**Next task:** Eliminate false positives across all `results_all_*.xlsx` files by filling in the judgment columns. Files missing the columns need them added first.

---

## Methodology Notes & Findings (2026-06)

### Vendor ↔ keyword comparability (fix before scaling)
The two searches are **not directly comparable**, which quietly pollutes the difference sets:
- **Different data source:** keyword = live NVD API (current); vendor = offline year-feed snapshot (can be stale) → some "gaps" are just data lag.
- **Different match surface:** vendor matches description **+ CPE**; keyword (`keywordSearch`) matches **description only** → many "vendor-only" CVEs are just *brand-in-CPE* artifacts, and device phrases can never match a CPE.
- **Different columns:** keyword output has **no CPE** (and the classification rubric leans on CPE).

Aligning columns alone is a trap. **Fix:** run *both* term lists (brands and device-phrases) through the **same engine** (`cve_search.py`) against **one freshly-downloaded NVD snapshot**, so the only difference is the search terms. Ideal end-state: one per-category run tags each CVE with `match_method` (vendor / keyword / both) → intersection and both differences become column filters. A fixed snapshot also makes the study **reproducible / citeable** ("dataset as of <date>").

### Symmetric (bidirectional) difference — planned
Today only `vendor − keyword` is built. The reverse `keyword − vendor` (surfaces **vendor/brand gaps**) needs per-category keyword files (`keyword_<cat>.xlsx`) produced via a **keyword-sheet → device-slug bridge mapping**. Agreed layout: `data/difference/<cat>/{vendor_only,keyword_only}/`, each a full review unit. A `build_set_ops.py` would normalize both directions to the common schema so the AI-review pipeline stays direction-agnostic.

### Reviewer behaviour & known data issues (from the baseline review)
Claude & Codex are the **permanent** reviewers; Gemini is the **swappable third vote**.
- **Systematic model biases:** Claude is the reliable anchor; **Codex over-excludes** (rejects unfamiliar security brands — e.g. Akuvox video doorbells, Qolsys/Abode/Eufy alarm hardware); **Gemini over-includes** (accepts function-overlap, e.g. IP-camera → baby monitor). The 2-of-3 + human flag catches both; Claude–Codex agree ~86%, Gemini is the outlier.
- **babymonitor contamination:** ~95% of its difference set are **generic IP cameras** (D-Link DCS…) dragged in by an over-broad vendor list — *the fix is tightening the vendor list, not the reviewer.*
- **sleeptracker:** ~88% wearables, 0 bedside monitors, no keyword sheet — needs a rebuild and may be dropped (see scope section).

### Gemini reviewer model & limits
The automated third reviewer evolved `gemini-2.5-flash` → `gemini-3.1-flash-lite` → **`gemma-4-31b-it`** (current; chosen for higher daily quota, supports the structured-output request with no code change). Free-tier caps: 3.1-flash-lite ≈ **500 req/day**; **Gemma 4 31B = 15 RPM / 1,500 req/day**. **Daily quota resets at midnight *Pacific*** (≈03:00 ET — confirmed via a live 429, *not* local midnight). For a clean one-pass run, straddle the reset at `--rps 0.30`. Keep **one model across the whole Gemini column** for consistency (re-run with `--redo` if switching mid-stream; `run_gemma_column.sh` backs up the prior model's results first).

### Future dimension — Shodan / Censys (not yet in the pipeline)
A second axis: NVD = *known vulnerabilities*; Shodan/Censys = *real-world deployment / exposure* (internet scanning). Join to NVD via **CPE / vendor-product**, used mainly at the **brand/category level** (which doesn't need per-CVE CPE, so it survives NVD's 2024+ CPE backlog). Uses: scope validation, brand discovery, exposure-weighting CVEs. **Caveat:** they see only internet-exposed devices (most home IoT is behind NAT) → it measures *exposure, not ownership*.

---

## Environment

- Python 3.14 (at `/Library/Frameworks/Python.framework/Versions/3.14/bin/python3`); invoke as `python3` (no `python` shim on PATH)
- Dependencies installed: `pandas`, `openpyxl`, `numpy`, `requests`
- `tqdm` optional (for progress bars in `cve_search.py`)
- **API keys live in a gitignored `.env`** (never hardcoded): `GEMINI_API_KEY` (Gemini/Gemma reviewer) and `NVD_API_KEY` (read from `os.environ` by `nvd_keyword_query.py`). Load with `set -a; source .env; set +a` before running. NVD key: https://nvd.nist.gov/developers/request-an-api-key · Gemini/Gemma key: https://aistudio.google.com/apikey

## Preferred file formats (for importing from Google Docs/Sheets)
- Google Docs → `.txt` (plain text, directly readable)
- Google Sheets (single sheet) → `.csv`
- Google Sheets (multi-sheet) → `.xlsx` (pandas + openpyxl required, now installed)
