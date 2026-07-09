# Home IoT Security — Project Guide

This doc is reviewer rules + design rationale (the *why*). For exact commands to run any stage,
see `README.md`; for first-run result tables and worked examples, see `docs/FIRST_RUN_RESULTS.md`;
for full per-script flags, see `docs/SCRIPTS_REFERENCE.md`.

## What This Project Is

A security research pipeline that systematically maps real-world home IoT device brands to known CVEs from NIST's National Vulnerability Database (NVD), organized by device category. The goal is to build a comprehensive dataset of vulnerability exposure across consumer IoT device types (see *Definition of a Home IoT Device* for the scoping criteria; game consoles remain excluded as entertainment, while streaming TVs/sticks were re-admitted as **home-control surfaces** — see criterion 4), with manual review to eliminate false positives. The scope is **frozen to 24 analysis categories** — see *Finalized Category Scope*.

---

## Pipeline Design Rationale (by stage)

### Two search methods (researcher attribution)
The project combines two complementary CVE-discovery methods, each owned by a different researcher, both run through the **same engine** (`cve_search.py`'s `filter_by_keywords`, description **+ CPE**, `whole_word=True`) against **one fixed NVD snapshot** — so a gap between them reflects a genuine difference in search terms, not data freshness:

- **Vendor-based search — Jason.** Compiles manufacturers/brands per device type, searches NVD for those names. More prone to false positives, since brand names overlap with unrelated products. Terms: `data/vendor-search/vendor_terms.csv` (`slug,term`); qualified with a product word where the bare brand overlaps unrelated products (e.g. `carrier infinity`, not `carrier`).
- **Keyword-based search — Lizzie.** Searches generic device-type keywords (e.g. "security camera"). Terms: `data/keyword-search/keyword_terms.csv` — device-type **phrases only**, no brands/protocols/firmware/umbrella terms (brand discovery is the vendor search's job). Also owns the per-category **intersection** direction (Stage 3).
- **Whole-word matching** on both blocks substring bombs (e.g. `nvr`→`nvram`) without affecting CPE matching (non-alphanumerics act as boundaries).

The `matched_terms` column on both builders' output (pipe-separated, one CVE can list multiple terms) feeds `term_precision.py` — per-term false-positive rate on the difference set, a prune-candidate list for `keyword_terms.csv`/`vendor_terms.csv`.

### Stage 3 — Intersection audit (V∩K is *not* assumed clean)
Historically the intersection was assumed high-precision ("both methods agree") and skipped. An audit of 470 CVEs showed that holds for most categories (≈96% true) but **fails for `cameras`**: generic device-phrase keywords collide with pro/enterprise surveillance brands (Axis/Hikvision/Milesight/Geovision etc. — judged per the same nuanced convention as the difference set). So intersection is now a fourth review direction, routed through the same Stage-4 chain. It is disjoint from `vendor_only`/`keyword_only` (the three partition V∪K) and from `cpe_expansion`.

### Stage 4 — Triple-AI review
Classifying which difference-set CVEs are true matches both (a) cleans the dataset and (b) surfaces keywords the keyword search is missing. **Blind judgment is a hard rule** — no reviewer may see another's answer, guaranteed structurally: each reviewer works on its own copy containing only raw data + its own empty columns.

| Reviewer | Columns it owns | How it runs |
|----------|-----------------|-------------|
| **Claude Code** | `Claude Judgment / Confidence / Reasoning` | manual (in-session) |
| **ChatGPT Codex** | `Codex Judgment / Confidence / Reasoning` | manual (run by a person) |
| **Gemini** | `Gemini Judgment / Confidence / Reasoning` | automated via `gemini_classify.py` |

All three judge by the same rubric (`data/difference/CLASSIFICATION_PROMPT.md`) **and** the same per-category scope note (`data/categories.csv`, `scope_note` column) — so unanimity means agreement under one shared scope. Gemini gets the note injected automatically (slug derived from its review-copy path); Claude and Codex read their category's row before judging.

**Human-review flag** (set in `merge_judgments.py`): `Needs Human Review = Yes` when both Claude and Codex are Low confidence, **or** the 3 judgments are not unanimous. Gemini is a weaker third model, so its confidence is recorded but **excluded** from the flag (it skews Low and would inflate the queue); its *judgment* still counts toward unanimity. Rows any AI hasn't reviewed are `Review Status = incomplete` (pending, unflagged).

### Stage 5 — Why CPE expansion runs *after* review, not as a third search up front
It trades breadth for precision. Seeding only from confirmed-`Yes` CPEs means it can never invent a new brand — but every CVE it returns is already attributed by NVD to a device a human/consensus signed off on, so it is far higher-precision than a third text search would be. Vendor terms find brands, keyword terms find device language, CPE expansion finds everything NVD itself already attributed to a confirmed device. Because it depends on settled judgments, it slots in after the review loop and feeds its output back through that same loop (a **densification** method — deepens confirmed products, never a new brand).

**Three guardrails** keep it honest:
1. **Seed only from confirmed `Yes`** rows (`judgment_store.csv`) — never an unreviewed CVE.
2. **Device-CPE granularity.** (a) `vendor:product` only, never vendor-only (`tp-link:tapo_p100`, not all of `tp-link`). (b) `part ∈ {o, h}` only — a co-listed `part=a` app/library CPE riding on a device's Yes row (e.g. `openweave:openweave-core` on a camera CVE) is dropped, pinning expansion to the physical device, not its dependencies. (c) **General-purpose computing platforms are denied** (`GENERIC_PLATFORM_CPES`) even though `part=o` — Apple/Google attribute one CVE across every OS at once, so an Apple-TV Yes row co-lists `apple:tvos` with `apple:mac_os_x`/`apple:iphone_os`/`apple:watchos`; seeding those would pull the whole desktop/mobile corpus. Only shared platforms (macOS, iOS, Android, Windows, Linux kernel, NVIDIA Jetson dev boards) are denied; device-specific OS/firmware CPEs are kept. `apple:tvos` itself is deliberately kept (in-scope via criterion 4(b)).
3. **Candidates are never auto-included** — they still go through Stage 4 (or an audit sample). High CPE precision ≠ zero false positives.

See `docs/FIRST_RUN_RESULTS.md` for measured yield/precision.

### Stage 6 — Capture–recapture recall estimation
Review measures **precision**; it says nothing about **recall**. Stage 6 treats the vendor and keyword searches as two independent capture occasions of the same CVE population (Lincoln–Petersen/Chapman), estimating `N̂` and combined recall `|V∪K|/N̂` without any new labelling. `--three` adds a third capture set `C` (every CVE NVD attributes to a confirmed-Yes device CPE) via an AIC-selected Poisson log-linear model, letting the data estimate V–K dependence instead of assuming it away.

Honest caveats:
1. **Two-source `N̂` is biased *down* by V–K positive dependence** → its recall is an upper bound. Prefer the three-source figure where present.
2. **`C` is not a clean third capture** — seeded from already-confirmed products, so it can't reach a CVE whose product never appeared in V/K.
3. **The `yes` population isn't yet paper-grade** — needs a labelled `keyword_only` direction and labelled `V∩K` samples for a few rich categories. The `raw` (search-stage) recall is defensible today.
4. `recall = 1.0` rows are flagged `degenerate` (one list ⊆ the other — recapture carries no information) and excluded from the pooled total.

See `docs/FIRST_RUN_RESULTS.md` for measured numbers.

### Refresh invariant
Human verdicts (`extract_human_review.py`) and AI judgments (`judgment_store.csv`, read by `make_review_copies.py`) are both preserved by `(category, cve_id)`, so a deliberate `01_raw` regeneration never repeats settled work — it only creates review load for *genuinely new* rows. The store survives folder restructures and pipeline changes since it's a flat CSV independent of the review directory layout. See `docs/FIRST_RUN_RESULTS.md` for a worked example with real numbers.

---

## File Structure

```
Home IoT Security/
├── CLAUDE.md                        # This project guide (reviewer rules + design rationale)
├── README.md                        # How to run every stage
├── AGENTS.md                        # Codex reviewer instructions (auto-loaded by Codex)
├── docs/
│   ├── FIRST_RUN_RESULTS.md             # Point-in-time result tables + worked examples
│   ├── SCRIPTS_REFERENCE.md             # Full per-script flag tables
│   └── ...                              # Prior analysis docs, report draft
│
├── scripts/                         # All pipeline scripts (see README "Scripts" for one-liners)
│   └── _legacy/                          # Retired — superseded, kept for reference only
│
└── data/                            # All datasets, grouped by search method
    ├── categories.csv                # THE 24 frozen analysis categories: slug, label, scope_note
    ├── nvd-snapshot/                 # Fixed offline NVD dataset (one snapshot, reproducible/citeable)
    ├── keyword-search/               # Stage 1 output + user-authored keyword_terms.csv
    ├── vendor-search/                # Stage 2 output + user-authored vendor_terms.csv
    └── difference/                  # Stage 3+4 — vendor/keyword difference + its triple-AI review
        ├── CLASSIFICATION_PROMPT.md     # shared rubric all 3 AI reviewers judge by
        ├── judgment_store.csv           # persistent AI judgment store — keyed (category, cve_id)
        ├── final_resolved.csv           # Final Judgment per CVE, all categories (derived)
        ├── term_precision.csv           # per-term precision from settled judgments (derived)
        ├── recall_estimate.csv          # per-category capture-recapture recall + POOLED total (derived)
        └── <device>/                    # per-category review — all directions in one reviews/ folder
            ├── vendor_only/01_raw.csv, keyword_only/01_raw.csv, cpe_expansion/01_raw.csv, intersection/01_raw.csv
            ├── reviews/{claude,codex,gemini}.csv    # combined blind copies (all 4 directions)
            ├── 02_merged.csv, 02_high_confidence_audit.csv, 02_needs_human_review.csv
            └── 03_final.csv, 03_keyword_additions.md
```
> All four review directions are **disjoint**. `vendor_only`, `keyword_only`, and `intersection`
> together **partition** V∪K; `cpe_expansion` (Stage 5) sits outside it. The `Difference Type`
> column (`vendor_only` / `keyword_only` / `cpe_expansion` / `intersection`) sorts every row back
> to its direction within the combined files. Full column schemas are in `README.md` § Data Schemas.

---

## Definition of a Home IoT Device

**Definition.** Home IoT devices are internet-connected sensors, appliances, and embedded systems deployed within residential environments for the purpose of monitoring, automation, or control, without dedicated IT security oversight (Balta-Ozkan et al., 2013; Alrawi et al., 2019).

The criteria below are derived directly from this definition — one per clause. A device must satisfy **all five** definitional criteria.

**Definitional criteria:**
1. **Connectivity** — communicates over a network via standard protocols (TCP/IP, MQTT, CoAP, Zigbee, BLE). *(from "internet-connected")*
2. **Device class** — a special-purpose sensor, appliance, or embedded system; **not** general-purpose IT (PC, phone, tablet, game console). *(from "sensors, appliances, and embedded systems")*
3. **Deployment context** — intended for a private residence, not primarily enterprise/industrial. *(from "deployed within residential environments")*
4. **Function** — qualifies if **either** (a) its primary purpose is to **monitor, automate, or control the home environment or its systems** (climate, security, access, lighting, appliances, presence), **or** (b) it serves as a **home-control surface/hub** for *other* home IoT devices — i.e. it can discover, control, or display the state of other home IoT devices (acts as a Matter/Thread controller or border router, runs a voice assistant, or surfaces camera/sensor feeds). **General-purpose computing and pure media playback with no such control role do not qualify.** *(from "for the purpose of monitoring, automation, or control"; clause (b) generalizes the precedent that admitted smart speakers — media hardware whose qualifying function is home control)*
5. **Security context** — owned and maintained by non-expert consumers, with no professional security administration. *(from "without dedicated IT security oversight")*

**Study-inclusion criterion** (operational, *not* definitional — it scopes what can be analyzed, not what qualifies as home IoT):
- Has a Common Platform Enumeration (CPE)-identifiable footprint in NVD and is subject to CVE disclosure.

**Guiding principle — connectivity is not membership.** Being networked alongside home IoT does not make a device home IoT. The discriminator is the device's **function** (criterion 4) and **class** (criterion 2). A game console controlling smart lights via an app fails criterion 2, and the app is not the device acting as a control surface — contrast a streaming TV whose *platform* is a Matter/Thread controller, where the device itself is the home-control surface (satisfying criterion 4(b)).

**Entertainment — the hybrid line (criterion 4(b)).** Entertainment hardware qualifies *only* when it doubles as a home-control surface (control of other home IoT devices, not just connectivity):
- **In scope:** streaming TVs / sticks / boxes (Google TV, Fire TV, Apple TV) — platforms act as Matter/Thread controllers, run assistants, surface camera/doorbell feeds. Form the `streaming` category. Smart speakers, soundbars, and displays qualify the same way (`smartspeakers`).
- **Out of scope:** game consoles and VR/AR headsets (general-purpose compute, fail criteria 2 & 4). `results_all_gameconsoles.csv` stays on disk but is **out of the analysis set**.

**Networking — hub-in / router-out (criterion 4 / 4(b)).** The discriminator is **whether the device controls other home IoT devices**, not whether it carries their traffic. Per Alrawi et al. (2019), hubs are study subjects; routers/modems appear only as untrusted threat-model context.
- **In scope:** IoT **hubs / bridges / controllers** (SmartThings, Hubitat, Hue Bridge, Matter/Zigbee/Z-Wave controllers) — home control is their primary function (4(a)). Mesh/gateways that **also** act as Matter/Thread/Zigbee controllers are reviewed under `hub` via 4(b).
- **Out of scope:** pure **transport** gear — plain routers, modems, ONT, unmanaged switches. The generic `router` category is dropped.

**Open scoping note — sleep trackers.** The current set is ~88% wearables (Fitbit/Apple Watch/Garmin — out by criterion 3), 0 actual bedside monitors. Near-total rebuild needed; may be dropped if it doesn't clear the NVD-footprint bar.

---

## Finalized Category Scope (frozen 2026-06)

**Granularity rule:** two device types are *separate* analysis categories if a consumer would call
them different products **and** they have a meaningfully different brand set; *merge* only when
they're the same product with a different label. (e.g. cameras / doorbell / baby monitor stay
separate — different brands; blinds / curtains / shutters merge into one `shades` — same product.)

The frozen list is **24 analysis categories** (the 25th vendor slug, `gameconsoles`, stays on disk but is out of the analysis set; pure-transport networking excluded per Alrawi 2019). Category membership is frozen; **term coverage** is not — run `python3 scripts/pipeline.py status` for live per-category coverage. The full family/slug table lives in `README.md` § Device Categories to avoid duplicating it here.

**Open scope calls still to confirm:** `ev-charging`/`home-power`, `shades`, `garden`/`pet`, and whether `smart display` stays merged into `smartspeakers` or splits out.

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

| Column | Values | When to populate |
|--------|--------|-----------------|
| `AI Judgment` | Yes / No / Maybe | Always |
| `AI Confidence` | High / Low | Always |
| `AI Judgment Reasoning` | Short explanation | Low confidence and Maybe rows only |

- `Yes` — CVE genuinely affects a home IoT device of this category
- `No` — false positive, keyword matched but CVE is unrelated
- `Maybe` — ambiguous, needs human review. **Always paired with Low confidence** — there is no `Maybe (High)`; being confident something is ambiguous still means the classification itself is unresolved.
- `High` confidence — classification is clear from the description and/or CPE strings. Reasoning left empty.
- `Low` confidence — some uncertainty exists (device could be commercial/industrial; CPE points to enterprise hardware; description mentions a shared software layer; no CPE on a borderline row). Reasoning column must be populated.

**Reasoning must be self-contained.** Explain the classification from the description and CPE strings alone. Never reference other reviewers' judgments (e.g. "Lizzie marked this Maybe") — it must stand on its own and work consistently across files with no prior human review.

**A Maybe or Low-confidence No is more useful than a confident wrong answer.** Reviewers only check rows with reasoning populated. A High-confidence mistake will never be caught. When in doubt, use Low confidence.

### CPE absence does not automatically mean Maybe
A missing CPE string should not downgrade a classification to `Maybe` if the description is unambiguous. CPE data on recent CVEs (especially 2024–2026) is frequently absent due to NIST data lag. If the description explicitly names a home device and describes a residential attack vector (e.g. "accessible via LAN or home router port forwarding"), treat the spirit of criterion 3 as satisfied and classify based on the content.

**Example:** CVE-2025-6260 has no CPE string but its description reads *"the embedded web server on the thermostat... allows unauthenticated attackers, either on the local area network or from the Internet via a router with port forwarding"* — this is unambiguously a home thermostat and should be classified `Yes (High)`.

### Why false positives exist
The keyword search is text-based, so generic brand names produce noise (e.g. `"cerberus"` matches Cerberus FTP Server CVEs; `"honeywell"` matches industrial controls). The thermostat file showed a ~65% false positive rate (14 Yes / 7 Maybe / 40 No out of 61 rows) before the current term set.

### Review decision rule
For each row, read the `description` and `cpe_strings` and ask:
> "Does this CVE describe a vulnerability in a device that a typical home user would have in their home for this category?"

---

## Methodology Notes

### Reviewer behaviour & known data issues
Claude & Codex are the **permanent** reviewers; Gemini is the **swappable third vote**.
- **Systematic model biases:** Claude is the reliable anchor; **Codex over-excludes** (rejects unfamiliar security brands — e.g. Akuvox video doorbells, Qolsys/Abode/Eufy alarm hardware); **Gemini over-includes** (accepts function-overlap, e.g. IP-camera → baby monitor). The 2-of-3 + human flag catches both; Claude–Codex agree ~86%, Gemini is the outlier.
- **babymonitor contamination:** ~95% of its difference set are **generic IP cameras** (D-Link DCS…) dragged in by an over-broad vendor list — *the fix is tightening the vendor list, not the reviewer.*
- **sleeptracker:** ~88% wearables, 0 bedside monitors, no keyword sheet — needs a rebuild and may be dropped (see scope section).

### Gemini reviewer model choice
The automated third reviewer uses **`gemma-4-31b-it`** (chosen for higher daily quota over the default `gemini-2.5-flash`). Free-tier caps: **15 RPM / 1,500 req/day**, resetting at midnight *Pacific*. Keep **one model across the whole Gemini column** for consistency — re-run with `--redo` if switching mid-stream, backing up the prior column first if it needs preserving. Exact run commands/flags are in `README.md`.

### Future dimension — Shodan / Censys (not yet in the pipeline)
A second axis: NVD = *known vulnerabilities*; Shodan/Censys = *real-world deployment / exposure* (internet scanning). Join to NVD via **CPE / vendor-product**, used mainly at the **brand/category level** (which doesn't need per-CVE CPE, so it survives NVD's 2024+ CPE backlog). Uses: scope validation, brand discovery, exposure-weighting CVEs. **Caveat:** they see only internet-exposed devices (most home IoT is behind NAT) → it measures *exposure, not ownership*.

---

## Environment

Python version, dependencies, and API-key setup are documented once, in `README.md` §
Prerequisites — this file doesn't duplicate it. `.env` provides `GEMINI_API_KEY` and `NVD_API_KEY`; never hardcode either.

## Preferred file formats (for importing from Google Docs/Sheets)
- Google Docs → `.txt` (plain text, directly readable)
- Google Sheets (single sheet) → `.csv`
- Google Sheets (multi-sheet) → `.xlsx` (pandas + openpyxl required, now installed)
