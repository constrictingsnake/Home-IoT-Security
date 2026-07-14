# Claude vs. Codex Disagreement Analysis — Findings & Handling Plan

**Date captured:** 2026-07-01
**Basis:** `data/intersection/matched_*_cves.csv` as of the capture date (directory since deleted —
recover via git history) + current `data/difference/<cat>/reviews/{claude,codex}.csv`
**Status:** PRELIMINARY — no Gemini vote and no human adjudication folded in yet. These are the
Claude/Codex-only patterns. Save this for the adjudication / keyword-refresh pass; nothing here has
been acted on.

---

## TL;DR

Claude and Codex use fundamentally different judgment strategies, and their disagreements are **not
random noise** — they sort into four repeatable types, three of which are one-sided (one reviewer is
systematically right) and can be resolved by *rule* instead of by hand.

- **Codex judges by brand/keyword name-recognition.** It over-includes on a name it recognizes
  (even the wrong product line) and over-excludes on a brand it doesn't recognize (even a genuine
  home device).
- **Claude judges by device-class and scope from the description.** It is the more accurate anchor,
  but has one real weakness (an over-cautious "different product line" boilerplate) and one
  inconsistency (shared-codebase CVEs — see Type D).

This means most contested rows can be auto-resolved by rule, one contested category (`lighting`) is
really a *keyword bug*, and one gap (`Type D`) is a missing rubric rule.

---

## The four disagreement types

Notation: `Cl=X/Cx=Y` means Claude said X, Codex said Y. "N/Y" = Claude No, Codex Yes.

### Type A — Scope boundary: home vs commercial / enterprise / fleet
**Codex over-includes on brand; Claude correctly filters. → Resolve NO.**
Reflects a real definitional line (Definition criteria 2 = device class, 3 = residential deployment).

Evidence:
- **cameras** (~75 of the 149 Cl=N/Cx=Y rows): enterprise Hikvision Hybrid SAN / cluster storage,
  Dahua management servers (DSS / cloud gateway), Pelco professional cameras, wireless bridges, VMS
  server software. All fail criterion 3. Codex said Yes purely on the famous brand name.
- **ev-charging** (all 29 Cl=N/Cx=Y rows): Circontrol Raption, eCharge Salia, **Iocharger** AC
  chargers (one commercial product = an 11-CVE cluster, CVE-2024-43648..43662). All commercial /
  fleet / public EVSE — out of scope per the "home wallbox only" rule. Codex included every EV
  charger regardless.

Consequence: **ev-charging's true pool ≈ its both-Yes floor (~22)**; Codex's extra 29 are all
out-of-scope. Claude correctly applied the home/commercial line.

### Type B — Keyword collision: the search term matched an unrelated product
**Codex over-includes on the keyword hit; Claude correctly rejects. → Resolve NO, AND fix the keyword.**
This is not a reviewer problem — it is a bad search *term*.

Evidence:
- **lighting** (~26 of the contested rows — nearly the entire Cl=N/Cx=Y set): the term
  **"smart switch"** dragged in
  - **Samsung Smart Switch** — the phone data-migration *software* (CVE-2019-20570, 2023-30672/3,
    2025-20996 / 21060 / 21061, 2022-27842)
  - **network switches** — Cisco Small Business, Emerson DeltaV, TP-Link JetStream, Trendnet
    (CVE-2013-1154, 2018-11691, 2023-43318, 2025-25523)
  - Razer Synapse "RazerPhilipsHueUninstall" privilege escalation (CVE-2025-9870) — a Razer app, not
    a Hue bulb.
  None are lighting devices. Claude marked all No (High confidence, reasoning left blank).

Consequence: **lighting's true pool ≈ its both-Yes floor (~24)**, and the keyword list needs the
`smart switch` / bare `switch` term qualified or removed.

### Type C — Unfamiliar-brand under-recognition
**Codex over-EXCLUDES brands it doesn't know; Claude correctly IDs the home device. → Resolve YES.**
This is the documented "Codex over-excludes unfamiliar security brands" bias. It is the main driver
of Cl=Y/Cx=N disagreements in the mid-size categories, and it means the both-Yes floor *undercounts*
these categories.

Evidence:
- **home-power** (17): the **SMA Solar Technology** inverter cluster (CVE-2017-9852..9864, 11 rows) +
  **Victron** Venus OS (CVE-2021-36797) — canonical residential solar/battery brands.
- **alarms** (21): Anker / **eufy HomeBase** (CVE-2021-21940/41/50, 2022-21806/25989/26073,
  2023-37822), **Nexx Smart Home** (CVE-2023-1748..1752) — genuine consumer security hardware.
- **garden** (10): **Green Electronics RainMachine** irrigation (CVE-2018-6011/6012/6906..6909),
  Yarbo (CVE-2026-7413..7415), ECOVACS mowers (CVE-2024-12078).
- **doorlock** (10): **Tinxy** lock (CVE-2020-9438, 2025-44612/14/19), **Yale Keyless**
  (CVE-2023-26943), SGUDA U-Lock (CVE-2022-46307), Genie Aladdin garage opener (CVE-2023-5880),
  EmberZNet Zigbee door-lock cluster (CVE-2026-47149/47151).
- **cameras** (33 Cl=Y/Cx=N): Amcrest, EZVIZ, Zivif, Beward, Mercury, TRENDnet, Momentum Axel, TVT,
  First Corp DVRs.

Consequence: across these, Claude is the reliable anchor; Codex simply isn't recognizing legitimate
brands. These resolve toward Yes and **raise** the category pools above the both-Yes floor.

### Type D — Shared-codebase / platform CVEs  (the genuinely hard ambiguity)
**Both reviewers waver, and Claude is INCONSISTENT between categories.** This is a real rubric gap,
not a bias.

Evidence:
- **streaming** (24 Cl=Y/Cx=N): all "Apple iOS before X **and Apple TV** before Y" shared-codebase
  CVEs (WebKit / kernel / dyld — e.g. CVE-2014-4452, 2011-3259, 2013-0977). Claude says **Yes**
  (Apple TV is explicitly listed and in scope); Codex says No ("really an iOS bug").
- **cameras** (14 rows, from the Type-A/boilerplate analysis): "Nest Cam IQ Indoor" OpenWeave-daemon
  CVEs (CVE-2019-5034/5035/5036/5040/5043) and several Tapo camera-model firmware CVEs. Here Claude
  said **No** with a boilerplate *"not about a camera (likely a different product line)"* — even
  though the device is explicitly named.

Same situation (in-scope device named in a multi-product / shared-stack CVE), **opposite Claude
call**. There is no consistent rule, and Claude's "different product line" boilerplate is firing on
rows where the description *does* name the device.

---

## Per-category pool summary (preliminary)

Confirmed-Yes pool = intersection CVEs + difference rows where BOTH Claude and Codex said Yes.
Direction of skew tells you which way adjudication will move the number.

| Category | ∩ | both-Yes | floor pool | Contested | Dominant type | Adjudication will… |
|---|--:|--:|--:|--:|---|---|
| cameras | 355 | 385 | ~740 | 307 | A + C + D | mostly confirm; net roughly flat |
| streaming | 17 | 127 | ~144 | 40 | D (Apple TV) | rise if Type-D rule = Yes |
| hub | 5 | 75 | ~80 | 17 | mixed | roughly flat |
| alarms | 11 | 29 | ~40 | 30 | C | **rise** |
| ev-charging | 3 | 19 | ~22 | 35 | A | stay ~floor (extras are out-of-scope) |
| lighting | 5 | 19 | ~24 | 34 | B (keyword bug) | stay ~floor (extras are FPs) |
| home-power | 2 | 15 | ~17 | 18 | C | **rise** |
| doorlock | 11 | 5 | ~16 | 13 | C | **rise** |
| garden | 1 | 0 | ~1 | 10 | C | **rise** |
| smartplugs | 4 | 17 | ~21 | 9 | mixed | roughly flat |
| smartspeakers | 6 | 25 | ~31 | 6 | mixed | roughly flat |
| doorbell | 21 | 15 | ~36 | 21 | C + cross-category | rise |
| thermostat | 11 | 6 | ~17 | 2 | — | flat (clean) |
| robotvacuum | 4 | 17 | ~21 | 4 | — | flat (clean) |
| pet | 6 | 27 | ~33 | 2 | — | flat (clean) |
| babymonitor | 5 | 4 | ~9 | 10 | vendor-list contamination | fix vendor list, not review |
| sensors | 1 | 1 | ~2 | 5 | thin | — |
| airconditioner | 1 | 0 | ~1 | 6 | — | flat (nearly all FP) |
| shades | 0 | 0 | 0 | 0 | — | all FP (unanimous No) |
| sleeptracker | 0 | 0 | 0 | 0 | — | all FP — confirms drop |
| appliances / airpurifier / fans / fridge | 0 | ~0 | ~0 | — | empty / stub | need real builds |

Also note: a set of cameras Cl=N/Cx=Y rows are **cross-category reclassifications**, not errors —
Claude moves video doorbells → `doorbell` (Reolink Video Doorbell cluster, Foscam VD1) and baby
monitors → `babymonitor`. Confirm the de-dup rule before adjudicating; it affects `doorbell` too.

---

## HANDLING PLAN (do these later, in this order)

### Action 1 — Fix the `lighting` keyword (Type B), then audit all terms for the same class of bug
Highest leverage, quickest. This is the keyword-mining loop run in reverse (mining a *bad* term out).

1. Edit `data/keyword-search/keyword_terms.csv`, `lighting` slug:
   - Remove / comment the bare `smart switch` and any bare `switch` term.
   - Replace with qualified phrases: `light switch`, `dimmer switch`, `wall switch`, `smart dimmer`,
     `smart bulb`, `smart light`. (Whole-word matching is already on, so these stay tight.)
2. Grep every other category's terms for the same collision risk — generic words that name unrelated
   products: `switch`, `hub` (network), `bridge`, `gateway`, `station`, `monitor`, `plug`. Qualify
   any bare ones.
3. Re-run only the affected category chain (per the CLAUDE.md dependency rule — changing one
   category only re-runs that category):
   - `python3 scripts/build_keyword_search.py --categories lighting --overwrite`
   - `python3 scripts/build_difference_sets.py data/device_lst.txt --direction both --overwrite`
     (or scope to lighting)
   - `python3 scripts/make_review_copies.py lighting`  ← auto-restores prior judgments from
     `judgment_store.csv`; only genuinely new rows go blank, so settled work is not repeated.
4. Re-judge only the new blank rows, then re-merge / re-extract / re-finalize.

**Expected outcome:** lighting's contested count collapses from ~34 toward ~8; the ~26 Samsung /
network-switch / Razer false positives disappear from the difference set entirely.

### Action 2 — Add a shared-codebase rule to the classification rubric (Type D)
Fixes the one genuine gap and the one place Claude is internally inconsistent.

1. Edit `data/difference/CLASSIFICATION_PROMPT.md`. Add a rule, roughly:
   > **Shared-codebase / multi-product CVEs.** If an in-scope device for this category is explicitly
   > named in the CVE's affected-products list (description or CPE), classify **Yes** even when the
   > CVE also affects out-of-scope products that share the same OS, library, or stack (e.g. an
   > iOS/tvOS WebKit CVE that lists Apple TV; an OpenWeave CVE that lists Nest Cam IQ). The shared
   > codebase does not downgrade a device that is named. Do **not** use a "different product line"
   > rejection when the description names the device model itself.
2. This single rule:
   - flips the cameras Nest Cam IQ / Tapo boilerplate rows (14) from Claude-No → Yes,
   - confirms the streaming Apple TV rows (24) as Yes,
   - removes Claude's over-cautious "different product line" boilerplate as a failure mode.
3. Because the rubric is the single source of truth all three reviewers read, no code change is
   needed — it takes effect on the next review pass. Only re-judge rows currently flagged as Type D
   (mostly `streaming` and `cameras`).

### Action 3 — Generate a pre-bucketed adjudication queue (A/B/C/D)
Turns the human pass into mostly confirmation instead of from-scratch review.

1. Write a small script (or extend `extract_human_review.py`) that, for every Claude≠Codex row,
   tags a `Disagreement Type` column using these heuristics:
   - **A (scope):** Claude reasoning contains commercial/enterprise/fleet/industrial/"not a home"
     language, or description names known-commercial product lines (Hybrid SAN, DSS, Raption,
     Iocharger, Circontrol, Pelco pro, wireless bridge, VMS/management server).
   - **B (keyword collision):** description names an unrelated product for the category's search term
     (Samsung Smart Switch, network switch vendors, app/plugin/library). Category-specific list.
   - **C (unfamiliar brand):** Cl=Y/Cx=N and description names a device model of a residential brand
     (SMA, Victron, eufy/Anker, Nexx, RainMachine, Tinxy, Yale, Amcrest, EZVIZ, …).
   - **D (shared codebase):** description lists multiple products / an OS/stack (iOS + Apple TV;
     OpenWeave; EmberZNet/Zigbee stack).
   - else **U (unclassified)** — the only rows a human truly reviews from scratch.
2. Emit a per-category and combined queue with columns:
   `Category, Direction, Disagreement Type, Suggested Resolution, cve_id, description, Cl judgment,
   Cx judgment, Cl reasoning`.
   Suggested resolution: A→No, B→No, C→Yes, D→Yes (per Action 2), U→(blank, human decides).
3. Human confirms the A/B/C/D suggestions in bulk (they are one-sided by construction) and only
   hand-adjudicates the U rows. Feed results through the normal `finalize_judgments.py` path so
   `judgment_store.csv` is upserted.

### Action 4 — Weight the reviewers when Gemini is added
Now that Codex's dual bias is characterized (over-includes on Types A/B, over-excludes on Type C),
treat **Claude as the anchor** and Codex as a brand-recognition signal, not an equal device-class
vote. Gemini is the documented over-includer (function-overlap), so the 2-of-3 + human flag should
catch the residual. No code change — just informs how much the `Needs Human Review` flag should
trust a lone Codex dissent.

### Separate, already-known follow-ups (not from this analysis, but adjacent)
- **babymonitor:** ~95% generic D-Link IP cameras from an over-broad vendor list — fix the vendor
  list, not the reviews.
- **sleeptracker:** 28/28 unanimous No confirms the "88% wearables, drop it" call.
- **appliances / airpurifier / fans / fridge / shades:** empty or stub — need real vendor+keyword
  builds before they can be reviewed.

---

## How to reproduce the numbers in this file
All figures come from reading, per category:
- `data/intersection/matched_<cat>_cves.csv` (row count = intersection size; directory since
  deleted — check out the tree at this file's capture date from git history)
- `data/difference/<cat>/reviews/claude.csv` and `.../codex.csv`, joining on `cve_id` and comparing
  the `Claude Judgment` / `Codex Judgment` columns (normalized to first letter Y/N/M).
Both-Yes = rows where both said Yes; contested = rows where they differ. No new data was written.
