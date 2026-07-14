# Small-Category Recovery — Findings & Implementation Plan

*Analysis date: 2026-07-09, run against the fixed NVD snapshot (2026-06-25, 360,981 CVEs).
Status: **F1 (engine fix) implemented 2026-07-09** — see `scripts/cve_search.py`
`filter_by_keywords` whole-word matcher, which now matches a space in a multi-word term
against `[ _]` so CPE-only mentions are reachable. F2–F4 (vendor-term additions,
CPE-expansion guardrail relaxation, scope-decision writeups) are still **not implemented**.*

This doc records why the under-represented categories (`airpurifier`, `fans`, `fridge`,
`shades`, `sleeptracker`, `sensors`, `appliances`, `airconditioner`, `thermostat`,
`home-power`, `garden`, `pet`) yield so few CVEs, what was measured to be recoverable,
and the concrete changes to make. All candidate terms below were measured against the
snapshot with the same engine the builders use (`filter_by_keywords`, description + CPE,
`whole_word=True`), so the yield numbers are exact, not estimates.

---

## Findings

### F1 — The whole-word matcher is CPE-blind for every multi-word term

A term containing a space (`hunter douglas`, `aqara motion sensor`) can **never** match a
CPE string, because CPE uses underscores (`hunter_douglas`). Since non-alphanumerics act
as boundaries, single-word terms match CPE fine — but the small categories' vendor lists
are almost entirely qualified multi-word phrases (fans 47/51 terms, sensors 50/52,
smartspeakers 91/93, babymonitor 78/83). The FP-protection qualification simultaneously
disconnected these categories from NVD's own attribution data.

**Measured recovery** from letting a space in a term match `[ _]`: **~180 CVEs** across
all categories, at zero new FP surface (only adds CPE-side matches of already-vetted terms):

| Category | Extra CVEs | Driving terms |
|---|---|---|
| smartspeakers | +49 | `smart display` (google smart-display CPEs) |
| hub | +46 | `home hub` → `google:home_hub`, `tradfri gateway`, `hue bridge` |
| cameras | +38 | `ip camera`, `network camera`, `network video recorder` |
| streaming | +31 | `apple tv`, `android tv` |
| thermostat | +10 | `American Standard` → `american_standard` (CVE-2025-5822…5830, CVE-2025-6678) |
| gameconsoles | +9 | `console firmware` (stays out of analysis set) |
| alarms | +3 | `security system` |
| babymonitor | +2 | `baby monitor` → `ibaby:m6` etc. (CVE-2015-2886/2887) |
| doorbell / doorlock / sensors / smartplugs / airconditioner | +1 each | `nest doorbell`, `august home`, `presence sensor`, `smart plug`, `heat pump` |

### F2 — Qualified vendor bigrams have near-zero recall; bare niche brands are safe and yield

`dyson fan`, `levoit fan`, `aqara motion sensor` require the exact bigram verbatim in a
description; NVD text says "Dyson Purifier Cool TP07". For **niche brands the bare brand
is safe** — their entire NVD footprint is tiny, so FP review cost is negligible.
Measured **new** CVEs (beyond everything the current terms already catch), whole-word,
with underscore-variant matching:

| Category | New CVEs | Terms that deliver (new-CVE count) |
|---|---|---|
| home-power | **+66** | `growatt` +35, `solar-log` +13, `solax` +8, `sinapsi` +5, `solaredge` +4, `apsystems` +4, `goodwe` +1, `deye` +1, `enphase` +1 |
| sensors | **+36** | `aqara` +18, `shelly` +6, `fibaro` +6, `netatmo` +3, `zooz` +2, `sonoff` +1 |
| shades | **+23** | `aqara` +18 (curtain drivers ride on hub CVEs; needs routing at review), `lutron` +5 |
| appliances | **+21** | `wemo` +12 (Crock-Pot/WeMo line — partly smartplugs overlap), `miele` +5, `thinq` +3, `crock-pot` +1 |
| thermostat | **+5** | `netatmo` +3, `heatmiser` +2 |
| fridge | **+4** | `thinq` +4 (one is a webOS-TV FP) |
| fans | **+1** | `dyson` +1 (CVE-2025-56558) |

The `growatt` case shows why this channel is irreplaceable: those 35 descriptions are
terse ("An unauthenticated attacker can obtain a user's plant list") — the brand appears
**only in the CPE**, unreachable by any description-based search.

**FP bombs — verified, do NOT add:**
- `worx` (17 hits = Phoenix Contact "PC Worx" industrial software; WORX Landroid mowers have 0)
- `haier` / `hisense` bare (Android phones + Infineon TPM co-listings)
- `mitsubishi electric` bare (160 hits, overwhelmingly industrial)
- `fujitsu` (already prune-flagged 0/96 in `term_precision.csv`)

Also measured **zero** everywhere (searching them is pointless): levoit, coway, winix,
blueair, molekule, vesync, zhimi, smartmi, dreo, big-ass-fans, sensibo, tado, gree,
sleep number, resmed, respironics, dreamstation, withings, emfit, beddit, eight sleep,
petsafe, sureflap, litter-robot, petkit, petnet, tractive, rachio, b-hyve, gardena,
husqvarna, hydrawise, salus, evohome, drayton wiser, plugwise, braeburn, venstar,
proliphix, givenergy, home connect, smarthq, thermomix, instant pot, family hub,
dooya, zemismart, soma smart, motionblinds, hunter douglas, airthings, sensorpush.

### F3 — CPE expansion (Stage 5) cold-starts exactly where it's needed

It seeds only from confirmed-Yes rows, so categories with 0–3 Yes seeds return 0
candidates (`cpe_expansion_summary.csv`: appliances 0, thermostat 0, doorbell 0;
fans/shades/sleeptracker/airpurifier have no o/h seeds at all). Two safe relaxations:

1. **Small-footprint vendor-level expansion.** Guardrail 2(a) (vendor:product only)
   exists because conglomerates explode (vendor-level from current seeds would pull
   google 9.6k, d-link 1.7k, mitsubishielectric 112). But when the seed vendor's whole
   o/h footprint is **≤ ~30 CVEs**, vendor-level is safe by construction. Measured new
   rows: sonos +5, sma +4, assaabloy +4, shelly +1, trane +1. Deny component vendors
   (e.g. `silabs` — 27 Z-Wave-SDK CVEs ride on a doorlock Yes row) the same way
   `GENERIC_PLATFORM_CPES` denies shared OSes.
2. **Curated seed products for zero-seed categories** — let a human-vetted seed list
   (e.g. `atomberg:erica_smart_fan`, `schneider-electric:evlink_smart_wallbox_evb1a`)
   stand in where no Yes row can ever bootstrap the loop. Candidates still go through
   Stage 4 — same guardrail 3 as today.

### F4 — The rest is real NVD sparsity, not search failure

Verified against the live NVD API, not just our snapshot:

- Only **11 CVEs in all of NVD** mention "thermostat" in their description.
- **airpurifier:** every major brand (Levoit, Coway, Winix, Blueair, Molekule, VeSync,
  Xiaomi/zhimi) has zero NVD presence. Category total ≈ 2 CVEs (Mitsubishi co-listing).
- **fans:** exactly 2 CVEs exist (atomberg:erica_smart_fan, one 2025 Dyson).
- **sleeptracker:** zero bedside devices across all 8 brands tested — confirms the
  planned drop (CLAUDE.md open scoping note).
- **fridge:** ≈ 6 CVEs total.

For the paper this is a **finding**: consumer air-treatment and sleep devices are
essentially absent from CVE disclosure — a statement about research attention, not
about device security. Don't force yield; report the absence.

Context numbers: 2024+ CPE coverage in the snapshot decays (2024: 79%, 2025: 60%,
2026: 56%), so recent CVEs are often reachable **only** via description brand mentions —
another reason bare brands (F2) matter.

---

## Next steps (implementation order)

1. **Engine fix (F1) — DONE 2026-07-09.** In `cve_search.py` `filter_by_keywords` whole-word
   mode, a space in a term now matches `[ _]`:
   `re.escape(kw)` → `re.escape(kw).replace(r"\ ", "[ _]")`.
   Regeneration (`pipeline.py refresh --rebuild-search`) triggered same day; refresh
   invariant keeps settled judgments. ~180 new rows expected across categories.
2. **Vendor-term additions (F2)** — add to `vendor_terms.csv`:
   - `home-power`: `growatt`, `solar-log`, `solax`, `sinapsi`, `solaredge`, `apsystems`,
     `goodwe`, `deye` (keep existing enphase/victron/sma terms)
   - `sensors`: `aqara`, `shelly`, `fibaro`, `netatmo`, `zooz`, `sonoff`
   - `shades`: `lutron`, `aqara`
   - `appliances`: `miele`, `thinq`, `crock-pot`, `wemo` *(decide: wemo rows may belong
     to smartplugs — the review scope note should route them)*
   - `fridge`: `thinq`
   - `thermostat`: `netatmo`, `heatmiser`
   - `fans`: `dyson`
   Do **not** add the F2 FP bombs. Expected review load: ~150 rows, concentrated where
   Yes counts are single-digit today.
3. **CPE-expansion upgrades (F3)** — in `cpe_expansion.py`: vendor-level expansion when
   vendor o/h footprint ≤ 30 with a component-vendor denylist (start: `silabs`);
   optional `--seed-file` for curated zero-seed categories.
4. **Optional new channel** — re-download snapshot capturing `sourceIdentifier` (CNA);
   `download_nvd.py` drops it today. IoT-heavy CNAs (VDE ← home-power/heat pumps,
   ONEKEY, Bitdefender) give a discovery axis that works on the 40–44% of 2025–2026
   CVEs still lacking CPE. Requires a snapshot rebuild → new provenance entry.
5. **Scope decisions (F4)** — record in CLAUDE.md scope section: sleeptracker drop
   confirmed by data; airpurifier + fans have no measurable NVD footprint (keep as
   documented-empty categories or drop); fridge near-empty. Report NVD absence as a
   study finding.

## Reproduction

The measurements came from a one-off script (session scratchpad `fast_experiment.py`):
load the snapshot once, apply the exact `whole_word` regex with the `[ _]` variant, and
for each candidate term count hits and hits-not-already-caught-by-current-terms
(baseline = union of the category's current vendor+keyword term matches). Ambiguous
winners (`worx`, `haier`, `growatt`) were spot-checked by reading matched descriptions.
Vendor-level expansion potential was computed by mapping confirmed-Yes o/h CPE vendors
to their whole-vendor CVE sets minus already-reviewed rows.
