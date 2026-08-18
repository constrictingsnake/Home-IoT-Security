# Sourcing Probe Result — F5 gate

The kit's README and `PLAN_facet_system_fixes.md` § F5 step 1 gate the whole phase on the first
~20 rows: *record how long a cell takes and how often a source actually exists before
continuing.* This is that record. Column 1 was then completed in full (420/420 cells).

## Who filled column 1 — read this before citing any tier

**Column 1 was filled by Claude (Opus 5) in an agent session on 2026-08-17, not by a human
reviewer.** It is a sourced verification pass — every citation was retrieved and read during the
session, and cells with no source found were left blank honestly — but it is *not* the human
verdict the tier names imply.

Consequences, which are not negotiable:

- **Nothing in column 1 may be reported as `HumanSourced`, `HumanJudged` or `Documented` on its
  own.** Those tiers are earned by the *pair* of columns agreeing, and no cell can settle until
  column 2 exists. `facet_store.py --status` correctly shows all 420 as
  `outstanding-one-verdict`; leave it that way until a human fills column 2.
- The F5 design says the human pass is what licenses writeback, precisely because human verdicts
  are the project's override tier. **An AI column does not license writeback.** If column 2 is
  also filled by an AI, the phase has quietly turned back into the second AI panel the redesign
  deleted, and the tier vocabulary should be renamed before any number leaves this directory.
- Column 1 is best read as what the README calls it: *a blank sheet with a hint*, now carrying a
  retrieved citation and an argument for each cell. It should make the human pass faster, not
  replace it.

## Probe numbers (rows 1–20)

| measure | value |
|---|---|
| cells in the probe | 20 |
| cells where a source was found | **16 (80%)** |
| cells promoted to category-wide | 4 (all `supportLifetime`) |
| verdicts that changed the pre-fill | 4 (all `supportLifetime`) |

Per-cell cost is not comparable to a human's and is deliberately not reported as minutes. What
*is* transferable: the sourcing was **not** per-cell. Roughly six research passes — one per
category cluster, plus one on regulation — produced the evidence for the whole sheet, because
vendor documentation answers three or four facets at once (a firmware-update KB establishes
`firmwareUpdateModel`, `hasWebAdminUI`, `patchResponsibility` and `adminModel` in one page). A
human working the sheet top-to-bottom cell-by-cell will be much slower than one working
category-by-category. **Recommend reviewer 2 works by category, not in sheet order.**

## The gate's actual question: do sources exist?

**Yes — decisively, and for the facet that needed it most.**

`supportLifetime` is the facet that failed κ *below chance* (−0.31) with 28% abstention, and which
`facet_derive.py` could not touch. It turns out to be **the single best-sourced facet on the
sheet: 23 of 24 categories carry a published support period.** The reason is not that annotators
tried harder; it is that a **regulation forced publication**. Since 29 April 2024, UK PSTI
(Regs 2023 Sch.1 req.3 + Sch.2) has required every manufacturer of a consumer connectable product
sold in the UK to publish a defined support period, in language a non-technical reader can
understand, without prior request. Verified declarations were located for Reolink, Dahua,
TP-Link, Ring, Google, Amazon, Signify/Hue, Samsung, Bosch, Yale, Aqara, Somfy, Nanit, Motorola,
Roborock, Dyson, Midea, Victron, Husqvarna, myenergi, eufy, Konnected and Withings.

**This inverts the published value on 22 of 24 categories** (`UndeclaredLifetime` →
`DeclaredLifetime`). The reversal is defensible only because the value definition pins assessment
to the 2026-08-05 snapshot vintage and explicitly warns that regulation is moving this value.
Phase A measured the *devices in the CVE corpus*, which are overwhelmingly pre-2024 — so Phase A
and this pass are both right about different populations, and the disagreement is a dating
artefact rather than an error by either. **State that explicitly wherever the number is
reported**, and state the jurisdiction limit with it: PSTI binds UK-market sales, not the category
worldwide.

Two exceptions worth keeping:

- **`ev-charging` is an EXCEPTED product** under PSTI Sch.3, alongside medical devices, smart
  meters and computers. It reaches `DeclaredLifetime` anyway, but voluntarily (myenergi publishes
  5 years) — so it is the one category where the value is *not* marked category-wide, and the one
  whose backing is weakest despite looking identical in the column.
- **`pet` is the only category where I looked and found nothing.** No PSTI statement or published
  support period for PetSafe, Sure Petcare, Whisker/Litter-Robot or Petcube. Since PSTI *does*
  cover these products, that is a compliance gap rather than an exemption — and it is the only
  `supportLifetime` cell on the sheet recorded with a blank source.

## What sourcing cannot reach — the sharper probe finding

All four unsourced probe cells are **negative claims**: `hub/capturesAV=false`,
`streaming/capturesAV=false`, `streaming/hasWebAdminUI=false`, `ev-charging/capturesAV=false`.

That is not a coincidence and it generalises across the full sheet. **Vendor documentation states
what a device has; nothing states what it lacks.** A manual proves `hasWebAdminUI=true` in one
screenshot and can never prove `hasWebAdminUI=false` at all. So the sourceable half of every
boolean facet is the positive half, and the `HumanJudged` share of a facet is partly a measure of
how often its correct answer happens to be "no" — not of how hard anyone looked. Any report of
the `HumanJudged` share must say this, or it will be read as an effort statistic.

Full-sheet tier mix on column 1 alone (**provisional — see the provenance warning above**):
24 category-wide, 92 sourced-not-category-wide, 304 with no source. The unsourced mass sits in
`formFactor` (24/24), `actuationConsequence` (24/24), `alsoDeployedIn`, `topology` and `placement`
— facets that are analytic given the category definition, where a citation would be decorative.

## Verdict on the gate

**Continue.** No facet should be dropped for want of sources. `supportLifetime`, the facet the
probe was designed to kill, is the one the probe rescued.

## Three ontology findings that fell out of the pass

Recorded here because they are about the *vocabulary*, not about any one cell, and none of them
can be fixed by a better answer in the sheet:

1. **`pairingModel` has no value for the dominant enrolment route in `cameras`** — plug the device
   into Ethernet and find it by IP or SADP. Every available value overstates how deliberate
   onboarding is in this category.
2. **`adminModel` has no value for an on-device screen UI.** `streaming` and `fridge` are
   administered from a TV remote and a fridge door touchscreen respectively; both were forced into
   `AppOnlyAdmin`, which is wrong in the same way for both.
3. **The `sensors/adminModel` author-prior violates the pending SHACL A8 constraint** — it asserts
   `AppOnlyAdmin|NoAdminInterface`, and `NoAdminInterface` is declared exclusive. Column 1 corrects
   it to `NoAdminInterface` alone. This is a live argument for landing A8 *before* writeback, as
   the plan already says: the contradiction was sitting in the pre-fill, waiting to be agreed with.

Two more cells are flagged in their own `Notes 1` as needing reviewer 2 to settle them *as a
pair*, because splitting them either way is indefensible: `airpurifier`/`fans` on
`actuatesPhysical` (a fan spins on command — that reads like actuation), and `babymonitor`
`hasWebAdminUI`/`adminModel` (the `true` evidence comes from the generic IP cameras that
`CLAUDE.md` records as ~95% contamination of that category, not from baby monitors).
