# Plan — Multi-Annotator Facet Assignment with Measured Agreement

*Status: **EXECUTED** (2026-08 → 2026-09) — this doc is the design record, not a to-do list. The
route out of the `hiot:Estimated` dead end it proposed was taken, and it produced a verdict rather
than a promotion: the 3-rater panel ran (471 shared items) and **only 4 of 12 facets reach
κ ≥ 0.60**, with `supportLifetime` below chance at −0.311. Phase A (device sampling, § below) was
added mid-flight when it became clear **validity sits upstream of reliability**. Sourcing landed
via `PLAN_facet_system_fixes.md` § F5, not via this plan's writeback step. Live state and the
κ table are in `CLAUDE.md` § Phase A heterogeneity; the one open follow-on is F4's cameras subtype
pass. Read the `DONE` markers inline below for what each step actually produced.*

**Goal:** move the 496 device-type facet assertions in `ontology/homeiot.ttl` from
"one author asserted them" to "independently annotated by three models under a shared
rubric, disagreements adjudicated by two humans, with reported inter-rater agreement" —
so facets can appear in the paper as something other than a limitation.

**This is the same methodology the project already invented for CVE review, applied to a
different unit.** Stage 4 blind-judges *(category, cve_id)*; this blind-judges
*(category, facet)*. The rubric, the blind-copy structure, the flag rule, the human queue
and the sticky-verdict store are all proven — reuse them rather than inventing a parallel
mechanism.

---

## Why the current state blocks publication

All 18 facet properties carry `hiot:evidenceTier hiot:Estimated`: hand-assigned in one
pass, no source. `scripts/facet_derive.py` already established that the two most promising
facets **cannot** be rescued by measuring them from NVD text — `hasWebAdminUI` swings from
23% to 65% on cameras depending on the keyword list (19 of 22 categories move >25 points),
and `computeTier` leaves usable evidence on 1 of 22. That was the "derive it" route and it
is closed. This is the "measure the annotation instead" route.

The bar being cleared: a hand-assigned annotation is citable when it is measured, externally
grounded, **shown reliable across independent annotators**, or reframed as a scheme. This
plan buys the third.

---

## THE CONTAMINATION PROBLEM — read before designing anything

**The existing 496 assertions were authored by Claude**, in the same session that built the
facet vocabulary. Claude is also one of the three standing annotators. Three consequences,
all of which the design must handle rather than hope about:

1. **The current values cannot be the gold standard.** Comparing the panel against them
   would measure how well the panel reproduces one author, not whether the facets are
   reliable.
2. **Claude must re-annotate blind, in a fresh session, without reading `homeiot.ttl`.**
   Annotators get the criteria, the facet vocabulary with value definitions, and the
   category's `scope_note` — never the current assignment. This is the same structural
   guarantee Stage 4 already uses: each reviewer works on a copy containing only raw data
   and its own empty columns.
3. **A "fresh session" inside this repo is NOT blind — this is the leak that matters.**
   Claude Code auto-loads `CLAUDE.md`, which states the facet results outright
   (`capturesAV` = 1,120 rows / 79% cameras; `actuatesPhysical` = 388 rows over 13
   categories; the hand assignment wrong for 7 of 22 on `hasWebAdminUI`), and auto-loads the
   memory index, which carries `facet-dominance-rule` and `facet-provenance-estimated`.
   Running the annotator in the project directory hands it the prior's conclusions before it
   answers anything. The mechanical fix is in Phase 2 (*annotation kit*). A second, quieter
   channel: property-level `rdfs:comment` text carries the author's *rationale*, not just
   definitions — `formFactor`'s comment says "Worn is what excludes wrist wearables from the
   sleeptracker category", which hands over one category's answer directly. Phase 1 strips
   rationale from what reaches the annotator.
4. **Residual contamination must be disclosed anyway.** Even a fresh session in a clean
   directory is the same model that produced the prior. State it in the paper; do not claim
   it away.

**Turn the problem into a result.** Keep the original assignment as a separate
`author_prior` column, excluded from κ, and report how often the blind panel agreed with
it. That directly measures what the single-author pass was worth — a genuinely interesting
number either way, and the honest way to present work already done.

---

## Scale (measured, not estimated)

| Facet kind | Facets | Items per annotator |
|---|---|---|
| Nominal, single-valued (Fleiss over 24 categories each) | 12 | 288 |
| Multi-valued, binarised to present/absent per value | 7 | 696 |
| **Total per annotator** | **19** | **984** |
| **Total AI judgments** (×3) | | **2,952** |

For comparison, Stage 4 has already blind-judged far more than this. The annotation load is
not the risk; the statistics are (see *Small-N*).

Multi-valued facets (`topology`, `pairingModel`, `alsoDeployedIn`, `hasRole`, `adminModel`,
`credentialModel`, `patchResponsibility`) cannot take nominal κ directly — a set-valued
answer is not one category. Binarise: for each *(category, facet, value)* each annotator
says present/absent, and κ is computed over those binary decisions. Their value lists sum to
29, hence 29 × 24 = 696.

**The 19th facet is `hasRole`, and it is AXIOM-BEARING — annotate, never write back.** Only
18 properties carry `hiot:evidenceTier`; the 19th comes from `facet_analysis.py`'s `FACETS`
list, which includes `hasRole`. But `hasRole` sits inside the `hiot:InScopeDeviceType`
equivalence axiom (criterion 4(b), `homeiot.ttl` — the `owl:unionOf` branch), unlike every
descriptive sub-facet, all of which are deliberately outside it. `facet_analysis.py` only
*reads* it, which is safe; rewriting it is not — an adjudicated value could flip a published
in/out ruling. So `hasRole` is annotated (its κ is interesting: it measures whether
"is this a controller / assistant / feed surface / automation engine" is reliably assignable
at all, which is a statement about criterion 4(b) itself) but **excluded from the Phase 5
writeback**. `ontology_build.py --check`'s 31/31 reasoner gate would catch an accidental
write; that is the backstop, not the control.

---

## Phase A — Measure within-category heterogeneity (GATE on everything below)

*Added 2026-08-07. This supersedes Phase 0 as the first move, and it may retire several facets
before they are ever annotated.*

**The question that prompted it.** Facets are asserted per *category*, but every analysis joins them
onto *CVE rows*. If a category is internally varied, one facet value is not an approximation of that
category — it is a fiction stamped onto every CVE in it. No amount of annotator agreement fixes
this: three annotators can agree perfectly on a value that is wrong for half the rows it lands on.
κ measures reliability; this is validity, and it is upstream.

**Measured by `scripts/facet_sample.py --frame`, and the answer is not reassuring.** Over the 1,738
confirmed-Yes CVEs there are **2,539 distinct devices** under the same guardrails Stage 5 uses
(`part ∈ {o,h}`, `vendor:product` only, `GENERIC_PLATFORM_CPES` denied, `Excluded` rows dropped,
firmware/hardware twins collapsed). `cameras` alone contains **1,690** — and cameras is 51% of the
confirmed population. A single `computeTier` for that category is not a summary.

*(An earlier draft of this section said 4,624 devices and 3,161 for cameras. Those were measured off
`final_resolved.csv` without the guardrails and are inflated ~1.8×. The conclusion is unchanged —
1,690 distinct devices in one category is ample — but the figures above are the correct ones.)*

> **FRAME CONVENTION — quote the right number.** Three device counts circulate in this
> document and they are not interchangeable. State which frame any figure comes from.
>
> | Frame | Total devices | `cameras` | What it is |
> |---|---|---|---|
> | unguarded (retired) | 4,624 | 3,161 | measured off `final_resolved.csv` with no CPE guardrails — **inflated ~1.8×, never cite** |
> | guarded | 2,539 | 1,690 | Stage-5 guardrails applied; the figure that motivates this phase |
> | guarded + unique-to-one-category (**13B**, the drawn frame) | **2,290** | **1,674** | what `product_frame.csv` actually holds and what every sample and subtype pass draws from |
>
> Verified against `data/facets/product_frame.csv` (2,290 rows, 1,674 cameras) on 2026-08-07.

**Why full product-level annotation is not the answer.** 2,539 devices × 19 facets ≈ 48k items per
annotator, ~145k AI judgments — roughly 50× the category-level plan. That is a different project,
not a swap. **Sample instead.**

### Design

- **Frame.** Distinct `vendor:product` pairs over confirmed-Yes CVEs, device-CPE granularity, reusing
  Stage 5's guardrails (`part ∈ {o,h}`, `GENERIC_PLATFORM_CPES` denied) so the frame is held to the
  same bar as every other CPE-derived artifact here.
- **Draw: uniform per category, with each product's CVE count recorded** so both product-weighted
  and CVE-weighted estimates come out of one pass *(decision 9B)*. Product-weighted answers "what is
  a typical camera product like"; CVE-weighted answers "what does the camera CVE population look
  like", and the latter is what the analysis actually needs. **The gap between them is itself a
  result** — a large divergence means the CVE-heavy products are atypical of their category, which
  bears directly on the dominance problem.
- **n ≈ 40 per category**, categories with fewer products taken whole. Sized for the decision being
  made, not for precision: at the worst case (p=0.5) n=40 gives roughly ±15pp, ample to separate a
  90/10 category from a 55/45 one, and deliberately not enough to pin a value — pinning is not what
  this phase is for.
- **Facets: the 12 single-valued ones only.** The 7 multi-valued facets (`topology`, `pairingModel`,
  `alsoDeployedIn`, `hasRole`, `adminModel`, `credentialModel`, `patchResponsibility`) already
  express within-category spread by construction and are not at risk here.
- **Annotator input is the PRODUCT IDENTITY ONLY** — vendor, product name, CPE title. **Never the
  CVE description, CWE, or CVSS vector.** This is the hard constraint of the whole design: if a
  facet is assigned from CVE text, then any facet↔weakness contrast correlates that text with
  itself, which is precisely how `facet_derive.py` failed and why two of its contrasts stand
  retracted. Keeping the annotator away from the description is what makes facet and weakness
  independent, and it is the difference between a citable contrast and a circular one.
- **One annotator on the full sample; all three on a subsample for κ** *(decision 10A)*. The goal is
  a distribution, not a defensible per-item value, and individual errors partially wash out in the
  aggregate — paying 3× for per-item precision that gets averaged away is the wrong trade. The
  subsample still yields a reliability figure, on a smaller base and with a wider CI; say so.

### Output and decision rule

Per *(category, facet)*: the modal value, its proportion, both weightings, and the sample n.
**The proportion is the admission test** — deliberately mirroring the κ promotion rule in Phase 5:

- **modal share ≥ 0.80** → the category-level value is a defensible summary, reportable with the
  share quoted alongside it.
- **0.60 ≤ share < 0.80** → usable for grouping, **not** as a finding.
- **share < 0.60** → the category-level facet is **not usable for that category**. Report the
  distribution instead of a value. This is a result, not a failure.

### What this changes downstream

If most facets clear 0.80, the category-level design is vindicated *with evidence* rather than
hope, and Phase 0's pilot proceeds as written on a much firmer footing. If they do not, then the
facets that fail are retired before anyone spends 2,952 judgments annotating them — which is the
entire reason this phase runs first.

**Tier consequence, stated precisely.** This does **not** reach `hiot:Derived`. The sampling frame
and the aggregation are computed from the snapshot by a re-runnable script, but the per-product
facet values still come from an annotator, not from measurement — so the result is `hiot:Annotated`
with a *measured distribution behind it*, which is stronger than category-level `Annotated` and
still short of `Derived`. Only Route 2 (Shodan/Censys banner grounding) reaches `Derived`.

**Coverage limit to state.** **21.6%** of confirmed-Yes rows (376 of 1,738) carry no device CPE at
all and cannot be product-sampled at any budget. Those keep a category-level facet by necessity, and
their share must be reported next to any facet result. (This is stricter than the 11.5% "no CPE"
figure in `CLAUDE.md`, which counts rows carrying only `part=a` CPEs as covered.)

### Sampling regimes — device count and CVE count are decoupled, and not randomly

The frame exposed a failure mode the design above did not anticipate. NVD routinely lists **one**
vulnerability against a whole product catalogue, so a category's device count can be an artifact of
a couple of CVEs. `airpurifier` has **2** confirmed CVEs whose CPE lists name **178** and **119**
devices; `fridge` (3 CVEs) and `airconditioner` (5) inherit the same two. Drawing 40 devices there
would produce 40 annotation rows describing **two CVEs** — a sample of n=2 in costume, which would
then appear downstream as a confident modal share. **A CVE listing 178 devices is one piece of
evidence, not 178.**

`facet_sample.py` therefore labels every category with a `regime` and — per the discovery miners'
convention, flags triage and never filter — drops none from the report:

| regime | categories | meaning |
|---|---|---|
| `samplable` | 11 | enough CVEs, enough devices, no single CVE dominating |
| `mega-cpe-bound` | 1 (`home-power`) | enough CVEs, but one CVE names ≥50% of the devices |
| `too-few-cves` | 9 | below 20 confirmed CVEs — cannot support a distribution estimate |
| `take-whole` | 1 (`pet`) | too few devices to sample; population is the sample |
| `empty` | 2 (`sleeptracker`, `shades`) | no confirmed-Yes CVEs at all |

**Decision (12A): draw `samplable` categories only.** The other regimes keep their category-level
facet and are reported as **UNMEASURED** — not sampled-and-caveated, because a caveat attached to a
number does not survive being quoted second-hand.

### Cross-category contamination — the frame inherits a device's category from the CVE

A device's category comes from the **CVE**, not from the device. A CVE judged Yes for `hub` that
lists a dozen CPEs puts all twelve into `hub`'s frame, accessories included — which is how
`nanoleaf:lightstrip` reached `hub` and `google:chromecast` reached `smartspeakers`. Measured on the
unfiltered frame, **249 of 2,539 devices (9.8%) sat in more than one category**, concentrated
precisely in the categories being sampled: `robotvacuum` 72.5%, `smartplugs` 53.3%, `hub` 51.4%,
`lighting` 48.1%, against ≤0.9% for `cameras`, `streaming`, `ev-charging`, `smartspeakers`,
`doorlock`.

Since Phase A's output is a *per-category* distribution, contamination at that level would be read
as within-category heterogeneity and could push a facet below the 0.60 threshold for the wrong
reason — making a clean category look mixed.

**Decision (13B): restrict the frame to devices unique to one category.** `--keep-shared` A/Bs the
filter, the same way `cpe_expansion.py --no-part-filter` A/Bs its guardrail. `widest_cve` is
recomputed after the drop, or the regime test would still be judging the pre-filter frame.

**What it cost, stated plainly.** The filter shrinks exactly the categories it cleans, and it
*removes* ambiguous devices rather than resolving them — a device shared between `lighting` and
`hub` may be genuinely both (a smart bulb is a light and a mesh endpoint), not miscategorised. So
the survivors are cleaner but smaller and possibly less representative. Report the per-category drop
rate alongside any result.

- 864 category-device pairs dropped; frame 2,539 → **2,290** devices.
- `robotvacuum` fell from 51 devices to 14 and out of `samplable` into `mega-cpe-bound` — it sits
  exactly on the threshold (widest CVE 7 of 14 devices), so it is a boundary case, not a clear call.
- **`fridge` and `airpurifier` dropped to ZERO devices.** Their entire NVD device footprint was
  shared with other categories — they have no device population of their own in the snapshot at all.
  That is a finding about those categories worth reporting in its own right, not just a sampling
  side effect.
- Sampled categories 11 → **10**; devices 364 → **272**; sheet 4,368 → **3,264** rows.
- CVE coverage barely moved: 91.2% → **89.6%**, because the categories lost were CVE-light.

### Running it

```
python3 scripts/facet_sample.py --frame       # regimes + coverage, no draw
python3 scripts/facet_sample.py --draw        # -> product_frame.csv + product_sample.csv
python3 scripts/facet_sample.py --aggregate   # filled sheet -> facet_distribution.csv
```

The draw is seeded (`--seed`, default 20260807) and reproducible. Current draw: **272 devices,
3,264 annotation rows** (12 facets × 272), against ~145k for full product annotation.
`--keep-shared` reverts the 13B filter for comparison.

`--aggregate` emits per *(category, facet)*: modal value and share under both weightings, a
`weighting_divergence` marker when the two disagree, `n_unsure`, and the `verdict` from the
threshold rule above.

---

## Phase A — RESULTS (first pass, 2026-08-07)

**Status: one annotator complete, κ not yet measured. Nothing here is citable until the
Codex and Gemini subsample runs come back.** The `cameras` finding below is the one that
most needs a second reader, because it is the one that would change a published number.

### The run

Claude annotated the full sample — **3,264 rows, 272 devices × 12 facets, 100% filled** with
value, confidence and reasoning — from a fresh session in `data/facets/annotation-kit/`.
Codex and Gemini hold the 480-row κ subsample and have not run.

Claude is primary rather than Gemini because Gemini is the documented weakest annotator and
over-includes, and there is no Claude API path, so the alternative was resting the entire
distribution estimate on the model the project trusts least. **The cost is disclosed, not
argued away: Claude also authored the prior assignment and the value definitions.** The kit
directory closed the context channel (no `CLAUDE.md`, no memory index); the weights channel
is open and stays open. Claude's column is a re-reading by the same model under a rubric,
not an independent reading of the prior.

### Instrument checks (these passed)

- **0 of 3,264 values outside the allowed list.**
- Confidence split 2,244 High / 1,020 Low — not uniformly confident, which a rubber-stamp
  pass would be.
- **Low-confidence rate tracks the difficulty ordering the plan predicted a priori**:
  `supportLifetime` 68%, `firmwareUpdateModel` 68%, `computeTier` 57% — the vendor-policy
  facets Phase 0 named as the hard cases — against `dataSensitivity` 7% and `placement` 14%.
  The instrument being hardest exactly where the design expected is the best evidence
  available that the annotation is real rather than confabulated.
- `unsure` used sparingly but not never: 12.5% on `computeTier`, 0% on `hasWebAdminUI`.

### Headline: the category-level design mostly holds

Over 120 *(category, facet)* cells, CVE-weighted modal share:

| verdict | cells | share |
|---|---|---|
| `summary-defensible` (≥0.80) | 86 | **71.7%** |
| `grouping-only` (0.60–0.80) | 22 | 18.3% |
| `NOT-USABLE` (<0.60) | 12 | 10.0% |

So a category-level facet value is a defensible summary about **72%** of the time — the
reassuring half of the answer, and now evidence rather than hope. **8 cells** had the
product-weighted and CVE-weighted modal values disagree outright, which is decision 9B
earning its keep.

**Weakest facets** (mean CVE-weighted share, cells defensible):
`cloudDependence` 0.704 (3/10) · `firmwareUpdateModel` 0.759 (5/10) · `hasWebAdminUI`
0.841 (6/10). **Strongest:** `formFactor` 0.958 · `supportLifetime` 0.930 ·
`actuatesPhysical` 0.913.

**Cleanest categories:** `streaming` 0.945, `hub` 0.939, `ev-charging` 0.900.
**Messiest:** `alarms` 0.768, `doorlock` 0.797 — `doorlock`'s `cloudDependence` at 0.389 is
a real three-way split, not a near miss.

### The finding that matters: `cameras` is ~43% recorders

`cameras`/`capturesAV` came back at **0.591** — 17 of 40 sampled devices annotated
`capturesAV=false`. Every one of the 17 is a DVR, NVR or XVR, each with the same
High-confidence rationale: *a recorder has no lens or microphone of its own.* This is not
annotation error. Per the human-review reconciliation record, recorders were **deliberately**
ruled in scope (Frigate NVR = In), so `cameras` legitimately contains two device types and
one `capturesAV` value cannot be true for both.

**This invalidates a published number.** `CLAUDE.md` states `capturesAV=true` is 1,120 rows
of which cameras is 881 (79%) — the figure the entire dominance rule rests on. If only 59%
of camera CVE mass sits on devices that actually capture AV, that becomes roughly 520 from
cameras out of ~760 total, and cameras' share of the positive cell falls from 79% to ~68%.

Note the direction: **this makes the dominance problem worse, not better.** The concern was
that `capturesAV` is a rename of `cameras`. It is not even reliably cameras — it is a facet
asserted true across a category that is two-fifths recorders. `alarms`/`capturesAV` at 0.574
is very likely the same pattern (panels with and without cameras).

**Do not update the dominance figures from this pass alone** — n=40, one contaminated
annotator, no κ. The κ subsample is what licenses the correction.

### Should `cameras` be split? Measured: no

A `recorders` category was costed and rejected. Two blockers:

1. **The search stage cannot separate them.** `cameras` keyword terms already include `nvr`,
   `dvr`, `network video recorder`, so recorders were searched deliberately as part of
   cameras — that part is splittable. But the vendor terms are bare brands (`hikvision`,
   `dahua`, `xiongmaitech`, `cp plus`) that make **both**, so a `recorders` vendor search
   returns the same V set. That breaks Stage 6: capture–recapture needs V and K to be two
   independent captures of *that category's* population, and post-hoc partitioning of one V
   is not that. The split would cost a measurement currently held.
2. **The judgments do not migrate.** The store is keyed `(category, cve_id)`, so a re-slugged
   CVE loses its judgment. A product-token rule re-keys only **20.5%** of the 885 confirmed
   Yes rows — 58.0% carry device CPEs whose product names hold no camera/recorder token
   (`panasonic:bb_hcm511`), and 21.0% carry no device CPE at all.

**Decision: do not split. Run a device-subtype pass on `cameras` instead** — classify its
1,674 distinct devices as camera / recorder / other, one judgment each (~half the annotation
already completed), and compute the affected facets at device level for that category alone.
This fixes the number that is actually wrong while leaving the frozen 24, the searches, the
store, and recall estimation untouched. Revisit splitting only if recorders and cameras
diverge on **scope-relevant** grounds rather than facet grounds, which is a different
argument.

**Caveat on that estimate:** it assumes recorder-vs-camera is reliably judgeable from a
product name. The 17 found here were unambiguous; `panasonic:bb_hcm511` is the hard case and
58% of the set looks like that. **Pilot 100 devices before committing to the full pass.**

### Next — updated 2026-08-08 (see `PLAN_facet_system_fixes.md` for the full fix plan)

1. ~~Build `scripts/facet_agreement.py`~~ **DONE.** κ, bootstrap CIs, PABAK, raw
   agreement, per-facet `unsure` rate, the Phase A validity cross-tab, and a
   `--self-test` validating the statistics against the canonical 14-rater worked
   example (0.2099 vs 0.2101 published).
2. ~~Automate the Gemini column~~ **DONE.** `scripts/facet_gemini.py`, mirroring
   `gemini_classify.py`. One fix worth knowing: keying batch results by asking the model
   to echo the device string lost **193 of 480 rows silently** (39 of 40 on
   `cloudDependence`) because these keys are CPE-derived and full of backslashes and
   parentheses. Now keyed by integer index.
3. **Run Codex on the 480-row subsample — THE ONE REMAINING BLOCKER.** Human-run from
   the kit directory. Nothing here is citable until the panel is complete.
4. ~~Pilot the cameras device-subtype pass~~ **DONE — see below.**

### Phase A — the cameras subtype pilot (2026-08-08)

`scripts/camera_subtype.py`. 100 devices drawn from cameras' 1,674, classified
camera/recorder/other from product identity alone.

| | camera | recorder | other |
|---|---|---|---|
| product-weighted | 56% | **38%** | 6% |
| CVE-weighted | 62% | **34%** | 4% |

**Judgeability 70/100**, which lands in the middle band: *proceed with the full pass, but
report the unjudgeable share as its own class and never impute it.*

**This is independent corroboration, not a repeat.** The pilot shares only **3 of 100**
devices with the 40-device Phase A cameras sample, and lands at 38% against that sample's
42.5%. Two disjoint draws, two passes, same conclusion — `cameras` is roughly a third
recorders.

**The token baseline is the part to trust most, and it is also the warning.** A mechanical
rule (does the product name split to `nvr`/`dvr`/`xvr`/`recorder`?) is annotator-independent
and is deliberately kept **out of the sheet** so the annotator cannot anchor on it. Where it
fires, the annotation agreed **8/8**. But it fires on only **8.1%** of the frame: **91.9%**
of camera devices carry neither a camera-ish nor a recorder-ish token, and those
token-silent devices hold **92.9% of the CVE weight**. (The plan's earlier estimate was 58%
tokenless; the real figure is far worse.) So the full pass rests almost entirely on
product-line knowledge with no external check — which is precisely why a pilot was demanded.

### First agreement numbers — PROVISIONAL, panel incomplete

Claude vs Gemini only; Codex outstanding, so the statistic is **Scott's π** (Fleiss at 2
raters), not κ, and these are a signal rather than the Phase 5 promotion input.

- **`capturesAV` is the least reliable facet measured** — π = 0.065, raw agreement 67%.
  The facet at the centre of the correction fails on reliability as well as validity,
  which is a third independent direction pointing the same way.
- **Cells Phase A called NOT-USABLE draw more annotator disagreement** than usable ones
  (54% vs 67% unanimity). Validity and reliability track together here — but they remain
  separate gates, and a NOT-USABLE cell is not rescued by a good π.
- **Gemini's documented bias does not transfer.** On CVE review it skews Low-confidence;
  on facets it is High-confidence **92.7%** against Claude's 74.5%. The bias profile in
  `CLAUDE.md` is about CVE review and must not be assumed to hold on this unit.

---

## Phase 0 — Pilot first (do not skip)

> **Superseded as the first move by Phase A (2026-08-07).** Run this only on facets that clear
> Phase A's modal-share gate; a facet that fails there is not rescued by high κ. The facet choices
> below also predate Phase A and should be re-picked from its results.

Run the full protocol on **three facets only**, chosen to span the expected difficulty range:

| Facet | Expected | Why it is the right probe |
|---|---|---|
| `dataSensitivity` | high κ | Nearly observable — does it have a camera? |
| `computeTier` | medium κ | Requires product knowledge, but has a right answer |
| `patchResponsibility` | **low κ** | A vendor-policy fact, not a device fact. If anything scores badly it is this |

Pilot cost is **144 decisions per annotator**, not 72: `dataSensitivity` and `computeTier`
are nominal (24 each), but `patchResponsibility` is multi-valued and binarises to 4 × 24 = 96
under this plan's own accounting.

**Decision gate — per facet, never pooled.** Promote/stop on each facet's own κ. Pooling is
wrong here for a reason built into the pilot itself: `patchResponsibility` was chosen
*because* it is expected to score badly, so a pooled figure is dragged toward the gate by a
facet whose low score is the predicted result. dataSensitivity 0.85 / computeTier 0.35 /
patchResponsibility 0.05 pools to ≈0.4 and would stop the project having just demonstrated
one clearly reliable facet — which was the entire hypothesis. **Stop only if no pilot facet
clears 0.40**; that is the outcome meaning "the rubric is underspecified or facets are not
reliably assignable at all", and it is worth more than grinding through the remaining 16.

A low κ is **not** a failure of the plan. It identifies which device characteristics are
genuinely ambiguous, which is publishable: *"annotator agreement was high for observable
facets (κ=0.8) and poor for vendor-policy facets (κ=0.2), so we report only the former."*

---

## Phase 0.5 — Author the 33 missing value definitions (BLOCKING PREREQUISITE)

Phase 1 as first drafted said value definitions are *lifted verbatim* from the `rdfs:comment`
on each facet value, moved and never re-synthesised. **That step is not executable: 33 of the
59 value individuals have no `rdfs:comment` at all.** Annotators would be choosing between
bare CamelCase labels, which guarantees low κ for reasons that have nothing to do with the
devices.

| Facet | Values needing a definition |
|---|---|
| `pairingModel` | all 5 — `AccountLinked`, `BleProvisioned`, `MeshJoin`, `QrPaired`, `WpsPaired` |
| `firmwareUpdateModel` | all 4 — `ManualFlash`, `NoUpdatePath`, `OtaAutomatic`, `OtaUserInitiated` |
| `alsoDeployedIn` | all 4 — `Commercial`, `Industrial`, `Prosumer`, `Residential` |
| `patchResponsibility` | all 4 — `InstallerPatched`, `Unmaintained`, `UserPatched`, `VendorPatched` |
| `formFactor` | `Fixed`, `Portable`, `Worn` |
| `placement` | `Either`, `Indoor`, `Outdoor` |
| `adminModel` | `AppOnlyAdmin`, `CloudPortalAdmin`, `NoAdminInterface` |
| `dataSensitivity` | `AvStreamData`, `NoData` |
| `topology` / `computeTier` / `actuationConsequence` / `credentialModel` / `supportLifetime` | one each — `DirectIP`, `Rtos`, `NoActuation`, `AccountBound`, `DeclaredLifetime` |

The three boolean facets (`actuatesPhysical`, `capturesAV`, `hasWebAdminUI`) have no value
individuals; their true/false conditions come from the property comment, rationale stripped.

**Why this is safe despite being authored by the same author.** All three annotators receive
the *identical* definition set, so a bad definition shifts every annotator the same way — it
is a **validity** risk (are we measuring the right thing?), not a **blindness** risk (does one
annotator know the prior?). The one rule that keeps it that way: **write each definition
without looking at which categories currently hold that value.** Define `Prosumer` from what
prosumer means, not from the 10 categories `alsoDeployedIn` happens to be asserted on.

Definitions land in `homeiot.ttl` as ordinary `rdfs:comment`s (a documentation improvement
worth having regardless of whether annotation proceeds), and Phase 1 then moves them verbatim
as originally intended.

---

## Phase 1 — Rubric and vocabulary sheet

**New: `data/facets/FACET_ANNOTATION_PROMPT.md`**, modelled directly on
`data/difference/CLASSIFICATION_PROMPT.md` (which is the single source of truth all three
CVE reviewers follow). It must carry:

- The task: given a **device category** (label + `scope_note`) and **one facet**, choose from
  a closed value list.
- The **blind-judgment principle**, verbatim in spirit from the existing rubric: judge from
  the category definition and value definitions only; never look for another annotator's
  answer or the ontology's current value.
- **Value definitions** lifted verbatim from the `rdfs:comment` on each facet value in
  `homeiot.ttl` — moved, never re-synthesised, exactly as `scope_note` text is moved rather
  than rewritten (same anti-drift rule). Requires Phase 0.5 to have filled the 33 gaps first.
- **Definitions only, rationale stripped.** Carry what a value *means*; drop the property-level
  commentary about why the facet exists, which RQ it serves, and which categories motivated it.
  `formFactor`'s current comment ("Worn is what excludes wrist wearables from the sleeptracker
  category") is the worst case — it states an answer. This is a mechanical extraction step in
  `make_facet_copies.py`, not a judgement call at annotation time.
- **Exclusivity rules on multi-valued facets.** Some values are logically exclusive with their own
  siblings even though the facet accepts a set — `hiot:NoAdminInterface` is the known case (a device
  either has an admin surface or it has none). Nothing structural stops an annotator marking it
  alongside `AppOnlyAdmin`, and under binarisation the contradiction does not error: it silently
  produces a self-contradicting category and depresses κ on both values at once. The rule is carried
  in the value's own `rdfs:comment` (so it survives the verbatim lift) and must be restated in the
  rubric. Phase 5 should additionally enforce it in `shapes.ttl` before any writeback, so the
  contradiction cannot reach the ontology.
- An explicit **`unsure`** option. Forcing a guess is what manufactures fake agreement; an
  `unsure` rate per facet is itself a reliability signal.
- **How `unsure` enters κ, decided now:** it is scored as **an additional value**, not as a
  missing answer. Fleiss' κ requires a fixed rater count per item; dropping an annotator's
  `unsure` would leave that item with 2 raters and invalidate the statistic. Treating it as a
  value deflates κ, which is the conservative direction and the honest one — an annotator who
  cannot assign a value has not agreed with one who can. The per-facet `unsure` **rate** is
  reported separately so a κ depressed by abstention is distinguishable from one depressed by
  conflict.
- Confidence (High/Low), same as the CVE rubric.

**Reuse the documented annotator biases.** `CLAUDE.md` records that Codex over-excludes and
Gemini over-includes on CVE review. Check whether the same directional bias appears on facets
— if it does, that is a validation of the bias profile; if not, that is worth knowing before
trusting the merge rule.

---

## Phase 2 — Blind copies and annotation

**New: `scripts/make_facet_copies.py`** — mirror `make_review_copies.py`. Emits
`data/facets/annotations/{claude,codex,gemini}.csv`, each containing only:

```
slug, label, scope_note, facet, allowed_values, <Annotator> Value, <Annotator> Confidence, <Annotator> Reasoning
```

Structural blindness, not policy blindness: each file physically lacks the other annotators'
columns and the `author_prior`.

**The annotation kit — the fix for the auto-load leak.** Emit into a self-contained
`data/facets/annotation-kit/` holding the rubric, the value-definition sheet, and the three
CSVs — nothing else. **Run the Claude annotator with that directory as its working
directory, not the repo root.** This drops `CLAUDE.md` (which states the facet results) and
also changes the memory project key, so `facet-dominance-rule` and `facet-provenance-estimated`
do not load either. Both leak channels close together, and the fix is a `cd`, not a policy.
Codex's channel is narrower — `AGENTS.md` carries no facet content — but run it from the kit
too, for symmetry and because that guarantee is not permanent.

- **Gemini** — extend `gemini_classify.py` (or a sibling) to fill its column via API, with
  the value definitions injected the same way `--scope` injects `scope_note` today. Keep one
  model across the whole column; `gemma-4-31b-it` per the existing convention. Gemini is
  structurally immune to the auto-load leak (no repo context), which is a small argument for
  weighting its dissent more here than on CVE review.
- **Claude / Codex** — filled in-session by a person, from the kit directory.

---

## Phase 3 — Merge, flag, and compute agreement

**New: `scripts/merge_facet_annotations.py`** — mirror `merge_judgments.py`.

Adopt the **existing flag rule** unchanged — but note precisely what carries over. The
293/294 (99.7%) validation was measured on **binary** Yes/No CVE judgments; facet values are
3–5-way nominal, so chance agreement is much lower and a Claude+Codex High-High match is
*stronger* evidence per event. The transplant therefore errs in the safe direction, but the
number does not transfer: **do not cite 99.7% as validating the rule on this unit.** State it
as "adopted from a validated binary setting; its error rate on nominal facets is unmeasured."
Phase 4's human adjudication is what would measure it — the pilot alone yields enough
adjudicated nominal rows to report a first figure.

- `Needs Human Review = Yes` when Claude and Codex are both Low confidence, **or** the three
  values are not unanimous.
- A lone Gemini dissent against a Claude+Codex High-High agreement settles as
  `strong-consensus` and stays in the audit pool rather than the queue.
- Gemini's *value* counts toward unanimity; its *confidence* is excluded (it skews Low).

**Statistics — `scripts/facet_agreement.py`:**

- **Fleiss' κ** per nominal facet (3 raters, 24 items).
- **Binarised Fleiss' κ** per multi-valued facet.
- **Raw agreement and prevalence-adjusted κ (PABAK) alongside every binarised κ — required,
  not optional.** Binarised facets hit the kappa paradox hard: `alsoDeployedIn` is asserted on
  only 10 of 24 categories, so its 96 binary decisions run roughly 12 present / 84 absent, and
  κ collapses toward 0 even at ~95% raw agreement. A bare κ there reports prevalence, not
  disagreement. Where a value's positive rate is extreme, **say plainly that κ is
  uninformative for that cell and report raw agreement** rather than dressing up an artefact.
  This is a reporting fix, not a statistical one — see *Limitations*.
- **Bootstrap 95% CI** on every κ. Non-negotiable: 24 items is a small sample and a bare
  point estimate would overstate precision. Report the interval, not just the number. Note
  what the CI means here: the 24 categories are the whole population, not a sample of it, so
  the interval answers "would this agreement generalise to other device categories", which is
  a defensible question but must be stated as the one being answered.
- A **per-facet table** — the interesting output, since the whole hypothesis is that
  reliability varies by facet type. **No pooled κ as a decision statistic** (it mixes nominal
  and binarised units and averages a deliberately-hard facet against easy ones); report a
  pooled figure only as descriptive context, if at all.
- **Cross-tabulate `firmwareUpdateModel` × `patchResponsibility`** on the adjudicated values.
  Writing their definitions side by side (Phase 0.5) exposed a near-deterministic mapping —
  `OtaAutomatic`→`VendorPatched`, `OtaUserInitiated`/`ManualFlash`→`UserPatched` — that comes
  apart only in edge cells, most notably an abandoned product with working OTA (`Unmaintained` +
  `OtaAutomatic`), which is also the most security-relevant cell in the pair. If the cross-tab is
  near-diagonal, the two facets encode one judgment and their κ values are **not** independent
  evidence: report them as one result, not two. If it is not diagonal, both facets have earned
  their place. Either outcome is reportable; the failure mode is reporting two κs as if they were
  two findings. **The same check is owed by any other facet pair that looks collinear** — this is
  the first one caught, not necessarily the only one.
- **Cross-tabulate `hasWebAdminUI` × `adminModel`** (`LocalWebAdmin` present vs the boolean true) —
  the second collinear pair, found by applying the rule above. Here the redundancy is an **asset**,
  because this is the one facet with an external check available: `facet_derive.py` already
  attempted `hasWebAdminUI` from CVE text, failed, and in failing found the hand assignment wrong
  for **7 of 22** categories, all in the same direction. That gives three independent readings of a
  single property — the author's prior, the blind panel, and the derivation's (pattern-fragile)
  evidence. **The comparison to run: does the panel's blind answer land closer to the derivation's
  evidence than the author's prior did?** If it does, that is a direct measurement of what this
  protocol buys, and it is the strongest result available anywhere in this plan — stronger than any
  κ, because it tests annotation against something other than annotation. If it does not, that is
  equally worth reporting and considerably more sobering. Caveat that keeps it honest: the
  derivation is *not* ground truth — it failed for good reason, and its own numbers swing with the
  keyword list. Treat it as a third reading, never as the answer.
- **Agreement with `author_prior`**, reported separately and explicitly excluded from κ.
- Per-facet `unsure` rate, reported next to that facet's κ so abstention-driven and
  conflict-driven low scores are distinguishable.

---

## Phase 4 — Human adjudication

Route flagged rows to two human reviewers via the existing pattern: `finalize_judgments.py`
upserts raw verdicts into the store and `extract_human_review.py` regenerates the queue as
**outstanding-only**, so a settled row leaves the queue. Order matters — finalize before
extract.

- **New: `data/facets/facet_store.csv`**, keyed `(slug, facet)` — the durable home for facet
  answers, exactly as `judgment_store.csv` is for judgments. Human verdicts are **sticky**.
- Adjudicate all flagged rows, **plus a spot-check sample of unanimous rows** — mirroring the
  high-confidence audit pool, since unanimity among three correlated models is precisely the
  case most likely to be confidently wrong.

---

## Phase 5 — Write back to the ontology

1. Add a fourth evidence tier: `hiot:Annotated` — *"assigned by multiple independent
   annotators under a shared rubric, with measured agreement and human adjudication of
   disagreements."* Sits between `Estimated` and `Derived`.
2. Add `hiot:agreementKappa` (xsd:decimal) and `hiot:annotatorCount` per facet property, so
   the reliability travels with the facet and a reader can see it in the ontology itself.
3. **Promotion rule, decided in advance to avoid post-hoc rationalising:**
   - κ ≥ 0.60 (substantial) → `hiot:Annotated`, citable with κ reported alongside.
   - 0.40 ≤ κ < 0.60 → `hiot:Annotated`, usable for grouping, **not** as a finding.
   - κ < 0.40 → stays `hiot:Estimated`, or the facet is dropped. Report which and why.
   - Applied **per facet**, on that facet's own κ — never on a pooled figure (see Phase 0).
4. Replace asserted values with the adjudicated consensus — **for the 18 `evidenceTier`
   properties only. `hasRole` is annotated but never written back** (see *Scale*): it is
   inside the `hiot:InScopeDeviceType` equivalence axiom, so a rewrite could move a published
   in/out ruling. Its κ is reported; its values are not touched.
5. Re-run **all four gates**: `--check`, `--self-test`, `--sources`, `--verify-kg`.
   `categories.csv` and `families.csv` must stay byte-identical — the 18 descriptive facets
   touch neither (`categories.csv` is `slug,label,scope_note`), and if that breaks, something
   is wrong. Note the two gates are guarding different things: the byte-identical CSV check
   catches nothing about facets, while `--check`'s 31/31 reasoner ruling and `--self-test`'s
   per-criterion negative cases are what would catch an accidental `hasRole` write.
6. **Regenerate everything that quotes a facet number.** Changed values invalidate the
   published `facet_analysis.py` figures, including the dominance numbers quoted in
   `CLAUDE.md` (`capturesAV` 1,120 rows / 79% cameras; `actuatesPhysical` 388 rows over 13
   categories, top share 23%) and the two memory files that restate them
   ([[facet-dominance-rule]], [[facet-provenance-estimated]]). Re-run `facet_analysis.py`,
   update the prose, and update the facet-provenance paragraph in `CLAUDE.md` to describe the
   new mixed tier state. Leaving stale numbers in the guide is how the next session cites a
   figure that no longer holds.

---

## Limitations to state in the paper (write these before running, not after)

1. **Three LLMs are not three independent experts.** Shared pretraining means correlated
   error, so κ overstates true reliability. Human adjudication of disagreements *and* a
   sample of agreements is the partial mitigation; it is not a fix.
2. **Claude authored the prior assignment** and is one of the annotators. The annotation kit
   (Phase 2) closes the *context* leak — no `CLAUDE.md`, no memory — but not the *weights*
   leak: it is the same model that produced the prior. Reduced, not eliminated.
3. **24 items per facet is a small sample.** Report bootstrap CIs; expect wide ones.
4. **κ is uninformative for sparse binarised facets, and no adjustment fixes that.** Reporting
   PABAK and raw agreement alongside (Phase 3) stops a prevalence artefact from being read as
   disagreement, but with 24 categories and a value present on 10 of them, the underlying
   problem is n and prevalence — both properties of having 24 categories, not of this design.
   For the sparsest cells the honest output is raw agreement plus "κ not meaningful here".
5. **The value definitions are authored by the same author as the prior** (Phase 0.5, 33 of
   59). Giving all annotators the identical set makes this a validity risk rather than a
   blindness risk — a bad definition moves every annotator the same way — but it means the
   panel can agree because they were pointed at the same reading, and κ cannot detect that.
6. **Facets remain category-level, not device-level** — and Phase A is what turns this from a
   caveat into a measured quantity. High κ would mean annotators agree on how to characterise a
   *category*; it says nothing about any individual device, and with **1,674** distinct products
   inside `cameras` alone (frame convention below) the gap is not small. State the modal share next to any category-level facet
   value, and never present one whose share Phase A put below 0.60. The cameras-dominance confound
   ([[facet-dominance-rule]], `facet_analysis.py`) compounds this rather than being separate from
   it: the categories with the most products are also the ones carrying the most CVEs, so
   heterogeneity is worst exactly where it costs most.
7. **Agreement is not correctness.** Three annotators can agree and be wrong together —
   which is exactly why `patchResponsibility` and `supportLifetime` deserve suspicion even if
   they score well.

---

## What this does and does not buy

**Does:** facets become reportable as annotated data with measured reliability; per-facet κ
becomes a finding about which device characteristics are objectively assignable; the failed
derivation plus the agreement study together make a genuinely strong methods section.

**Does not:** make facets *measurements*. A high κ means annotators agree, not that the world
agrees with them. `hasWebAdminUI` would still be a characterisation — just a reliable one.
Only Route 2 (Shodan/Censys banner grounding, `CLAUDE.md` § Future dimension) reaches
`hiot:Derived`, and that stays the longer-term goal.
