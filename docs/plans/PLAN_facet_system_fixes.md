# Plan — Fix the Facet/Ontology System End-to-End

*Status: proposed 2026-08-07. Written from a full audit of `PLAN_ontology.md`,
`PLAN_facet_annotation.md`, the annotation kit, `facet_distribution.csv`, the four
ontology gates, and every facet script. All issue claims below were verified against the
repo, not read off the plans.*

**Goal:** take the facet system from "one annotator's uncitable pass + half-built
tooling + stale docs" to a working, enforced tagging pipeline: κ measured, Phase A
verdicts wired into the analysis scripts so an unusable facet cell physically cannot be
reported as a fact, the cameras dominance number corrected, and the plan docs telling
the truth about the current state.

---

## STATUS — 2026-08-10

| Phase | State |
|---|---|
| **F1** docs truth pass | **DONE** — `6619d86` |
| **F3** verdict enforcement | **DONE** — `6619d86` |
| **F2** κ loop | **PANEL COMPLETE** — Codex column landed `a51603f` (2026-08-10); 3-rater Fleiss' κ runs on 471 shared items. Closeout items remain (see the phase) |
| **F4** cameras subtype | **PILOT DONE** — `b4727de`, 70% judgeable → proceed with caveat. Full pass not started |
| **F5** category study + writeback | **REDESIGNED 2026-08-10** — human-sourced category tagging replaces the second AI panel (see the rewritten phase). Machinery BUILT; sheet widened to all 18 facets 2026-08-11 (432 cells, 420 asked); human pass not started |
| **F6** shades / KG vectors / push | **shades RESOLVED** (no NVD footprint, marker set, gates green); **branch pushed**; KG vectors still optional |

The Codex run is in. **The one remaining human step is now F5's sourced category pass** —
432 cells, pre-filled with the panel consensus so the human verifies with sources rather
than starting cold. **Widened 2026-08-11 from 288 to 432**: the 6 multi-valued facets are
asked in the same pass (step 6 below), so the vocabulary is settled once rather than in two
passes with a second sheet to build later.

### The panel verdict (3 raters, 471 shared items) — the result F2 existed to produce

| band | facets |
|---|---|
| **CITABLE** (κ ≥ 0.60) | `actuationConsequence` 0.755 · `actuatesPhysical` 0.737 · `consumerAvailability` 0.720 · `placement` 0.701 |
| **grouping-only** (0.40–0.60) | `dataSensitivity` 0.595 · `formFactor` 0.489 *(n=35 — four Gemini blanks sit exactly here; fill before quoting)* · `cloudDependence` 0.445 |
| **FAILS** (< 0.40) | `firmwareUpdateModel` 0.388 · `capturesAV` 0.386 · `computeTier` 0.384 · `hasWebAdminUI` 0.349 · `supportLifetime` **−0.311** |

**Adding Codex lowered agreement on 7 of 12 facets** — `formFactor` 1.000 → 0.489,
`actuatesPhysical` 0.950 → 0.737, `dataSensitivity` 0.796 → 0.595 (out of citable). That
is the panel working, not breaking: the 2-rater π was Claude-vs-Gemini, and Claude
authored both the prior assignment and the value definitions both were annotating
against, so the 2-rater figures were flattered. Quote the 3-rater κ everywhere; the π
values in this doc's history (0.358 / 0.131 / 0.283) are superseded.

**Joint salvage picture** (κ band × Phase A validity, CVE-weighted over the 1,733
confirmed-Yes rows; the 10 measured categories hold 89.6% of that population):
`actuatesPhysical` and `actuationConsequence` are defensible in 8/10 cells carrying
**85.6%** of CVE mass — the two facets that survive both gates outright.
`consumerAvailability` and `placement` are reliable but their `cameras` cell fails
validity, so their safe mass is only ~34–37% (cameras is 50.8% of the set) — note the
inversion: excluding cameras makes them the *least* cameras-confounded facets available.
The five κ-failed facets have 0% citable mass regardless of validity.

**What the work so far already established:**
1. Enforcement is live — `capturesAV=true` falls from 1,124 rows to 239 once the
   NOT-USABLE cameras cell is withheld, and `--ignore-phase-a` reproduces the old number.
2. The cameras-recorders finding survived an independent replication (38% vs 42.5% on
   samples sharing 3 of 100 devices) and an annotator-independent token check (8/8 where
   the product name carries a token).
3. `capturesAV` **fails reliability as well as validity** — κ = 0.386 on the full
   3-rater panel, below the 0.40 bar, on top of the NOT-USABLE validity verdicts for
   `cameras` (0.591) and `alarms` (0.574). The facet at the centre of the cameras
   correction is both invalid and unreliable.
4. **Two independent methods agree on which facets are unassignable.** `hasWebAdminUI`
   (0.349) and `computeTier` (0.384) sit at the bottom of the κ table (with
   `supportLifetime`, below), and they are precisely the two `facet_derive.py` already
   failed to derive from CVE text. Text derivation and independent annotation share no
   mechanism, so the agreement is much stronger evidence than either result alone — and
   it points the same way as the retraction already recorded in `CLAUDE.md`.
5. **`supportLifetime` is below chance** — κ = −0.311, 12% raw agreement, 28.3%
   `unsure`. That is not a hard facet, it is a broken instrument: annotators are reading
   the value definitions differently, or answering a question the input cannot support
   (vendor support policy, judged from a product name). A definition fix or a documentary
   source is the only route back; more annotation is not.

---

## Audit — every issue found, with evidence

### A. The tagging pipeline is half-built (blocking)

| # | Issue | Evidence |
|---|---|---|
| A1 | **κ subsample not run.** `codex.csv` and `gemini.csv` (480 rows each) are 0% filled. By the plan's own rule, *nothing* in Phase A is citable — including the cameras-recorders finding. | `data/facets/annotation-kit/` inspected: Value columns empty in both |
| A2 | **No Gemini automation path for facets.** `gemini_classify.py` has no facet mode; Phase 2 of the annotation plan requires extending it. Without this, the Gemini column can only be filled by hand. | `grep -i facet scripts/gemini_classify.py` → nothing |
| A3 | **`facet_agreement.py` does not exist.** κ, PABAK, bootstrap CIs, the collinearity cross-tabs, the author-prior comparison — none of the Phase 3 statistics can be computed. Named as "Next" item 2 in the results section and never started. | not in `scripts/` |
| A4 | **No merge/flag/store stage for facet annotations.** `merge_facet_annotations.py` and `data/facets/facet_store.csv` (Phase 3/4 of the annotation plan) don't exist, so there is no durable home for adjudicated facet answers and no human queue. *(2026-08-10: the F5 redesign resolves this with the store alone — the AI merge script is no longer needed; see F5 step 5.)* | not in `scripts/` or `data/facets/` |
| A5 | **Phase A verdicts are enforced by nothing.** `facet_analysis.py` has no awareness of `facet_distribution.csv`. 12 cells are `NOT-USABLE` (incl. `cameras/capturesAV` 0.591, `alarms/capturesAV` 0.574, `doorlock/cloudDependence` 0.389) yet every analysis run still stamps the single category-level value onto every CVE row in those cells. The plan's rule — "never present a value whose share is < 0.60" — is policy, not code. | `grep distribution scripts/facet_analysis.py` → nothing |
| A6 | **Cameras subtype pass decided, not started.** The agreed fix for the 43%-recorders finding (classify cameras' devices as camera/recorder/other, pilot 100 first) has no script and no sheet. Until it runs, the published `capturesAV` dominance figure (79% cameras) is known-suspect and uncorrected. | no artifact anywhere under `data/facets/` |
| A7 | **The ontology cannot carry annotation results yet.** No `hiot:Annotated` tier, no `hiot:agreementKappa` / `hiot:annotatorCount`. Expected (Phase 5 hasn't run) — but the writeback machinery doesn't exist either, so when κ lands there is nowhere for it to go. | `grep Annotated ontology/homeiot.ttl` → nothing |
| A8 | **`shapes.ttl` lacks the `NoAdminInterface` exclusivity constraint** the annotation plan requires before any writeback (a device marked `NoAdminInterface` + `AppOnlyAdmin` would silently self-contradict). | `grep NoAdminInterface ontology/shapes.ttl` → nothing |

### B. Docs and published numbers contradict the measured state

| # | Issue | Evidence |
|---|---|---|
| B1 | **`PLAN_facet_annotation.md` contradicts itself on the cameras device count.** Limitation 6 (line ~656) still cites **3,161** distinct camera products — the exact figure lines 119–121 retract as "inflated ~1.8×". The doc also uses 1,690 (full frame) and 1,674 (subtype-pass section) without saying which frame each refers to. | grep confirms all three figures present |
| B2 | **`CLAUDE.md` still teaches the suspect dominance number with no flag.** The dominance-rule section quotes `capturesAV` = 1,120 rows / 79% cameras as the worked example. Phase A measured that assertion `NOT-USABLE` for cameras (0.591) and alarms (0.574). The plan correctly says don't *update* until κ — but flagging ≠ updating, and an unflagged number is what the next session cites. Same exposure in the memory files `facet-dominance-rule` and `facet-provenance-estimated`. | CLAUDE.md § dominance rule vs `facet_distribution.csv` |
| B3 | **`PLAN_ontology.md`'s STATUS section is stale.** Says 27/27 reasoner rulings, "3 excluded", and lists gates `--reason` / `--align`. Actual: **31/31**, **7 excluded** classes (5 boundary cases added), gates are `--check` / `--self-test` / `--sources` / `--verify-kg`. | `ontology_build.py --check` output vs doc |
| B4 | **`PLAN_ontology.md` Phase 4 misstates why the KG has no CVSS vectors.** It says `download_nvd.py` discards `vectorString` — superseded by the 2026-08-05 snapshot cutover, which captured `vector_string` at 100% coverage (it's what unblocked RQ3). The KG *could* now carry AV/PR/UI/S; the doc claims it can't. | CLAUDE.md § Snapshot vintage |
| B5 | **`PLAN_scope_exclusion.md` is still unreachable.** Referenced by 8 tracked files (`categories.csv`, `homeiot.ttl`, 5 scripts, `RESULTS.md`), exists only on unmerged branches. Verified present on `docs/tvos-scope-exclusion`. | `git show docs/tvos-scope-exclusion:docs/plans/PLAN_scope_exclusion.md` works |
| B6 | **`shades` is still open.** The class carries `hiot:openScopeCall` "not finally confirmed", no `noNvdFootprint`, and the deciding test (re-run the 9 keyword terms against the snapshot, count hits) was killed twice and never finished. Evidence leans (a) genuinely-absent, but it is recorded as unconfirmed. | `homeiot.ttl` shades block |

### C. Design ambiguities the plans leave unresolved

| # | Issue |
|---|---|
| C1 | **The Phase 0 gate is per-facet but the Phase A verdict is per-cell.** "Run the pilot only on facets that clear Phase A" — `firmwareUpdateModel` is defensible in 5/10 measured cells. Does it clear? No rule exists. |
| C2 | **Two annotation units, no reconciliation.** Phase A's κ subsample is *product*-level; the original Phase 0–5 study is *category*-level. The plan never says whether category-level annotation still happens after Phase A, or what the κ from 480 product rows licenses at category level. `make_facet_copies.py` only emits product sheets — the category-mode sheets Phase 2 describes can't currently be generated. |

---

## The fix plan

Ordered so that (1) nothing wrong gets cited while the real fixes are in flight,
(2) the citability blocker (κ) is the critical path, (3) enforcement lands before any
new numbers do. Phases F1 and F6 are independent of the rest and can run any time.

### Phase F1 — Documentation truth pass *(small; do first)*

1. **`PLAN_facet_annotation.md`:** fix Limitation 6 — replace 3,161 with the corrected
   figures, and state the frame convention once: **1,690** = cameras devices in the full
   guarded frame, **1,674** = after the 13B unique-to-one-category filter (verify the
   1,674 by recomputing from `product_frame.csv` before writing it; if it doesn't
   reproduce, that's a third error to fix).
2. **`PLAN_ontology.md`:** update the STATUS block to 31/31 rulings, 7 excluded classes,
   and the real four-gate list; rewrite the Phase 4 CVSS sentence to "vectors are now
   captured in the snapshot (2026-08-05); KG vector enrichment is possible and
   deliberately deferred" (or schedule it — see F6).
3. **Cherry-pick `docs/plans/PLAN_scope_exclusion.md`** from `docs/tvos-scope-exclusion`
   (file only, not the branch) so the 8 references resolve.
4. **Flag, don't update, the dominance number.** In `CLAUDE.md`'s dominance-rule
   paragraph add one sentence: *"Phase A measured `capturesAV` NOT-USABLE for cameras
   (modal share 0.591 — ~43% of sampled camera devices are recorders) and alarms
   (0.574); the 79% figure is under correction pending κ (PLAN_facet_annotation Phase A)
   — do not cite it unqualified."* Mirror the same one-line flag in the two memory
   files. The *replacement* numbers land in F4, not here.

**Gate:** grep for `3,161`, `27/27`, `27 rulings` returns nothing; all
`PLAN_scope_exclusion.md` references resolve to a real file.

### Phase F2 — Close the κ loop *(critical path — everything citable waits on this)*

1. **New `scripts/facet_gemini.py`** (sibling of `gemini_classify.py`, same API/env/rate
   conventions, same model `gemma-4-31b-it` for the whole column): fills
   `annotation-kit/gemini.csv` from product identity + the kit's `VALUE_DEFINITIONS.md`
   injected per facet. Never shown CVE text — same hard constraint as the sheet itself.
2. **Run Codex on `codex.csv`** — human-run from the kit directory per the kit README
   (working directory = kit, so no `AGENTS.md`/repo context).
3. **New `scripts/facet_agreement.py`**, computing over the 480 shared rows:
   - Fleiss' κ per facet (3 raters × 40 devices), `unsure` scored as a value.
   - Raw agreement + PABAK alongside every κ; where prevalence is extreme, print "κ not
     meaningful for this cell" rather than the number.
   - Bootstrap 95% CI on every κ.
   - **Author-prior agreement, excluded from κ** — with the unit mismatch stated: the
     prior is category-level, so it is broadcast onto each product row; agreement with
     it measures "does the blind product-level read match the category-level prior",
     which is Phase A's validity question restated, and worth reporting as such.
   - The two collinearity cross-tabs (`firmwareUpdateModel` × `patchResponsibility`,
     `hasWebAdminUI` × `adminModel`) and the three-way `hasWebAdminUI` comparison
     against `facet_derive.py`'s evidence (`data/ontology/facet_evidence.csv`) — the
     strongest available result if the panel lands closer to the evidence than the
     prior did.
   - Per-facet `unsure` rate next to each κ.
4. **Re-run `facet_sample.py --aggregate`** unchanged — the distribution comes from the
   full Claude sheet; κ is what licenses quoting it.

**Gate:** a per-facet κ table with CIs exists in `data/facets/`; per-facet
citable/not-citable calls are recorded at the bottom of `PLAN_facet_annotation.md`'s
results section.

**Closeout — 2026-08-10.** Steps 1–2 are done (`facet_gemini.py` ran; Codex landed in
`a51603f`) and `facet_agreement.py` computes the 3-rater κ. What remains before the gate
is met:

1. **Fill the 9 blank Gemini cells** (`facet_gemini.py` re-run) — 4 of them are
   `formFactor`, whose κ is currently on n=35.
2. **Regenerate `data/facets/facet_agreement.csv`** — the checked-in file is the
   2-rater vintage (2026-08-08) and still reports π, including `formFactor` at 1.000.
3. **Add the two never-built statistics to `facet_agreement.py`:** the author-prior
   agreement (excluded from κ, unit mismatch stated) and the three-way `hasWebAdminUI`
   comparison against `data/ontology/facet_evidence.csv` — the strongest available
   result if the panel lands closer to the derivation evidence than the prior did.
4. **Record the per-facet citable calls** at the bottom of `PLAN_facet_annotation.md`
   (the gate condition itself).
5. **The two collinearity cross-tabs CANNOT run on this panel** — `patchResponsibility`
   and `adminModel` are not in the kit (the product sheet carries only the 12
   single-valued facets). They move to F5, computed on the adjudicated category values.

### Phase F3 — Enforce Phase A verdicts in code *(small; before any new analysis runs)*

The rule "report the distribution instead of a value for a NOT-USABLE cell" becomes
mechanical, not remembered:

1. **`facet_analysis.py` reads `facet_distribution.csv`** and joins the verdict onto
   every (category, facet) it reports: each output row gains `modal_share` and
   `phase_a_verdict` columns. For a `NOT-USABLE` cell the script prints the sampled
   distribution in place of the single value; `--ignore-phase-a` reproduces the old
   behaviour (the A/B convention every guardrail here already follows). Cells Phase A
   never measured (`too-few-cves` etc.) are labelled `UNMEASURED` — per decision 12A,
   not silently treated as defensible.
2. **`ontology_build.py --check` gains one visibility line**, same pattern as the
   existing provenance line: `facet heterogeneity (Phase A): 86 defensible /
   22 grouping-only / 12 NOT-USABLE / rest unmeasured`. No TTL write — the CSV stays
   the machine-readable source, and the hand-authored file is never reserialized.

*Why not write verdicts into `homeiot.ttl`?* 120 measured annotations hand-copied into
a hand-authored file is exactly the drift the byte-identical-CSV design exists to
prevent. The CSV-as-source + `--check` visibility matches how provenance is already
surfaced. (Open to revisiting at F5 writeback time, when `hiot:Annotated` lands anyway.)

**Gate:** running `facet_analysis.py` on current data visibly refuses to print a single
value for the 12 NOT-USABLE cells; `--check` still green.

### Phase F4 — Cameras subtype pass *(fixes the number that is actually wrong)*

1. **Pilot 100 devices** (seeded draw from cameras' 1,674 unique-frame devices):
   classify camera / recorder / other from **product identity only** (same hard
   constraint — never CVE text). The pilot's question is *judgeability*: what share can
   be called confidently from the name alone (`panasonic:bb_hcm511` is the hard case
   and ~58% of the set looks like it).
   - **Decision rule:** ≥80% confidently judgeable → proceed to the full pass;
     50–80% → full pass but report the unjudgeable share as its own class, never
     imputed; <50% → stop, the subtype pass doesn't work from names, and the finding
     stays at "capturesAV is not usable for cameras" with the distribution reported.
2. **Full pass** (if cleared): all 1,674 devices, one judgment each; reuse the kit
   mechanics (sheet emitted by `make_facet_copies.py` with a `--subtype cameras` mode,
   blind, kit directory).
3. **Recompute the dominance table at device level for cameras** (and only cameras) —
   `capturesAV`, `dataSensitivity` — then, κ permitting (F2), replace the 79% figure in
   `CLAUDE.md` and both memory files with the corrected one. This supersedes F1's flag.
   **Amended 2026-08-10 — κ did not permit.** `capturesAV` failed reliability (0.386)
   as well as validity, so recomputing the figure would imply the facet measures
   something once recorders are separated out, and the κ says it does not.
   **Recommendation: retire the 79% worked example rather than correct it** — replace
   it in the dominance-rule prose with `actuatesPhysical` (0.737, 8/10 cells, 23% top
   share), which survives both gates. The subtype pass itself still runs: the
   camera/recorder split is a real finding about the category and feeds
   `dataSensitivity` at device level. Decision open — settle it before touching
   `CLAUDE.md`.
4. **`alarms` gets the hypothesis, not a pass, for now:** record in the results section
   that `alarms/capturesAV` 0.574 is very likely the same panels-with/without-cameras
   pattern; run its own subtype pass only if alarms numbers are actually needed in the
   paper.

**Gate:** pilot judgeability number recorded before the full pass starts; no dominance
figure changes anywhere until both F2's κ and the full pass are done.

### Phase F5 — Human-sourced category tagging + writeback (REDESIGNED 2026-08-10), gated on F2+F3

**Supersedes the original "category-level annotation study" (a second 3-AI panel of 984
items each, merged and human-adjudicated).** Three reasons, all measured:

- **The reliability statistic already exists.** The product panel (F2) is the κ report;
  a second AI panel would re-measure reliability the project already has, at the cost of
  another human-run Codex sitting twice the size of the one just completed.
- **The failed facets fail for want of evidence, not effort.** `supportLifetime` is
  below chance with 28% abstention; `hasWebAdminUI` and `computeTier` failed blind
  annotation *and* text derivation — two mechanism-free-of-each-other methods. More
  blind annotation cannot fix a question the input does not answer. **Only a source
  can**, and sourcing is also the only route to an evidence tier above `Annotated`.
- **Human truth is already the top of the hierarchy everywhere else.** `Final Source =
  human` is sticky and supersedes all AI judgments in `judgment_store.csv`. Extending
  that to facets is consistency, not a new rule.

**Two boundaries, stated up front because they bound what this phase can deliver:**

- **Human+source rescues reliability failures, never validity failures.** A cell Phase A
  marked NOT-USABLE stays excluded from writeback *regardless of who tagged it or what
  source they cite* (decision C1, unchanged). `cameras/capturesAV` is not wrong because
  nobody checked a source — the category holds two device types and the slot holds one
  value. A human with perfect sources is still wrong on ~40% of the rows the value lands
  on. Those cells keep the distribution, or wait on F4.
- **A source is almost always per-product; the assertion is per-category.** A spec sheet
  documents the Tapo P100, not "smartplugs". The generalization step is still the
  human's, and the recorded tier must say so — which is why `Human-sourced` is a
  distinct tier below `Documented`, not a synonym for it.

The steps:

1. **Sourcing probe first — a gate on the whole phase.** ~20 cells across the κ-failed
   facets: minutes per cell, and the hit rate. If `supportLifetime` sources exist for 3
   of 24 categories' vendor bases, the facet gets dropped anyway — better to know after
   twenty minutes than after a full pass. Candidate source classes: vendor
   support/security pages and declared support periods (UK PSTI / EU CRA declarations —
   verify the regulatory detail before citing), Matter/certification requirements,
   product manuals, Shodan/Censys banners for `hasWebAdminUI` (`CLAUDE.md` § Future
   dimension; exposure-biased, say so).
   **The probe is the top of the sheet** — `make_tagging_sheet.py --probe 20` prints it,
   and it is exactly rows 1–20 of `category_tags.csv` because the sort puts κ-failed
   facets on high-CVE categories first. Record minutes-per-cell and hit rate here before
   continuing past row 20.
2. **`data/facets/facet_store.csv`** keyed `(slug, facet)` — sticky human verdicts,
   `finalize`/`extract` pattern reused — **plus `Sources` and `Evidence Tier` columns.**
   **BUILT** — `scripts/facet_store.py` (`--finalize` / `--extract` / `--status` /
   `--writeback`).
3. **The human sheet** — 24 categories × all 18 facets = **432 cells**, of which **420
   asked** and 12 emitted as `excluded-validity`. **BUILT** —
   `scripts/make_tagging_sheet.py` → `data/facets/tagging-kit/`. (Was 288/276 while the
   6 multi-valued facets were deferred; widened 2026-08-11, see step 6.)
4. **Priority order, so partial completion still pays:** the 5 κ-failed facets first
   (only sourcing saves them), then the 6 multi-valued, then the 3 grouping-only, then
   spot-check the 4 CITABLE. Implemented as the sheet's sort order (κ band, then category
   CVE count), so the schedule is the file rather than a rule someone has to remember. For
   `supportLifetime`, try a definition fix alongside the sourcing — below-chance κ plus
   28% abstention reads as annotators parsing the values differently.
   **Why multi sits at rank 2 of 4:** those facets have no κ and no Phase A verdict at
   all, so their need is *presumed* where the κ-failed cells' is *demonstrated* — they do
   not displace them. But nothing else will ever move them off `Estimated`, so they
   outrank the bands that already carry a measured number. Rank 0 is untouched, which is
   why the documented sourcing probe is still exactly the same 20 cells.
5. **No second AI panel, no `merge_facet_annotations.py`.** Two human columns on one
   sheet, the existing human-review convention: agreement on a non-`unsure` verdict
   settles; disagreement is discussed and reconciled (as the H1≠H2 scope rulings were).
   The AI merge/flag machinery has nothing to merge here.
6. **The 6 multi-valued facets are in the sheet — DONE 2026-08-11.** Previously deferred
   because the answer *shape* differs, not the list: a cell holds a set. Deferring them
   meant a third of the vocabulary could never leave `Estimated` and blocked both step-8
   cross-tabs, each of which pairs a sheet facet with a left-out one. Built as:
   `facet_sample.load_multi_facet_spec()` (a second loader path; `load_facet_spec()` is
   left single-valued-only so the frozen κ kit and its agreement figures cannot move), a
   `cardinality` column on the sheet and queue, `|`-separated verdicts, and
   `facet_store.canonical()` normalising order/case/spacing so **agreement is set
   equality**. A superset in one column is a disagreement, deliberately — it is a
   different claim about the category, not a more detailed version of the same one.
   `unsure` and `none` are whole-cell answers and never mix with values.
   - Required six new `hiot:annotatorGloss` assertions in `homeiot.ttl`: the kit
     generator hard-fails without one and refuses to fall back on `rdfs:comment`, which
     on these six states the expected answer outright (`patchResponsibility`: user-
     initiated patching is "in practice, frequently no patch") — exactly the anchor a
     reviewer must not be handed.
   - **`shapes.ttl`: `NoAdminInterface` exclusivity constraint** (A8) is still outstanding
     and should land *before* writeback, so the contradiction cannot reach the ontology.
     Now unblocked: `adminModel` is in the pass, so the constraint has settled values to
     police.
   - `facet_analysis.py` needed no change — it already collects each facet into a set and
     already lists all six in `FACETS`.
7. **Writeback — a REPORT, applied by hand.** Facet values live in hand-authored
   `homeiot.ttl`, and `ontology_build.py --write` deliberately only ever emits CSVs so
   rdflib cannot reserialize it. `facet_store.py --writeback` therefore emits
   `data/facets/facet_writeback_report.md` — every value change with its tier and
   source, plus the proposed per-property tier — and a person applies it, the same
   propose/commit split the discovery miners use. The **per-cell tier and source live
   in the store, never hand-copied into the TTL** (the anti-drift convention).
   **`hasRole` never written.** All four gates re-run afterwards, `categories.csv` and
   `families.csv` byte-identical, then regenerate `facet_analysis.py` output and update
   `CLAUDE.md` + memory files.
8. **The two collinearity cross-tabs** (`firmwareUpdateModel` × `patchResponsibility`,
   `hasWebAdminUI` × `adminModel`) run on the human-settled category values from this
   pass — they could not run on the product panel (F2 closeout item 5). Both were blocked
   on step 6 and are now unblocked: each pairs a single-valued sheet facet with a
   multi-valued one, which is why deferring the multi half stalled them entirely.

**Tier vocabulary — decided 2026-08-10, `hiot:Annotated` is dropped.** It was defined as
"multiple independent annotators under a shared rubric, with measured agreement and human
adjudication", and the category-level AI panel that would have earned it no longer runs —
so nothing at category level could ever hold it. Replaced by two tiers, now in
`homeiot.ttl`:

| tier | when | citable? |
|---|---|---|
| `hiot:Documented` | source covers the whole category (regulation, certification requirement) | yes, with source |
| `hiot:HumanSourced` | human verdict + per-product citations — **most cells** | yes, with the generalisation limit stated |
| `hiot:HumanJudged` | human verdict, source looked for and not found | no — treat as `Estimated` |

The tier is **derived from what the reviewer did**, not self-reported: source blank →
`HumanJudged`; source present → `HumanSourced`; source present and marked `category-wide`
→ `Documented`. So "I could not find a source" is recorded rather than papered over, and
the `HumanJudged` share becomes a reportable result about the facet.

**Per-cell tiers vs the per-property `hiot:evidenceTier`** — resolved by a **floor rule**:
a property carries the tier of its *weakest* cell, so one unevidenced category cannot hide
behind evidenced ones. Unsettled cells keep the hand value and count as `Estimated`.
`facet_store.py --status` and the writeback report both print it.

**Decision (C2), restated for the redesign:** product-level κ (F2) is the reliability
report and validates the Phase A distributions; the human-sourced category pass is what
licenses writeback, because the ontology's assertions are category-level and human
verdicts are the project's override tier. The paper states that the two measure
different things — and that the human pass is verification-with-sources of a disclosed
AI consensus, not an independent blind annotation.

**Gate:** probe numbers recorded before the sheet is built; all four ontology gates
green after writeback; `--check` prints the per-cell tier mix
(`Documented`/`Human-sourced`/`Human-judged`/`Estimated`); no stale facet number
survives in `CLAUDE.md` or memory.

### Phase F6 — Independent housekeeping *(any time)*

1. **Settle `shades` (B6).** Run `build_search.py --overwrite` for `shades` in the
   background (the previous attempts were killed for slowness — background it and let
   it finish) and read the row count. Zero hits → set `hiot:noNvdFootprint true` with
   the evidence `rdfs:comment` SHACL requires, clear `openScopeCall`, mirror the
   `sleeptracker` precedent. Nonzero → it's a recall gap: route through the normal
   review chain, and the ontology marker stays off.
2. **KG CVSS vectors (B4 follow-on, optional):** now that `vector_string` is 100%,
   `--export-kg` could attach AV/PR/UI/S to `Vulnerability` instances. Cheap, useful
   for RQ3-adjacent SPARQL, zero risk to the byte-identical invariant (instance file
   only). Do it or explicitly defer it in `PLAN_ontology.md` — just stop misstating
   why it's absent.
3. **Push the branch** — 11 commits ahead of `origin/ontology`, including the entire
   Phase A record. One machine failure loses it.

---

## Sequencing summary

```
F1 (docs truth)            ── DONE
F3 (verdict enforcement)   ── DONE
F2 closeout (gemini blanks → regenerate CSV → prior/three-way stats → record calls)
F5 (sourcing probe → store + sheet → human pass → writeback)  ← now the critical path
F4 (cameras full subtype pass) ── parallel to F5; settle retire-vs-recompute first
F6 (KG vectors) ── independent, any time
```

## What "done" looks like

- Every number in `CLAUDE.md`, the memory files, and both plan docs is either measured
  and current, or explicitly flagged as pending — nothing silently stale.
- A facet value cannot reach an analysis table without its Phase A verdict and modal
  share attached, enforced in code.
- The 3-rater κ table with CIs is the recorded reliability report; every category-level
  facet assertion carries a per-cell tier in the store
  (`Documented`/`Human-sourced`/`Human-judged`/`Estimated`), with sources cited where
  they exist; the cameras dominance example is retired or corrected per the F4
  decision; the ontology carries `hiot:Annotated` with per-property reliability; all
  four gates green.
