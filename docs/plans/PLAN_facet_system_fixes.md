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

## STATUS — 2026-08-08

| Phase | State |
|---|---|
| **F1** docs truth pass | **DONE** — `6619d86` |
| **F3** verdict enforcement | **DONE** — `6619d86` |
| **F2** κ loop | **BLOCKED ON CODEX.** Tooling done (`1ce16fb`); Gemini column filling; `facet_agreement.py` runs on a partial panel and already reports provisional Scott's π |
| **F4** cameras subtype | **PILOT DONE** — `b4727de`, 70% judgeable → proceed with caveat. Full pass not started |
| **F5** category study + writeback | not started (gated on F2) |
| **F6** shades / KG vectors / push | not started |

**The one human step in the whole plan is running Codex on
`data/facets/annotation-kit/codex.csv`** (480 rows), from the kit directory so the repo's
`CLAUDE.md` and memory index stay out of context. Everything downstream of "is this facet
citable" waits on it, and nothing else does.

**What the work so far already established** (all three independent of Codex):
1. Enforcement is live — `capturesAV=true` falls from 1,124 rows to 239 once the
   NOT-USABLE cameras cell is withheld, and `--ignore-phase-a` reproduces the old number.
2. The cameras-recorders finding survived an independent replication (38% vs 42.5% on
   samples sharing 3 of 100 devices) and an annotator-independent token check (8/8 where
   the product name carries a token).
3. `capturesAV` is also the *least reliable* facet on the provisional panel (π=0.065),
   so the facet at the centre of the correction fails validity and reliability both.

---

## Audit — every issue found, with evidence

### A. The tagging pipeline is half-built (blocking)

| # | Issue | Evidence |
|---|---|---|
| A1 | **κ subsample not run.** `codex.csv` and `gemini.csv` (480 rows each) are 0% filled. By the plan's own rule, *nothing* in Phase A is citable — including the cameras-recorders finding. | `data/facets/annotation-kit/` inspected: Value columns empty in both |
| A2 | **No Gemini automation path for facets.** `gemini_classify.py` has no facet mode; Phase 2 of the annotation plan requires extending it. Without this, the Gemini column can only be filled by hand. | `grep -i facet scripts/gemini_classify.py` → nothing |
| A3 | **`facet_agreement.py` does not exist.** κ, PABAK, bootstrap CIs, the collinearity cross-tabs, the author-prior comparison — none of the Phase 3 statistics can be computed. Named as "Next" item 2 in the results section and never started. | not in `scripts/` |
| A4 | **No merge/flag/store stage for facet annotations.** `merge_facet_annotations.py` and `data/facets/facet_store.csv` (Phase 3/4 of the annotation plan) don't exist, so there is no durable home for adjudicated facet answers and no human queue. | not in `scripts/` or `data/facets/` |
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
4. **`alarms` gets the hypothesis, not a pass, for now:** record in the results section
   that `alarms/capturesAV` 0.574 is very likely the same panels-with/without-cameras
   pattern; run its own subtype pass only if alarms numbers are actually needed in the
   paper.

**Gate:** pilot judgeability number recorded before the full pass starts; no dominance
figure changes anywhere until both F2's κ and the full pass are done.

### Phase F5 — Category-level annotation study (original Phases 0–5), gated on F2+F3

Resolves C1 and C2 explicitly, then builds the remaining machinery.

1. **Decision (C1) — the gate is per-cell, the study is per-facet.** A facet enters the
   κ study if it has ≥1 defensible or grouping-only cell (all 12 currently qualify);
   but a cell Phase A marked NOT-USABLE is **excluded from writeback regardless of κ**
   — high agreement on a fiction is still a fiction (the plan's own validity/reliability
   distinction, applied). UNMEASURED-regime categories keep `Estimated` values.
2. **Decision (C2) — both units, explicit roles.** Product-level κ (F2) validates the
   Phase A distributions. The category-level study is still what licenses writeback,
   because the ontology's assertions are category-level: three annotators on the 24
   categories per the original plan, restricted per decision 1. State in the paper that
   the two measure different things.
3. **`make_facet_copies.py --unit category`** — emit the category-level sheets the
   original Phase 2 describes (`slug, label, scope_note, facet, allowed_values, …`),
   same kit, same blindness structure. Product mode stays as-is.
4. **New `scripts/merge_facet_annotations.py`** (mirror `merge_judgments.py`): existing
   flag rule transplanted (Claude+Codex both Low, or non-unanimous → human queue; lone
   Gemini dissent vs High-High → `strong-consensus`), with the caveat already written
   in the plan — do not cite 99.7% as validating it on this unit.
5. **New `data/facets/facet_store.csv`** keyed `(slug, facet)`, sticky human verdicts,
   `finalize`/`extract` pattern reused.
6. **`shapes.ttl`: `NoAdminInterface` exclusivity constraint** (A8) — landed *before*
   writeback so the contradiction cannot reach the ontology.
7. **Writeback (original Phase 5, unchanged):** `hiot:Annotated` tier,
   `hiot:agreementKappa` + `hiot:annotatorCount` per property, promotion per facet on
   its own κ (≥0.60 citable / 0.40–0.60 grouping / <0.40 stays Estimated or dropped),
   **`hasRole` annotated but never written**, all four gates re-run, `categories.csv`
   and `families.csv` byte-identical, then regenerate `facet_analysis.py` output and
   update `CLAUDE.md` + memory files.

**Gate:** all four ontology gates green after writeback; `--check`'s provenance line
shows the mixed tier state; no stale facet number survives in `CLAUDE.md` or memory.

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
F1 (docs truth)            ── independent, do immediately
F2 (κ: gemini script → codex run → agreement stats)   ← critical path
F3 (verdict enforcement)   ── after F2 starts, before any new analysis is quoted
F4 (cameras subtype)       ── pilot after F2 kicks off; full pass + number correction after κ
F5 (category study + writeback) ── after F2+F3; largest block
F6 (shades / KG vectors / push) ── independent, any time
```

## What "done" looks like

- Every number in `CLAUDE.md`, the memory files, and both plan docs is either measured
  and current, or explicitly flagged as pending — nothing silently stale.
- A facet value cannot reach an analysis table without its Phase A verdict and modal
  share attached, enforced in code.
- κ, PABAK, and CIs exist for every annotated facet; the cameras dominance figure is
  corrected at device level; the ontology carries `hiot:Annotated` with per-property
  reliability; all four gates green.
