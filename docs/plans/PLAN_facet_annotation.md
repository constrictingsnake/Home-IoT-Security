# Plan — Multi-Annotator Facet Assignment with Measured Agreement

*Status: **planned**, not started. Supersedes nothing; it is the route out of the
`hiot:Estimated` dead end recorded in `CLAUDE.md` § Facet provenance.*

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
3. **Residual contamination must be disclosed anyway.** Even a fresh session is the same
   model that produced the prior. State it in the paper; do not claim it away.

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
says present/absent, and κ is computed over those binary decisions.

---

## Phase 0 — Pilot first (do not skip)

Run the full protocol on **three facets only**, chosen to span the expected difficulty range:

| Facet | Expected | Why it is the right probe |
|---|---|---|
| `dataSensitivity` | high κ | Nearly observable — does it have a camera? |
| `computeTier` | medium κ | Requires product knowledge, but has a right answer |
| `patchResponsibility` | **low κ** | A vendor-policy fact, not a device fact. If anything scores badly it is this |

Pilot cost is ~72 nominal items per annotator. **Decision gate:** if pooled κ across the
pilot is below ~0.40 (fair), stop and reconsider — either the rubric is underspecified or
these facets are genuinely not reliably assignable, and that finding is worth more than
grinding through the remaining 16.

A low κ is **not** a failure of the plan. It identifies which device characteristics are
genuinely ambiguous, which is publishable: *"annotator agreement was high for observable
facets (κ=0.8) and poor for vendor-policy facets (κ=0.2), so we report only the former."*

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
  than rewritten (same anti-drift rule).
- An explicit **`unsure`** option. Forcing a guess is what manufactures fake agreement; an
  `unsure` rate per facet is itself a reliability signal.
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

- **Gemini** — extend `gemini_classify.py` (or a sibling) to fill its column via API, with
  the value definitions injected the same way `--scope` injects `scope_note` today. Keep one
  model across the whole column; `gemma-4-31b-it` per the existing convention.
- **Claude / Codex** — filled in-session by a person, as today.

---

## Phase 3 — Merge, flag, and compute agreement

**New: `scripts/merge_facet_annotations.py`** — mirror `merge_judgments.py`.

Adopt the **existing flag rule** unchanged, because it has been validated against a fully
worked human queue (humans sided with the Claude/Codex High-High consensus on 293/294 rows):

- `Needs Human Review = Yes` when Claude and Codex are both Low confidence, **or** the three
  values are not unanimous.
- A lone Gemini dissent against a Claude+Codex High-High agreement settles as
  `strong-consensus` and stays in the audit pool rather than the queue.
- Gemini's *value* counts toward unanimity; its *confidence* is excluded (it skews Low).

**Statistics — `scripts/facet_agreement.py`:**

- **Fleiss' κ** per nominal facet (3 raters, 24 items).
- **Binarised Fleiss' κ** per multi-valued facet.
- **Bootstrap 95% CI** on every κ. Non-negotiable: 24 items is a small sample and a bare
  point estimate would overstate precision. Report the interval, not just the number.
- Pooled κ across facets, and a per-facet table — the per-facet table is the interesting
  output, since the whole hypothesis is that reliability varies by facet type.
- **Agreement with `author_prior`**, reported separately and explicitly excluded from κ.
- Per-facet `unsure` rate.

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
4. Replace asserted values with the adjudicated consensus. Re-run **all four gates**:
   `--check`, `--self-test`, `--sources`, `--verify-kg`. `categories.csv` and `families.csv`
   must stay byte-identical — facets do not touch either, and if that breaks, something is
   wrong.

---

## Limitations to state in the paper (write these before running, not after)

1. **Three LLMs are not three independent experts.** Shared pretraining means correlated
   error, so κ overstates true reliability. Human adjudication of disagreements *and* a
   sample of agreements is the partial mitigation; it is not a fix.
2. **Claude authored the prior assignment** and is one of the annotators. Blind re-annotation
   in a fresh session reduces but does not eliminate this.
3. **24 items per facet is a small sample.** Report bootstrap CIs; expect wide ones.
4. **Facets remain category-level, not device-level.** High κ would mean annotators agree on
   how to characterise a *category*; it says nothing about any individual device. The
   cameras-dominance confound ([[facet-dominance-rule]], `facet_analysis.py`) is untouched by
   this plan.
5. **Agreement is not correctness.** Three annotators can agree and be wrong together —
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
