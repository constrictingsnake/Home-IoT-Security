# §III Our Methodology — annotated map
*State: CURRENT (restructured 2026-09-14 around the collection framework diagram; figures
recomputed 2026-09-09 and unchanged since) · tex lines 136–921 · a ten-stage framework
walkthrough + eight subsections*

## How this section fits

This is the section that has to earn the rest of the paper. RQ1 and RQ2 report distributions over
a corpus of 1,738 category assignments; neither is interesting unless the reader already accepts
(a) that those assignments are *home IoT*, (b) that the false positives a text search inevitably
drags in were removed rather than counted, and (c) that what the terms never reached is bounded
rather than ignored. §III owes exactly those three things, in that order, and everything else in
it is scaffolding for them.

Two structural traps to keep in view. First, §II already argues the *scope literature* — the
consumer/industrial boundary, the hub-in/router-out precedent, the per-category study grounding —
so §III should assert the criteria and point at §II for provenance rather than re-argue them. It
currently does this with four citations doing double duty (`balta2013`, `alrawi2019`,
`kumar2019`, `fernandes2016`); a reviewer who reads §II first will not want them re-explained.
Second, §V (Threats) is where every *measured weakness* of this methodology lives — facet κ,
alignment gaps, residual reviewer error, recall's upper-bound status. The division that keeps them
from duplicating each other: §III states the design and the check that was run, §V states what the
check returned and what it costs the claims. Where §III now reports a number that reads like a
finding (intersection precision, CPE-expansion precision, per-category FP rates), it is there
because it *characterises the pipeline*, not the devices — that is the line to hold if the section
is trimmed.

**The section is now built around the framework diagram, in three parts.** The diagram is a
diagram of *collection*, and that is the whole reason the shape works: it governs the middle and
is honestly absent from the two ends.

| part | subsections | what it is |
|---|---|---|
| **prior** | Topics 1–2 (scope, ontology) | what counts as a home IoT device — inherited by every stage, itself no stage |
| **pipeline** | Topics 3–6 (stages 1–4 · 5–8 · 9 · 10) | the diagram, in running order, stage range in each title |
| **measurement** | Topics 7–8 (extraction, CWE-888 mapping) | what a confirmed CVE contributes — feeds stage 11 |

The previous order (scope → ontology → collection → extraction → CWE-888 → review → term
refinement) ran definition first and measurement last, which is defensible on its own terms, but
the restructure fixed **three real ordering inversions**, not just navigation:

1. **Term discovery sat among the searches** though all three mining passes read *settled
   judgments* as their evidence — it was printed upstream of the data it consumes. Now Topic 5,
   stage 9, beside its pruning counterpart.
2. **The review totals and the tvOS exclusion closed the collection subsection**, before the
   review that produces them had been described. Now the close of Topic 4.
3. **Extraction preceded the review** on the argument that it defines what a CVE row *is* — but
   its own opening sentence counts "the 1,676 confirmed CVEs in the analysis set", a
   post-review, post-exclusion denominator, and the review subsection never referenced it back.
   Now Topic 7, after the pipeline.

What the old order got right and the new one keeps: the CWE-888 mapping still follows extraction,
and scope still precedes everything. What it costs: two subsections gained stage-range titles that
must be renumbered if the diagram is ever renumbered.

---

## Topic 0 · The framework stage by stage — the numbered walkthrough
*tex 186–284 · added 2026-09-14 · the organizing spine of Topics 3–6 · keyed to the hand-drawn
collection-framework diagram*

**Beats:** **ten** collection stages in the order a CVE meets them, plus the analysis that
consumes them numbered eleventh · Topics 3–6 are organized around this numbering and **carry their
stage range in their titles** · the two subsections on either side are deliberately outside it —
the *prior* (Topics 1–2) and the *measurement* (Topics 7–8) · **1** keyword term list
(208 device-type phrases, no brands/protocols/firmware) · **2** vendor term list (1,564
category–term pairs / 1,540 distinct brands, bare-brand overlap qualified with a product word) ·
**3** one fixed snapshot + **one** matching engine (373,518 records @ 2026-08-05; description +
CPE; whole-word) → a gap between methods is attributable to *terms*, not freshness · **4**
reconciliation into three disjoint parts partitioning V∪K (vendor-only · keyword-only ·
intersection), intersection reviewed rather than trusted · **5** blind AI review — (5.1) Claude ·
(5.2) Codex · (5.3) Gemini — blindness structural, own copy + own empty columns · **6** merge and
flag · **7** judgment store keyed (category, CVE), the re-runnability mechanism · **8** human
review queue, two blind adjudicators, settles only on an agreeing non-Maybe pair, verdicts return
to the store · **9** term refinement back onto stages 1–2, in two opposite directions — (9.1)
per-term precision *prunes* on measured evidence · (9.2) keyword mining + (9.3) CPE mining
*discover*, and every candidate is hand-vetted · **10** recall estimation (capture–recapture, no
new labelling) · **11** CVE analysis (CWE, CWE-888, CVSS) · **two non-stages**: the CPE-expansion
feedback arrow (store → snapshot → re-enters review at stage 5 as a fourth direction) and the
**category list** upstream of everything (generated from the ontology; frozen while terms stay
open)

**How it connects:** this is a map, not an argument, and it must never acquire findings. Since the
2026-09-14 restructure it is also load-bearing in a way it was not when first written: Topics 3–6
are *ordered by it* and cite their stage ranges in their titles, so the list is no longer a
convenience the reader can skip — it is the key to the section's shape. Two consequences follow.
**The numbering is now structural**: renumbering the diagram renumbers four subsection titles and
every stage-range cross-reference, so the diagram and the prose have to move together or not at
all. And **the list must stay honest about what the diagram is** — a collection diagram. Stage 11
is named but explicitly flagged as downstream of the framework rather than part of it, and the
prose says in as many words that the prior and the measurement are not stages. Drop that sentence
and the list starts implying the methodology *is* the pipeline, which is the overclaim the
three-part shape exists to avoid.
⚠️ Three figures in the list are **duplicated** from Topic 3 (208 · 1,564/1,540 · 373,518). If one
changes, it changes in two places — check before submission.

**Quote — the two non-stages, tex** (`docs/home_iot_security_report.tex:276`):
> It deepens coverage of devices
> already in the corpus and by construction cannot introduce a brand no reviewer
> has approved.

**Quote — why the category list is upstream, tex** (`docs/home_iot_security_report.tex:281`):
> This is why category
> membership is frozen before collection while the term lists stay open, and why
> changing one category forces a re-run of only that category's chain.

**Evidence:** the hand-drawn framework diagram (1–11 + the CPE-expansion arrow + the
"where to mention categories" note) · `scripts/pipeline.py` (`refresh` / `settle` chains, which
are stages 1–8 in code) · stage-to-script map: 1–3 `build_search.py` + `cve_search.py` ·
4 `build_review_sets.py` · 5 `make_review_copies.py` + `gemini_classify.py` ·
6 `merge_judgments.py` · 7 `finalize_judgments.py` · 8 `extract_human_review.py` ·
9.1 `term_precision.py` · 9.2 `keyword_mining.py` · 9.3 `cpe_brand_mining.py` +
`cpe_product_scan.py` · 10 `recall_estimate.py` · 11 `cwe888_analysis.py` + `cvss_analysis.py` ·
CPE expansion `cpe_expansion.py`

**Cite:** none — the list forward-references subsections, and every citation sits in the
subsection it belongs to

**Known divergences from the drawing** (recorded so the diagram and the prose can be reconciled
deliberately rather than silently; the restructure resolved the third, the rest stand):
- **Box 9.3 covers two scripts.** `cpe_brand_mining.py` mines the CPE *vendor* field,
  `cpe_product_scan.py` the CPE *product* field. The paper describes three mining surfaces
  (vendor field · descriptions · product field); the drawing shows two mining boxes. The prose
  names both under 9.3 rather than adding a 9.4, so the numbering still matches the drawing.
- **Box 4 shows three directions; review sees four.** CPE expansion is the fourth, and in the
  drawing it appears only as the dashed arrow. The prose says explicitly that it re-enters at
  stage 5 like the other three.
- ✅ **The scope-exclusion step is not on the diagram — now handled in prose.** `mark_excluded.py`
  is what takes 3,753 confirmed rows to the 1,738-assignment analysis set (the tvOS ruling). It is
  a deliberate human ruling rather than a pipeline step, which is why it is not on the drawing and
  not chained into `refresh`/`settle`. The restructure moved it to the close of Topic 4, where the
  3,753 is produced, so a reader tracing 3,753 → 1,738 now finds it in the right place even though
  the diagram has no box for it. Worth a dashed box if you redraw.
- **Box 8's arrow should be bidirectional.** Human verdicts flow back into the store
  (`finalize_judgments.py` upserts them), which is what lets the queue regenerate as
  outstanding-only. Drawn one-way, the store looks like a dead end for human work.

🔴 **The figure is not in the build.** `docs/figures/pipeline.pdf` does not exist, so the
`\begin{figure}` block at tex 180–186 is **commented out** and the walkthrough currently stands
alone. Export the diagram to that path, uncomment the block, and add the
`Figure~\ref{fig:pipeline}` clause flagged in the comment.

---

## Topic 1 · Scope — five criteria, function and class as the discriminators
*tex 285–343* 

**Beats:** definition = internet-connected sensor/appliance/embedded system · residential ·
monitor/automate/control · consumer-maintained, no IT oversight → five criteria, all required ·
criterion 1 (connectivity) is near-universal → non-discriminating · the load sits on criterion 4
(function) + criterion 2 (class) · criterion 4 is a disjunction: 4(a) direct home control, 4(b)
control *surface* for other devices · study-inclusion criterion (CPE-identifiable + CVE-disclosed)
is operational, **not** definitional · entertainment: streaming/speakers in via 4(b), consoles and
VR/AR out on 2 ∧ 4 · networking: hubs/bridges/Matter-Thread controllers in, pure transport out ·
24 analysis categories · granularity rule = different product name **and** different brand set →
separate category · merges: smart display + soundbar → `smartspeakers`; blinds/curtains/shutters →
`shades` · defined-but-excluded types kept as definitions, not data · `sleeptracker` listed but
~all wearables, pending rebuild · membership frozen before collection; **term lists not frozen**

**How it connects:** every downstream number inherits this subsection's judgment calls, which is
why the operational/definitional split matters more than it looks: a reviewer who conflates them
will read "has a CPE" as part of your definition of home IoT and then object that you have defined
the population by the instrument that measures it. The 4(a)/4(b) disjunction is the single most
contestable move in the paper — it is what admits Apple TV and Alexa hardware — and it is the
reason Topic 2 quantifies the split rather than merely asserting it. The frozen-membership /
open-terms distinction licenses Topic 7: you can prune a term without re-running the study, but you
cannot add a category without re-running that category's chain.

**Quote — the guiding principle, tex** (`docs/home_iot_security_report.tex:311`):
> a device that merely interoperates with home IoT is not
> itself home IoT.

**Quote — the granularity rule as applied, tex** (`docs/home_iot_security_report.tex:332`):
> while cameras, doorbells, and baby monitors stay
> distinct despite their hardware overlap, since their brand sets differ.

**Evidence:** `data/categories.csv` (24 slugs + `scope_note`, generated) · `CLAUDE.md`
§"Definition of a Home IoT Device" and §"Finalized Category Scope" · `data/ontology/families.csv`

**Cite:** `balta2013` · `alrawi2019` · `kumar2019` · `fernandes2016` · `stanford_iot`

---

## Topic 2 · The ontology — the scope criteria as an auditable artifact
*tex 344–442 · new subsection as of this rewrite (was two paragraphs inside Topic 1)*

**Beats:** five criteria → OWL 2 equivalence axiom · reasoner, not prose, decides membership ·
"reproduces 31 rulings" = weak, true by construction 🚫 **never the headline** · strong check =
**deletion test**: delete each conjunct, require the reasoner to object · one negative boundary
case per criterion → `non-networked-detector` (1) · `tablet-control-panel` (2) ·
`commercial-hvac-controller` (3) · `transport-networking` (4) · `monitored-alarm-service` (5) ·
all five load-bearing · admission route recorded, not just verdict → **1,624 via 4(a) / 114 via
4(b) = 6.6%** · 13 folding categories over 24 leaves = the sparse-category reporting tier ·
generates `categories.csv` byte-identically → formal model can't drift from the reviewed artifact ·
**circularity boundary**: classes + scope notes only, never judgments · instance-graph export
(80,072 triples · 1,676 vulns · 1,738 assignments · 4,707 products · 292 vendors · 21 CWE-888
classes · 1,904 attributions) reconciled by gate against `judgment_store.csv` · 2 of 24 categories
and 2 of 13 families are empty classes · descriptive facets ≠ membership facets · **all 496 facet
assertions `Estimated`** · three independent facet gates: validity (272 devices / 10 categories /
120 cells) · reliability (Fleiss κ, 4 of 12 clear 0.60) · sourcing (185 cells, 94 cited / 91
judged, 0 documented, coverage floor) · failing cells withheld **in code**, second withholding
route for reviewer splits · 14 categories stay UNMEASURED, never assumed sound · ~a fifth of
confirmed assignments have no device CPE → unsamplable at any budget · alignment = subclass /
broadMatch only, never `owl:equivalentClass` · **8 searched** (SAREF core + 7 extensions) ·
**12 source documents / 435 IRIs** manifested, each pinned at a version + sha256 · **8 used**
(S4AUTO and S4CITY yielded nothing in scope → a result, not an omission) · literature provenance split: direct study vs methodological-only → 13 of 24
(54%) direct · `streaming` has neither · **14.6% of the analysis set on categories no manifest
study examines directly**

**How it connects:** this subsection is doing three different jobs and a reviewer will read them
at three different levels of interest, so the ordering inside it matters. The deletion test is the
part with actual evidentiary force and it is what §V-A leans on; the KG export is a
reproducibility claim; the facet apparatus exists mainly to *withhold* things, and its payoff is
that no RQ in the paper rests on a facet. Note what the facet paragraph buys you rhetorically: by
stating up front that all 496 assertions are Estimated and that only 4 of 12 facets clear κ, you
convert a soft spot into a demonstration of discipline — but only if no later section quietly uses
a facet as a grouping variable. Check that before submission. The 14.6% literature figure is new to
the paper as of this rewrite and is the literature-side twin of the SAREF granularity finding in
§V-A; if a reviewer accepts one they should accept the other.

**Quote — the weak-test disclaimer, tex** (`docs/home_iot_security_report.tex:352`):
> Reproducing our published in-scope and out-of-scope rulings is a weak test on its own,
> since most of those rulings are in-scope categories confirming that they are in scope,
> which the axiom satisfies by construction.

**Quote — the 4(b) exposure, tex** (`docs/home_iot_security_report.tex:366`):
> 1{,}624 of the 1{,}738 confirmed CVE--category
> assignments enter through 4(a) and only 114 through 4(b), so the boundary that attracts
> the most methodological objection governs 6.6\% of the corpus.

**Quote — the circularity boundary, tex** (`docs/home_iot_security_report.tex:373`):
> It holds classes and scope notes only, never judgments: no
> CVE is classified by the ontology, and no reviewer sees information the prose scope note
> did not already contain.

**Quote — facet provenance, tex** (`docs/home_iot_security_report.tex:393`):
> all
> 496 facet assertions in the published ontology are marked \texttt{Estimated}, meaning
> hand-assigned from domain knowledge with no external source

**Evidence:** `ontology/homeiot.ttl` · `ontology/shapes.ttl` · `ontology/homeiot-align.ttl` ·
`ontology/homeiot-sources.ttl` · `ontology/external_classes.tsv` (435 IRIs) ·
`ontology/study_sources.tsv` (10/10 `verified=yes`) · gates:
`ontology_build.py --check` → `facet provenance: 496 of 496 unevidenced`, `reasoner: 31/31`;
`--self-test` → all 5 criteria load-bearing; `--sources` → 13 direct / 10 methodological /
`streaming` none, 14.6% by CVE weight; `--verify-kg` → PASS, every count reconciles ·
`data/facets/facet_distribution.csv` (120 cells: 86 defensible / 22 grouping-only / 12 not usable) ·
`data/facets/facet_agreement.csv` · `data/facets/facet_store.csv` (185 settled: 94 HumanSourced /
91 HumanJudged) · `data/facets/source_coverage.csv`

**Cite:** none currently in this subsection — 🔴 see *Before you write* items 1 and 2 (SAREF/S4BLDG
standards and Fleiss have no `\bibitem`; OWL 2 / SHACL are uncited)

---

## Topic 3 · Collection — two text searches, one engine, one snapshot *(stages 1--4)*
*tex 443–581 · six labelled paragraphs · restructured 2026-09-14: term mining moved to Topic 5,
review totals + the tvOS exclusion moved to Topic 4, recall split out as Topic 6*

**Beats:** snapshot = NVD 2.0 API, 2026-08-05, **373,518** records, offline · freezing buys
reproducibility **and** removes data-lag as a confound between methods · collection is a
point-in-time picture, not a date range · **comparability**: the live-API/description-only
asymmetry was the original confound and is gone · **snapshot vintage**: pinned ≠ frozen;
refreshed once (360,981 @ 2026-06-25 → 373,518 @ 2026-08-05), both searches re-run, cost
**111 genuinely new review rows of 5,122** · **vendor search (stage 2)** = brands per category,
ecosystem enumeration (Google Nest/Home, Apple Home, Alexa, hub platforms) + targeted
per-category search + vetted mined terms · bare-brand overlap → qualify with a product word
(`carrier infinity`, not `carrier`) · match against description **+ CPE** · whole-word, trailing
plural allowed → blocks `nvr`→`nvram`, `evse`→`prevsell` · CPE punctuation acts as a boundary ·
space in a multi-word term also matches `_` → `hunter douglas` reaches `hunter_douglas:…` ·
matched-term attribution recorded per row → feeds Topic 5 · **1,564 category–term pairs / 1,540
distinct brands** · **keyword search (stage 1)** = device-type phrases only, no
brands/protocols/firmware · **208 phrases** · same engine, same snapshot, same match surface →
only the *terms* differ · **reconciliation (stage 4)** = three disjoint parts partitioning V∪K ·
intersection was originally assumed clean and skipped → audit killed that → **70.2% intersection
precision** overall, `cameras` 67.0%, `smartspeakers` 15.8% · **CPE expansion** = the feedback
loop, fourth review direction, seeds only from settled Yes, `vendor:product` not vendor,
`part ∈ {o,h}`, general-purpose platforms denied · 2,068 candidates → 1,960 confirmed →
**1,897 are tvOS**, so post-exclusion precision is **36.8% (63/171)**; `alarms` 38/38 vs
`cameras` 15/67

**How it connects:** this is the subsection a methods reviewer will actually attack, and the
defence is that every asymmetry between the two methods has been eliminated by construction —
same engine, same snapshot, same match surface, same output schema — so the difference sets mean
what you say they mean. Two of the beats above are load-bearing for claims elsewhere and should
not be cut: the underscore concession (without it every multi-word brand was silently
description-only, which is a *bug-shaped* methodological fact and worth keeping) and the
intersection audit (it is the reason the review population is 8,124 rather than ~7,400, and it
pre-empts the obvious "why review rows both methods agreed on?" question). The third — the tvOS
decomposition of CPE-expansion precision — stays here with the expansion paragraph, but the
exclusion *itself* now lives in Topic 4, where the numbers it operates on are produced; the two
must stay numerically consistent. Note what the restructure bought: this subsection no longer
describes anything that depends on a settled judgment, so it can be read straight through without
forward-referencing the review.

**Quote — the matcher concession, tex** (`docs/home_iot_security_report.tex:479`):
> One matching
> concession is specific to CPE: a space in a multi-word term also matches an
> underscore, so that \texttt{hunter douglas} reaches
> \texttt{hunter\_douglas:\ldots}. Without it a multi-word term could only ever match
> the description half of the haystack, which had silently suppressed the CPE
> contribution of every multi-word brand.

**Quote — what method agreement is worth, tex** (`docs/home_iot_security_report.tex:520`):
> Method agreement, in other words,
> measures that two term lists overlap, not that the device is in scope.

**Quote — expansion precision after the exclusion, tex** (`docs/home_iot_security_report.tex:548`):
> The step returned 2{,}068 candidates, of which
> reviewers confirmed 1{,}960 --- but 1{,}897 of those confirmations are Apple TV
> expansions later removed by the tvOS exclusion, so on the 171 candidates that reach the
> analysis set precision is 36.8\% (63 of 171).

**Evidence:** `data/nvd-snapshot/SNAPSHOT.md` (date, source, record count) ·
`data/vendor-search/vendor_terms.csv` (1,564 pairs / 1,540 distinct) ·
`data/keyword-search/keyword_terms.csv` (208) ·
`scripts/cve_search.py::filter_by_keywords` (whole-word + plural + space↔underscore rule) ·
`scripts/build_search.py` · `scripts/build_review_sets.py` · `scripts/cpe_expansion.py` ·
`data/difference/judgment_store.csv` (direction counts, per-direction precision) ·
`data/nvd-snapshot/snapshot_churn.md`

**Cite:** `ref-nvd`

---

## Topic 4 · False-positive classification — three blind AI reviewers, two human adjudicators *(stages 5--8)*
*tex 582–733 · the longest subsection, and the one that carries (b) of the section's three debts ·
absorbed the review totals + the tvOS scope exclusion in the 2026-09-14 restructure*

**Beats:** text search → brand strings that name unrelated products, marketing copy that mentions
a category · every candidate row judged independently and **blind** · 3 AI reviewers judge *every*
row; 2 humans blind-adjudicate only flagged rows · reviewers = Claude (Claude Code, 2026-06-01 →
07-02) · ChatGPT Codex (06-15 → 06-30) · `gemma-4-31b-it` via Gemini API (06-16 → 07-01) · one
pass per row, no self-consistency sampling, one model fixed per column · ⚠️ collection dates
recorded instead of build identifiers → stated reproducibility limitation, not resolved ·
blindness enforced **structurally**: each reviewer gets its own copy with only raw fields + its own
empty columns · one shared rubric + one shared per-category `scope_note` → agreement means
agreement *under one scope* · judged only from `description` + `cpe_strings` · fields per row:
Judgment (Yes/No/Maybe) · Confidence (High/Low) · Reasoning (required for Low and Maybe) · Maybe
always pairs with Low · Low reserved for: plausibly-residential-but-commercial · description says
category, CPE says enterprise · shared software/protocol layer · **missing CPE ≠ Maybe** (NVD
enrichment lag on 2024–2026) · rubric fixes two recurring calls: companion app + vendor cloud API
count as the device · one app-layer CVE spanning several product lines is accepted for each named
line · human-review flag = both strong reviewers Low **or** the three not unanimous · relaxation:
lone Gemini dissent does not flag when Claude+Codex agree definitely at High → settles as
`strong-consensus`, stays in the audit pool with the dissent recorded · relaxation validated at
**293/294 (99.7%)**; at any confidence it drops to 95.5% → hence High-High required · Gemini =
weaker third vote: judgment counts toward unanimity, confidence excluded from the flag · human
stage mirrors the AI stage: settles only on two agreeing non-Maybe verdicts; one verdict, a
conflict, or a Maybe stays outstanding → no final label rests on a lone human reading · human
verdicts **sticky** across flag-rule changes and queue regenerations · at analysis time: nothing
outstanding, no surviving Maybe · persistent store keyed (category, CVE) → regeneration re-reviews
only genuinely new rows · aggregate: **3,753 (46.2%) Yes / 4,371 (53.8%) No** → majority of
candidate rows are noise · FP rate tracks how distinctive a category's language and brands are ·
set aside as scope-driven: `shades` 5/5 · `sleeptracker` 29/29 · highest: airconditioner 96.2% ·
thermostat 80.0% · babymonitor 78.0% · cameras 77.6% (n=3,950) · lowest: home-power 13.5% ·
garden 29.6% · hub 30.0% · camera/baby-monitor rates trace to an over-broad vendor list → a
term-pruning action, not a reviewer problem · `smartspeakers` 62.0% is not what its name suggests:
one term (`smart display`) accounts for 48 rejections · `streaming` 14.3% (n=2,440) must be read
with the tvOS exclusion — review kept those rows, the *scope decision* removed them · pairwise
agreement **87.0 / 86.3 / 85.2**, unanimity **80.3%** · final labels **6,467 ai-consensus / 1,638
human / 19 strong-consensus**, none outstanding · **totals now close this subsection** (moved here
2026-09-14): **8,124** candidate pairs (4,241 vendor-only · 1,049 keyword-only · 766 intersection ·
2,068 expansion) → 3,753 Yes / 4,371 No · per-direction precision **22.9% / 18.5% / 70.2%** →
the two one-sided differences carry the FP load · **tvOS exclusion** applied *after* review, not
before: removes **2,015** confirmed rows, all `streaming` → analysis set **1,738 assignments /
1,676 CVEs** · exclusions recorded as exclusions, judgments never reversed

**How it connects:** the blindness-by-construction argument is what distinguishes this from
"we asked three models and took a vote", and it is the sentence to lead with if the subsection ever
has to be cut for space. The 99.7% validation is doing double duty: here it justifies the
relaxation, and in §V-B it becomes the *residual error rate* estimate for rows that never reached a
human — so if you re-word it here, §V-B moves with it. Two per-category rates need their caveat
attached wherever they travel: `sleeptracker` at 100% is a scope artefact (wearables), not term
noise, and `streaming` at 14.3% would otherwise read as your cleanest category when in fact almost
all of it was later excluded. `smartspeakers` at 62.0% is the best single illustration in the paper
of why Topic 5 exists — one term, 48 rejections, one prune action.

The totals and the tvOS exclusion moved here from Topic 3 in the restructure, and the reason is
worth keeping: those numbers are *produced* by this subsection. Stated at the end of collection
they forced a forward reference to a review that had not been described yet, and the exclusion —
which is a scope ruling applied to settled judgments — read as though it happened before anyone
judged anything. The sentence that has to survive any edit is that the exclusion is applied after
review rather than before it, because that is what keeps the review outcome and the scope decision
separable in the published data.

**Quote — structural blindness, tex** (`docs/home_iot_security_report.tex:606`):
> We enforce
> blindness structurally. Each reviewer works on its own copy of the data, containing only
> the raw fields plus its own empty judgment columns, so no reviewer can see another's
> answer.

**Quote — the relaxation and its validation, tex** (`docs/home_iot_security_report.tex:652`):
> We
> validated this relaxation against a fully worked human queue, on which the human
> reviewers sided with the Claude--Codex pair on 293 of 294 such rows (99.7\%); that
> agreement drops to 95.5\% when the pair agree at any confidence, which is why we require
> High confidence on both.

**Quote — the aggregate, tex** (`docs/home_iot_security_report.tex:674`):
> Across all 8{,}124 reviewed (category, CVE) rows, 3{,}753 (46.2\%) settled as true
> matches and 4{,}371 (53.8\%) as false positives.

**Evidence:** `data/difference/CLASSIFICATION_PROMPT.md` (the shared rubric — Yes/No/Maybe,
confidence policy, missing-CPE rule, companion-app rule at lines 68–77) · `data/categories.csv`
(`scope_note`) · `data/difference/judgment_store.csv` (recomputed this session: totals, 46.2/53.8,
per-category FP rates, agreement 87.0/86.3/85.2, unanimity 80.3%, labels 6,467/1,638/19) ·
`scripts/make_review_copies.py` · `scripts/gemini_classify.py` · `scripts/merge_judgments.py`
(flag rule) · `scripts/finalize_judgments.py` (stickiness) · `scripts/extract_human_review.py`
(outstanding-only queue) · `scripts/mark_excluded.py` (the tvOS ruling — flags `Excluded` without
touching any judgment cell) · `docs/plans/PLAN_scope_exclusion.md`

**Cite:** `alrawi2019` (for the app–device–cloud coupling behind the companion-app rule)

---

## Topic 5 · Closing the loop — pruning and discovery, the two halves *(stage 9)*
*tex 734–804 · absorbed automated term discovery from Topic 3 in the 2026-09-14 restructure*

**Beats:** matched-term attribution recorded at collection is what makes this possible · join each
settled judgment back to the term(s) that pulled the CVE in · per-term precision = confirmed-true
share of a term's judged difference-set matches · prune candidate iff precision ≤ **0.10** over
≥ **5** judged rows · computed per (term, category, method), since one string can be registered for
several categories or on both lists · **426 combinations / 398 distinct strings** with ≥1 judged
match → **20 flagged over 19 distinct terms** · most are vendor terms naming professional or
enterprise lines (`synology surveillance station`, `geutebruck`, `digital watchdog` under cameras
— 0.0 over 7–25 rows) · plus broad consumer brands dominating a category's FPs (`d-link` under
cameras, 0.044 over 1,802 rows) · **5 are keyword terms**, not brands (`smart display`, `home hub`,
`evse`, `charge point`, `weather station`) · `smart display` sits on **both** lists → flagged twice,
which is why 20 combinations span 19 terms · symmetry matters: the loop prunes either method's
terms, and the keyword list is not immune to over-breadth just because it avoids brands · ⚠️ labels
cover only the difference set → this is a **prioritised prune list**, not global per-term precision ·
**discovery, the other half (moved here from Topic 3 on 2026-09-14)** = three text surfaces mined
separately: CPE **vendor** field · confirmed-Yes **descriptions** (n-grams, discriminativeness +
real new-yield through the pipeline's own matcher) · CPE **product** field (single device nouns,
precise inside a product name where useless in free text — the only surface several vendors were
reachable on at all) · risk flags (mega-vendor / dictionary word / known FP bomb) **triage, never
filter** · candidates never auto-included → one vetting pass accepted **41 terms (17 brand / 24
phrase)**; product scan runs **47 tokens / 19 categories** · accepted product tokens enter as
ordinary brand terms, since the underscore concession reaches CPE strings directly · the two
halves are deliberately asymmetric: discovery proposes and requires human acceptance, pruning
removes on measured evidence · both write only candidate lists · both run *between* passes, never
inside one

**How it connects:** this is the subsection that converts a recurring reviewer complaint ("your
term list is arbitrary") into a measured maintenance procedure, and the asymmetry paragraph is the
argument for why the arbitrariness is bounded in one direction only — adding a term is a judgment,
removing one is a measurement. §V-B cites the 20-of-426 figure as its internal-validity evidence,
so the two must agree numerically. The honest limit is already in the text and should stay there:
difference-set-only labels mean a term's precision on the intersection is unmeasured, so a term
that is noisy only where both methods agree cannot be caught by this pass.

Discovery moved here from Topic 3 in the restructure, and the move fixed a real ordering error
rather than just tidying: all three mining passes read **settled judgments** as their evidence
(Tier-A vendors come off confirmed-Yes CVEs, the n-gram score is computed against the labelled
Yes/No corpus), so describing them among the searches placed them upstream of the data they
consume. They are stage 9 in the diagram for exactly that reason — they hang off the judgment
store, not off the term lists. The asymmetry paragraph now closes a subsection that contains
both halves, so it no longer has to reach across subsections to state its own subject.

**Quote — the threshold and what it produces, tex** (`docs/home_iot_security_report.tex:745`):
> We flag as prune candidates any term whose difference-set precision falls
> at or below $0.10$ over at least 5 judged rows. In practice this turns a brand string that
> collides with unrelated software, or an over-broad vendor entry that pulls in generic
> hardware, into a concrete line item to remove from the term list rather than a recurring
> disagreement to re-adjudicate.

**Quote — the loop's asymmetry, tex** (`docs/home_iot_security_report.tex:796`):
> Discovery
> proposes terms a hand-compiled list is missing and requires a human to accept each one,
> because accepting a brand is a scope judgment. Pruning identifies terms that have already
> been shown to generate noise, using labels the review produced, so the evidence for
> removal is measured rather than predicted.

**Evidence:** `data/difference/term_precision.csv` (recomputed this session: 426 rows / 398 distinct
terms / 20 `prune_candidate=Yes` over 19 terms / 15 vendor + 5 keyword) · `scripts/term_precision.py` ·
`scripts/cpe_brand_mining.py` · `scripts/keyword_mining.py` · `scripts/cpe_product_scan.py` ·
`data/cpe-product-tokens.csv` (47 tokens / 19 slugs) · `data/vendor-search/vendor_candidates.csv` ·
`data/keyword-search/keyword_candidates.csv` ·
`data/cpe-product-scan/product_candidates.csv` · commit `d4c09b3` (the 41 accepted mined terms)

**Cite:** none

---

## Topic 6 · Recall — bounding what the terms never reached *(stage 10)*
*tex 805–837 · split out of Topic 3 on 2026-09-14; previously the last two paragraphs of collection*

**Beats:** review measures **precision** and says nothing about **recall** · a device-relevant CVE
naming none of our terms never enters the corpus at all · vendor and keyword searches treated as
two capture occasions of one CVE population → Chapman-corrected Lincoln–Petersen, **no additional
labelling required** · pooled search-stage recall **0.603 (95% CI 0.556–0.648)**, 4,849 observed
against N̂ **8,046** · ⚠️ **upper bound**, always in the same sentence as the figure: V and K are
positively dependent (a CVE naming a brand often names the device type too), which biases N̂ down
and recall up · three-source log-linear variant, **AIC-selected**, estimable for 21 of 22
categories, exists precisely because the 2-source figure assumes away the dependence it most likely
violates · structural gaps: **5 degenerate** (one list ⊆ the other → estimator returns an
artifactual 1.0, excluded from the pool) · 1 category with no in-scope seed → no third set ·
2 with an empty term list on one side → no recapture possible · per-category figures read as
indicative, not precise · limitations returned to in §V-C

**How it connects:** this is the section's most exposed claim and the one that discharges debt (c)
of the three §III owes, which is why it is now its own subsection rather than the tail of
collection. Standing alone it is harder to skim past, and the title states the job rather than the
method. The upper-bound caveat is not optional framing — it is the difference between an honest
coverage claim and an overclaim, and §V-C inherits it. Note the tension recorded below: 0.603 is
simultaneously the paper's headline coverage figure and a number biased in the flattering
direction, and there is no comfortable way to write that. The three-source variant is the
mitigation, but its per-category intervals are too wide to headline and **there is no pooled
3-source estimate in the CSV** — do not compute one on the fly.

**Quote — recall's direction of bias, tex** (`docs/home_iot_security_report.tex:815`):
> That figure should be read as an \emph{upper}
> bound: the two searches are positively dependent rather than independent, since a CVE
> naming a brand often also names the device type, and such dependence biases the estimated
> population size downward and hence recall upward.

**Evidence:** `data/difference/recall_estimate.csv` (POOLED row = `2src-chapman(sum)`, 4,849
observed / N̂ 8,045.7 / CI 7,488.1–8,721.2 / recall 0.603 CI 0.556–0.648; 23 2-src rows incl.
POOLED, 21 3-src rows; degenerate = fans/fridge/pet/robotvacuum/sensors) ·
`scripts/recall_estimate.py` · `docs/RECALL_ESTIMATION_EXPLAINER.md`

**Cite:** `chapman1951` · `fienberg1972` · `akaike1974`

---

## Topic 7 · Per-CVE extraction — CWE gaps, CPE gaps, CVSS version policy
*tex 838–891 · moved after the pipeline block 2026-09-14: its denominators are post-review*

**Beats:** CWE per CVE, `NVD-CWE-noinfo` / `NVD-CWE-Other` = no usable mapping · **118 of 1,676
(7.0%)** unusable — the merged year-feed schema collapses all three cases, so they are reported
together, not split · kept in the CVE-level analysis, excluded from the CWE analysis · remaining
**1,558** CVEs → **155** distinct CWE ids pre-mapping · second, independent gap: **193 (11.5%)**
carry no CPE at all → the population reviewers judged from text alone, and the ceiling on CPE
expansion · both gaps are **standing limitations, not backlog** · churn vs the prior vintage: 0
CWEs backfilled on 118 · 3 CPEs on 196 · 0 base-score changes · 0 v2 records re-scored · 0 newly
rejected · all 3 real changes = first analysis, not reanalysis · CVSS 0–10, exploitability +
impact · severity bands None/Low/Medium/High/Critical · corpus mixes v2.0, v3.x, **v4.0** ·
version preference **v3.1 → v3.0 → v4.0 → v2.0**, deliberately putting v4.0 below v3 to keep the
bulk of the distribution on one formula · resolves to **1,211 v3.1 · 330 v3.0 · 54 v4.0-only ·
81 v2.0-only** · score + vector present for **1,676/1,676** · that completeness came from a
**parser fix on our side**, not NVD: 57 previously unscored, 54 of them v4.0-only, 3 genuinely new ·
vector strings not extracted at all before that pass · component-level extraction not performed
(future work)

**How it connects:** this subsection quietly sets up two later defences. The churn table is what
lets §V-C say the corpus is bounded by NVD *practice* rather than by NVD *lag* — a reviewer will
otherwise propose "just re-download" as a fix for the 7.0%/11.5% gaps, and the measured answer is
that a six-week refresh moved 3 rows. The parser-fix attribution is the more interesting
methodological point and is new to the paper as of this rewrite: a silent extraction gap is
indistinguishable from missing upstream data unless you keep the superseded snapshot and diff it,
which is the concrete argument for the retain-the-old-vintage discipline in Topic 3. RQ2's v2-only
sensitivity check depends on the version-preference rule being stated here, so do not compress it.

**Quote — the parser attribution, tex** (`docs/home_iot_security_report.tex:880`):
> That completeness is
> worth attributing correctly, because it came from a correction on our side rather than from
> NVD: 57 CVEs in the analysis set had previously extracted as unscored, of which 54 were
> scored only under v4.0 and were being missed by a metric reader that never inspected the
> v4.0 block

**Quote — what the vintage comparison measures, tex** (`docs/home_iot_security_report.tex:862`):
> what the comparison
> measures is first analysis, not reanalysis: on a fixed set of already-analyzed records, NVD
> churn is close to nil

**Evidence:** `data/nvd-snapshot/nvd_all.csv` (verified this session over the 1,676: version mix
1211/330/81/54 · 118 no CWE · 193 no CPE · 0 missing vectors · 155 distinct CWEs) ·
`data/nvd-snapshot/snapshot_churn.md` + `.csv` · `scripts/download_nvd.py:139` (the preference
order, with its own comment explaining why v4.0 sits below v3) ·
`data/difference/cvss_distribution.csv` (`n_scored == n_cves` everywhere)

**Cite:** `ref-cvss`

---

## Topic 8 · CWE-888 mapping — why this view, and how far over-counting goes
*tex 892–923*

**Beats:** CWE = MITRE taxonomy, several organising views · CWE-888 Software Fault Patterns chosen
for two reasons: comparability with the prior study, and a fault-centred, wider-coverage framing
than CWE-699 · catalog pinned to **v4.12 (29 June 2023)** → mapping reproducible · **23 primary
clusters**, 21 attributed, 2 empty (retained in the mapping, blank in results) · CWE in the view →
map directly · CWE not in the view → map through parents; parents in two clusters → counts in both ·
over-counting bounded and quantified over the **1,613** assignments carrying ≥1 CWE (1,571 resolve
to ≥1 class; 42 resolve to none): **76 (4.7%)** single CWE spanning two classes · **220 (13.6%)**
with ≥2 distinct CWEs, of which 123 resolve to one class and 97 span · union **173 (10.7%)**
contribute to more than one class · large majority contribute to exactly one

**How it connects:** the whole point of stating 4.7 / 13.6 / 10.7 rather than "some over-counting
occurs" is that RQ1's percentages are computed over attributions, not CVEs, so a reviewer needs
the inflation ceiling to read the table. §V-A owns the *threat* framing of the same mechanism —
keep the arithmetic here and the "this is a modelling choice" argument there. One consistency trap:
these are per-(category, CVE) **assignments**, not CVEs; the denominators differ from Topic 4's and
a stray "CVEs" in this paragraph would make the two subsections look mutually inconsistent.

**Quote — the mapping rule, tex** (`docs/home_iot_security_report.tex:908`):
> When an identified CWE is itself part of the CWE-888 view, we mapped it directly to
> its corresponding primary class. When it is not, we examined its parent CWEs and mapped
> those instead, so a CWE whose parents fall under two different primary classes counts
> toward both.

**Evidence:** `data/difference/cwe888_cve_map.csv` (recomputed this session: 1,613 / 1,571 / 42 ·
76 · 220 → 123/97 · 173 · 155 CWEs · 21 classes present) ·
`data/difference/cwe888_distribution.csv` · `data/cwe/cwec_v4.12.xml.zip` (pinned catalog) ·
`scripts/cwe888_analysis.py`

**Cite:** `ref-cwe` · `ref-cwe888` · `ref-cwe699` · `ref-mcsoftware`

---

## Belongs in another section

- **Reviewer model biases** (Codex over-excludes unfamiliar security brands, Gemini/Gemma
  over-includes on function overlap) — §V-B Internal Validity already owns this, tex 1413–1441. It
  is tempting to put it beside the Gemini-as-weaker-vote rule in Topic 4; don't, or §V-B loses its
  evidence.
- **What the SAREF alignment *found*** (7 exact / 17 coarse · generic superclass only for 6 of 24
  carrying 10.0% · `s4bldg:AudioVisualAppliance` covering five categories with 61.1%) — §V-A,
  tex 1354–1412. Topic 2 now states only the procedure and points there; the de-duplication edit
  is already applied.
- **Facet κ table and the three named failures** (`supportLifetime` below chance ·
  `hasWebAdminUI`/`computeTier` failing both annotation and derivation · `capturesAV` failing both
  gates) — §V-D, tex 1460–1555 incl. `tab:facet-kappa` at 1532.
- **Per-category CVE counts, CWE-888 distributions, treemaps** — RQ1, incl. two
  `BEGIN GENERATED` blocks (tex ~1044 and ~1090) that must never be hand-edited.
- **Recall's consequences for generalisation** — §V-C External Validity, tex 1442–1459. Topic 6
  states the estimate; §V-C states what it means for the claims.

## Tensions and open arguments

- **CPE expansion is described as a high-precision densifier and measures 36.8% once tvOS is
  removed.** Both statements are defensible — the 1,897 tvOS rows *were* judged genuine, and it is
  a scope decision that removes them — but the tension is real and a reviewer will find it. The
  text now leads with the decomposition rather than the aggregate; keep it that way, and resist
  re-quoting 94.8% anywhere.
- **Intersection precision (70.2%) vs the per-category FP narrative.** Topic 4 attributes
  `cameras`' 77.6% FP rate to an over-broad vendor list, while Topic 3 attributes the intersection
  failure in the same category to generic device *phrases* colliding with pro brands. Both are
  true and they are the same collision seen from two sides; if a reviewer reads them as competing
  explanations, the reconciliation is that the two term lists overlap precisely on
  enterprise-surveillance hardware.
- **`recall = 0.603` is an upper bound and is also the paper's headline coverage figure.** There is
  no way to make this comfortable. The 3-source variant exists specifically because the 2-source
  figure assumes away the dependence it is most likely violating, but its per-category intervals
  are too wide to headline and there is **no pooled 3-source estimate in the CSV** — do not compute
  one on the fly for the paper.
- **"Roughly a fifth" of confirmed assignments have no device CPE.** `guardrails.md` §2 records
  **21.6%** (from `facet_sample.py`'s frame); an independent recomputation this session over
  `judgment_store.csv` × `nvd_all.csv` with an explicit `part ∈ {o,h}` + platform-deny rule gives
  **21.1%**. The difference is deny-list handling, not a data disagreement. The tex deliberately
  says "roughly a fifth" rather than pick one; if a precise figure is ever needed, cite
  `facet_sample.py`'s frame and say which rule produced it.
- **The facet apparatus takes ~28 lines of methodology to support zero findings.** That is the
  point — it is why nothing rests on a facet — but be ready to defend the space. The compression
  option, if a reviewer objects: keep provenance + the withheld-in-code mechanism, move the three
  gates' design detail to §V-D.
- **`sleeptracker` is inside the 24 while contributing nothing.** It is listed, has a 100% FP rate,
  and is described as pending a rebuild. A reviewer may reasonably ask why it is a category at all.
  The current answer is honesty about the frozen list; the alternative (drop to 23) would require
  re-freezing scope, which the dependency rule makes expensive.

## Works cited

Every key below is defined in `\begin{thebibliography}` (tex 1603+) and survived the full
bibliography pass of 2026-09-08. 48 cited = 48 defined, no dangling refs.

Reference text and links below are transcribed from the `\bibitem` entries themselves (opened this
session at the line given), **not** reconstructed — five of five spot-checked entries were once
wrong because they had been drafted from memory, so nothing here is written from recall. Where an
entry records no DOI or URL, the column says so rather than guessing one.

| key | reference (as printed in the tex) | link | why §III cites it |
|---|---|---|---|
| `ref-nvd` | NIST, "National Vulnerability Database (NVD)" — tex 1606 | `https://nvd.nist.gov/` | The data source itself — cited once for what a CVE record is (tex 446) and once for the snapshot. Everything in §III is downstream of this one artifact. |
| `ref-mcsoftware` | K. Goseva-Popstojanova and J. Tyo, "Experience report: Security vulnerability profiles of mission critical software: Empirical analysis of security related bug reports," IEEE ISSRE, 2017, pp. 152–163 — tex 1608 | no DOI/URL in the entry | The methodological ancestor. It is why the CWE-888 view is used at all, and the comparability argument in Topic 5 is entirely about staying commensurable with it. Cited twice: in the overview (tex 153) and at the point of choosing the view (tex 897). |
| `ref-cwe888` | Common Weakness Enumeration, "CWE-888: Software Fault Pattern (SFP) Clusters" — tex 1612 | `https://cwe.mitre.org/data/definitions/888.html` | Defines the 23 primary clusters that RQ1's rows *are*. Cited where the view is first named (tex 154) and again where it is chosen over the alternative (tex 896). |
| `ref-cwe` | Common Weakness Enumeration, "CWE" — tex 1617 | `https://cwe.mitre.org/data/index.html` | Establishes CWE as a community taxonomy maintained by MITRE before the paper starts reorganising it — needed so "view", "primary class" and "parent CWE" have a referent (tex 894). |
| `ref-cwe699` | Common Weakness Enumeration, "CWE-699: Software Development" — tex 1615 | `https://cwe.mitre.org/data/definitions/699.html` | The rejected alternative. Cited only so the CWE-888 choice reads as a comparison rather than an assertion; it answers "why not the development view?" (tex 900). |
| `ref-cvss` | FIRST, "Common Vulnerability Scoring System (CVSS): Specification Document" — tex 1619 | `https://www.first.org/cvss/` | Backs the 0–10 range, the exploitability/impact derivation and the severity bands (tex 867). Load-bearing for RQ2, whose bands are not the paper's own invention. |
| `balta2013` | N. Balta-Ozkan, R. Davidson, M. Bicket, and L. Whitmarsh, "Social barriers to the adoption of smart homes," *Energy Policy*, vol. 63, pp. 363–374, 2013 — tex 1623 | no DOI/URL in the entry | One of the two anchors of the written definition (tex 291). Supplies the *residential deployment* framing, so criterion 3 and the consumer-ownership half of criterion 5 rest on prior work rather than on us. |
| `alrawi2019` | O. Alrawi, C. Lever, M. Antonakakis, and F. Monrose, "SoK: Security evaluation of home-based IoT deployments," IEEE S&P, 2019, pp. 1362–1380 — tex 1626 | no DOI/URL in the entry | The most load-bearing citation in §III, cited three times for three different jobs: the other anchor of the definition (tex 291); the hub-in / router-out precedent, i.e. hubs are study subjects while routers are threat-model context (tex 322); and the four-component device–app–cloud–communication deployment model, which is what justifies the rubric rule that a companion-app CVE is in scope for its device (tex 631). |
| `kumar2019` | D. Kumar, K. Shen, B. Case, D. Garg, G. Alperovich, D. Kuznetsov, R. Gupta, and Z. Durumeric, "All things considered: An analysis of IoT devices on home networks," USENIX Security, 2019, pp. 1169–1185 — tex 1632 | no DOI/URL in the entry | Cited at the entertainment / 4(b) boundary (tex 316) because it classifies devices seen on real home networks and separates computers, phones and routers from home IoT — external support for treating streaming and speaker hardware as device classes rather than general-purpose compute. |
| `fernandes2016` | E. Fernandes, J. Jung, and A. Prakash, "Security analysis of emerging smart home applications," IEEE S&P, 2016, pp. 636–654 — tex 1677 | no DOI/URL in the entry | Paired with `kumar2019` at the same boundary (tex 316). It takes the smart-home *platform* — hub, apps, capabilities — as the unit of security analysis, which is the precedent for admitting a control surface under 4(b) rather than only end devices. |
| `stanford_iot` | Stanford University, "Minimum security standards: Internet of Things (IoT) devices" — tex 1663 | `https://uit.stanford.edu/guide/securitystandards/iot` | Cited for the networking exclusion (tex 322): a widely used institutional IoT definition that explicitly excludes routers, switches and access points, so treating pure-transport gear as context rather than subject is not idiosyncratic to this study. |

### Added 2026-09-09 — external vocabularies and statistical methods

Ten entries closing the "named method / named vocabulary, no reference" gap. Each was verified
this session against a publisher, standards-body or catalogue record — none written from recall.
The three vocabulary entries are pinned to **the exact versions in `ontology/external_sources.tsv`**,
so the citation and the manifest cannot describe different documents.

| key | reference (as printed in the tex) | link | why §III cites it |
|---|---|---|---|
| `saref` | ETSI, "SmartM2M; Smart Applications; Reference Ontology and oneM2M Mapping," ETSI TS 103 264 V3.2.1, Jan. 2024 — tex 1755 | `https://www.etsi.org/deliver/etsi_ts/103200_103299/103264/03.02.01_60/ts_103264v030201p.pdf` | The alignment target itself (tex 424). V3.2.1 is exactly the SAREF core version pinned in `external_sources.tsv` (retrieved 2026-08-04, sha `d3d859e57c7a0755`) — cite any other version and the manifest stops matching the citation. |
| `saref4bldg` | ETSI, "SmartM2M; Extension to SAREF; Part 3: Building Domain," ETSI TS 103 410-3 V1.1.2, May 2020 — tex 1759 | `https://www.etsi.org/deliver/etsi_ts/103400_103499/10341003/01.01.02_60/ts_10341003v010102p.pdf` | Carries the load-bearing half of §V-A's replacement finding: `s4bldg:AudioVisualAppliance` is the single class that collapses five of our categories (61.1% of confirmed CVEs). That claim was previously made about a document the paper never cited. Pinned version v1.1.2 matches the manifest. |
| `saref4ext` | ETSI, "SmartM2M; Extension to SAREF," TS 103 410 series — Part 1 Energy (V1.2.1), Part 4 Smart Cities (V2.1.1), Part 6 Smart Agriculture and Food Chain (V2.1.1), Part 7 Automotive (V2.1.1), Part 8 eHealth/Ageing-well (V2.1.1), Part 9 Wearables (V1.1.1) — tex 1762 | `https://saref.etsi.org/` | Covers the six remaining vocabularies §III claims to have searched (tex 424–425). One compound entry rather than six: they are cited at a single point, in a single sentence, and four of them contributed no alignment at all — but each part number and version is given so any one of them can be pulled individually. Each version matches the ontology serialization pinned in `external_sources.tsv`. |
| `ssn2017` | Haller, Janowicz, Cox, Le Phuoc, Taylor, Lefrançois (Eds.), "Semantic Sensor Network Ontology," W3C Recommendation, 19 Oct. 2017 — tex 1768 | `https://www.w3.org/TR/2017/REC-vocab-ssn-20171019/` | The second alignment target (tex 426). Also the reason `sosa:System` does not exist — it is `ssn:System` — one of the four invented IRIs the manifest check caught. ⚠️ A 2023 Edition exists (`https://www.w3.org/TR/vocab-ssn-2023/`); we cite the 2017 Recommendation because that is the namespace document retrieved into the manifest. |
| `chapman1951` | D. G. Chapman, *Some Properties of the Hypergeometric Distribution with Applications to Zoological Sample Censuses*, Univ. of California Publications in Statistics, vol. 1, no. 7, 1951 — tex 1773 | no DOI; Open Library `OL200768M` | Names the estimator the recall figure comes from (tex 811). Without it "Chapman-corrected Lincoln–Petersen" is an eponym with no referent, and the 0.603 has no method a reader can check. ⚠️ Page range deliberately omitted: catalogue records disagree (131–159 per Open Library, 131–160 in most secondary citations). |
| `fienberg1972` | S. E. Fienberg, "The multiple recapture census for closed populations and incomplete $2^k$ contingency tables," *Biometrika*, vol. 59, no. 3, pp. 591–603, 1972 — tex 1777 | `https://doi.org/10.1093/biomet/59.3.591` | The three-source estimator (tex 821). This is the paper that makes log-linear modelling of multi-source capture–recapture standard practice, i.e. it is the authority for estimating V–K dependence rather than assuming independence — the exact objection the 2-source figure attracts. |
| `akaike1974` | H. Akaike, "A new look at the statistical model identification," *IEEE Trans. Automatic Control*, vol. 19, no. 6, pp. 716–723, 1974 — tex 1780 | `https://doi.org/10.1109/TAC.1974.1100705` | Backs "AIC-selected" (tex 822). The weakest of the ten on its own — AIC needs no introduction — but the model-selection step is what turns "we fitted several models" into a stated rule, and a rule should have a source. |
| `fleiss1971` | J. L. Fleiss, "Measuring nominal scale agreement among many raters," *Psychological Bulletin*, vol. 76, no. 5, pp. 378–382, 1971 — tex 1782 | PsycNet `1972-05083-001` | The κ we report is Fleiss', not Cohen's, specifically because there are three raters (tex 410, and again at §V-D's table, tex 1476). Cited in both places so the reader of the table alone can tell which κ it is. |
| `landis1977` | J. R. Landis and G. G. Koch, "The measurement of observer agreement for categorical data," *Biometrics*, vol. 33, no. 1, pp. 159–174, 1977 — tex 1784 | `https://doi.org/10.2307/2529310` | Sources the word "conventional" in the κ bands (tex 411, 1528). The paper draws real consequences from the 0.60 and 0.40 cutoffs — four facets citable, the rest not — so the cutoffs need an origin outside this study. Note for the author: these bands are widely criticised as arbitrary; citing Landis–Koch makes that criticism *about the convention* rather than about you. |
| `kruskal1952` | W. H. Kruskal and W. A. Wallis, "Use of ranks in one-criterion variance analysis," *JASA*, vol. 47, no. 260, pp. 583–621, 1952 — tex 1786 | `https://doi.org/10.1080/01621459.1952.10483441` | RQ2's omnibus test (tex 1245). Not §III, but the same defect class, and it was the paper's only uncited inferential statistic besides Dunn's. |
| `dunn1964` | O. J. Dunn, "Multiple comparisons using rank sums," *Technometrics*, vol. 6, no. 3, pp. 241–252, 1964 — tex 1789 | `https://doi.org/10.1080/00401706.1964.10490181` | RQ2's post-hoc test (tex 1254). Matters more than it looks: the paper reports 136 Bonferroni-adjusted comparisons and 13 significant pairs, so the correction procedure is doing visible work on the result. |

## Before you write this section

1. ✅ **RESOLVED 2026-09-09 — vocabulary citations and the provenance gap behind them.**
   `saref` (TS 103 264 V3.2.1), `saref4bldg` (TS 103 410-3 V1.1.2), `saref4ext` (the remaining
   six TS 103 410 parts: 1 Energy V1.2.1 · 4 Smart Cities V2.1.1 · 6 Agriculture V2.1.1 ·
   7 Automotive V2.1.1 · 8 eHealth V2.1.1 · 9 Wearables V1.1.1) and `ssn2017` are in the
   bibliography and cited at tex 424–426. Every TS number and version was read off the SAREF
   portal page for the exact ontology version we pinned, so citation and manifest describe the
   same document.

   The underlying defect was **provenance coverage, not a wrong IRI**: `external_sources.tsv`
   recorded 6 of the 12 source documents the manifest draws on. All 12 are now recorded with
   version, URL, sha256 and retrieval date, and the whole manifest was re-verified by
   downloading each document and resolving every IRI in it. Results worth keeping:
   **435 of 435 IRIs resolve**, the four hashes recorded 2026-08-04 all reproduce byte-for-byte,
   and the four undocumented extensions really are v2.1.1 as `CLAUDE.md` claimed. The one
   apparent anomaly — `ssn:SystemCapability` missing from the SSN namespace document — is not an
   error: it lives in the **SSN systems module**, a separate namespace document that was simply
   never recorded as a source. Same family of mistake as `sosa:System` vs `ssn:System`, caught
   the same way.

   **Three counts, kept deliberately distinct** (now stated in the `homeiot-align.ttl` header,
   `CLAUDE.md` and the paper): **8 searched** — what a `coarse` label claims and what §III
   reports; **12 documents / 435 IRIs manifested** — the searched eight plus SOSA, SSN core, SSN
   systems and one SAREF4SYST class checked while resolving the `System` confusion, verified but
   unused; **8 used** in the alignment — S4AUTO and S4CITY were searched and yielded nothing in
   scope, which §III now records as a result rather than dropping them from the searched set.
2. ✅ **RESOLVED 2026-09-09 — statistical citations.** `chapman1951` (tex 811), `fienberg1972` +
   `akaike1974` (tex 821–822), `fleiss1971` + `landis1977` (tex 410–411, and again at §V-D
   1476/1528), plus `kruskal1952` (tex 1245) and `dunn1964` (tex 1254) for RQ2, which had the
   same defect. Bibliography is now 58 entries, 58 cited, no dangling refs.
3. ⚠️ **Reviewer model identifiers.** The `\stub` at tex 598 asks for exact Claude and Codex model
   version strings. They were not captured at run time; the text already states this as a
   reproducibility limitation. Either resolve or delete the stub before submission — a red
   bracket in the PDF reads as an unfinished paper.
4. ✅ **RESOLVED 2026-09-09 — `guardrails.md` re-synced.** The `sandia2020` / SAND2020-11401
   entry was replaced with the verified `johnson2022sandia` = SAND2022-9315 record (tex 1705).
   No bibliography blocker remains. Two stale manifest counts were fixed at the same time
   (`ontology/README.md` and the `homeiot-align.ttl` header both said 331 IRIs; the manifest
   holds 435). All four ontology gates re-run green afterwards.
5. ✅ **RESOLVED 2026-09-14 — literal em-dashes converted.** The two in RQ1 prose are now `---`.
   A scan confirms no non-ASCII remains anywhere outside `%` comments, so the file is safe for a
   plain `pdflatex` run with no `inputenc`/`fontspec`.
6. ✅ **RESOLVED 2026-09-14 — the paper compiles.** First successful build in the project's
   history, run after the §III restructure: **19 pages, 0 errors, 0 undefined references, 0
   undefined citations, 0 overfull boxes.** Engine was `tectonic` 0.17.0 (installed via Homebrew;
   no TeX toolchain was present). Four defects the build exposed that no static check had caught:

   - **The walkthrough rendered as "a)"** — a bare `\paragraph` directly under `\section` gets
     lettered by IEEEtran, so the lead-in appeared as a list item before III-A. Now `\paragraph*`.
   - **A stale cross-reference the restructure created**: the review subsection pointed at
     Section III-C for the tvOS scope exclusion, which the restructure had moved into III-D
     itself. Now "described at the end of this section". *This is the class of error only a build
     or a careful read catches — the `\ref` resolved fine, it just resolved to the wrong place.*
   - **"described below"** in the vendor paragraph pointed at discovery, which had moved two
     subsections away. Now an explicit `\ref{sec:method-precision}`.
   - **`tab:facet-kappa` overflowed its column** by 1.9pt. Fixed with `\tabcolsep` 4pt.

   ⚠️ **Engine caveat.** `tectonic` is XeTeX-based; the paper's header documents `pdflatex`. The
   52 remaining warnings are all `TU/ptm` font-shape substitutions, an artifact of XeTeX asking
   IEEEtran for Times in Unicode encoding — they would not appear under pdflatex. Conversely a
   XeTeX build cannot confirm the pdflatex input-encoding behaviour, so the two literal em-dashes
   formerly at tex 934/937 were converted to `---` regardless; **no non-ASCII remains outside
   comments**. A pdflatex run is still worth doing once before submission.

   Two `\stub` markers still render as red brackets (item 3 below) — deliberately left, since
   resolving or deleting them is an author decision, not a build fix.

7. 🔴 **Added 2026-09-14 — the framework figure is not in the build.** Topic 0's walkthrough is
   live prose, but `docs/figures/pipeline.pdf` does not exist, so the `\begin{figure}` block at
   tex 180–186 is commented out and the list stands alone — **confirmed to read correctly without
   it in the 19-page build**, so this is a completeness gap, not a blocker.
   Export the diagram to that path, uncomment the block, and add the `Figure~\ref{fig:pipeline}`
   clause the comment flags. Two consistency obligations come with it: the list's numbering is
   keyed to the drawing, so renumbering one renumbers the other; and the list repeats three
   figures (208 phrases, 1,564/1,540 brands, 373,518 records) from Topic 3, so each of those now
   has two homes in the tex. The four divergences between the drawing and the code are recorded under Topic 0 —
   9.3 covering two scripts, box 4 showing three of four review directions, the missing
   scope-exclusion step, and box 8's one-way arrow.
8. **Do not re-run the pipeline for this section.** Every figure in §III was recomputed from
   `judgment_store.csv`, `nvd_all.csv`, `cwe888_cve_map.csv`, `term_precision.csv`,
   `recall_estimate.csv`, `facet_*.csv` and the four ontology gates on 2026-09-09, and all four
   gates were green at that time (`--check` 31/31 + byte-identical CSVs, `--self-test` all five
   criteria load-bearing, `--sources`, `--verify-kg` PASS).
