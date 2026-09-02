# Plan — Home IoT Device Ontology (OWL/SKOS, native Turtle)

*Decision taken: author natively in RDF/OWL Turtle (not YAML→TTL) because the paper ships an
ontology as a contribution and a generated artifact is a weaker claim than an authored one.
`rdflib`, `pyshacl`, `owlrl` are new dependencies (added to README Prerequisites).*

**Goal:** replace the prose scope definition in `docs/home_iot_security_report.tex`
§`sec:method-scope` with a machine-checkable OWL ontology that (a) formalizes the five
definitional criteria as class axioms, (b) adds the **folding-category hierarchy** the paper
currently lacks, and (c) generates `data/categories.csv` byte-identically so no pipeline stage
changes.

**The load-bearing deliverable is the hierarchy, not the artifact.** Everything else is
framing; the family rollup changes a result.

---

## STATUS — 2026-09-01, branch `main`

**COMPLETE. Phases 1–5 have landed and every open item in this plan is closed.** The four
gates are green as printed below (re-run 2026-09-01). Facet *provenance* work continues in
`PLAN_facet_annotation.md` and its fix plan `PLAN_facet_system_fixes.md` — neither can move a
scope ruling, since every descriptive sub-facet sits outside the membership axiom by
construction.

Closed on 2026-09-01, in the order they appear below:

| Item | Was | Now |
|---|---|---|
| **L11** F5 exclusions not enforced | `facet_analysis.py` reported `garden` as `[unmeasured]` — the label meaning "nobody looked" — on 5 cells somebody *had* looked at and ruled unusable | `facet_store.csv` is a second withholding source, with its own A/B switch and a distinct output line that carries no fabricated share |
| **L10** dead citation | 1 dead URL, believed to be a bad source on 1 cell | Link rot on **2** cells; same document relocated, and re-verified **by quoted content**, which is the check the limitation says a 200 cannot perform |
| **Phase 4** CVSS vectors | "representable but not exported yet" | Already exported and verified: 1,676 `cvssVector`, 1,595 parsed metrics, 80,072 triples. F6.2 closed |
| **Carried-forward 2** `PLAN_scope_exclusion.md` | unreachable, on unmerged branches only | tracked on `main` at `6619d86`; all 9 citing files resolve |
| **Phase 5** optional facet triage | "not done" | **Deliberately not done, and the paper says why** — superseded by the κ panel, which is now written into §`sec:threats-reliability` along with the validity/reliability distinction |
| `shades` | open scope call | resolved 2026-08-08, `noNvdFootprint` (unchanged, see below) |

**The one standing limitation that is not closeable here:** L1–L9 remain true statements about
the facet layer, and L2 in particular is *scope working as designed*, not a defect — F5 asked
10 facets across 16 categories, so the floor rule leaves every property at `Estimated`. Nothing
in this plan promotes a facet, and the four gates say nothing about whether one is citable.
Read L1 before citing anything downstream of a green run.

**Four gates, all currently green** (the plan originally described two; `--self-test` and
`--sources` landed later). **Read *Known limitations of the facet layer* before citing anything
downstream of a green run** — the gates test schema, axioms and reconciliation, and say nothing
about whether a facet value is reliable or evidenced (L1). `--check` covers the schema side:

```
SHACL: clean
parsed: 24 analysis categories, 7 excluded, 13 families
categories.csv: byte-identical ✓
families.csv:   byte-identical ✓
alignment: all external IRIs verified against manifest ✓
facet provenance: 18 estimated (496 of 496 assertions unevidenced)
sources: all cited studies verified against manifest ✓
reasoner: 31/31 rulings reproduced
```

`--self-test` covers the axiom side — deleting each criterion in turn and requiring the
reasoner to object. **This, not the ruling count, is the claim that survives scrutiny:**

```
1 connectivity                   non-networked-detector   ok
2 device class                     tablet-control-panel   ok
3 deployment                 commercial-hvac-controller   ok
4 function/role                    transport-networking   ok
5 security ctx                  monitored-alarm-service   ok
self-test: PASS — all 5 criteria are load-bearing
```

The excluded count moved 3 → 7 and the ruling count 27 → 31 because the four boundary
cases above (plus `non-networked-detector`) were added as defined-but-excluded types, each
failing **exactly one** criterion. `--sources` covers literature provenance.

`--verify-kg` covers the instance side (see *Phase 4* below):

```
reparse: 63918 triples load in rdflib ✓
Vulnerability 1676 | CategoryAssignment 1738 | Product 4706 | Vendor 292 | Cwe888Class 21
affectsCategory edges: 1738 = confirmed pairs ✓
per-category counts vs judgment_store: all 22 categories agree ✓
CWE-888 attributions (SPARQL over the graph): 1904 vs 1904 from cwe888_cve_map.csv ✓
family rollup via rdfs:subClassOf: all 11 families match families.csv ✓
gate: PASS
```

| Commit | What |
|---|---|
| `a1d8a65` | Phase 1 — `homeiot.ttl`, `shapes.ttl`, `ontology_build.py` |
| `c9121f5` | Phase 2 — **scope-exclusion bug fix**, 13 supervisor folds, `--group family`, micro/macro |
| `65802d2` | Phase 3 — `homeiot-align.ttl`, 331-IRI pinned manifest, IRI verification |
| `7f59e0b` | 3 of 4 scope calls resolved, `hiot:noNvdFootprint` added |
| `c5106d0` | Phase 4 — `homeiot-kg.ttl` schema + `--export-kg` / `--verify-kg` |
| *(this branch)* | Phase 5 — paper integration (below) |

### Phase 5 — what landed (2026-08-05)

**Data regenerated first** (everything downstream depended on it):
`tab:cwe888-matrix` was stale *and* pre-exclusion-fix (N=2,879 over 20 categories, `streaming`
at 1,785). Regenerated to **N=1,904 over 22 categories**; `cameras` is now 52% of attributions
and `streaming` 3%. Two generator bugs surfaced and were fixed:
- Both generators crashed on the `ALL-MACRO` pseudo-row Phase 2 added (percentages only, so
  `n_cwes` is empty by construction). The table now renders it as an `All (macro)` row; the
  treemap script skips it, since treemap area is a count.
- Family labels are prose, not slugs, so `Alarms & Sensors` emitted an **unescaped `&`** that
  silently added a table column. `generate_cwe888_table.py` now escapes row labels.

`generate_cwe888_table.py` gained `--label`, `--unit-label`, and `--order-by-n` so the same
script emits both the per-category and the folding-category table. Treemap
`DEFAULT_CATEGORIES` was re-picked on corrected data: the `N > 75` rule now selects
**cameras, hub, alarms, ev-charging** (`streaming` at 61 drops out); the stale
`cwe888_treemap_streaming.pdf` was deleted.

**Paper edits** (`docs/home_iot_security_report.tex`):
- §`sec:method-scope` — ontology as the formal counterpart to the prose criteria, incl. the
  4(a)/4(b) admission-route split (**1,624 vs 114**, so the contested entertainment boundary
  governs 6.6% of the corpus).
- §`sec:rq1` — both tables inlined, the `\stub` discussion written, micro/macro reported as a
  robustness note (7.3 pts by category, narrowing to 5.3 by family).
- `sec:rq1-cat1`–`cat4` — filled with the four largest folding categories (Cameras and
  Monitors, Hubs and Controllers, Energy, Alarms and Sensors = 82% of attributions).
- §`sec:threats-construct` — the 27-ruling reasoner check *and* the alignment gap.
- Data Availability — the `.ttl` artifacts + KG.
- Fixed a pre-existing dangling reference: the paper cited `category_scope.csv` twice; the
  actual file is `data/categories.csv`.

**Numbers worth not re-deriving.** The plan's "six categories at N ≤ 5" is true of **confirmed
CVEs** (airconditioner 5, sensors 4, appliances 3, fridge 3, airpurifier 2, fans 1), *not* of
CWE attributions — by attributions only five sit at ≤5 and airconditioner is 8. Keep the two
units distinct when citing. The alignment gap is **9 exact / 15 coarse** over the 24 analysis
categories (a 10th "exact", `vrar`, is an excluded class — don't count it), and those 15
coarse categories carry **91.5%** of confirmed CVEs / 92.3% of attributions.

**The last Phase 5 item — CLOSED 2026-09-01, but not as planned.** The optional deliverable was
a facet-level triage of reviewer disagreement in §`sec:threats-reliability` (which facet drove
each H1≠H2 split). **It is deliberately not done, and the section says so in the paper.** The
triage would use facets as the grouping variable for a reliability analysis, and the κ panel
that landed after this plan was written establishes that 8 of 12 facets are not reliable enough
to carry that weight. Explaining a *measured* disagreement in terms of an *unmeasured* one
inverts the evidentiary order — the refusal is the more defensible result, so it is stated
rather than silently skipped.

**What §`sec:threats-reliability` got instead** — the stronger material the plan could not have
known about, since the section previously discussed only snapshot pinning and the swappable
Gemini model, and reported no facet reliability at all:
- The **3-rater κ table** (`tab:facet-kappa`), 471 facet–item judgments over 35–40 devices per
  facet, with bootstrap CIs and the citable/grouping/unreliable bands. Only 4 of 12 clear 0.60.
- The three bounding results, each retiring a claim: `supportLifetime` **below chance**
  (−0.311 — a broken instrument, not a hard facet); `hasWebAdminUI`/`computeTier` failing κ
  *and* text-derivation, two methods sharing no mechanism; and `capturesAV` failing reliability
  on top of its validity verdict.
- The **validity-vs-reliability distinction** stated explicitly (three annotators can agree
  perfectly on a value that is false of the devices it is stamped onto), with Phase A's 272
  devices / 86-of-120 cells and *both* withholding routes described as enforced in code.
- An explicit statement that no finding in the paper uses a facet as its grouping variable, and
  that all 496 assertions are `Estimated`.

Not compiled — no LaTeX toolchain on this machine. Verified structurally instead: environments
balanced, brace depth 0, and the new table's rows carry exactly the declared 4 columns (the
unescaped-`&` bug from Phase 5 was a column-count error of precisely this kind).

### ~~The one thing still open: `shades`~~ — RESOLVED 2026-08-08, answer is (a)

`build_search.py --categories shades --overwrite` was run against the 2026-08-05 snapshot,
rebuilding both outputs from scratch rather than skipping existing ones. **9 keyword terms
returned 0 CVEs; 40 vendor terms returned 5**, all of them the previously judged
somfy/powerview rows. The terms are correct and *did* fire against a freshly built output,
so this is **not** the stale-output failure mode — the absence is in NVD.

`shades` now carries `hiot:noNvdFootprint true` with the evidence comment SHACL requires,
matching the `sleeptracker` precedent, and its `hiot:openScopeCall` is cleared. All four
gates green after the edit; `categories.csv` and `families.csv` stayed byte-identical.

Note what this settles and what it does not: the call was recorded as *"is the
blinds/curtains/shutters merge correct?"*, but **at n=0 that question is moot** — a merge
rule cannot be validated against an empty population. If `shades` ever acquires a
footprint, the merge question reopens on its own terms.

The original analysis is kept below for the record.

### (original) The one thing still open: `shades`

`shades` has **0 confirmed-Yes from 5 judged**, and `data/keyword-search/keyword_shades.csv` is
88 bytes (header only) despite 40 vendor terms and 9 keyword terms existing. Two possible
explanations, and they lead to opposite actions:

- **(a) genuinely absent from NVD** → treat exactly like `sleeptracker`: set
  `hiot:noNvdFootprint true` with an evidence `rdfs:comment` (SHACL enforces the comment).
- **(b) stale search output** — approved terms that were never rebuilt into the search, the
  failure mode recorded in the `stale-search-outputs-recall-lever` finding → this is a **recall
  gap**, not a scope call, and the fix is a rebuild, not an ontology marker.

Evidence so far leans **(a)**: `keyword_shades.csv` is dated 2026-07-23 while the shades keyword
terms date from `c1ffb39` (2026-06-24), so the search does appear to have run *with* the terms
and found nothing. `term_precision.csv` agrees on the vendor side — `powerview` 4 judged / 0 Yes,
`somfy` 1 / 0. **Not yet confirmed.**

**To resume:** re-run the shades terms live against the snapshot and count hits. Both attempts on
2026-08-04 were killed before finishing — `filter_by_keywords` over 748k rows is slow, and the
faster streaming version still ran several minutes. Consider scoping the scan to
`description` + `cpe_strings` for the 9 keyword terms only, or just running
`build_search.py --overwrite` for `shades` and reading the row count.

Note the framing shift: the call was recorded as *"is the blinds/curtains/shutters merge
correct?"*, but **at n=0 that question is moot** — the real question is (a) vs (b) above.

### Resolved scope calls (see `hiot:resolvedScopeCall` in the TTL for the evidence)

| Call | Outcome | Evidence |
|---|---|---|
| `ev-charging` vs `home-power` | separate | 0 shared Yes CVEs (71 vs 45); disjoint vendor terms |
| smart-display split | stay merged | 2 of 38 Yes touch a display; `smart display` = 48 judged / 0 Yes |
| `sleeptracker` | kept, `noNvdFootprint` | 0 Yes / 29 judged; terms correct and firing |

### Carried-forward items not part of this plan

1. ~~`tab:cwe888-matrix` is stale AND predates the exclusion fix.~~ **Done in Phase 5** — table,
   family table, and all treemaps regenerated at N=1,904.
2. ~~**`docs/plans/PLAN_scope_exclusion.md` is referenced but unreachable.**~~ **RESOLVED** —
   the file is tracked on `main` as of `6619d86`, so all nine citing files
   (`data/categories.csv`, `ontology/homeiot.ttl`, `mark_excluded.py`, `cpe_expansion.py`,
   `cpe_brand_mining.py`, `finalize_judgments.py`, `extract_human_review.py`,
   `docs/RESULTS.md`, this plan) now resolve. No merge or cherry-pick was needed.
3. ~~`CLAUDE.md` still describes the ontology-less layout.~~ **Done in Phase 5** — added
   `ontology/` + `data/ontology/` to the file structure and a design-rationale section.

---

## Measured motivation

> **Corrected 2026-08-04.** The first version of this section argued from
> `streaming` = 55% of all CWE attributions. That figure was an artifact of a bug, not a
> property of the data — see *The exclusion bug* below. The corrected numbers are here; the
> argument for the hierarchy survives, the argument about corpus skew largely does not.

### The exclusion bug (found while validating this plan; fixed 2026-08-04)

`mark_excluded.py` applies a scope ruling by setting `Excluded` on a settled row: the judgment
stands, but the row leaves the analysis population, and `finalize_judgments.py` drops it from
`final_resolved.csv`. That worked. But **`cwe888_analysis.py` and `cvss_analysis.py` both read
`judgment_store.csv` directly and tested only `Final Judgment == Yes`** — so the 2,015 tvOS rows
excluded in July 2026 were silently back in RQ1 and RQ2.

| | as computed | exclusion applied |
|---|---|---|
| confirmed-Yes rows | 3,753 | **1,738** |
| CWE attributions | 3,635 | **1,904** |
| `streaming` share | 50.8% | **3.5%** |
| `cameras` share | 26.3% | **55.3%** |

Independently corroborated: the supervisor-agreed folding table (streaming 75, cameras 778,
hub 98 …) reconciles against `final_resolved.csv` to within ±1 on most categories, so the
supervisors were already looking at the exclusion-applied population.

Both scripts now filter `Excluded` by default, with `--include-excluded` to reproduce the old
behaviour. **Any `report.tex` figure predating this fix is wrong**, including `tab:cwe888-matrix`
(which was already stale at N=2,879 over 20 rows).

### What remains true

**The tail problem is real and unchanged.** Six categories sit at N ≤ 5 (`sensors`,
`airpurifier`, `appliances`, `fans`, `fridge`, `airconditioner`) yet are published as
percentages — a cell reading "Channel 100%" on N=2 is two attributions rendered as a finding.
These rows cannot support the per-category discussion the `\stub` at `report.tex:493` requests.
Folding is the direct answer.

**The skew problem is much smaller than claimed.** Measured micro vs macro gap on the corrected
population: max **7.3** points by category (Memory Access), max **5.3** by family. Real, worth
reporting, *not* a headline. `Cameras and Monitors` is still 55% of the corpus, but its CWE
profile is close enough to the mean that pooling does not badly distort the overall shape.
Report both averages as standard practice; do not build a claim on the gap.

### Folding categories (supervisor-agreed — authoritative)

These 13 replace the 7 families originally invented in this plan. Agreed with supervisors as the
"more abstract, high-level overview"; the rule is *keep categories with a large enough n
standalone*, which is why `hub`, `streaming`, `smartspeakers`, `doorlock`, `sleeptracker`, and
`shades` fold to themselves. N = CWE attributions, exclusion applied.

| Folding category | Members | N | share |
|---|---|---|---|
| Cameras and Monitors | cameras, doorbell, babymonitor | 1,052 | 55.3% |
| Hubs and Controllers | hub | 282 | 14.8% |
| Energy | ev-charging, home-power | 135 | 7.1% |
| Alarms & Sensors | alarms, sensors | 89 | 4.7% |
| Outdoor & Pet | garden, pet | 75 | 3.9% |
| Entertainment | streaming | 61 | 3.2% |
| Electrical & Lighting | smartplugs, lighting | 60 | 3.2% |
| Access Control | doorlock | 43 | 2.3% |
| Appliances | robotvacuum, fridge, appliances | 41 | 2.2% |
| Audio | smartspeakers | 33 | 1.7% |
| Climate & Air | thermostat, airconditioner, fans, airpurifier | 33 | 1.7% |
| Sleep | sleeptracker | 0 | — |
| Shades | shades | 0 | — |

Sums to 1,904, matching the per-category total exactly. Note this grouping tracks **admission
route** where it matters: `Hubs and Controllers` (criterion 4(a), primary home control) is kept
apart from `Entertainment` and `Audio` (in only via 4(b)) — the distinction the paper's scope
section is built on.

---

## Scope — what this does and does not do

**Does:**
- Formalize criteria 1–5 as OWL axioms over a facet vocabulary.
- Add the 13 supervisor-agreed folding categories as a hierarchy over the 24 frozen leaves.
- Generate `data/categories.csv` (byte-identical) and a new `data/ontology/families.csv`.
- Add `--group family` rollups **and micro/macro-averaged overall rows** to
  `cwe888_analysis.py` and `cvss_analysis.py`.
- Publish `ontology/homeiot.ttl` + alignment file as a citable artifact.

**Does not:**
- **Classify any CVE.** Reviewers judge; `PLAN_deterministic_preclassifier.md` stays
  independent and unontologized. See *Circularity boundary* below.
- **Change any count.** Every CVE number, judgment, and precision figure is untouched.
  Families are a *view* over existing judgments, never a re-labeling.
- **Touch category membership.** The 24 categories stay frozen per `CLAUDE.md`.

### Circularity boundary (read before wiring anything)

`scope_note` is today hand-authored prose injected into reviewer prompts by
`scripts/gemini_classify.py` (`--scope`, default `data/categories.csv`). The ontology will
**hold that same text verbatim** as a `skos:scopeNote` annotation and emit it unchanged — text
*moved*, never *synthesized*. No new information reaches any reviewer, so reviewer behaviour and
all measured precision are unaffected.

Deriving judgments from facets would be a different act and is **out of scope**: it would make
`term_precision.csv` self-confirming, the same hazard `PLAN_deterministic_preclassifier.md`
guards against at its lines 85–86 by excluding `rule:*` rows from the precision computation.

---

## Class tree

Root `hiot:HomeIoTDeviceType`, 13 folding categories, 24 in-scope leaves, 3 defined-but-excluded classes.

```
HomeIoTDeviceType                     (13 supervisor-agreed folding categories)
├── CamerasMonitorsDevice     cameras, doorbell, babymonitor
├── HubsControllersDevice     hub                     [standalone — large enough n, and 4(a)]
├── AlarmsSensorsDevice       alarms, sensors
├── EntertainmentDevice       streaming               [standalone — in via 4(b)]
├── ElectricalLightingDevice  smartplugs, lighting
├── EnergyDevice              ev-charging, home-power
├── OutdoorPetDevice          garden, pet
├── AudioDevice               smartspeakers           [standalone — in via 4(b)]
├── AppliancesDevice          robotvacuum, fridge, appliances
├── AccessControlDevice       doorlock                [standalone]
├── ClimateAirDevice          thermostat, airconditioner, fans, airpurifier
├── SleepDevice               sleeptracker            [provisional — see below]
└── ShadesDevice              shades

ExcludedDeviceType (defined, not in the analysis set)
├── GameConsole              fails criteria 2, 4
├── VRARHeadset              fails criteria 2, 4
└── TransportNetworking      fails criterion 4 (plain routers, modems, ONT, switches)
```

`SleepDevice` is a singleton flagged `hiot:provisional true` — `sleeptracker` is ~88%
wrist wearables (out by criterion 3) with essentially no bedside monitors and is pending a
rebuild that may drop it (`CLAUDE.md` § Open scoping note). Encoding the provisional status is
better than hiding it; if the category is dropped, the family goes with it.

**Family assignment is not ours to invent — it was agreed with supervisors.** The rationale for
each fold is recorded as `rdfs:comment` on the family class in `homeiot.ttl`. Two rules are
visible in the agreed list and worth stating in the paper: *keep categories with a large enough n
standalone* (six folds are singletons for this reason), and folds do not cross the 4(a)/4(b)
admission boundary (`Hubs and Controllers` stays apart from `Entertainment`/`Audio`).

---

## Facet vocabulary

Five criterion facets (object properties, closed value sets as `owl:oneOf` individuals):

| Property | Criterion | Values |
|---|---|---|
| `hiot:hasConnectivity` | 1 | wifi, ethernet, zigbee, zwave, thread, matter, ble, mqtt, coap, cellular, rtsp, onvif |
| `hiot:hasDeviceClass` | 2 | EmbeddedSensor, EmbeddedAppliance, EmbeddedController, GeneralPurposeCompute |
| `hiot:hasDeployment` | 3 | Residential, Prosumer, Commercial, Industrial |
| `hiot:hasFunction` | 4a | Monitor, Automate, Control, MediaPlayback, Transport |
| `hiot:hasRole` | 4b | HomeControlSurface (Matter/Thread controller, assistant, feed surfacing) |
| `hiot:hasSecurityContext` | 5 | ConsumerManaged, ProfessionallyAdministered |

Analysis facets (not criteria — carried for RQ1/RQ2, no bearing on membership):

| Property | Values | Why |
|---|---|---|
| `hiot:formFactor` | Fixed, Portable, Worn | `Worn` is what excludes wearables from `sleeptracker` |
| `hiot:placement` | Indoor, Outdoor, Either | outdoor exposure vs. severity |
| `hiot:actuatesPhysical` | boolean | a lock/EVSE/oven has physical consequence; a plug less so — **feeds the RQ2 severity discussion**, where CVSS impact metrics do not capture physical safety |
| `hiot:capturesAV` | boolean | camera/mic presence — privacy-relevant class for RQ1 InfoLeak |

`actuatesPhysical` and `capturesAV` are the two facets most likely to yield a *new* RQ2 claim
(severity vs. physical/privacy consequence) that the flat category list cannot express. Treat
them as optional in Phase 1, required by Phase 3.

---

## Criteria as OWL axioms

```turtle
hiot:InScopeDeviceType a owl:Class ;
  owl:equivalentClass [
    owl:intersectionOf (
      hiot:DeviceType
      [ owl:onProperty hiot:hasConnectivity   ; owl:someValuesFrom hiot:Protocol ]
      [ owl:onProperty hiot:hasDeviceClass    ; owl:someValuesFrom hiot:SpecialPurposeEmbedded ]
      [ owl:onProperty hiot:hasDeployment     ; owl:hasValue      hiot:Residential ]
      [ owl:unionOf (
          [ owl:onProperty hiot:hasFunction ; owl:someValuesFrom hiot:HomeControlFunction ]
          [ owl:onProperty hiot:hasRole     ; owl:hasValue       hiot:HomeControlSurface ] ) ]
      [ owl:onProperty hiot:hasSecurityContext ; owl:hasValue     hiot:ConsumerManaged ]
    ) ] .

hiot:SpecialPurposeEmbedded owl:disjointWith hiot:GeneralPurposeCompute .
hiot:HomeControlFunction    owl:unionOf (hiot:Monitor hiot:Automate hiot:Control) .
```

`SpecialPurposeEmbedded ≡ EmbeddedSensor ⊔ EmbeddedAppliance ⊔ EmbeddedController`. The
disjointness axiom is what makes `GameConsole` (asserted `GeneralPurposeCompute`) provably
out — it cannot satisfy criterion 2 — while `streaming` enters through the `hasRole` disjunct
without needing a home-control *function*, exactly reproducing the 4(b) argument in the paper.

**The reasoner validation experiment.** Assert facets for all 27 classes, run a reasoner (owlrl
or HermiT via `owlready2`), and check its in/out verdict matches the paper's published rulings
on **all 27**. Any mismatch means the facets or the prose is wrong — this is a genuine finding
for §`sec:threats-construct`, and the reason to do this before submission rather than after.

Honest limitation to state in the paper: the reasoner automates the *easy* half (what follows
once facets are asserted). Asserting "a Fire TV is a HomeControlSurface" remains a human
judgment. The ontology makes that judgment **explicit, located, and contestable** — it does not
make it automatic. Do not overclaim this.

---

## External alignment

Separate file (`ontology/homeiot-align.ttl`) so a reviewer can evaluate the core without it.

**Implemented 2026-08-04** — `ontology/homeiot-align.ttl`, 76 external references across
SAREF core v3.2.1, SAREF4BLDG v1.1.2, SAREF4ENER v1.2.1, SAREF4WEAR v1.1.1, W3C SOSA and SSN.

Every external IRI is verified against `ontology/external_classes.tsv` (331 class IRIs pulled
from the published vocabularies; provenance in `external_sources.tsv`). `--check` fails on an
unverified IRI. This caught four plausible-but-nonexistent classes that were in the original
draft of this plan: `saref:Multimedia`, `saref:WashingMachine`, `saref:Generator`, and
`sosa:System` (the class is `ssn:System`). Negative-tested — all four are re-caught on demand.

**Coverage finding — this is a publishable result, not bookkeeping.** Only **9 of 24 categories
(38%)** align exactly to an existing external class. **15 of 24 (62%)** have no corresponding
class in *any* of the six vocabularies: airpurifier, alarms, babymonitor, cameras, doorbell,
doorlock, ev-charging, fridge, garden, hub, pet, robotvacuum, sleeptracker, smartspeakers,
streaming. The gap falls almost entirely on the consumer security-and-convenience tier — which
is exactly where this study finds the CVEs. SAREF is precise about meters, HVAC, lighting,
shading and appliances (its energy/building-management origins) and silent about most consumer
home IoT. Recompute with `--align`.

**Do not use `owl:equivalentClass` against SAREF.** Our classes are strictly *narrower*
(`hiot:cameras` is residential consumer IP cameras; `saref:Sensor` is any sensor). Asserting
equivalence would be false and is a standard reviewer objection to alignment sections.
`rdfs:subClassOf` + `skos:broadMatch` is what the relationship actually is.

---

## Phase 4 — the instance graph (DONE 2026-08-04)

`--export-kg` writes `data/ontology/homeiot-kg.ttl` (63,918 triples, ~4.1 MB): every
confirmed-Yes CVE, the CPE vendor/product pairs NVD attributes it to, its raw CWEs, and their
CWE-888 view classes. The vocabulary lives in `ontology/homeiot-kg.ttl` (hand-authored),
deliberately in a *second* file so nothing about the instance layer can perturb `homeiot.ttl`
and its byte-identical-`categories.csv` invariant. The only edge crossing the two is
`hkg:affectsCategory` / `hkg:assignedCategory`, whose range is `hiot:DeviceType` — so the 24
device types keep one definition and a family rollup is answered by the class hierarchy in
`homeiot.ttl` rather than by re-encoding `families.csv`.

**Four decisions worth recording:**

1. **The population comes from `judgment_store.csv`, not `final_resolved.csv`** — despite the
   gate text below saying otherwise. The store has 1,738 non-excluded Yes rows against
   `final_resolved.csv`'s 1,733; the 5 extra are 2026 CVEs present in both the store and the
   snapshot but not yet propagated to the derived file. `cwe888_analysis.py` and
   `cvss_analysis.py` both read the store, so sourcing the KG anywhere else would put the graph
   permanently 5 rows out of step with RQ1/RQ2. `Excluded` is a **reason string**, not a flag —
   any non-empty value excludes (`--include-excluded` keeps them).
2. **Category assignment is reified** (`hkg:CategoryAssignment`), because provenance is
   per-*pair*, not per-CVE: the same CVE can be confirmed in two categories by different routes
   (one by AI consensus, one by a human verdict), which a triple on the CVE alone cannot
   express. `hkg:affectsCategory` is kept alongside as a shortcut.
3. **CWE-888 classes hang off the `Weakness`, not the `Vulnerability`.** `cwe888_cve_map.csv` is
   keyed `(category, cve_id, cwe_id)` — one row per CWE — and `cwe_id → classes` is a function
   (verified: 0 inconsistencies across 155 CWEs). Attaching per-CWE is also what makes the graph
   reproduce RQ1's counting unit, a CWE **attribution**: walking
   `assignment → vulnerability → weakness → class` yields exactly 1,904. A deduplicated set of
   classes on the vulnerability would silently undercount.
4. **Minted instances are written as full `<IRI>`s, not prefixed names.** A Turtle local name may
   not contain `/`, and CPE product tokens routinely do once vendor and product are joined
   (`kgp:tp-link/tapo_p100` produces a file that will not parse). The prefixes are still
   *declared* in the output for SPARQL authors.

Output is deterministic — subjects sorted, predicate/object pairs sorted — so a re-export with
unchanged inputs produces an identical diff except the one `dcterms:created` line.

**What is deliberately absent.** No inferred edges, no similarity links, no attack paths, and no
property that could feed a classifier (PLAN § *Circularity boundary*). The graph records settled
judgments; it never produces one.

**CVSS vectors — the old reason no longer applies (corrected 2026-08-07).** This section
previously said CVSS is base-score-only because `download_nvd.py` discards `vectorString`, so
AV/PR/UI/S "are not representable here without a snapshot change". **That snapshot change has
happened:** the 2026-08-05 cutover added `vector_string` at 100% coverage (it is what unblocked
RQ3), and `cvss_vector.parse_vector` already reads it for `cvss_analysis.py` and
`facet_analysis.py --cross attack_vector`.

**DONE — the vectors are exported (verified 2026-09-01).** `build_kg` emits `hkg:cvssScore`,
`hkg:cvssVersion` and `hkg:cvssVector` on every `Vulnerability`, plus the eight parsed metrics
in `VECTOR_PREDICATES` (`hkg:attackVector`, `attackComplexity`, `privilegesRequired`,
`userInteraction`, `scope`, `confidentialityImpact`, `integrityImpact`, `availabilityImpact`).
Measured in the committed graph: **1,676 CVEs carry `cvssVector`, 1,595 carry the parsed
metrics** — the 81-CVE gap is CVSS 2.0 records that do not normalise to 3.x, which the exporter
deliberately skips rather than coercing. The triple count moved 63,918 → **80,072** accordingly,
so any doc still quoting 63,918 predates this. F6.2 is closed; nothing here is deferred.

---

## Files

```
ontology/
  homeiot.ttl              # core: classes, facets, criteria axioms, scopeNotes  [hand-authored]
  homeiot-align.ttl        # external alignments                                  [hand-authored]
  homeiot-kg.ttl           # instance-level vocabulary (Phase 4)                   [hand-authored]
  shapes.ttl               # SHACL: every class needs 5 facets + parent + sortOrder
  README.md                # how to edit, how to regenerate, Turtle crib sheet
scripts/
  ontology_build.py        # rdflib: parse → SHACL validate → reason → emit CSVs
data/
  categories.csv           # GENERATED — byte-identical to today
  ontology/families.csv    # GENERATED — slug,family,family_label
  ontology/homeiot-kg.ttl  # GENERATED — the instance graph (Phase 4)
```

### `scripts/ontology_build.py`

```
--check      parse + SHACL + reason + regenerate to temp, diff against committed CSVs; exit 1 on drift
--write      regenerate data/categories.csv and data/ontology/families.csv in place
--reason     run the 27-class in/out validation, print a ruling table
--align      verify alignment IRIs against the pinned manifest + coverage report
--export-kg  emit data/ontology/homeiot-kg.ttl, then run the verify gate
--verify-kg  re-run the gate against the committed graph without rewriting it
             (+ --include-excluded on either, to keep scope-excluded Yes rows)
```

**Two hard constraints on generation:**

1. **`data/categories.csv` must stay byte-identical**, including **row order**.
   `scripts/cwe888_analysis.py:249-251` reads it into `cat_order` and uses that for table row
   ordering; `scripts/build_review_sets.py:44` sniffs the header for a `slug` column. Carry an
   explicit `hiot:sortOrder` integer per class so ordering is deterministic and reproducible,
   seeded from the current file's order.
2. **No comment lines in `categories.csv`.** Unlike `keyword_terms.csv` / `vendor_terms.csv`
   (custom parser, `#` ignored), `categories.csv` is read by `csv.DictReader` in 11 scripts — a
   leading `#` line would be consumed as the header row. Provenance goes in `ontology/README.md`
   and this plan, never in the generated CSV.

Consumers to leave untouched (they must not notice the swap): `make_review_copies.py`,
`merge_judgments.py`, `gemini_classify.py`, `cwe888_analysis.py`, `cvss_analysis.py`,
`cpe_brand_mining.py`, `cpe_product_scan.py`, `keyword_mining.py`, `build_review_sets.py`,
`pipeline.py`, `generate_cwe888_table.py`, `run_gemini.sh`.

---

## Phases

| # | Deliverable | Gate |
|---|---|---|
| 1 | `homeiot.ttl` (24+3 classes, facets, axioms, scopeNotes), `shapes.ttl`, `ontology_build.py --check` | `categories.csv` regenerates byte-identical; SHACL clean |
| 2 | `families.csv`; `--group family` + micro/macro rows in `cwe888_analysis.py` + `cvss_analysis.py`; **Excluded-column fix in both** | family N's sum to 1,904; `--include-excluded` reproduces pre-fix numbers |
| 3 | ~~`homeiot-align.ttl`; reasoner validation of all 27 rulings~~ **DONE 2026-08-04** | reasoner 27/27; all 76 external IRIs verified against a pinned 331-IRI manifest |
| 4 | ~~KG export (`--export-kg`): confirmed-Yes CVEs, CPE vendor/product, CWE-888 classes as instances~~ **DONE 2026-08-04** | 63,918 triples reparse in rdflib; `--verify-kg` reconciles 5 instance-class counts, all 22 non-empty per-category counts, the 1,904 CWE-888 attributions and all 11 non-empty family rollups. Counts are against `judgment_store.csv`, not `final_resolved.csv` — see *Phase 4* for the 5-row reason |
| 5 | Paper edits | below |

Phase 1 changes no behaviour at all — it only proves the ontology can reproduce the current
file. Do not proceed to Phase 2 until `--check` is green.

### Phase 5 — paper integration

- §`sec:method-scope` — keep the prose; add the ontology as its formal counterpart + artifact cite.
- §`sec:rq1` — regenerate `tab:cwe888-matrix` (it predates the exclusion fix); add the folding-
  category rollup table; report the overall profile **both** micro- and macro-averaged. Do NOT
  build a claim on the micro/macro gap — measured at ≤7.3 points, it is a robustness note.
- `sec:rq1-cat1`–`cat4` (currently empty, `report.tex:581-593`) — one subsection per major family.
- §`sec:threats-construct` — the 27-ruling reasoner check as a validation mechanism.
- §`sec:threats-reliability` — optional: facet-level triage of reviewer disagreement
  (which facet drove each H1≠H2 split), read-only over the 1,638 human-settled rows.
- Data Availability (`report.tex:789`) — `.ttl` artifact.

---

## Known limitations of the facet layer (as of 2026-09-01)

Written down because most of them are invisible from a green gate run, and two of them were
live defects that a gate actively *concealed*. Scope-side limitations are not repeated here —
the criteria, the reasoner and `--self-test` are unaffected by everything below, since no
descriptive sub-facet appears in the membership axiom.

### L1. Four green gates say nothing about whether a facet is citable

`--check`, `--self-test`, `--sources` and `--verify-kg` verify schema, axioms, citation
registration and instance reconciliation. **None of them tests whether a facet value is true,
reliable, or evidenced.** That is the job of three separate measurements — κ
(`facet_agreement.csv`), Phase A modal share (`facet_distribution.csv`), and the F5 evidence
tier (`facet_store.csv`) — and all three are reported outside the gates. A run that prints
`gate: PASS` five times is consistent with every facet in the file being unevidenced, and
currently is: `facet provenance: 18 estimated (496 of 496 assertions unevidenced)`.

### L2. F5 promotes no facet above `Estimated`, by construction

The per-property tier uses a **floor rule** — weakest cell wins. F5 deliberately asked only
10 facets across 16 categories, so of 432 cells:

| bucket | cells |
|---|---|
| settled | 185 |
| 7 facets never asked (4 CITABLE + 3 grouping-only keep their prior 5-category coverage) | 130 |
| asked facet, one of the 8 skipped categories | 80 |
| `computeTier`, dropped 2026-09-01 | 19 |
| `excluded-validity` — 12 Phase A NOT-USABLE + 5 `garden` reviewer-split (L11) | 17 |
| **genuine gap** — `doorlock/patchResponsibility`, answered `unsure` (n=36) | **1** |

The 20 queue disagreements were adjudicated 2026-09-01 and the queue is now empty; every
superseded answer is preserved verbatim in the losing column's `Notes`, together with the rule
that decided it. Four rules settled all 20 — the multi-set rule (list what is *common*, not
everything possible), the corpus rule (a citation on a vendor holding 0% of the category cannot
overturn a value about the population the facet is joined onto), sourced-beats-unsourced where
the source materially covers the corpus, and the `garden` exclusion below. **When a verdict lost,
its column's `Source` was cleared**, since a citation supporting a different value must not ride
along as evidence for the settled one.

Every property therefore contains at least one unsettled cell and reports `Estimated`. This is
scope working as designed, **not** a failure — but it means the deliverable of F5 is the
per-cell tier mix and CVE-weighted sourced share, never a promoted property. Property-level
promotion would need a "weakest cell *among asked categories*" variant of the floor rule, which
is a design change and not a rerun.

### L3. `Documented` is zero — no cell has a class-binding source

Settled tier mix: **94 HumanSourced, 91 HumanJudged, 0 Documented.** Not one cell in the whole
pass rests on a source binding the product class; every citation is per-product, generalised by
a reviewer. Report that as a finding rather than letting it read as a gap — it is a real
statement about how little of consumer IoT is covered by class-binding instruments.

### L4. A regulation binds a market; a standard binds a class — conflating them inflated the tier

The original coverage exemption listed UK PSTI and grid codes alongside ETSI EN 303 645 and
Matter, reasoning that "a law does not need a market share". That is true of a **standard**
(conformance is the only precondition, so it reaches every vendor in the corpus) and false of a
**regulation** (UK PSTI reaches only vendors selling into the UK).

Measured when caught: all 11 `supportLifetime` cells returned `DeclaredLifetime` sourced on
PSTI, 10 claiming category-wide, and in **7 of those the cited vendor held 0% of the category's
confirmed-Yes CVEs** — `babymonitor` sourced on Nanit while `dlink` carries 44%, `doorbell` on
Ring while `akuvox` carries 36%, `thermostat` on Google/Bosch while `ecobee` carries 22%. The
white-label brands holding the CVE mass are precisely the ones publishing no support
declaration, so the exemption converted *absence of evidence* into the highest tier. A facet
returning one identical value on all 11 categories also discriminates nothing.

Fixed by splitting `CLASS_BINDING` (exempt) from `JURISDICTION_BOUND` (measured, labelled
`jurisdiction-bound`, share still decides). `supportLifetime` went from 15 cells silently exempt
to 12 below-floor and 3 passing on merits. **Do not restore the old exemption**; the standing
caveat is that jurisdiction-bound evidence is only ever evidence about the part of the corpus
sold into that jurisdiction.

### L5. Two promotion checks could only fail in the promoting direction

Both found 2026-09-01, both in `is_category_wide()`:

1. **OR across columns.** Clearing `Category-Wide 2` left `Category-Wide 1` firing, so
   `supportLifetime` still reported 100% sourced after the first correction. 24 stale claims
   cleared (22 `supportLifetime` + `ev-charging`/`home-power` `consumerAvailability`).
2. **The Notes substring fallback.** Any cell whose notes contained the phrase `category-wide`
   was promoted, and a substring test cannot tell a claim from its denial. All three cells
   firing it meant the opposite — including `ev-charging/supportLifetime`, whose note reads
   *"Deliberately NOT marked category-wide"* because EV chargepoints are an **excepted product
   under PSTI Schedule 3**. Column 1 got that right and the fallback was silently overriding it.
   Zero cells depended on it for a genuine promotion; removed.

The generalisable rule, and the reason both survived so long: **a check whose failure mode is
one-directional will always fail toward the flattering answer.** Any future promotion test
needs a negative case, the same way `--self-test` gives each criterion one.

### L6. The CVE-weighted sourced share is dominance-contaminated

Headline: **68.8% CVE-weighted sourced** across the 10 asked facets. Per *cell* it is 94/185 =
**50.8%**. The gap is `cameras` (885 CVEs, **50.9%** of the confirmed population) sitting in the
sourced half of several facets. `supportLifetime` is the clearest case: 57.7% CVE-weighted, but
**13 of its 16 settled cells are `HumanJudged`** — `hub` (247), `alarms`, `streaming` and
`ev-charging` are all unsourced, and the number is carried by `cameras` almost alone. Always
report both figures; the CVE-weighted one alone overstates how much is actually sourced. This is
the same dominance hazard `facet_analysis.py` flags for value cells, reappearing in the
provenance layer where nothing currently checks for it.

### L7. `computeTier` is dropped for the tail and settled for the head

Dropped from the asked set after failing three routes — κ 0.38, `facet_derive.py` (evidence
sufficed for 1 of 22 categories), and sourcing (`unsure` on 8 of 11). **But five cells were
already settled** in the earlier human-verified block, four of them `HumanSourced`: `cameras`
(885), `hub` (247), `alarms` (89), `streaming` (76), `ev-charging` (71) — **1,368 CVEs, 78.7%
of the population.**

So the honest statement is that sourcing failed **on the tail, not the head**: Codex's `unsure`
answers were all small categories the human block never reached.

**RESOLVED 2026-09-01 — the 5 cells are kept, as a restricted claim.** `computeTier` may be
reported over `cameras`, `hub`, `alarms`, `streaming` and `ev-charging` **only**, and every use
must name that restriction. It must **never** be reported as a whole-vocabulary property or
compared across the other 19 categories: the κ and derivation failures are global, and the tail
is not merely unsourced but demonstrably unsourceable — vendor documentation describes what a
device does and essentially never states its SoC class.

### L8. `source_vendors.csv` is not a complete record of what was cited

It is hand-maintained, and the 2026-09-01 rebuild only adds vendor tokens **already present in
that category's confirmed-Yes corpus** — anything else contributes 0% to a coverage share by
construction, so omitting it cannot change a verdict. Correct for coverage, but it means the
file must not be read as "the vendors this cell cites". 75 tokens were added across 60 cells,
46 of which had no coverage row at all beforehand (`representative` 50 → 104, `below-floor`
47 → 37). Any future citation edit needs a matching update here or coverage silently scores the
*previous* citation — which is exactly how the 19 re-sourced cells stayed below-floor after
being fixed.

### L9. Reviewer independence is weaker on cells 90–202 than on 1–89

Recorded in `scripts/make_codex_column2.py` and repeated here because it bounds every tier the
pass produces:

```
cells   1- 89 : Claude draft (col 1) + human verification (col 2)
cells  90-202 : Claude draft (col 1) + Codex draft, human-adjudicated (col 2)
```

On the second block the human **adjudicates two AI drafts** rather than acting as an independent
second reviewer. The sheet is non-blind by design — it is a verification pass built from
pre-fills, the opposite of `data/facets/annotation-kit/` — so the human was always the settling
authority. But `HumanSourced` on a second-block cell is a weaker claim than the same label on a
first-block cell, and the report must say so rather than presenting one tier column.

### L10. Citation checking proves reachability, not support

61 URLs across the Codex column were checked: 53 resolved, 7 were bot-blocked (Cloudflare/
Zendesk, pages real), **1 was dead** — `akuvox.com/ProductsDownloadFile.aspx?did=253`, cited by
**two** cells (`doorbell/capturesAV` and `doorbell/alsoDeployedIn`), not one.

**RESOLVED 2026-09-01, and the failure mode is worth recording: the citation was never wrong,
only its URL.** Akuvox dropped the `.aspx` route; the same document is live at
`www.akuvox.com/productsDownloadFile?did=253` (the `www.` matters — the bare host 500s). This is
link rot, not a bad source, and the two are easy to confuse when all you have is a status code.

The document was then re-verified **by content, not by status code**, which is exactly what this
limitation says a 200 cannot do. The R29CT datasheet reads `Main Camera: 3M pixels`,
`Auxiliary Camera: 1M pixels`, `Microphone: -32dB`, `Camera permanently operational` and
`Enables audio and visual monitoring of doors/gates` — which supports `capturesAV=true` — and
markets the device for `residential or commercial premises`, which supports `alsoDeployedIn`.
Both quotes are now recorded in the cells' `Notes 2`, so a future checker can test support
rather than reachability. Coverage is unaffected (same vendor token, so `source_vendors.csv`
needs no edit per L8) and both cells keep `HumanSourced` / `representative`.

A 200 still does not establish that the page says what the facet claims; nothing in the
pipeline tests that, and it remains a manual reviewer duty. This
is the same limit `--sources` has on the literature side (7 of 10 manifest entries still carry
`verified=` UNCONFIRMED bibliographic detail) and that the alignment manifest has on the
standards side — **a manifest proves what you used exists, never that you used it correctly,
and never that you looked for the right thing.** That is precisely how the retracted 62%/91.5%
SAREF gap survived.

### L11. An F5 validity exclusion does NOT propagate to `facet_analysis.py`

`garden`'s 5 cells were excluded 2026-09-01 because the two reviewers split along a subfamily
line — Ecovacs robot mowers (42% of the category's CVEs) against RainMachine irrigation
controllers (32%) — with each right about a different half. `capturesAV` is true of the mowers
and false of the controllers; `hasWebAdminUI` is false for Ecovacs and documented for "all
RainMachine models". That is the NOT-USABLE condition exactly, reached by a different route than
Phase A's device sampling: **Phase A never tested `garden` at all** (n=19, below its CVE floor),
so a reviewer disagreement is the only instrument that could have found it.

**The exclusion binds F5 and nothing else.** `facet_analysis.py` withholds a cell only when
`facet_distribution.csv` carries the literal verdict `NOT-USABLE-report-distribution` for it,
and that file is `facet_sample.py`'s machine-written output. `garden` has no row there, so
**`facet_analysis.py` still reports `garden` and labels it `[unmeasured]`, not withheld.** The
sheet records it as `NOT-USABLE-reviewer-split` to keep the two kinds of evidence distinguishable.

Hand-adding `garden` rows to `facet_distribution.csv` would be the wrong fix twice over: it is
the hand-copying of measured numbers into a machine-written file that the byte-identical-CSV
design exists to prevent, and it would misrepresent a reviewer split as a sampled modal share
(there is no `n_devices` and no `modal_share` to put in the row).

**RESOLVED 2026-09-01 — `facet_analysis.py` now reads `facet_store.csv` as a second withholding
source.** The manual workaround below is retired; `garden`'s 5 cells are withheld by the script.

Three properties of the fix are deliberate:
1. **Only `NOT-USABLE-reviewer-split` is read from the store.** The store also carries the 12
   Phase A cells, but `facet_distribution.csv` is the machine-written source of truth for those
   — reading them twice would let a hand-edited copy silently outvote the measurement it was
   copied from.
2. **The two withholdings print differently and are never merged into one count.** A Phase A
   line carries a modal share and `n_devices`; a reviewer-split line carries neither and says
   so, because rendering a disagreement in the Phase A format would dress it up as a
   measurement.
3. **Each guard has its own A/B switch** (`--ignore-phase-a`, `--ignore-f5-exclusions`), per the
   `cpe_expansion.py --no-part-filter` convention. They are independent: disabling Phase A still
   enforces the split exclusions, and vice versa. With both off, `capturesAV=true` reproduces the
   published unguarded 1,124 rows / 79% cameras exactly, which is the regression check that
   nothing else moved.

Measured effect: on `capturesAV`, `garden` moves out of `[unmeasured]` (11 categories instead of
12) into an explicit `WITHHELD garden: 19 CVEs` line, and the `false` cell drops 525 → 506. On
the 13 facets `garden` was *not* excluded for, it correctly stays `[unmeasured]` — the exclusion
is per-cell, not per-category.

### Carried over, already documented elsewhere — do not re-derive

- **All 496 facet assertions are `Estimated`**, hand-assigned with no source (`CLAUDE.md`).
- **Phase A sampled only 10 of 24 categories**; the rest stay UNMEASURED, and **21.6% of
  confirmed-Yes rows carry no device CPE** so cannot be product-sampled at any budget
  (`PLAN_facet_annotation.md`).
- **12 cells are Phase A NOT-USABLE** — a category holding two device types cannot have one
  true value, and a perfect source does not repair that (`facet_analysis.py` withholds them).
- **A per-category facet can never resolve below 24 buckets**, so the majority cell of nearly
  every facet inherits `cameras`' mass (`CLAUDE.md`, dominance rule).

---

## Risks

| Risk | Mitigation |
|---|---|
| `rdflib` dependency + Turtle authoring wall for curators | `ontology/README.md` crib sheet; curators keep editing `vendor_terms.csv`/`keyword_terms.csv` in CSV as today — the ontology holds *classes*, not terms |
| rdflib reserialization churns git diffs | Never reserialize the hand-authored files; `--write` only emits CSVs. If TTL is ever machine-written, sort triples deterministically |
| Reasoner contradicts a published ruling | That is the experiment working. Budget time in Phase 3 to fix facets *or* correct the paper |
| Family assignment looks arbitrary | `rdfs:comment` rationale per family, tied to the existing granularity rule; report per-category numbers alongside families, never instead of |
| Over-claimed SAREF equivalence | `rdfs:subClassOf` only; alignment in a separate droppable file |
| Scope creep into classification | Enforced by the *Circularity boundary* section above |
| A promotion check fails one-directionally and inflates a tier | Every promotion test needs a negative case, as `--self-test` gives each criterion. Two such checks shipped and both failed toward the flattering answer — see L5 |
| A green gate run is read as "the facets are citable" | L1 + the STATUS pointer; `--check` prints the provenance mix on every run so it cannot fade from view |
| Forces 3 open scope calls closed (`ev-charging`/`home-power`, `shades`, smart-display split) | Surface them in Phase 1 as explicit `hiot:provisional` markers; decide before Phase 3 |

## Acceptance criteria

**All met — re-verified 2026-09-01.** Counts 2 and 3 were written as 27 before the five
boundary cases were added; the real figure is **31** (24 analysis + 7 excluded), and the
self-test below is the criterion that actually has teeth.

1. ✅ `python3 scripts/ontology_build.py --check` exits 0 with `categories.csv` **and**
   `families.csv` byte-identical.
2. ✅ SHACL clean: all ~~27~~ **31** classes carry 5 criterion facets, a parent, and a sortOrder.
3. ✅ Reasoner reproduces all ~~27~~ **31** in/out rulings — and, more importantly,
   `--self-test` shows all 5 criteria load-bearing, each isolated by a boundary case that fails
   exactly one. **Report the self-test, not the ruling count** (most rulings are true by
   construction).
4. ✅ `cwe888_analysis.py --group family` family totals sum to the per-category total (1,904,
   exclusion applied), and `--include-excluded` reproduces the pre-fix population.
5. ✅ No change to `judgment_store.csv`, `final_resolved.csv`, `term_precision.csv`, or
   `recall_estimate.csv` — verified by `git status` after the 2026-09-01 work: all four are
   untouched, as are `categories.csv` and `families.csv`. The facet work of this session
   changed only `data/facets/*` and `scripts/facet_analysis.py`, which no CVE count reads.
