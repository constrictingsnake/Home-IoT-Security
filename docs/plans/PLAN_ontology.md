# Plan — Home IoT Device Ontology (OWL/SKOS, native Turtle)

*Status: **Proposed 2026-08-04** — no code written. Decision taken: author natively in
RDF/OWL Turtle (not YAML→TTL) because the paper ships an ontology as a contribution and a
generated artifact is a weaker claim than a authored one. `rdflib` becomes a new dependency.*

**Goal:** replace the prose scope definition in `docs/home_iot_security_report.tex`
§`sec:method-scope` with a machine-checkable OWL ontology that (a) formalizes the five
definitional criteria as class axioms, (b) adds the **family hierarchy** the paper currently
lacks, and (c) generates `data/categories.csv` byte-identically so no pipeline stage changes.

**The load-bearing deliverable is the hierarchy, not the artifact.** Everything else is
framing; the family rollup changes a result.

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

## Files

```
ontology/
  homeiot.ttl              # core: classes, facets, criteria axioms, scopeNotes  [hand-authored]
  homeiot-align.ttl        # external alignments                                  [hand-authored]
  shapes.ttl               # SHACL: every class needs 5 facets + parent + sortOrder
  README.md                # how to edit, how to regenerate, Turtle crib sheet
scripts/
  ontology_build.py        # rdflib: parse → SHACL validate → reason → emit CSVs
data/
  categories.csv           # GENERATED — byte-identical to today
  ontology/families.csv    # GENERATED — slug,family,family_label
```

### `scripts/ontology_build.py`

```
--check      parse + SHACL + reason + regenerate to temp, diff against committed CSVs; exit 1 on drift
--write      regenerate data/categories.csv and data/ontology/families.csv in place
--reason     run the 27-class in/out validation, print a ruling table
--export-kg  (Phase 4) emit instance graph
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
| 4 | KG export (`--export-kg`): confirmed-Yes CVEs, CPE vendor/product, CWE-888 classes as instances | loads in rdflib; spot-check counts vs `final_resolved.csv` |
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

## Risks

| Risk | Mitigation |
|---|---|
| `rdflib` dependency + Turtle authoring wall for curators | `ontology/README.md` crib sheet; curators keep editing `vendor_terms.csv`/`keyword_terms.csv` in CSV as today — the ontology holds *classes*, not terms |
| rdflib reserialization churns git diffs | Never reserialize the hand-authored files; `--write` only emits CSVs. If TTL is ever machine-written, sort triples deterministically |
| Reasoner contradicts a published ruling | That is the experiment working. Budget time in Phase 3 to fix facets *or* correct the paper |
| Family assignment looks arbitrary | `rdfs:comment` rationale per family, tied to the existing granularity rule; report per-category numbers alongside families, never instead of |
| Over-claimed SAREF equivalence | `rdfs:subClassOf` only; alignment in a separate droppable file |
| Scope creep into classification | Enforced by the *Circularity boundary* section above |
| Forces 3 open scope calls closed (`ev-charging`/`home-power`, `shades`, smart-display split) | Surface them in Phase 1 as explicit `hiot:provisional` markers; decide before Phase 3 |

## Acceptance criteria

1. `python3 scripts/ontology_build.py --check` exits 0 with `categories.csv` byte-identical.
2. SHACL validation clean: all 27 classes carry 5 criterion facets, a parent, and a sortOrder.
3. Reasoner reproduces all 27 in/out rulings, or every discrepancy is documented and resolved.
4. `cwe888_analysis.py --group family` family totals sum to the per-category total (1,904 as of
   2026-08-04, exclusion applied), and `--include-excluded` reproduces the pre-fix population.
5. No change to `judgment_store.csv`, `final_resolved.csv`, `term_precision.csv`, or
   `recall_estimate.csv` — verified by diff before and after.
```
