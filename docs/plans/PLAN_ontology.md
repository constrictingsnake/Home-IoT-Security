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

Numbers below are from **live** `data/difference/cwe888_distribution.csv` (verified 2026-08-04),
N = CWE attributions. Note the committed `tab:cwe888-matrix` in `report.tex` is **stale**
(N=2,879 over 20 category rows vs. live N=3,259 over 22) — regenerate via
`scripts/generate_cwe888_table.py` before submission, independent of this plan.

| | N | share |
|---|---|---|
| `streaming` | 1,791 | **55.0%** |
| `cameras` | 883 | 27.1% |
| `hub` | 109 | 3.3% |
| `alarms` | 86 | 2.6% |
| …18 more rows | 390 | 12.0% |
| **All** | **3,259** | |

Two structural defects follow:

1. **The `All` row is largely the `streaming` row.** `streaming`+`cameras` = **82%** of
   attributions, so the overall class distribution is dominated by two categories and any claim
   about "home IoT devices" from that row is mostly a claim about streaming platforms.
2. **Six categories have N ≤ 5** and are published as percentages: `sensors` N=2,
   `airpurifier` N=2, `appliances` N=3, `fans` N=4, `fridge` N=4, `airconditioner` N=5. A cell
   reading "Channel 100%" on N=2 is two attributions rendered as a finding. These rows cannot
   support the per-category discussion the `\stub` at `report.tex:493` requests.

Family rollup (sums to exactly 3,259 — verified against live data):

| Family | Members | N | largest member | its share of family |
|---|---|---|---|---|
| Media & Control Surfaces | streaming, hub, smartspeakers | 1,932 | streaming 1,791 | 93% |
| Security & Access | cameras, alarms, doorlock, doorbell, babymonitor, sensors | 1,052 | cameras 883 | 84% |
| Domestic & Chores | pet, robotvacuum, garden, appliances, fridge | 114 | pet 49 | 43% |
| Energy | home-power, ev-charging, smartplugs | 101 | ev-charging 38 | 38% |
| Fixtures | lighting, shades | 31 | lighting 31 | 100% |
| Climate & Air | thermostat, airconditioner, airpurifier, fans | 29 | thermostat 18 | 62% |
| Wellness | sleeptracker | 0 | — | — |

### What the hierarchy does and does not fix (be precise about this in the paper)

**Fixes the tail.** Climate & Air pools 2+4+5+18 → 29; Energy pools 28+35+38 → 101; Domestic &
Chores pools 3+4+24+34+49 → 114. That makes **12 of 24 categories** reportable that individually
are not, and it is the direct answer to defect 2.

**Does not fix the head.** Media & Control Surfaces is 93% `streaming` and Security & Access is
84% `cameras` — the concentration simply moves up one level. Rolling up alone does **not** cure
defect 1, and claiming it does would be indefensible.

**Defect 1 needs a second, orthogonal fix: macro-averaging.** Report the overall profile two
ways — attribution-weighted (micro, what exists today) and unweighted mean of per-unit profiles
(macro), at both category and family level. The micro/macro gap *is* the finding: it quantifies
how much of "home IoT vulnerability distribution" is really streaming. The ontology's
contribution here is supplying the family level at which macro-averaging is meaningful; the
averaging itself is arithmetic and carries no ontological commitment. Both must be reported
together, never one instead of the other.

---

## Scope — what this does and does not do

**Does:**
- Formalize criteria 1–5 as OWL axioms over a facet vocabulary.
- Add a 6-family (+1 provisional) hierarchy over the 24 frozen leaf categories.
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

Root `hiot:HomeIoTDeviceType`, 7 families, 24 in-scope leaves, 3 defined-but-excluded classes.

```
HomeIoTDeviceType
├── SecurityAccessDevice     cameras, doorbell, babymonitor, alarms, sensors, doorlock
├── ControlSurfaceDevice     hub, smartspeakers, streaming
├── ClimateAirDevice         thermostat, airconditioner, airpurifier, fans
├── EnergyDevice             home-power, ev-charging, smartplugs
├── DomesticChoresDevice     appliances, fridge, robotvacuum, garden, pet
├── FixtureDevice            lighting, shades
└── WellnessDevice           sleeptracker            [provisional — see below]

ExcludedDeviceType (defined, not in the analysis set)
├── GameConsole              fails criteria 2, 4
├── VRARHeadset              fails criteria 2, 4
└── TransportNetworking      fails criterion 4 (plain routers, modems, ONT, switches)
```

`WellnessDevice` is a singleton flagged `hiot:provisional true` — `sleeptracker` is ~88%
wrist wearables (out by criterion 3) with essentially no bedside monitors and is pending a
rebuild that may drop it (`CLAUDE.md` § Open scoping note). Encoding the provisional status is
better than hiding it; if the category is dropped, the family goes with it.

**Family assignment is a judgment call and must be defensible per leaf.** The rule mirrors the
existing granularity rule: leaves share a family when they share a *primary function*, not a
brand set. `sensors` sits under Security & Access (motion/contact/leak feed alarm systems, and
its brand set overlaps `alarms`), not under Climate, despite temperature sensors existing.
Record the rationale as `rdfs:comment` on each family.

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

| Target | Use | Predicate |
|---|---|---|
| SAREF (ETSI) | `saref:Device`, `saref:Sensor`, `saref:Actuator`, `saref:Appliance` | `rdfs:subClassOf` |
| SAREF4ENER | Energy family | `rdfs:subClassOf` |
| W3C SSN/SOSA | `sosa:Sensor`, `sosa:Actuator`, `sosa:Platform` (hubs) | `rdfs:subClassOf` |
| CWE / CPE / CVE | existing NVD/MITRE identifiers, reused not redefined | `dcterms:references` |

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
| 2 | `families.csv`; `--group family` + micro/macro rows in `cwe888_analysis.py` + `cvss_analysis.py` | family N's sum to 3,259; per-category output byte-unchanged |
| 3 | `homeiot-align.ttl`; reasoner validation of all 27 rulings | reasoner matches published rulings, or discrepancies documented |
| 4 | KG export (`--export-kg`): confirmed-Yes CVEs, CPE vendor/product, CWE-888 classes as instances | loads in rdflib; spot-check counts vs `final_resolved.csv` |
| 5 | Paper edits | below |

Phase 1 changes no behaviour at all — it only proves the ontology can reproduce the current
file. Do not proceed to Phase 2 until `--check` is green.

### Phase 5 — paper integration

- §`sec:method-scope` — keep the prose; add the ontology as its formal counterpart + artifact cite.
- §`sec:rq1` — regenerate the stale `tab:cwe888-matrix` first (N=2,879→3,259, 20→22 rows); add
  the family-level rollup table; report the overall profile **both** micro- and macro-averaged,
  and make the gap between them an explicit finding about streaming/camera dominance.
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
4. `cwe888_analysis.py --group family` family totals sum to the per-category total (3,259 as of
   2026-08-04); the existing per-category output is byte-unchanged by the new flag.
5. No change to `judgment_store.csv`, `final_resolved.csv`, `term_precision.csv`, or
   `recall_estimate.csv` — verified by diff before and after.
```
