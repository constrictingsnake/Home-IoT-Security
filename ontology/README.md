# Home IoT Device Ontology

Formal source of truth for the 24 analysis categories, the 13 supervisor-agreed **folding
categories** above them, and the five definitional criteria from `docs/home_iot_security_report.tex` §`sec:method-scope` /
`CLAUDE.md` § *Definition of a Home IoT Device*.

Design rationale and phasing: `docs/plans/PLAN_ontology.md`.

| File | What it is |
|---|---|
| `homeiot.ttl` | The ontology. **Hand-authored** — edit this, never the generated CSVs. |
| `shapes.ttl` | SHACL constraints. Catches what a reasoner won't (missing facet, duplicate sortOrder, bad slug). |
| `homeiot-align.ttl` | Alignment to SAREF + SSN/SOSA. **Hand-authored.** Separate so a reviewer can evaluate the core without it. |
| `homeiot-kg.ttl` | Instance-level **vocabulary** for the vulnerability knowledge graph. **Hand-authored.** Separate file so nothing about the instance layer can perturb `homeiot.ttl`. |
| `external_classes.tsv` | Pinned manifest of 331 verified external class IRIs. Generated; regenerate only when bumping a vocabulary version. |
| `external_sources.tsv` | Retrieval provenance for the manifest: version, URL, source sha256, date. |

Generated **from** this ontology (do not hand-edit):

| File | Consumed by |
|---|---|
| `data/categories.csv` | 11 scripts + `run_gemini.sh` |
| `data/ontology/families.csv` | `cwe888_analysis.py --group family` (RQ1), and RQ2 |
| `data/ontology/homeiot-kg.ttl` | Nothing in the pipeline — it is an *output*, queried by SPARQL |

## Commands

```bash
python3 scripts/ontology_build.py --check      # validate + prove CSVs unchanged; exit 1 on drift
python3 scripts/ontology_build.py --write      # regenerate categories.csv + families.csv
python3 scripts/ontology_build.py --reason     # 27-class in/out ruling table
python3 scripts/ontology_build.py --align      # verify alignment IRIs + coverage report
python3 scripts/ontology_build.py --export-kg  # rebuild the instance graph, then verify it
python3 scripts/ontology_build.py --verify-kg  # verify the committed graph without rewriting it
```

Requires `rdflib`, `pyshacl`, `owlrl` (`pip install rdflib pyshacl owlrl`).

Run `--check` before committing any edit to `homeiot.ttl`.

## Two invariants you can break by accident

**1. `data/categories.csv` must regenerate byte-identically, row order included.**
`cwe888_analysis.py:249-251` reads its order into `cat_order` and uses that for RQ1 table row
ordering, so reordering silently reorders a published table. `hiot:sortOrder` fixes the order;
SHACL enforces uniqueness. **Never put a comment line in `categories.csv`** — unlike
`keyword_terms.csv` / `vendor_terms.csv` (custom parser, `#` ignored), it is read by
`csv.DictReader`, which would swallow a leading `#` line as the header row.

**2. `skos:scopeNote` reaches AI reviewers.** `gemini_classify.py --scope` injects it into the
classification prompt. The text was *moved* here verbatim from the old hand-authored
`categories.csv` and must never be synthesized from facets — editing it changes reviewer
behaviour and therefore every downstream precision number. See PLAN_ontology.md § *Circularity
boundary*: the ontology must not become a classification input beyond this pass-through.

## Turtle crib sheet

You only need four patterns to curate this file.

```turtle
hiot:cameras a owl:Class, hiot:DeviceType ;   # ← every statement ends in ;  except the last, which ends in .
  rdfs:subClassOf hiot:CamerasMonitorsDevice ; # ← which folding category it belongs to
  hiot:slug "cameras" ;                       # ← quoted string
  hiot:sortOrder 23 ;                         # ← bare integer, no quotes
  hiot:hasConnectivity hiot:wifi, hiot:rtsp ; # ← comma = multiple values for one property
  hiot:actuatesPhysical false ;               # ← bare true/false
  skos:scopeNote """IN: ... OUT: ...""" .     # ← triple quotes hold commas, quotes, newlines
```

- `;` = "same subject, next property". `.` = "end of this block". A missing `.` is the usual
  parse error.
- `,` = "same property, another value".
- Prefixes (`hiot:`, `skos:`, …) are declared once at the top of the file.
- Names with a hyphen in the slug use an underscore in the class name (`hiot:ev_charging`,
  slug `"ev-charging"`) — the slug string is what the pipeline uses.

**Adding a category** is not just a Turtle edit: category membership is frozen (`CLAUDE.md` §
*Finalized Category Scope*), and adding one forces a full chain re-run for it.

## Punning (why each type is both a class and an individual)

Each device type is declared `a owl:Class, hiot:DeviceType`. The class side gives a real
hierarchy (families subclass `hiot:InScopeDeviceType`); the individual side lets the
`hiot:InScopeDeviceType` equivalence axiom actually classify it under OWL-RL. Facet *values*
are individuals, so value groupings use `owl:oneOf` — `owl:unionOf` is over classes and would
produce an axiom no reasoner acts on.

## The reasoner check

`--reason` evaluates the criteria axiom over the asserted facets and compares its verdict to
each type's published placement (in the analysis set, or under `hiot:ExcludedDeviceType`).
All 27 currently agree.

This is a real check, not a tautology — verified by perturbation:

| Perturbation | Result |
|---|---|
| remove every `hasRole hiot:HomeControlSurface` | `streaming` + `smartspeakers` flip to **out** (`hub` survives on 4(a)) |
| give `gameconsoles` `EmbeddedController` + `Control` | flips to **in** |
| move `cameras` to `hasDeployment hiot:Commercial` | flips to **out** |

**What it does not do:** the reasoner automates only what *follows* once facets are asserted.
Deciding that a Fire TV *is* a `HomeControlSurface` remains a human judgment. The ontology makes
that judgment explicit, located, and contestable — not automatic. Do not overclaim this in the
paper.

## External alignment

`homeiot-align.ttl` maps the 24 categories onto SAREF (core, 4BLDG, 4ENER, 4WEAR) and W3C
SSN/SOSA. Three rules:

1. **Never `owl:equivalentClass`.** Our classes are strictly narrower than theirs
   (`hiot:cameras` is residential consumer IP cameras; `saref:Sensor` is any sensor).
   `rdfs:subClassOf` + `skos:broadMatch` is what the relationship actually is, and
   over-claimed alignment is a standard reviewer objection.
2. **Every external IRI is verified** against `external_classes.tsv` before it can be
   committed — `--check` fails otherwise. This is not theoretical: `saref:Multimedia`,
   `saref:WashingMachine`, `saref:Generator` and `sosa:System` are all plausible-sounding
   classes that **do not exist**, and all four were caught this way (negative-tested).
3. **The external vocabularies are not `owl:imports`-ed** — the pipeline runs offline against
   a fixed snapshot. Consequence, stated plainly: no reasoner validates these `subClassOf`
   assertions. They are curatorial claims, checked for IRI *existence* but not semantic
   correctness.

### The coverage finding

**9 of 24 categories (38%) align exactly. 15 of 24 (62%) have no corresponding class in any
of the six vocabularies** and can only sit under a generic `Device`/`Sensor`/`Actuator`/
`Appliance` superclass.

The gap is not random — it falls almost entirely on the consumer security-and-convenience
tier (cameras, doorbells, baby monitors, alarm panels, smart locks, hubs, speakers, streaming
boxes, EV chargers, robot vacuums, pet devices), which is exactly where this study finds the
CVEs. SAREF is precise about meters, HVAC, lighting, shading and appliances — its energy and
building-management origins — and silent about most of what a consumer bought in the last
decade. That is the empirical argument for this ontology, and `--align` recomputes it.

## The knowledge graph (`homeiot-kg.ttl`)

Two files, same split as everywhere else here: `ontology/homeiot-kg.ttl` is the hand-authored
**vocabulary**; `data/ontology/homeiot-kg.ttl` is the **generated instance graph** (63,918
triples, ~4.1 MB) written by `--export-kg`. It holds every confirmed-Yes CVE, the CPE
vendor/product pairs NVD attributes it to, its raw CWEs and their CWE-888 classes, and a reified
category assignment per (CVE, category) pair carrying how that decision settled.

It is an **output**, not an input. Nothing in the pipeline reads it, and it carries no property
that could feed a classifier — see PLAN_ontology.md § *Circularity boundary*. The graph records
settled judgments; it never produces one.

```
hkg:Vulnerability ──affectsProduct──▶ hkg:Product ──vendor──▶ hkg:Vendor
        │  ──hasWeakness──▶ hkg:Weakness ──hasCwe888Class──▶ hkg:Cwe888Class
        │  ──assignment──▶ hkg:CategoryAssignment ──assignedCategory──▶ hiot:DeviceType
        └─ ──affectsCategory────────────────────(shortcut)───────────────┘
```

That last edge is the only one crossing into `homeiot.ttl`, and it is why there is no family
table in the KG: a rollup is answered by the `rdfs:subClassOf` hierarchy already asserted there.

**Three things to know before querying it.**

- **The population is `judgment_store.csv`, not `final_resolved.csv`** — 1,738 non-excluded Yes
  rows vs 1,733. The 5 extra are 2026 CVEs in the store and the snapshot that the derived file
  hasn't picked up. `cwe888_analysis.py` and `cvss_analysis.py` both read the store, so any other
  source would leave the graph permanently out of step with RQ1/RQ2.
- **`hasCwe888Class` hangs off the `Weakness`, not the `Vulnerability`.** RQ1's counting unit is a
  CWE *attribution*, so walk `assignment → vulnerability → weakness → class` — that reproduces
  1,904 exactly. Deduplicating classes onto the CVE undercounts. This is also why the
  1,738-assignment numbers below don't match the 1,904-attribution family table in
  PLAN_ontology.md: different units, both correct.
- **CVSS is base score only.** `download_nvd.py:116-124` discards `vectorString`, so attack
  vector, privileges required, UI and scope are simply not in the snapshot to export.

Minted instances are written as full `<IRI>`s rather than prefixed names — a Turtle local name
may not contain `/`, and joined CPE vendor:product tokens routinely do. The prefixes are still
declared in the file. Output is deterministic (sorted subjects, sorted predicate/object pairs),
so a re-export with unchanged inputs diffs only on the `dcterms:created` line.

### `--verify-kg`

The gate reparses the file in rdflib, then reconciles it against the CSVs it came from: five
instance-class counts, the `affectsCategory` edge count, per-category counts against the
judgment store, the CWE-888 attribution total *computed by SPARQL over the graph* against
`cwe888_cve_map.csv`, and the family rollup via `rdfs:subClassOf` against `families.csv`. It
prints `gate: PASS` or exits 1. Two of the 24 categories (`sleeptracker`, `shades`) and 2 of the
13 families carry no confirmed CVE, so they are reported as absent rather than as a mismatch.

### What it answers that a CSV doesn't

The admission route — which criterion let a category in — lives only in the ontology, and the
CVE counts only in the study data; joining them takes one query:

```sparql
SELECT ?route (COUNT(DISTINCT ?a) AS ?n) (COUNT(DISTINCT ?d) AS ?cats) WHERE {
  ?a hkg:assignedCategory ?d .
  BIND(EXISTS { ?d hiot:hasFunction ?f . VALUES ?f { hiot:Monitor hiot:Automate hiot:Control } } AS ?is4a)
  BIND(IF(?is4a, "4(a) home-control function", "4(b) home-control surface") AS ?route)
} GROUP BY ?route
```

→ 4(a) **1,624** assignments across 20 categories; 4(b) **114** across 2 (`streaming`,
`smartspeakers`). So the contested half of the scope section — entertainment hardware admitted
only because its platform is a home-control surface — accounts for 6.6% of the confirmed corpus.
(Use `COUNT(DISTINCT ?a)`: a category asserts up to three `hasFunction` values, and a plain
`COUNT(*)` multiplies rows by that arity.)

Two more that need the join, both one query each:

- **Review provenance by folding category**, without touching `families.csv` — `?d rdfs:subClassOf
  ?f` does the rollup. Human-settled share ranges from 9% (`Hubs and Controllers`, 22/247) to 39%
  (`Entertainment`, 30/76); the entertainment boundary really is where the reviewers disagreed.
- **Vendors spanning multiple categories** via `affectsProduct` + `affectsCategory` — four span
  four categories: `tp-link` (52 CVEs), `google` (19), `yeelight` (2), `mitsubishielectric` (2).

## Scope calls

`hiot:openScopeCall` marks a boundary still unsettled; `hiot:resolvedScopeCall` records one that
was settled *and the evidence that settled it*, so the paper can cite why the call went the way
it did. Resolved calls are kept, not deleted.

| Call | Outcome (2026-08-04) | Evidence |
|---|---|---|
| `ev-charging` vs `home-power` | **separate** | zero shared confirmed-Yes CVEs (71 vs 45); disjoint vendor term sets, even the two Tesla terms |
| smart displays split from `smartspeakers` | **stay merged** | 2 of 38 Yes rows touch a display; `smart display` scores 48 judged / 0 Yes (prune_candidate) in both term blocks |
| `sleeptracker` | **kept, reclassified** | 0 Yes from 29 judged; terms are correct and fired — see below |
| `shades` merge rule | see below | |

### `hiot:noNvdFootprint` — the third kind of exclusion

Some categories satisfy all five **definitional** criteria but fail the paper's operational
**study-inclusion** criterion ("has a CPE-identifiable footprint in NVD"). That is a weaker and
different exclusion than `hiot:failsCriteria`, which is for types that are not home IoT at all
(game consoles fail criteria 2 and 4).

Such a category **stays** in the ontology and in `categories.csv` — the frozen 24-category scope
and the whole pipeline are untouched — but contributes no rows to RQ1/RQ2. Dropping it instead
would take the scope from 24 to 23 and contradict the paper text. SHACL requires an
`rdfs:comment` recording the evidence, so the marker cannot be used to quietly retire an
inconvenient category.

This is a finding about NVD coverage, not an embarrassment: the device class exists, is in
scope, and is invisible to the vulnerability record.

## Folding categories

The 13 folds are **supervisor-agreed**, not derived — do not re-derive or "improve" them without
taking it back to the supervisors. Two rules are visible in the agreed list and are worth stating
in the paper:

- **Keep categories with a large enough n standalone.** Six folds are singletons for this reason
  (`hub`, `streaming`, `smartspeakers`, `doorlock`, `sleeptracker`, `shades`).
- **Folds do not cross the 4(a)/4(b) admission boundary.** `Hubs and Controllers` (in via 4(a),
  primary home control) stays separate from `Entertainment` and `Audio` (in only via 4(b)) —
  the distinction the paper's scope section is built on.

| Fold | Members |
|---|---|
| Cameras and Monitors | cameras, doorbell, babymonitor |
| Hubs and Controllers | hub |
| Alarms & Sensors | alarms, sensors |
| Entertainment | streaming |
| Electrical & Lighting | smartplugs, lighting |
| Energy | ev-charging, home-power |
| Outdoor & Pet | garden, pet |
| Audio | smartspeakers |
| Appliances | robotvacuum, fridge, appliances |
| Access Control | doorlock |
| Climate & Air | thermostat, airconditioner, fans, airpurifier |
| Sleep | sleeptracker |
| Shades | shades |
