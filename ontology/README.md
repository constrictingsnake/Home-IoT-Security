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
| `external_classes.tsv` | Pinned manifest of 331 verified external class IRIs. Generated; regenerate only when bumping a vocabulary version. |
| `external_sources.tsv` | Retrieval provenance for the manifest: version, URL, source sha256, date. |

Generated **from** this ontology (do not hand-edit):

| File | Consumed by |
|---|---|
| `data/categories.csv` | 11 scripts + `run_gemini.sh` |
| `data/ontology/families.csv` | `cwe888_analysis.py --group family` (RQ1), and RQ2 |

## Commands

```bash
python3 scripts/ontology_build.py --check    # validate + prove CSVs unchanged; exit 1 on drift
python3 scripts/ontology_build.py --write    # regenerate categories.csv + families.csv
python3 scripts/ontology_build.py --reason   # 27-class in/out ruling table
python3 scripts/ontology_build.py --align    # verify alignment IRIs + coverage report
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

## Open scope calls

`hiot:openScopeCall` marks boundaries not finally settled: `ev-charging`/`home-power`, `shades`,
and the `smartspeakers` smart-display split. `hiot:provisional` marks `sleeptracker` (and with
it the single-member `Sleep` fold), pending rebuild. Per PLAN_ontology.md these must be
resolved before the Phase 3 reasoner validation is treated as binding.

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
