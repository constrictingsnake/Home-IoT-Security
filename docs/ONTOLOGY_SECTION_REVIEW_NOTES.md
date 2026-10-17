# Review notes — "Formalizing the scope as an ontology" (Section III-B)

**Status:** the rewritten section in `home_iot_security_report.tex` carries the author's wording
verbatim. Everything below is a *suggested* correction that was applied once and then **reverted**,
so the paper text is the author's. Each spot is marked in the `.tex` with a `% REVIEW-NOTE n`
comment (invisible in the PDF) that points back to the matching number here.

Verified 2026-09-23 against `scripts/ontology_build.py --check / --self-test / --sources / --verify-kg`
(all four pass) and `ontology/homeiot-align.ttl`, `ontology/external_sources.tsv`.

## Numbers checked and confirmed (no action)

| Claim in the text | Source | Result |
|---|---|---|
| 80,072 triples; 1,676 vulnerabilities; 1,738 category assignments; 4,707 products; 292 vendors; 21 CWE-888 classes | `--verify-kg` | all match |
| 2 of the 24 categories have no confirmed CVE | `--verify-kg` | confirmed |
| 435-IRI pinned manifest | `ontology/external_classes.tsv` | confirmed |
| 13 of 24 (54%) direct study, 10 methodological-only, `streaming` neither | `--sources` | confirmed |
| 14.6% of confirmed CVEs on categories no study examines directly | `--sources` (n=1,738) | confirmed |
| every criterion is load-bearing | `--self-test` | PASS, one boundary type per criterion |
| 13 folding categories over 24 leaves | `--check` | confirmed |

## Reverted suggestions (text currently says what the author wrote)

| # | Author's wording (now in the paper) | Suggested change | Why |
|---|---|---|---|
| 1 | "Our five defined-yet-excluded **criteria** are: a non-networked detector …" | "**types**" | The five items are excluded device types. The criteria are what those types fail. |
| 2 | "We verify this by making sure the reasoner objects if any of the five criteria are not met." | "We verify this by deleting each of the five conjuncts of the membership axiom in turn and requiring the reasoner to object, which it can only do if some defined type fails on exactly that criterion." | As written this describes the weak test (a device that fails a criterion is out), which the paragraph has just called weak. The `--self-test` deletes each conjunct from the *axiom*. |
| 3 | "… so that the published graph is **as accurate as possible**." | "… so that the published graph cannot drift from the files the analysis runs on." | The gate proves the graph matches the judgment store and CWE map. It says nothing about whether those are correct. |
| 4 | "… which are only expressed as **subclass and broader-match** relations, and never as class equivalence …" | "subclass and SKOS match relations (broad, close and related)" | `homeiot-align.ttl` uses `rdfs:subClassOf` (26), `skos:broadMatch` (19), `skos:closeMatch` (8) and `skos:relatedMatch` (19). "Never equivalence" is correct (the only `owl:equivalentClass` hit is a comment saying there is none). |
| 5 | "… with each recorded at **a fixed version and** content hash …" | "… recorded with its retrieval date and content hash, and a version where the vocabulary publishes one …" | In `external_sources.tsv` the three W3C documents (`sosa`, `ssn`, `ssn-systems`) have version `-`: a hash and date only. The nine SAREF documents do have versions. |
| 6 | "Two of the eight yielded nothing in scope, which **was interpreted** as a result." | "Two of the eight **SAREF vocabularies** …" (and "we interpret") | "Eight" is SAREF core plus seven extensions. SSN/SOSA is a separate ninth item, so a reader who counts the list above gets nine. |
| 7 | "… a commercial **HVAC** (3) …" | "a commercial HVAC **controller**" | The ontology boundary type is `commercial-hvac-controller`. |

## Open decisions for the author (not changed)

| # | Item | Detail |
|---|---|---|
| 8 | "Secondly, the ontology layer also records the route of admission, not just the verdict." | The earlier draft followed this with the 4(a)/4(b) split (1,624 vs 114 of 1,738 assignments, 6.6%). The sentence now claims something without saying what. The ontology records the route per *category* (`hiot:hasRole`, criterion 4(b)), not per CVE assignment, so any per-assignment count is derived by category. Either restore the numbers or cut the sentence. |
| 9 | Spelling: "judgement" | The author's text uses "judgement" (7 uses); the rest of the paper uses "judgment" (39 uses). Pick one. |
| 10 | Undefined terms | SAREF, SSN/SOSA, IRI and "pinned manifest" are never defined for the reader. IEEE style expects acronyms expanded at first use. |
| 11 | Style | "Firstly / Secondly / Lastly" (IEEE prefers First / Second / Third); comma splice in "Under this test all five criteria are load-bearing, we report …"; "leads to the paper overstating" could be "would overstate". |

## Mechanical fixes that were kept (formatting only, no change of meaning)

- Section references are `\ref` cross-references, so they render as Roman numerals and cannot
  go stale: "6-A" → VI-A (`sec:threats-construct`), "4" → IV (`sec:rq1`), "#-E" → III-E
  (`sec:method-precision`), "4-5" → IV–V.
- Hardcoded citations `[50]`–`[53]` are `\cite{saref}`, `\cite{saref4bldg}`, `\cite{saref4ext}`,
  `\cite{ssn2017}`; they render as [50]–[53].
- Typos: "axion" → "axiom", "by constructions" → "by construction". "machine readable" hyphenated.
- Thousands separators (`80{,}072`), `\texttt{}` for file/class names, "criteria 1-5" → `1--5`,
  "Criterion 1" → `criterion~1`, curly quotes around streaming replaced by `\texttt{streaming}`.
- The placeholder line "Descriptive facets?" is replaced by the old facets paragraph, verbatim,
  inside a red WORK IN PROGRESS marker (`\wipbegin` / `\wipend` in the preamble).
- The red `\stub` note now sits below this section, and says the facets block is excepted.

## To apply any suggestion

Edit the marked sentence in `home_iot_security_report.tex` (search `REVIEW-NOTE n`) and delete the
comment line. Rebuild with `tectonic -X compile home_iot_security_report.tex`.
