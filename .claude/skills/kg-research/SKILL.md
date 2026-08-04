---
name: kg-research
description: Use this skill when asked a research question about the home IoT vulnerability knowledge graph — CVE counts, category comparisons, CWE/weakness patterns, disclosure trends over time, vendor exposure, CVSS severity, or anything shaped like "what does the data say about X" over the confirmed-Yes dataset. Also use it when deciding whether a number is safe to cite in the paper.
version: 0.1.0
---

# KG Research

Answers open-ended research questions over the confirmed-Yes home IoT vulnerability dataset by
querying `ontology/homeiot.ttl` + `data/ontology/homeiot-kg.ttl` through `scripts/kg_queries.py`,
instead of writing a new one-off analysis script per question. Read that script's module
docstring for the full command reference before using it.

## Before answering anything: staleness check

The KG is a generated snapshot (`scripts/ontology_build.py --export-kg`), not a live view. Run
`python3 scripts/kg_queries.py run class-counts` and compare the `CategoryAssignment` count
against the confirmed-Yes row count in `data/difference/judgment_store.csv` (`Final Judgment ==
Yes`, not `Excluded`). A gap means new judgments haven't propagated to the KG yet (a known,
normal lag — e.g. 1,738 in the KG vs 1,733 in `final_resolved.csv` at one point, from 5 CVEs not
yet exported). If the gap looks larger than a handful of rows, say so before answering, and
suggest `--export-kg` to refresh.

## How to answer

1. **Reach for `scripts/kg_queries.py` in this order**: a canned query (`list` then `run <name>`)
   before an ad hoc query (`sparql "SELECT ..."`) before writing a new script. If a question
   needs the two heavier analyses, use `weakness-fingerprint` (CWE-888 fingerprint vs. an
   NVD-wide baseline, chi-square tested) or `cves-by-year` (per-category disclosure trend, cut
   off at 2024 for the NVD enrichment backlog — see the script's docstring for why).
2. **Chain**: don't stop at the first headline number if an obvious follow-up would sharpen it —
   drill into the category that stands out, check whether the difference is significant, check
   who actually judged those rows. A one-shot answer to a multi-part question is a weaker answer.
3. **If the same ad hoc question is likely to come up again**, add it to the `QUERIES` dict in
   `kg_queries.py` instead of re-deriving it next time. That's what keeps this from turning back
   into a pile of one-off scratch scripts.
4. **Cite provenance with every number**: which query produced it, the snapshot date
   (`snapshotDate` in the KG header), and — for a per-category count — the `judgment-source`
   mix for that category (`judgment-source-by-category`). A number rich in `human`-settled rows
   carries different weight than one that's mostly `ai-consensus`, and the reader should know
   which.
5. **Fold small categories.** Six of the 24 categories sit at N≤5. Before reporting a raw
   percentage for a small category, check `data/ontology/families.csv` and report the folded
   family number alongside it (or instead of it) — this is the entire reason the fold hierarchy
   exists.
6. **Know when to defer instead of approximating.** For anything that needs paper-grade
   statistical rigor — Kruskal-Wallis + Dunn's post-hoc (`scripts/cvss_analysis.py`), Chapman
   capture-recapture recall estimation (`scripts/recall_estimate.py`) — point at the real script
   rather than eyeballing an equivalent via SPARQL. This skill is for exploration and triage, not
   a replacement for the project's audited statistics. Likewise, `scripts/cwe888_analysis.py` is
   not redundant with the KG's weakness data — it's the *producer* of `cwe888_cve_map.csv`,
   which `--export-kg` reads to build `hasWeakness`/`hasCwe888Class`. Never suggest retiring it.
7. **Label exploratory vs. citable.** If an answer came from a quick ad hoc SPARQL chain rather
   than a reviewed script, say so, so it doesn't silently end up quoted in `docs/RESULTS.md` or
   the paper as if it had the same rigor as a Kruskal-Wallis result.

## Hard boundary — do not cross

**Never use ontology facets (`hasFunction`, `hasRole`, `actuatesPhysical`, `capturesAV`, etc.)
or KG structure to produce or suggest a Yes/No/Maybe judgment for a specific CVE.** This is the
"circularity boundary" documented in `docs/plans/PLAN_ontology.md` — facets were assigned once,
by construction, when the 24 categories were frozen; they operate at the category level and
carry zero information about the actual hard call in Stage 4 review (is this specific CPE string
a real member of the category, or a brand collision). Deriving judgments from them would make
`term_precision.csv` self-confirming — the same failure mode `PLAN_deterministic_preclassifier.md`
already had to guard against for its own rule-based auto-decisions. This skill only answers
aggregate research questions over already-settled data. It never touches Stage 4 review, never
proposes a judgment, and never edits `judgment_store.csv`.
