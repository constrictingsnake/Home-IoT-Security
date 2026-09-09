---
name: paper-section
description: Use this skill when the user names a section of the paper (docs/home_iot_security_report.tex) — Abstract, Introduction, Related Work, Methodology, RQ1, RQ2, RQ3, Threats to Validity, Lessons Learned, Conclusions, Data Availability — and asks what to write in it, what goes there, for an outline, for help drafting it, or what evidence supports it. Produces an annotated map of the section — topics, connective commentary, verbatim quotes, works cited with links and verification status, and blockers. It never produces prose for the paper.
version: 0.1.0
---

# Paper Section Map

Maps one section of `docs/home_iot_security_report.tex` against the actual state of this
repository, so the author can write it. **The author writes the prose. This skill does not.**

## The output contract

Everything emitted sits in exactly one of three registers, and they are never blended:

1. **Ledger** — claims as telegraphic fragments. Noun phrases, `→`, `·`, no finite-verb
   sentences. `cameras = 52% of attributions · dominance ≠ recurrence`.
2. **Commentary** — written *about* the paper, addressed to the author in second person.
   "Your reviewer will push here." "The trap is that §II already argues this."
   Explains how pieces fit, where the argument load sits, what a claim licenses downstream.
3. **Quotes** — verbatim, attributed, with a locator. These *are* meant to be used, as quotes.

**The paste test.** Before emitting any line, ask: could this be pasted into the `.tex` with no
edits and read as the author's own writing? If yes, it is a contract violation — rewrite it as a
fragment, or lift it into commentary by addressing the author.

Specifically never emit: a topic sentence, an abstract sentence, a title, a transition
(`However`, `Moreover`, `In this paper`), or anything in the paper's voice (`We present`,
`Our results show`, `This section describes`).

If the user asks for actual prose, say once — briefly — that this skill is built not to produce
it, and offer to critique prose they have written instead. If they ask again, that is their
call: write it, outside this format, and don't re-litigate.

---

## Step 1 — Locate the section and classify its state

`grep -n 'section{' docs/home_iot_security_report.tex`, then read the section body plus its
immediate neighbours. Classify and state the verdict up front:

| state | meaning | consequence |
|---|---|---|
| **EMPTY** | body blank (Abstract, Introduction, Lessons Learned, Conclusions as of 2026-09) | full map |
| **CURRENT** | prose in sync with the derived data | map what is missing/weak, not what exists |
| **STALE** | prose written against a superseded vintage | the fix list *is* the map; name each wrong figure |
| **GENERATED** | inside a `BEGIN GENERATED` block (lines ~568–691) | **never outline content here** — it comes from `generate_cwe888_table.py` / `generate_cwe888_treemaps.py`. Report and move on. |

Two dataset vintages are currently mixed in the tex. Never assume a section is current because
its neighbour is.

## Step 2 — Read the standing state before assembling anything

In order, every time:

1. **`docs/plans/PLAN_paper_submission_fixes.md`** — the audited defect list, organised by tex
   section. Anything it records for this section is either a blocker or a required fix and must
   surface in the "Before you write" footer. This is the single highest-value read.
2. **`references/guardrails.md`** (in this skill) — retracted figures and known-bad citations.
   Non-negotiable; check every number and every key against it.
3. **`CLAUDE.md`** — design rationale for whatever the section covers, and the authoritative
   home of the retraction notices. If it disagrees with `guardrails.md`, CLAUDE.md wins and
   `guardrails.md` should be updated.
4. **Adjacent tex sections** — to find overlap. Duplicated argument across sections is a real
   defect; when a beat belongs elsewhere, say so under *Belongs in another section*.
5. **`git log --oneline -15`** and any `docs/plans/PLAN_*.md` with an open STATUS block touching
   this section's subject matter.

`docs/RESULTS.md` is a useful secondary read but is prose, not a source of truth — a derived CSV
outranks it.

## Step 3 — Numbers

**Do not invoke the `kg-research` skill and do not write new analysis scripts.** This skill reads
tracked, derived files. The one script it may run is `scripts/ontology_build.py` with a read-only
gate flag (`--check` / `--self-test` / `--sources` / `--verify-kg`), and only when the section's
claims depend on gate status.

Every number carries the file it came from. Source of truth by type:

| number | file |
|---|---|
| snapshot date / record count | `data/nvd-snapshot/SNAPSHOT.md` |
| review totals, judgments, reviewer agreement, FP rates | `data/difference/judgment_store.csv` |
| per-CVE final labels | `data/difference/final_resolved.csv` |
| CWE-888 distribution / attributions | `data/difference/cwe888_distribution.csv`, `cwe888_cve_map.csv` (+ `_family`) |
| CVSS scores, severity, Kruskal–Wallis + Dunn | `data/difference/cvss_distribution.csv`, `cvss_severity.csv`, `cvss_dunn_pairwise.csv`, `cvss_matrix.md` |
| CVSS vectors (RQ3) | `data/difference/cvss_vectors.csv`, `cvss_vector_matrix.md` |
| recall estimates | `data/difference/recall_estimate.csv` |
| term precision / prune candidates | `data/difference/term_precision.csv` |
| facet validity (Phase A modal shares) | `data/facets/facet_distribution.csv` |
| facet reliability (Fleiss' κ) | `data/facets/facet_agreement.csv` |
| facet sourcing / coverage | `data/facets/facet_store.csv`, `data/facets/source_coverage.csv` |
| categories, scope notes | `data/categories.csv`, `data/ontology/families.csv` |

Rules:

- **Never launder a number.** A figure that exists only in a plan doc, a commit message, or older
  tex prose is `⚠️ unverified` — quote it with that mark and name the file that would settle it.
  `PLAN_paper_submission_fixes.md` is a fix list, not a measurement.
- **A tex/CSV disagreement is itself a finding.** Report both values, say which is authoritative,
  and put it in the footer.
- **Small N.** Six categories sit at N≤5. Before reporting a per-category percentage, check
  `data/ontology/families.csv` and give the folded family figure alongside.
- **Label the tier.** Anything Estimated-provenance (all 496 facet assertions), anything below a
  κ or Phase A threshold, and anything the guardrails flag is organising structure — not evidence.

## Step 4 — Quotes

Verbatim only, from something actually opened **in this session**.

- **Repo / tex quotes**: quote with `path:line`. Safe and cheap — prefer these.
- **External literature**: WebFetch the DOI, publisher page, or arXiv abstract first, then quote
  with a locator. If it cannot be fetched, emit the placeholder and stop:
  `⚠️ needs fetching from <url> — not opened in this session`.
- **Never reconstruct a quote, author list, venue, or DOI from memory.** Five of five
  spot-checked bibliography entries in this paper were drafted from memory and all five were
  wrong (`PLAN_paper_submission_fixes.md` §3). That is the failure mode this rule exists for.

## Step 5 — Works cited

- A key is only usable if it appears in `\begin{thebibliography}` (~line 1137). Otherwise mark
  `🔴 NEW-ENTRY-NEEDED` and give what is known plus the link to verify against.
- Cross-check `ontology/study_sources.tsv` — its `verified=no` rows have a real title from the
  team's dossier but **unconfirmed** authors/venue/year. Carry that status into the table.
- Check every key against the known-bad list in `references/guardrails.md`. A key that needs
  fixing gets `⚠️` plus the correction, in the table, not in a footnote.
- Prefer DOI links; publisher/USENIX/arXiv landing page otherwise.

## Step 6 — Emit

```markdown
# §<N> <Section Name> — annotated map
*State: EMPTY | CURRENT | STALE  ·  tex lines <a>–<b>*

## How this section fits
<commentary: the section's job in the argument, its relationship to neighbours,
 the main structural trap, what the reader must already accept by the time they arrive>

## Topic 1 · <short fragment naming the beat>
**Beats:** <fragment · fragment · fragment>
**How it connects:** <commentary — what this licenses downstream, where the load sits,
 what a reviewer does with it>
**Quote — <source>** (`path:line` or fetched URL):
> <verbatim>
**Evidence:** <file / script>
**Cite:** `key` · `key`

## Topic 2 … N  (same shape; 3–6 topics is the normal range)

## Belongs in another section
<beats that would duplicate a neighbour, with the section that owns them>

## Tensions and open arguments
<commentary: where the evidence is contested, where two repo sources disagree,
 where the honest claim is weaker than the tempting one>

## Works cited
| key | reference | link | status |

## Before you write this section
1. <blocker — from PLAN, guardrails, or a tex/CSV disagreement>
```

Include `🚫 do not cite` / `🔴 blocked` / `⚠️ verify` markers inline wherever they apply — a
guardrail buried in a footer gets missed.

## Anti-patterns

- Emitting a sentence the author could paste. The single failure that makes this skill useless.
- Reading a number from `PLAN_paper_submission_fixes.md` and presenting it as measured.
- Outlining content for a `BEGIN GENERATED` block.
- Restating a neighbouring section's argument instead of flagging the overlap.
- Citing a retracted figure, or a corrected-but-not-yet-fixed bibliography key, without its mark.
- Padding to 6 topics when the section has 3.
- Reporting a per-category percentage at N≤5 without the folded family figure.
- Delegating to `kg-research` or writing a new analysis script for a number.
