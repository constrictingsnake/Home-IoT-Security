# Facet Annotation Kit

**Run your annotator with THIS DIRECTORY as its working directory**, not the repo
root. That is what keeps the annotation blind: the repo's `CLAUDE.md` states the
prior facet results outright, and opening it before answering would hand you the
conclusions this exercise exists to test independently.

## What to do

1. Read `FACET_ANNOTATION_PROMPT.md` — the rubric. All annotators follow it.
2. Read `VALUE_DEFINITIONS.md` for each facet before answering it the first time.
3. Fill `Value`, `Confidence`, and `Reasoning` in your own CSV. Touch no other file.

## Files

- `claude.csv` — FULL sample, 3264 rows
- `codex.csv` — kappa subsample, 480 rows
- `gemini.csv` — kappa subsample, 480 rows

The subsample is 40 devices shared by all three annotators; agreement
is computed on those rows. The full sample carries the distribution estimate.

You will see only your own columns. That is deliberate and structural — another
annotator's answer is not withheld by policy, it is absent from the file.

## Do not

- Do not look up CVE descriptions, CWEs, or CVSS scores for these devices.
- Do not look up the ontology's current value for any facet.
- Do not adjust an answer toward what the category's answer 'should' be.

## CONTAMINATION — disclose this, do not claim it away

Claude carries the full sample here as a deliberate choice: Gemini is the
documented weakest annotator and over-includes, and no Claude API path exists,
so the full sample is filled in-session. The cost is that **Claude also authored
the prior facet assignment and the value definitions in this kit.** Running from
this directory drops `CLAUDE.md` and the memory index, which closes the *context*
channel — it does not close the *weights* channel. It is the same model that
produced the prior.

Two things follow, both mandatory:

1. **Use a FRESH session started in this directory.** A session that helped build
   the kit has read the definitions, argued the boundary calls, and seen the
   design intent. That is strictly worse than a cold start and costs nothing to
   avoid.
2. **State the residual in the paper.** Claude's column is not an independent
   reading of the prior; it is a re-reading by the same model under a rubric.
   Report it as such. Gemini's column is the one structurally free of this,
   which is a reason to weigh its dissent more here than on CVE review.
