---
name: kg-discovery-triage
description: Use this skill when asked why a device category has low CVE coverage or recall, to find new vendor/keyword/product candidates for a category, or to decide which categories need search-term attention next. Orchestrates the existing discovery scripts (cpe_brand_mining.py, keyword_mining.py, cpe_product_scan.py) and triages their output — it never edits vendor_terms.csv or keyword_terms.csv itself.
version: 0.1.0
---

# KG Discovery Triage

Automates the *scheduling and triage* work a human currently does by hand around the project's
three discovery-mining scripts — it does not replace the scripts, and it never accepts a
candidate on its own. See `CLAUDE.md` §"Automated vendor/keyword discovery" for the full design
rationale behind each miner before using this skill.

## Workflow

1. **Find the target category.** Read `data/difference/recall_estimate.csv` for low-recall
   categories, or take a category the user names directly.

2. **Check for a rebuild gap before assuming a real coverage gap.** The single biggest lever
   historically has been *unrealized approved terms* — `build_search` skips regenerating outputs
   that already exist, so an already-accepted vendor/keyword term can sit unused for a long time
   if the category's search output was never rebuilt. Before running a miner, check whether the
   category's `data/vendor-search/` / `data/keyword-search/` outputs are stale relative to
   `vendor_terms.csv` / `keyword_terms.csv`. If they are, say so and recommend a rebuild first —
   it's cheaper and higher-yield than finding brand-new vendors.

3. **Pick the miner(s) that fit the gap** and run them scoped to the category:
   - `scripts/cpe_brand_mining.py` — new vendors, mined from the CPE vendor field.
   - `scripts/keyword_mining.py` — new device-type phrases, mined from Yes-CVE descriptions.
   - `scripts/cpe_product_scan.py` — new product tokens, mined from the CPE product field.
   Run more than one if the category's gap isn't obviously one kind of term.

4. **Read the resulting candidates file** (`vendor_candidates.csv` / `keyword_candidates.csv` /
   `product_candidates.csv`) including the risk flags each script already computes (mega-vendor,
   known-fp-bomb, dictionary-word, broad-token, non-consumer-vendor, pro-surveillance for
   cameras). Do not re-derive these flags — they're already sourced from `term_precision.csv`
   and the shared device-CPE-granularity guardrails.

5. **Summarize, don't just dump the CSV.** Report: candidate count, how many are risk-flagged
   and why, and a prioritized subset worth reviewing first (high `new_yield`, low
   `snapshot_total`-vs-yield gap, no risk flags). Surface cross-slug coverage notes (a vendor
   already added under a different category) as a "you may already have this" flag — it's a
   useful signal, not a disqualifier.

6. **Stop there.** Point at the candidates file and the prioritized list; do not draft an edit to
   `vendor_terms.csv`/`keyword_terms.csv`/`cpe-product-tokens.csv`, even as a suggestion to
   copy-paste. Accepting a term is a judgment call the project deliberately keeps human — say so
   if asked to go further.

7. **Optional closing-the-loop step**: if the human has already accepted terms and rerun the
   pipeline, report the yield/precision delta (before/after counts, any new `term_precision.csv`
   rows for the added terms) so they can see whether the addition actually helped.

## Hard boundaries — do not cross

- **Never write to `vendor_terms.csv`, `keyword_terms.csv`, or `cpe-product-tokens.csv`.** These
  are hand-authored and human-reviewed by design (`CLAUDE.md`: "candidates are never
  auto-included... accepting a vendor is a judgment call, not an idempotent step").
- **Never invoke `pipeline.py refresh` or `pipeline.py settle`.** The discovery scripts are
  deliberately not chained into either for the same reason.
- **Never touch `data/difference/judgment_store.csv` or any Stage 4 review file.** This skill
  operates purely on the search-method side (the green side of the pipeline), not the
  confirmed-Yes review side — see the `kg-research` skill for that.
