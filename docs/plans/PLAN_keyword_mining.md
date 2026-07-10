# Plan — Keyword Mining from Confirmed-Yes Descriptions

**Goal:** systematically extract device-type phrases that appear in confirmed-Yes CVE
descriptions but are missing from `data/keyword-search/keyword_terms.csv`, ranked by how many
*new* snapshot CVEs each phrase would pull. This is the systematic version of what
`03_keyword_additions.md` does anecdotally per category.

**Output is a candidate list for a human to vet — this script never edits `keyword_terms.csv`.**

**Convention guard (from CLAUDE.md):** `keyword_terms.csv` holds device-type **phrases only** —
no brands, protocols, firmware names, or umbrella terms. Brand-like candidates must be filtered
out and routed to the vendor-mining candidate list instead (see
`docs/plans/PLAN_cpe_brand_mining.md`).

## New script: `scripts/keyword_mining.py`

### Inputs

| File | Schema | Role |
|---|---|---|
| `data/difference/final_resolved.csv` | has `Category, cve_id, description, cpe_strings, Final Judgment` (Yes/No) | labelled corpus (6,773 rows) |
| `data/keyword-search/keyword_terms.csv` | `slug,term` | existing terms to exclude |
| `data/nvd-snapshot/nvd_all.csv` | `cve_id,published,description,...,cpe_strings` | new-yield scoring |
| `data/keyword-search/keyword_<cat>.csv`, `data/vendor-search/results_all_<cat>.csv` | | "already known" per category |
| `scripts/cve_search.py` | `filter_by_keywords` | **matching semantics — reuse, don't reimplement** |

**Important:** read `scripts/cve_search.py` first and reuse its `filter_by_keywords` (with
`whole_word=True`, description + CPE matching) for the new-yield step, so a candidate's yield
is measured with *exactly* the semantics the real pipeline will use. If the space↔underscore
CPE-matching fix (space matches `[ _]`) has been applied there, mining inherits it for free.

### Algorithm

**Step 1 — build per-category labelled doc sets.** From `final_resolved.csv`: for each
category, `yes_docs` (Final Judgment == Yes) and `no_docs` (== No), descriptions lowercased.
Pool across all directions. Skip categories with < 5 Yes rows (nothing to learn).

**Step 2 — candidate n-gram extraction.** From `yes_docs` only, extract word 1–3-grams.
Tokenize on non-alphanumerics but keep internal hyphens (`z-wave`, `wi-fi`). Filters, in order:
1. Drop n-grams containing a stopword-only edge token (the/a/of/in/and/for/with/via/an/to/is).
2. Drop CVE boilerplate: any n-gram matching a small embedded deny list — `buffer overflow`,
   `remote attacker(s)`, `cross-site scripting`, `sql injection`, `denial of service`,
   `arbitrary code`, `command injection`, `authentication bypass`, `firmware version`,
   `web interface`, `admin(istrative) interface`, `default password`, version-number patterns,
   pure CWE language. Expect to grow this list on the first run — make it a module-level set.
3. Drop n-grams already covered by an existing `keyword_terms.csv` term for that slug
   (normalized casefold; drop if the candidate contains an existing term or vice versa).
4. **Brand filter:** drop any n-gram containing a token that appears as a CPE *vendor* in the
   snapshot with ≥ 3 CVEs (build the vendor-token set in the same snapshot pass as Step 4, or
   from `data/nvd-snapshot/nvd_all_stats_top_vendor_product.csv` if it has enough coverage).
   Write dropped brand-ish candidates to a side file `keyword_candidates_brands.csv` so they
   feed the vendor-mining vet instead of being lost.

**Step 3 — discriminativeness score.** For each surviving candidate `t` in category `c`:
`n_yes` = Yes docs containing `t` (whole-word), `n_no` = No docs containing `t`.
Score = `n_yes * log((n_yes + 0.5) / (n_no + 0.5))`. Keep the top ~50 per category by score
with `n_yes ≥ 3` and `n_yes > n_no`. This is deliberately simple — the human vet and the
new-yield numbers do the real filtering; don't add ML.

**Step 4 — new-yield scoring (one snapshot pass).** For each kept candidate, run it through
`filter_by_keywords` semantics against the snapshot; `new_yield` = matches not already in that
category's known set (union of `keyword_<cat>.csv` + `results_all_<cat>.csv` cve_ids — same
logic as `cpe_expansion.load_known_cve_ids`, import it). Record:
- `new_yield` count and up to 3 sample `(cve_id, description[:150])` from the new matches,
- `pct_device_cpe` — fraction of new matches whose `cpe_strings` include a `part ∈ {o,h}` CPE
  (reuse `cpe_expansion.parse_cpe`). Low values (< ~30%) signal the phrase mostly matches
  software, a likely FP bomb.

Performance note: score all candidates in one snapshot pass (build a combined term→categories
map, stream rows once), not one pass per term — the snapshot is 360k rows.

### Output

`data/keyword-search/keyword_candidates.csv`, per category sorted by `new_yield` desc:

```
category,phrase,n_yes,n_no,score,new_yield,pct_device_cpe,sample_cves,sample_descriptions
```

Plus `data/keyword-search/keyword_candidates_brands.csv` (brand-filtered candidates:
`category,phrase,reason_vendor_token`).

### CLI

```
python3 scripts/keyword_mining.py --all
python3 scripts/keyword_mining.py streaming hub          # subset
python3 scripts/keyword_mining.py --all --top 50 --min-yes 3
```

## Human workflow after the script

1. Vet `keyword_candidates.csv` — accept only genuine device-type phrases; add as `slug,term`
   rows to `keyword_terms.csv`.
2. Re-run the keyword search + set-ops for affected categories (README), then
   `make_review_copies.py <cat> --refresh`; the judgment store means only new rows get reviewed.

## Acceptance checks

- No candidate equals or contains an existing `keyword_terms.csv` term for its slug.
- No candidate contains a known brand token (spot-check: `hikvision`, `tapo`, `ring` should
  never appear in the main output; brand-ish ones land in the `_brands` side file).
- Boilerplate like `buffer overflow` / `web interface` absent from output.
- Categories with < 5 Yes rows are skipped with a console note, not errored.
- Spot-check plausibility: `cameras` should surface phrases like `network video recorder`
  variants or `ptz camera` if not already terms; each candidate's samples read as devices.
- Script is read-only outside the two candidate CSVs.
