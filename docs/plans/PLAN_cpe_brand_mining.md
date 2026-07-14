# Plan — CPE-Dictionary Brand Mining (automated vendor discovery)

*Status: **Implemented 2026-07-09** — `scripts/cpe_brand_mining.py`, wired into
`scripts/pipeline.py` as `discover-vendors` (not chained into `refresh`/`settle` — accepting a
candidate is a human decision). Rationale in `CLAUDE.md` § Automated vendor discovery, commands
in `README.md`, flag table in `docs/SCRIPTS_REFERENCE.md`. This doc remains the algorithm
reference. Acceptance checks verified against the live snapshot: already-covered vendors
(growatt/aqara/shelly/fibaro) correctly excluded, `moxa`/cameras surfaces zero evidence,
mega-vendors (cisco/google/tp-link/qualcomm/redhat) correctly flagged rather than silently
included, no `GENERIC_PLATFORM_CPES` entry seeds a candidate.*

**Goal:** surface CPE vendors that make devices in our 24 categories but are missing from
`data/vendor-search/vendor_terms.csv`, ranked by how many *new* CVEs adding them would pull.
This attacks the low-recall categories (`streaming` 0.15, `hub` 0.19, `alarms` 0.27,
`ev-charging` 0.28, `lighting` 0.30 — see `data/difference/recall_estimate.csv`): recall is low
there mainly because the hand-compiled vendor list is missing brands NVD already knows about.

**Output is a candidate list for a human to vet — this script never edits `vendor_terms.csv`.**

## Why this finds anything new

The keyword search matches *descriptions* against device phrases ("smart lock", "ip camera").
Each matched CVE also carries `cpe_strings` — NVD's own structured attribution of which
vendor:product it affects. A vendor appearing on keyword-matched (or confirmed-Yes) CVEs is
evidence that vendor makes devices of that category. But most of that vendor's *other* CVEs
have terse descriptions mentioning neither a device phrase nor any term we search — so they're
invisible to both current methods. Mining the vendor name out of the CPE and adding it as a
vendor term makes the vendor's whole catalogue searchable.

## New script: `scripts/cpe_brand_mining.py`

Follow the conventions of `scripts/cpe_expansion.py` (same repo-relative path handling,
`csv.field_size_limit(1 << 24)`, single snapshot pass). Reuse (import from `cpe_expansion`):
`parse_cpe`, `GENERIC_PLATFORM_CPES`, `load_known_cve_ids`, `seeded_categories`.

### Inputs (all existing files)

| File | Schema (header) | Role |
|---|---|---|
| `data/nvd-snapshot/nvd_all.csv` | `cve_id,published,description,cvss_score,cvss_version,cwe_ids,cpe_strings` (`cpe_strings` pipe-separated CPE 2.3 URIs) | corpus |
| `data/keyword-search/keyword_<cat>.csv` | same + `matched_terms` | Tier-B evidence |
| `data/vendor-search/results_all_<cat>.csv` | same + `matched_terms` | "already known" set |
| `data/difference/judgment_store.csv` | keyed `(category, cve_id)`, has `Final Judgment` | Tier-A evidence |
| `data/vendor-search/vendor_terms.csv` | `slug,term` | already-covered vendors |
| `data/difference/<cat>/{vendor_only,keyword_only,cpe_expansion,intersection}/01_raw.csv` | `Difference Type,cve_id,published,description,cvss_score,cvss_version,cwe_ids,cpe_strings` | cpe_strings for Yes rows |

### Algorithm

**Step 1 — per-category evidence vendors.** For each category:
- **Tier A (strong):** every `Final Judgment == Yes` CVE in `judgment_store.csv` for the
  category. Get its `cpe_strings` by looking the cve_id up in the four direction `01_raw.csv`
  files, **falling back to the snapshot** (2,136 of 3,085 Yes rows are absent from
  vendor_only/keyword_only raws — the snapshot always has the row). Extract vendors via
  `parse_cpe`, keeping only `part ∈ {o,h}` CPEs, dropping any `vendor:product` in
  `GENERIC_PLATFORM_CPES`.
- **Tier B (weak):** every CVE in `keyword_<cat>.csv` *not* judged No in the store. Same CPE
  extraction. (These matched a device phrase for this category — circumstantial evidence.)

Count per vendor: `n_yes_evidence`, `n_keyword_evidence`.

**Step 2 — drop already-covered vendors.** A vendor is covered for a slug if any
`vendor_terms.csv` term for that slug, normalized (casefold, `_`↔space, strip `-`), contains
the normalized vendor token or vice versa (`tp-link tapo` covers vendor `tp-link`; `carrier
infinity` covers `carrier`). Compare against the whole file too and report cross-slug coverage
(vendor covered under a *different* slug is worth knowing, not dropping — flag it).

**Step 3 — score new yield (one snapshot pass).** Build `{vendor: set(categories)}` for all
surviving candidates, then stream the snapshot once. For each CVE, extract its CPE vendors; for
each candidate vendor hit, if the cve_id is not in that category's known set
(`load_known_cve_ids`), count it as `new_yield` and stash up to 3 sample `(cve_id, description
[:150])`. Also count `snapshot_total` (all CVEs listing the vendor, in-scope or not) — a huge
gap between `snapshot_total` and evidence counts flags a diversified mega-vendor (samsung,
bosch) that must NOT be added bare.

**Step 4 — risk flags.** Emit a `risk_flags` column:
- `mega-vendor` — `snapshot_total > 200` (tune) and evidence < 10% of it.
- `known-fp-bomb` — vendor in a hardcoded deny list from measured experiments: `worx`, `haier`,
  `hisense`, `fujitsu`, `moxa`, `mitsubishi electric` (bare), `cerberus`, `pelco`, `geovision`,
  `verint`, `anviz` (source: `data/difference/term_precision.csv` `prune_candidate=Yes` rows +
  memory notes). Load the term_precision prune list dynamically rather than hardcoding where possible.
- `dictionary-word` — vendor token is an English word (check against a small embedded list or
  `/usr/share/dict/words` if present; e.g. `carrier`, `august`, `wink`, `hue`).

### Output

`data/vendor-search/vendor_candidates.csv`, sorted by `new_yield` desc within category:

```
category,vendor,n_yes_evidence,n_keyword_evidence,covered_elsewhere_slug,
snapshot_total,new_yield,risk_flags,sample_cves,sample_descriptions
```

Plus a console summary: top 10 candidates per category, totals per category.

### CLI

```
python3 scripts/cpe_brand_mining.py --all                 # every category
python3 scripts/cpe_brand_mining.py hub streaming alarms  # subset
python3 scripts/cpe_brand_mining.py --all --min-evidence 2   # require ≥2 evidence CVEs (default 1)
```

## Human workflow after the script

1. Review `vendor_candidates.csv`; for each accepted vendor add a `slug,term` line to
   `vendor_terms.csv` (term = vendor with `_`→space; qualify with a product word if
   `dictionary-word` or `mega-vendor` flagged, per existing convention).
2. Re-run the vendor search + set-ops for affected categories (commands in `README.md`), then
   `make_review_copies.py <cat> --refresh` — the judgment store carries settled rows forward,
   so only genuinely new CVEs enter review.

## Acceptance checks

- Run `--all`: verified expectations from prior experiments should surface — `home-power`
  should show `growatt`-class vendors; `sensors`/`shades` should show `aqara`, `shelly`,
  `fibaro` *unless already added to vendor_terms.csv*.
- No vendor from `GENERIC_PLATFORM_CPES` (apple, google, microsoft, linux…) appears as a candidate.
- `moxa` for cameras either doesn't appear or carries `known-fp-bomb`.
- A vendor already in `vendor_terms.csv` for the same slug never appears.
- Script is read-only outside `vendor_candidates.csv`.
