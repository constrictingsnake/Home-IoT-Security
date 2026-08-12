# Category Tagging Kit

**This is a verification pass, not a blind annotation.** You are shown the current best
answer for every cell and asked to confirm or correct it **against a source**. That is the
opposite of `data/facets/annotation-kit/`, which exists to keep annotators away from the
current value — do not carry habits between the two.

`category_tags.csv` holds **432 cells** (18 facets x 24 categories):
**420 to answer**, 12 emitted as `excluded-validity` and not asked. This is
the WHOLE facet vocabulary in one pass — 276 single-valued cells and 144
multi-valued ones.

## Two kinds of row — check `cardinality` before you answer

| `cardinality` | what to put in `Verdict N` |
|---|---|
| `single` | **exactly one** value from `allowed_values` |
| `multi` | **every** value that applies, `|`-separated — e.g. `AppOnlyAdmin|LocalWebAdmin` |

The 6 multi-valued facets (adminModel, alsoDeployedIn, credentialModel, pairingModel, patchResponsibility, topology) start at row
114. They ask what is **common for the category**, not what is merely possible
somewhere: if a route appears on a handful of outlier products, leave it out. A one-value
answer is perfectly normal for a `multi` row — listing everything is the failure mode, since
a facet that ends up true of every category discriminates nothing.

`unsure` is a whole-cell answer: put it alone, never mixed in with real values. For
`alsoDeployedIn` (the one optional facet) `none` is a real answer, meaning the category is
sold to households only.

## What to do

Work **top to bottom** — the sheet is sorted so the most valuable cells come first. For each
row:

1. Read `facet` and look it up in `VALUE_DEFINITIONS.md`. The definitions are narrow; several
   are easy to answer from the everyday sense of the word instead of the defined one.
2. Look for a **source**: vendor documentation and spec sheets, support/security pages,
   declared support periods (UK PSTI / EU CRA), certification requirements (Matter and
   similar), or scan banners for `hasWebAdminUI`. Sources are usually per-product — cite two
   or three representative products for the category rather than hunting for one page that
   covers the whole class.
3. Fill `Verdict N` with a value from `allowed_values`, `Source N` with the URL(s) or a short
   citation, `Notes N` with anything the next reader needs.
4. Put `yes` in `Category-Wide N` **only** if your source covers the entire category — a
   regulation, a certification requirement, a standard. Citing three representative products
   is not category-wide; leave it blank. This column is the only thing that promotes a cell
   to `Documented`, so it is deliberately a separate answer rather than a note.
5. **Leave `Source N` blank if you looked and found nothing.** That is a real answer and it is
   recorded as `HumanJudged`. Do not cite a page that does not actually say what the facet
   claims — an unsourced honest verdict is worth more than a decorative citation.

Two reviewers fill columns 1 and 2 independently. Agreement on a non-`unsure` verdict settles
the cell; disagreement is discussed and reconciled, exactly as the CVE scope disagreements
were. On a `multi` row agreement means the **same set** — order and spacing do not matter,
so `MeshJoin|QrPaired` and `qrpaired | meshjoin` settle as one answer, but an extra value in
one column is a disagreement and goes back to the queue.

## How your answer is tiered

Set automatically by `facet_store.py` from what you fill in:

| tier | when |
|---|---|
| `Documented` | `Source N` filled **and** `Category-Wide N` = `yes` |
| `HumanSourced` | `Source N` filled — **most cells should land here** |
| `HumanJudged` | `Source N` blank: you answered from knowledge, no source found |

`HumanJudged` overrides any AI-assigned value but carries no evidence — for citation it is
treated exactly as `Estimated`. The share of cells that end up there is itself a result.

## Reading the context columns

- `prefill_value` / `prefill_source` — the suggestion and **where it came from**. Weigh them
  differently: `phase-a-cve-weighted` was measured over sampled devices; `author-prior` is the
  original hand assignment, which is the thing this pass exists to test.
  **312 of 420 asked cells (74%) carry an
  author-prior pre-fill** — treat those as a blank sheet with a hint.
- `phase_a_verdict` / `modal_share` — how well one value described the sampled devices.
  `UNMEASURED` means that category was never sampled, not that it passed.
- `facet_kappa` / `kappa_band` — how reliably three independent annotators could assign this
  facet at all. A `FAILS` band means they could not, which is exactly why a source matters
  more here than anywhere else on the sheet.
- `category_cves` — confirmed-Yes CVEs in the category. Drives the ordering; not evidence.

**Every `multi` row has all three of those blank or `UNMEASURED`, and that is not an
oversight.** The multi-valued facets were never in the blind product panel, so they have no
kappa and no Phase A verdict — nobody has measured whether they can be assigned reliably or
whether one set is even true of a whole category. Your verdict is the first evidence they
will ever carry, and without it they stay `Estimated` permanently: usable for organising
analysis, never citable as a finding. Treat their `author-prior` pre-fill as especially weak
— it has not survived even the one check the single-valued priors have.

## The probe comes first

The first ~20 rows are the sourcing probe that gates the rest of the phase: they are the
`FAILS`-band facets (capturesAV, computeTier, firmwareUpdateModel, hasWebAdminUI, supportLifetime) on the highest-CVE categories. **Record how long a
cell takes and how often a source actually exists before continuing.** If sources turn out not
to exist for a facet, that facet gets dropped rather than tagged — better to know after twenty
minutes than after a full pass.

The probe is deliberately all `single` rows — the multi-valued facets start lower down at row
114, so the phase gate is judged on the same 20 cells it was defined on. When you
reach the first `multi` row, take its per-cell timing separately: a set answer needs a source
per member, so it is the one part of this sheet whose cost the probe does not predict.

## Excluded cells

Rows marked `excluded-validity` are cells Phase A measured as NOT-USABLE: the category holds
more than one kind of device, so no single value is true of it. A source cannot fix that — a
perfectly sourced value is still wrong for a large share of the rows it lands on. They are
shown for context and stay excluded from writeback.
