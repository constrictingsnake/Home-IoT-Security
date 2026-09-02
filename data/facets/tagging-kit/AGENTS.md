# Codex instructions — category facet tagging, column 2

You are drafting **column 2** of the F5 category-tagging pass. Read this file, then
`VALUE_DEFINITIONS.md`, then `PROBE_RESULT.md`. Fill **`codex_column2.csv`** — 113 rows.
Touch no other file.

## You are drafting, not settling

Every answer you write will be reviewed cell by cell by a human before it counts. A cell
settles only when column 1 and column 2 agree *and* the human has signed off. So the most
useful thing you can put in `Notes 2` is **what you actually checked and what you could not
confirm** — that is what makes the review fast. A confident answer with no trail is worth
less here than a hedged one that says where it stopped.

## This sheet is the OPPOSITE of `../annotation-kit/`

That kit is a **blind** exercise: annotators are kept away from the current value on
purpose. This one is a **verification** pass: you are *shown* the current best answer
(`Verdict 1`, with its `Source 1` and `Notes 1`) and asked to confirm or correct it against
evidence. **Do not carry habits between the two kits.** Reading column 1 here is required,
not cheating.

## The one rule inherited from the blind kit — do not break it

**Do not determine a facet value from CVE descriptions, CWE IDs, or CVSS scores** — not in
this repo, not on the web. Facet values are later crossed against weakness data, and a facet
assigned from CVE text would correlate that data with itself. This is the circularity
boundary `CLAUDE.md` draws, and it is the reason the ontology holds classes and scope notes
but never judgments.

Facet values come from **vendor documentation**: manuals, spec sheets, support and security
pages, firmware-update KBs, declared support periods, certification requirements.

The `corpus_vendors` column tells you **which vendors to go and research**. It is a
weighting aid, never evidence for the value itself. "Akuvox holds 36% of this category's
CVEs" means *read Akuvox's documentation*, not *the answer is whatever Akuvox's CVEs
suggest*.

## What to fill

| column | what goes in it |
|---|---|
| `Verdict 2` | a value from `allowed_values` (see cardinality below) |
| `Source 2` | URL(s) or short citation — **or blank if you looked and found nothing** |
| `Category-Wide 2` | `yes` **only** for a source binding the whole product class |
| `Notes 2` | what you checked, what you could not confirm, why you differ from column 1 |

### Cardinality — check it on every row

- `single` → **exactly one** value from `allowed_values`.
- `multi` → **every** value that is *common for the category*, `|`-separated, e.g.
  `AppOnlyAdmin|LocalWebAdmin`. Not everything merely possible on some outlier product. A
  one-value answer is normal; listing everything is the failure mode, since a facet true of
  every category discriminates nothing.

`unsure` is a whole-cell answer — put it alone, never mixed with real values. For
`alsoDeployedIn`, `none` is a real answer meaning "sold to households only".

### `Category-Wide 2` is a high bar

`yes` only when the source binds the class: UK PSTI declarations, ETSI EN 303 645, Matter /
CSA certification requirements, grid codes. Citing three representative products is **not**
category-wide — leave it blank. This column is the only thing that promotes a cell to
`Documented`, so it must be claimed deliberately.

### A blank `Source 2` is a real answer, and often the correct one

**Vendor documentation states what a device has; nothing states what it lacks.** A manual
proves `hasWebAdminUI=true` in one screenshot and can never prove `false` at all. So the
sourceable half of every boolean facet is the positive half. If the true answer is negative,
you will usually not find a source — **write the verdict, leave `Source 2` blank, and say in
`Notes 2` that the claim is negative and unsourceable in principle.**

Do **not** cite a page that does not actually say what the facet claims. An unsourced honest
verdict is recorded as `HumanJudged` and is worth more than a decorative citation.

## Two kinds of row — the file is sorted so the harder ones come first

### 1. `resource_required = yes` — 19 rows, do these first

These are cells where `facet_source_coverage.py` measured column 1's citation as
**`below-floor`**: the vendors it cited do not hold enough of the category's CVEs to be
evidence about it. `cited_vendors` and `cited_share` show what column 1 used and how thin it
was. Example: `doorbell/capturesAV` was sourced on Ring at **2.2%**, while Akuvox carries
**36%** of that category.

For these, **do not verify column 1's source — replace it.** Research the brands in
`corpus_vendors`, starting from the top, and cite those. If the value turns out the same,
that is a fine result; the point is that the evidence now comes from the population the
assertion lands on.

### 2. The other 94 rows — verify column 1

Read `Source 1` and check it genuinely supports `Verdict 1` for this category. Then:

- **It holds** → repeat the value in `Verdict 2`, cite the same source in `Source 2`, and
  note in `Notes 2` that you verified it (say which part of the page carried it).
- **It does not hold** → correct the value, cite what you found, and explain the difference
  in `Notes 2`.
- **You cannot reach or verify the source** → say so in `Notes 2` and answer from the best
  evidence you can find, leaving `Source 2` blank if there is none.

After the 19, the file is grouped **by category**, and you should work it that way. Sourcing
is not per-cell: one vendor firmware-update KB typically settles `firmwareUpdateModel`,
`hasWebAdminUI`, `patchResponsibility` and `adminModel` for a category at once. Roughly six
research passes covered the entire 420-cell sheet in column 1 (`PROBE_RESULT.md`).

## The 11 facets in this pass, and why these

- **κ-failed (5)** — `capturesAV`, `computeTier`, `firmwareUpdateModel`, `hasWebAdminUI`,
  `supportLifetime`. Three independent annotators could not agree on these (κ < 0.40;
  `supportLifetime` came out *below chance* at −0.31). Two of them also defeated automated
  derivation from CVE text. **A source is the only thing that can rescue them**, which is
  why they are here and why a real citation matters more on these rows than anywhere else.
- **multi-valued (6)** — `adminModel`, `alsoDeployedIn`, `credentialModel`, `pairingModel`,
  `patchResponsibility`, `topology`. These were never in the blind panel, so they have no κ
  and no Phase A verdict — `kappa_band` and `phase_a_verdict` are blank on those rows and
  that is not an oversight. **Your draft is the first evidence they will ever carry.** Treat
  their `prefill_value` as especially weak: it is the original hand assignment and has not
  survived even the one check the single-valued priors have.

## If no allowed value fits

Two vocabulary gaps are known and unfixed: `pairingModel` has no value for
Ethernet/IP-discovery onboarding, and `adminModel` has no value for an on-device screen UI.
If you hit a cell where nothing in `allowed_values` is right, **pick the closest value and
say so explicitly in `Notes 2`**. Do not invent a value — one outside `allowed_values` is
discarded, not corrected.

## Reading the context columns

- `prefill_value` / `prefill_source` — `phase-a-cve-weighted` was *measured* over sampled
  devices; `author-prior` is the original hand assignment, which is the thing this pass
  exists to test. Weigh them differently.
- `phase_a_verdict` / `modal_share` — how well one value described the sampled devices.
  `UNMEASURED` means the category was never sampled, not that it passed.
- `facet_kappa` / `kappa_band` — how reliably three annotators could assign the facet at all.
- `category_cves` — confirmed-Yes CVEs in the category. Ordering weight, **not evidence**.
- `scope_note` — what is in and out of this category. Read it: several categories exclude
  the products you would first think of.

## Data quirks worth knowing

- NVD carries the same vendor under more than one spelling. `babymonitor` shows both
  `dlink 44%` and `d-link 11%` in `corpus_vendors` — that is one vendor at ~55%, not two.
- Some categories are dominated by brands that are not the household name: `pet` is Furbo
  (51%), `doorbell` is Akuvox (36%), `garden` is Ecovacs (42%). Research what the corpus
  contains, not what the category evokes.

## Do not

- Edit any column other than the four `... 2` columns.
- Edit `category_tags.csv`, `facet_store.csv`, the ontology, or any other sheet.
- Open `../annotation-kit/` — it is the frozen record of the κ study and its reproducibility
  depends on it not moving.
- Fill a cell you did not actually research. `unsure` with an honest note is a usable answer;
  a fabricated citation is not, and it will cost more human time to catch than it saved.

## When you are done

Report: how many cells you filled, how many carry a source, how many you marked
category-wide, how many differ from column 1, and any cell where you think the vocabulary or
the scope note is wrong. The human merges with
`python3 scripts/make_codex_column2.py --merge`.
