# Plan — CPE Product-Token Scan (automated discovery from NVD product names)

*Status: **Implemented 2026-07-13** — `scripts/cpe_product_scan.py`, wired into
`scripts/pipeline.py` as `scan-products` (not chained into `refresh`/`settle` — accepting a
candidate is a human decision). Rationale in `CLAUDE.md` § Automated product-token discovery,
commands in `README.md`, flag table in `docs/SCRIPTS_REFERENCE.md`. This doc remains the
algorithm reference. Companion to `PLAN_cpe_brand_mining.md` (mines CPE **vendor** fields) and
`PLAN_keyword_mining.md` (mines **descriptions**): this one mines CPE **product** fields, the
last of the three text surfaces no current method searches.*

**Goal:** find CVEs whose NVD product name says what the device *is* (`insteon:hub_firmware`,
`yitechnology:yi_home_camera_firmware`, `mica:fingerprint_bluetooth_padlock_fb50`) but whose
description names no device phrase and whose vendor is on no list — CVEs structurally
unreachable by both text searches today. Prototype measured ~625 raw / ~150–250 curated new
CVEs, concentrated in the worst-recall categories (`hub` 2-src recall 0.33; Insteon Hub alone
is 97 CVEs).

**Output is a candidate list for a human to vet — this script never edits any term file.**

## Why this finds anything new (the capability gap)

Single device nouns — `camera`, `hub`, `alarm`, `plug`, `lock` — are unusable as description
keywords: too generic, they'd match half of NVD ("an attacker can *lock* the device…"). But
inside a CPE **product** field they are high-precision: a product literally *named*
`..._camera_firmware` is a camera. The keyword search can never use these tokens; the vendor
search only knows brands someone already listed. Scanning product-name tokens is therefore not
a sharper version of an existing method — it reaches a class of CVE neither method can:
description silent, vendor unknown, product name explicit.

Distinct from its two siblings:
- `cpe_expansion.py` (Stage 5) **densifies** confirmed `vendor:product` seeds — it can never
  find a new brand.
- `cpe_brand_mining.py` finds new **vendors**, but only vendors that already co-occur with a
  keyword-matched or confirmed-Yes CVE — it needs an evidence trail into the category.
- This scan needs **no evidence trail at all**: the product name itself is the evidence. It is
  the only method that could ever have found `insteon` (hub), `yitechnology` (cameras), or
  `summerinfant` (babymonitor) — none appear on any CVE either search matches.

## Prototype validation (2026-07-13, 2026-06-25 snapshot, 360,981 CVEs)

Exact-token match against product names split on `[_\-.]`, `part ∈ {o,h}` only,
`GENERIC_PLATFORM_CPES` denied, excluding each category's known set (keyword ∪ vendor results ∪
judgment store). **625 distinct new CVEs**; the headline finds and the noise both matter:

| Category | Raw new | Signal | Noise (why curation is the real work) |
|---|---|---|---|
| hub | 454 | `insteon:hub_firmware` **97** | `gateway`/`bridge` drag in Citrix NetScaler (31), Dell Edge Gateway (20) |
| cameras | 102 | `yi_home_camera` 12, Binatone `halo+_camera` 12 | Furbo 360 (17) already owned by `pet`; Geutebrück is pro-surveillance → No |
| ev-charging | 27 | GARO/ABB `wallbox` rows | mostly claimed by the 2026-07 `wallbox`/`charging station` keyword additions |
| sensors | 17 | Proges, QbeeCam | Cisco IPS "sensor", Sourcefire 3D "sensor" |
| home-power | 11 | OutBack Power Mojave inverter 3 | Sinapsi/Gavazzi claimed by new `photovoltaic` keyword |
| babymonitor | 4 | Summer Infant `baby_zoom` 2, Mimo Baby | — |
| doorlock | 1 | Mica fingerprint padlock | — |
| pet / fans / shades | 1–3 | — | GE "feeder protection relay", IBM chassis "fan", Nissan "blind spot ECU" |

Two lessons baked into the design: (1) broad tokens (`gateway`, `bridge`, `sensor`, `feeder`,
`fan`, `blind`) need a risk flag, not exclusion; (2) the scan must run against a **current**
baseline — ~40 prototype hits were already claimed by term additions made the same day.

## New file: `data/cpe-product-tokens.csv`

Hand-authored, `slug,token` (same `#`-comment format as the other term files). One token per
line; matched **exactly** against the product name split on `[_\-.]` (no substring matching —
`cam` must be its own token so it can't hit `camshaft`). Multi-word device names are already
handled by the existing search path (space↔underscore rule); this file is for the single tokens
that path can't use. Starter list = the prototype's, tuned:

```
cameras: camera, cam, ipcam, ipcamera, netcam, webcam, nvr, dvr
doorbell: doorbell, doorphone      doorlock: lock, deadbolt, padlock
thermostat: thermostat             smartplugs: plug, outlet, socket
lighting: bulb, dimmer             robotvacuum: vacuum
ev-charging: evse, wallbox, charger
home-power: inverter, powerwall    hub: hub, bridge, gateway
alarms: alarm, siren               babymonitor: baby
garden: sprinkler, irrigation, mower, lawnmower
pet: feeder, petfeeder             smartspeakers: speaker, soundbar
fridge: refrigerator, fridge       sensors: sensor
fans: fan                          shades: blind, blinds, curtain, shutter
```

The token list is the ongoing curation surface, exactly as `vendor_terms.csv` is for brands.

## New script: `scripts/cpe_product_scan.py`

Follow `cpe_brand_mining.py`'s conventions (repo-relative paths, `csv.field_size_limit`,
single snapshot pass). Reuse from `cpe_expansion` / `cpe_brand_mining`: `parse_cpe`,
`DEVICE_PARTS`, `GENERIC_PLATFORM_CPES`, `load_judgment_store`, `load_known_cve_ids`, the
vendor-term coverage index (`build_coverage_index` / `is_covered` / `covered_elsewhere`).

### Algorithm

**Step 1 — build the known sets.** Per category: cve_ids in `keyword_<cat>.csv` ∪
`results_all_<cat>.csv` ∪ the judgment store (any verdict — a settled No must not resurface).

**Step 2 — one snapshot pass.** For each CVE's `cpe_strings`: keep `part ∈ {o,h}`, deny
`GENERIC_PLATFORM_CPES`; split each product name on `[_\-.]`; on an exact token hit for a slug
where the cve_id is unknown, record the hit keyed by `(slug, vendor:product)`.

**Step 3 — aggregate per `(slug, vendor:product)`,** not per CVE — a human vets *products*
("is the Insteon Hub in scope?"), and one decision settles all its CVEs. Columns: `n_new_cves`,
`matched_tokens`, `covered_elsewhere_slug` (Furbo→pet: report, don't drop, per the
brand-mining convention), up to 3 `sample_cves` + truncated `sample_descriptions`.

**Step 4 — risk flags.** `broad-token` (token in an embedded list fed by the prototype's noise:
`gateway`, `bridge`, `sensor`, `feeder`, `fan`, `blind`, `lock`, `switch`, `controller`);
`non-consumer-vendor` (vendor flagged mega-vendor by `cpe_brand_mining.py`'s criteria, e.g.
cisco, dell, ge, ibm); `pro-surveillance` for the cameras deny-convention brands (Geutebrück,
Axis, Milesight…, sourced from `term_precision.csv` prune rows where possible). Flags triage,
never filter — same rule as both sibling miners.

### Output

`data/cpe-product-scan/product_candidates.csv`, sorted by `n_new_cves` desc within category:

```
category,vendor_product,matched_tokens,n_new_cves,covered_elsewhere_slug,
risk_flags,sample_cves,sample_descriptions
```

Console summary: per-category totals, top 10 products each.

### CLI

```
python3 scripts/cpe_product_scan.py --all
python3 scripts/cpe_product_scan.py hub cameras            # subset
python3 scripts/cpe_product_scan.py --all --min-cves 2     # drop 1-CVE products (default 1)
```

Wire into `pipeline.py` as `scan-products` — like `discover-vendors` and `mine-keywords`,
**not** chained into `refresh`/`settle` (accepting a candidate is a human decision).

## Routing accepted candidates — vendor terms, not a fifth direction

An accepted product becomes an ordinary `vendor_terms.csv` line (`hub,insteon`,
`cameras,yi home camera`), flowing through the existing Stage 1–4 chain untouched. The
space→underscore matcher rule means the term reaches the CPE string directly, so nothing is
lost. The alternative — a fifth review direction beside `cpe_expansion` — would touch set-ops
disjointness, `make_review_copies.py`, `merge_judgments.py`, and the `Difference Type` enum for
no extra yield; revisit only if the term route measurably drops rows.

## Sequencing & limitations

- **Run after `pipeline.py refresh`** has absorbed the 2026-07 term additions, so the known-set
  baseline is current (else the candidate list is padded with already-claimed rows).
- **CPE-less CVEs are invisible to it** — NVD's 2024+ enrichment backlog means many recent CVEs
  carry no CPE. This complements the text searches; it cannot replace them.
- Yes rows it produces feed Stage 5 seeding and `cpe_brand_mining.py` evidence on the next
  cycle — the three miners compound.

## Acceptance checks

- `hub` surfaces `insteon:hub_firmware` (~97 new CVEs) unless `insteon` was already added to
  `vendor_terms.csv`; `cameras` surfaces `yitechnology`; `babymonitor` surfaces `summerinfant`.
- Citrix NetScaler / Dell Edge Gateway rows appear only with `broad-token` +
  `non-consumer-vendor` flags — never unflagged.
- No `GENERIC_PLATFORM_CPES` vendor and no `part=a` CPE produces a candidate.
- A product whose CVEs are all in the category's known set never appears; a settled-No CVE
  never counts toward `n_new_cves`.
- Script is read-only outside `data/cpe-product-scan/`.
