# alarms — Stage 8 keyword/vendor mining (resolved-Yes)

Mined from `final_resolved.csv` resolved-`Yes` rows (AI-unanimous + human-confirmed), both directions.

## Vendor/brand-term additions (from `keyword_only` Yes → `vendor_terms.csv`)

| Add | Device | Example CVE |
|-----|--------|-------------|
| `chuango` | Chuango 433 MHz burglar alarm | CVE-2019-9659 |
| `digoo` | Digoo DG-HAMB smart home security system | CVE-2023-31762 |
| `hozard alarm` | Hozard alarm system | CVE-2023-50123 |

## Keyword/device-phrase additions (from `vendor_only` Yes → `keyword_terms.csv`)

| Add | Rationale | Example CVE |
|-----|-----------|-------------|
| `keypad` | alarm keypad seen in Yes rows; **broad** (also POS/phone keypads) — low confidence | CVE-2018-11402 |
| `base station` | alarm base station; **broad** — low confidence | CVE-2019-3997 |
