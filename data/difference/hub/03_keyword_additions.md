# hub — Stage 8 keyword/vendor mining (resolved-Yes)

Mined from `final_resolved.csv` resolved-`Yes` rows (AI-unanimous + human-confirmed), both directions.

## Vendor/brand-term additions (from `keyword_only` Yes → `vendor_terms.csv`)

| Add | Device | Example CVE |
|-----|--------|-------------|
| `bosch smart home` (or `bosch shc`) | Bosch Smart Home Controller — qualified; bare `bosch` collides with industrial | CVE-2019-11891 |
| `zipato`, `zipabox` | Zipato Zipabox smart home controller | CVE-2018-15123 |

## Keyword/device-phrase additions (from `vendor_only` Yes → `keyword_terms.csv`)

_None — existing device-phrase set already covers the device types; misses are brand-specific._
