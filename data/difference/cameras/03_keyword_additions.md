# cameras — Stage 8 keyword/vendor mining (resolved-Yes)

Mined from `final_resolved.csv` resolved-`Yes` rows (AI-unanimous + human-confirmed), both directions.

## Vendor/brand-term additions (from `keyword_only` Yes → `vendor_terms.csv`)

| Add | Device | Example CVE |
|-----|--------|-------------|
| `beward` | Beward N100 IP camera (unauth video stream access) | CVE-2019-25248 |

## Keyword/device-phrase additions (from `vendor_only` Yes → `keyword_terms.csv`)

_None — existing device-phrase set already covers the device types; misses are brand-specific._

## Note

Keyword set is mature (ip/network/security/ptz/dome/bullet camera, nvr, dvr, onvif, rtsp) — no new device phrases. `frigate` (open-source self-hosted NVR) is a borderline software-not-brand candidate; left out.
