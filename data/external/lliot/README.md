# LLIoT label extract

Source: `github.com/Tina-Rezaei/LLIoT` (Rezaei et al., EuroS&P 2026), MIT License (`LICENSE`,
copied verbatim). Repo HEAD `56ed1d23a9b9b95621ed194f150e3a56ac69141f`, fetched 2026-10-13.

| File | Committed | SHA-256 |
|---|---|---|
| `iot_cls_full.tsv`: their full `cve_iot_classification` table, 211,182 rows | no (75 MB, gitignored) | `9e0ab0a4a385feb2447a937c0d1ea3069baa512d4731fadbd2ce052103333314` |
| `lliot_labels.csv`: `cve_id, is_iot, sector` extracted from it, sorted by `cve_id` | yes | `2ed3293648be7141dfefa053e8f55d331d479de7cbae12541a7934cdd70fae65` |

Used **only** to stratify the never-surfaced pool in `docs/plans/PLAN_lliot_method_comparison.md`.
The model under test never sees these labels.
