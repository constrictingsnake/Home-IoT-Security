#!/bin/bash
# Run the Gemini reviewer (gemma-4-31b-it) over every category's blind review copy, with
# token-aware batching paced under the free-tier limits (30 req/min, 16k tokens/min).
#
# Why a driver script: gemini_classify.py handles one review copy at a time. This loops
# every category, pulling each category's human-readable label + scope note from
# data/categories.csv (so it stays correct if the category set changes), and applies the
# rate-limit knobs consistently across the whole pass.
#
# Resumable & idempotent: each category classifies only rows whose Gemini Judgment is still
# blank (progress is flushed to disk after every batch), so a re-run continues where a prior
# run stopped and re-fills any rows a weak model garbled/omitted. Finished categories print
# "nothing to do" and skip instantly.
#
# Token accounting note: gemini_classify.py estimates tokens at ~4 chars/token, which
# undercounts CPE-dense rows. The defaults below are therefore set *below* the true limits
# (est. 14k TPM / 12k-token batches) so real throughput lands near — but not over — 16k
# TPM; the script does not retry 429s, so staying under the ceiling matters.
#
# Usage:
#   scripts/run_gemini.sh                 # all categories
#   scripts/run_gemini.sh hub cameras     # only these slugs
#
# Env overrides: MODEL, MAX_BATCH_TOKENS, TPM, RPS, MAX_BATCH_ROWS.
# Requires GEMINI_API_KEY (loaded from .env if present).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
[ -f .env ] && { set -a; . ./.env; set +a; }

MODEL="${MODEL:-gemma-4-31b-it}"
MAX_BATCH_TOKENS="${MAX_BATCH_TOKENS:-12000}"
TPM="${TPM:-14000}"
RPS="${RPS:-0.5}"
MAX_BATCH_ROWS="${MAX_BATCH_ROWS:-50}"
ARGS=(--model "$MODEL" --max-batch-tokens "$MAX_BATCH_TOKENS" --tpm "$TPM" \
      --rps "$RPS" --max-batch-rows "$MAX_BATCH_ROWS")

SELECT="$*"

# Emit "slug<TAB>label" for the requested slugs (or all, in categories.csv order).
while IFS=$'\t' read -r slug label; do
  f="data/difference/$slug/reviews/gemini.csv"
  [ -f "$f" ] || { echo "SKIP $slug (no gemini.csv)"; continue; }
  echo "==================== $slug ($label) ===================="
  python3 scripts/gemini_classify.py "$f" --category "$label" "${ARGS[@]}"
done < <(python3 - "$SELECT" <<'PY'
import csv, sys
sel = set(sys.argv[1].split()) if len(sys.argv) > 1 and sys.argv[1].strip() else None
for r in csv.DictReader(open('data/categories.csv')):
    s = r['slug'].strip()
    if sel is None or s in sel:
        print(f"{s}\t{r['label'].strip()}")
PY
)
echo "ALL GEMINI DONE"
