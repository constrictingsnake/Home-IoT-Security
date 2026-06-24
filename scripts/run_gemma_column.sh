#!/usr/bin/env bash
# One-pass Gemma 4 31B review of the ENTIRE Gemini column (all 11 categories incl. cameras).
#
# Designed to straddle the daily RPD reset: started ~95 min before reset at --rps 0.30
# (~11.6 rows/min), ~1,100 of the 2,263 rows land before reset and ~1,163 after, each under
# the 1,500/day cap, so it never stalls.
#
# Prep (back up the 3.1 baseline + blank the Gemini columns) runs ONCE, guarded by a flag
# file, so the fill is fully resumable with no --redo. Run AFTER the 3.1 small-category run
# has finished.
#
# Launch (detached, survives closing the terminal):
#     nohup bash scripts/run_gemma_column.sh > gemma_run.log 2>&1 &
#     tail -f gemma_run.log     # watch progress
set -u
cd "$(dirname "$0")/.." || exit 1
set -a; source .env; set +a

MODEL="gemma-4-31b-it"
RPS="0.30"
DIRECTION="${DIRECTION:-vendor_only}"   # which difference direction's reviews to fill
FLAG="data/difference/.gemma_prepped"

# --- one-time prep: backup 3.1 baseline + blank Gemini columns ---
if [ ! -f "$FLAG" ]; then
  echo "[$(date '+%H:%M:%S')] Prep: backing up 3.1 baseline + blanking Gemini columns ..."
  python3 - <<'PY' || exit 1
import csv, glob, os, shutil
for f in sorted(glob.glob("data/difference/*/*/reviews/gemini.csv")):
    bak = f.replace("gemini.csv", "gemini_3.1_baseline.csv")
    if not os.path.exists(bak):
        shutil.copy2(f, bak)              # preserve the 3.1 results
    with open(f, newline="") as fh:
        rows = list(csv.DictReader(fh)); fields = rows[0].keys() if rows else []
    for r in rows:
        for c in ("Gemini Judgment", "Gemini Confidence", "Gemini Reasoning"):
            if c in r: r[c] = ""
    with open(f, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(fields)); w.writeheader(); w.writerows(rows)
print("Prep done — 3.1 saved as *_3.1_baseline.csv, Gemini columns cleared.")
PY
  touch "$FLAG"
else
  echo "[$(date '+%H:%M:%S')] Prep already done (flag present) — resuming fill only."
fi

# --- fill on Gemma, smalls first (early comparison) then cameras (spans the reset) ---
for pair in \
  "doorlock:smart lock" \
  "smartspeakers:smart speaker" \
  "sleeptracker:sleep tracker" \
  "doorbell:video doorbell" \
  "thermostat:smart thermostat" \
  "babymonitor:baby monitor" \
  "smartplugs:smart plug" \
  "alarms:home alarm" \
  "robotvacuum:robot vacuum" \
  "airconditioner:smart air conditioner" \
  "cameras:security camera" ; do
  cat="${pair%%:*}"; kw="${pair#*:}"
  echo "=== [$(date '+%H:%M:%S')] $cat/$DIRECTION ($kw) ==="
  python3 scripts/merge_judgments.py --reviews "data/difference/$cat/$DIRECTION/reviews" \
      --run-gemini --category "$kw" --model "$MODEL" --rps "$RPS" \
      || echo "FAILED: $cat/$DIRECTION"
done
echo "=== GEMMA RUN COMPLETE [$(date '+%H:%M:%S')] ==="
