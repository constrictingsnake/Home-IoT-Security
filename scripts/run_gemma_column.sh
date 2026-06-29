#!/usr/bin/env bash
# One-pass Gemma 4 31B review of the ENTIRE Gemini column (all ~24 analysis categories).
#
# Designed to straddle the daily RPD reset: started ~95 min before reset at --rps 0.30
# (~11.6 rows/min), so requests are spread across the reset and stay under the 1,500/day cap.
#
# Prep (back up the 3.1 baseline + blank the Gemini columns) runs ONCE, guarded by a flag
# file, so the fill is fully resumable with no --redo. Run AFTER the 3.1 small-category run
# has finished.
#
# Set DIRECTION=keyword_only before launching to run the keyword_only direction instead:
#     DIRECTION=keyword_only nohup bash scripts/run_gemma_column.sh > gemma_kw.log 2>&1 &
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
FLAG="data/difference/.gemma_prepped_${DIRECTION}"

# --- one-time prep: backup 3.1 baseline + blank Gemini columns (for this direction only) ---
if [ ! -f "$FLAG" ]; then
  echo "[$(date '+%H:%M:%S')] Prep: backing up 3.1 baseline + blanking Gemini columns ($DIRECTION) ..."
  python3 - "$DIRECTION" <<'PY' || exit 1
import csv, glob, os, shutil, sys
direction = sys.argv[1]
pattern = f"data/difference/*/{direction}/reviews/gemini.csv"
for f in sorted(glob.glob(pattern)):
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
print(f"Prep done ({direction}) — 3.1 saved as *_3.1_baseline.csv, Gemini columns cleared.")
PY
  touch "$FLAG"
else
  echo "[$(date '+%H:%M:%S')] Prep already done (flag present) — resuming fill only."
fi

# --- fill on Gemma: all ~24 analysis categories (smalls first, cameras last — spans the reset)
# Keyword strings are the human-readable device category label passed to Gemini as context.
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
  "fans:smart fan" \
  "fridge:smart refrigerator" \
  "shades:smart blinds" \
  "sensors:home sensor" \
  "airpurifier:air purifier" \
  "lighting:smart lighting" \
  "appliances:smart appliance" \
  "hub:smart home hub" \
  "ev-charging:EV home charger" \
  "home-power:home energy system" \
  "garden:smart garden" \
  "pet:smart pet device" \
  "streaming:streaming device" \
  "airconditioner:smart air conditioner" \
  "cameras:security camera" ; do
  cat="${pair%%:*}"; kw="${pair#*:}"
  reviews_dir="data/difference/$cat/$DIRECTION/reviews"
  if [ ! -d "$reviews_dir" ]; then
    echo "=== [$(date '+%H:%M:%S')] $cat/$DIRECTION — SKIP (no reviews dir; run make_review_copies.py first)"
    continue
  fi
  echo "=== [$(date '+%H:%M:%S')] $cat/$DIRECTION ($kw) ==="
  python3 scripts/merge_judgments.py --reviews "$reviews_dir" \
      --run-gemini --category "$kw" --model "$MODEL" --rps "$RPS" \
      || echo "FAILED: $cat/$DIRECTION"
done
echo "=== GEMMA RUN COMPLETE [$(date '+%H:%M:%S')] ==="
