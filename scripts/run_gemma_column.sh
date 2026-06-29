#!/usr/bin/env bash
# One-pass Gemma 4 31B review of the ENTIRE Gemini column (all ~24 analysis categories).
#
# Designed to straddle the daily RPD reset: started ~95 min before reset at --rps 0.30
# (~11.6 rows/min), so requests are spread across the reset and stay under the 1,500/day cap.
#
# Reviews are now combined per category (vendor_only + keyword_only in one file) under
# data/difference/<cat>/reviews/. The Difference Type column on each row distinguishes
# which direction a CVE came from.
#
# Prep (back up the 3.1 baseline + blank the Gemini columns) runs ONCE, guarded by a
# per-category flag file, so the fill is fully resumable with no --redo.
#
# Launch (detached, survives closing the terminal):
#     nohup bash scripts/run_gemma_column.sh > gemma_run.log 2>&1 &
#     tail -f gemma_run.log     # watch progress
set -u
cd "$(dirname "$0")/.." || exit 1
set -a; source .env; set +a

MODEL="gemma-4-31b-it"
RPS="0.30"

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
  reviews_dir="data/difference/$cat/reviews"
  if [ ! -d "$reviews_dir" ]; then
    echo "=== [$(date '+%H:%M:%S')] $cat — SKIP (no reviews dir; run make_review_copies.py first)"
    continue
  fi

  flag="data/difference/$cat/.gemma_prepped"
  if [ ! -f "$flag" ]; then
    echo "[$(date '+%H:%M:%S')] Prep $cat: backing up 3.1 baseline + blanking Gemini columns ..."
    python3 - "$reviews_dir" <<'PY' || exit 1
import csv, os, shutil, sys
reviews_dir = sys.argv[1]
f = os.path.join(reviews_dir, "gemini.csv")
if not os.path.isfile(f):
    print(f"  no gemini.csv yet in {reviews_dir} — nothing to back up")
    sys.exit(0)
bak = os.path.join(reviews_dir, "gemini_3.1_baseline.csv")
if not os.path.exists(bak):
    shutil.copy2(f, bak)
with open(f, newline="") as fh:
    rows = list(csv.DictReader(fh)); fields = list(rows[0].keys()) if rows else []
for r in rows:
    for c in ("Gemini Judgment", "Gemini Confidence", "Gemini Reasoning"):
        if c in r: r[c] = ""
with open(f, "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=fields); w.writeheader(); w.writerows(rows)
print(f"  3.1 saved as gemini_3.1_baseline.csv, Gemini columns cleared.")
PY
    touch "$flag"
  else
    echo "[$(date '+%H:%M:%S')] $cat prep already done — resuming fill only."
  fi

  echo "=== [$(date '+%H:%M:%S')] $cat ($kw) ==="
  python3 scripts/merge_judgments.py --reviews "$reviews_dir" \
      --run-gemini --category "$kw" --model "$MODEL" --rps "$RPS" \
      || echo "FAILED: $cat"
done
echo "=== GEMMA RUN COMPLETE [$(date '+%H:%M:%S')] ==="
