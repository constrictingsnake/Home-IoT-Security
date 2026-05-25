#!/bin/bash

KEYWORDS=("fitbit" "garmin" "apple watch" "samsung galaxy watch" "withings" "whoop strap" "whoop firmware" "whoop app" "polar sleep" "suunto" "amazfit" "mobvoi" "beddit" "emfit" "resmed" "philips respironics" "philips dreamstation" "somnox" "dreem" "kokoon" "sleep number" "tempur-pedic" "beautyrest" "dodow sleep" "sleepon" "sleeptracker monitor" "loona sleep" "lumie connected" "biostrap" "wearable sleep tracker" "smart mattress" "sleep monitor" "breathing rate monitor")
DIR_NAME="CVEs_By_Year"
OUTPUT_DIR="Results"

for YEAR in {2002..2026}; do
    python cve_search.py \
        --input ${DIR_NAME}/nvd_${YEAR}.csv \
        --keywords "${KEYWORDS[@]}" \
        --no-preview \
        --output ${OUTPUT_DIR}/${YEAR}_out.csv
done

python cve_search.py \
    --merge ${OUTPUT_DIR}/*.csv \
    --merged-out results_all.csv