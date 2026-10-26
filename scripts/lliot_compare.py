#!/usr/bin/env python3
"""Build the blind adjudication sheet for the LLIoT-method experiment (P5).

docs/plans/PLAN_lliot_method_comparison.md § The adjudication sheet, as amended 2026-10-26
(one adjudicator, ~2 hours). Compares the model's labels with the pipeline's, then draws:

  core (~118 rows, shuffled together; the adjudicator does all of these)
    cat-disagree   every CVE in Y/M/R where both say home IoT but the category sets differ
    control        15 where both say home IoT with the same categories (shared errors)
    u1-model-yes   20 of the U1 CVEs the model calls home IoT and the pipeline never surfaced
  extension (shuffled; done in sheet order, as far as time allows; stopping is by time only)
    every other home-IoT disagreement: N, Y, R, U1 (rest), U2, U3
  retest          15 core rows, reshuffled under new row IDs, done >= 1 week after the core

  -> data/lliot-comparison/adjudication/sheet_A.csv    what the adjudicator fills in
  -> data/lliot-comparison/adjudication/retest_A.csv   the test-retest pass
  -> data/lliot-comparison/adjudication/_key.csv       row -> cve_id, block, stratum, prior exposure

BLINDNESS: the sheets show only description and cpe_strings under an opaque row ID. No CVE ID,
no model or pipeline label, no stratum, no block. The adjudicator must never open _key.csv
(block membership says which way the methods disagreed). This script prints counts only.

Usage:
    python3 scripts/lliot_compare.py            # refuses to overwrite an existing sheet
"""
import collections
import csv
import glob
import json
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXP = os.path.join(ROOT, "data", "lliot-comparison")
OUT = os.path.join(EXP, "adjudication")
STORE = os.path.join(ROOT, "data", "difference", "judgment_store.csv")
SEED = 20261016 + 2  # +1 picked the reruns
N_CONTROL, N_U1, N_RETEST = 15, 20, 15
SHEET_FIELDS = ["row", "description", "cpe_strings", "home_iot", "categories",
                "exclusion_reason", "notes"]


def group(stratum):
    """Y sub-strata (Y-cameras, ...) collapse to Y; N-/X- variants to N/X."""
    if stratum.startswith("Y"):
        return "Y"
    return stratum.split("-")[0] if stratum[0] in "NX" else stratum


def main():
    sheet_path = os.path.join(OUT, "sheet_A.csv")
    if os.path.exists(sheet_path):
        sys.exit(f"STOP: {sheet_path} exists. The sheet is drawn once; delete it deliberately "
                 "(and amend the plan) to redraw.")
    man = {r["cve_id"]: r["stratum"]
           for r in csv.DictReader(open(os.path.join(EXP, "manifest.csv"), encoding="utf-8"))}

    pipe, prior = collections.defaultdict(set), set()
    for r in csv.DictReader(open(STORE, encoding="utf-8")):
        if r["cve_id"] not in man:
            continue
        if r["Final Judgment"] == "Yes" and not r["Excluded"].strip():
            pipe[r["cve_id"]].add(r["category"])
        if r["Final Source"] == "human" or r["Human Verdict 1"].strip() or r["Human Verdict 2"].strip():
            prior.add(r["cve_id"])

    model, payload = {}, {}
    for f in glob.glob(os.path.join(EXP, "outputs", "A", "main", "*.json")):
        for e in json.load(open(f, encoding="utf-8"))["results"]:
            model[e["cve_id"]] = e
    for f in glob.glob(os.path.join(EXP, "run-kit", "jobs", "main", "job-*.json")):
        for p in json.load(open(f, encoding="utf-8")):
            payload[p["cve_id"]] = p
    missing = set(man) - set(model)
    if missing:
        sys.exit(f"STOP: {len(missing)} sampled CVEs have no model output; finish the main run first.")

    cat_dis, agree, u1_yes, home_dis = [], [], [], []
    for cve in sorted(man):
        g, e = group(man[cve]), model[cve]
        p_yes, m_yes = bool(pipe[cve]), e["home_iot"] != "No"
        if p_yes != m_yes:
            (u1_yes if g == "U1" else home_dis).append(cve)
        elif p_yes and set(e["categories"]) != pipe[cve]:
            cat_dis.append(cve)
        elif p_yes and g in ("Y", "M", "R"):
            agree.append(cve)

    rng = random.Random(SEED)
    control = rng.sample(agree, N_CONTROL)
    u1_core = rng.sample(u1_yes, N_U1)
    core = ([(c, "cat-disagree") for c in cat_dis] + [(c, "control") for c in control]
            + [(c, "u1-model-yes") for c in u1_core])
    rest_u1 = sorted(set(u1_yes) - set(u1_core))
    ext = [(c, "ext-home-disagree") for c in home_dis + rest_u1]
    rng.shuffle(core)
    rng.shuffle(ext)
    retest = rng.sample(core, N_RETEST)
    rng.shuffle(retest)

    os.makedirs(OUT, exist_ok=True)
    key = []

    def write_sheet(path, rows, prefix):
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=SHEET_FIELDS)
            w.writeheader()
            for i, (cve, block) in enumerate(rows, 1):
                rid = f"{prefix}{i:03d}"
                w.writerow({"row": rid, "description": payload[cve]["description"],
                            "cpe_strings": payload[cve]["cpe_strings"]})
                key.append({"row": rid, "cve_id": cve, "block": block,
                            "stratum": man[cve], "prior_exposure": "yes" if cve in prior else "no"})

    write_sheet(sheet_path, core + ext, "R")
    write_sheet(os.path.join(OUT, "retest_A.csv"), retest, "T")
    with open(os.path.join(OUT, "_key.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["row", "cve_id", "block", "stratum", "prior_exposure"])
        w.writeheader()
        w.writerows(key)

    blocks = collections.Counter(k["block"] for k in key if k["row"].startswith("R"))
    print(f"sheet_A.csv: {len(core)} core rows (R001-R{len(core):03d}), then {len(ext)} extension rows")
    for b in ("cat-disagree", "control", "u1-model-yes", "ext-home-disagree"):
        print(f"  {b:18s} {blocks[b]:4d}")
    print(f"retest_A.csv: {len(retest)} rows")
    print(f"prior exposure: {sum(k['prior_exposure'] == 'yes' for k in key if k['row'].startswith('R'))} sheet rows")


if __name__ == "__main__":
    main()
