#!/usr/bin/env python3
"""F4 — is `cameras` two device types, and can they be told apart from a product name?

Phase A measured cameras/capturesAV at 0.591: 17 of 40 sampled camera devices were
annotated false, every one of them a DVR/NVR/XVR, each with the same rationale — a
recorder has no lens or microphone of its own. That is not annotation error. Recorders
were DELIBERATELY ruled in scope (Frigate NVR = In, per the human-review reconciliation
record), so `cameras` legitimately holds two device types and one capturesAV value cannot
be true for both.

This matters beyond one facet because cameras is 51% of the confirmed population and the
capturesAV=true cell is the worked example the whole dominance rule rests on (CLAUDE.md:
1,120 rows, 79% cameras). If only ~59% of camera CVE mass sits on devices that capture
AV, that share falls to roughly 68% — and note the DIRECTION: it makes the dominance
problem worse, not better. capturesAV is not even reliably cameras.

WHY NOT SPLIT THE CATEGORY. Costed and rejected: the vendor terms are bare brands
(hikvision, dahua, xiongmaitech) that make BOTH product types, so a `recorders` vendor
search returns the same V set and Stage 6's capture-recapture breaks — it needs V and K to
be independent captures of that category's population, and post-hoc partitioning of one V
is not that. The judgment store is keyed (category, cve_id), so re-slugging loses every
judgment. Fixing the facet at device level costs neither.

THE PILOT COMES FIRST, AND IT MAY SAY STOP. The full pass assumes recorder-vs-camera is
reliably judgeable from a product name. Measured here, that assumption is in trouble:
88.8% of the 1,674 camera devices carry NEITHER a camera-ish nor a recorder-ish token
(`reolink:rlc-410w`, `foscam:c2`). So the full pass would rest almost entirely on an
annotator's product-line knowledge, not on anything in the string. The pilot measures
whether that knowledge is actually there.

    Decision rule, fixed in advance (PLAN_facet_system_fixes.md F4):
      >= 80% confidently judgeable  -> run the full pass
      50-80%                        -> full pass, but the unjudgeable share is reported
                                       as its own class and never imputed
      <  50%                        -> STOP. Subtype cannot be read from names; the
                                       finding stays "capturesAV is not usable for
                                       cameras" and the distribution is reported instead.

THE TOKEN BASELINE IS AN EXTERNAL CHECK, AND IT IS DELIBERATELY KEPT OUT OF THE SHEET.
A mechanical rule (does the product name contain nvr/dvr/xvr/recorder?) is evidence-free
of any annotator, so where it fires it is the closest thing to ground truth available.
It is computed here and compared at --aggregate, but never shown to the annotator, who
would otherwise anchor on it and the agreement would measure the anchor.

    python3 scripts/camera_subtype.py --frame       # token baseline, no draw
    python3 scripts/camera_subtype.py --draw        # -> camera_subtype_pilot.csv
    python3 scripts/camera_subtype.py --aggregate   # filled sheet -> judgeability verdict
"""
import argparse
import csv
import os
import random
import re
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRAME = os.path.join(ROOT, "data", "facets", "product_frame.csv")
OUT_DIR = os.path.join(ROOT, "data", "facets")
PILOT = os.path.join(OUT_DIR, "camera_subtype_pilot.csv")

CATEGORY = "cameras"
ALLOWED = "camera|recorder|other|unsure"
DEFAULT_N = 100
DEFAULT_SEED = 20260807

# Matched on the product name split by [_-.], exactly like cpe_product_scan.py's token
# rule, so `cam` cannot hit `camshaft` and `dvr` cannot hit `dvrip`. Deliberately narrow:
# this is meant to be high-precision where it fires and silent everywhere else, because
# its job is to be a check, not a classifier.
RECORDER_TOKENS = {"nvr", "nvrs", "dvr", "dvrs", "xvr", "hvr", "recorder", "recorders",
                   "videorecorder"}
CAMERA_TOKENS = {"camera", "cameras", "cam", "ipcamera", "ipcam", "webcam", "ptz",
                 "bullet", "dome", "turret", "doorbell"}

SHEET_COLS = ["category", "device", "vendor", "product", "cve_count",
              "allowed_values", "Value", "Confidence", "Reasoning"]

# Same tripwire as facet_gemini.py, for the same reason: if subtype were read off CVE
# text, then the corrected capturesAV number would be correlated with the weakness data
# it is later contrasted against.
FORBIDDEN_COLS = {"description", "cve_id", "cwe", "cwe_id", "cvss", "base_score",
                  "vector_string", "cpe_strings"}


def tokens(product):
    return {t for t in re.split(r"[_\-.]+", product.lower()) if t}


def token_baseline(product):
    """'recorder' / 'camera' / '' — the mechanical read, empty when the name is silent."""
    tk = tokens(product)
    rec, cam = tk & RECORDER_TOKENS, tk & CAMERA_TOKENS
    if rec and not cam:
        return "recorder"
    if cam and not rec:
        return "camera"
    return ""


def load_frame(path=FRAME):
    if not os.path.exists(path):
        raise SystemExit(f"missing {path} — run facet_sample.py --draw first")
    with open(path, newline="", encoding="utf-8") as fh:
        return [r for r in csv.DictReader(fh) if r["category"] == CATEGORY]


def report_frame(rows):
    n = len(rows)
    base = Counter(token_baseline(r["product"]) for r in rows)
    silent = base[""]
    print(f"`{CATEGORY}` devices in the drawn frame: {n}")
    print(f"  token says recorder : {base['recorder']:5d}  ({base['recorder']/n:.1%})")
    print(f"  token says camera   : {base['camera']:5d}  ({base['camera']/n:.1%})")
    print(f"  token SILENT        : {silent:5d}  ({silent/n:.1%})")
    print()
    print("The silent share is the whole risk. Where the token rule is silent the full")
    print("pass rests entirely on an annotator's product-line knowledge, with nothing in")
    print("the string to check it against. That is what the pilot measures.")
    ex = [r["device"] for r in rows if not token_baseline(r["product"])][:6]
    print(f"  examples: {', '.join(ex)}")
    cve = sum(int(r["cve_count"]) for r in rows)
    cve_silent = sum(int(r["cve_count"]) for r in rows if not token_baseline(r["product"]))
    print(f"\nCVE weight: {cve} confirmed-Yes CVE attributions over these devices; "
          f"{cve_silent} ({cve_silent/cve:.1%}) sit on token-silent devices.")


def draw(rows, n, seed, overwrite):
    if os.path.exists(PILOT) and not overwrite:
        raise SystemExit(f"{PILOT} exists — pass --overwrite to redraw "
                         "(this DISCARDS any annotation already in it)")
    rng = random.Random(seed)
    # Stratify by the token baseline so the pilot cannot come back trivially easy or
    # trivially hard by luck of the draw. Proportional to the population, so the
    # judgeability figure still estimates the real mix rather than a balanced one.
    by = {"recorder": [], "camera": [], "": []}
    for r in rows:
        by[token_baseline(r["product"])].append(r)
    picked = []
    for stratum, items in by.items():
        take = max(1, round(n * len(items) / len(rows))) if items else 0
        take = min(take, len(items))
        picked += rng.sample(sorted(items, key=lambda r: r["device"]), take)
    picked.sort(key=lambda r: r["device"])

    with open(PILOT, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=SHEET_COLS)
        w.writeheader()
        for r in picked:
            w.writerow({"category": CATEGORY, "device": r["device"], "vendor": r["vendor"],
                        "product": r["product"], "cve_count": r["cve_count"],
                        "allowed_values": ALLOWED, "Value": "", "Confidence": "",
                        "Reasoning": ""})
    assert not (set(SHEET_COLS) & FORBIDDEN_COLS), "sheet must carry no CVE-derived column"
    strat = Counter(token_baseline(r["product"]) for r in picked)
    print(f"drew {len(picked)} devices (seed {seed}) -> {os.path.relpath(PILOT, ROOT)}")
    print(f"  strata: recorder-token {strat['recorder']}, camera-token {strat['camera']}, "
          f"silent {strat['']}")
    print("\nThe token baseline is NOT in the sheet — annotating against it would measure")
    print("the anchor. --aggregate joins it back afterwards.")


def aggregate():
    if not os.path.exists(PILOT):
        raise SystemExit(f"missing {PILOT} — run --draw first")
    with open(PILOT, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    filled = [r for r in rows if (r["Value"] or "").strip()]
    if not filled:
        print(f"{PILOT}: 0 of {len(rows)} rows annotated — nothing to aggregate.")
        return 1

    print(f"pilot: {len(filled)} of {len(rows)} rows annotated\n")
    vals = Counter(r["Value"].strip() for r in filled)
    conf = Counter((r["Value"].strip(), (r["Confidence"] or "").strip()) for r in filled)

    # JUDGEABILITY is the pilot's actual question: a confident, non-unsure call.
    judgeable = sum(n for (v, c), n in conf.items() if v != "unsure" and c == "High")
    rate = judgeable / len(filled)
    print("subtype distribution (product-weighted)")
    for v, n in vals.most_common():
        print(f"  {v:10} {n:4d}  {n/len(filled):6.1%}")

    cve_tot = sum(int(r["cve_count"]) for r in filled)
    print("\nsubtype distribution (CVE-weighted — what the analysis actually joins onto)")
    for v, _n in vals.most_common():
        w = sum(int(r["cve_count"]) for r in filled if r["Value"].strip() == v)
        print(f"  {v:10} {w:4d}  {w/cve_tot:6.1%}")

    print(f"\nJUDGEABILITY: {judgeable}/{len(filled)} = {rate:.1%} "
          f"confident non-unsure calls")
    if rate >= 0.80:
        verdict = "PROCEED — run the full pass on all 1,674 devices"
    elif rate >= 0.50:
        verdict = ("PROCEED WITH A CAVEAT — run the full pass, but report the "
                   "unjudgeable share as its own class and never impute it")
    else:
        verdict = ("STOP — subtype is not readable from product names. Report "
                   "cameras/capturesAV as a distribution; do not attempt the full pass")
    print(f"  verdict: {verdict}")

    # The external check. Where the mechanical rule fires it is annotator-independent,
    # so disagreement here is the strongest available signal that the annotation is
    # tracking the product rather than confabulating.
    checked = [r for r in filled if token_baseline(r["product"])]
    if checked:
        agree = sum(1 for r in checked
                    if r["Value"].strip() == token_baseline(r["product"]))
        print(f"\nTOKEN CHECK (annotator-independent): {agree}/{len(checked)} = "
              f"{agree/len(checked):.1%} agreement where the name carries a token")
        for r in checked:
            base = token_baseline(r["product"])
            if r["Value"].strip() != base:
                print(f"  MISMATCH {r['device'][:44]:46} token={base:9} "
                      f"annotator={r['Value'].strip()}")
        silent = [r for r in filled if not token_baseline(r["product"])]
        if silent:
            s_judge = sum(1 for r in silent if r["Value"].strip() != "unsure"
                          and (r["Confidence"] or "").strip() == "High")
            print(f"\n  on token-SILENT devices ({len(silent)}): {s_judge} confident "
                  f"calls ({s_judge/len(silent):.1%}) — these rest on product-line "
                  f"knowledge with no external check available")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--frame", action="store_true", help="token baseline stats, no draw")
    ap.add_argument("--draw", action="store_true", help="draw the pilot sample")
    ap.add_argument("--aggregate", action="store_true", help="read the filled sheet back")
    ap.add_argument("-n", type=int, default=DEFAULT_N, help=f"pilot size (default {DEFAULT_N})")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--overwrite", action="store_true", help="redraw over an existing sheet")
    args = ap.parse_args()

    if not any((args.frame, args.draw, args.aggregate)):
        ap.error("pick one of --frame / --draw / --aggregate")
    if args.aggregate:
        return aggregate()
    rows = load_frame()
    if args.frame:
        report_frame(rows)
        return 0
    report_frame(rows)
    print()
    draw(rows, args.n, args.seed, args.overwrite)
    return 0


if __name__ == "__main__":
    sys.exit(main())
