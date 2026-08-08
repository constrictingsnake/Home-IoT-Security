#!/usr/bin/env python3
"""Phase 3 — inter-annotator agreement over the facet kappa subsample.

Reads the three blind annotation copies in data/facets/annotation-kit/ and reports, per
facet, how reliably the value can be assigned at all. This is the statistic that decides
whether a facet may be cited: PLAN_facet_annotation.md Phase 5 promotes on kappa >= 0.60,
allows grouping-only use at 0.40-0.60, and leaves anything below at hiot:Estimated.

    python3 scripts/facet_agreement.py                  # per-facet table
    python3 scripts/facet_agreement.py --verbose        # + per-item disagreements
    python3 scripts/facet_agreement.py --csv out.csv    # machine-readable

WHAT KAPPA MEANS HERE, AND WHAT IT DOES NOT.
    Agreement is RELIABILITY: do independent annotators assign the same value? It is not
    VALIDITY: three annotators can agree perfectly on a value that is wrong. Validity is
    what facet_sample.py's modal share measures, and it sits upstream — a facet that
    Phase A marked NOT-USABLE for a category is not rescued by high kappa, because the
    disagreement being measured is between annotators, not with the world. The two
    statistics answer different questions and both gates must pass.

THREE LLMS ARE NOT THREE INDEPENDENT EXPERTS. Shared pretraining means correlated error,
so kappa here OVERSTATES true reliability. Worse for this panel specifically: Claude
authored both the prior facet assignment and the value definitions the other two annotate
against. Human adjudication of disagreements AND of a sample of agreements is the partial
mitigation; it is not a fix, and the writeup must say so rather than reporting kappa bare.

THE KAPPA PARADOX IS LOAD-BEARING, NOT A FOOTNOTE. Where one value dominates a facet
(placement is Indoor nearly everywhere), chance agreement approaches observed agreement
and kappa collapses toward 0 even at ~95% raw agreement. A bare kappa there reports
PREVALENCE, not disagreement. So raw agreement and PABAK are printed beside every kappa,
and cells whose majority value exceeds --skew-threshold are marked `skewed`, meaning:
read the raw agreement, the kappa is uninformative. This is a reporting fix, not a
statistical one — no adjustment repairs n=40 at 95% prevalence.

UNSURE IS SCORED AS A VALUE, not as a missing answer. Fleiss' kappa needs a fixed rater
count per item; dropping one annotator's `unsure` would leave that item with 2 raters and
invalidate the statistic. Treating it as a value deflates kappa, which is the conservative
and honest direction — an annotator who cannot assign a value has not agreed with one who
can. The per-facet unsure RATE is reported separately so a kappa depressed by abstention
is distinguishable from one depressed by conflict.
"""
import argparse
import csv
import os
import random
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KIT = os.path.join(ROOT, "data", "facets", "annotation-kit")
ANNOTATORS = ["claude", "codex", "gemini"]
DISTRIBUTION = os.path.join(ROOT, "data", "facets", "facet_distribution.csv")

# Phase 5 promotion bands, stated here so the thresholds live next to the statistic that
# feeds them. Decided in advance precisely so a disappointing number cannot be
# rationalised into a passing one after the fact.
BANDS = [(0.60, "CITABLE"), (0.40, "grouping-only"), (0.0, "stays-Estimated")]


def band(k):
    if k is None:
        return "n/a"
    for lo, name in BANDS:
        if k >= lo:
            return name
    return "stays-Estimated"


def load_annotations():
    """{(device, facet): {annotator: value}} over rows all three annotators share.

    The kappa subsample is the intersection by construction (make_facet_copies.py draws
    it), but it is recomputed here rather than assumed: a partially-filled column would
    otherwise silently reduce the rater count on some items and inflate agreement.
    """
    per = {}
    for name in ANNOTATORS:
        path = os.path.join(KIT, f"{name}.csv")
        if not os.path.exists(path):
            raise SystemExit(f"missing annotation copy: {path}")
        rows = {}
        with open(path, newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                v = (r.get("Value") or "").strip()
                if v:
                    rows[(r["device"], r["facet"])] = {
                        "value": v,
                        "conf": (r.get("Confidence") or "").strip(),
                        "category": r["category"],
                    }
        per[name] = rows

    shared = set.intersection(*(set(r) for r in per.values()))
    out = {}
    for key in shared:
        out[key] = {n: per[n][key] for n in ANNOTATORS}
    return out, per


def fleiss_kappa(items):
    """items: list of lists of category labels (one list per item, one label per rater).

    Returns (kappa, p_observed, p_expected) or (None, ...) when undefined — which happens
    when every rater on every item chose the same single label, so there is no variance
    for chance agreement to be computed against.
    """
    if not items:
        return None, None, None
    n = len(items[0])
    if n < 2 or any(len(i) != n for i in items):
        return None, None, None
    labels = sorted({v for i in items for v in i})
    N = len(items)

    p_obs = 0.0
    for i in items:
        c = Counter(i)
        p_obs += (sum(v * v for v in c.values()) - n) / (n * (n - 1))
    p_obs /= N

    totals = Counter(v for i in items for v in i)
    p_exp = sum((totals[l] / (N * n)) ** 2 for l in labels)

    if abs(1 - p_exp) < 1e-12:
        # Degenerate: one label everywhere. Perfect agreement carries no information
        # about reliability, so report it as undefined rather than as kappa=1.
        return None, p_obs, p_exp
    return (p_obs - p_exp) / (1 - p_exp), p_obs, p_exp


def raw_agreement(items):
    """Share of items on which all raters chose the same label."""
    if not items:
        return None
    return sum(1 for i in items if len(set(i)) == 1) / len(items)


def pabak(p_obs, n_labels):
    """Prevalence-adjusted bias-adjusted kappa.

    PABAK asks what kappa would be if the labels were equally prevalent, which is the
    right correction when a facet is dominated by one value. It is a rescaling of
    observed agreement, so it does NOT rescue a small n — it only stops prevalence being
    misread as disagreement.
    """
    if p_obs is None or n_labels < 2:
        return None
    return (n_labels * p_obs - 1) / (n_labels - 1)


def bootstrap_ci(items, reps=2000, seed=20260807):
    """Percentile 95% CI on Fleiss' kappa, resampling ITEMS (devices), not ratings.

    Non-negotiable per the plan: 40 devices is a small sample and a bare point estimate
    would overstate precision. Resampling items is the right unit because items are what
    was sampled; raters are fixed and exhaustive.
    """
    if len(items) < 3:
        return None, None
    rng = random.Random(seed)
    ks = []
    for _ in range(reps):
        draw = [items[rng.randrange(len(items))] for _ in range(len(items))]
        k, _o, _e = fleiss_kappa(draw)
        if k is not None:
            ks.append(k)
    if len(ks) < reps * 0.5:
        # Too many degenerate resamples for the interval to mean anything.
        return None, None
    ks.sort()
    return ks[int(0.025 * len(ks))], ks[int(0.975 * len(ks))]


def skew(items):
    """Share held by the single most common label across all ratings."""
    c = Counter(v for i in items for v in i)
    return max(c.values()) / sum(c.values()) if c else 0.0


def self_test():
    """Validate the statistics against known values before anyone cites them.

    A kappa implementation is easy to get subtly wrong and impossible to eyeball, and
    this one decides which facets reach the paper. The canonical case is the standard
    14-rater/10-subject/5-category worked example (kappa = 0.210); the rest pin the
    edges that matter here — degenerate single-label input must come back UNDEFINED
    rather than 1.0, since "everyone said Indoor" is prevalence, not reliability.
    """
    checks = []

    tab = [[0, 0, 0, 0, 14], [0, 2, 6, 4, 2], [0, 0, 3, 5, 6], [0, 3, 9, 2, 0],
           [2, 2, 8, 1, 1], [7, 7, 0, 0, 0], [3, 2, 6, 3, 0], [2, 5, 3, 2, 2],
           [6, 5, 2, 1, 0], [0, 2, 2, 3, 7]]
    items = [[str(c) for c, n in enumerate(row) for _ in range(n)] for row in tab]
    k, _o, _e = fleiss_kappa(items)
    checks.append(("canonical 14-rater example = 0.210", k is not None and abs(k - 0.2101) < 0.001, f"{k:.4f}"))

    k, _o, _e = fleiss_kappa([["a"] * 3] * 5 + [["b"] * 3] * 5)
    checks.append(("perfect agreement, 2 labels = 1.0", k == 1.0, str(k)))

    k, p_obs, _e = fleiss_kappa([["a"] * 3] * 5)
    checks.append(("single label everywhere = UNDEFINED", k is None and p_obs == 1.0, str(k)))

    k, _o, _e = fleiss_kappa([["a", "b", "c"]] * 6)
    checks.append(("total disagreement < 0", k is not None and k < 0, f"{k:.3f}"))

    checks.append(("raw agreement", raw_agreement([["a"] * 3, ["a", "a", "b"]]) == 0.5, "0.50"))
    checks.append(("PABAK at p_obs=1, 2 labels = 1.0", pabak(1.0, 2) == 1.0, "1.00"))

    lo, hi = bootstrap_ci([["a"] * 3] * 20 + [["b"] * 3] * 20, reps=200)
    checks.append(("bootstrap CI brackets kappa=1", lo is not None and hi is not None
                   and lo <= 1.0 <= hi + 1e-9, f"[{lo}, {hi}]"))

    print("statistics self-test")
    print("-" * 60)
    for name, ok, got in checks:
        print(f"  {'ok  ' if ok else 'FAIL'}  {name:38} {got}")
    bad = [n for n, ok, _g in checks if not ok]
    print("-" * 60)
    print("self-test: PASS" if not bad else f"self-test: FAIL — {bad}")
    return 0 if not bad else 1


def load_phase_a():
    """{(category, facet): verdict} so kappa can be read next to validity."""
    if not os.path.exists(DISTRIBUTION):
        return {}
    with open(DISTRIBUTION, newline="", encoding="utf-8") as fh:
        return {(r["category"], r["facet"]): r.get("verdict", "").strip()
                for r in csv.DictReader(fh)}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--skew-threshold", type=float, default=0.85,
                    help="mark a facet `skewed` above this single-label share, meaning "
                         "its kappa reports prevalence rather than disagreement "
                         "(default 0.85)")
    ap.add_argument("--reps", type=int, default=2000, help="bootstrap replicates")
    ap.add_argument("--verbose", action="store_true",
                    help="list every item the annotators split on")
    ap.add_argument("--csv", help="write the per-facet table here")
    ap.add_argument("--self-test", action="store_true",
                    help="validate the statistics against known values and exit")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    shared, per = load_annotations()
    filled = {n: len(r) for n, r in per.items()}
    print("annotation copies (filled rows): "
          + ", ".join(f"{n} {c}" for n, c in filled.items()))

    if not shared:
        print("\nNO SHARED ANNOTATED ROWS — agreement cannot be computed.")
        print("Every annotator must fill the kappa subsample before this reports "
              "anything. Nothing in Phase A is citable until then.")
        return 1

    print(f"shared fully-annotated items: {len(shared)}\n")

    by_facet = defaultdict(list)
    for (device, facet), got in sorted(shared.items()):
        by_facet[facet].append((device, got))

    phase_a = load_phase_a()
    rows = []
    print(f"{'facet':22} {'n':>4} {'kappa':>7} {'95% CI':>16} {'raw':>6} "
          f"{'PABAK':>7} {'unsure':>7}  band / note")
    print("-" * 104)

    for facet in sorted(by_facet):
        entries = by_facet[facet]
        items = [[got[a]["value"] for a in ANNOTATORS] for _dev, got in entries]
        k, p_obs, _p_exp = fleiss_kappa(items)
        lo, hi = bootstrap_ci(items, reps=args.reps)
        raw = raw_agreement(items)
        n_labels = len({v for i in items for v in i})
        pab = pabak(p_obs, max(n_labels, 2))
        unsure = sum(1 for i in items for v in i if v == "unsure") / (len(items) * 3)
        sk = skew(items)

        note = band(k)
        if sk > args.skew_threshold:
            note = f"SKEWED ({sk:.0%} one value) — read raw, kappa uninformative"
        elif k is None:
            note = "kappa undefined (no label variance) — read raw"

        ci = f"[{lo:.2f}, {hi:.2f}]" if lo is not None else "—"
        print(f"{facet:22} {len(items):4d} "
              f"{(f'{k:7.3f}' if k is not None else '      —')} {ci:>16} "
              f"{raw:6.0%} {(f'{pab:7.3f}' if pab is not None else '      —')} "
              f"{unsure:7.1%}  {note}")

        rows.append({
            "facet": facet, "n_items": len(items),
            "fleiss_kappa": f"{k:.4f}" if k is not None else "",
            "ci_low": f"{lo:.4f}" if lo is not None else "",
            "ci_high": f"{hi:.4f}" if hi is not None else "",
            "raw_agreement": f"{raw:.4f}", "pabak": f"{pab:.4f}" if pab is not None else "",
            "unsure_rate": f"{unsure:.4f}", "top_label_share": f"{sk:.4f}",
            "skewed": "yes" if sk > args.skew_threshold else "",
            "band": band(k),
        })

    # Per-annotator profile. CLAUDE.md records that on CVE review Codex over-excludes and
    # Gemini over-includes; whether the same directional bias shows up on facets is worth
    # knowing before trusting any merge rule built on that profile.
    print("\nper-annotator profile (does the documented bias reappear on facets?)")
    for a in ANNOTATORS:
        vals = [got[a] for _d, got in shared.items()]
        uns = sum(1 for v in vals if v["value"] == "unsure") / len(vals)
        high = sum(1 for v in vals if v["conf"] == "High") / len(vals)
        print(f"  {a:8} unsure {uns:5.1%}   High-confidence {high:5.1%}")

    # Agreement with the author's prior is deliberately NOT part of kappa: the prior is
    # one of the things under test. Reported separately, and note the unit mismatch —
    # the prior is category-level, so it is broadcast onto product rows here.
    disputed = [(d, g) for (d, f), g in shared.items()
                if len({g[a]["value"] for a in ANNOTATORS}) > 1]
    print(f"\nitems with any split: {len(disputed)} of {len(shared)} "
          f"({len(disputed)/len(shared):.0%})")

    if phase_a:
        both = Counter()
        for (device, facet), got in shared.items():
            cat = got[ANNOTATORS[0]]["category"]
            v = phase_a.get((cat, facet))
            if v:
                split = len({got[a]["value"] for a in ANNOTATORS}) > 1
                both[(v, "split" if split else "unanimous")] += 1
        print("\nkappa vs Phase A validity (reliability and validity are independent —"
              "\na cell can be agreed-on and still be a fiction):")
        for verdict in sorted({k[0] for k in both}):
            u, s = both[(verdict, "unanimous")], both[(verdict, "split")]
            tot = u + s
            print(f"  {verdict:32} {u:4d} unanimous / {s:3d} split  "
                  f"({u/tot:.0%} agreement)" if tot else "")

    if args.verbose and disputed:
        print("\nitems the annotators split on:")
        for device, got in sorted(disputed)[:60]:
            vals = " | ".join(f"{a}={got[a]['value']}" for a in ANNOTATORS)
            print(f"  {device[:44]:46} {vals}")

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        print(f"\nwrote {args.csv}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
