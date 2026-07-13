#!/usr/bin/env python3
r"""Capture-recapture recall estimation for the two (and three) discovery methods.

The pipeline measures *precision* (false-positive rate via review) well but has no
answer to "what fraction of real in-scope CVEs did we find?". This script supplies a
per-category recall estimate from counts we already have, treating the searches as
mark-recapture capture occasions.

METHODS
  Two-source (all categories): vendor (V) and keyword (K) searches are two captures of
  the same underlying population of true in-scope CVEs. Chapman's estimator (the
  bias-corrected Lincoln-Petersen, stable at small overlap) gives N-hat; combined recall
  = |V u K| / N-hat. Reported with a log-normal 95% CI (Chao), which never goes < the
  observed count.

  Three-source (categories with a CPE-expansion capture set): adds C = every CVE NVD
  attributes to a confirmed-Yes device CPE (reconstructed here from the snapshot WITH its
  overlaps against V and K intact -- the stored 09_*_candidates.csv keeps only C \ (V u K),
  which discards the overlap cells a log-linear model needs). We fit hierarchical Poisson
  log-linear models over the 7 observable inclusion cells, pick by AIC, and extrapolate the
  unobserved "missed by all three" cell. Three sources let the data estimate pairwise
  dependence instead of assuming independence -- the main weakness of naive two-source LP,
  since V and K share an engine/snapshot/fields and are positively correlated.

ESTIMANDS  (choose with --population)
  raw   -- population = candidate CVEs the searches *could* match (true + false positives).
           Recall of the search stage. Available for every category now.
  yes   -- population = TRUE in-scope CVEs. Each cell is scaled by its Yes-rate from review.
           Needs labels. The intersection cell (V n K) is NOT reviewed by the pipeline, so
           its precision is a supplied assumption (--isect-precision, default 1.0); we print
           a sensitivity band. Only categories with review labels appear here.

CAVEATS baked into the output
  * Positive dependence between V and K biases the two-source N-hat DOWN -> recall is an
    UPPER bound. The three-source estimate is the one to trust where available.
  * C is seeded from already-confirmed products, so it cannot capture a true CVE whose
    product never appeared in V/K -- list C's catchability is conditional, not independent.
    Three-source relaxes the V-K independence assumption but does not make C a clean third
    capture; read its N-hat as "population reachable through confirmed products".
  * Small m2 -> wide CI. Rows with m2 < 3 or |V u K| tiny are flagged low-confidence.

Run:  python3 scripts/recall_estimate.py                # raw, all categories, two-source
      python3 scripts/recall_estimate.py --three        # add three-source where C exists
      python3 scripts/recall_estimate.py --population yes --three
Output: printed table + data/difference/recall_estimate.csv
"""
import argparse
import csv
import math
import os
import sys

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cpe_expansion as ce  # reuse build_seeds / scan_snapshot / load helpers


# ---------------------------------------------------------------- set loading
def vendor_ids(cat):
    p = os.path.join(DATA, "vendor-search", f"results_all_{cat}.csv")
    if not os.path.exists(p):
        return set()
    import csv
    ids = set()
    with open(p, newline="") as f:
        for r in csv.DictReader(f):
            if r.get("cve_id"):
                ids.add(str(r["cve_id"]))
    return ids


def keyword_ids(cat):
    p = os.path.join(DATA, "keyword-search", f"keyword_{cat}.csv")
    if not os.path.exists(p):
        return set()
    with open(p, newline="") as f:
        return {r["cve_id"] for r in csv.DictReader(f)}


def categories():
    cats = []
    for fn in os.listdir(os.path.join(DATA, "keyword-search")):
        if (fn.startswith("keyword_") and fn.endswith(".csv")
                and "terms" not in fn and "candidates" not in fn):
            cats.append(fn[len("keyword_"):-len(".csv")])
    return sorted(cats)


# ---------------------------------------------------------------- review labels
def yes_rates(cat):
    """Per-direction (n_yes, n_judged) from final_resolved.csv for this category."""
    p = os.path.join(DATA, "difference", "final_resolved.csv")
    agg = {}  # direction -> [yes, judged]
    if not os.path.exists(p):
        return agg
    with open(p, newline="") as f:
        for r in csv.DictReader(f):
            if r["Category"] != cat:
                continue
            fj = (r.get("Final Judgment") or "").strip().lower()
            if fj not in ("yes", "no"):
                continue
            d = r["Direction"]
            agg.setdefault(d, [0, 0])
            agg[d][1] += 1
            if fj == "yes":
                agg[d][0] += 1
    return agg


# ---------------------------------------------------------------- two-source
def chapman(n1, n2, m2):
    """Chapman estimator + log-normal 95% CI. Returns (N_hat, lo, hi, se)."""
    obs = n1 + n2 - m2
    N = (n1 + 1) * (n2 + 1) / (m2 + 1) - 1
    var = ((n1 + 1) * (n2 + 1) * (n1 - m2) * (n2 - m2)
           / ((m2 + 1) ** 2 * (m2 + 2)))
    se = math.sqrt(var) if var > 0 else 0.0
    # Chao log-normal CI on the unseen count f0 = N - obs (keeps lower >= obs).
    f0 = N - obs
    if f0 > 0 and se > 0:
        C = math.exp(1.96 * math.sqrt(math.log(1 + var / f0 ** 2)))
        lo, hi = obs + f0 / C, obs + f0 * C
    else:
        lo = hi = N
    return N, lo, hi, se


# ---------------------------------------------------------------- three-source
def _poisson_irls(y, X, iters=100, tol=1e-10):
    """Poisson GLM (log link) via IRLS. Returns (beta, loglik)."""
    beta = np.zeros(X.shape[1])
    beta[0] = math.log(max(y.mean(), 1e-3))
    for _ in range(iters):
        eta = X @ beta
        mu = np.exp(np.clip(eta, -30, 30))
        W = mu
        z = eta + (y - mu) / mu
        WX = X * W[:, None]
        try:
            beta_new = np.linalg.solve(X.T @ WX, X.T @ (W * z))
        except np.linalg.LinAlgError:
            break
        if np.max(np.abs(beta_new - beta)) < tol:
            beta = beta_new
            break
        beta = beta_new
    mu = np.exp(np.clip(X @ beta, -30, 30))
    ll = np.sum(y * np.log(mu) - mu - np.array([math.lgamma(v + 1) for v in y]))
    return beta, ll


# hierarchical models over the 7 observable cells (000 is the unobserved target).
_LL_MODELS = {
    "indep":     ["int", "A", "B", "C"],
    "+AB":       ["int", "A", "B", "C", "AB"],
    "+AC":       ["int", "A", "B", "C", "AC"],
    "+BC":       ["int", "A", "B", "C", "BC"],
    "+AB+AC":    ["int", "A", "B", "C", "AB", "AC"],
    "+AB+BC":    ["int", "A", "B", "C", "AB", "BC"],
    "+AC+BC":    ["int", "A", "B", "C", "AC", "BC"],
    "+AB+AC+BC": ["int", "A", "B", "C", "AB", "AC", "BC"],
}


def _fit_loglinear(y):
    """AIC-select a hierarchical Poisson log-linear model over the 7 cells.

    y is ordered by the 7 non-empty inclusion patterns (see _LL_PATTERNS).
    Returns (name, N_hat, obs) or (None, nan, obs) if no model is stable.
    """
    obs = y.sum()
    A, B, C = (_LL_PAT_ARR[k] for k in "ABC")
    base = {"int": np.ones_like(A), "A": A, "B": B, "C": C,
            "AB": A * B, "AC": A * C, "BC": B * C}
    best = None
    for name, cols in _LL_MODELS.items():
        X = np.column_stack([base[c] for c in cols])
        beta, ll = _poisson_irls(y, X)
        if not np.isfinite(ll) or beta[0] > 25:          # separation / overfit blow-up
            continue
        n000 = math.exp(beta[0])                         # all effects zero at 000 cell
        if not math.isfinite(n000) or n000 > 20 * obs:   # implausible extrapolation
            continue
        aic = 2 * len(cols) - 2 * ll
        if best is None or aic < best[0]:
            best = (aic, name, obs + n000)
    if best is None:
        return None, float("nan"), obs
    return best[1], best[2], obs


_LL_PATTERNS = [(1, 0, 0), (0, 1, 0), (0, 0, 1), (1, 1, 0),
                (1, 0, 1), (0, 1, 1), (1, 1, 1)]
_LL_PAT_ARR = {"A": np.array([p[0] for p in _LL_PATTERNS], float),
               "B": np.array([p[1] for p in _LL_PATTERNS], float),
               "C": np.array([p[2] for p in _LL_PATTERNS], float)}


def loglinear3(cells, boot=800, seed=20260702):
    """Point estimate + nonparametric bootstrap 95% CI for the 3-source estimate.

    cells: pattern(tuple in {0,1}^3) -> observed count. Bootstrap resamples the observed
    CVEs multinomially across the 7 cells and RE-SELECTS the model each replicate, so the
    CI absorbs both sampling and model-selection uncertainty. Returns dict with name,
    N_hat, obs, N_lo, N_hi (percentile CI over N_hat).
    """
    y = np.array([cells.get(p, 0) for p in _LL_PATTERNS], dtype=float)
    name, N, obs = _fit_loglinear(y)
    obs = int(obs)
    rng = np.random.default_rng(seed)
    p = y / y.sum()
    draws = []
    for _ in range(boot):
        yb = rng.multinomial(obs, p).astype(float)
        _, Nb, _ = _fit_loglinear(yb)
        if math.isfinite(Nb):
            draws.append(Nb)
    if len(draws) >= boot // 2:
        lo, hi = np.percentile(draws, [2.5, 97.5])
    else:
        lo = hi = float("nan")
    return dict(name=name or "unstable", N=N, obs=obs, lo=lo, hi=hi)


# ---------------------------------------------------------------- driver
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--population", choices=["raw", "yes"], default="raw")
    ap.add_argument("--three", action="store_true",
                    help="add the three-source log-linear estimate where a CPE-expansion "
                         "capture set exists (needs snapshot + confirmed-Yes seeds)")
    ap.add_argument("--isect-precision", type=float, default=1.0,
                    help="assumed Yes-rate of the V n K intersection cell (population=yes)")
    ap.add_argument("--categories", nargs="*")
    args = ap.parse_args()

    cats = args.categories or categories()

    # Reconstruct full C capture sets in one snapshot pass (only for seeded cats).
    three_sets = {}
    if args.three:
        seeds_by_cat = {}
        for cat in cats:
            seeds, _src, _st = ce.build_seeds(cat, part_filter=True)
            if seeds:
                seeds_by_cat[cat] = seeds
        if seeds_by_cat:
            print(f"[scanning snapshot for {len(seeds_by_cat)} seeded categories...]",
                  file=sys.stderr)
            hits = ce.scan_snapshot(seeds_by_cat)
            for cat, matched in hits.items():
                three_sets[cat] = {r["cve_id"] for r, _s in matched}

    rows = []
    pool = {"obs": 0.0, "N": 0.0, "var": 0.0}
    for cat in cats:
        V, K = vendor_ids(cat), keyword_ids(cat)
        if not V or not K:
            continue
        n1, n2, m2 = len(V), len(K), len(V & K)
        rates = yes_rates(cat) if args.population == "yes" else {}

        if args.population == "yes":
            # scale each observed cell by its Yes-rate; skip if no labels at all.
            if not rates:
                continue
            def rate(direction):
                yy, nn = rates.get(direction, [0, 0])
                return (yy / nn) if nn else None
            rv, rk = rate("vendor_only"), rate("keyword_only")
            if rv is None and rk is None:
                continue
            assumed = rv is None or rk is None  # one side unlabeled -> proxy the other
            if rv is None:
                rv = rk
            if rk is None:
                rk = rv
            n1 = round((n1 - m2) * rv + m2 * args.isect_precision)  # true V
            n2 = round((n2 - m2) * rk + m2 * args.isect_precision)  # true K
            m2 = round(m2 * args.isect_precision)                    # true V n K

        N, lo, hi, se = chapman(n1, n2, m2)
        obs = n1 + n2 - m2
        recall = obs / N if N > 0 else float("nan")
        r_hi = obs / lo if lo > 0 else float("nan")   # small N -> high recall
        r_lo = obs / hi if hi > 0 else float("nan")
        conf = "low" if (m2 < 3 or obs < 8) else "ok"
        if m2 and m2 == min(n1, n2):
            conf = "degenerate"   # one list subset of other: N_hat collapses, recall uninformative
        if args.population == "yes" and assumed:
            conf = "assumed-rate"

        row = dict(category=cat, population=args.population, method="2src-chapman",
                   n_vendor=n1, n_keyword=n2, n_both=m2, n_observed=obs,
                   N_hat=round(N, 1), N_lo=round(lo, 1), N_hi=round(hi, 1),
                   recall=round(recall, 3), recall_lo=round(r_lo, 3),
                   recall_hi=round(r_hi, 3), confidence=conf)
        rows.append(row)
        if conf != "degenerate":                 # pool only informative categories
            pool["obs"] += obs
            pool["N"] += N
            pool["var"] += se ** 2

        if args.three and cat in three_sets and args.population == "raw":
            C = three_sets[cat]
            if C:
                cells = {}
                allids = V | K | C
                for cid in allids:
                    p = (int(cid in V), int(cid in K), int(cid in C))
                    cells[p] = cells.get(p, 0) + 1
                r3 = loglinear3(cells)
                N3, obs3, lo3, hi3 = r3["N"], r3["obs"], r3["lo"], r3["hi"]
                rec3 = obs3 / N3 if N3 > 0 else float("nan")
                rl3 = obs3 / hi3 if hi3 and hi3 > 0 else float("nan")
                rh3 = obs3 / lo3 if lo3 and lo3 > 0 else float("nan")
                rows.append(dict(category=cat, population="raw",
                                 method=f"3src-loglin[{r3['name']}]",
                                 n_vendor=len(V), n_keyword=len(K), n_both=f"C={len(C)}",
                                 n_observed=obs3, N_hat=round(N3, 1),
                                 N_lo=round(lo3, 1) if math.isfinite(lo3) else "",
                                 N_hi=round(hi3, 1) if math.isfinite(hi3) else "",
                                 recall=round(rec3, 3),
                                 recall_lo=round(rl3, 3) if math.isfinite(rl3) else "",
                                 recall_hi=round(rh3, 3) if math.isfinite(rh3) else "",
                                 confidence="ok" if obs3 >= 15 else "low"))

    # ---- pooled total across informative categories (Var adds; N-hats independent)
    if pool["N"] > pool["obs"]:
        obsP, NP = pool["obs"], pool["N"]
        f0, seP = NP - obsP, math.sqrt(pool["var"])
        if f0 > 0 and seP > 0:
            Cf = math.exp(1.96 * math.sqrt(math.log(1 + (seP / f0) ** 2)))
            loP, hiP = obsP + f0 / Cf, obsP + f0 * Cf
        else:
            loP = hiP = NP
        rows.append(dict(category="POOLED", population=args.population,
                         method="2src-chapman(sum)", n_vendor="", n_keyword="",
                         n_both="", n_observed=int(obsP), N_hat=round(NP, 1),
                         N_lo=round(loP, 1), N_hi=round(hiP, 1),
                         recall=round(obsP / NP, 3), recall_lo=round(obsP / hiP, 3),
                         recall_hi=round(obsP / loP, 3), confidence="pooled"))

    # ---- print
    hdr = ["category", "method", "n_vendor", "n_keyword", "n_both", "n_observed",
           "N_hat", "N_lo", "N_hi", "recall", "recall_lo", "recall_hi", "confidence"]
    w = {h: max(len(h), *(len(str(r.get(h, ""))) for r in rows)) if rows else len(h)
         for h in hdr}
    line = "  ".join(h.ljust(w[h]) for h in hdr)
    print(f"\npopulation = {args.population}   (recall band = CI on N inverted)\n")
    print(line)
    print("-" * len(line))
    for r in rows:
        print("  ".join(str(r.get(h, "")).ljust(w[h]) for h in hdr))

    out = os.path.join(DATA, "difference", "recall_estimate.csv")
    with open(out, "w", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=hdr)
        wr.writeheader()
        for r in rows:
            wr.writerow({h: r.get(h, "") for h in hdr})
    print(f"\n-> {os.path.relpath(out, ROOT)}")
    if args.population == "yes":
        print(f"   (intersection precision assumed {args.isect_precision:.2f} — "
              "the V n K cell is unreviewed; re-run with --isect-precision to test "
              "sensitivity)")
    print("   two-source N-hat is biased DOWN by V-K positive dependence -> recall is an "
          "UPPER bound; prefer 3src where present.")


if __name__ == "__main__":
    main()
