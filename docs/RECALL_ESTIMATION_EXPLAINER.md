# Estimating Recall Without Knowing the Population
### Capture–Recapture (Stage 6) — methods explainer, one slide per section

> Each `##` heading below = one slide. Numbers are from the current
> `data/difference/recall_estimate.csv`; method lives in `scripts/recall_estimate.py`.

---

## 1. The objection

**"Recall = TP / (TP + FN). You can't know recall without knowing the total."**

- Correct — recall cannot be **measured** here. Nobody knows the true number
  of home-IoT CVEs in NVD; if we did, we wouldn't need the searches.
- But the same argument says ecologists can't count fish, the Census Bureau
  can't state its undercount, and epidemiologists can't report surveillance
  completeness.
- All of them report exactly such numbers — by **estimating N from the overlap
  between independent capture attempts**.
- That's **capture–recapture** (dual-/multiple-systems estimation). It is a
  century old. N is the *estimand*, not an input.

---

## 2. The idea in one picture

Two independent searches over the **same** population:

```
            population  (size N — unknown)
        ┌───────────────────────────────┐
        │      ┌─────────┐              │
        │      │ Vendor  │  n₁ found    │
        │      │    ┌────┼────┐         │
        │      │    │ m₂ │    │         │
        │      └────┼────┘    │         │
        │           │ Keyword │  n₂     │
        │           └─────────┘         │
        └───────────────────────────────┘
```

**Key insight:** the fraction of search 2's catch that search 1 had *already
found* estimates search 1's capture probability.

- Keyword finds n₂ CVEs; m₂ of them were already in the vendor list
- ⇒ vendor catches ≈ m₂/n₂ of everything ⇒ **N ≈ n₁ · n₂ / m₂**

The overlap is **data about the unseen**.

---

## 3. The estimator

**Lincoln–Petersen** (Petersen 1896, Lincoln 1930):

$$\hat{N} = \frac{n_1 \, n_2}{m_2}$$

**Chapman (1951)** — bias-corrected, stable at small overlap (what we use):

$$\hat{N} = \frac{(n_1+1)(n_2+1)}{m_2+1} - 1$$

**Combined recall** of the two searches:

$$\widehat{\text{recall}} = \frac{|V \cup K|}{\hat{N}}$$

- 95% CI: Chao's log-normal interval on the unseen count
  f₀ = N̂ − |V∪K| — lower bound can never fall below what we already observed.

---

## 4. Sanity check — read it off our own data

| category | vendor n₁ | keyword n₂ | overlap m₂ | N̂ | recall |
|----------|-----------|------------|------------|------|--------|
| doorbell | 60 | 22 | **21** | 62.8 | **97%** |
| hub | 110 | 79 | **16** | 521.4 | **33%** |

- **doorbell:** keyword search went looking independently and re-found 21 of
  its 22 hits — if a hidden mass of doorbell CVEs existed, it would have
  landed in it. It didn't ⇒ population barely exceeds what we have.
- **hub:** each search mostly finds CVEs the other missed ⇒ both are sampling
  a much larger pool than either one sees.
- Two lists that keep re-finding each other ⇒ small N.
  Two lists that barely intersect ⇒ large N. Checkable by eye.

---

## 5. Assumptions — and this setting satisfies the classical ones *better* than ecology

| assumption | ecology / census | this pipeline |
|------------|------------------|---------------|
| Closed population | animals die, migrate, are born | **exact**: one frozen NVD snapshot, both searches run against it |
| Perfect matching | physical tags, record-linkage error | **exact**: CVE IDs are unique keys |
| Independent captures | field protocols, hard to verify | **violated — handled** (next slide) |
| Equal catchability | varies by animal | violated; biases the same direction (next slide) |

---

## 6. The expected objection: "but your sources aren't independent"

True — and **no real application of capture–recapture has independent
sources**. The method's entire applied history runs under acknowledged
dependence:

| application | the "independent" sources | dependence |
|-------------|---------------------------|------------|
| Census dual-system estimation | census + post-enumeration survey | both miss the same hard-to-reach people |
| Software inspections (Eick 1992) | human inspectors **reading the same document** | subtle defects hide from everyone |
| Casualty estimation (HRDAG) | police / NGO / morgue lists | wildly correlated coverage |
| Ecology (the origin!) | trap occasions | trap-happy / trap-shy animals |

The objection holds this pipeline to a standard **no field meets**.
The real questions: do you know the bias **direction**, and can you
**model** the dependence? Yes and yes → next three slides.

---

## 7. What is actually dependent here — and what isn't

- **Not a dependence:** shared engine + shared frozen snapshot + exact CVE-ID
  keys = the **closed-population** and **perfect-matching** assumptions
  satisfied *exactly* — a feature the classical applications wish they had.
- **Lexically disjoint by construction:** `keyword_terms.csv` bans brands;
  vendor terms *are* brands. No shared-vocabulary channel exists.
- **The real channel:** latent "documentation richness" — a verbose,
  CPE-tagged CVE is easier for *both* searches ⇒ **positive** dependence.
- Positive dependence **inflates the overlap m₂ ⇒ biases N̂ down ⇒ biases
  recall up**. Unequal catchability pushes the same direction.

Known mechanism, known direction ⇒ the two-source number is not broken,
it is a **bound**.

---

## 8. Two sources: a directional bound is still a strong claim

The two-source figure is reported as an **upper bound on recall** —
printed with every run of the script, caveat #1 in its docstring.

A known-direction bound is *asymmetrically* strong:

- **hub: recall ≤ ~33%.** Dependence can only make the truth **worse**.
  "Hub coverage is badly incomplete" is a conclusion the independence
  objection cannot touch — it is **reinforced** by it.
- **doorbell: ~97%** is the kind of number to hold loosely — which is why
  the pipeline doesn't stop at two sources.
- Estimates are used **comparatively** (rank categories → aim brand/keyword
  mining at the weak ones): a roughly common bias washes out of the ranking.

**Then we stop assuming and start estimating** → three-source model.

---

## 9. Three sources: we don't assume independence — we *estimate the dependence*

Add a third capture set **C** = every CVE NVD attributes to a confirmed-Yes
device CPE.

- Three sources ⇒ 7 of the 8 cells of the V×K×C inclusion table are observed;
  only "missed by all three" is unknown.
- Fit hierarchical **Poisson log-linear models** whose terms *include the
  pairwise dependences* — VK, VC, KC (Fienberg 1972; Bishop, Fienberg &
  Holland 1975, ch. 6); select by AIC; extrapolate the one unobserved cell.
- A model with a VK term does **not** assume V ⊥ K — it **measures how
  dependent they are** and corrects N̂ accordingly.
- Only remaining assumption: **no three-way interaction** — the standard
  identifying assumption of multiple-systems estimation, far weaker than
  pairwise independence.
- CI: bootstrap that **re-selects the model each replicate** — model-selection
  uncertainty is inside the interval, not under the rug.

---

## 10. And the data agrees: the dependence is detected, measured, corrected

- The AIC-selected model includes the **+AB term (V–K dependence) in 8 of 13
  three-source categories** — alarms, babymonitor, cameras, ev-charging,
  hub, lighting, smartspeakers, streaming.
  *The model found exactly the dependence the objection worries about,
  and put a coefficient on it.*
- **Cameras: 2-source 66% → 3-source 93%.** The 27-point gap **is** the
  measured size of the V–K dependence — the naive estimator's error,
  quantified rather than hand-waved.

Honest residual (concede before it's raised): **C is not a clean third
capture** — seeded from confirmed products, it can't reach a CVE whose
product never surfaced in V/K; VC/KC terms absorb its dependence only
partially. Hence C's N̂ is stated as *"population reachable through
confirmed products"* — in the script's own printed output.

---

## 11. Remaining honest caveats (we say them before reviewers do)

1. **Degenerate rows excluded** — when one list ⊆ the other, recapture
   carries no information; flagged and left out of the pooled total.
2. **Small overlap ⇒ wide CI, and the method says so** —
   airconditioner: recall 0.55, CI (0.22, 0.84), flagged `low`.
3. **`raw` (search-stage) recall is defensible today**; the `yes`-population
   (true-CVE) recall still needs labelled intersection cells before it's
   paper-grade.
4. (C's conditional reach — already conceded on slide 10.)

---

## 12. Current results (raw population)

| category | method | observed | N̂ | recall | 95% CI |
|----------|--------|----------|------|--------|--------|
| cameras | 3-src log-linear | 3131 | 3353 | **0.93** | (0.88, 0.96) |
| alarms | 3-src log-linear | 141 | 173 | **0.81** | (0.67, 1.0) |
| ev-charging | 3-src log-linear | 91 | 121 | **0.75** | (0.51, 1.0) |
| hub | 2-src Chapman | 173 | 521 | 0.33 ↑bound | (0.22, 0.46) |
| doorbell | 3-src log-linear | 61 | 61.5 | **0.99** | (0.94, 1.0) |
| **POOLED (2-src)** | Chapman sum | **4081** | **6349** | **0.64** | (0.61, 0.68) |

- Low-recall categories (hub, ev-charging, home-power…) are exactly where the
  brand-mining scripts target new vendor terms — the estimate **drives** the
  pipeline, it isn't decoration.

---

## 10. Pedigree — five literatures, same math

| field | use | key reference |
|-------|-----|---------------|
| Ecology | animal population size | Petersen 1896; Lincoln 1930; Chapman 1951 |
| Official statistics | census undercount (US post-enumeration survey) | Sekar & Deming 1949, *JASA* |
| Epidemiology | completeness of case ascertainment; casualty estimation (HRDAG) | Hook & Regal 1995, *Epidemiol. Reviews* |
| Software engineering | remaining defects from overlap of independent inspectors | Eick et al., ICSE 1992; Petersson et al. 2004, *JSS* |
| **Systematic reviews** | **recall of a literature search over an unknown relevant total** | **Spoor et al. 1996, *BMJ*** |

The last row is our problem isomorphically — substitute NVD for MEDLINE.

---

## 11. The one-line answer

> "Recall can't be *computed* without the population size — so we **estimate
> the population size, with a confidence interval**, from the overlap of two
> independent searches (Chapman/dual-system estimation), report it as an
> upper bound because the searches are positively dependent, and relax that
> assumption with a three-source log-linear model that estimates the
> dependence from data."

**The alternative to estimating recall is not knowing recall —
it's not reporting recall at all.**
Most corpus-based security studies report only precision and stay silent on
the denominator. An estimate with a CI and a stated bias direction is *more*
rigorous than the norm, not less.

---

## References

- Petersen, C.G.J. (1896). The yearly immigration of young plaice into the Limfjord from the German Sea.
- Lincoln, F.C. (1930). Calculating waterfowl abundance on the basis of banding returns. *USDA Circular* 118.
- Chapman, D.G. (1951). Some properties of the hypergeometric distribution with applications to zoological sample censuses. *Univ. Calif. Publ. Stat.*
- Sekar, C.C. & Deming, W.E. (1949). On a method of estimating birth and death rates and the extent of registration. *JASA* 44.
- Fienberg, S.E. (1972). The multiple recapture census for closed populations and incomplete 2^k contingency tables. *Biometrika* 59.
- Bishop, Y., Fienberg, S. & Holland, P. (1975). *Discrete Multivariate Analysis*, ch. 6. MIT Press.
- Chao, A. (1987). Estimating the population size for capture-recapture data with unequal catchability. *Biometrics* 43.
- Hook, E.B. & Regal, R.R. (1995). Capture-recapture methods in epidemiology. *Epidemiologic Reviews* 17.
- Eick, S.G. et al. (1992). Estimating software fault content before coding. *ICSE '92*.
- Petersson, H., Thelin, T., Runeson, P. & Wohlin, C. (2004). Capture-recapture in software inspections after 10 years research. *Journal of Systems and Software* 72.
- Spoor, P. et al. (1996). Use of the capture-recapture technique to evaluate the completeness of systematic literature searches. *BMJ* 313.

*(Verify page numbers before citing in the report.)*
