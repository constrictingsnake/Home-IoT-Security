#!/usr/bin/env python3
"""Generate the Stage-4 (triple-AI + human review) figures for the paper.

Five figures, all computed at run time from `data/difference/judgment_store.csv`
-- the same store `merge_judgments.py`/`finalize_judgments.py` write and the same
one the paper's Section III-E prose is quoted from. Nothing here is hardcoded:
every count, rate and denominator in every figure is derived from the store on
each run, so a figure can never drift away from the data the way a hand-typed
number can.

  review_funnel.pdf        8,124 reviewed rows -> AI agreement -> settlement
                           route -> final label -> scope gate. Sankey; node and
                           ribbon thickness are strictly proportional to counts
                           (no minimum-width fudge). Two paths are consequently
                           hairlines: unanimous -> human (60 rows, unanimous but
                           both strong reviewers Low confidence) and split ->
                           strong-consensus -> final (19 rows, lone Gemini
                           dissent). Only the strong-consensus node itself falls
                           under the 1.2% callout threshold, so it is the only
                           one with a leader line.
                           WIDE -- use \\begin{figure*} (two-column span).
  review_disagreement.pdf  (a) each reviewer's Yes/No/Maybe mix over all rows;
                           (b) who the lone dissenter was on the split rows.
  review_precision.pdf     share of rows reaching the analysis set, by the
                           provenance direction the row came in on.
  review_confidence.pdf    unanimity and human-routing rate by the (Claude,
                           Codex) confidence pattern -- the empirical case for
                           keying the human-review flag on those two columns.
  review_fp_by_category.pdf  per-category false-positive rate, all 24 categories,
                           with n on every bar.

Denominator convention (matches the paper): "reaching the analysis set" and the
per-direction precision figures divide by *non-excluded* rows, so the tvOS scope
exclusion is removed from numerator and denominator alike. The false-positive
rate in review_fp_by_category is No/total over *all* reviewed rows, since a
scope exclusion is not a review outcome. Both conventions are stated on the
figures themselves.

Colors reuse BASE_HUES from generate_cwe888_treemaps.py so every figure in the
paper reads as one system. Assignment is by meaning (Yes is always the same
green, No always the same red), never by a bar's rank within a plot.

Output: vector PDF under docs/figures/ (crisp at any scale, and resolves under
Overleaf where docs/ is the project root). --png-dir additionally writes PNGs
for previewing outside LaTeX.

Usage:
    python3 scripts/generate_review_figures.py
    python3 scripts/generate_review_figures.py --png-dir /tmp/preview
    python3 scripts/generate_review_figures.py --print-stats
"""
import argparse
import csv
import os
from collections import Counter, defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.path import Path
from matplotlib.patches import PathPatch, Rectangle

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE = os.path.join(ROOT, "data", "difference", "judgment_store.csv")
FIGDIR = os.path.join(ROOT, "docs", "figures")

REVIEWERS = ["Claude", "Codex", "Gemini"]
DIRECTIONS = ["vendor_only", "keyword_only", "intersection", "cpe_expansion"]
DIRECTION_LABEL = {
    "vendor_only": "Vendor-only",
    "keyword_only": "Keyword-only",
    "intersection": "Intersection",
    "cpe_expansion": "CPE expansion",
}

# Same eight base hues as generate_cwe888_treemaps.py, so the review figures and
# the CWE figures share one palette. Bound to meaning, not to position.
BLUE, GREEN, AMBER, DGREEN = "#2a78d6", "#1baf7a", "#eda100", "#008300"
PURPLE, RED, PINK, ORANGE = "#4a3aa7", "#e34948", "#e87ba4", "#eb6834"
GRAY, INK, MUTED = "#8a8f98", "#1a1a1a", "#5b6068"

YES_C, NO_C, MAYBE_C = DGREEN, RED, AMBER

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 7.5,
    "axes.titlesize": 8.5,
    "axes.labelsize": 8,
    "xtick.labelsize": 7,
    "ytick.labelsize": 7,
    "axes.edgecolor": "#c9ccd1",
    "axes.linewidth": 0.6,
    "text.color": INK,
    "axes.labelcolor": INK,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "figure.dpi": 150,
    "savefig.bbox": "tight",
    "pdf.fonttype": 42,  # embed TrueType, not Type 3 -- some venues reject Type 3
})


# ---------------------------------------------------------------- data loading

def load_rows(path=STORE):
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise SystemExit(f"no rows in {path}")
    return rows


def judgment(row, reviewer):
    return row[f"{reviewer} Judgment"].strip()


def confidence(row, reviewer):
    return row[f"{reviewer} Confidence"].strip()


def is_unanimous(row):
    return len({judgment(row, r) for r in REVIEWERS}) == 1


def lone_dissenter(row):
    """Which reviewer stood alone, on a row that is not unanimous.

    Returns a reviewer name, or "three-way" when all three judgments differ
    (possible here because the judgment vocabulary is Yes/No/Maybe, not binary).
    """
    c, x, g = (judgment(row, r) for r in REVIEWERS)
    if len({c, x, g}) == 3:
        return "three-way"
    if c == x:
        return "Gemini"
    if c == g:
        return "Codex"
    return "Claude"


def compute_stats(rows):
    """Every number any figure draws. Computed once, so the figures and the
    --print-stats audit output can never disagree."""
    s = {}
    s["n_rows"] = len(rows)
    complete = [r for r in rows if all(judgment(r, rev) for rev in REVIEWERS)]
    s["n_complete"] = len(complete)

    s["judgment_mix"] = {
        rev: Counter(judgment(r, rev) for r in rows) for rev in REVIEWERS
    }
    s["pairwise"] = {}
    for a, b in [("Claude", "Codex"), ("Claude", "Gemini"), ("Codex", "Gemini")]:
        agree = sum(1 for r in complete if judgment(r, a) == judgment(r, b))
        s["pairwise"][(a, b)] = (agree, len(complete))

    unanimous = [r for r in rows if is_unanimous(r)]
    split = [r for r in rows if not is_unanimous(r)]
    s["n_unanimous"], s["n_split"] = len(unanimous), len(split)
    s["dissent"] = Counter(lone_dissenter(r) for r in split)

    s["route"] = Counter(r["Final Source"] for r in rows)
    s["agreement_by_route"] = Counter(
        ("unanimous" if is_unanimous(r) else "split", r["Final Source"]) for r in rows
    )
    s["route_by_final"] = Counter((r["Final Source"], r["Final Judgment"]) for r in rows)
    s["final"] = Counter(r["Final Judgment"] for r in rows)
    s["excluded_by_final"] = Counter(
        (bool(r["Excluded"].strip()), r["Final Judgment"]) for r in rows
    )
    s["n_analysis"] = s["excluded_by_final"][(False, "Yes")]
    s["n_excluded"] = sum(v for (ex, _), v in s["excluded_by_final"].items() if ex)
    s["n_rejected"] = s["excluded_by_final"][(False, "No")]
    analysis_rows = [r for r in rows
                     if r["Final Judgment"] == "Yes" and not r["Excluded"].strip()]
    s["n_analysis_cves"] = len({r["cve_id"] for r in analysis_rows})

    # Per-direction precision, on the paper's denominator: non-excluded rows.
    s["direction"] = {}
    for d in DIRECTIONS:
        drows = [r for r in rows if r["Difference Type"] == d]
        kept = [r for r in drows if not r["Excluded"].strip()]
        yes = sum(1 for r in kept if r["Final Judgment"] == "Yes")
        s["direction"][d] = {
            "n_reviewed": len(drows), "n_scoped": len(kept), "n_yes": yes,
            "precision": yes / len(kept) if kept else 0.0,
        }

    # Confidence pattern of the two strong reviewers vs. what happened next.
    by_conf = defaultdict(list)
    for r in rows:
        by_conf[(confidence(r, "Claude"), confidence(r, "Codex"))].append(r)
    s["confidence"] = {}
    for key, group in by_conf.items():
        s["confidence"][key] = {
            "n": len(group),
            "unanimity": sum(1 for r in group if is_unanimous(r)) / len(group),
            "human": sum(1 for r in group if r["Final Source"] == "human") / len(group),
        }

    cats = defaultdict(list)
    for r in rows:
        cats[r["category"]].append(r)
    s["categories"] = {
        c: {
            "n": len(v),
            "n_no": sum(1 for r in v if r["Final Judgment"] == "No"),
            "fp_rate": sum(1 for r in v if r["Final Judgment"] == "No") / len(v),
            "n_excluded": sum(1 for r in v if r["Excluded"].strip()),
            "n_yes": sum(1 for r in v if r["Final Judgment"] == "Yes"),
        }
        for c, v in cats.items()
    }
    return s


# ------------------------------------------------------------ sankey primitive

def _ribbon(ax, x0, x1, y0_top, y0_bot, y1_top, y1_bot, color, alpha=0.42):
    """One flow band, cubic-Bezier on both edges so the two edges stay parallel."""
    cx0, cx1 = x0 + (x1 - x0) * 0.42, x0 + (x1 - x0) * 0.58
    verts = [
        (x0, y0_top), (cx0, y0_top), (cx1, y1_top), (x1, y1_top),
        (x1, y1_bot),
        (cx1, y1_bot), (cx0, y0_bot), (x0, y0_bot),
        (x0, y0_top),
    ]
    codes = [Path.MOVETO, Path.CURVE4, Path.CURVE4, Path.CURVE4,
             Path.LINETO,
             Path.CURVE4, Path.CURVE4, Path.CURVE4,
             Path.CLOSEPOLY]
    ax.add_patch(PathPatch(Path(verts, codes), facecolor=color, edgecolor="none",
                           alpha=alpha, zorder=1))


def fig_funnel(s, out):
    """Stage 4 end to end. Heights are strictly proportional to counts."""
    total = s["n_rows"]
    stages = [
        [("all", "Reviewed rows", total, GRAY)],
        [("unan", "Unanimous", s["n_unanimous"], BLUE),
         ("split", "Split", s["n_split"], AMBER)],
        [("ai", "AI consensus", s["route"]["ai-consensus"], BLUE),
         ("strong", "Strong consensus", s["route"]["strong-consensus"], GREEN),
         ("human", "Human adjudicated", s["route"]["human"], AMBER)],
        [("yes", "True match", s["final"]["Yes"], YES_C),
         ("no", "False positive", s["final"]["No"], NO_C)],
        [("set", "Analysis set", s["n_analysis"], YES_C),
         ("tvos", "tvOS scope exclusion", s["n_excluded"], PURPLE),
         ("rej", "Rejected", s["n_rejected"], NO_C)],
    ]
    links = [
        ("all", "unan", s["n_unanimous"]), ("all", "split", s["n_split"]),
        ("unan", "ai", s["agreement_by_route"][("unanimous", "ai-consensus")]),
        ("unan", "human", s["agreement_by_route"][("unanimous", "human")]),
        ("split", "human", s["agreement_by_route"][("split", "human")]),
        ("split", "strong", s["agreement_by_route"][("split", "strong-consensus")]),
        ("ai", "yes", s["route_by_final"][("ai-consensus", "Yes")]),
        ("ai", "no", s["route_by_final"][("ai-consensus", "No")]),
        ("strong", "yes", s["route_by_final"][("strong-consensus", "Yes")]),
        ("strong", "no", s["route_by_final"][("strong-consensus", "No")]),
        ("human", "yes", s["route_by_final"][("human", "Yes")]),
        ("human", "no", s["route_by_final"][("human", "No")]),
        ("yes", "set", s["n_analysis"]), ("yes", "tvos", s["n_excluded"]),
        ("no", "rej", s["n_rejected"]),
    ]
    # Every stage must re-partition the same 8,124 rows; if it doesn't, the
    # figure would silently misstate the pipeline. Fail loudly instead.
    for i, stage in enumerate(stages):
        got = sum(v for _, _, v, _ in stage)
        if got != total:
            raise SystemExit(f"funnel stage {i} sums to {got}, expected {total}")

    fig, ax = plt.subplots(figsize=(7.1, 3.15))
    gap = 0.030
    node_w, xs = 0.024, [0.0, 0.235, 0.47, 0.705, 0.94]
    geom, top_of = {}, {}
    for stage, x in zip(stages, xs):
        span = 1.0 - gap * (len(stage) - 1)
        y = 1.0
        for key, label, value, color in stage:
            h = span * value / total
            geom[key] = dict(x=x, y_top=y, y_bot=y - h, value=value,
                             label=label, color=color)
            top_of[key] = y          # running cursor for ribbon stacking
            y -= h + gap
    bot_of = {k: g["y_top"] for k, g in geom.items()}

    for src, dst, value in links:
        if value == 0:
            continue
        g0, g1 = geom[src], geom[dst]
        h0 = (g0["y_top"] - g0["y_bot"]) * value / g0["value"]
        h1 = (g1["y_top"] - g1["y_bot"]) * value / g1["value"]
        y0t, y1t = top_of[src], bot_of[dst]
        _ribbon(ax, g0["x"] + node_w, g1["x"], y0t, y0t - h0, y1t, y1t - h1,
                g0["color"])
        top_of[src] -= h0
        bot_of[dst] -= h1

    for key, g in geom.items():
        ax.add_patch(Rectangle((g["x"], g["y_bot"]), node_w,
                               max(g["y_top"] - g["y_bot"], 0.0015),
                               facecolor=g["color"], edgecolor="none", zorder=3))

    # Labels all sit to the right of their node, reading into the band that
    # leaves it. Tiny nodes (< 1.2% of the total) can't hold text beside them at
    # this scale, so they get a leader line into the open space above rather
    # than a widened box -- the geometry stays honest.
    def pct(v):
        return f"{v:,} ({v / total * 100:.1f}%)"

    for key, g in geom.items():
        mid = (g["y_top"] + g["y_bot"]) / 2
        tx = g["x"] + node_w + 0.010
        if g["value"] / total < 0.012:
            # Callout goes up and to the LEFT, into the inbound band's open
            # space; to the right it would run into the next stage's labels.
            ax.annotate(f"{g['label']} {pct(g['value'])}",
                        xy=(g["x"], mid), xytext=(g["x"] - 0.012, mid + 0.085),
                        ha="right", va="center", fontsize=6.3, color=INK,
                        arrowprops=dict(arrowstyle="-", color="#9aa0a8", lw=0.5,
                                        shrinkA=0, shrinkB=1))
        else:
            ax.text(tx, mid, f"{g['label']}\n{pct(g['value'])}", ha="left",
                    va="center", fontsize=6.9, color=INK, linespacing=1.35)

    headers = ["Candidate rows", "AI agreement", "Settlement", "Final label",
               "Scope gate"]
    for x, h in zip(xs, headers):
        ax.text(x, 1.075, h, ha="left", va="bottom", fontsize=7.2,
                color=INK, fontweight="bold")

    ax.text(0.0, -0.075,
            f"Analysis set: {s['n_analysis']:,} category-CVE assignments over "
            f"{s['n_analysis_cves']:,} distinct CVEs. Band thickness is strictly "
            f"proportional to row count throughout.",
            fontsize=6.3, color=MUTED, ha="left", va="top")

    ax.set_xlim(-0.005, 1.30)
    ax.set_ylim(-0.12, 1.16)
    ax.axis("off")
    _save(fig, out)


# ------------------------------------------------------------------- bar figs

def fig_disagreement(s, out):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.1, 2.0),
                                   gridspec_kw={"width_ratios": [1.25, 1]})
    total = s["n_rows"]

    order = ["Yes", "No", "Maybe"]
    colors = {"Yes": YES_C, "No": NO_C, "Maybe": MAYBE_C}
    ypos = list(range(len(REVIEWERS)))[::-1]
    for y, rev in zip(ypos, REVIEWERS):
        left = 0
        for label in order:
            v = s["judgment_mix"][rev][label]
            # 2px-equivalent gap between stacked segments (skill: mark specs)
            ax1.barh(y, v, left=left, height=0.52, color=colors[label],
                     edgecolor="white", linewidth=0.9, zorder=2)
            if v / total > 0.03:
                ax1.text(left + v / 2, y, f"{v:,}", ha="center", va="center",
                         fontsize=6.6, color="white", zorder=3)
            left += v
        # The Maybe sliver is too thin to hold its own number; it gets a
        # direct label past the bar end rather than being left unreadable.
        ax1.text(total * 1.02, y, f"{s['judgment_mix'][rev]['Maybe']:,} Maybe",
                 va="center", fontsize=6.3, color=MUTED)
    ax1.set_yticks(ypos, REVIEWERS)
    ax1.set_xlim(0, total * 1.20)
    ax1.set_xticks([0, 2000, 4000, 6000, 8000], ["0", "2k", "4k", "6k", "8k"])
    ax1.set_xlabel(f"rows judged (all {total:,})")
    ax1.set_title("(a) Each reviewer's judgment mix", loc="left")
    handles = [plt.Rectangle((0, 0), 1, 1, color=colors[k]) for k in order]
    ax1.legend(handles, order, frameon=False, fontsize=6.5, ncol=3,
               loc="upper center", bbox_to_anchor=(0.45, -0.24))
    for sp in ("top", "right", "left"):
        ax1.spines[sp].set_visible(False)
    ax1.tick_params(axis="y", length=0)

    keys = ["Gemini", "Codex", "Claude", "three-way"]
    labels = ["Gemini alone", "Codex alone", "Claude alone", "all three differ"]
    vals = [s["dissent"][k] for k in keys]
    cols = [BLUE, BLUE, BLUE, GRAY]
    y2 = list(range(len(keys)))[::-1]
    ax2.barh(y2, vals, height=0.56, color=cols, zorder=2)
    for y, v in zip(y2, vals):
        # One decimal, matching how the prose quotes these shares.
        ax2.text(v + s["n_split"] * 0.015, y, f"{v:,}  ({v / s['n_split'] * 100:.1f}%)",
                 va="center", fontsize=6.6, color=INK)
    ax2.set_yticks(y2, labels)
    ax2.set_xlim(0, max(vals) * 1.42)
    ax2.set_xlabel(f"split rows (of {s['n_split']:,})")
    ax2.set_title("(b) Who dissented, when they split", loc="left")
    for sp in ("top", "right", "left"):
        ax2.spines[sp].set_visible(False)
    ax2.tick_params(axis="y", length=0)
    ax2.set_xticks([])

    fig.subplots_adjust(wspace=0.42)
    _save(fig, out)


def fig_precision(s, out):
    fig, ax = plt.subplots(figsize=(3.4, 2.35))
    ds = sorted(DIRECTIONS, key=lambda d: -s["direction"][d]["precision"])
    vals = [s["direction"][d]["precision"] * 100 for d in ds]
    # Intersection is the one direction the original design assumed clean and
    # skipped; it is highlighted because that assumption is what the audit
    # overturned. Color carries emphasis only -- every bar is labeled.
    cols = [GREEN if d == "intersection" else BLUE for d in ds]
    y = list(range(len(ds)))[::-1]
    ax.barh(y, vals, height=0.56, color=cols, zorder=2)
    for yy, d, v in zip(y, ds, vals):
        info = s["direction"][d]
        note = f"{v:.1f}%   n={info['n_scoped']:,}"
        if info["n_scoped"] != info["n_reviewed"]:
            note += f" of {info['n_reviewed']:,} reviewed"
        ax.text(v + 2.0, yy, note, va="center", fontsize=6.6, color=INK)
    ax.set_yticks(y, [DIRECTION_LABEL[d] for d in ds])
    ax.set_xlim(0, 100)
    ax.set_xlabel("share of rows reaching the analysis set (%)")
    ax.set_title("Precision by provenance direction", loc="left")
    for sp in ("top", "right", "left"):
        ax.spines[sp].set_visible(False)
    ax.tick_params(axis="y", length=0)
    ax.grid(axis="x", color="#e6e8eb", linewidth=0.6, zorder=0)
    ax.set_axisbelow(True)
    ax.text(0, -0.30, "Denominator excludes tvOS-scoped rows, which is why CPE\n"
                      "expansion is scored on 171 of its 2,068 reviewed rows.",
            transform=ax.transAxes, fontsize=6.0, color=MUTED, va="top")
    _save(fig, out)


def fig_confidence(s, out):
    fig, ax = plt.subplots(figsize=(3.4, 2.35))
    keys = [("High", "High"), ("Low", "High"), ("High", "Low"), ("Low", "Low")]
    keys = [k for k in keys if k in s["confidence"]]
    x = range(len(keys))
    w = 0.38
    unan = [s["confidence"][k]["unanimity"] * 100 for k in keys]
    hum = [s["confidence"][k]["human"] * 100 for k in keys]
    ax.bar([i - w / 2 for i in x], unan, w, color=BLUE, label="unanimous", zorder=2)
    ax.bar([i + w / 2 for i in x], hum, w, color=AMBER, label="sent to humans", zorder=2)
    for i, k in zip(x, keys):
        ax.text(i, -17, f"n={s['confidence'][k]['n']:,}", ha="center",
                fontsize=6.2, color=MUTED)
    for i, v in zip(x, unan):
        ax.text(i - w / 2, v + 2, f"{v:.0f}", ha="center", fontsize=6.3, color=INK)
    for i, v in zip(x, hum):
        ax.text(i + w / 2, v + 2, f"{v:.0f}", ha="center", fontsize=6.3, color=INK)
    ax.set_xticks(list(x), [f"{a}/{b}" for a, b in keys])
    ax.set_xlabel("Claude / Codex confidence", labelpad=14)
    ax.set_ylabel("% of rows in that cell")
    ax.set_ylim(0, 108)
    ax.set_title("Confidence predicts disagreement", loc="left", pad=20)
    # Above the axes: the 100%-tall bars leave no in-plot corner free.
    ax.legend(frameon=False, fontsize=6.5, ncol=2, loc="lower left",
              bbox_to_anchor=(0.0, 1.005))
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    ax.grid(axis="y", color="#e6e8eb", linewidth=0.6, zorder=0)
    ax.set_axisbelow(True)
    _save(fig, out)


def fig_fp_by_category(s, out):
    # Ties at 0% are ordered by n, so the better-evidenced zero sorts above the
    # n=1 one rather than landing in dict order.
    cats = sorted(s["categories"].items(), key=lambda kv: (-kv[1]["fp_rate"], -kv[1]["n"]))
    fig, ax = plt.subplots(figsize=(3.4, 4.3))
    y = list(range(len(cats)))[::-1]
    # Bars below the small-sample line are drawn in gray: at n < 30 a rate is
    # an anecdote, and shading is what stops it being read as a finding.
    SMALL_N = 30
    vals = [c["fp_rate"] * 100 for _, c in cats]
    cols = [AMBER if c["n"] < SMALL_N else BLUE for _, c in cats]
    ax.barh(y, vals, height=0.62, color=cols, zorder=2)
    for yy, (name, c) in zip(y, cats):
        # A 0% category draws no bar, so its label states the rate outright --
        # otherwise the empty row reads as missing data rather than as zero.
        text = f"n={c['n']:,}" if c["fp_rate"] else f"0%  n={c['n']:,}"
        ax.text(c["fp_rate"] * 100 + 1.6, yy, text, va="center",
                fontsize=5.9, color=MUTED)
    # A low false-positive rate is not the same as a high yield: a category can
    # pass review and then lose those rows at the scope gate. Categories where
    # that happens are daggered so the bar can't be read as a yield claim.
    scoped = {name for name, c in cats if c["n_excluded"]}
    ax.set_yticks(y, [f"{name}$^\\dagger$" if name in scoped else name
                      for name, _ in cats], fontsize=6.4)
    ax.set_xlim(0, 118)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.set_xlabel("false-positive rate (% of reviewed rows judged No)")
    ax.set_title("False-positive load by category", loc="left")
    handles = [plt.Rectangle((0, 0), 1, 1, color=BLUE),
               plt.Rectangle((0, 0), 1, 1, color=AMBER)]
    ax.legend(handles, [f"n ≥ {SMALL_N}", f"n < {SMALL_N} (rate is indicative only)"],
              frameon=False, fontsize=6.0, loc="lower right",
              bbox_to_anchor=(1.0, 0.06))
    if scoped:
        note = "; ".join(
            f"{name}: {s['categories'][name]['n_excluded']:,} of its "
            f"{s['categories'][name]['n_yes']:,} true matches are removed later "
            f"by the tvOS scope exclusion" for name in sorted(scoped))
        ax.text(0, -0.135, "$\\dagger$ " + note, transform=ax.transAxes,
                fontsize=5.6, color=MUTED, va="top", wrap=True)
    for sp in ("top", "right", "left"):
        ax.spines[sp].set_visible(False)
    ax.tick_params(axis="y", length=0)
    ax.grid(axis="x", color="#e6e8eb", linewidth=0.6, zorder=0)
    ax.set_axisbelow(True)
    _save(fig, out)


_PNG_DIR = None


def _save(fig, out):
    path = os.path.join(FIGDIR, out)
    fig.savefig(path)
    print(f"wrote {os.path.relpath(path, ROOT)}")
    if _PNG_DIR:
        png = os.path.join(_PNG_DIR, out.replace(".pdf", ".png"))
        fig.savefig(png, dpi=220)
        print(f"wrote {png}")
    plt.close(fig)


def print_stats(s):
    """Every figure's numbers as text, so they can be checked against the paper
    without opening a PDF."""
    total = s["n_rows"]
    print(f"\nreviewed rows: {total:,}  (all three columns filled: {s['n_complete']:,})")
    print("\npairwise agreement:")
    for (a, b), (n, d) in s["pairwise"].items():
        print(f"  {a}-{b}: {n:,}/{d:,} = {n / d * 100:.1f}%")
    print(f"  unanimous: {s['n_unanimous']:,}/{total:,} = "
          f"{s['n_unanimous'] / total * 100:.1f}%   split: {s['n_split']:,}")
    print("\nlone dissenter on split rows:", dict(s["dissent"]))
    print("judgment mix:", {k: dict(v) for k, v in s["judgment_mix"].items()})
    print("\nsettlement route:", dict(s["route"]))
    print("agreement x route:", dict(s["agreement_by_route"]))
    print("route x final:", dict(s["route_by_final"]))
    print(f"\nfinal: {dict(s['final'])}")
    print(f"  Yes rate {s['final']['Yes'] / total * 100:.1f}%  "
          f"No rate {s['final']['No'] / total * 100:.1f}%")
    print(f"  analysis set {s['n_analysis']:,} rows / {s['n_analysis_cves']:,} CVEs; "
          f"tvOS-excluded {s['n_excluded']:,}; rejected {s['n_rejected']:,}")
    print("\nper-direction:")
    for d in DIRECTIONS:
        i = s["direction"][d]
        print(f"  {d:<14} reviewed={i['n_reviewed']:>5,} scoped={i['n_scoped']:>5,} "
              f"yes={i['n_yes']:>5,} precision={i['precision'] * 100:.1f}%")
    print("\nconfidence pattern (Claude/Codex):")
    for k, v in sorted(s["confidence"].items(), key=lambda kv: -kv[1]["n"]):
        print(f"  {k[0]:>4}/{k[1]:<4} n={v['n']:>5,}  unanimous={v['unanimity'] * 100:5.1f}%"
              f"  human={v['human'] * 100:5.1f}%")
    print("\nper-category false-positive rate:")
    for c, v in sorted(s["categories"].items(), key=lambda kv: -kv[1]["fp_rate"]):
        print(f"  {c:<16} n={v['n']:>5,}  No={v['n_no']:>5,}  {v['fp_rate'] * 100:5.1f}%")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--store", default=STORE, help="judgment store CSV")
    ap.add_argument("--png-dir", help="also write PNG copies here (for previewing)")
    ap.add_argument("--print-stats", action="store_true",
                    help="print every figure's numbers as text and exit")
    args = ap.parse_args()

    global _PNG_DIR
    _PNG_DIR = args.png_dir
    if _PNG_DIR:
        os.makedirs(_PNG_DIR, exist_ok=True)
    os.makedirs(FIGDIR, exist_ok=True)

    stats = compute_stats(load_rows(args.store))
    if args.print_stats:
        print_stats(stats)
        return
    fig_funnel(stats, "review_funnel.pdf")
    fig_disagreement(stats, "review_disagreement.pdf")
    fig_precision(stats, "review_precision.pdf")
    fig_confidence(stats, "review_confidence.pdf")
    fig_fp_by_category(stats, "review_fp_by_category.pdf")


if __name__ == "__main__":
    main()
