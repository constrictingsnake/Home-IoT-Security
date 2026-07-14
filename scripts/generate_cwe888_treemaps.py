#!/usr/bin/env python3
"""Generate treemap figures of the CWE-888 primary-class distribution, in the
style of Figs. 2-4 of the transportation IoT study (area-proportional boxes,
one per CWE-888 class, sized by that class's share of the category's CWEs).

Reads the same source as generate_cwe888_table.py (data/difference/
cwe888_distribution.csv) so the two stay consistent by construction. One
figure is produced for the "ALL" (overall) row plus the top-N categories by
total CWE count (default: streaming, cameras, hub, alarms — the only
categories with N > 75, a natural break from the next-largest at N=43).

Each CWE-888 class keeps the same fixed color across every figure (assigned
by class identity in CLASS_ORDER, never by size/rank within a given
treemap), and every box's identity is always available as text — in-box for
large slices, a side legend for slices too small to hold in-box text — so
identity never depends on color alone.

Output: one PDF per figure under docs/figures/, named
cwe888_treemap_<slug>.pdf (slug "all" for the overall figure). Vector PDF so
it stays crisp in the paper regardless of print/scaling; also works
unmodified with \\includegraphics in Overleaf, where docs/ is the project
root (see the comment above the inlined table in home_iot_security_report.tex
for why paths outside docs/ don't resolve there).

Usage:
    python3 scripts/generate_cwe888_treemaps.py
    python3 scripts/generate_cwe888_treemaps.py --categories streaming cameras hub alarms
"""
import argparse
import csv
import os
import textwrap
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import squarify

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Same canonical order as generate_cwe888_table.py, so class->color assignment
# is identical across the table and every treemap.
CLASS_ORDER = [
    "API", "Access Control", "Authentication", "Channel", "Cryptography",
    "Entry Points", "Exception Management", "Failure to Release Memory",
    "Faulty Resource Release", "Information Leak", "Malware", "Memory Access",
    "Memory Management", "Other", "Path Resolution", "Predictability",
    "Privilege", "Resource Management", "Risky Values", "Synchronization",
    "Tainted Input", "UI",
]

# One fixed, distinct color per CWE-888 class (22 classes need more slots
# than the dataviz skill's 8-hue categorical palette can give without
# repeating a hue). The first 8 are that palette's validated steps, kept for
# continuity with the CVE table's shading; the rest come from matplotlib's
# tab20/tab20b qualitative sets, chosen so no two classes land on the same
# color. Assignment is by class identity in CLASS_ORDER, never by a given
# treemap's box ranking, so a class is the same color in every figure. Every
# box also carries a direct text label (in-box or in the side legend), which
# is the mitigation for going beyond a CVD-validated palette size.
BASE_HUES = [
    "#2a78d6", "#1baf7a", "#eda100", "#008300",
    "#4a3aa7", "#e34948", "#e87ba4", "#eb6834",
]
EXTRA_HUES = [
    "#17becf", "#9467bd", "#8c564b", "#bcbd22", "#7f7f7f", "#393b79",
    "#637939", "#8c6d31", "#843c39", "#7b4173", "#3182bd", "#e6550d",
    "#31a354", "#756bb1",
]
PALETTE = BASE_HUES + EXTRA_HUES
assert len(PALETTE) >= len(CLASS_ORDER), "not enough distinct colors for all CWE-888 classes"
CLASS_COLOR = dict(zip(CLASS_ORDER, PALETTE))


def _text_color(hex_color):
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
    luminance = 0.299 * r + 0.587 * g + 0.114 * b
    return "#0b0b0b" if luminance > 150 else "#ffffff"

# Categories with N > 75 (streaming 1785, cameras 625, hub 102, alarms 77);
# the next-largest (pet, N=43) is a clear break below that.
DEFAULT_CATEGORIES = ["streaming", "cameras", "hub", "alarms"]

# Boxes whose area share is below this fraction are too small to hold a
# readable in-box label; they're called out in a side legend instead, sorted
# by size (mirrors the reference figure's intent of not leaving any slice
# unlabeled, without the leader-line clutter of one line per small slice).
SMALL_SLICE_THRESHOLD = 0.10


def load_counts(distribution_csv):
    counts = {}
    with open(distribution_csv, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            counts.setdefault(row["category"], Counter())[row["cwe888_class"]] = int(row["n_cwes"])
    return counts


def _fit_label(cls, pct, rect):
    # Wrap the class name to roughly fit the box's aspect ratio, and scale
    # font size down for small boxes so text never overflows its rectangle.
    # The 0.8 factor leaves a margin so adjacent labels don't visually touch
    # even when the char-count wrap estimate runs a little long (clip_path
    # is the hard backstop against actually bleeding into the next box).
    box_w_pt = rect["dx"] * 6.0 * 0.8   # ~6 points-per-unit at this figure's scale
    # Capped at 11: without this, a wide box lets a long two-word class name
    # ("Information Leak") sit on one line and clip mid-word at the box edge
    # instead of wrapping — the cap forces the wrap regardless of box width.
    chars_per_line = max(min(int(box_w_pt / 5.5), 11), 4)
    wrapped = textwrap.fill(cls, width=chars_per_line)
    n_lines = wrapped.count("\n") + 1
    fontsize = max(5.5, min(9.5, min(rect["dx"], rect["dy"]) * 0.8 / (n_lines + 1) * 1.1))
    return f"{wrapped}\n{pct:.0f}%", fontsize


def draw_treemap(counter, title, out_path):
    total = sum(counter.values())
    items = sorted(counter.items(), key=lambda kv: kv[1], reverse=True)
    items = [(cls, n) for cls, n in items if n > 0]
    sizes = [n for _, n in items]

    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    norm_sizes = squarify.normalize_sizes(sizes, 100, 100)
    rects = squarify.squarify(norm_sizes, 0, 0, 100, 100)

    small_items = []
    for (cls, n), rect in zip(items, rects):
        color = CLASS_COLOR[cls]
        box = patches.Rectangle(
            (rect["x"], rect["y"]), rect["dx"], rect["dy"],
            facecolor=color, edgecolor="white", linewidth=1.5)
        ax.add_patch(box)
        share = n / total
        if share >= SMALL_SLICE_THRESHOLD:
            cx, cy = rect["x"] + rect["dx"] / 2, rect["y"] + rect["dy"] / 2
            label, fontsize = _fit_label(cls, share * 100, rect)
            text = ax.text(cx, cy, label, ha="center", va="center",
                            fontsize=fontsize, color=_text_color(color),
                            weight="bold", linespacing=1.3)
            # Clip to the box: the char-count wrap estimate is approximate,
            # so on narrow boxes this stops overflow bleeding into neighbors
            # (the failure mode seen in the first draft) instead of trying
            # to make the estimate exact.
            text.set_clip_path(box)
        else:
            small_items.append((cls, n, share))

    # Small slices: no in-box text (would overflow), listed in a side legend
    # instead of leader lines, which get tangled once more than a couple of
    # slices are small (see the first draft of this figure).
    legend_x = 104
    if small_items:
        ax.text(legend_x, 98, "Other classes", fontsize=7.5, weight="bold",
                color="#52514e", va="top")
        for i, (cls, n, share) in enumerate(small_items):
            y = 92 - i * 7
            color = CLASS_COLOR[cls]
            ax.add_patch(patches.Rectangle((legend_x, y - 3.5), 4, 4, facecolor=color))
            ax.text(legend_x + 6, y - 1.5, f"{cls} ({share * 100:.0f}%)",
                    fontsize=6.5, color="#0b0b0b", va="center")

    ax.set_xlim(0, 135 if small_items else 100)
    ax.set_ylim(0, 100)
    ax.set_aspect("equal")
    ax.axis("off")
    ax.set_title(title, fontsize=10)
    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--distribution",
                     default=os.path.join(ROOT, "data/difference/cwe888_distribution.csv"))
    ap.add_argument("--out-dir", default=os.path.join(ROOT, "docs/figures"))
    ap.add_argument("--categories", nargs="*", default=DEFAULT_CATEGORIES,
                     help="Category slugs to render, in addition to the overall ALL figure.")
    args = ap.parse_args()

    counts = load_counts(args.distribution)
    os.makedirs(args.out_dir, exist_ok=True)

    targets = [("all", "ALL", "Overall")] + [(c, c, c) for c in args.categories]
    for slug, key, title in targets:
        if key not in counts:
            print(f"skip {key}: not found in {args.distribution}")
            continue
        out_path = os.path.join(args.out_dir, f"cwe888_treemap_{slug}.pdf")
        draw_treemap(counts[key], f"CWE-888 class distribution — {title}", out_path)
        print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
