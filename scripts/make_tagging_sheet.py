#!/usr/bin/env python3
"""Build the human category-tagging sheet — F5 of PLAN_facet_system_fixes.md.

Emits data/facets/tagging-kit/category_tags.csv: 24 categories x 12 single-valued facets,
for two human reviewers to VERIFY AGAINST SOURCES. That is a different exercise from the
one make_facet_copies.py serves, which is why this is a separate script and a separate
directory rather than a flag on that one.

WHY NOT A MODE OF make_facet_copies.py — the blindness inverts.
    The annotation kit exists to keep an annotator away from the current value: its
    AGENTS.md says "Do not look up the ontology's current value for any facet", and the
    whole point of the blind-copy structure is that another answer is ABSENT from the file
    rather than withheld by policy. This sheet does the opposite on purpose — it pre-fills
    the current best answer so the reviewer spends their time finding evidence rather than
    re-deriving a guess. Shipping both instruction sets from one script into one directory
    would put "never look at the prior" next to a sheet made of priors. So: separate
    script, separate kit, and annotation-kit/ is left frozen as the record of the kappa
    study whose reproducibility depends on it not moving.

WHAT THE PRE-FILL IS, AND WHY EVERY ROW SAYS WHERE IT CAME FROM.
    Three different things can fill the suggestion, and they are not worth the same:

      phase-a-cve-weighted   the modal value measured over sampled devices, CVE-weighted.
                             10 categories, 120 cells, and the only evidenced pre-fill.
      author-prior           the hand-assigned value from homeiot.ttl. This is the thing
                             under test. 14 categories, 168 cells (61% of what is asked).
      (excluded)             Phase A marked the cell NOT-USABLE; it is emitted as context,
                             never asked.

    Anchoring a reviewer on an unevidenced prior is a real cost, so the sheet states the
    provenance on every row instead of presenting one undifferentiated "suggested value".
    A reviewer who sees author-prior knows the suggestion carries no weight at all.

WHAT A SOURCE CAN AND CANNOT FIX (the boundary that governs this whole phase).
    Sourcing rescues RELIABILITY failures — facets where annotators disagreed because the
    question cannot be answered from a product name (supportLifetime at kappa -0.311 is the
    extreme case). It cannot rescue VALIDITY failures. cameras/capturesAV is NOT-USABLE
    because the category holds cameras AND recorders and the slot holds one value; a human
    with perfect sources is still wrong on ~40% of the rows it lands on. Those cells stay
    excluded regardless of who tags them or what they cite.

ORDERING IS THE SCHEDULE. Rows are sorted kappa-failed facets first, then by the category's
confirmed-Yes CVE count. That makes the top of the sheet the cells where sourcing is the
only thing that can help, on the categories that carry the most CVEs — so a partial pass is
still worth having, and the first ~20 rows ARE the sourcing probe the phase gate asks for.

Usage:
    python3 scripts/make_tagging_sheet.py              # build the sheet
    python3 scripts/make_tagging_sheet.py --probe 20   # just the probe subset, to stdout
    python3 scripts/make_tagging_sheet.py --overwrite  # rebuild, discarding filled answers
"""

import argparse
import csv
import os
import sys
from collections import Counter

from rdflib import Graph, Namespace

from facet_sample import load_facet_spec

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
ONTO = os.path.join(ROOT, "ontology")
FACETS = os.path.join(DATA, "facets")
KIT = os.path.join(FACETS, "tagging-kit")

CATEGORIES = os.path.join(DATA, "categories.csv")
DISTRIBUTION = os.path.join(FACETS, "facet_distribution.csv")
AGREEMENT = os.path.join(FACETS, "facet_agreement.csv")
RESOLVED = os.path.join(DATA, "difference", "final_resolved.csv")
SHEET = os.path.join(KIT, "category_tags.csv")

HIOT = Namespace("https://w3id.org/homeiot/ontology#")

NOT_USABLE = "NOT-USABLE-report-distribution"

CONTEXT_COLS = ["priority", "status", "slug", "label", "facet", "allowed_values",
                "prefill_value", "prefill_source", "phase_a_verdict", "modal_share",
                "facet_kappa", "kappa_band", "category_cves", "scope_note"]
# Category-Wide is its own column rather than a magic word in Notes. It is the only input
# that can promote a cell to Documented — the claim that a source covers the whole category
# rather than a few products — so it should be made deliberately and be greppable, not
# recovered by substring-matching free text.
ANSWER_COLS = ["Verdict 1", "Source 1", "Category-Wide 1", "Notes 1",
               "Verdict 2", "Source 2", "Category-Wide 2", "Notes 2"]

# Sourcing a facet the panel could already assign reliably buys little; sourcing one it
# could not is the only thing that rescues it. Band drives the schedule accordingly.
BAND_RANK = {"FAILS": 0, "stays-Estimated": 0, "grouping-only": 1, "CITABLE": 2}


def load_categories():
    with open(CATEGORIES, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def load_phase_a():
    """(slug, facet) -> (verdict, cve-weighted modal value, modal share)."""
    out = {}
    if not os.path.exists(DISTRIBUTION):
        return out
    with open(DISTRIBUTION, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            out[(r["category"], r["facet"])] = (
                r["verdict"], r["modal_value_cve"], r["modal_share_cve"])
    return out


def load_kappa():
    """facet -> (kappa, band). The 3-rater panel; regenerate before building the sheet."""
    out = {}
    if not os.path.exists(AGREEMENT):
        return out
    with open(AGREEMENT, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            out[r["facet"]] = (r["fleiss_kappa"], r["band"])
    return out


def load_author_prior(spec):
    """(slug, facet) -> the value currently asserted in homeiot.ttl.

    Read rather than copied, for the same reason categories.csv is generated: a hand-kept
    second copy of the assignment would drift from the assignment.
    """
    g = Graph()
    g.parse(os.path.join(ONTO, "homeiot.ttl"), format="turtle")
    prior = {}
    for cls in g.subjects(HIOT.slug, None):
        slug = str(g.value(cls, HIOT.slug))
        for facet in spec:
            val = g.value(cls, HIOT[facet])
            if val is None:
                continue
            text = str(val)
            prior[(slug, facet)] = text if "#" not in text else text.split("#")[1]
    return prior


def load_cve_weight():
    """slug -> confirmed-Yes CVE count. The sheet's schedule, not evidence."""
    w = Counter()
    if not os.path.exists(RESOLVED):
        return w
    with open(RESOLVED, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if (r.get("Final Judgment") or "").strip() == "Yes":
                w[r["Category"]] += 1
    return w


def build_rows(spec, cats, phase_a, kappa, prior, weight):
    rows = []
    for cat in cats:
        slug = cat["slug"]
        for facet, values in spec.items():
            verdict, modal, share = phase_a.get((slug, facet), ("", "", ""))
            k, band = kappa.get(facet, ("", ""))
            if verdict == NOT_USABLE:
                # Emitted for context and explicitly not asked. A source cannot repair a
                # cell whose category holds two device types.
                status, prefill, src = "excluded-validity", modal, "phase-a-cve-weighted"
            elif modal:
                status, prefill, src = "ask", modal, "phase-a-cve-weighted"
            else:
                status, prefill, src = "ask", prior.get((slug, facet), ""), "author-prior"
            rows.append({
                "priority": 0,
                "status": status,
                "slug": slug,
                "label": cat["label"],
                "facet": facet,
                "allowed_values": "|".join(list(values) + ["unsure"]),
                "prefill_value": prefill,
                "prefill_source": src,
                "phase_a_verdict": verdict or "UNMEASURED",
                "modal_share": share,
                "facet_kappa": k,
                "kappa_band": band,
                "category_cves": weight.get(slug, 0),
                "scope_note": cat["scope_note"],
                **{c: "" for c in ANSWER_COLS},
            })

    rows.sort(key=lambda r: (r["status"] != "ask",
                             BAND_RANK.get(r["kappa_band"], 1),
                             -int(r["category_cves"]),
                             r["slug"], r["facet"]))
    for i, r in enumerate(rows, 1):
        r["priority"] = i
    return rows


def kit_readme(rows, spec):
    ask = [r for r in rows if r["status"] == "ask"]
    unevidenced = sum(1 for r in ask if r["prefill_source"] == "author-prior")
    excluded = len(rows) - len(ask)
    failed = sorted({r["facet"] for r in ask if BAND_RANK.get(r["kappa_band"], 1) == 0})
    return f"""# Category Tagging Kit

**This is a verification pass, not a blind annotation.** You are shown the current best
answer for every cell and asked to confirm or correct it **against a source**. That is the
opposite of `data/facets/annotation-kit/`, which exists to keep annotators away from the
current value — do not carry habits between the two.

`category_tags.csv` holds **{len(rows)} cells** ({len(spec)} facets x 24 categories):
**{len(ask)} to answer**, {excluded} emitted as `excluded-validity` and not asked.

## What to do

Work **top to bottom** — the sheet is sorted so the most valuable cells come first. For each
row:

1. Read `facet` and look it up in `VALUE_DEFINITIONS.md`. The definitions are narrow; several
   are easy to answer from the everyday sense of the word instead of the defined one.
2. Look for a **source**: vendor documentation and spec sheets, support/security pages,
   declared support periods (UK PSTI / EU CRA), certification requirements (Matter and
   similar), or scan banners for `hasWebAdminUI`. Sources are usually per-product — cite two
   or three representative products for the category rather than hunting for one page that
   covers the whole class.
3. Fill `Verdict N` with a value from `allowed_values`, `Source N` with the URL(s) or a short
   citation, `Notes N` with anything the next reader needs.
4. Put `yes` in `Category-Wide N` **only** if your source covers the entire category — a
   regulation, a certification requirement, a standard. Citing three representative products
   is not category-wide; leave it blank. This column is the only thing that promotes a cell
   to `Documented`, so it is deliberately a separate answer rather than a note.
5. **Leave `Source N` blank if you looked and found nothing.** That is a real answer and it is
   recorded as `HumanJudged`. Do not cite a page that does not actually say what the facet
   claims — an unsourced honest verdict is worth more than a decorative citation.

Two reviewers fill columns 1 and 2 independently. Agreement on a non-`unsure` verdict settles
the cell; disagreement is discussed and reconciled, exactly as the CVE scope disagreements
were.

## How your answer is tiered

Set automatically by `facet_store.py` from what you fill in:

| tier | when |
|---|---|
| `Documented` | `Source N` filled **and** `Category-Wide N` = `yes` |
| `HumanSourced` | `Source N` filled — **most cells should land here** |
| `HumanJudged` | `Source N` blank: you answered from knowledge, no source found |

`HumanJudged` overrides any AI-assigned value but carries no evidence — for citation it is
treated exactly as `Estimated`. The share of cells that end up there is itself a result.

## Reading the context columns

- `prefill_value` / `prefill_source` — the suggestion and **where it came from**. Weigh them
  differently: `phase-a-cve-weighted` was measured over sampled devices; `author-prior` is the
  original hand assignment, which is the thing this pass exists to test.
  **{unevidenced} of {len(ask)} asked cells ({unevidenced / len(ask):.0%}) carry an
  author-prior pre-fill** — treat those as a blank sheet with a hint.
- `phase_a_verdict` / `modal_share` — how well one value described the sampled devices.
  `UNMEASURED` means that category was never sampled, not that it passed.
- `facet_kappa` / `kappa_band` — how reliably three independent annotators could assign this
  facet at all. A `FAILS` band means they could not, which is exactly why a source matters
  more here than anywhere else on the sheet.
- `category_cves` — confirmed-Yes CVEs in the category. Drives the ordering; not evidence.

## The probe comes first

The first ~20 rows are the sourcing probe that gates the rest of the phase: they are the
`FAILS`-band facets ({", ".join(failed)}) on the highest-CVE categories. **Record how long a
cell takes and how often a source actually exists before continuing.** If sources turn out not
to exist for a facet, that facet gets dropped rather than tagged — better to know after twenty
minutes than after a full pass.

## Excluded cells

Rows marked `excluded-validity` are cells Phase A measured as NOT-USABLE: the category holds
more than one kind of device, so no single value is true of it. A source cannot fix that — a
perfectly sourced value is still wrong for a large share of the rows it lands on. They are
shown for context and stay excluded from writeback.
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--probe", type=int, metavar="N",
                    help="print the first N cells and exit; writes nothing")
    ap.add_argument("--overwrite", action="store_true",
                    help="rebuild an existing sheet, DISCARDING any answers in it")
    args = ap.parse_args()

    spec = load_facet_spec()
    cats = load_categories()
    phase_a = load_phase_a()
    kappa = load_kappa()
    if not kappa:
        print("  WARNING: no facet_agreement.csv — kappa columns will be blank.\n"
              "  Run: python3 scripts/facet_agreement.py --csv data/facets/facet_agreement.csv")
    prior = load_author_prior(spec)
    weight = load_cve_weight()

    rows = build_rows(spec, cats, phase_a, kappa, prior, weight)

    if args.probe:
        print(f"sourcing probe — first {args.probe} cells:\n")
        print(f"  {'#':>3}  {'facet':22}{'category':16}{'kappa':>7}{'CVEs':>6}  prefill")
        for r in rows[:args.probe]:
            print(f"  {r['priority']:3d}  {r['facet']:22}{r['slug']:16}"
                  f"{r['facet_kappa']:>7}{r['category_cves']:>6}  "
                  f"{r['prefill_value']} ({r['prefill_source']})")
        return 0

    if os.path.exists(SHEET) and not args.overwrite:
        sys.exit(f"{SHEET} exists — refusing to overwrite answers. Use --overwrite to rebuild.")

    os.makedirs(KIT, exist_ok=True)
    with open(SHEET, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CONTEXT_COLS + ANSWER_COLS)
        w.writeheader()
        w.writerows(rows)

    # The value definitions the reviewer works from are the SAME generated sheet the blind
    # annotators used, so the two passes cannot drift into answering different questions.
    src = os.path.join(FACETS, "annotation-kit", "VALUE_DEFINITIONS.md")
    if os.path.exists(src):
        with open(src, encoding="utf-8") as fh:
            defs = fh.read()
        with open(os.path.join(KIT, "VALUE_DEFINITIONS.md"), "w", encoding="utf-8") as fh:
            fh.write(defs)
    else:
        print("  WARNING: no VALUE_DEFINITIONS.md in the annotation kit to copy.")

    with open(os.path.join(KIT, "README.md"), "w", encoding="utf-8") as fh:
        fh.write(kit_readme(rows, spec))

    ask = [r for r in rows if r["status"] == "ask"]
    unevidenced = sum(1 for r in ask if r["prefill_source"] == "author-prior")
    print(f"kit: {os.path.relpath(KIT, ROOT)}")
    print(f"  category_tags.csv  {len(rows)} cells "
          f"({len(ask)} to answer, {len(rows) - len(ask)} excluded-validity)")
    print(f"  pre-fill provenance: {len(ask) - unevidenced} measured, "
          f"{unevidenced} author-prior ({unevidenced / len(ask):.0%} unevidenced)")
    print("\nStart with the probe — it gates the rest of the phase:")
    print("  python3 scripts/make_tagging_sheet.py --probe 20")
    return 0


if __name__ == "__main__":
    sys.exit(main())
