#!/usr/bin/env python3
"""Build the human category-tagging sheet — F5 of PLAN_facet_system_fixes.md.

Emits data/facets/tagging-kit/category_tags.csv: 24 categories x every facet in the
vocabulary, for two human reviewers to VERIFY AGAINST SOURCES. That is a different exercise
from the one make_facet_copies.py serves, which is why this is a separate script and a
separate directory rather than a flag on that one.

SINGLE- AND MULTI-VALUED FACETS IN ONE SHEET.
    The 6 multi-valued facets (adminModel, alsoDeployedIn, credentialModel, pairingModel,
    patchResponsibility, topology) were originally left out because the answer SHAPE
    differs: a cell holds a set, so verdicts are `|`-separated and two reviewers agree by
    set equality rather than string equality. Leaving them out meant a third of the facet
    vocabulary could never leave hiot:Estimated, and blocked both planned collinearity
    cross-tabs (firmwareUpdateModel x patchResponsibility, hasWebAdminUI x adminModel) since
    each pairs a sheet facet with a left-out one. They are asked here, marked by the
    `cardinality` column, so the vocabulary is settled in one pass.

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

from rdflib import RDFS, Graph, Namespace

from facet_sample import facet_is_optional, load_facet_spec, load_multi_facet_spec

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

CONTEXT_COLS = ["priority", "status", "slug", "label", "facet", "cardinality",
                "allowed_values", "prefill_value", "prefill_source", "phase_a_verdict",
                "modal_share", "facet_kappa", "kappa_band", "category_cves", "scope_note"]
# Category-Wide is its own column rather than a magic word in Notes. It is the only input
# that can promote a cell to Documented — the claim that a source covers the whole category
# rather than a few products — so it should be made deliberately and be greppable, not
# recovered by substring-matching free text.
ANSWER_COLS = ["Verdict 1", "Source 1", "Category-Wide 1", "Notes 1",
               "Verdict 2", "Source 2", "Category-Wide 2", "Notes 2"]

# Sourcing a facet the panel could already assign reliably buys little; sourcing one it
# could not is the only thing that rescues it. Band drives the schedule accordingly.
#
# The multi-valued facets sit at rank 1 — below the kappa-failed cells, above everything
# else. They were never in the blind panel, so they have no kappa and no Phase A verdict at
# all: their need is PRESUMED where the rank-0 cells' is DEMONSTRATED, which is why they do
# not displace them. But nothing except this pass will ever move them off Estimated, so they
# outrank the bands that already have a measured number. Rank 0 is left untouched so the
# documented sourcing probe (rows 1-20) is exactly the same 20 cells as before.
BAND_RANK = {"FAILS": 0, "stays-Estimated": 0, "grouping-only": 2, "CITABLE": 3}
MULTI_RANK = 1


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


def load_author_prior(spec, cardinality):
    """(slug, facet) -> the value(s) currently asserted in homeiot.ttl.

    Read rather than copied, for the same reason categories.csv is generated: a hand-kept
    second copy of the assignment would drift from the assignment.

    A multi-valued facet is joined with `|` and sorted, which is both the sheet's answer
    format and the repo's existing convention for a set in a CSV cell (matched_terms).
    Sorting makes the pre-fill order-independent, so it round-trips through the store
    unchanged when a reviewer confirms it.
    """
    g = Graph()
    g.parse(os.path.join(ONTO, "homeiot.ttl"), format="turtle")

    def local(term):
        text = str(term)
        return text.split("#")[1] if "#" in text else text

    prior = {}
    for cls in g.subjects(HIOT.slug, None):
        slug = str(g.value(cls, HIOT.slug))
        for facet in spec:
            if cardinality[facet] == "multi":
                vals = sorted(local(v) for v in g.objects(cls, HIOT[facet]))
                # An optional facet with nothing asserted is asserting `none`, not silence;
                # showing it blank would read as "not yet assigned" and hide the real prior.
                if vals or facet_is_optional(facet):
                    prior[(slug, facet)] = "|".join(vals) if vals else "none"
                continue
            val = g.value(cls, HIOT[facet])
            if val is not None:
                prior[(slug, facet)] = local(val)
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


def build_rows(spec, cardinality, cats, phase_a, kappa, prior, weight):
    rows = []
    for cat in cats:
        slug = cat["slug"]
        for facet, values in spec.items():
            multi = cardinality[facet] == "multi"
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
            allowed = list(values)
            if multi and facet_is_optional(facet):
                allowed.append("none")
            rows.append({
                "priority": 0,
                "status": status,
                "slug": slug,
                "label": cat["label"],
                "facet": facet,
                "cardinality": "multi" if multi else "single",
                "allowed_values": "|".join(allowed + ["unsure"]),
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

    def rank(r):
        if r["cardinality"] == "multi":
            return MULTI_RANK
        return BAND_RANK.get(r["kappa_band"], BAND_RANK["grouping-only"])

    rows.sort(key=lambda r: (r["status"] != "ask",
                             rank(r),
                             -int(r["category_cves"]),
                             r["slug"], r["facet"]))
    for i, r in enumerate(rows, 1):
        r["priority"] = i
    return rows


def multi_definitions_md(multi):
    """Definitions for the multi-valued facets, appended to the copied reference sheet.

    Same two rules the annotation kit's generator enforces, for the same reasons: the
    property is described by its hiot:annotatorGloss and NEVER by rdfs:comment (those
    comments state research hypotheses and, on several of these six, the expected answer —
    `patchResponsibility` says user-initiated patching is "in practice, frequently no
    patch", which is precisely the anchor a reviewer must not be handed), while each VALUE
    is described by its own rdfs:comment, which is definitional.
    """
    g = Graph()
    g.parse(os.path.join(ONTO, "homeiot.ttl"), format="turtle")

    missing = [f for f in multi if g.value(HIOT[f], HIOT.annotatorGloss) is None]
    if missing:
        sys.exit(
            "refusing to build: no hiot:annotatorGloss on " + ", ".join(sorted(missing)) +
            "\nThe kit must NOT fall back to rdfs:comment — those comments state research "
            "hypotheses and expected answers. Add a gloss in homeiot.ttl first."
        )

    out = ["---", "",
           "# Multi-valued facets",
           "",
           "**These are answered differently from everything above.** Give **every** value "
           "that is common for the category, `|`-separated (`AppOnlyAdmin|LocalWebAdmin`), "
           "not just the most typical one. `unsure` stands alone as a whole-cell answer and "
           "is never mixed with real values.",
           "",
           "Common for the category, not merely possible: a route found on a few outlier "
           "products does not belong in the set. A facet that ends up true of all 24 "
           "categories discriminates nothing, so a one-value answer is a normal outcome.",
           ""]
    for facet, values in multi.items():
        prop = HIOT[facet]
        label = g.value(prop, RDFS.label) or facet
        out.append(f"## `{facet}` — {label}")
        out.append("")
        out.append(str(g.value(prop, HIOT.annotatorGloss)))
        out.append("")
        if facet_is_optional(facet):
            out.append("Optional: `none` is a real answer here.")
            out.append("")
        for v in values:
            vlabel = g.value(HIOT[v], RDFS.label)
            vcomment = g.value(HIOT[v], RDFS.comment)
            out.append(f"- **`{v}`**" + (f" — *{vlabel}*" if vlabel else ""))
            if vcomment:
                out.append(f"  <br>{vcomment}")
        out.append("- **`unsure`** — you could not tell even after looking. A real answer; "
                   "use it rather than guessing a set.")
        out.append("")
    return "\n".join(out)


def kit_readme(rows, spec, cardinality):
    ask = [r for r in rows if r["status"] == "ask"]
    unevidenced = sum(1 for r in ask if r["prefill_source"] == "author-prior")
    excluded = len(rows) - len(ask)
    failed = sorted({r["facet"] for r in ask
                     if r["cardinality"] == "single"
                     and BAND_RANK.get(r["kappa_band"], 1) == 0})
    multi_facets = sorted(f for f, c in cardinality.items() if c == "multi")
    n_multi = sum(1 for r in ask if r["cardinality"] == "multi")
    n_single = len(ask) - n_multi
    first_multi = min((int(r["priority"]) for r in ask if r["cardinality"] == "multi"),
                      default=0)
    return f"""# Category Tagging Kit

**This is a verification pass, not a blind annotation.** You are shown the current best
answer for every cell and asked to confirm or correct it **against a source**. That is the
opposite of `data/facets/annotation-kit/`, which exists to keep annotators away from the
current value — do not carry habits between the two.

`category_tags.csv` holds **{len(rows)} cells** ({len(spec)} facets x 24 categories):
**{len(ask)} to answer**, {excluded} emitted as `excluded-validity` and not asked. This is
the WHOLE facet vocabulary in one pass — {n_single} single-valued cells and {n_multi}
multi-valued ones.

## Two kinds of row — check `cardinality` before you answer

| `cardinality` | what to put in `Verdict N` |
|---|---|
| `single` | **exactly one** value from `allowed_values` |
| `multi` | **every** value that applies, `|`-separated — e.g. `AppOnlyAdmin|LocalWebAdmin` |

The {len(multi_facets)} multi-valued facets ({", ".join(multi_facets)}) start at row
{first_multi}. They ask what is **common for the category**, not what is merely possible
somewhere: if a route appears on a handful of outlier products, leave it out. A one-value
answer is perfectly normal for a `multi` row — listing everything is the failure mode, since
a facet that ends up true of every category discriminates nothing.

`unsure` is a whole-cell answer: put it alone, never mixed in with real values. For
`alsoDeployedIn` (the one optional facet) `none` is a real answer, meaning the category is
sold to households only.

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
were. On a `multi` row agreement means the **same set** — order and spacing do not matter,
so `MeshJoin|QrPaired` and `qrpaired | meshjoin` settle as one answer, but an extra value in
one column is a disagreement and goes back to the queue.

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

**Every `multi` row has all three of those blank or `UNMEASURED`, and that is not an
oversight.** The multi-valued facets were never in the blind product panel, so they have no
kappa and no Phase A verdict — nobody has measured whether they can be assigned reliably or
whether one set is even true of a whole category. Your verdict is the first evidence they
will ever carry, and without it they stay `Estimated` permanently: usable for organising
analysis, never citable as a finding. Treat their `author-prior` pre-fill as especially weak
— it has not survived even the one check the single-valued priors have.

## The probe comes first

The first ~20 rows are the sourcing probe that gates the rest of the phase: they are the
`FAILS`-band facets ({", ".join(failed)}) on the highest-CVE categories. **Record how long a
cell takes and how often a source actually exists before continuing.** If sources turn out not
to exist for a facet, that facet gets dropped rather than tagged — better to know after twenty
minutes than after a full pass.

The probe is deliberately all `single` rows — the multi-valued facets start lower down at row
{first_multi}, so the phase gate is judged on the same 20 cells it was defined on. When you
reach the first `multi` row, take its per-cell timing separately: a set answer needs a source
per member, so it is the one part of this sheet whose cost the probe does not predict.

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

    single, multi = load_facet_spec(), load_multi_facet_spec()
    spec = {**single, **multi}
    cardinality = {**{f: "single" for f in single}, **{f: "multi" for f in multi}}
    cats = load_categories()
    phase_a = load_phase_a()
    kappa = load_kappa()
    if not kappa:
        print("  WARNING: no facet_agreement.csv — kappa columns will be blank.\n"
              "  Run: python3 scripts/facet_agreement.py --csv data/facets/facet_agreement.csv")
    prior = load_author_prior(spec, cardinality)
    weight = load_cve_weight()

    rows = build_rows(spec, cardinality, cats, phase_a, kappa, prior, weight)

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
    #
    # The multi-valued half is APPENDED here rather than added to the annotation kit: that
    # kit is frozen as the record of the kappa study, and its sheets contain only the 12
    # single-valued facets. Regenerating it to carry definitions for facets it never asked
    # about would edit the study's own reference document after the fact.
    src = os.path.join(FACETS, "annotation-kit", "VALUE_DEFINITIONS.md")
    if os.path.exists(src):
        with open(src, encoding="utf-8") as fh:
            defs = fh.read()
        with open(os.path.join(KIT, "VALUE_DEFINITIONS.md"), "w", encoding="utf-8") as fh:
            fh.write(defs.rstrip() + "\n\n" + multi_definitions_md(multi))
    else:
        print("  WARNING: no VALUE_DEFINITIONS.md in the annotation kit to copy.")

    with open(os.path.join(KIT, "README.md"), "w", encoding="utf-8") as fh:
        fh.write(kit_readme(rows, spec, cardinality))

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
