#!/usr/bin/env python3
"""Durable store for human facet verdicts — F5 of PLAN_facet_system_fixes.md.

data/facets/facet_store.csv is to category tagging what judgment_store.csv is to CVE
review: the answers live here, keyed (slug, facet), and they survive sheet regeneration.
Same three-command shape and the same ORDER RULE — finalize before extract, or a
freshly-filled verdict is still outstanding when the queue is rebuilt and gets asked twice.

    python3 scripts/facet_store.py --finalize   # sheet answers -> store
    python3 scripts/facet_store.py --extract    # store -> outstanding-only queue
    python3 scripts/facet_store.py --status     # coverage + tier mix
    python3 scripts/facet_store.py --writeback  # report of TTL edits the store implies

WHY A NEW SCRIPT RATHER THAN REUSING finalize_judgments.py / extract_human_review.py.
    Those two work and are wired end to end into judgment_store.csv's columns and the CVE
    review directory layout. Generalising them over a second unit would put every CVE
    settlement at risk to serve a 432-cell sheet. The pattern is what is worth reusing
    here, not the code.

SINGLE- AND MULTI-VALUED CELLS SETTLE BY THE SAME RULE, APPLIED TO DIFFERENT THINGS.
    A multi-valued cell holds a SET written into one CSV field, so two reviewers can write
    the same answer in different order, case, or spacing. canonical() normalises both sides
    first, which makes "the two reviewers agree" set equality rather than string equality —
    the alternative is a settle rule that silently depends on typing. A superset in one
    column is a DISAGREEMENT, deliberately: it is a different claim about the category, not
    a more detailed version of the same one. `unsure` and `none` are whole-cell answers and
    never mix with values; a cell that mixes them is `outstanding-malformed`, and one whose
    agreed set violates an exclusivity rule is `outstanding-contradiction` — both named
    distinctly so the queue says what actually needs doing instead of "awaiting reviewer 2".

THE TIER IS DERIVED FROM WHAT THE REVIEWER DID, NOT SELF-REPORTED.
    A reviewer who cites evidence gets HumanSourced; one who looked and found nothing gets
    HumanJudged. Documented needs an explicit category-wide marker because it is the only
    tier claiming the source covers the class rather than a few products, and that claim
    should have to be made deliberately. This means the honest answer "I could not find a
    source" is recorded rather than papered over, and the share of cells landing in
    HumanJudged becomes a reportable result about the facet instead of an invisible gap.

    ONE THING THE REVIEWER'S OWN ACTIONS CANNOT REPORT is whether the products they cited
    come from the population the cell asserts something about. facet_source_coverage.py
    measures that, and a `below-floor` cell is demoted to HumanJudged with its source
    RETAINED — citing a brand the corpus does not contain is not evidence about the corpus,
    and "evidence exists but is unrepresentative" says more than a blank source would.
    Measured on the first pass, the median cell cited vendors holding 3% of its category's
    confirmed-Yes CVEs, so this is not a hypothetical failure mode.

WHY --writeback ONLY WRITES A REPORT.
    Facet values live in hand-authored homeiot.ttl, and this project never lets a script
    reserialize that file — ontology_build.py --write emits CSVs for exactly that reason
    (rdflib would reformat every line and bury the real change). So the writeback step
    emits a reviewed list of edits for a human to apply, in the same spirit as the
    discovery miners: the script proposes, a person commits.
"""

import argparse
import csv
import os
import sys
from collections import Counter, OrderedDict

from rdflib import Graph, Namespace

from facet_sample import load_facet_spec, load_multi_facet_spec

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
ONTO = os.path.join(ROOT, "ontology")
FACETS = os.path.join(DATA, "facets")

SHEET = os.path.join(FACETS, "tagging-kit", "category_tags.csv")
STORE = os.path.join(FACETS, "facet_store.csv")
QUEUE = os.path.join(FACETS, "facet_review_queue.csv")
REPORT = os.path.join(FACETS, "facet_writeback_report.md")

HIOT = Namespace("https://w3id.org/homeiot/ontology#")

COVERAGE = os.path.join(FACETS, "source_coverage.csv")

STORE_COLS = ["slug", "facet", "Final Value", "Final Source", "Evidence Tier", "Sources",
              "Category-Wide", "Source Coverage", "Status",
              "Verdict 1", "Source 1", "Category-Wide 1", "Notes 1",
              "Verdict 2", "Source 2", "Category-Wide 2", "Notes 2",
              "Phase A Verdict", "Facet Kappa"]

TRUE_ISH = {"yes", "y", "true", "1", "category-wide"}

# Weakest first. The floor rule takes the minimum over a property's cells, so a single
# unevidenced category cannot hide behind evidenced ones.
TIER_ORDER = ["Estimated", "HumanJudged", "HumanSourced", "Documented", "Derived"]

UNSETTLED = {"", "unsure", "maybe"}


def full_spec():
    """Every facet -> allowed values, and every facet -> cardinality."""
    single, multi = load_facet_spec(), load_multi_facet_spec()
    spec = {**single, **multi}
    cardinality = {**{f: "single" for f in single}, **{f: "multi" for f in multi}}
    return spec, cardinality


def canonical(verdict, facet, cardinality, spec):
    """Normalise one reviewer's answer to its comparable, storable form.

    A multi-valued verdict is a SET written into a CSV cell, so two reviewers can write the
    same answer in different order, spacing, or case. Canonicalising to a sorted, ontology-
    cased, `|`-joined string makes agreement a string comparison again — the alternative is
    a settle rule that silently depends on typing.

    Returns "" when the answer is unsettled (blank/unsure), so the caller's UNSETTLED check
    keeps working unchanged for both kinds of row.
    """
    text = (verdict or "").strip()
    if text.lower() in UNSETTLED:
        return ""
    if cardinality.get(facet) != "multi":
        return text
    # Ontology casing wins over the reviewer's, so `qrpaired` and `QrPaired` are one answer.
    casing = {v.lower(): v for v in spec.get(facet, [])}
    casing["none"] = "none"
    parts = {p.strip().lower() for p in text.split("|") if p.strip()}
    if not parts:
        return ""
    # `unsure` is a whole-cell answer; mixed into a set it is a malformed cell, not a value.
    if "unsure" in parts:
        return ""
    if "none" in parts and len(parts) > 1:
        return ""
    return "|".join(sorted(casing.get(p, p) for p in parts))


# Values that are meaningful only ALONE: a device either has an admin surface or it has
# none, so NoAdminInterface cannot sit in a set beside a real interface. The rule is stated
# in the value's own rdfs:comment and reaches the reviewer through VALUE_DEFINITIONS.md;
# this catches it if they answer past it. It does NOT replace the shapes.ttl constraint that
# plan item A8 still owes — a warning here guards the sheet, SHACL guards the ontology.
EXCLUSIVE_VALUES = {"adminModel": "NoAdminInterface"}


def contradictory(verdict, facet, cardinality):
    """True when a canonicalised set pairs an exclusive value with anything else."""
    if cardinality.get(facet) != "multi" or not verdict:
        return False
    lone = EXCLUSIVE_VALUES.get(facet)
    parts = verdict.split("|")
    return bool(lone) and lone in parts and len(parts) > 1


def invalid_values(verdict, facet, cardinality, spec):
    """Values in a canonicalised verdict that are not in the ontology's allowed set.

    Reported as a warning rather than enforced: this script has never rejected a human
    answer, and a typo should be visible to the person fixing it, not silently dropped on
    the floor by the settle rule.
    """
    if not verdict:
        return []
    allowed = set(spec.get(facet, [])) | {"none"}
    parts = verdict.split("|") if cardinality.get(facet) == "multi" else [verdict]
    return [p for p in parts if p not in allowed]


def malformed(verdict, facet, cardinality, spec):
    """A non-blank answer canonical() cannot make sense of (`unsure`/`none` inside a set).

    Distinguished from blank so the queue's Reason names what actually happened. Without
    this the cell reports `outstanding-one-verdict`, which reads as "waiting on the second
    reviewer" when the truth is that the first reviewer's answer needs rewriting.
    """
    text = (verdict or "").strip()
    if not text or text.lower() in UNSETTLED:
        return False
    return not canonical(text, facet, cardinality, spec)


def _read(path, key=None):
    if not os.path.exists(path):
        return OrderedDict() if key else []
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    if key:
        return OrderedDict(((r[key[0]], r[key[1]]), r) for r in rows)
    return rows


def _write(path, cols, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def load_coverage():
    """(slug, facet) -> coverage verdict from facet_source_coverage.py, or {} if never run."""
    if not os.path.exists(COVERAGE):
        return {}
    return {(r["slug"], r["facet"]): r["verdict"] for r in _read(COVERAGE)}


def derive_tier(sources, category_wide, coverage=""):
    """What the reviewer actually did decides the tier — see the module docstring.

    `coverage` adds the one thing the reviewer's own actions cannot report: whether the
    products they cited are drawn from the population the cell asserts something about.
    A citation of a brand the corpus does not contain is not evidence about the corpus, so
    a `below-floor` cell is demoted to HumanJudged even though a source is present — and
    the source stays recorded, because "evidence exists but is unrepresentative" is a more
    useful thing to know than a blank. `regulation` and `unmeasurable` never demote:
    a law does not need a market share, and a category with too few CVEs has no measurable
    share to fail.
    """
    if not sources.strip():
        return "HumanJudged"
    if coverage == "below-floor" and not category_wide:
        return "HumanJudged"
    return "Documented" if category_wide else "HumanSourced"


def is_category_wide(row):
    """Did a reviewer claim the source covers the whole category, not a few products?

    Read ONLY from the dedicated Category-Wide columns. There used to be a fallback that also
    returned True when the phrase "category-wide" appeared anywhere in either Notes field,
    so an answer written the old way (the marker as free text) would not be silently
    downgraded to HumanSourced.

    THAT FALLBACK IS REMOVED (2026-09-01) because a substring test cannot tell a claim from
    its denial, and it can only ever fail in the promoting direction. Measured on the sheet
    when it was pulled: three cells fired the fallback with the column unset, and all three
    were the OPPOSITE of a claim - `ev-charging/supportLifetime` says "Deliberately NOT marked
    category-wide" (EV chargepoints are an EXCEPTED product under PSTI Schedule 3, which is
    the whole point of that note), `thermostat/topology` says "rather than a required
    category-wide hub", and the third was a note recording a WITHDRAWN claim. Zero cells
    depended on the fallback for a genuine promotion. A reviewer who means the claim has a
    column to put it in, and reasoning about the claim in prose must stay free to do so.
    """
    return any((row.get(f"Category-Wide {n}") or "").strip().lower() in TRUE_ISH
               for n in ("1", "2"))


def settle(row, cardinality, spec, coverage=None):
    """Return (final_value, tier, sources, category_wide, status) for one sheet cell.

    A cell settles only on two independent, agreeing, non-`unsure` verdicts — the same bar
    the CVE queue uses, and for the same reason: a lone verdict is one reviewer, not a
    reconciliation.

    On a multi-valued row "agreeing" means the SAME SET: canonical() has already sorted and
    re-cased both sides, so equality here is set equality. An extra value in one column is a
    disagreement, deliberately — a superset is a different claim about the category, not a
    more detailed version of the same one.
    """
    facet = row.get("facet", "")
    v1 = canonical(row.get("Verdict 1"), facet, cardinality, spec)
    v2 = canonical(row.get("Verdict 2"), facet, cardinality, spec)
    s1 = (row.get("Source 1") or "").strip()
    s2 = (row.get("Source 2") or "").strip()

    if row.get("status") == "excluded-validity":
        return "", "", "", False, "", "excluded-validity"
    if any(malformed(row.get(f"Verdict {n}"), facet, cardinality, spec) for n in ("1", "2")):
        return "", "", "", False, "", "outstanding-malformed"
    if not v1 and not v2:
        return "", "", "", False, "", "outstanding-no-verdict"
    if not v1 or not v2:
        return "", "", "", False, "", "outstanding-one-verdict"
    if v1.lower() != v2.lower():
        return "", "", "", False, "", "outstanding-disagreement"
    # Two reviewers can agree on a set the ontology forbids. Agreement is not correctness,
    # so this goes back to them rather than into a settled value the SHACL shape (A8) would
    # later have to reject at the ontology boundary.
    if contradictory(v1, facet, cardinality):
        return "", "", "", False, "", "outstanding-contradiction"

    sources = " ; ".join(s for s in (s1, s2) if s)
    wide = is_category_wide(row)
    cov = (coverage or {}).get((row["slug"], row["facet"]), "")
    return v1, derive_tier(sources, wide, cov), sources, wide, cov, "settled"


def cmd_finalize():
    if not os.path.exists(SHEET):
        sys.exit(f"no sheet at {SHEET} — run: python3 scripts/make_tagging_sheet.py")
    sheet = _read(SHEET)
    store = _read(STORE, key=("slug", "facet"))
    spec, cardinality = full_spec()
    coverage = load_coverage()

    added = updated = kept = 0
    warnings = []
    for row in sheet:
        key = (row["slug"], row["facet"])
        value, tier, sources, wide, cov, status = settle(row, cardinality, spec, coverage)
        for n in ("1", "2"):
            raw = (row.get(f"Verdict {n}") or "").strip()
            canon = canonical(raw, row["facet"], cardinality, spec)
            if raw and raw.lower() not in UNSETTLED and not canon:
                warnings.append(f"  {row['slug']}/{row['facet']} Verdict {n}: "
                                f"{raw!r} — malformed (`unsure`/`none` mixed with values?)")
            for bad in invalid_values(canon, row["facet"], cardinality, spec):
                warnings.append(f"  {row['slug']}/{row['facet']} Verdict {n}: "
                                f"{bad!r} is not an allowed value")
            if contradictory(canon, row["facet"], cardinality):
                warnings.append(
                    f"  {row['slug']}/{row['facet']} Verdict {n}: {canon!r} — "
                    f"{EXCLUSIVE_VALUES[row['facet']]} is exclusive, it cannot be "
                    f"combined with another value")
        prior = store.get(key)

        # Human verdicts are STICKY: a settled cell stays settled unless a fresh, agreeing
        # pair supersedes it. Regenerating the sheet must never silently unsettle an answer.
        if prior and prior.get("Final Source") == "human" and status != "settled":
            kept += 1
            continue

        rec = {
            "slug": row["slug"], "facet": row["facet"],
            "Final Value": value,
            "Final Source": "human" if status == "settled" else "",
            "Evidence Tier": tier,
            "Sources": sources,
            "Category-Wide": "yes" if wide else "",
            "Source Coverage": cov,
            "Status": status,
            "Verdict 1": row.get("Verdict 1", ""), "Source 1": row.get("Source 1", ""),
            "Category-Wide 1": row.get("Category-Wide 1", ""),
            "Notes 1": row.get("Notes 1", ""),
            "Verdict 2": row.get("Verdict 2", ""), "Source 2": row.get("Source 2", ""),
            "Category-Wide 2": row.get("Category-Wide 2", ""),
            "Notes 2": row.get("Notes 2", ""),
            "Phase A Verdict": row.get("phase_a_verdict", ""),
            "Facet Kappa": row.get("facet_kappa", ""),
        }
        if prior is None:
            added += 1
        elif prior != rec:
            updated += 1
        store[key] = rec

    _write(STORE, STORE_COLS, list(store.values()))
    settled = sum(1 for r in store.values() if r["Status"] == "settled")
    print(f"{os.path.relpath(STORE, ROOT)}: {len(store)} cells "
          f"({added} added, {updated} updated, {kept} sticky-kept)")
    print(f"  settled: {settled}")
    if warnings:
        # Warn, never reject: an unusable answer stays outstanding on its own merits and the
        # person fixing the typo needs to see it named.
        print(f"\n  {len(warnings)} answer(s) need attention (cells stay outstanding):")
        for w in warnings:
            print(w)
    print("\nNow regenerate the queue — finalize before extract, always:")
    print("  python3 scripts/facet_store.py --extract")


def cmd_extract():
    store = _read(STORE, key=("slug", "facet"))
    if not store:
        sys.exit("empty store — run --finalize first")
    sheet = {(r["slug"], r["facet"]): r for r in _read(SHEET)}

    out = []
    for key, rec in store.items():
        if rec["Status"] in ("settled", "excluded-validity"):
            continue
        src = sheet.get(key, {})
        out.append({**{c: src.get(c, "") for c in
                       ("priority", "slug", "label", "facet", "cardinality",
                        "allowed_values", "prefill_value", "prefill_source",
                        "phase_a_verdict", "facet_kappa", "kappa_band", "category_cves",
                        "scope_note")},
                    "Reason": rec["Status"],
                    "Verdict 1": rec["Verdict 1"], "Source 1": rec["Source 1"],
                    "Category-Wide 1": rec.get("Category-Wide 1", ""),
                    "Notes 1": rec["Notes 1"],
                    "Verdict 2": rec["Verdict 2"], "Source 2": rec["Source 2"],
                    "Category-Wide 2": rec.get("Category-Wide 2", ""),
                    "Notes 2": rec["Notes 2"]})
    out.sort(key=lambda r: int(r["priority"] or 0))
    cols = list(out[0]) if out else ["slug", "facet", "Reason"]
    _write(QUEUE, cols, out)

    reasons = Counter(r["Reason"] for r in out)
    print(f"{os.path.relpath(QUEUE, ROOT)}: {len(out)} outstanding")
    for reason, n in reasons.most_common():
        print(f"  {reason:28} {n}")
    if not out:
        print("  nothing outstanding — every asked cell is settled")


def property_tiers(store, spec):
    """Floor rule: a property carries the tier of its weakest cell.

    Cells that never settled keep the hand-assigned value, so they count as Estimated —
    which is what stops a property being promoted on the strength of its evidenced cells
    while most of it remains a guess.
    """
    tiers = {}
    for facet in spec:
        cells = [r for r in store.values() if r["facet"] == facet
                 and r["Status"] != "excluded-validity"]
        if not cells:
            tiers[facet] = "Estimated"
            continue
        worst = min((TIER_ORDER.index(r["Evidence Tier"]) if r["Evidence Tier"] in TIER_ORDER
                     else 0) for r in cells)
        tiers[facet] = TIER_ORDER[worst]
    return tiers


def cmd_status():
    store = _read(STORE, key=("slug", "facet"))
    if not store:
        sys.exit("empty store — run --finalize first")
    spec, cardinality = full_spec()

    status = Counter(r["Status"] for r in store.values())
    tiers = Counter(r["Evidence Tier"] for r in store.values() if r["Evidence Tier"])
    print(f"cells: {len(store)}")
    for k, n in status.most_common():
        print(f"  {k:28} {n}")
    print("\nper-cell evidence tier (settled cells only):")
    for k in TIER_ORDER:
        if tiers.get(k):
            print(f"  {k:28} {tiers[k]}")
    if not tiers:
        print("  none yet")

    print("\nper-property tier by the FLOOR rule (weakest cell wins):")
    for facet, tier in sorted(property_tiers(store, spec).items()):
        kind = "[multi]" if cardinality.get(facet) == "multi" else ""
        print(f"  {facet:24} {tier:14} {kind}")


def cmd_writeback():
    """Emit the edit list a human applies to homeiot.ttl by hand."""
    store = _read(STORE, key=("slug", "facet"))
    if not store:
        sys.exit("empty store — run --finalize first")
    spec, cardinality = full_spec()

    g = Graph()
    g.parse(os.path.join(ONTO, "homeiot.ttl"), format="turtle")

    def local(term):
        text = str(term)
        return text.split("#")[1] if "#" in text else text

    current = {}
    for cls in g.subjects(HIOT.slug, None):
        slug = str(g.value(cls, HIOT.slug))
        for facet in spec:
            if cardinality[facet] == "multi":
                # Sorted and joined the same way the sheet's pre-fill and canonical() are,
                # so "unchanged" means the same set rather than the same serialisation.
                vals = sorted(local(v) for v in g.objects(cls, HIOT[facet]))
                current[(slug, facet)] = "|".join(vals) if vals else "none"
                continue
            val = g.value(cls, HIOT[facet])
            if val is not None:
                current[(slug, facet)] = local(val)

    changes, unchanged, excluded = [], 0, 0
    for (slug, facet), rec in store.items():
        if rec["Status"] == "excluded-validity":
            excluded += 1
            continue
        if rec["Final Source"] != "human":
            continue
        now = current.get((slug, facet), "")
        if rec["Final Value"] == now:
            unchanged += 1
        else:
            changes.append((slug, facet, now, rec["Final Value"], rec["Evidence Tier"],
                            rec["Sources"], cardinality[facet]))
    changes.sort()
    n_multi_changes = sum(1 for c in changes if c[6] == "multi")

    lines = [
        "# Facet writeback report",
        "",
        "**Generated by `scripts/facet_store.py --writeback`. Apply these edits to "
        "`ontology/homeiot.ttl` BY HAND.**",
        "",
        "No script rewrites that file — rdflib would reserialize every line and bury the "
        "real change, which is why `ontology_build.py --write` only ever emits CSVs. This "
        "report is the reviewed proposal; a person commits it.",
        "",
        f"- settled cells confirming the current value: **{unchanged}**",
        f"- settled cells CHANGING the current value: **{len(changes)}**",
        f"- cells excluded on validity (never written): **{excluded}**",
        "",
        "## Value changes",
        "",
    ]
    if changes:
        if n_multi_changes:
            lines += [
                f"**{n_multi_changes} of these are multi-valued** (`kind` = `multi`), where "
                "the value is a `|`-separated SET. Applying one means replacing the whole "
                "comma-separated object list on that line — `hiot:pairingModel hiot:A, "
                "hiot:B ;` — not appending to it. A `current` of `none` means the property "
                "is absent for that category and the line must be added; a `new` of `none` "
                "means the line is deleted. Both sides are sorted, so a row appears here "
                "only when the SET differs, never because the order does.",
                "",
            ]
        lines += ["| category | facet | kind | current | new | tier | source |",
                  "|---|---|---|---|---|---|---|"]
        for slug, facet, old, new, tier, src, kind in changes:
            lines.append(f"| `{slug}` | `{facet}` | {kind} | `{old}` | **`{new}`** | "
                         f"{tier} | {src or '—'} |")
    else:
        lines.append("None — every settled cell confirms the value already asserted.")

    lines += ["", "## Property-level `hiot:evidenceTier` (floor rule)", "",
              "A property carries the tier of its **weakest** cell, so one unevidenced "
              "category cannot hide behind evidenced ones. Unsettled cells keep the hand "
              "value and count as `Estimated`.", "",
              "| facet | current | proposed |", "|---|---|---|"]
    for facet, tier in sorted(property_tiers(store, spec).items()):
        cur = g.value(HIOT[facet], HIOT.evidenceTier)
        cur = str(cur).split("#")[1] if cur else "—"
        mark = "" if cur == tier else " **←change**"
        lines.append(f"| `{facet}` | {cur} | {tier}{mark} |")

    lines += ["", "## After applying", "",
              "```bash",
              "python3 scripts/ontology_build.py --check      # SHACL, IRIs, reasoner, CSVs",
              "python3 scripts/ontology_build.py --self-test  # every criterion still enforced",
              "python3 scripts/ontology_build.py --sources",
              "python3 scripts/ontology_build.py --verify-kg",
              "```",
              "",
              "`categories.csv` and `families.csv` must stay byte-identical — the "
              "descriptive facets touch neither. `hiot:hasRole` is never written: it sits "
              "inside the `hiot:InScopeDeviceType` equivalence axiom, so an edit there "
              "could move a published in/out ruling.", ""]

    with open(REPORT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print(f"{os.path.relpath(REPORT, ROOT)}: {len(changes)} value change(s), "
          f"{unchanged} confirmation(s), {excluded} excluded")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--finalize", action="store_true", help="sheet answers -> store")
    g.add_argument("--extract", action="store_true", help="store -> outstanding-only queue")
    g.add_argument("--status", action="store_true", help="coverage and tier mix")
    g.add_argument("--writeback", action="store_true", help="report the TTL edits implied")
    args = ap.parse_args()

    if args.finalize:
        cmd_finalize()
    elif args.extract:
        cmd_extract()
    elif args.status:
        cmd_status()
    else:
        cmd_writeback()
    return 0


if __name__ == "__main__":
    sys.exit(main())
