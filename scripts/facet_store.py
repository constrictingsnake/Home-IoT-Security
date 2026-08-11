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
    settlement at risk to serve a 288-cell sheet. The pattern is what is worth reusing
    here, not the code.

THE TIER IS DERIVED FROM WHAT THE REVIEWER DID, NOT SELF-REPORTED.
    A reviewer who cites evidence gets HumanSourced; one who looked and found nothing gets
    HumanJudged. Documented needs an explicit category-wide marker because it is the only
    tier claiming the source covers the class rather than a few products, and that claim
    should have to be made deliberately. This means the honest answer "I could not find a
    source" is recorded rather than papered over, and the share of cells landing in
    HumanJudged becomes a reportable result about the facet instead of an invisible gap.

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

from facet_sample import load_facet_spec

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

STORE_COLS = ["slug", "facet", "Final Value", "Final Source", "Evidence Tier", "Sources",
              "Category-Wide", "Status",
              "Verdict 1", "Source 1", "Category-Wide 1", "Notes 1",
              "Verdict 2", "Source 2", "Category-Wide 2", "Notes 2",
              "Phase A Verdict", "Facet Kappa"]

TRUE_ISH = {"yes", "y", "true", "1", "category-wide"}

# Weakest first. The floor rule takes the minimum over a property's cells, so a single
# unevidenced category cannot hide behind evidenced ones.
TIER_ORDER = ["Estimated", "HumanJudged", "HumanSourced", "Documented", "Derived"]

UNSETTLED = {"", "unsure", "maybe"}


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


def derive_tier(sources, category_wide):
    """What the reviewer actually did decides the tier — see the module docstring."""
    if not sources.strip():
        return "HumanJudged"
    return "Documented" if category_wide else "HumanSourced"


def is_category_wide(row):
    """Did a reviewer claim the source covers the whole category, not a few products?

    Read from the dedicated Category-Wide columns. The Notes fallback exists only so an
    answer written the old way (the marker as free text) is not silently downgraded to
    HumanSourced; new sheets carry the column and should use it.
    """
    for n in ("1", "2"):
        if (row.get(f"Category-Wide {n}") or "").strip().lower() in TRUE_ISH:
            return True
        if "category-wide" in (row.get(f"Notes {n}") or "").lower():
            return True
    return False


def settle(row):
    """Return (final_value, tier, sources, status) for one sheet cell.

    A cell settles only on two independent, agreeing, non-`unsure` verdicts — the same bar
    the CVE queue uses, and for the same reason: a lone verdict is one reviewer, not a
    reconciliation.
    """
    v1 = (row.get("Verdict 1") or "").strip()
    v2 = (row.get("Verdict 2") or "").strip()
    s1 = (row.get("Source 1") or "").strip()
    s2 = (row.get("Source 2") or "").strip()

    if row.get("status") == "excluded-validity":
        return "", "", "", False, "excluded-validity"
    if v1.lower() in UNSETTLED and v2.lower() in UNSETTLED:
        return "", "", "", False, "outstanding-no-verdict"
    if v1.lower() in UNSETTLED or v2.lower() in UNSETTLED:
        return "", "", "", False, "outstanding-one-verdict"
    if v1.lower() != v2.lower():
        return "", "", "", False, "outstanding-disagreement"

    sources = " ; ".join(s for s in (s1, s2) if s)
    wide = is_category_wide(row)
    return v1, derive_tier(sources, wide), sources, wide, "settled"


def cmd_finalize():
    if not os.path.exists(SHEET):
        sys.exit(f"no sheet at {SHEET} — run: python3 scripts/make_tagging_sheet.py")
    sheet = _read(SHEET)
    store = _read(STORE, key=("slug", "facet"))

    added = updated = kept = 0
    for row in sheet:
        key = (row["slug"], row["facet"])
        value, tier, sources, wide, status = settle(row)
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
                       ("priority", "slug", "label", "facet", "allowed_values",
                        "prefill_value", "prefill_source", "phase_a_verdict",
                        "facet_kappa", "kappa_band", "category_cves", "scope_note")},
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
    spec = load_facet_spec()

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
        print(f"  {facet:24} {tier}")


def cmd_writeback():
    """Emit the edit list a human applies to homeiot.ttl by hand."""
    store = _read(STORE, key=("slug", "facet"))
    if not store:
        sys.exit("empty store — run --finalize first")
    spec = load_facet_spec()

    g = Graph()
    g.parse(os.path.join(ONTO, "homeiot.ttl"), format="turtle")
    current = {}
    for cls in g.subjects(HIOT.slug, None):
        slug = str(g.value(cls, HIOT.slug))
        for facet in spec:
            val = g.value(cls, HIOT[facet])
            if val is not None:
                text = str(val)
                current[(slug, facet)] = text.split("#")[1] if "#" in text else text

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
                            rec["Sources"]))
    changes.sort()

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
        lines += ["| category | facet | current | new | tier | source |",
                  "|---|---|---|---|---|---|"]
        for slug, facet, old, new, tier, src in changes:
            lines.append(f"| `{slug}` | `{facet}` | `{old}` | **`{new}`** | {tier} | "
                         f"{src or '—'} |")
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
