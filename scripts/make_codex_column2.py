#!/usr/bin/env python3
"""Emit and merge back the Codex draft of column 2 — F5 of PLAN_facet_system_fixes.md.

WHAT CHANGED, AND WHY THIS SCRIPT EXISTS
----------------------------------------
F5 as designed had two independent reviewers on one sheet. Column 1 was filled by Claude
(see tagging-kit/PROBE_RESULT.md), and column 2 was to be human. The decision taken
2026-08-30 is that Codex DRAFTS column 2 and the human reviews every cell before it
settles. The tier vocabulary survives that — the human verdict is still what settles a
cell — but the provenance shape changes and must be recorded:

    cells  1- 89 : Claude draft (col 1)          + human verification (col 2)
    cells 90-202 : Claude draft (col 1)          + Codex draft, human-adjudicated (col 2)

On the second block the human is adjudicating TWO AI DRAFTS rather than acting as an
independent second reviewer. That is a weaker form of independence than the first block and
the report must say so. It is not a reason to avoid it: the drafts are non-blind by design
(this is a verification sheet made of pre-fills, the opposite of annotation-kit/), so the
human has always been the settling authority here.

SCOPE — 113 CELLS, NOT 420
--------------------------
Four scope decisions taken 2026-08-30, all recorded in PLAN_facet_system_fixes.md § F5:

  1. Deliverable is the reportable sourcing result (tier mix + CVE-weighted sourced share),
     not TTL writeback — writeback returns 0 value changes either way.
  2. Column 2 verifies column 1's citation; independent retrieval only on `below-floor` cells.
  3. The 8 categories holding 18 CVEs between them are deliberately untagged. Two of them
     (shades, sleeptracker) have no NVD footprint at all.
  4. Only the 5 kappa-failed and 6 multi-valued facets are asked. The 4 CITABLE and 3
     grouping-only facets keep the 5-category coverage they already have.

Decisions 3 and 4 compose better than either does alone: they leave all 11 asked facets
settled on all 16 categories that carry CVEs — 1,715 of 1,733 confirmed-Yes CVEs, 99.0% —
so each facet's HumanJudged share is reportable against a complete denominator rather than
against whichever categories someone got to.

    python3 scripts/make_codex_column2.py --emit    # scoped sheet -> codex_column2.csv
    python3 scripts/make_codex_column2.py --merge   # Codex answers -> category_tags.csv

--merge NEVER touches column 1 and REFUSES to overwrite a non-blank Verdict 2, so the 89
cells already settled by hand cannot be clobbered by a rerun.
"""

import argparse
import collections
import csv
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FACETS = os.path.join(ROOT, "data", "facets")
SHEET = os.path.join(FACETS, "tagging-kit", "category_tags.csv")
OUT = os.path.join(FACETS, "tagging-kit", "codex_column2.csv")
COVERAGE = os.path.join(FACETS, "source_coverage.csv")
JUDGMENTS = os.path.join(ROOT, "data", "difference", "judgment_store.csv")
SNAPSHOT = os.path.join(ROOT, "data", "nvd-snapshot", "nvd_all.csv")

# The kappa-failed facets that sourcing can still rescue: blind annotation already failed, and
# for two of them so did text derivation, so a citation is the last route open to them.
#
# computeTier IS NO LONGER ASKED (dropped 2026-09-01). It has now failed all three independent
# routes: the F2 blind panel (kappa 0.38), automated derivation from CVE text (facet_derive.py
# found evidence sufficient for 1 of 22 categories), and this sourcing pass - where Codex
# returned `unsure` on 8 of the 11 categories it was asked, because vendor documentation
# describes what a device DOES and essentially never states its SoC class. Three exhausted
# routes is a drop decision, and it is the outcome the probe gate in tagging-kit/README.md
# exists to produce: "if sources turn out not to exist for a facet, that facet gets dropped
# rather than tagged". computeTier keeps its column-1 answers but can never settle, so it stays
# Estimated permanently - usable for organising analysis, never citable as a finding.
KAPPA_FAILED = ["capturesAV", "firmwareUpdateModel",
                "hasWebAdminUI", "supportLifetime"]

# The 6 multi-valued facets. No kappa, no Phase A verdict — they were never in the blind
# panel, so this pass is the first evidence they will ever carry. Without it they stay
# Estimated permanently.
MULTI_VALUED = ["adminModel", "alsoDeployedIn", "credentialModel",
                "pairingModel", "patchResponsibility", "topology"]

ASKED_FACETS = set(KAPPA_FAILED) | set(MULTI_VALUED)

# Deliberately untagged (decision 3). Held between them: 18 confirmed-Yes CVEs, 1.0%.
SKIPPED_CATEGORIES = {"airconditioner", "sensors", "appliances", "fridge",
                      "airpurifier", "fans", "shades", "sleeptracker"}

ANSWER_COLS = ["Verdict 2", "Source 2", "Category-Wide 2", "Notes 2"]

CONTEXT_COLS = ["slug", "label", "facet", "cardinality", "allowed_values",
                "kappa_band", "facet_kappa", "phase_a_verdict", "modal_share",
                "category_cves", "scope_note"]

COL1_COLS = ["prefill_value", "prefill_source",
             "Verdict 1", "Source 1", "Category-Wide 1", "Notes 1"]

BRIEF_COLS = ["coverage_verdict", "resource_required", "cited_vendors",
              "cited_share", "corpus_vendors"]

OUT_COLS = CONTEXT_COLS + COL1_COLS + BRIEF_COLS + ANSWER_COLS


def in_scope(row):
    """An asked, still-outstanding cell inside the 113."""
    return (row.get("status") == "ask"
            and row["facet"] in ASKED_FACETS
            and row["slug"] not in SKIPPED_CATEGORIES
            and not (row.get("Verdict 2") or "").strip())


def read_csv(path):
    csv.field_size_limit(10 ** 8)
    with open(path) as fh:
        return list(csv.DictReader(fh))


def corpus_vendors(slugs, top_n=6):
    """slug -> "vendor 45% | vendor 12% | ..." over the category's confirmed-Yes CVEs.

    This is the brief a reviewer needs to re-source a `below-floor` cell: it names the
    brands whose CVEs the assertion actually lands on. Shares are CVE-level and a CVE
    attributed to two vendors counts toward both, so they do not sum to 1 — the same
    convention facet_source_coverage.py uses, and for the same reason.
    """
    yes = collections.defaultdict(set)
    for r in read_csv(JUDGMENTS):
        if r.get("Final Judgment") == "Yes" and not (r.get("Excluded") or "").strip():
            if r["category"] in slugs:
                yes[r["category"]].add(r["cve_id"])

    wanted = set().union(*yes.values()) if yes else set()
    per_cve = {}
    with open(SNAPSHOT) as fh:
        for r in csv.DictReader(fh):
            if r["cve_id"] not in wanted:
                continue
            vs = set()
            for c in (r.get("cpe_strings") or "").split("|"):
                p = c.split(":")
                if len(p) > 4 and p[1] == "2.3":
                    vs.add(p[3].lower())
            per_cve[r["cve_id"]] = vs

    out = {}
    for slug, cves in yes.items():
        counts = collections.Counter()
        for c in cves:
            for v in per_cve.get(c, ()):
                counts[v] += 1
        n = len(cves)
        out[slug] = " | ".join(f"{v} {c / n:.0%}" for v, c in counts.most_common(top_n))
    return out


def cmd_emit():
    rows = [r for r in read_csv(SHEET) if in_scope(r)]
    if not rows:
        print("nothing outstanding in scope — codex_column2.csv not written")
        return

    cov = {(r["slug"], r["facet"]): r for r in read_csv(COVERAGE)}
    vendors = corpus_vendors({r["slug"] for r in rows})

    out = []
    for r in rows:
        c = cov.get((r["slug"], r["facet"]), {})
        verdict = c.get("verdict", "")
        rec = {k: r.get(k, "") for k in CONTEXT_COLS + COL1_COLS}
        rec.update({
            "coverage_verdict": verdict,
            "resource_required": "yes" if verdict == "below-floor" else "",
            "cited_vendors": c.get("cited_vendors", ""),
            "cited_share": c.get("cited_share", ""),
            "corpus_vendors": vendors.get(r["slug"], ""),
        })
        for k in ANSWER_COLS:
            rec[k] = ""
        out.append(rec)

    # below-floor first, then category, then kappa-failed before multi-valued. The 19
    # defective cells are the ones needing real retrieval, so they lead — and grouping by
    # category after that matches how the sourcing actually works (one vendor KB answers
    # three or four facets of one category at once; see PROBE_RESULT.md).
    order = {f: i for i, f in enumerate(KAPPA_FAILED + MULTI_VALUED)}
    out.sort(key=lambda r: (r["resource_required"] != "yes", r["slug"], order[r["facet"]]))

    with open(OUT, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=OUT_COLS)
        w.writeheader()
        w.writerows(out)

    need = sum(1 for r in out if r["resource_required"] == "yes")
    print(f"wrote {OUT}")
    print(f"  cells: {len(out)}")
    print(f"  needing independent re-sourcing (below-floor): {need}")
    print(f"  categories: {len(set(r['slug'] for r in out))}")


def validate(row):
    """Warnings, never rejections — a typo should be visible to the person fixing it.

    Mirrors facet_store.invalid_values(): this script has no business dropping a human- or
    model-authored answer on the floor, and the settle rule downstream will catch anything
    that is genuinely unusable.
    """
    v = (row.get("Verdict 2") or "").strip()
    if not v:
        return []
    allowed = set((row.get("allowed_values") or "").split("|")) | {"unsure", "none"}
    parts = v.split("|") if row.get("cardinality") == "multi" else [v]
    parts = [p.strip() for p in parts]
    bad = [p for p in parts if p not in allowed]
    if row.get("cardinality") != "multi" and len(v.split("|")) > 1:
        bad.append(f"(single-valued cell holds {len(v.split('|'))} values)")
    if len(parts) > 1 and ("unsure" in parts or "none" in parts):
        bad.append("(unsure/none mixed into a set)")
    return bad


def cmd_merge():
    if not os.path.exists(OUT):
        sys.exit(f"no {OUT} — run --emit first")

    answers = {}
    for r in read_csv(OUT):
        if (r.get("Verdict 2") or "").strip():
            answers[(r["slug"], r["facet"])] = r

    sheet = read_csv(SHEET)
    with open(SHEET) as fh:
        cols = csv.DictReader(fh).fieldnames

    merged = skipped = 0
    warnings = []
    for row in sheet:
        key = (row["slug"], row["facet"])
        if key not in answers:
            continue
        # The 89 hand-settled cells are protected: a rerun cannot overwrite an answer that
        # is already there. Same instinct as the sticky human verdicts in judgment_store.
        if (row.get("Verdict 2") or "").strip():
            skipped += 1
            continue
        src = answers[key]
        bad = validate(src)
        if bad:
            warnings.append(f"  {key[0]}/{key[1]}: {', '.join(bad)}")
        for c in ANSWER_COLS:
            row[c] = (src.get(c) or "").strip()
        merged += 1

    with open(SHEET, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(sheet)

    print(f"merged {merged} cells into {SHEET}")
    if skipped:
        print(f"  skipped {skipped} already-filled (protected)")
    if warnings:
        print(f"  {len(warnings)} value warnings (merged anyway, fix in the sheet):")
        print("\n".join(warnings))
    print("\nnext: python3 scripts/facet_store.py --finalize"
          "  then  --extract   (order matters)")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--emit", action="store_true", help="write the scoped Codex sheet")
    g.add_argument("--merge", action="store_true", help="fold Codex answers back")
    a = ap.parse_args()
    cmd_emit() if a.emit else cmd_merge()


if __name__ == "__main__":
    main()
