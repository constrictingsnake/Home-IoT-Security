#!/usr/bin/env python3
"""Build the blind facet-annotation kit from the Phase A product sample.

Mirrors make_review_copies.py: each annotator gets a copy carrying only raw data and its
OWN empty columns, so blindness is structural rather than a matter of policy — a file that
does not contain another annotator's column cannot leak it.

THE AUTO-LOAD LEAK, AND WHY THIS EMITS A SELF-CONTAINED DIRECTORY.
    Running the Claude annotator inside this repo is not blind, whatever the CSV contains.
    Claude Code auto-loads CLAUDE.md, which states the facet results outright (capturesAV
    is 79% cameras; the hand assignment wrong for 7 of 22 on hasWebAdminUI), and auto-loads
    a memory index carrying facet-dominance-rule and facet-provenance-estimated. That hands
    over the prior's conclusions before a single row is answered.

    So the kit is a directory holding the rubric, the value definitions, and the CSVs, and
    NOTHING ELSE. Run the annotator with the kit as its working directory. That drops
    CLAUDE.md and changes the memory project key, closing both channels at once — the fix
    is a `cd`, not a policy. Codex's channel is narrower (AGENTS.md carries no facet
    content) but run it from the kit too, for symmetry and because that is not permanent.

    What the kit CANNOT fix: the same model authored the prior assignment and the value
    definitions. That is a weights-level leak, and it is disclosed, not solved.

VALUE DEFINITIONS ARE GENERATED, NEVER HAND-COPIED.
    VALUE_DEFINITIONS.md is emitted from homeiot.ttl on every run, so the sheet an
    annotator reads cannot drift from the ontology being annotated — the same anti-drift
    contract that makes ontology_build.py generate categories.csv rather than tracking it
    by hand. Rationale was stripped at source in the .ttl (commit 2169b27), so this is now
    a straight extraction with no filtering step to get wrong.

THE 10A SPLIT. Phase A estimates a DISTRIBUTION, not a defensible per-item value, so
paying 3x for per-item precision that gets averaged away is the wrong trade. One annotator
takes the full sample; all three take a kappa subsample drawn from it. The subsample rows
appear in all three files, which is what makes agreement computable at all.

Usage:
    python3 scripts/make_facet_copies.py                      # build kit, default split
    python3 scripts/make_facet_copies.py --primary claude
    python3 scripts/make_facet_copies.py --kappa-devices 60
    python3 scripts/make_facet_copies.py --overwrite          # rebuild existing copies

Reads   data/facets/product_sample.csv     (from facet_sample.py --draw)
        data/facets/FACET_ANNOTATION_PROMPT.md
        ontology/homeiot.ttl
Writes  data/facets/annotation-kit/{FACET_ANNOTATION_PROMPT.md,VALUE_DEFINITIONS.md,README.md}
        data/facets/annotation-kit/{claude,codex,gemini}.csv
"""
import argparse
import csv
import os
import random
import shutil
import sys
from collections import OrderedDict, defaultdict

from rdflib import Graph, RDF, RDFS, Namespace

from facet_sample import DEFAULT_SEED, load_facet_spec

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
ONTO = os.path.join(ROOT, "ontology")
FACETS = os.path.join(DATA, "facets")
KIT = os.path.join(FACETS, "annotation-kit")

HIOT = Namespace("https://w3id.org/homeiot/ontology#")

ANNOTATORS = ["claude", "codex", "gemini"]
DEFAULT_KAPPA_DEVICES = 40

# Carried into every annotator copy. Deliberately excludes everything CVE-derived — see the
# rubric's "hard constraint" section. cve_count is carried as an aggregation WEIGHT and the
# rubric tells annotators to ignore it when choosing a value.
CARRY_COLS = ["category", "device", "vendor", "product", "cve_count", "facet", "allowed_values"]
OWN_COLS = ["Value", "Confidence", "Reasoning"]
FORBIDDEN = {"description", "cwe_ids", "cvss_score", "cvss_version", "vector_string",
             "cve_id", "published"}


def value_definitions_md(spec):
    """Emit the annotator's reference sheet straight from the ontology."""
    g = Graph()
    g.parse(os.path.join(ONTO, "homeiot.ttl"), format="turtle")

    out = ["# Facet Value Definitions",
           "",
           "**Generated from `ontology/homeiot.ttl` — do not edit by hand.** Regenerate with",
           "`python3 scripts/make_facet_copies.py`.",
           "",
           "Each facet below is single-valued: choose exactly one value, or `unsure`.",
           ""]
    missing = [f for f in spec if g.value(HIOT[f], HIOT.annotatorGloss) is None]
    if missing:
        sys.exit(
            "refusing to build: no hiot:annotatorGloss on " + ", ".join(sorted(missing)) +
            "\nThe kit must NOT fall back to rdfs:comment — those comments state research "
            "hypotheses, expected weakness classes, and in one case the facet's own modal "
            "answer. Add a gloss in homeiot.ttl first."
        )
    for facet, values in spec.items():
        prop = HIOT[facet]
        label = g.value(prop, RDFS.label) or facet
        # The GLOSS, never rdfs:comment — see the annotatorGloss block in homeiot.ttl.
        gloss = g.value(prop, HIOT.annotatorGloss)
        out.append(f"## `{facet}` — {label}")
        out.append("")
        out.append(str(gloss))
        out.append("")
        for v in values:
            if v in ("true", "false"):
                out.append(f"- **`{v}`**")
                continue
            ind = HIOT[v]
            vlabel = g.value(ind, RDFS.label)
            vcomment = g.value(ind, RDFS.comment)
            head = f"- **`{v}`**" + (f" — *{vlabel}*" if vlabel else "")
            out.append(head)
            if vcomment:
                out.append(f"  <br>{vcomment}")
        out.append("- **`unsure`** — the product name does not identify the device well")
        out.append("  enough to judge, or the facet does not apply. A real answer; use it.")
        out.append("")
    return "\n".join(out)


def kit_readme(primary, kappa_devices, counts):
    lines = [
        "# Facet Annotation Kit",
        "",
        "**Run your annotator with THIS DIRECTORY as its working directory**, not the repo",
        "root. That is what keeps the annotation blind: the repo's `CLAUDE.md` states the",
        "prior facet results outright, and opening it before answering would hand you the",
        "conclusions this exercise exists to test independently.",
        "",
        "## What to do",
        "",
        "1. Read `FACET_ANNOTATION_PROMPT.md` — the rubric. All annotators follow it.",
        "2. Read `VALUE_DEFINITIONS.md` for each facet before answering it the first time.",
        "3. Fill `Value`, `Confidence`, and `Reasoning` in your own CSV. Touch no other file.",
        "",
        "## Files",
        "",
    ]
    for name in ANNOTATORS:
        role = "FULL sample" if name == primary else "kappa subsample"
        lines.append(f"- `{name}.csv` — {role}, {counts[name]} rows")
    lines += [
        "",
        f"The subsample is {kappa_devices} devices shared by all three annotators; agreement",
        "is computed on those rows. The full sample carries the distribution estimate.",
        "",
        "You will see only your own columns. That is deliberate and structural — another",
        "annotator's answer is not withheld by policy, it is absent from the file.",
        "",
        "## Do not",
        "",
        "- Do not look up CVE descriptions, CWEs, or CVSS scores for these devices.",
        "- Do not look up the ontology's current value for any facet.",
        "- Do not adjust an answer toward what the category's answer 'should' be.",
    ]
    if primary == "claude":
        lines += [
            "",
            "## CONTAMINATION — disclose this, do not claim it away",
            "",
            "Claude carries the full sample here as a deliberate choice: Gemini is the",
            "documented weakest annotator and over-includes, and no Claude API path exists,",
            "so the full sample is filled in-session. The cost is that **Claude also authored",
            "the prior facet assignment and the value definitions in this kit.** Running from",
            "this directory drops `CLAUDE.md` and the memory index, which closes the *context*",
            "channel — it does not close the *weights* channel. It is the same model that",
            "produced the prior.",
            "",
            "Two things follow, both mandatory:",
            "",
            "1. **Use a FRESH session started in this directory.** A session that helped build",
            "   the kit has read the definitions, argued the boundary calls, and seen the",
            "   design intent. That is strictly worse than a cold start and costs nothing to",
            "   avoid.",
            "2. **State the residual in the paper.** Claude's column is not an independent",
            "   reading of the prior; it is a re-reading by the same model under a rubric.",
            "   Report it as such. Gemini's column is the one structurally free of this,",
            "   which is a reason to weigh its dissent more here than on CVE review.",
        ]
    return "\n".join(lines) + "\n"


def build(primary, kappa_devices, seed, overwrite):
    sample_path = os.path.join(FACETS, "product_sample.csv")
    if not os.path.exists(sample_path):
        sys.exit("no product_sample.csv — run: python3 scripts/facet_sample.py --draw")

    with open(sample_path, newline="") as f:
        rows = list(csv.DictReader(f))
    leaked = FORBIDDEN & set(rows[0])
    if leaked:
        sys.exit(f"refusing to build: sample carries CVE-derived columns {leaked}")

    # Devices, in a stable order, then a seeded subsample for the kappa rows.
    devices = list(OrderedDict.fromkeys((r["category"], r["device"]) for r in rows))
    rng = random.Random(seed)
    k = min(kappa_devices, len(devices))
    kappa = set(rng.sample(sorted(devices), k))

    os.makedirs(KIT, exist_ok=True)
    counts = {}
    for name in ANNOTATORS:
        path = os.path.join(KIT, f"{name}.csv")
        if os.path.exists(path) and not overwrite:
            print(f"  {name}.csv exists — skipping (use --overwrite to rebuild)")
            with open(path, newline="") as f:
                counts[name] = sum(1 for _ in f) - 1
            continue
        subset = rows if name == primary else [
            r for r in rows if (r["category"], r["device"]) in kappa
        ]
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=CARRY_COLS + OWN_COLS)
            w.writeheader()
            for r in subset:
                out = {c: r[c] for c in CARRY_COLS}
                out.update({c: "" for c in OWN_COLS})
                w.writerow(out)
        counts[name] = len(subset)
        print(f"  {name}.csv  {len(subset)} rows"
              f"{'  (FULL sample)' if name == primary else '  (kappa subsample)'}")

    spec = load_facet_spec()
    with open(os.path.join(KIT, "VALUE_DEFINITIONS.md"), "w") as f:
        f.write(value_definitions_md(spec))
    shutil.copy(os.path.join(FACETS, "FACET_ANNOTATION_PROMPT.md"),
                os.path.join(KIT, "FACET_ANNOTATION_PROMPT.md"))
    with open(os.path.join(KIT, "README.md"), "w") as f:
        f.write(kit_readme(primary, k, counts))

    stray = set(os.listdir(KIT)) - {f"{n}.csv" for n in ANNOTATORS} - {
        "VALUE_DEFINITIONS.md", "FACET_ANNOTATION_PROMPT.md", "README.md"}
    if stray:
        print(f"\n  WARNING: kit contains unexpected files {sorted(stray)} — the kit must stay")
        print("  self-contained, or the auto-load leak it exists to close reopens.")

    print(f"\nkit: {KIT}")
    print(f"  primary (full sample): {primary}")
    print(f"  kappa subsample: {k} devices x {len(spec)} facets = {k * len(spec)} rows each")
    print("\nRun each annotator with the kit as its working directory:")
    print(f"  cd {os.path.relpath(KIT, ROOT)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--primary", choices=ANNOTATORS, default="claude",
                    help="annotator taking the FULL sample (default claude — Gemini is the "
                         "documented weakest annotator and no Claude API path exists, so the "
                         "full sample is filled in-session; see CONTAMINATION in the README)")
    ap.add_argument("--kappa-devices", type=int, default=DEFAULT_KAPPA_DEVICES,
                    help=f"devices annotated by all three (default {DEFAULT_KAPPA_DEVICES})")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--overwrite", action="store_true", help="rebuild existing copies")
    args = ap.parse_args()
    build(args.primary, args.kappa_devices, args.seed, args.overwrite)


if __name__ == "__main__":
    main()
