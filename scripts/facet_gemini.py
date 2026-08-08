#!/usr/bin/env python3
"""Gemini API annotator for the facet workflow — the third column of the kappa panel.

Fills the `Value` / `Confidence` / `Reasoning` columns of a blind facet annotation copy
(gemini.csv from make_facet_copies.py) by sending each row's PRODUCT IDENTITY and the
facet's value definitions to the Gemini API. Sibling of gemini_classify.py, which does
the same job for CVE review; the conventions here (model choice, rate limiting, resume,
batching, one model per column) are deliberately identical so the two are read together.

THE HARD CONSTRAINT — product identity only, never CVE text.
    Only category, vendor, product and the facet's value definitions are ever sent.
    NO CVE description, NO CWE, NO CVSS. This is enforced in code (see assert_no_cve_text)
    and is not a style preference: if a facet were assigned from CVE text, then any later
    facet-vs-weakness contrast would correlate that text with itself, which is exactly how
    facet_derive.py became circular and why two of its contrasts stand retracted in
    CLAUDE.md. Keeping the annotator away from the description is what makes facet and
    weakness independent. `cve_count` is a WEIGHT for aggregation, not evidence about the
    device, and is likewise never sent.

WHY GEMINI IS WORTH HAVING HERE despite being the documented weakest annotator: it is the
only one of the three structurally immune to the auto-load leak. Claude and Codex are run
from the kit directory to keep CLAUDE.md and the memory index out of context; Gemini never
had them. On this unit that is a real argument for weighting its dissent slightly more
than CVE review does — the annotator with the least contamination is the one with the
least skill, and both facts belong in the writeup.

Blindness is structural: this script only ever opens its own CSV, which physically lacks
the other annotators' columns and the author's prior.

Setup:
    export GEMINI_API_KEY=...        # https://aistudio.google.com/apikey

Usage:
    python3 scripts/facet_gemini.py data/facets/annotation-kit/gemini.csv
    python3 scripts/facet_gemini.py data/facets/annotation-kit/gemini.csv \
        --model gemma-4-31b-it --batch-size 20 --limit 50
"""
import argparse
import json
import os
import re
import sys
import time

import pandas as pd
import requests

VALUE_COL = "Value"
CONF_COL = "Confidence"
REASON_COL = "Reasoning"

# Keep ONE model across the whole column, per the project convention for the Gemini
# reviewer: mixing models mid-column makes the column an average of two annotators and
# its kappa uninterpretable. gemma-4-31b-it is the standing choice (higher daily quota).
DEFAULT_MODEL = "gemma-4-31b-it"
API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KIT = os.path.join(ROOT, "data", "facets", "annotation-kit")
RUBRIC_DEFAULT = os.path.join(KIT, "FACET_ANNOTATION_PROMPT.md")
DEFINITIONS_DEFAULT = os.path.join(KIT, "VALUE_DEFINITIONS.md")

# Columns that would leak CVE text into the prompt. The sheet is built without them
# (facet_sample.py SHEET_COLS), so this is a tripwire for a future edit, not a filter.
FORBIDDEN_COLS = {
    "description", "cve_id", "cwe", "cwe_id", "cwe888_classes", "vector_string",
    "cvss", "base_score", "severity", "cpe_strings", "matched_terms",
}

BATCH_RESPONSE_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "device": {"type": "string"},
            "value": {"type": "string"},
            "confidence": {"type": "string", "enum": ["High", "Low"]},
            "reasoning": {"type": "string"},
        },
        "required": ["device", "value", "confidence", "reasoning"],
    },
}


def assert_no_cve_text(df, path):
    """Fail loudly if the sheet ever grows a CVE-text column.

    The whole independence argument for these facets rests on the annotator never seeing
    CVE text, so this is checked at run time rather than trusted to the generator.
    """
    bad = {c for c in df.columns if c.strip().lower() in FORBIDDEN_COLS}
    if bad:
        raise SystemExit(
            f"REFUSING TO RUN: {path} carries CVE-derived column(s) {sorted(bad)}.\n"
            "Facets must be assigned from product identity alone — see the module "
            "docstring and facet_sample.py's SHEET_COLS. Fix the sheet, not this check."
        )


def load_definitions(path=DEFINITIONS_DEFAULT):
    """{facet: markdown block} from the generated VALUE_DEFINITIONS.md.

    Sections are '## `facet` — label'. Splitting the file per facet means each request
    carries only the definitions for the facet being judged, which keeps the prompt small
    and stops one facet's wording bleeding into another's judgment.
    """
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    out = {}
    parts = re.split(r"^## +`([^`]+)`", text, flags=re.M)
    for i in range(1, len(parts), 2):
        out[parts[i]] = f"## `{parts[i]}`{parts[i + 1]}".strip()
    if not out:
        raise SystemExit(f"no facet sections parsed from {path}")
    return out


def build_batch_prompt(rubric, definitions, facet, allowed, rows):
    """rows: list of (device, vendor, product, category) tuples, all for ONE facet."""
    entries = [
        f"--- device: {device} ---\n"
        f"Vendor: {vendor}\nProduct name: {product}\nCategory: {category}"
        for device, vendor, product, category in rows
    ]
    return (
        f"{rubric}\n\n"
        f"=== FACET UNDER ANNOTATION ===\n{facet}\n\n"
        f"=== VALUE DEFINITIONS (authoritative — choose from these only) ===\n"
        f"{definitions}\n\n"
        f"=== ALLOWED VALUES ===\n{allowed}\n\n"
        f"=== DEVICES TO ANNOTATE ===\n" + "\n\n".join(entries) + "\n\n"
        "Assign the facet value for EACH device above. Judge ONLY from the vendor and "
        "product name — you have no CVE text and must not imagine any. If the product "
        "name does not identify the device well enough to judge, answer `unsure`; that "
        "is a real answer and forcing a guess is worse. Return a JSON array with one "
        "object per device, each containing device, value, confidence, and reasoning. "
        "The `device` field must repeat the device string exactly as given."
    )


def call_with_retry(session, api_key, model, prompt, max_retries=5):
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": BATCH_RESPONSE_SCHEMA,
            "temperature": 0,
        },
    }
    for attempt in range(max_retries):
        try:
            resp = session.post(API_URL.format(model=model), params={"key": api_key},
                                json=payload, timeout=120)
            resp.raise_for_status()
            text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
            items, _ = json.JSONDecoder().raw_decode(text.strip())
            # Weaker models echo the key with stray whitespace; strip so the exact-match
            # map-back does not silently drop rows (same fix as gemini_classify.py).
            return {
                it["device"].strip(): (it["value"], it.get("confidence", "Low"),
                                       it.get("reasoning", ""))
                for it in items
            }
        except requests.HTTPError as e:
            code = e.response.status_code if e.response is not None else None
            if code == 429:
                # Never retry a 429 — each retry burns daily quota. Skip; a later run
                # picks the row up once quota resets, because this script is resumable.
                raise
            if code in (500, 502, 503, 504) and attempt < max_retries - 1:
                wait = 2.0 ** attempt
                print(f"    HTTP {code} — retrying in {wait:.0f}s")
                time.sleep(wait)
                continue
            raise
    raise RuntimeError("max retries exceeded")


def annotate_file(csv_path, *, model=DEFAULT_MODEL, rubric_path=RUBRIC_DEFAULT,
                  definitions_path=DEFINITIONS_DEFAULT, rps=1.0, save_every=5,
                  limit=0, redo=False, api_key=None, batch_size=20):
    """Fill the Value/Confidence/Reasoning columns of one facet copy in place.

    Resumable: only blank rows are annotated unless redo=True, and progress is flushed
    every save_every batches so a rate-limit stop loses at most one batch.
    """
    api_key = api_key or os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise SystemExit("GEMINI_API_KEY not set (see .env / README Prerequisites)")

    df = pd.read_csv(csv_path, dtype=str).fillna("")
    assert_no_cve_text(df, csv_path)
    for col in (VALUE_COL, CONF_COL, REASON_COL):
        if col not in df.columns:
            raise SystemExit(f"{csv_path} has no {col!r} column — is this a facet copy?")

    with open(rubric_path, encoding="utf-8") as fh:
        rubric = fh.read()
    definitions = load_definitions(definitions_path)

    todo = df.index if redo else df.index[df[VALUE_COL].str.strip() == ""]
    if limit:
        todo = todo[:limit]
    if len(todo) == 0:
        print(f"{os.path.basename(csv_path)}: nothing to do (all rows filled)")
        return 0

    # Group by facet so one request carries one definition block. Batching by facet is
    # also what keeps the annotator's frame of reference stable within a request.
    by_facet = {}
    for idx in todo:
        by_facet.setdefault(df.at[idx, "facet"], []).append(idx)

    session = requests.Session()
    done = failed = 0
    print(f"{os.path.basename(csv_path)}: {len(todo)} rows over {len(by_facet)} facets, "
          f"model={model}, batch={batch_size}")

    for facet, idxs in sorted(by_facet.items()):
        if facet not in definitions:
            print(f"  {facet}: NO DEFINITIONS in {os.path.basename(definitions_path)} "
                  f"— skipping {len(idxs)} rows rather than annotating blind")
            failed += len(idxs)
            continue
        for start in range(0, len(idxs), batch_size):
            chunk = idxs[start:start + batch_size]
            rows = [(df.at[i, "device"], df.at[i, "vendor"], df.at[i, "product"],
                     df.at[i, "category"]) for i in chunk]
            allowed = df.at[chunk[0], "allowed_values"]
            prompt = build_batch_prompt(rubric, definitions[facet], facet, allowed, rows)
            try:
                got = call_with_retry(session, api_key, model, prompt)
            except requests.HTTPError as e:
                code = e.response.status_code if e.response is not None else "?"
                print(f"  {facet}: HTTP {code} — stopping; re-run to resume")
                df.to_csv(csv_path, index=False)
                return done
            except Exception as e:  # noqa: BLE001 — one bad batch must not lose the run
                print(f"  {facet}: {type(e).__name__}: {e} — batch skipped")
                failed += len(chunk)
                continue

            allowed_set = {v.strip() for v in allowed.split("|") if v.strip()}
            for i in chunk:
                dev = df.at[i, "device"]
                if dev not in got:
                    failed += 1
                    continue
                value, conf, reason = got[dev]
                value = (value or "").strip()
                if value not in allowed_set:
                    # An out-of-vocabulary value is left BLANK, never coerced. A coerced
                    # value would enter kappa as a real judgment; a blank is visibly
                    # missing and gets retried.
                    print(f"    {dev}/{facet}: value {value!r} not in allowed set — left blank")
                    failed += 1
                    continue
                df.at[i, VALUE_COL] = value
                df.at[i, CONF_COL] = (conf or "Low").strip()
                df.at[i, REASON_COL] = (reason or "").strip()
                done += 1
            time.sleep(max(0.0, 1.0 / rps) if rps > 0 else 0)
        df.to_csv(csv_path, index=False)
        print(f"  {facet}: {done} filled so far")

    df.to_csv(csv_path, index=False)
    print(f"done: {done} annotated, {failed} left blank for a later run")
    return done


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv_path", nargs="?", default=os.path.join(KIT, "gemini.csv"),
                    help="facet annotation copy to fill (default: the kit's gemini.csv)")
    ap.add_argument("--model", default=DEFAULT_MODEL,
                    help=f"one model for the WHOLE column (default {DEFAULT_MODEL})")
    ap.add_argument("--rubric", default=RUBRIC_DEFAULT)
    ap.add_argument("--definitions", default=DEFINITIONS_DEFAULT)
    ap.add_argument("--rps", type=float, default=1.0, help="requests per second")
    ap.add_argument("--batch-size", type=int, default=20, help="devices per request")
    ap.add_argument("--limit", type=int, default=0, help="stop after N rows")
    ap.add_argument("--redo", action="store_true",
                    help="re-annotate filled rows (back the column up first)")
    args = ap.parse_args()

    annotate_file(args.csv_path, model=args.model, rubric_path=args.rubric,
                  definitions_path=args.definitions, rps=args.rps,
                  limit=args.limit, redo=args.redo, batch_size=args.batch_size)
    return 0


if __name__ == "__main__":
    sys.exit(main())
