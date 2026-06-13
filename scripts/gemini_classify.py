#!/usr/bin/env python3
"""Gemini API reviewer for the difference workflow.

Fills the `Gemini Judgment` / `Gemini Confidence` / `Gemini Reasoning` columns of a blind
review copy (gemini.csv from make_review_copies.py) by sending each row's description and
cpe_strings to the Gemini API.

Blindness is structural here: only the description and CPE strings are ever sent to the
model — never another reviewer's columns.

Resumable: rows that already have a Gemini Judgment are skipped, and progress is written
to disk every --save-every rows, so the script can be re-run after an interruption or a
rate-limit without redoing work.

Setup:
    export GEMINI_API_KEY=...        # https://aistudio.google.com/apikey
    # requests + pandas are already installed in this project

Usage:
    python gemini_classify.py path/to/reviews/gemini.csv --category "security camera"
    python gemini_classify.py path/to/reviews/gemini.csv --category "smart lock" \
        --model gemini-2.5-flash --rps 1.0 --limit 50
"""
import argparse
import json
import os
import sys
import time

import pandas as pd
import requests

REVIEWER = "Gemini"
JUDGMENT_COL = f"{REVIEWER} Judgment"
CONF_COL = f"{REVIEWER} Confidence"
REASON_COL = f"{REVIEWER} Reasoning"

DEFAULT_MODEL = "gemini-2.5-flash"
API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
RUBRIC_DEFAULT = os.path.join(
    os.path.dirname(__file__), "..", "data", "difference", "CLASSIFICATION_PROMPT.md"
)

RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "judgment": {"type": "string", "enum": ["Yes", "No", "Maybe"]},
        "confidence": {"type": "string", "enum": ["High", "Low"]},
        "reasoning": {"type": "string"},
    },
    "required": ["judgment", "confidence", "reasoning"],
}


def build_prompt(rubric, category, description, cpe):
    return (
        f"{rubric}\n\n"
        f"=== DEVICE CATEGORY UNDER REVIEW ===\n{category}\n\n"
        f"=== CVE DESCRIPTION ===\n{description or '(none)'}\n\n"
        f"=== CPE STRINGS ===\n{cpe or '(none)'}\n\n"
        "Classify this CVE for the device category above. Judge ONLY from the description "
        "and CPE strings. Respond with the required JSON object."
    )


def call_gemini(session, api_key, model, prompt):
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": RESPONSE_SCHEMA,
            "temperature": 0,
        },
    }
    resp = session.post(
        API_URL.format(model=model), params={"key": api_key}, json=payload, timeout=60
    )
    resp.raise_for_status()
    text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
    obj = json.loads(text)
    return obj["judgment"], obj["confidence"], obj.get("reasoning", "")


def call_with_retry(session, api_key, model, prompt, max_retries=5):
    for attempt in range(max_retries):
        try:
            return call_gemini(session, api_key, model, prompt)
        except requests.HTTPError as e:
            code = e.response.status_code if e.response is not None else None
            if code in (429, 500, 502, 503, 504) and attempt < max_retries - 1:
                wait = 2.0 ** attempt
                print(f"    HTTP {code} — retrying in {wait:.0f}s")
                time.sleep(wait)
                continue
            raise
    raise RuntimeError("max retries exceeded")


def classify_file(
    csv_path,
    category,
    *,
    model=DEFAULT_MODEL,
    rubric_path=RUBRIC_DEFAULT,
    rps=1.0,
    save_every=25,
    limit=0,
    redo=False,
    api_key=None,
):
    """Fill the Gemini columns of one review copy in place. Returns rows classified.

    Importable so merge_judgments.py can run the Gemini pass before merging. Resumable:
    only blank rows are classified unless redo=True, and progress is flushed to disk.
    """
    api_key = api_key or os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("Set GEMINI_API_KEY (get one at https://aistudio.google.com/apikey)")
    if not os.path.isfile(csv_path):
        raise FileNotFoundError(f"File not found: {csv_path}")
    if not os.path.isfile(rubric_path):
        raise FileNotFoundError(f"Rubric not found: {rubric_path}")

    with open(rubric_path, encoding="utf-8") as fh:
        rubric = fh.read()

    df = pd.read_csv(csv_path, dtype=str).fillna("")
    if "description" not in df.columns:
        raise ValueError(f"{csv_path}: missing 'description' column")
    for col in (JUDGMENT_COL, CONF_COL, REASON_COL):
        if col not in df.columns:
            df[col] = ""
    cpe_col = "cpe_strings" if "cpe_strings" in df.columns else None

    pending = list(df.index) if redo else list(df.index[df[JUDGMENT_COL].str.strip() == ""])
    if limit:
        pending = pending[:limit]
    if not pending:
        print("  Gemini: nothing to do — all rows already classified.")
        return 0

    print(f"  Gemini: classifying {len(pending)} rows with {model} ...")
    session = requests.Session()
    delay = 1.0 / rps if rps > 0 else 0.0
    done = 0
    for idx in pending:
        prompt = build_prompt(
            rubric, category, df.at[idx, "description"], df.at[idx, cpe_col] if cpe_col else ""
        )
        try:
            judgment, confidence, reasoning = call_with_retry(session, api_key, model, prompt)
        except Exception as e:  # leave blank; a later run will retry this row
            print(f"    row {idx} ({df.at[idx, 'cve_id']}): error {e} — left blank for retry")
            continue

        # Convention (matches the rubric): keep reasoning only for Low confidence or Maybe.
        if confidence == "High" and judgment != "Maybe":
            reasoning = ""
        df.at[idx, JUDGMENT_COL] = judgment
        df.at[idx, CONF_COL] = confidence
        df.at[idx, REASON_COL] = reasoning

        done += 1
        if done % save_every == 0:
            df.to_csv(csv_path, index=False)
            print(f"    ...{done}/{len(pending)} saved")
        if delay:
            time.sleep(delay)

    df.to_csv(csv_path, index=False)
    print(f"  Gemini: classified {done} rows; saved to {csv_path}")
    return done


def main():
    ap = argparse.ArgumentParser(description="Classify a Gemini review copy via the Gemini API.")
    ap.add_argument("csv", help="Path to the Gemini review copy (gemini.csv)")
    ap.add_argument("--category", required=True, help="Device category, e.g. 'security camera'")
    ap.add_argument("--model", default=os.environ.get("GEMINI_MODEL", DEFAULT_MODEL))
    ap.add_argument("--rubric", default=RUBRIC_DEFAULT, help="Path to the shared rubric markdown")
    ap.add_argument("--rps", type=float, default=1.0, help="Max requests per second")
    ap.add_argument("--save-every", type=int, default=25, help="Write progress to disk every N rows")
    ap.add_argument("--limit", type=int, default=0, help="Classify only the first N pending rows (0 = all)")
    ap.add_argument("--redo", action="store_true", help="Re-classify rows that already have a Gemini judgment")
    args = ap.parse_args()

    try:
        classify_file(
            args.csv,
            args.category,
            model=args.model,
            rubric_path=args.rubric,
            rps=args.rps,
            save_every=args.save_every,
            limit=args.limit,
            redo=args.redo,
        )
    except (RuntimeError, FileNotFoundError, ValueError) as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
